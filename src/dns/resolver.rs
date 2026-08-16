//! In-daemon DNS resolver reached via the magic IP (no host :53 socket).
//! Answers names held in the hostname tables and forwards everything else to
//! the captured system upstreams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use smol_str::SmolStr;

use crate::dns::{HostnameTable, MAGIC_DNS_V4, MAGIC_DNS_V6, ReverseLookupTable};

/// Our own Magic DNS addresses. Forwarding to either is a loop: the query would
/// come straight back in through `handle_tun_query`.
fn is_magic_dns(ip: IpAddr) -> bool {
    ip == IpAddr::V4(MAGIC_DNS_V4) || ip == IpAddr::V6(MAGIC_DNS_V6)
}

pub struct Resolver {
    table: HostnameTable,
    reverse: ReverseLookupTable,
    upstreams: Arc<ArcSwap<Vec<SocketAddr>>>,
    /// Upstreams to use instead of `upstreams` while a full tunnel is up, so
    /// lookups leave by the exit node rather than around it. See
    /// [`set_tunnel_upstreams`](Resolver::set_tunnel_upstreams).
    tunnel_upstreams: Arc<ArcSwapOption<Vec<SocketAddr>>>,
    /// Whether this node's data plane is IPv6-only. When set, the roster
    /// responder withholds A records (see [`crate::dns::handle_query`]): mesh
    /// IPv4 is not routed here, so handing an app one is a black hole.
    ipv6_only: AtomicBool,
    /// Per-name forwarding counters for [`LOOP_WINDOW`], kept only for names
    /// sent to another mesh's resolver. See [`Resolver::loop_guard_allows`].
    overlay_forwards: DashMap<SmolStr, (Instant, u32)>,
    /// Whether the stub has another nameserver listed after ours, so a name
    /// outside `.ray` can be declined instead of forwarded. See
    /// [`Resolver::set_defer_off_mesh`].
    defer_off_mesh: AtomicBool,
}

/// How many times one name may go to another mesh's resolver inside
/// [`LOOP_WINDOW`] before we stop sending it there.
///
/// A resolver we share `/etc/resolv.conf` with can be pointed straight back at
/// us, and then a name neither mesh owns bounces between the two until
/// something gives. Tailscale reads the live file for its own upstreams and
/// drops only its *own* service IPs from what it finds (`GetBaseConfig` in
/// `net/dns/direct.go`, added for tailscale/tailscale#7816, which is this same
/// loop with systemd-resolved on the other end), so a daemon that starts while
/// our file is in place adopts our magic IP as its upstream and neither side's
/// filter catches it.
///
/// The threshold is a circuit breaker, not a rate limit: it has to sit above
/// what a busy host legitimately asks for (glibc does not cache, so every
/// `getaddrinfo` is a query and parallel connections to one host are normal),
/// and a loop blows past it inside a millisecond because each hop multiplies.
const LOOP_LIMIT: u32 = 10;
const LOOP_WINDOW: Duration = Duration::from_secs(5);

/// Cap on distinct names tracked at once, so a host resolving endlessly many
/// names cannot grow the map without bound. Well above the working set a loop
/// produces (a loop hammers *one* name), so eviction never hides one.
const LOOP_GUARD_MAX_NAMES: usize = 1024;

impl Resolver {
    pub fn new(table: HostnameTable, reverse: ReverseLookupTable) -> Self {
        Self {
            table,
            reverse,
            upstreams: Arc::new(ArcSwap::from_pointee(Vec::new())),
            tunnel_upstreams: Arc::new(ArcSwapOption::empty()),
            ipv6_only: AtomicBool::new(false),
            overlay_forwards: DashMap::new(),
            defer_off_mesh: AtomicBool::new(false),
        }
    }

    /// Override the upstream set for as long as a full tunnel is up, or with
    /// `None` go back to the captured one.
    ///
    /// A layer rather than a write to `upstreams`, so teardown restores what the
    /// system capture found without having to re-detect the OS DNS backend.
    ///
    /// It exists for the IPv6-only client tunnel. The daemon forwards non-`.ray`
    /// queries itself, and every upstream the desktop capture can produce is IPv4
    /// (`DnsConfigurator::captured_upstreams`), while that tunnel carries IPv6
    /// alone: left as they are, the exit node would see the traffic and none of
    /// the lookups that steered it. Pointing the forwarder at an IPv6 resolver
    /// puts the queries back inside the tunnel.
    ///
    /// Filters the magic IPs for the same reason [`Self::set_upstream_addrs`]
    /// does: `dns_upstreams` now accepts any `IpAddr`, so `ray config set
    /// dns-upstreams 200::53` would otherwise hand the forwarder its own address
    /// and every miss would recurse through `handle_tun_query`.
    ///
    /// It governs only what *we* forward, so it does nothing on a host that
    /// declines off-mesh names ([`Self::set_defer_off_mesh`]): there the stub
    /// asks the next `nameserver` itself and never reaches the forwarder. That
    /// combination is not hypothetical, it is the same host this mode exists
    /// for, so `apply_exit_dns` warns about it rather than leaving the override
    /// looking effective.
    pub fn set_tunnel_upstreams(&self, addrs: Option<Vec<SocketAddr>>) {
        // An override that filters down to nothing becomes no override: `forward`
        // reads an empty list as "no upstream configured" and refuses, where
        // falling back to the captured ones at least resolves something.
        let addrs = addrs
            .map(|v| {
                v.into_iter()
                    .filter(|a| !is_magic_dns(a.ip()))
                    .collect::<Vec<_>>()
            })
            .filter(|v: &Vec<SocketAddr>| !v.is_empty());
        self.tunnel_upstreams.store(addrs.map(Arc::new));
    }

    /// Whether to decline names outside `.ray` instead of forwarding them.
    ///
    /// Only true while `/etc/resolv.conf` lists a live resolver after ours,
    /// which is what sharing the file with another mesh leaves behind. The stub
    /// then does the work the forwarder would have: glibc treats REFUSED as a
    /// failed server and asks the next `nameserver` line, so the query reaches
    /// the other resolver directly instead of being relayed by us. Off by
    /// default, because on an ordinary host ours is the only line in the file
    /// and declining would take the machine's DNS down.
    pub fn set_defer_off_mesh(&self, on: bool) {
        self.defer_off_mesh.store(on, Ordering::Relaxed);
    }

    /// Whether off-mesh names are being declined, for the callers that need to
    /// know the forwarder is out of the path.
    pub fn defers_off_mesh(&self) -> bool {
        self.defer_off_mesh.load(Ordering::Relaxed)
    }

    /// Record whether mesh IPv4 is usable on this node. Called once at daemon
    /// start; a setter rather than a `new` parameter so the mode stays out of
    /// every construction site.
    pub fn set_ipv6_only(&self, on: bool) {
        self.ipv6_only.store(on, Ordering::Relaxed);
    }

    /// Replace the upstream set (bare IPv4 on port 53), dropping the magic IP to
    /// avoid a forwarding loop. The desktop capture path uses this.
    pub fn set_upstreams(&self, servers: Vec<Ipv4Addr>) {
        self.set_upstream_addrs(servers.into_iter().map(|ip| SocketAddr::from((ip, 53u16))));
    }

    /// Replace the upstream set with explicit socket addresses (ip:port). Lets a
    /// caller point the resolver at a loopback proxy on a non-53 port: Android
    /// runs a local `DnsResolver.rawQuery` proxy so non-`.ray` lookups honor the
    /// system Private DNS (DoT/DoH) instead of being downgraded to cleartext :53.
    pub fn set_upstream_addrs(&self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let v: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| !is_magic_dns(a.ip()))
            .collect();
        self.upstreams.store(Arc::new(v));
    }

    pub fn upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams.load().as_ref().clone()
    }

    /// The tunnel override in force, if any. `None` means queries go to the
    /// captured upstreams.
    pub fn tunnel_upstreams(&self) -> Option<Vec<SocketAddr>> {
        self.tunnel_upstreams
            .load_full()
            .map(|v| v.as_ref().clone())
    }

    /// Answer from the roster, and fall back to the system resolver for
    /// everything the roster does not hold.
    ///
    /// The fallback is what makes a name that looks like a mesh name but isn't
    /// work: with a network called `dev` joined, `zed.dev` misses the roster and
    /// goes upstream to the real internet instead of failing. It does not apply
    /// inside `.ray`, where [`crate::dns::handle_query`] answers a miss itself.
    pub async fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        let ipv6_only = self.ipv6_only.load(Ordering::Relaxed);
        if let Some(local) =
            crate::dns::handle_query(query, &self.table, &self.reverse, ipv6_only).await
        {
            return Some(local);
        }
        // Sharing resolv.conf means the stub has another nameserver listed
        // after ours, and it will ask that one the moment we decline. Doing
        // that instead of forwarding is not a shortcut: relaying the host's
        // general DNS through us puts a userspace hop in front of every name,
        // flattens whatever the other resolver does natively (its own split
        // DNS, its own encrypted upstreams) into one plain UDP query, and is
        // the only reason two resolvers pointed at each other can loop.
        if self.defer_off_mesh.load(Ordering::Relaxed) {
            // `.ray` is ours to answer, misses included: passing those on would
            // hand a mesh name to the other resolver for the same failure.
            return crate::dns::nxdomain_if_in_zone(query).or_else(|| refused(query));
        }
        if let Some(forwarded) = self.forward(query).await {
            return Some(forwarded);
        }
        // Nobody to ask. A `.ray` name is still ours to fail.
        crate::dns::nxdomain_if_in_zone(query)
    }

    /// Answer a DNS query that arrived addressed to the magic IP via the TUN.
    /// UDP only; TCP is dropped (no userspace TCP handler yet).
    pub async fn handle_tun_query(
        &self,
        pkt: &[u8],
        info: &crate::firewall::PacketInfo,
        tun_tx: &tokio::sync::mpsc::Sender<bytes::Bytes>,
    ) {
        if info.protocol != 17 {
            return; // TCP/other: drop cleanly.
        }
        // UDP payload begins after the IP header + the 8-byte UDP header. IPv4's
        // header is IHL words long; IPv6's is a fixed 40 bytes (`parse_packet_info`
        // read the next-header field directly, so there are no extension headers
        // to walk past here).
        let ip_header_len = match info.dst_ip {
            IpAddr::V6(_) => 40,
            IpAddr::V4(_) => ((pkt.first().copied().unwrap_or(0) & 0x0f) as usize) * 4,
        };
        let payload_start = ip_header_len + 8;
        let Some(dns_query) = pkt.get(payload_start..) else {
            return;
        };
        let resp = match self.resolve(dns_query).await {
            Some(resp) => resp,
            // No upstream answered. Reply SERVFAIL instead of dropping: a dropped
            // query looks like packet loss, so the client retries until its own
            // timeout and the box appears to hang. SERVFAIL fails it immediately
            // and lets a resolver with a second nameserver move on to it.
            None => match servfail(dns_query) {
                Some(resp) => resp,
                None => return,
            },
        };
        if let Some(reply) = crate::dns::packet::build_udp_reply(info, &resp) {
            let _ = tun_tx.send(reply).await;
        }
    }

    async fn forward(&self, query: &[u8]) -> Option<Vec<u8>> {
        let tunnel = self.tunnel_upstreams.load_full();
        let upstreams = match &tunnel {
            Some(over) => Arc::clone(over),
            None => self.upstreams.load_full(),
        };
        if upstreams.is_empty() {
            tracing::warn!("no DNS upstream configured; cannot forward off-mesh queries");
            return None;
        }
        // The name is only needed to count loops, so it is parsed only when an
        // upstream could loop. A host with ordinary resolvers pays nothing.
        let name = upstreams
            .iter()
            .any(|a| crate::membership::is_overlay_ip(a.ip()))
            .then(|| query_name(query))
            .flatten();
        for up in upstreams.iter() {
            // Skip an overlay resolver that this name has already been bounced
            // off, and fall through to the next upstream (a real server, if the
            // capture found one) rather than feeding the loop another hop.
            if crate::membership::is_overlay_ip(up.ip()) && !self.loop_guard_allows(name.as_ref()) {
                continue;
            }
            match forward_once(query, *up, FORWARD_TIMEOUT).await {
                Ok(resp) => return Some(resp),
                Err(e) => tracing::debug!(upstream = %up, error = %e, "upstream DNS query failed"),
            }
        }
        tracing::warn!(upstreams = ?upstreams.as_ref(), "no DNS upstream answered");
        None
    }

    /// Count one forward of this query's name to another mesh's resolver, and
    /// say whether it is still under [`LOOP_LIMIT`] for the current window.
    ///
    /// Only asked about overlay upstreams, so the map hit stays off the path a
    /// host with ordinary resolvers takes. A query we could not parse a name
    /// out of is allowed: it is not the shape a loop has, and guessing would
    /// drop real traffic.
    fn loop_guard_allows(&self, name: Option<&SmolStr>) -> bool {
        let Some(name) = name else {
            return true;
        };
        let now = Instant::now();
        // Evict before inserting a new name, never on a hit, so a loop's own
        // entry cannot be swept out from under the count that is tripping.
        if self.overlay_forwards.len() >= LOOP_GUARD_MAX_NAMES
            && !self.overlay_forwards.contains_key(name.as_str())
        {
            self.overlay_forwards
                .retain(|_, (started, _)| now.duration_since(*started) < LOOP_WINDOW);
        }
        let mut entry = self
            .overlay_forwards
            .entry(name.clone())
            .or_insert((now, 0));
        let (started, count) = &mut *entry;
        if now.duration_since(*started) >= LOOP_WINDOW {
            // Window expired: start a fresh one. A loop that is still running
            // gets to send exactly one more burst before tripping again, which
            // is also what lets a genuinely transient trip heal.
            *started = now;
            *count = 1;
            return true;
        }
        *count += 1;
        if *count > LOOP_LIMIT {
            // Once per window, not once per query: a loop trips this thousands
            // of times a second.
            if *count == LOOP_LIMIT + 1 {
                tracing::warn!(
                    %name,
                    "another mesh's resolver has been sent this name {LOOP_LIMIT} times in \
                     {LOOP_WINDOW:?}; it is forwarding back to us, so no longer sending it there"
                );
            }
            return false;
        }
        true
    }
}

/// The first question's name in a DNS query, lowercased for comparison.
fn query_name(query: &[u8]) -> Option<SmolStr> {
    let packet = simple_dns::Packet::parse(query).ok()?;
    let name = packet.questions.first()?.qname.to_string();
    Some(SmolStr::new(name.to_ascii_lowercase()))
}

/// How long to wait for an upstream to answer a forwarded query.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to wait for an upstream to answer the liveness probe. Shorter than
/// [`FORWARD_TIMEOUT`]: this runs on the `ray up` path, once per candidate.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

async fn forward_once(query: &[u8], up: SocketAddr, wait: Duration) -> std::io::Result<Vec<u8>> {
    // Bind the upstream's own family: a `0.0.0.0` socket cannot reach an IPv6
    // resolver, which is the only kind a full tunnel in IPv6-only mode has.
    let bind: SocketAddr = match up {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(up).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(wait, sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream DNS timeout"))??;
    buf.truncate(n);
    Ok(buf)
}

/// True if `up` answers a DNS query at all.
///
/// Captured upstreams are only ever a *claim* about where DNS lives: on a box
/// whose resolv.conf is rendered by another manager the entry can be stale, and
/// forwarding to it silently blackholes every non-`.ray` name (see #111). Any
/// well-formed reply counts, including SERVFAIL: this asks "is something
/// listening", not "is it a good resolver", and a dead upstream answers nothing.
pub async fn probe_upstream(up: SocketAddr) -> bool {
    // `. NS`, the cheapest question every resolver understands, and one that
    // needs no upstream connectivity of its own to produce a reply.
    let query = [
        0x2b, 0x1d, // id (arbitrary, fixed: we only compare against the reply)
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // qdcount 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar count 0
        0x00, // qname: root
        0x00, 0x02, // qtype NS
        0x00, 0x01, // qclass IN
    ];
    match forward_once(&query, up, PROBE_TIMEOUT).await {
        // Match the transaction id so a stray datagram can't pass as an answer.
        Ok(resp) => resp.len() >= 12 && resp[..2] == query[..2],
        Err(_) => false,
    }
}

/// Filter `candidates` down to the ones that actually answer, probing them
/// concurrently so a set of dead entries costs one [`PROBE_TIMEOUT`], not one
/// per entry. Order is preserved: callers treat the first as preferred.
pub async fn live_upstreams(candidates: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let probes = candidates
        .iter()
        .map(|ip| async move { probe_upstream(SocketAddr::from((*ip, 53u16))).await });
    let alive = futures::future::join_all(probes).await;
    candidates
        .iter()
        .zip(alive)
        .filter_map(|(ip, ok)| ok.then_some(*ip))
        .collect()
}

/// Turn a query into a SERVFAIL response by flipping the header in place,
/// keeping the id, question, and any EDNS OPT so the client matches it to its
/// outstanding query. Editing the header beats decoding and re-encoding: it
/// can't drop a section we failed to model.
fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    resp[2] |= 0x80; // QR: this is a response
    resp[3] = 0x80 | 2; // RA=1, Z=0, RCODE=2 (server failure)
    Some(resp)
}

/// "Not mine, ask somebody else."
///
/// REFUSED rather than SERVFAIL because it is the true statement (we are
/// declining, not failing) and rather than silence because silence costs the
/// stub its whole timeout: glibc waits `timeout:5` twice before moving on,
/// while any of REFUSED/SERVFAIL/NOTIMP makes it try the next nameserver at
/// once. musl asks every server at once and discards the refusal.
fn refused(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut resp = query.to_vec();
    resp[2] |= 0x80; // QR: this is a response
    resp[3] = 0x80 | 5; // RA=1, Z=0, RCODE=5 (refused)
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question};

    fn build_a_query(name: &str) -> Vec<u8> {
        let mut pkt = Packet::new_query(1);
        pkt.set_flags(PacketFlag::RECURSION_DESIRED);
        pkt.questions.push(Question::new(
            Name::new_unchecked(name),
            QTYPE::TYPE(simple_dns::TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        pkt.build_bytes_vec().expect("build query")
    }

    /// Off-mesh names are declined, not forwarded, so the stub asks the next
    /// nameserver itself. `.ray` stays ours to answer either way, including the
    /// misses: sending those on would leak a mesh name to the other resolver
    /// and get the same failure back a round trip later.
    #[tokio::test]
    async fn declining_leaves_off_mesh_names_to_the_next_nameserver() {
        let upstream_answer = Ipv4Addr::new(93, 184, 216, 34);
        let up = fake_upstream(upstream_answer).await;

        let r = Resolver::new(HostnameTable::default(), ReverseLookupTable::default());
        r.set_upstream_addrs([up]);
        r.set_defer_off_mesh(true);

        let resp = r
            .resolve(&build_a_query("example.com"))
            .await
            .expect("a reply, not silence: a dropped query costs the stub its timeout");
        assert_eq!(
            Packet::parse(&resp).expect("parse").rcode(),
            simple_dns::RCODE::Refused,
            "declined, so glibc moves to the next nameserver at once"
        );
        assert!(
            !response_has_a(&resp, upstream_answer),
            "the upstream must not have been asked at all"
        );

        // A `.ray` name nobody holds is still ours to fail authoritatively.
        let resp = r
            .resolve(&build_a_query("nobody.homelab.ray"))
            .await
            .expect("local NXDOMAIN");
        assert_eq!(
            Packet::parse(&resp).expect("parse").rcode(),
            simple_dns::RCODE::NameError
        );
    }

    /// The circuit breaker opens for one name and only that name, and a query
    /// with no question in it is never what trips it.
    #[test]
    fn loop_guard_trips_on_the_looping_name_alone() {
        let r = Resolver::new(HostnameTable::default(), ReverseLookupTable::default());
        let looping = build_a_query("bounced.example.com");

        // Everything up to the limit goes through: a busy host asking for one
        // name repeatedly is normal, and this must not be a rate limit on it.
        for i in 1..=LOOP_LIMIT {
            assert!(
                r.loop_guard_allows(query_name(&looping).as_ref()),
                "forward {i} of {LOOP_LIMIT} should be allowed"
            );
        }
        assert!(
            !r.loop_guard_allows(query_name(&looping).as_ref()),
            "the forward past the limit is the one that stops"
        );
        // Still shut on the next query, or a loop would get a hop per query.
        assert!(!r.loop_guard_allows(query_name(&looping).as_ref()));

        // A different name is unaffected: the breaker is per-name, so one
        // looping lookup cannot take the host's other DNS down with it.
        assert!(r.loop_guard_allows(query_name(&build_a_query("fine.example.com")).as_ref()));

        // A malformed query has no name to count. Allowed, since dropping what
        // we cannot parse would fail real traffic to protect against a shape a
        // loop does not have.
        assert!(r.loop_guard_allows(query_name(&[0u8; 4]).as_ref()));
    }

    /// Names differing only in case are one name to DNS, so they have to be one
    /// counter here: a loop that varies the case would otherwise never trip.
    #[test]
    fn loop_guard_counts_a_name_case_insensitively() {
        let r = Resolver::new(HostnameTable::default(), ReverseLookupTable::default());
        for _ in 1..=5 {
            assert!(r.loop_guard_allows(query_name(&build_a_query("Mixed.Example.Com")).as_ref()));
            assert!(r.loop_guard_allows(query_name(&build_a_query("mixed.example.com")).as_ref()));
        }
        assert!(!r.loop_guard_allows(query_name(&build_a_query("MIXED.EXAMPLE.COM")).as_ref()));
    }

    fn response_has_a(bytes: &[u8], ip: Ipv4Addr) -> bool {
        let pkt = Packet::parse(bytes).expect("parse response");
        pkt.answers.iter().any(|rr| {
            if let simple_dns::rdata::RData::A(a) = &rr.rdata {
                Ipv4Addr::from(a.address) == ip
            } else {
                false
            }
        })
    }

    #[tokio::test]
    async fn handle_tun_query_injects_reply_for_ray_name() {
        use std::net::{IpAddr, Ipv4Addr};
        let table = crate::dns::new_hostname_table();
        let reverse = crate::dns::new_reverse_table();
        crate::dns::update_hostname(
            &table,
            &reverse,
            "homelab",
            "dario",
            Some(Ipv4Addr::new(100, 64, 0, 7)),
            "200::7".parse().unwrap(),
        )
        .await;
        let r = Resolver::new(table, reverse);

        // Build a full IPv4/UDP query packet to MAGIC_IP:53 (use build_udp_reply
        // in reverse: synthesize a query with src=app, dst=magic).
        let dns_query = build_a_query("dario.homelab.ray");
        let app = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)),
            dst_ip: IpAddr::V4(crate::dns::MAGIC_DNS_V4),
            protocol: 17,
            src_port: 50000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        let query_pkt = crate::dns::packet::build_udp_reply(
            &crate::firewall::PacketInfo {
                // reuse builder: swap so the produced packet is app->magic
                src_ip: app.dst_ip,
                dst_ip: app.src_ip,
                src_port: app.dst_port,
                dst_port: app.src_port,
                ..app
            },
            &dns_query,
        )
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let info = crate::firewall::parse_packet_info(&query_pkt).unwrap();
        r.handle_tun_query(&query_pkt, &info, &tx).await;

        let reply = rx.try_recv().expect("a reply was injected");
        let rinfo = crate::firewall::parse_packet_info(&reply).unwrap();
        assert_eq!(rinfo.src_ip, IpAddr::V4(crate::dns::MAGIC_DNS_V4));
        assert_eq!(rinfo.dst_port, 50000);
        assert!(response_has_a(&reply[28..], Ipv4Addr::new(100, 64, 0, 7)));
    }

    #[tokio::test]
    async fn handle_tun_query_drops_tcp() {
        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let info = crate::firewall::PacketInfo {
            src_ip: "100.64.0.5".parse().unwrap(),
            dst_ip: std::net::IpAddr::V4(crate::dns::MAGIC_DNS_V4),
            protocol: 6,
            src_port: 50000,
            dst_port: 53,
            tcp_flags: 0x02,
            icmp_type: 0,
            icmp_id: 0,
        };
        r.handle_tun_query(&[0u8; 40], &info, &tx).await;
        assert!(rx.try_recv().is_err(), "TCP must be dropped, no reply");
    }

    #[tokio::test]
    async fn ray_name_answered_locally_not_forwarded() {
        let table = crate::dns::new_hostname_table();
        let reverse = crate::dns::new_reverse_table();
        crate::dns::update_hostname(
            &table,
            &reverse,
            "homelab",
            "dario",
            Some(Ipv4Addr::new(100, 64, 0, 7)),
            "200::7".parse().unwrap(),
        )
        .await;
        let r = Resolver::new(table, reverse);
        // No upstreams set; a .ray name must still resolve locally.
        let query = build_a_query("dario.homelab.ray");
        let resp = r.resolve(&query).await.expect("local answer");
        assert!(response_has_a(&resp, Ipv4Addr::new(100, 64, 0, 7)));
    }

    /// A network named `dev` must not swallow `zed.dev`. The roster holds a
    /// `box` peer and no `zed`, so the lookup misses and falls back to the real
    /// internet, while `box.dev` still resolves to its mesh IP.
    #[tokio::test]
    async fn unknown_bare_network_name_falls_back_upstream() {
        let peer_ip = Ipv4Addr::new(100, 64, 0, 7);
        let table = crate::dns::new_hostname_table();
        let reverse = crate::dns::new_reverse_table();
        crate::dns::update_hostname(
            &table,
            &reverse,
            "dev",
            "box",
            Some(peer_ip),
            "200::7".parse().unwrap(),
        )
        .await;

        let upstream_answer = Ipv4Addr::new(93, 184, 216, 34);
        let up = fake_upstream(upstream_answer).await;
        let r = Resolver::new(table, reverse);
        r.set_upstream_addrs([up]);

        let resp = r
            .resolve(&build_a_query("zed.dev"))
            .await
            .expect("forwarded answer");
        assert!(
            response_has_a(&resp, upstream_answer),
            "a name no peer holds must come from the real DNS"
        );

        // The peer that does exist keeps resolving to the mesh, suffix or not.
        for name in ["box.dev", "box.dev.ray", "box.ray"] {
            let resp = r.resolve(&build_a_query(name)).await.expect("local answer");
            assert!(
                response_has_a(&resp, peer_ip),
                "{name} must resolve locally"
            );
        }
    }

    /// A `.ray` name nobody holds is failed here, never forwarded. The zone is
    /// ours, so even an upstream that would gladly answer must not be asked: its
    /// NXDOMAIN carries the public root's 86400 negative TTL, which would cache
    /// the name dead for a day once the roster does hold it.
    #[tokio::test]
    async fn unknown_ray_name_nxdomains_without_asking_upstream() {
        let upstream_answer = Ipv4Addr::new(93, 184, 216, 34);
        let up = fake_upstream(upstream_answer).await;
        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        r.set_upstream_addrs([up]);

        let resp = r
            .resolve(&build_a_query("nobody.ray"))
            .await
            .expect("local NXDOMAIN");
        assert!(
            !response_has_a(&resp, upstream_answer),
            "a `.ray` name must not be answered by the upstream"
        );
        let pkt = Packet::parse(&resp).expect("parse NXDOMAIN");
        assert_eq!(pkt.rcode(), simple_dns::RCODE::NameError);
    }

    /// Minimal upstream that answers every A query with `ip`. Returns its addr.
    async fn fake_upstream(ip: Ipv4Addr) -> SocketAddr {
        use simple_dns::{ResourceRecord, rdata::A, rdata::RData};

        let sock = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let query = Packet::parse(&buf[..n]).expect("parse query");
                let mut reply = Packet::new_reply(query.id());
                let qname = query.questions[0].qname.clone();
                reply.questions.push(query.questions[0].clone());
                reply.answers.push(ResourceRecord::new(
                    qname,
                    simple_dns::CLASS::IN,
                    60,
                    RData::A(A { address: ip.into() }),
                ));
                let bytes = reply.build_bytes_vec().expect("build reply");
                let _ = sock.send_to(&bytes, from).await;
            }
        });
        addr
    }

    /// The reporter path in #111: a non-`.ray` name must be forwarded to the
    /// captured upstream and the answer injected back into the TUN. Without
    /// this the host loses all DNS the moment Magic DNS takes over resolv.conf.
    #[tokio::test]
    async fn non_ray_name_is_forwarded_and_reply_injected() {
        use std::net::IpAddr;

        let upstream_answer = Ipv4Addr::new(93, 184, 216, 34);
        let up = fake_upstream(upstream_answer).await;

        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        r.set_upstream_addrs([up]);

        let dns_query = build_a_query("example.com");
        let app = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 69, 9, 225)),
            dst_ip: IpAddr::V4(crate::dns::MAGIC_DNS_V4),
            protocol: 17,
            src_port: 50000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        let query_pkt = crate::dns::packet::build_udp_reply(
            &crate::firewall::PacketInfo {
                src_ip: app.dst_ip,
                dst_ip: app.src_ip,
                src_port: app.dst_port,
                dst_port: app.src_port,
                ..app
            },
            &dns_query,
        )
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let info = crate::firewall::parse_packet_info(&query_pkt).unwrap();
        r.handle_tun_query(&query_pkt, &info, &tx).await;

        let reply = rx.try_recv().expect("forwarded answer injected into TUN");
        let rinfo = crate::firewall::parse_packet_info(&reply).unwrap();
        assert_eq!(rinfo.src_ip, IpAddr::V4(crate::dns::MAGIC_DNS_V4));
        assert_eq!(rinfo.dst_port, 50000);
        assert!(response_has_a(&reply[28..], upstream_answer));
    }

    /// A dead address: bind a socket to claim a port, then drop it, so nothing
    /// is listening there. Sending to it fails fast (loopback ICMP port
    /// unreachable) instead of waiting out the probe timeout.
    async fn dead_upstream() -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        sock.local_addr().unwrap()
    }

    #[tokio::test]
    async fn probe_accepts_a_live_upstream_and_rejects_a_dead_one() {
        let live = fake_upstream(Ipv4Addr::new(1, 2, 3, 4)).await;
        assert!(probe_upstream(live).await, "a listening resolver is live");
        assert!(
            !probe_upstream(dead_upstream().await).await,
            "nothing listening must not pass as a working upstream"
        );
    }

    #[tokio::test]
    async fn live_upstreams_preserves_order_of_survivors() {
        // No listener on the loopback addresses, so both are filtered out and
        // the caller is left with the empty set it needs to refuse on.
        assert!(
            live_upstreams(&[Ipv4Addr::new(127, 0, 0, 2)])
                .await
                .is_empty()
        );
        assert!(live_upstreams(&[]).await.is_empty());
    }

    /// #111: with no upstream that answers, a forwarded query must come back
    /// SERVFAIL rather than vanish. A dropped query is indistinguishable from
    /// packet loss, so the client retries until its own timeout and the box
    /// looks hung; SERVFAIL fails it immediately.
    #[tokio::test]
    async fn servfail_returned_when_no_upstream_answers() {
        use std::net::IpAddr;

        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        r.set_upstream_addrs([dead_upstream().await]);

        let dns_query = build_a_query("example.com");
        let app = crate::firewall::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(100, 69, 9, 225)),
            dst_ip: IpAddr::V4(crate::dns::MAGIC_DNS_V4),
            protocol: 17,
            src_port: 50000,
            dst_port: 53,
            tcp_flags: 0,
            icmp_type: 0,
            icmp_id: 0,
        };
        let query_pkt = crate::dns::packet::build_udp_reply(
            &crate::firewall::PacketInfo {
                src_ip: app.dst_ip,
                dst_ip: app.src_ip,
                src_port: app.dst_port,
                dst_port: app.src_port,
                ..app
            },
            &dns_query,
        )
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let info = crate::firewall::parse_packet_info(&query_pkt).unwrap();
        r.handle_tun_query(&query_pkt, &info, &tx).await;

        let reply = rx
            .try_recv()
            .expect("SERVFAIL injected, not a dropped query");
        let pkt = Packet::parse(&reply[28..]).expect("parse SERVFAIL");
        assert_eq!(pkt.rcode(), simple_dns::RCODE::ServerFailure);
        // The id and question have to survive or the client can't match the
        // response to its outstanding query and will ignore it.
        assert_eq!(pkt.id(), Packet::parse(&dns_query).unwrap().id());
        assert_eq!(pkt.questions.len(), 1);
    }

    #[test]
    fn servfail_rejects_a_runt_packet() {
        // Shorter than a DNS header: there is nothing to turn into a response.
        assert!(servfail(&[0u8; 11]).is_none());
    }

    #[tokio::test]
    async fn upstream_dropped_when_equal_to_magic_ip() {
        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        r.set_upstreams(vec![crate::dns::MAGIC_DNS_V4, Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(
            r.upstreams(),
            vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn set_upstream_addrs_keeps_custom_port_and_drops_magic() {
        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        // A loopback rawQuery proxy on a non-53 port survives; the magic IP is
        // still filtered regardless of the port it carries.
        r.set_upstream_addrs([
            "127.0.0.1:5353".parse::<SocketAddr>().unwrap(),
            SocketAddr::from((crate::dns::MAGIC_DNS_V4, 5353)),
        ]);
        assert_eq!(
            r.upstreams(),
            vec!["127.0.0.1:5353".parse::<SocketAddr>().unwrap()]
        );
    }

    /// The tunnel override wins while it is set, and `None` puts the captured
    /// upstreams back without re-detecting the OS DNS backend.
    #[tokio::test]
    async fn tunnel_override_wins_and_clears() {
        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        let captured = "192.168.1.1:53".parse::<SocketAddr>().unwrap();
        let v6 = "[2606:4700:4700::1111]:53".parse::<SocketAddr>().unwrap();
        r.set_upstream_addrs([captured]);
        assert_eq!(r.tunnel_upstreams(), None);

        r.set_tunnel_upstreams(Some(vec![v6]));
        assert_eq!(r.tunnel_upstreams(), Some(vec![v6]));
        // Layered, not written through: teardown has to find these unchanged.
        assert_eq!(r.upstreams(), vec![captured]);

        r.set_tunnel_upstreams(None);
        assert_eq!(r.tunnel_upstreams(), None);
        assert_eq!(r.upstreams(), vec![captured]);
    }

    /// The override takes the same magic-IP filter as the capture path, because
    /// `dns_upstreams` now accepts any `IpAddr` and `200::53` is a loop back into
    /// our own responder. Filtering to empty means no override at all, not an
    /// override with nowhere to send.
    #[tokio::test]
    async fn tunnel_override_drops_the_magic_ips() {
        let r = Resolver::new(
            crate::dns::new_hostname_table(),
            crate::dns::new_reverse_table(),
        );
        let v6 = "[2606:4700:4700::1111]:53".parse::<SocketAddr>().unwrap();
        r.set_tunnel_upstreams(Some(vec![
            SocketAddr::from((crate::dns::MAGIC_DNS_V6, 53)),
            v6,
        ]));
        assert_eq!(r.tunnel_upstreams(), Some(vec![v6]));

        r.set_tunnel_upstreams(Some(vec![
            SocketAddr::from((crate::dns::MAGIC_DNS_V6, 53)),
            SocketAddr::from((crate::dns::MAGIC_DNS_V4, 53)),
        ]));
        assert_eq!(r.tunnel_upstreams(), None);
    }
}
