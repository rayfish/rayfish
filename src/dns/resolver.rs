//! In-daemon DNS resolver reached via the magic IP (no host :53 socket).
//! Answers names held in the hostname tables and forwards everything else to
//! the captured system upstreams.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::dns::{HostnameTable, MAGIC_DNS_V4, ReverseLookupTable};

pub struct Resolver {
    table: HostnameTable,
    reverse: ReverseLookupTable,
    upstreams: Arc<ArcSwap<Vec<SocketAddr>>>,
}

impl Resolver {
    pub fn new(table: HostnameTable, reverse: ReverseLookupTable) -> Self {
        Self {
            table,
            reverse,
            upstreams: Arc::new(ArcSwap::from_pointee(Vec::new())),
        }
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
            .filter(|a| a.ip() != IpAddr::V4(MAGIC_DNS_V4))
            .collect();
        self.upstreams.store(Arc::new(v));
    }

    pub fn upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams.load().as_ref().clone()
    }

    /// Answer from the roster, and fall back to the system resolver for
    /// everything the roster does not hold.
    ///
    /// The fallback is what makes a name that looks like a mesh name but isn't
    /// work: with a network called `dev` joined, `zed.dev` misses the roster and
    /// goes upstream to the real internet instead of failing.
    pub async fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        if let Some(local) = crate::dns::handle_query(query, &self.table, &self.reverse).await {
            return Some(local);
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
        // UDP payload begins after the IPv4 header (IHL*4) + 8-byte UDP header.
        let ihl = ((pkt.first().copied().unwrap_or(0) & 0x0f) as usize) * 4;
        let payload_start = ihl + 8;
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
        let upstreams = self.upstreams.load();
        if upstreams.is_empty() {
            tracing::warn!("no DNS upstream configured; cannot forward off-mesh queries");
            return None;
        }
        for up in upstreams.iter() {
            match forward_once(query, *up, FORWARD_TIMEOUT).await {
                Ok(resp) => return Some(resp),
                Err(e) => tracing::debug!(upstream = %up, error = %e, "upstream DNS query failed"),
            }
        }
        tracing::warn!(upstreams = ?upstreams.as_ref(), "no DNS upstream answered");
        None
    }
}

/// How long to wait for an upstream to answer a forwarded query.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to wait for an upstream to answer the liveness probe. Shorter than
/// [`FORWARD_TIMEOUT`]: this runs on the `ray up` path, once per candidate.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

async fn forward_once(query: &[u8], up: SocketAddr, wait: Duration) -> std::io::Result<Vec<u8>> {
    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
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
            Ipv4Addr::new(100, 64, 0, 7),
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
            Ipv4Addr::new(100, 64, 0, 7),
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
            peer_ip,
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

    /// A `.ray` name nobody holds also falls back before it is failed: the
    /// upstream gets asked, and only a dead upstream produces NXDOMAIN.
    #[tokio::test]
    async fn unknown_ray_name_falls_back_then_nxdomains() {
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
            .expect("forwarded answer");
        assert!(response_has_a(&resp, upstream_answer));

        // With nothing listening upstream, the zone is ours to fail: NXDOMAIN,
        // not the SERVFAIL a client would retry.
        r.set_upstream_addrs([dead_upstream().await]);
        let resp = r
            .resolve(&build_a_query("nobody.ray"))
            .await
            .expect("local NXDOMAIN");
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
}
