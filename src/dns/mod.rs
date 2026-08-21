//! Magic DNS for the `.ray` TLD.
//!
//! This module (`mod.rs`) is the roster responder: it answers A, AAAA, PTR, and
//! SOA queries for peer names. The resolver is reached via a magic IP
//! (`MAGIC_DNS_V4` = 100.100.100.53) routed through the TUN, no host-level port
//! 53 bind is made: `forward::run_mesh` intercepts UDP DNS packets destined for
//! the magic IP and hands them to [`resolver::Resolver`], which calls
//! [`handle_query`] and forwards whatever it declines to the system upstreams.
//!
//! Outside `.ray` a name is answered only when the roster actually holds it: a
//! `<host>.<network>` whose host is not a peer is declined so it can fall back
//! to the real DNS. Inside `.ray` every name is answered here, a miss included,
//! because no upstream can resolve a `.ray` name and only we can say it is gone.
//!
//! Submodules: [`config`] (OS resolver integration), [`resolver`] (in-daemon
//! resolver reached via the magic IP), [`packet`] (UDP reply synthesis).

pub mod config;
pub mod packet;
pub mod resolver;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock;

use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, rdata::AAAA, rdata::OPT,
    rdata::RData, rdata::SOA,
};

use crate::DNS_DOMAIN;

/// Reserved virtual IPv4 for the in-daemon Magic DNS resolver. It lives in the
/// `100.64.0.0/10` peer range (so the existing TUN route delivers packets to it)
/// but is NEVER assigned to a member and NEVER bound as a local interface
/// address, it is reachable only by being routed into the TUN, which is what
/// lets us answer DNS without competing for the host's port 53. Distinct from
/// Tailscale's 100.100.100.100 so both can coexist.
pub const MAGIC_DNS_V4: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 53);

/// The same resolver, addressed inside our own IPv6 range. The only address the
/// OS is ever pointed at: the overlay carries no IPv4.
///
/// The v4 address above is unusable on the hosts we run on. Tailscale
/// installs an anti-spoof rule (`-s 100.64.0.0/10 ! -i tailscale0 -j DROP`) that
/// drops anything sourced from the CGNAT range arriving on another interface,
/// and our reply is synthesized with the magic IP as its source and injected
/// into the TUN. The host route delivers the query fine; the reply dies in
/// netfilter, so `.ray` resolution just times out. `200::/7` is ours alone and
/// nothing filters it.
///
/// Needs no host route of its own: [`crate::tun::route_peer_range`] already
/// points all of `200::/7` at the TUN. Never assigned to a member, like the v4
/// one, though here that is a statement of intent rather than a guard:
/// [`crate::membership::derive_ipv6`] would have to hash to these exact 15 bytes.
pub const MAGIC_DNS_V6: Ipv6Addr = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0x53);

/// Per-network hostname to mesh IPv6 mapping. There is no second address to
/// hold: the overlay is IPv6-only, and a peer's address is derived from its
/// identity, so a name either resolves to one or the roster does not hold it.
pub type HostnameEntry = Ipv6Addr;
pub type HostnameTable = Arc<RwLock<HashMap<String, HashMap<String, HostnameEntry>>>>;

/// Reverse lookup: IP → (hostname, network).
pub type ReverseLookupTable = Arc<DashMap<IpAddr, (String, String)>>;

pub fn new_hostname_table() -> HostnameTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn new_reverse_table() -> ReverseLookupTable {
    Arc::new(DashMap::new())
}

/// Update both the hostname table and reverse lookup table atomically.
pub async fn update_hostname(
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
    network: &str,
    hostname: &str,
    ipv6: Ipv6Addr,
) {
    {
        let mut t = table.write().await;
        let hosts = t.entry(network.to_string()).or_default();
        hosts.insert(hostname.to_string(), ipv6);
    }
    reverse.insert(
        IpAddr::V6(ipv6),
        (hostname.to_string(), network.to_string()),
    );
}

/// Remove a hostname by IP address from both tables.
pub async fn remove_hostname_by_ip(
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
    network: &str,
    ipv6: Ipv6Addr,
) {
    let mut t = table.write().await;
    if let Some(hosts) = t.get_mut(network) {
        hosts.retain(|_, v6| {
            if *v6 == ipv6 {
                reverse.remove(&IpAddr::V6(ipv6));
                false
            } else {
                true
            }
        });
    }
}

/// Replace all hostname entries for a network with `entries`, rebuilding the
/// reverse-lookup entries to match. Used when a roster update (MemberSync or
/// group blob) arrives so renamed, added, and removed peers all reflect
/// immediately: the roster is the single source of truth for DNS.
pub async fn sync_network_hostnames(
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
    network: &str,
    entries: &[(String, Ipv6Addr)],
) {
    let mut t = table.write().await;
    // Drop reverse entries for the network's previous set before rebuilding.
    if let Some(old) = t.get(network) {
        for v6 in old.values() {
            reverse.remove(&IpAddr::V6(*v6));
        }
    }
    let mut hosts = HashMap::with_capacity(entries.len());
    for (name, v6) in entries {
        hosts.insert(name.clone(), *v6);
        reverse.insert(IpAddr::V6(*v6), (name.clone(), network.to_string()));
    }
    t.insert(network.to_string(), hosts);
}

/// Remove all hostnames for a network from both tables.
pub async fn remove_network(table: &HostnameTable, reverse: &ReverseLookupTable, network: &str) {
    let mut t = table.write().await;
    if let Some(hosts) = t.remove(network) {
        for (_, ipv6) in hosts {
            reverse.remove(&IpAddr::V6(ipv6));
        }
    }
}

/// Answer a query from the roster, or return `None` for "not mine": the caller
/// forwards those to the system resolver.
///
/// Outside `.ray` we claim a name only when we can actually answer it. That is
/// what keeps a network named `dev` from swallowing `zed.dev`: the lookup misses
/// the roster, we decline it, and it goes upstream like any public name.
///
/// Inside `.ray` the zone is ours whether or not the roster holds the name, so
/// a miss is answered here with NXDOMAIN rather than declined. Declining it
/// would put a public resolver's 86400 negative TTL on a name only we can ever
/// resolve.
///
/// An A query is always NODATA: the overlay carries no IPv4, so there is no
/// record of that type to hand out. NODATA rather than NXDOMAIN because the name
/// exists, and NXDOMAIN would fail the AAAA alongside it in most stub resolvers.
pub(crate) async fn handle_query(
    data: &[u8],
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
) -> Option<Vec<u8>> {
    let packet = Packet::parse(data).ok()?;

    let question = packet.questions.first()?;
    let name_str = question.qname.to_string();
    let name_lower = name_str.trim_end_matches('.').to_lowercase();

    let is_a = question.qtype == QTYPE::TYPE(simple_dns::TYPE::A);
    let is_aaaa = question.qtype == QTYPE::TYPE(simple_dns::TYPE::AAAA);
    let is_ptr = question.qtype == QTYPE::TYPE(simple_dns::TYPE::PTR);
    let is_soa = question.qtype == QTYPE::TYPE(simple_dns::TYPE::SOA);

    // PTR queries for in-addr.arpa / ip6.arpa
    if is_ptr {
        return handle_ptr_query(&packet, &name_lower, reverse).await;
    }

    let suffix = format!(".{DNS_DOMAIN}");

    if name_lower == DNS_DOMAIN || name_lower.ends_with(&suffix) {
        // Inside `.ray`, the zone is ours.
        if is_soa {
            return Some(make_soa_response(&packet, &question.qname));
        }
        // A miss here is an authoritative answer, not a reason to ask the
        // internet. `.ray` is not a delegated TLD, so a forwarded query can only
        // come back NXDOMAIN carrying the root's SOA and its 86400 negative TTL.
        // Trading our own 60s SOA for that turns a roster still filling in at
        // startup into a name the OS caches as dead for a day.
        let Some(v6) = resolve_name(&name_lower, &suffix, table).await else {
            tracing::info!(name = %name_lower, "DNS query NXDOMAIN");
            return Some(make_nxdomain(&packet));
        };
        if is_a {
            // The overlay carries no IPv4, so there is never an A record to give.
            // NODATA and not NXDOMAIN: the name exists, and NXDOMAIN here would
            // fail the AAAA lookup alongside it.
            tracing::debug!(name = %name_lower, "DNS A withheld (no mesh IPv4)");
            return Some(make_nodata(&packet));
        }
        if is_aaaa {
            tracing::info!(name = %name_lower, ip = %v6, "DNS resolved AAAA");
            return Some(make_aaaa_response(&packet, &question.qname, v6));
        }
        // The peer exists but holds no record of this type. NODATA is the
        // authoritative answer; no upstream knows better.
        return Some(make_nodata(&packet));
    }

    // Outside `.ray`, `<host>.<network>` is also a perfectly good public name,
    // so we take it only for A/AAAA and only when the peer is really there.
    if !(is_a || is_aaaa) {
        return None;
    }
    let v6 = resolve_bare_network_name(&name_lower, table).await?;
    if is_a {
        // The roster holds the name, so this is ours to answer even though we
        // have no address of that family; going upstream would resolve a mesh
        // peer to whatever public name happens to collide with it.
        tracing::debug!(name = %name_lower, "DNS A withheld (no mesh IPv4)");
        Some(make_nodata(&packet))
    } else {
        tracing::info!(name = %name_lower, ip = %v6, "DNS resolved AAAA");
        Some(make_aaaa_response(&packet, &question.qname, v6))
    }
}

/// NXDOMAIN for a `.ray` name, used when the upstream fallback found nobody to
/// ask. The zone is ours, so failing it closed beats the SERVFAIL a client
/// would otherwise keep retrying. Returns `None` for any other name.
pub(crate) fn nxdomain_if_in_zone(data: &[u8]) -> Option<Vec<u8>> {
    let packet = Packet::parse(data).ok()?;
    let name = packet.questions.first()?.qname.to_string();
    let name_lower = name.trim_end_matches('.').to_lowercase();
    if name_lower != DNS_DOMAIN && !name_lower.ends_with(&format!(".{DNS_DOMAIN}")) {
        return None;
    }
    tracing::info!(name = %name_lower, "DNS query NXDOMAIN");
    Some(make_nxdomain(&packet))
}

async fn handle_ptr_query(
    packet: &Packet<'_>,
    name: &str,
    reverse: &ReverseLookupTable,
) -> Option<Vec<u8>> {
    let ip = parse_ptr_name(name)?;

    if let Some(entry) = reverse.get(&ip) {
        let (hostname, network) = entry.value();
        let fqdn = format!("{hostname}.{network}.{DNS_DOMAIN}.");
        tracing::info!(ip = %ip, name = %fqdn, "DNS resolved PTR");
        return Some(make_ptr_response(packet, &packet.questions[0].qname, &fqdn));
    }

    // If IP is in our range but not found, NXDOMAIN. `100.64.0.0/10` is not ours
    // to speak for: it belongs to whichever VPN we are sharing the host with, and
    // answering an authoritative NXDOMAIN would break reverse lookups for its
    // nodes. Only reachable when we are the system-wide resolver; with split DNS,
    // `in-addr.arpa` is not routed to us at all.
    match ip {
        IpAddr::V4(_) => {}
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // 200::/7
            if (segments[0] & 0xFE00) == 0x0200 {
                tracing::info!(ip = %ip, "DNS PTR NXDOMAIN (our range)");
                return Some(make_nxdomain(packet));
            }
        }
    }

    // A PTR for an address outside our ranges: not ours, let it go upstream.
    None
}

/// Resolve `<hostname>.<network>` (no `.ray` suffix), the form an app uses when
/// the network name doubles as a search domain. Only a real roster hit counts:
/// a miss leaves the name to the system resolver.
async fn resolve_bare_network_name(name: &str, table: &HostnameTable) -> Option<HostnameEntry> {
    let (hostname, network) = name.rsplit_once('.')?;
    let table_guard = table.read().await;
    table_guard.get(network)?.get(hostname).copied()
}

fn parse_ptr_name(name: &str) -> Option<IpAddr> {
    if let Some(stripped) = name.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = stripped.split('.').collect();
        if parts.len() == 4 {
            let a: u8 = parts[3].parse().ok()?;
            let b: u8 = parts[2].parse().ok()?;
            let c: u8 = parts[1].parse().ok()?;
            let d: u8 = parts[0].parse().ok()?;
            return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
        }
    }

    if let Some(stripped) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = stripped.split('.').collect();
        if nibbles.len() == 32 {
            let mut octets = [0u8; 16];
            for i in 0..16 {
                let hi = u8::from_str_radix(nibbles[31 - i * 2], 16).ok()?;
                let lo = u8::from_str_radix(nibbles[31 - i * 2 - 1], 16).ok()?;
                octets[i] = (hi << 4) | lo;
            }
            return Some(IpAddr::V6(Ipv6Addr::from(octets)));
        }
    }

    None
}

pub async fn resolve_name(
    name: &str,
    suffix: &str,
    table: &HostnameTable,
) -> Option<HostnameEntry> {
    let stripped = name.strip_suffix(suffix)?;
    let table_guard = table.read().await;

    // Try <hostname>.<network>.ray
    if let Some((hostname, network)) = stripped.rsplit_once('.')
        && let Some(network_hosts) = table_guard.get(network)
    {
        return network_hosts.get(hostname).copied();
    }

    // Try <hostname>.ray (search all networks, return first match)
    for network_hosts in table_guard.values() {
        if let Some(entry) = network_hosts.get(stripped) {
            return Some(*entry);
        }
    }

    None
}

fn pi_soa<'a>() -> SOA<'a> {
    SOA {
        mname: Name::new_unchecked("ns.ray"),
        rname: Name::new_unchecked("admin.ray"),
        serial: 1,
        refresh: 3600,
        retry: 600,
        expire: 86400,
        minimum: 60,
    }
}

fn finalize_response(response: &mut Packet, query: &Packet) {
    if query.opt().is_some() {
        *response.opt_mut() = Some(OPT {
            opt_codes: vec![],
            udp_packet_size: 1232,
            version: 0,
        });
    }
}

fn make_aaaa_response(query: &Packet, qname: &Name, ip: Ipv6Addr) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    response.answers.push(ResourceRecord::new(
        qname.clone(),
        CLASS::IN,
        60,
        RData::AAAA(AAAA {
            address: u128::from(ip),
        }),
    ));
    finalize_response(&mut response, query);
    response.build_bytes_vec().unwrap_or_default()
}

fn make_ptr_response(query: &Packet, qname: &Name, hostname: &str) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    response.answers.push(ResourceRecord::new(
        qname.clone(),
        CLASS::IN,
        60,
        RData::PTR(simple_dns::rdata::PTR(Name::new_unchecked(hostname))),
    ));
    finalize_response(&mut response, query);
    response.build_bytes_vec().unwrap_or_default()
}

fn make_soa_response(query: &Packet, qname: &Name) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    response.answers.push(ResourceRecord::new(
        qname.clone(),
        CLASS::IN,
        60,
        RData::SOA(pi_soa()),
    ));
    finalize_response(&mut response, query);
    response.build_bytes_vec().unwrap_or_default()
}

fn make_nxdomain(query: &Packet) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    *response.rcode_mut() = RCODE::NameError;
    response.name_servers.push(ResourceRecord::new(
        Name::new_unchecked(DNS_DOMAIN),
        CLASS::IN,
        60,
        RData::SOA(pi_soa()),
    ));
    finalize_response(&mut response, query);
    response.build_bytes_vec().unwrap_or_default()
}

fn make_nodata(query: &Packet) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    response.name_servers.push(ResourceRecord::new(
        Name::new_unchecked(DNS_DOMAIN),
        CLASS::IN,
        60,
        RData::SOA(pi_soa()),
    ));
    finalize_response(&mut response, query);
    response.build_bytes_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUFFIX: &str = ".ray";

    /// A mesh address in `200::/7`, distinct per `n`.
    fn v6(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, n)
    }

    fn entry(v6: Ipv6Addr) -> HostnameEntry {
        v6
    }

    #[tokio::test]
    async fn test_resolve_with_network() {
        let table = new_hostname_table();
        {
            let mut t = table.write().await;
            let mut hosts = HashMap::new();
            hosts.insert("alice".to_string(), entry(v6(5)));
            t.insert("gaming".to_string(), hosts);
        }
        let result = resolve_name("alice.gaming.ray", SUFFIX, &table).await;
        assert_eq!(result, Some(v6(5)));
    }

    #[tokio::test]
    async fn test_sync_network_hostnames_rename_and_remove() {
        let table = new_hostname_table();
        let reverse = new_reverse_table();
        let v6 = |n: u16| Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, n);

        // Initial roster: alice + bob.
        sync_network_hostnames(
            &table,
            &reverse,
            "net",
            &[("alice".to_string(), v6(1)), ("bob".to_string(), v6(2))],
        )
        .await;
        assert_eq!(
            resolve_name("alice.net.ray", SUFFIX, &table).await,
            Some(v6(1))
        );
        assert_eq!(
            reverse.get(&IpAddr::V6(v6(1))).map(|e| e.0.clone()),
            Some("alice".to_string())
        );

        // alice renames to dario; bob leaves.
        sync_network_hostnames(&table, &reverse, "net", &[("dario".to_string(), v6(1))]).await;
        assert_eq!(
            resolve_name("dario.net.ray", SUFFIX, &table).await,
            Some(v6(1))
        );
        // Old name and departed peer no longer resolve; reverse is rebuilt.
        assert_eq!(resolve_name("alice.net.ray", SUFFIX, &table).await, None);
        assert_eq!(resolve_name("bob.net.ray", SUFFIX, &table).await, None);
        assert_eq!(reverse.get(&IpAddr::V6(v6(2))).map(|e| e.0.clone()), None);
        assert_eq!(
            reverse.get(&IpAddr::V6(v6(1))).map(|e| e.0.clone()),
            Some("dario".to_string())
        );
    }

    #[tokio::test]
    async fn test_resolve_flat() {
        let table = new_hostname_table();
        {
            let mut t = table.write().await;
            let mut hosts = HashMap::new();
            hosts.insert("bob".to_string(), entry(v6(3)));
            t.insert("work".to_string(), hosts);
        }
        let result = resolve_name("bob.ray", SUFFIX, &table).await;
        assert_eq!(result, Some(v6(3)));
    }

    #[tokio::test]
    async fn test_resolve_unknown() {
        let table = new_hostname_table();
        let result = resolve_name("nobody.ray", SUFFIX, &table).await;
        assert_eq!(result, None);
    }

    /// The mesh IPv4 is not routed on any node, so an A record would point an
    /// app at an address owned by another VPN. The name still resolves over
    /// IPv6, and NODATA (not NXDOMAIN) is what keeps it that way.
    #[tokio::test]
    async fn ipv6_only_withholds_a_but_still_answers_aaaa() {
        use simple_dns::{CLASS as C, PacketFlag, QCLASS, Question};

        let table = new_hostname_table();
        let reverse = new_reverse_table();
        update_hostname(&table, &reverse, "dev", "box", v6(5)).await;

        let query = |name: &str, qtype: QTYPE| {
            let mut pkt = Packet::new_query(1);
            pkt.set_flags(PacketFlag::RECURSION_DESIRED);
            pkt.questions.push(Question::new(
                Name::new_unchecked(name).into_owned(),
                qtype,
                QCLASS::CLASS(C::IN),
                false,
            ));
            pkt.build_bytes_vec().expect("build query")
        };
        let a = QTYPE::TYPE(simple_dns::TYPE::A);
        let aaaa = QTYPE::TYPE(simple_dns::TYPE::AAAA);
        let ask = async |name: &str, qtype| {
            handle_query(&query(name, qtype), &table, &reverse)
                .await
                .expect("the roster holds this name, so it is ours to answer")
        };

        // A: answered, but with nothing in it. NOERROR keeps the stub resolver
        // going to the AAAA instead of failing the name outright.
        for name in ["box.dev.ray", "box.dev"] {
            let bytes = ask(name, a).await;
            let resp = Packet::parse(&bytes).expect("parse response");
            assert_eq!(resp.rcode(), RCODE::NoError, "{name} should be NODATA");
            assert!(resp.answers.is_empty(), "{name} must not carry an A record");
        }

        // AAAA still resolves: this is the address that actually carries traffic.
        let bytes = ask("box.dev.ray", aaaa).await;
        let resp = Packet::parse(&bytes).expect("parse response");
        assert_eq!(resp.answers.len(), 1);
        assert!(
            matches!(resp.answers[0].rdata, RData::AAAA(ref got) if Ipv6Addr::from(got.address) == v6(5))
        );

        // A PTR for the CGNAT range belongs to whichever VPN owns it here, so we
        // decline rather than claiming an authoritative NXDOMAIN for its nodes.
        assert!(
            handle_query(
                &query(
                    "9.0.64.100.in-addr.arpa",
                    QTYPE::TYPE(simple_dns::TYPE::PTR)
                ),
                &table,
                &reverse,
            )
            .await
            .is_none()
        );
        // Our own IPv6 range is still ours to speak for.
        assert!(
            handle_query(
                &query(
                    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.ip6.arpa",
                    QTYPE::TYPE(simple_dns::TYPE::PTR)
                ),
                &table,
                &reverse,
            )
            .await
            .is_some()
        );
    }

    /// The other half of the same rule, seen from the peer's side: a peer is
    /// held in the table with no IPv4, so we withhold its A record too.
    #[tokio::test]
    async fn peer_without_ipv4_gets_no_a_record() {
        use simple_dns::{CLASS as C, PacketFlag, QCLASS, Question};

        let table = new_hostname_table();
        let reverse = new_reverse_table();
        update_hostname(&table, &reverse, "dev", "box", v6(9)).await;

        let query = |qtype: QTYPE| {
            let mut pkt = Packet::new_query(1);
            pkt.set_flags(PacketFlag::RECURSION_DESIRED);
            pkt.questions.push(Question::new(
                Name::new_unchecked("box.dev.ray").into_owned(),
                qtype,
                QCLASS::CLASS(C::IN),
                false,
            ));
            pkt.build_bytes_vec().expect("build query")
        };

        let bytes = handle_query(&query(QTYPE::TYPE(simple_dns::TYPE::A)), &table, &reverse)
            .await
            .expect("the roster holds the name");
        let resp = Packet::parse(&bytes).expect("parse response");
        assert_eq!(resp.rcode(), RCODE::NoError);
        assert!(resp.answers.is_empty());

        let bytes = handle_query(
            &query(QTYPE::TYPE(simple_dns::TYPE::AAAA)),
            &table,
            &reverse,
        )
        .await
        .expect("the roster holds the name");
        let resp = Packet::parse(&bytes).expect("parse response");
        assert_eq!(resp.answers.len(), 1);

        // Nothing claims an IPv4 reverse entry for a peer that has no IPv4.
        assert!(!reverse.iter().any(|e| e.key().is_ipv4()));
    }

    /// The decline contract: `handle_query` returns `None` for anything the
    /// roster does not hold, which is what lets the caller fall back upstream.
    #[tokio::test]
    async fn declines_what_the_roster_does_not_hold() {
        use simple_dns::{CLASS as C, PacketFlag, QCLASS, Question};

        let table = new_hostname_table();
        let reverse = new_reverse_table();
        update_hostname(&table, &reverse, "dev", "box", v6(5)).await;

        let query = |name: &str, qtype: QTYPE| {
            let mut pkt = Packet::new_query(1);
            pkt.set_flags(PacketFlag::RECURSION_DESIRED);
            pkt.questions.push(Question::new(
                Name::new_unchecked(name).into_owned(),
                qtype,
                QCLASS::CLASS(C::IN),
                false,
            ));
            pkt.build_bytes_vec().expect("build query")
        };
        let a = QTYPE::TYPE(simple_dns::TYPE::A);
        let declined = |name: &'static str, qtype| {
            let (table, reverse) = (table.clone(), reverse.clone());
            async move {
                handle_query(&query(name, qtype), &table, &reverse)
                    .await
                    .is_none()
            }
        };

        // A public name that collides with the network name, the case this
        // exists for: `box` is a peer, `zed` is not.
        assert!(declined("zed.dev", a).await);
        assert!(!declined("box.dev", a).await);
        // MX for a peer name outside `.ray` stays a public question.
        assert!(declined("box.dev", QTYPE::TYPE(simple_dns::TYPE::MX)).await);
        // An unknown `.ray` name is ours to fail, never upstream's to answer.
        assert!(!declined("nobody.dev.ray", a).await);
        // PTRs outside our ranges do go upstream.
        assert!(
            declined(
                "34.216.184.93.in-addr.arpa",
                QTYPE::TYPE(simple_dns::TYPE::PTR)
            )
            .await
        );
        // A PTR inside `100.64.0.0/10` also goes upstream: that range is not ours
        // any more, and answering an authoritative NXDOMAIN would break reverse
        // lookups for the nodes of whatever VPN owns it here.
        assert!(
            declined(
                "9.0.64.100.in-addr.arpa",
                QTYPE::TYPE(simple_dns::TYPE::PTR)
            )
            .await
        );
        // ...but a PTR inside `200::/7` is ours to answer, hit or miss.
        assert!(
            !declined(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.ip6.arpa",
                QTYPE::TYPE(simple_dns::TYPE::PTR)
            )
            .await
        );
    }

    /// A `.ray` name the roster does not hold has to fail with *our* SOA and its
    /// 60s negative TTL. Declining it instead sends it to a public resolver,
    /// whose NXDOMAIN carries the root's 86400: a name queried during the gap
    /// between DNS coming up and a roster reconverging then stays dead in the OS
    /// cache for a day, long after the peer is back.
    #[tokio::test]
    async fn unknown_ray_name_nxdomains_with_our_short_soa() {
        use simple_dns::{CLASS as C, PacketFlag, QCLASS, Question};

        let table = new_hostname_table();
        let reverse = new_reverse_table();

        let mut pkt = Packet::new_query(1);
        pkt.set_flags(PacketFlag::RECURSION_DESIRED);
        pkt.questions.push(Question::new(
            Name::new_unchecked("srv.devbox.ray").into_owned(),
            QTYPE::TYPE(simple_dns::TYPE::A),
            QCLASS::CLASS(C::IN),
            false,
        ));
        let query = pkt.build_bytes_vec().expect("build query");

        let resp = handle_query(&query, &table, &reverse)
            .await
            .expect("an empty roster still answers inside our own zone");
        let resp = Packet::parse(&resp).expect("parse NXDOMAIN");
        assert_eq!(resp.rcode(), RCODE::NameError);

        let soa = resp
            .name_servers
            .first()
            .expect("NXDOMAIN carries an authority SOA");
        assert_eq!(soa.ttl, 60, "the negative TTL the client will cache");
        match &soa.rdata {
            RData::SOA(soa) => assert_eq!(soa.minimum, 60, "our SOA, not the root's"),
            other => panic!("expected SOA, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_ptr_ipv4() {
        let ip = parse_ptr_name("5.10.64.100.in-addr.arpa");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(100, 64, 10, 5))));
    }

    #[test]
    fn test_parse_ptr_ipv6() {
        // 0200::1 in nibble format
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.ip6.arpa";
        let ip = parse_ptr_name(name);
        assert_eq!(
            ip,
            Some(IpAddr::V6(Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn test_parse_ptr_invalid() {
        assert_eq!(parse_ptr_name("example.com"), None);
        assert_eq!(parse_ptr_name("1.2.3.in-addr.arpa"), None);
    }

    #[tokio::test]
    async fn test_update_and_reverse_lookup() {
        let table = new_hostname_table();
        let reverse = new_reverse_table();
        let v6 = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1);

        update_hostname(&table, &reverse, "gaming", "alice", v6).await;

        // Forward lookup works
        let result = resolve_name("alice.gaming.ray", SUFFIX, &table).await;
        assert_eq!(result, Some(v6));

        // Reverse lookup works
        let rev6 = reverse.get(&IpAddr::V6(v6)).map(|e| e.value().clone());
        assert_eq!(rev6, Some(("alice".to_string(), "gaming".to_string())));
    }
}
