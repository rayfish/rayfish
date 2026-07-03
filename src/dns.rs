//! Magic DNS responder for the `.ray` TLD.
//!
//! Answers A, AAAA, PTR, and SOA queries for `*.ray` names. The resolver is
//! reached via a magic IP (`MAGIC_DNS_V4` = 100.100.100.53) routed through the
//! TUN — no host-level port 53 bind is made. `handle_query` is called directly
//! by `forward::run_mesh` when it intercepts a UDP DNS packet destined for the
//! magic IP.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock;

use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, rdata::A, rdata::AAAA,
    rdata::OPT, rdata::RData, rdata::SOA,
};

use crate::DNS_DOMAIN;

/// Reserved virtual IPv4 for the in-daemon Magic DNS resolver. It lives in the
/// `100.64.0.0/10` peer range (so the existing TUN route delivers packets to it)
/// but is NEVER assigned to a member and NEVER bound as a local interface
/// address — it is reachable only by being routed into the TUN, which is what
/// lets us answer DNS without competing for the host's port 53. Distinct from
/// Tailscale's 100.100.100.100 so both can coexist.
pub const MAGIC_DNS_V4: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 53);

/// Per-network hostname → (IPv4, IPv6) mapping.
pub type HostnameEntry = (Ipv4Addr, Ipv6Addr);
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
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
) {
    {
        let mut t = table.write().await;
        let hosts = t.entry(network.to_string()).or_default();
        hosts.insert(hostname.to_string(), (ipv4, ipv6));
    }
    reverse.insert(
        IpAddr::V4(ipv4),
        (hostname.to_string(), network.to_string()),
    );
    reverse.insert(
        IpAddr::V6(ipv6),
        (hostname.to_string(), network.to_string()),
    );
}

/// Remove a hostname from both tables.
#[allow(dead_code)]
pub async fn remove_hostname(
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
    network: &str,
    hostname: &str,
) {
    let mut t = table.write().await;
    if let Some(hosts) = t.get_mut(network)
        && let Some((ipv4, ipv6)) = hosts.remove(hostname)
    {
        reverse.remove(&IpAddr::V4(ipv4));
        reverse.remove(&IpAddr::V6(ipv6));
    }
}

/// Remove a hostname by IP address from both tables.
pub async fn remove_hostname_by_ip(
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
    network: &str,
    ipv4: Ipv4Addr,
) {
    let mut t = table.write().await;
    if let Some(hosts) = t.get_mut(network) {
        hosts.retain(|_, (v4, v6)| {
            if *v4 == ipv4 {
                reverse.remove(&IpAddr::V4(*v4));
                reverse.remove(&IpAddr::V6(*v6));
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
/// immediately — the roster is the single source of truth for DNS.
pub async fn sync_network_hostnames(
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
    network: &str,
    entries: &[(String, Ipv4Addr, Ipv6Addr)],
) {
    let mut t = table.write().await;
    // Drop reverse entries for the network's previous set before rebuilding.
    if let Some(old) = t.get(network) {
        for (_, (v4, v6)) in old.iter() {
            reverse.remove(&IpAddr::V4(*v4));
            reverse.remove(&IpAddr::V6(*v6));
        }
    }
    let mut hosts = HashMap::with_capacity(entries.len());
    for (name, v4, v6) in entries {
        hosts.insert(name.clone(), (*v4, *v6));
        reverse.insert(IpAddr::V4(*v4), (name.clone(), network.to_string()));
        reverse.insert(IpAddr::V6(*v6), (name.clone(), network.to_string()));
    }
    t.insert(network.to_string(), hosts);
}

/// Remove all hostnames for a network from both tables.
pub async fn remove_network(table: &HostnameTable, reverse: &ReverseLookupTable, network: &str) {
    let mut t = table.write().await;
    if let Some(hosts) = t.remove(network) {
        for (_, (ipv4, ipv6)) in hosts {
            reverse.remove(&IpAddr::V4(ipv4));
            reverse.remove(&IpAddr::V6(ipv6));
        }
    }
}

pub(crate) async fn handle_query(
    data: &[u8],
    table: &HostnameTable,
    reverse: &ReverseLookupTable,
) -> Option<Vec<u8>> {
    let packet = Packet::parse(data).ok()?;

    if packet.questions.is_empty() {
        return None;
    }

    let question = &packet.questions[0];
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

    // SOA query for the zone apex
    if is_soa && (name_lower == DNS_DOMAIN || name_lower.ends_with(&suffix)) {
        return Some(make_soa_response(&packet, &question.qname));
    }

    // Try resolving: first as .ray name, then as bare <host>.<network>
    let entry = if is_a || is_aaaa {
        if name_lower.ends_with(&suffix) {
            resolve_name(&name_lower, &suffix, table).await
        } else {
            resolve_bare_network_name(&name_lower, table).await
        }
    } else {
        None
    };

    if let Some((v4, v6)) = entry {
        if is_a {
            tracing::info!(name = %name_lower, ip = %v4, "DNS resolved A");
            return Some(make_a_response(&packet, &question.qname, v4));
        } else {
            tracing::info!(name = %name_lower, ip = %v6, "DNS resolved AAAA");
            return Some(make_aaaa_response(&packet, &question.qname, v6));
        }
    }

    // For .ray names, return NXDOMAIN (A/AAAA) or NODATA (other types)
    if name_lower.ends_with(&suffix) || name_lower == DNS_DOMAIN {
        if is_a || is_aaaa {
            tracing::info!(name = %name_lower, "DNS query NXDOMAIN");
            return Some(make_nxdomain(&packet));
        }
        return Some(make_nodata(&packet));
    }

    // Bare network name that didn't resolve — check if the TLD is a known network
    {
        let tld = name_lower
            .rsplit_once('.')
            .map(|(_, t)| t)
            .unwrap_or(&name_lower);
        let table_guard = table.read().await;
        if table_guard.contains_key(tld) {
            if is_a || is_aaaa {
                tracing::info!(name = %name_lower, "DNS query NXDOMAIN (known network)");
                return Some(make_nxdomain(&packet));
            }
            return Some(make_nodata(&packet));
        }
    }

    tracing::debug!(name = %name_lower, "DNS query for unknown domain, refusing");
    Some(make_refused(&packet))
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

    // If IP is in our range but not found, NXDOMAIN
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 100.64.0.0/10
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                tracing::info!(ip = %ip, "DNS PTR NXDOMAIN (our range)");
                return Some(make_nxdomain(packet));
            }
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // 200::/7
            if (segments[0] & 0xFE00) == 0x0200 {
                tracing::info!(ip = %ip, "DNS PTR NXDOMAIN (our range)");
                return Some(make_nxdomain(packet));
            }
        }
    }

    Some(make_refused(packet))
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

/// Resolve `<hostname>.<network>` (without .ray suffix).
/// Used when the OS routes a bare network domain to us via supplemental match.
async fn resolve_bare_network_name(name: &str, table: &HostnameTable) -> Option<HostnameEntry> {
    let (hostname, network) = name.rsplit_once('.')?;
    let table_guard = table.read().await;
    table_guard.get(network)?.get(hostname).copied()
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

fn make_a_response(query: &Packet, qname: &Name, ip: Ipv4Addr) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    response.answers.push(ResourceRecord::new(
        qname.clone(),
        CLASS::IN,
        60,
        RData::A(A {
            address: u32::from(ip),
        }),
    ));
    finalize_response(&mut response, query);
    response.build_bytes_vec().unwrap_or_default()
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

fn make_refused(query: &Packet) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE);
    response.questions = query.questions.clone();
    *response.rcode_mut() = RCODE::Refused;
    finalize_response(&mut response, query);
    response.build_bytes_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUFFIX: &str = ".ray";

    fn entry(v4: Ipv4Addr) -> HostnameEntry {
        let v6 = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1);
        (v4, v6)
    }

    #[tokio::test]
    async fn test_resolve_with_network() {
        let table = new_hostname_table();
        {
            let mut t = table.write().await;
            let mut hosts = HashMap::new();
            hosts.insert("alice".to_string(), entry(Ipv4Addr::new(100, 64, 10, 5)));
            t.insert("gaming".to_string(), hosts);
        }
        let result = resolve_name("alice.gaming.ray", SUFFIX, &table).await;
        assert_eq!(
            result.map(|(v4, _)| v4),
            Some(Ipv4Addr::new(100, 64, 10, 5))
        );
    }

    #[tokio::test]
    async fn test_sync_network_hostnames_rename_and_remove() {
        let table = new_hostname_table();
        let reverse = new_reverse_table();
        let v6 = |n: u16| Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, n);
        let alice_v4 = Ipv4Addr::new(100, 64, 10, 5);
        let bob_v4 = Ipv4Addr::new(100, 64, 10, 6);

        // Initial roster: alice + bob.
        sync_network_hostnames(
            &table,
            &reverse,
            "net",
            &[
                ("alice".to_string(), alice_v4, v6(1)),
                ("bob".to_string(), bob_v4, v6(2)),
            ],
        )
        .await;
        assert_eq!(
            resolve_name("alice.net.ray", SUFFIX, &table)
                .await
                .map(|(v4, _)| v4),
            Some(alice_v4)
        );
        assert_eq!(
            reverse.get(&IpAddr::V4(alice_v4)).map(|e| e.0.clone()),
            Some("alice".to_string())
        );

        // alice renames to dario; bob leaves.
        sync_network_hostnames(
            &table,
            &reverse,
            "net",
            &[("dario".to_string(), alice_v4, v6(1))],
        )
        .await;
        assert_eq!(
            resolve_name("dario.net.ray", SUFFIX, &table)
                .await
                .map(|(v4, _)| v4),
            Some(alice_v4)
        );
        // Old name and departed peer no longer resolve; reverse is rebuilt.
        assert_eq!(resolve_name("alice.net.ray", SUFFIX, &table).await, None);
        assert_eq!(resolve_name("bob.net.ray", SUFFIX, &table).await, None);
        assert_eq!(reverse.get(&IpAddr::V4(bob_v4)).map(|e| e.0.clone()), None);
        assert_eq!(
            reverse.get(&IpAddr::V4(alice_v4)).map(|e| e.0.clone()),
            Some("dario".to_string())
        );
    }

    #[tokio::test]
    async fn test_resolve_flat() {
        let table = new_hostname_table();
        {
            let mut t = table.write().await;
            let mut hosts = HashMap::new();
            hosts.insert("bob".to_string(), entry(Ipv4Addr::new(100, 64, 20, 3)));
            t.insert("work".to_string(), hosts);
        }
        let result = resolve_name("bob.ray", SUFFIX, &table).await;
        assert_eq!(
            result.map(|(v4, _)| v4),
            Some(Ipv4Addr::new(100, 64, 20, 3))
        );
    }

    #[tokio::test]
    async fn test_resolve_unknown() {
        let table = new_hostname_table();
        let result = resolve_name("nobody.ray", SUFFIX, &table).await;
        assert_eq!(result, None);
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
        let v4 = Ipv4Addr::new(100, 64, 10, 5);
        let v6 = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1);

        update_hostname(&table, &reverse, "gaming", "alice", v4, v6).await;

        // Forward lookup works
        let result = resolve_name("alice.gaming.ray", SUFFIX, &table).await;
        assert_eq!(result, Some((v4, v6)));

        // Reverse lookup works
        let rev4 = reverse.get(&IpAddr::V4(v4)).map(|e| e.value().clone());
        assert_eq!(rev4, Some(("alice".to_string(), "gaming".to_string())));
        let rev6 = reverse.get(&IpAddr::V6(v6)).map(|e| e.value().clone());
        assert_eq!(rev6, Some(("alice".to_string(), "gaming".to_string())));
    }

    #[tokio::test]
    async fn test_remove_hostname() {
        let table = new_hostname_table();
        let reverse = new_reverse_table();
        let v4 = Ipv4Addr::new(100, 64, 10, 5);
        let v6 = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1);

        update_hostname(&table, &reverse, "gaming", "alice", v4, v6).await;
        remove_hostname(&table, &reverse, "gaming", "alice").await;

        assert_eq!(resolve_name("alice.gaming.ray", SUFFIX, &table).await, None);
        assert!(reverse.get(&IpAddr::V4(v4)).is_none());
        assert!(reverse.get(&IpAddr::V6(v6)).is_none());
    }
}
