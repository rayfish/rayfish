//! Minimal DNS responder for Magic DNS (.pi TLD).
//!
//! Binds to 100.64.0.1:53 (UDP) and answers A queries for `*.pi` names.
//! All other queries receive REFUSED.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use simple_dns::{Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, Name, CLASS, rdata::RData, rdata::A, rdata::AAAA};

use crate::DNS_DOMAIN;

/// Per-network hostname → (IPv4, IPv6) mapping.
pub type HostnameEntry = (Ipv4Addr, Ipv6Addr);
pub type HostnameTable = Arc<RwLock<HashMap<String, HashMap<String, HostnameEntry>>>>;

pub fn new_hostname_table() -> HostnameTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub async fn spawn_dns_server(
    table: HostnameTable,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("DNS resolver listening on {addr}");

    let mut buf = vec![0u8; 512];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = socket.recv_from(&mut buf) => {
                let (len, src) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(error = %e, "DNS recv error");
                        continue;
                    }
                };
                let response = handle_query(&buf[..len], &table).await;
                if let Some(resp_bytes) = response {
                    let _ = socket.send_to(&resp_bytes, src).await;
                }
            }
        }
    }
    Ok(())
}

async fn handle_query(data: &[u8], table: &HostnameTable) -> Option<Vec<u8>> {
    let packet = Packet::parse(data).ok()?;

    if packet.questions.is_empty() {
        return None;
    }

    let question = &packet.questions[0];
    let is_a = question.qtype == QTYPE::TYPE(simple_dns::TYPE::A);
    let is_aaaa = question.qtype == QTYPE::TYPE(simple_dns::TYPE::AAAA);
    if !is_a && !is_aaaa {
        return Some(make_refused(&packet));
    }

    let name_str = question.qname.to_string();
    let name_lower = name_str.trim_end_matches('.').to_lowercase();

    let suffix = format!(".{DNS_DOMAIN}");
    if !name_lower.ends_with(&suffix) {
        tracing::debug!(name = %name_lower, "DNS query for non-.{} domain, refusing", DNS_DOMAIN);
        return Some(make_refused(&packet));
    }

    let entry = resolve_name(&name_lower, &suffix, table).await;

    match entry {
        Some((v4, v6)) => {
            if is_a {
                tracing::info!(name = %name_lower, ip = %v4, "DNS resolved A");
                Some(make_a_response(&packet, &question.qname, v4))
            } else {
                tracing::info!(name = %name_lower, ip = %v6, "DNS resolved AAAA");
                Some(make_aaaa_response(&packet, &question.qname, v6))
            }
        }
        None => {
            tracing::info!(name = %name_lower, "DNS query NXDOMAIN");
            Some(make_nxdomain(&packet))
        }
    }
}

async fn resolve_name(name: &str, suffix: &str, table: &HostnameTable) -> Option<HostnameEntry> {
    let stripped = name.strip_suffix(suffix)?;
    let table_guard = table.read().await;

    // Try <hostname>.<network>.pi
    if let Some((hostname, network)) = stripped.rsplit_once('.')
        && let Some(network_hosts) = table_guard.get(network) {
            return network_hosts.get(hostname).copied();
        }

    // Try <hostname>.pi (search all networks, return first match)
    for network_hosts in table_guard.values() {
        if let Some(entry) = network_hosts.get(stripped) {
            return Some(*entry);
        }
    }

    None
}

fn make_a_response(query: &Packet, qname: &Name, ip: Ipv4Addr) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    response.answers.push(ResourceRecord::new(
        qname.clone(),
        CLASS::IN,
        60,
        RData::A(A { address: u32::from(ip) }),
    ));
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
        RData::AAAA(AAAA { address: u128::from(ip) }),
    ));
    response.build_bytes_vec().unwrap_or_default()
}

fn make_nxdomain(query: &Packet) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query.questions.clone();
    *response.rcode_mut() = RCODE::NameError;
    response.build_bytes_vec().unwrap_or_default()
}

fn make_refused(query: &Packet) -> Vec<u8> {
    let mut response = Packet::new_reply(query.id());
    response.set_flags(PacketFlag::RESPONSE);
    response.questions = query.questions.clone();
    *response.rcode_mut() = RCODE::Refused;
    response.build_bytes_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUFFIX: &str = ".pi";

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
        let result = resolve_name("alice.gaming.pi", SUFFIX, &table).await;
        assert_eq!(result.map(|(v4, _)| v4), Some(Ipv4Addr::new(100, 64, 10, 5)));
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
        let result = resolve_name("bob.pi", SUFFIX, &table).await;
        assert_eq!(result.map(|(v4, _)| v4), Some(Ipv4Addr::new(100, 64, 20, 3)));
    }

    #[tokio::test]
    async fn test_resolve_unknown() {
        let table = new_hostname_table();
        let result = resolve_name("nobody.pi", SUFFIX, &table).await;
        assert_eq!(result, None);
    }
}
