//! In-daemon DNS resolver reached via the magic IP (no host :53 socket).
//! Answers `.ray` names from the hostname tables and forwards everything else
//! to the captured system upstreams.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use simple_dns::Packet;

use crate::dns::{HostnameTable, ReverseLookupTable, MAGIC_DNS_V4};
use crate::DNS_DOMAIN;

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

    /// Replace the upstream set, dropping the magic IP to avoid a forwarding loop.
    pub fn set_upstreams(&self, servers: Vec<Ipv4Addr>) {
        let v: Vec<SocketAddr> = servers
            .into_iter()
            .filter(|ip| *ip != MAGIC_DNS_V4)
            .map(|ip| SocketAddr::from((ip, 53u16)))
            .collect();
        self.upstreams.store(Arc::new(v));
    }

    pub fn upstreams(&self) -> Vec<SocketAddr> {
        self.upstreams.load().as_ref().clone()
    }

    pub async fn resolve(&self, query: &[u8]) -> Option<Vec<u8>> {
        let pkt = Packet::parse(query).ok()?;
        let q = pkt.questions.first()?;
        let name = q.qname.to_string();
        let name_lower = name.trim_end_matches('.').to_lowercase();

        if is_local_name(&name_lower, &self.table).await {
            // Authoritative for .ray (handle_query returns NXDOMAIN/NODATA too).
            return crate::dns::handle_query(query, &self.table, &self.reverse).await;
        }
        self.forward(query).await
    }

    async fn forward(&self, query: &[u8]) -> Option<Vec<u8>> {
        let upstreams = self.upstreams.load();
        for up in upstreams.iter() {
            if let Ok(resp) = forward_once(query, *up).await {
                return Some(resp);
            }
        }
        None
    }
}

async fn forward_once(query: &[u8], up: SocketAddr) -> std::io::Result<Vec<u8>> {
    let sock = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
    sock.send_to(query, up).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream DNS timeout"))??;
    buf.truncate(n);
    Ok(buf)
}

/// A name we answer locally: `.ray`, the apex `ray`, or `<host>.<network>`
/// where `<network>` is a known network in the table.
pub async fn is_local_name(name_lower: &str, table: &HostnameTable) -> bool {
    let suffix = format!(".{DNS_DOMAIN}");
    if name_lower == DNS_DOMAIN || name_lower.ends_with(&suffix) {
        return true;
    }
    let tld = name_lower
        .rsplit_once('.')
        .map(|(_, t)| t)
        .unwrap_or(name_lower);
    table.read().await.contains_key(tld)
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
}
