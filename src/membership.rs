use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use iroh::EndpointId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub identity: String,
    pub ip: Ipv4Addr,
    pub is_coordinator: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupMode {
    Open,
    #[default]
    Restricted,
}

impl fmt::Display for GroupMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupMode::Open => write!(f, "open"),
            GroupMode::Restricted => write!(f, "restricted"),
        }
    }
}

impl std::str::FromStr for GroupMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(GroupMode::Open),
            "restricted" => Ok(GroupMode::Restricted),
            other => Err(format!("unknown group mode: {other}")),
        }
    }
}

#[derive(Debug)]
pub struct IpCollision {
    pub ip: Ipv4Addr,
    pub existing_identity: String,
    pub new_identity: String,
}

impl fmt::Display for IpCollision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IP collision: {} already assigned to {}, cannot assign to {}",
            self.ip, self.existing_identity, self.new_identity
        )
    }
}

impl std::error::Error for IpCollision {}

#[derive(Debug, Clone)]
pub struct MemberList {
    members: HashMap<String, Member>,
}

impl MemberList {
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    pub fn add(&mut self, member: Member) -> Result<(), IpCollision> {
        if let Some(existing) = self.get_by_ip(member.ip)
            && existing.identity != member.identity
        {
            return Err(IpCollision {
                ip: member.ip,
                existing_identity: existing.identity.clone(),
                new_identity: member.identity.clone(),
            });
        }
        self.members.insert(member.identity.clone(), member);
        Ok(())
    }

    pub fn remove(&mut self, identity: &str) -> Option<Member> {
        self.members.remove(identity)
    }

    pub fn get(&self, identity: &str) -> Option<&Member> {
        self.members.get(identity)
    }

    pub fn get_by_ip(&self, ip: Ipv4Addr) -> Option<&Member> {
        self.members.values().find(|m| m.ip == ip)
    }

    pub fn is_member(&self, identity: &str) -> bool {
        self.members.contains_key(identity)
    }

    pub fn all(&self) -> Vec<&Member> {
        self.members.values().collect()
    }

    pub fn into_members(self) -> Vec<Member> {
        self.members.into_values().collect()
    }

    pub fn from_members(members: Vec<Member>) -> Self {
        let mut list = Self::new();
        for m in members {
            let _ = list.add(m);
        }
        list
    }
}

pub trait MembershipPolicy: Send + Sync {
    fn can_authorize(&self, acceptor: &Member) -> bool;
}

pub struct OpenPolicy;

impl MembershipPolicy for OpenPolicy {
    fn can_authorize(&self, _acceptor: &Member) -> bool {
        true
    }
}

pub struct RestrictedPolicy;

impl MembershipPolicy for RestrictedPolicy {
    fn can_authorize(&self, acceptor: &Member) -> bool {
        acceptor.is_coordinator
    }
}

pub fn policy_for_mode(mode: GroupMode) -> Box<dyn MembershipPolicy> {
    match mode {
        GroupMode::Open => Box::new(OpenPolicy),
        GroupMode::Restricted => Box::new(RestrictedPolicy),
    }
}

pub trait IdentityProvider: Send + Sync {
    fn local_ip(&self) -> Ipv4Addr;
    fn local_identity(&self) -> String;
    fn derive_ip(&self, peer_identity: &str) -> Ipv4Addr;
    fn verify_peer(&self, claimed_identity: &str, transport_identity: &str) -> bool;
}

pub fn derive_ip(identity: &str) -> Ipv4Addr {
    let mut hash: u32 = 2_166_136_261; // FNV-1a offset basis
    for &b in identity.as_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(16_777_619); // FNV-1a prime
    }

    let base: u32 = 0x6440_0000; // 100.64.0.0
    let host_bits = hash & 0x003F_FFFF; // lower 22 bits
    // Reserve 0 (network) and 1 (TUN gateway)
    let host_bits = if host_bits <= 1 {
        host_bits + 2
    } else {
        host_bits
    };
    Ipv4Addr::from(base | host_bits)
}

#[derive(Clone)]
pub struct IrohIdentityProvider {
    endpoint_id: EndpointId,
    ip: Ipv4Addr,
}

impl IrohIdentityProvider {
    pub fn new(endpoint_id: EndpointId) -> Self {
        let ip = derive_ip(&endpoint_id.to_string());
        Self { endpoint_id, ip }
    }
}

impl IdentityProvider for IrohIdentityProvider {
    fn local_ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn local_identity(&self) -> String {
        self.endpoint_id.to_string()
    }

    fn derive_ip(&self, peer_identity: &str) -> Ipv4Addr {
        derive_ip(peer_identity)
    }

    fn verify_peer(&self, claimed_identity: &str, transport_identity: &str) -> bool {
        claimed_identity == transport_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_ip_deterministic() {
        let ip1 = derive_ip("abc123");
        let ip2 = derive_ip("abc123");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_derive_ip_in_cgnat_range() {
        let ip = derive_ip("test-identity-string");
        let octets = ip.octets();
        // 100.64.0.0/10 = first 10 bits fixed: 01100100.01xxxxxx
        assert_eq!(octets[0], 100);
        assert!(octets[1] >= 64 && octets[1] <= 127);
    }

    #[test]
    fn test_derive_ip_different_identities_differ() {
        let ip1 = derive_ip("identity-a");
        let ip2 = derive_ip("identity-b");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_derive_ip_avoids_reserved() {
        // Hash could theoretically land on 100.64.0.0 or 100.64.0.1
        // Test many inputs and verify none hit reserved addresses
        let reserved1 = Ipv4Addr::new(100, 64, 0, 0);
        let reserved2 = Ipv4Addr::new(100, 64, 0, 1);
        for i in 0..10000 {
            let ip = derive_ip(&format!("test-{i}"));
            assert_ne!(ip, reserved1);
            assert_ne!(ip, reserved2);
        }
    }

    #[test]
    fn test_iroh_identity_provider() {
        let key = iroh::SecretKey::generate();
        let endpoint_id = key.public();
        let provider = IrohIdentityProvider::new(endpoint_id);

        let ip = provider.local_ip();
        let octets = ip.octets();
        assert_eq!(octets[0], 100);
        assert!(octets[1] >= 64 && octets[1] <= 127);

        // derive_ip for same identity gives same result
        let id_str = provider.local_identity();
        assert_eq!(provider.derive_ip(&id_str), ip);
    }

    #[test]
    fn test_iroh_verify_peer() {
        let key = iroh::SecretKey::generate();
        let endpoint_id = key.public();
        let provider = IrohIdentityProvider::new(endpoint_id);

        let id_str = endpoint_id.to_string();
        assert!(provider.verify_peer(&id_str, &id_str));
        assert!(!provider.verify_peer("wrong-identity", &id_str));
    }

    #[test]
    fn test_member_list_add_and_lookup() {
        let mut list = MemberList::new();
        let member = Member {
            identity: "peer-a".to_string(),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
        };
        list.add(member.clone()).unwrap();
        assert!(list.is_member("peer-a"));
        assert!(!list.is_member("peer-b"));
        assert_eq!(list.get("peer-a").unwrap().ip, Ipv4Addr::new(100, 64, 10, 5));
    }

    #[test]
    fn test_member_list_lookup_by_ip() {
        let mut list = MemberList::new();
        let member = Member {
            identity: "peer-a".to_string(),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
        };
        list.add(member).unwrap();
        let found = list.get_by_ip(Ipv4Addr::new(100, 64, 10, 5)).unwrap();
        assert_eq!(found.identity, "peer-a");
        assert!(list.get_by_ip(Ipv4Addr::new(100, 64, 10, 6)).is_none());
    }

    #[test]
    fn test_member_list_ip_collision() {
        let mut list = MemberList::new();
        list.add(Member {
            identity: "peer-a".to_string(),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
        })
        .unwrap();
        let result = list.add(Member {
            identity: "peer-b".to_string(),
            ip: Ipv4Addr::new(100, 64, 10, 5), // same IP, different identity
            is_coordinator: false,
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_member_list_same_identity_updates() {
        let mut list = MemberList::new();
        list.add(Member {
            identity: "peer-a".to_string(),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
        })
        .unwrap();
        // Re-adding same identity with same IP is OK (idempotent)
        list.add(Member {
            identity: "peer-a".to_string(),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: true,
        })
        .unwrap();
        assert!(list.get("peer-a").unwrap().is_coordinator);
    }

    #[test]
    fn test_member_list_remove() {
        let mut list = MemberList::new();
        list.add(Member {
            identity: "peer-a".to_string(),
            ip: Ipv4Addr::new(100, 64, 10, 5),
            is_coordinator: false,
        })
        .unwrap();
        let removed = list.remove("peer-a");
        assert!(removed.is_some());
        assert!(!list.is_member("peer-a"));
        assert!(list.remove("peer-a").is_none());
    }

    #[test]
    fn test_member_list_all() {
        let mut list = MemberList::new();
        list.add(Member {
            identity: "a".to_string(),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            is_coordinator: true,
        })
        .unwrap();
        list.add(Member {
            identity: "b".to_string(),
            ip: Ipv4Addr::new(100, 64, 0, 3),
            is_coordinator: false,
        })
        .unwrap();
        assert_eq!(list.all().len(), 2);
    }

    #[test]
    fn test_open_policy_anyone_can_authorize() {
        let policy = OpenPolicy;
        let member = Member {
            identity: "regular-peer".to_string(),
            ip: Ipv4Addr::new(100, 64, 0, 5),
            is_coordinator: false,
        };
        assert!(policy.can_authorize(&member));
    }

    #[test]
    fn test_restricted_policy_only_coordinators() {
        let policy = RestrictedPolicy;
        let coordinator = Member {
            identity: "coord".to_string(),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            is_coordinator: true,
        };
        let regular = Member {
            identity: "peer".to_string(),
            ip: Ipv4Addr::new(100, 64, 0, 3),
            is_coordinator: false,
        };
        assert!(policy.can_authorize(&coordinator));
        assert!(!policy.can_authorize(&regular));
    }
}
