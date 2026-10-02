//! Mesh SSH authorization snapshots and login policy resolution.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use iroh::EndpointId;
use smol_str::SmolStr;

pub type SshAuthz = Arc<ArcSwap<HashMap<String, Vec<crate::config::SshRule>>>>;

pub fn new_authz() -> SshAuthz {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

#[derive(Default, Debug, PartialEq)]
#[cfg_attr(
    any(target_os = "macos", test),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(super) struct UserPolicy {
    matched: bool,
    any: bool,
    nonroot: bool,
    users: HashSet<String>,
}

impl UserPolicy {
    pub(super) fn add(&mut self, users: &[String]) {
        self.matched = true;
        if users.iter().any(|user| user == "*") {
            self.any = true;
        } else if users.is_empty() {
            self.nonroot = true;
        } else {
            self.users.extend(users.iter().cloned());
        }
    }

    pub(super) fn authorized(&self) -> bool {
        self.matched
    }

    pub(super) fn permits(&self, name: &str, uid: u32) -> bool {
        self.any || self.users.contains(name) || (self.nonroot && uid != 0)
    }
}

pub(super) fn auth_banner(
    policy: &UserPolicy,
    peer: &EndpointId,
    networks: &[SmolStr],
) -> Option<String> {
    if policy.authorized() {
        return None;
    }
    let network = networks
        .iter()
        .min()
        .map(ToString::to_string)
        .unwrap_or_else(|| "<network>".to_string());
    Some(format!(
        "rayfish mesh SSH: peer {} is not authorized on this node.\r\n\
         Authorize it here with: ray firewall ssh allow {network} {} [-u <users>]\r\n\
         A password prompt after this line comes from the system sshd, not rayfish.\r\n",
        peer.fmt_short(),
        peer.fmt_short(),
    ))
}

#[cfg(test)]
pub(super) fn resolve_user_policy(
    authz: &SshAuthz,
    user: &EndpointId,
    networks: &[SmolStr],
) -> UserPolicy {
    resolve_user_policy_with_hostnames(authz, user, networks, &|_, _| None)
}

pub(super) fn resolve_user_policy_with_hostnames(
    authz: &SshAuthz,
    user: &EndpointId,
    networks: &[SmolStr],
    resolve_hostname: &dyn Fn(&str, &str) -> Option<EndpointId>,
) -> UserPolicy {
    let rules_by_network = authz.load();
    let identity = user.to_string();
    let mut policy = UserPolicy::default();
    for network in networks {
        if let Some(rules) = rules_by_network.get(network.as_str()) {
            for rule in rules {
                if rule.peer == "*"
                    || rule.peer == identity
                    || resolve_hostname(network, &rule.peer) == Some(*user)
                {
                    policy.add(&rule.users);
                }
            }
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn hostname_grant_resolves_at_login_time() {
        let peer = SecretKey::generate().public();
        let authz = new_authz();
        authz.store(Arc::new(HashMap::from([(
            "infra".to_string(),
            vec![crate::config::SshRule {
                peer: "laptop".to_string(),
                users: vec!["deploy".to_string()],
            }],
        )])));
        let networks = [SmolStr::new("infra")];
        let missing = resolve_user_policy_with_hostnames(&authz, &peer, &networks, &|_, _| None);
        assert!(!missing.authorized());
        let joined = resolve_user_policy_with_hostnames(&authz, &peer, &networks, &|net, host| {
            (net == "infra" && host == "laptop").then_some(peer)
        });
        assert!(joined.permits("deploy", 1000));
        assert!(!joined.permits("root", 0));
    }
}
