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

    fn restriction(&self) -> Option<String> {
        if self.any {
            return None;
        }
        let mut named: Vec<&str> = self.users.iter().map(String::as_str).collect();
        named.sort_unstable();
        Some(match (self.nonroot, named.is_empty()) {
            (true, true) => "any user except root".to_string(),
            (true, false) => format!("any user except root, plus {}", named.join(", ")),
            (false, false) => named.join(", "),
            (false, true) => "no users".to_string(),
        })
    }
}

pub(super) fn auth_banner(
    policy: &UserPolicy,
    peer: &EndpointId,
    networks: &[SmolStr],
) -> Option<String> {
    let network = networks
        .iter()
        .min()
        .map(ToString::to_string)
        .unwrap_or_else(|| "<network>".to_string());
    if !policy.authorized() {
        return Some(format!(
            "rayfish mesh SSH: peer {} is not authorized on this node.\r\n\
             Authorize it here with: ray firewall ssh allow {network} {} [-u <users>]\r\n\
             A password prompt after this line comes from the system sshd, not rayfish.\r\n",
            peer.fmt_short(),
            peer.fmt_short(),
        ));
    }
    policy.restriction().map(|allowed| {
        format!(
            "rayfish mesh SSH: peer {} may log in as {allowed}.\r\n\
             Widen it with: ray firewall ssh allow {network} {} -u '*'\r\n",
            peer.fmt_short(),
            peer.fmt_short(),
        )
    })
}

pub(super) fn resolve_user_policy(
    authz: &SshAuthz,
    user: &EndpointId,
    networks: &[SmolStr],
) -> UserPolicy {
    let rules_by_network = authz.load();
    let identity = user.to_string();
    let mut policy = UserPolicy::default();
    for network in networks {
        if let Some(rules) = rules_by_network.get(network.as_str()) {
            for rule in rules {
                if rule.peer == "*" || rule.peer == identity {
                    policy.add(&rule.users);
                }
            }
        }
    }
    policy
}
