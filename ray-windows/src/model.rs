use ray_proto::Action;
use ray_proto::ipc::{
    ConnectionErrorInfo, FirewallRuleView, InactiveNetwork, ManagedMachineInfo, NetworkStatus,
    PendingFileInfo,
};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
pub(crate) struct Status {
    pub active: bool,
    pub identity: Option<String>,
    pub networks: Vec<NetworkStatus>,
    #[serde(default)]
    pub inactive_networks: Vec<InactiveNetwork>,
    #[serde(default)]
    pub connection_errors: Vec<ConnectionErrorInfo>,
    pub managed_machines: Option<Vec<ManagedMachineInfo>>,
    pub pending: PendingCounts,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct PendingCounts {
    pub connects: usize,
    pub files: usize,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Firewall {
    pub default_inbound: Action,
    pub default_outbound: Action,
    pub rules: Vec<FirewallRuleView>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Request {
    pub id: String,
    pub hostname: Option<String>,
    pub waiting_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Files {
    pub pending: Vec<PendingFileInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingKind {
    Join { network: String, id: String },
    Connect { id: String },
    File { id: u64 },
    Firewall { network: String },
}

#[derive(Debug)]
pub(crate) struct PendingItem {
    pub kind: PendingKind,
    pub description: String,
}

impl PendingItem {
    pub fn command(&self, accept: bool) -> Vec<String> {
        let resolution = if accept { "accept" } else { "deny" };
        match &self.kind {
            PendingKind::Join { network, id } => words(&["requests", network, resolution, id]),
            PendingKind::Connect { id } => {
                words(&["connect", if accept { "approve" } else { "deny" }, id])
            }
            PendingKind::File { id } => words(&[
                "files",
                if accept { "accept" } else { "reject" },
                &id.to_string(),
            ]),
            PendingKind::Firewall { network } => words(&["firewall", resolution, network]),
        }
    }

    pub fn review_command(&self) -> Option<Vec<String>> {
        match &self.kind {
            PendingKind::Firewall { network } => Some(words(&["firewall", "pending", network])),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Snapshot {
    pub status: Status,
    pub config: Result<Map<String, Value>, String>,
    pub firewall: Result<Firewall, String>,
    pub pending: Vec<PendingItem>,
    pub warnings: Vec<String>,
    pub launch_at_login: bool,
}

impl Snapshot {
    pub fn enabled(&self, key: &str) -> bool {
        self.config
            .as_ref()
            .ok()
            .and_then(|config| config.get(key))
            .is_some_and(|value| {
                value == true
                    || value
                        .as_str()
                        .is_some_and(|v| matches!(v, "on" | "partial"))
            })
    }
}

pub(crate) fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_buttons_use_the_matching_cli_command() {
        let join = PendingItem {
            kind: PendingKind::Join {
                network: "example".into(),
                id: "request-id".into(),
            },
            description: String::new(),
        };
        assert_eq!(
            join.command(true),
            ["requests", "example", "accept", "request-id"]
        );
        assert_eq!(
            join.command(false),
            ["requests", "example", "deny", "request-id"]
        );
        let connection = PendingItem {
            kind: PendingKind::Connect {
                id: "request-id".into(),
            },
            description: String::new(),
        };
        assert_eq!(
            connection.command(true),
            ["connect", "approve", "request-id"]
        );
        let file = PendingItem {
            kind: PendingKind::File { id: 3 },
            description: String::new(),
        };
        assert_eq!(file.command(false), ["files", "reject", "3"]);
    }
}
