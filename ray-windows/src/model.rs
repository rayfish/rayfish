use anyhow::{Result, bail};
use ray_proto::Action;
use ray_proto::ipc::{
    ConnectionErrorInfo, FirewallRuleView, InactiveNetwork, IpcMessage, ManagedMachineInfo,
    NetworkStatus, NodeStatus,
};
use serde_json::{Map, Value};

#[derive(Debug)]
pub(crate) struct Status {
    pub active: bool,
    pub identity: Option<String>,
    pub networks: Vec<NetworkStatus>,
    pub inactive_networks: Vec<InactiveNetwork>,
    pub connection_errors: Vec<ConnectionErrorInfo>,
    pub pending_networks: Vec<String>,
    pub managed_machines: Option<Vec<ManagedMachineInfo>>,
    pub pending: PendingCounts,
}

impl Status {
    pub fn from_response(response: IpcMessage) -> Result<Self> {
        match response {
            IpcMessage::StatusResponse(NodeStatus {
                active,
                identity,
                networks,
                inactive_networks,
                connection_errors,
                pending_networks,
                pending_files,
                pending_connects,
                ..
            }) => Ok(Self {
                active,
                identity: identity.map(|identity| identity.to_string()),
                networks,
                inactive_networks,
                connection_errors,
                pending_networks,
                managed_machines: None,
                pending: PendingCounts {
                    connects: pending_connects,
                    files: pending_files,
                },
            }),
            IpcMessage::Error { message } => bail!(message),
            _ => bail!("The daemon returned an unexpected status response."),
        }
    }

    pub fn visible_networks(&self) -> impl Iterator<Item = &NetworkStatus> {
        self.networks.iter().chain(
            self.inactive_networks
                .iter()
                .filter_map(|network| network.saved.as_ref()),
        )
    }
}

#[derive(Debug, Default)]
pub(crate) struct PendingCounts {
    pub connects: usize,
    pub files: usize,
}

#[derive(Debug)]
pub(crate) struct Firewall {
    pub default_inbound: Action,
    pub default_outbound: Action,
    pub rules: Vec<FirewallRuleView>,
}

impl Firewall {
    pub fn from_response(response: IpcMessage) -> Result<Self> {
        match response {
            IpcMessage::FirewallState {
                default_inbound,
                default_outbound,
                rules,
                ..
            } => Ok(Self {
                default_inbound,
                default_outbound,
                rules,
            }),
            IpcMessage::Error { message } => bail!(message),
            _ => bail!("The daemon returned an unexpected firewall response."),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshRule {
    pub network: String,
    pub peer: String,
    pub users: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshState {
    pub enabled: bool,
    pub port: u16,
    pub rules: Vec<SshRule>,
}

impl SshState {
    pub fn from_response(response: IpcMessage) -> Result<Self> {
        match response {
            IpcMessage::FirewallSshState {
                enabled,
                port,
                networks,
            } => Ok(Self {
                enabled,
                port,
                rules: networks
                    .into_iter()
                    .flat_map(|(network, rules)| {
                        rules.into_iter().map(move |rule| SshRule {
                            network: network.clone(),
                            peer: rule.peer,
                            users: rule.users,
                        })
                    })
                    .collect(),
            }),
            IpcMessage::Error { message } => bail!(message),
            _ => bail!("The daemon returned an unexpected SSH settings response."),
        }
    }
}

pub(crate) fn config_from_response(response: IpcMessage) -> Result<Map<String, Value>> {
    match response {
        IpcMessage::ConfigValues { rows } => Ok(rows
            .into_iter()
            .map(|(key, value)| (key, Value::String(value)))
            .collect()),
        IpcMessage::Error { message } => bail!(message),
        _ => bail!("The daemon returned an unexpected settings response."),
    }
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
    pub fn command(&self, accept: bool) -> IpcMessage {
        match (&self.kind, accept) {
            (PendingKind::Join { network, id }, true) => IpcMessage::AcceptRequest {
                network: network.clone(),
                id: id.clone(),
            },
            (PendingKind::Join { network, id }, false) => IpcMessage::DenyRequest {
                network: network.clone(),
                id: id.clone(),
            },
            (PendingKind::Connect { id }, true) => IpcMessage::ApproveConnection { id: id.clone() },
            (PendingKind::Connect { id }, false) => IpcMessage::ConnectDeny { id: id.clone() },
            (PendingKind::File { id }, true) => IpcMessage::AcceptFile {
                id: *id,
                output: None,
            },
            (PendingKind::File { id }, false) => IpcMessage::RejectFile { id: *id },
            (PendingKind::Firewall { network }, true) => IpcMessage::FirewallAccept {
                network: network.clone(),
            },
            (PendingKind::Firewall { network }, false) => IpcMessage::FirewallDeny {
                network: network.clone(),
            },
        }
    }

    pub fn review_command(&self) -> Option<IpcMessage> {
        match &self.kind {
            PendingKind::Firewall { network } => Some(IpcMessage::FirewallPending {
                network: network.clone(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Snapshot {
    pub status: Status,
    pub config: Result<Map<String, Value>, String>,
    pub firewall: Result<Firewall, String>,
    pub ssh: Result<SshState, String>,
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
    use ray_proto::ipc::SshAllowView;
    use ray_proto::{Direction, Protocol};

    use super::*;

    fn status_response() -> IpcMessage {
        let fixture = crate::preview::fixture(true).status;
        let mut saved = fixture.networks[0].clone();
        saved.name = "saved-example".into();
        IpcMessage::StatusResponse(NodeStatus {
            endpoint_id: "5866666666666666666666666666666666666666666666666666666666666666"
                .parse()
                .unwrap(),
            mdns_enabled: true,
            auto_update: true,
            active: true,
            identity: None,
            daemon_version: "0.0.0".into(),
            networks: fixture.networks,
            packets_rx: 0,
            packets_tx: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            pending_files: 2,
            pending_connects: 3,
            connection_errors: Vec::new(),
            pending_networks: vec!["pending-example".into()],
            inactive_networks: vec![InactiveNetwork {
                name: saved.name.clone(),
                reason: Some("Example coordinator is reconnecting.".into()),
                saved: Some(saved),
            }],
            lan_peers: Vec::new(),
        })
    }

    #[test]
    fn direct_status_keeps_live_saved_and_pending_networks() {
        let status = Status::from_response(status_response()).unwrap();
        assert!(status.active);
        assert_eq!(status.networks[0].name, "example");
        assert_eq!(status.inactive_networks[0].name, "saved-example");
        assert_eq!(status.visible_networks().count(), 2);
        assert_eq!(status.pending_networks, ["pending-example"]);
        assert_eq!(status.pending.files, 2);
        assert_eq!(status.pending.connects, 3);
        assert!(status.managed_machines.is_none());
    }

    #[test]
    fn service_errors_remain_service_errors_instead_of_json_failures() {
        let error = Status::from_response(IpcMessage::Error {
            message: "Example service refused the request.".into(),
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "Example service refused the request.");
        assert!(
            Status::from_response(IpcMessage::Ok {
                message: "example".into()
            })
            .is_err()
        );
    }

    #[test]
    fn direct_firewall_and_settings_keep_typed_daemon_values() {
        let rule = FirewallRuleView {
            direction: Direction::In,
            action: Action::Allow,
            protocol: Protocol::Any,
            port: "*".into(),
            peer: "any".into(),
            network: "example".into(),
            suggested_by: None,
        };
        let firewall = Firewall::from_response(IpcMessage::FirewallState {
            default_inbound: Action::Deny,
            default_outbound: Action::Allow,
            reject: false,
            disabled: false,
            rules: vec![rule.clone()],
        })
        .unwrap();
        assert_eq!(firewall.default_inbound, Action::Deny);
        assert_eq!(firewall.default_outbound, Action::Allow);
        assert_eq!(firewall.rules, [rule]);
        let config = config_from_response(IpcMessage::ConfigValues {
            rows: vec![
                ("dns".into(), "partial".into()),
                ("mdns".into(), "on".into()),
            ],
        })
        .unwrap();
        assert_eq!(config["dns"], "partial");
        assert_eq!(config["mdns"], "on");
    }

    #[test]
    fn ssh_settings_keep_networks_accounts_and_configured_port() {
        let state = SshState::from_response(IpcMessage::FirewallSshState {
            enabled: true,
            port: u16::MAX,
            networks: vec![
                (
                    "example".into(),
                    vec![
                        SshAllowView {
                            peer: "*".into(),
                            users: Vec::new(),
                        },
                        SshAllowView {
                            peer: "example-peer".into(),
                            users: vec![r".\example-user".into()],
                        },
                    ],
                ),
                (
                    "second-example".into(),
                    vec![SshAllowView {
                        peer: "example-peer".into(),
                        users: vec!["*".into()],
                    }],
                ),
            ],
        })
        .unwrap();
        assert!(state.enabled);
        assert_eq!(state.port, u16::MAX);
        assert_eq!(
            state.rules,
            [
                SshRule {
                    network: "example".into(),
                    peer: "*".into(),
                    users: Vec::new()
                },
                SshRule {
                    network: "example".into(),
                    peer: "example-peer".into(),
                    users: vec![r".\example-user".into()]
                },
                SshRule {
                    network: "second-example".into(),
                    peer: "example-peer".into(),
                    users: vec!["*".into()]
                },
            ]
        );
    }

    #[test]
    fn empty_ssh_grants_and_failed_reads_remain_distinct() {
        let state = SshState::from_response(IpcMessage::FirewallSshState {
            enabled: false,
            port: u16::MAX,
            networks: Vec::new(),
        })
        .unwrap();
        assert!(!state.enabled);
        assert!(state.rules.is_empty());
        let error = SshState::from_response(IpcMessage::Error {
            message: "Example SSH settings read failed.".into(),
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "Example SSH settings read failed.");
        let unexpected = SshState::from_response(IpcMessage::PairingTicket {
            ticket: "example-secret".into(),
        })
        .unwrap_err();
        assert!(unexpected.to_string().contains("unexpected SSH settings"));
        assert!(!unexpected.to_string().contains("example-secret"));
    }

    #[test]
    fn request_buttons_send_the_matching_daemon_request() {
        let join = PendingItem {
            kind: PendingKind::Join {
                network: "example".into(),
                id: "request-id".into(),
            },
            description: String::new(),
        };
        assert!(
            matches!(join.command(true), IpcMessage::AcceptRequest { network, id } if network == "example" && id == "request-id")
        );
        assert!(
            matches!(join.command(false), IpcMessage::DenyRequest { network, id } if network == "example" && id == "request-id")
        );
        let connection = PendingItem {
            kind: PendingKind::Connect {
                id: "request-id".into(),
            },
            description: String::new(),
        };
        assert!(
            matches!(connection.command(true), IpcMessage::ApproveConnection { id } if id == "request-id")
        );
        assert!(
            matches!(connection.command(false), IpcMessage::ConnectDeny { id } if id == "request-id")
        );
        let file = PendingItem {
            kind: PendingKind::File { id: 3 },
            description: String::new(),
        };
        assert!(matches!(
            file.command(true),
            IpcMessage::AcceptFile { id: 3, .. }
        ));
        assert!(matches!(
            file.command(false),
            IpcMessage::RejectFile { id: 3 }
        ));
        let firewall = PendingItem {
            kind: PendingKind::Firewall {
                network: "example".into(),
            },
            description: String::new(),
        };
        assert!(
            matches!(firewall.command(true), IpcMessage::FirewallAccept { network } if network == "example")
        );
        assert!(
            matches!(firewall.command(false), IpcMessage::FirewallDeny { network } if network == "example")
        );
        assert!(
            matches!(firewall.review_command(), Some(IpcMessage::FirewallPending { network }) if network == "example")
        );
    }
}
