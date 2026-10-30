use anyhow::{Result, bail};

use ray_proto::invite::decode_invite_code;
use ray_proto::ipc::IpcMessage;
use ray_proto::{Action, Direction, GroupMode, Protocol};

use crate::model::SshRule;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FormKind {
    Create,
    Join,
    Connect,
    Rename,
    Firewall,
}

pub(crate) struct Field {
    pub label: &'static str,
    pub choices: &'static [&'static str],
    pub required: bool,
    pub hint: &'static str,
}

impl Field {
    const fn text(label: &'static str, required: bool) -> Self {
        Self {
            label,
            choices: &[],
            required,
            hint: "",
        }
    }

    const fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = hint;
        self
    }

    const fn choice(label: &'static str, choices: &'static [&'static str]) -> Self {
        Self {
            label,
            choices,
            required: true,
            hint: "",
        }
    }
}

impl FormKind {
    pub fn submit_label(self) -> &'static str {
        match self {
            Self::Create => "Create network",
            Self::Join => "Join network",
            Self::Connect => "Send request",
            Self::Rename => "Save name",
            Self::Firewall => "Add rule",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Create => "Create a network",
            Self::Join => "Join a network",
            Self::Connect => "Connect to a peer",
            Self::Rename => "Rename this PC in the network",
            Self::Firewall => "Add a firewall rule",
        }
    }

    pub fn fields(self) -> &'static [Field] {
        const CREATE: &[Field] = &[
            Field::text("Network name (optional)", false),
            Field::text("This PC's name (optional)", false),
        ];
        const JOIN: &[Field] = &[
            Field::text("Invite code", true),
            Field::text("This PC's name (optional)", false),
        ];
        const CONNECT: &[Field] = &[
            Field::text("Identity or nearby peer ID", true),
            Field::text("This PC's name (optional)", false),
        ];
        const RENAME: &[Field] = &[Field::text("This PC's name", true)];
        const FIREWALL: &[Field] = &[
            Field::choice("Direction", &["in", "out"])
                .with_hint("in: traffic to this PC; out: traffic from this PC"),
            Field::choice("Action", &["allow", "deny"]),
            Field::choice("Protocol", &["tcp", "udp", "icmp", "any"]),
            Field::text("Ports (blank means Any)", false)
                .with_hint("443 or 8000-9000; leave blank for all ports"),
            Field::text("Peer (blank means Any)", false)
                .with_hint("Peer name, IP address or identity"),
            Field::text("Network (blank means Any)", false)
                .with_hint("Network name; leave blank for every network"),
        ];
        match self {
            Self::Create => CREATE,
            Self::Join => JOIN,
            Self::Connect => CONNECT,
            Self::Rename => RENAME,
            Self::Firewall => FIREWALL,
        }
    }

    pub fn initial_values(self) -> Vec<String> {
        let mut values = self
            .fields()
            .iter()
            .map(|field| field.choices.first().copied().unwrap_or("").to_owned())
            .collect::<Vec<_>>();
        if self == Self::Firewall {
            // Start with one TCP port instead of an unrestricted allow rule.
            values[3] = "443".into();
        }
        values
    }

    pub fn command(self, values: &[String], network: Option<&str>) -> Result<IpcMessage> {
        let fields = self.fields();
        if values.len() != fields.len() {
            bail!("The form is incomplete.");
        }
        for (field, value) in fields.iter().zip(values) {
            if field.required && value.trim().is_empty() {
                bail!("Enter {}.", field.label.to_lowercase());
            }
            if !field.choices.is_empty() && !field.choices.contains(&value.as_str()) {
                bail!("Select {}.", field.label.to_lowercase());
            }
        }
        let value = |index: usize| {
            let text = values[index].trim();
            (!text.is_empty()).then(|| text.to_owned())
        };
        Ok(match self {
            Self::Create => IpcMessage::Create {
                mode: GroupMode::default(),
                name: value(0),
                hostname: value(1),
                transport: None,
            },
            Self::Join => {
                let code = values[0].trim();
                // Bare network keys are shorter than encoded invites. Preserve
                // them, but report damaged invite credentials before sending.
                let decoded = match decode_invite_code(code) {
                    Ok(invite) => Some(invite),
                    Err(_) if code.len() <= 64 => None,
                    Err(error) => return Err(error),
                };
                IpcMessage::Join {
                    network_key: decoded
                        .as_ref()
                        .map_or_else(|| code.to_owned(), |invite| invite.network_key.to_string()),
                    name: None,
                    hostname: value(1),
                    transport: None,
                    coordinator: decoded.as_ref().map(|invite| invite.coordinator),
                    invite: decoded.map(|invite| invite.secret),
                    auto_accept_firewall: false,
                    auto_accept_files: true,
                }
            }
            Self::Connect => IpcMessage::Connect {
                peer: values[0].trim().to_owned(),
                hostname: value(1),
            },
            Self::Rename => IpcMessage::SetHostname {
                network: network
                    .ok_or_else(|| anyhow::anyhow!("Select a network."))?
                    .to_owned(),
                hostname: values[0].trim().to_owned(),
            },
            Self::Firewall => {
                let protocol = values[2].parse::<Protocol>().map_err(anyhow::Error::msg)?;
                IpcMessage::FirewallAdd {
                    direction: values[0].parse::<Direction>().map_err(anyhow::Error::msg)?,
                    action: values[1].parse::<Action>().map_err(anyhow::Error::msg)?,
                    protocol,
                    port: if protocol == Protocol::Icmp {
                        None
                    } else {
                        value(3)
                    },
                    peer: value(4),
                    network: value(5),
                }
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SshAccounts {
    Specific,
    NonAdministrator,
    All,
}

impl SshAccounts {
    pub const ALL: [Self; 3] = [Self::Specific, Self::NonAdministrator, Self::All];

    pub fn label(self) -> &'static str {
        match self {
            Self::Specific => "Specific accounts",
            Self::NonAdministrator => "Any account except administrators",
            Self::All => "Any account, including administrators",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SshPeerScope {
    Specific,
    All,
}

pub(crate) struct SshEditor {
    pub network: String,
    pub peer: String,
    pub scope: SshPeerScope,
    pub accounts: SshAccounts,
    pub usernames: String,
    pub original: Option<SshRule>,
}

impl SshEditor {
    pub fn new(network: Option<&str>) -> Self {
        Self {
            network: network.unwrap_or_default().into(),
            peer: String::new(),
            scope: SshPeerScope::Specific,
            accounts: SshAccounts::Specific,
            usernames: String::new(),
            original: None,
        }
    }

    pub fn edit(rule: SshRule) -> Self {
        Self {
            network: rule.network.clone(),
            peer: rule.peer.clone(),
            scope: if rule.peer == "*" {
                SshPeerScope::All
            } else {
                SshPeerScope::Specific
            },
            accounts: if rule.users.contains(&"*".to_owned()) {
                SshAccounts::All
            } else if rule.users.is_empty() {
                SshAccounts::NonAdministrator
            } else {
                SshAccounts::Specific
            },
            usernames: rule
                .users
                .iter()
                .filter(|user| user.as_str() != "*")
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            original: Some(rule),
        }
    }

    pub fn command(&self) -> Result<IpcMessage> {
        let network = self.network.trim();
        if network.is_empty() || network.contains('\0') {
            bail!("Choose a network.");
        }
        let peer = match self.scope {
            SshPeerScope::All => "*",
            SshPeerScope::Specific => {
                let peer = self.peer.trim();
                if peer.is_empty() || peer.contains('\0') {
                    bail!("Choose or enter a peer.");
                }
                if peer == "*" {
                    bail!("Choose All peers on this network explicitly to allow every peer.");
                }
                peer
            }
        };
        let users = match self.accounts {
            SshAccounts::All => vec!["*".into()],
            SshAccounts::NonAdministrator => Vec::new(),
            SshAccounts::Specific => {
                let mut users = Vec::new();
                for name in self
                    .usernames
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                {
                    if name.contains(['*', '\0']) {
                        bail!("Enter specific local usernames, without wildcards.");
                    }
                    if !users.iter().any(|user| user == name) {
                        users.push(name.to_owned());
                    }
                }
                if users.is_empty() {
                    bail!("Enter at least one local Windows username.");
                }
                users
            }
        };
        Ok(IpcMessage::FirewallSshAllow {
            network: network.to_owned(),
            peer: peer.to_owned(),
            users,
            allow: true,
        })
    }
}

pub(crate) fn console_args(input: &str) -> Result<Vec<String>> {
    // Parse quotes without consuming Windows path separators. No shell is involved.
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut started = false;
    for ch in input.chars() {
        if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
            started = true;
        } else if quote.is_none() && ch.is_whitespace() {
            if started {
                args.push(std::mem::take(&mut current));
                started = false;
            }
        } else {
            current.push(ch);
            started = true;
        }
    }
    if quote.is_some() {
        bail!("Close the quoted argument.");
    }
    if started {
        args.push(current);
    }
    if args.first().is_some_and(|arg| arg == "ray") {
        args.remove(0);
    }
    let command = args.iter().find(|arg| !arg.starts_with('-'));
    match command.map(String::as_str) {
        None => bail!("Enter a ray command."),
        Some("gui" | "daemon" | "rootless") => bail!("Use a terminal for this command."),
        _ => Ok(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_preserves_windows_paths_and_quoted_arguments() {
        assert_eq!(
            console_args(r#"ray send "C:\My Files\note.txt" peer"#).unwrap(),
            ["send", r"C:\My Files\note.txt", "peer"]
        );
        assert!(console_args("status \"").is_err());
        assert!(console_args("--system daemon").is_err());
    }

    #[test]
    fn join_preserves_the_invite_credentials_and_paired_device_file_policy() {
        use crate::model::words;

        let key = "5866666666666666666666666666666666666666666666666666666666666666"
            .parse()
            .unwrap();
        let code = ray_proto::invite::encode_invite_code(&key, &key, &[1; 16]);
        let request = FormKind::Join
            .command(&words(&[&code, "workstation"]), None)
            .unwrap();
        match request {
            IpcMessage::Join {
                network_key,
                coordinator,
                invite,
                hostname,
                auto_accept_files,
                ..
            } => {
                assert_eq!(network_key, key.to_string());
                assert_eq!(coordinator, Some(key));
                assert_eq!(invite, Some(vec![1; 16]));
                assert_eq!(hostname.as_deref(), Some("workstation"));
                assert!(auto_accept_files);
            }
            _ => panic!("join should produce the typed Join request"),
        }
        assert!(
            FormKind::Join
                .command(&words(&[&code[..code.len() - 4], ""]), None)
                .is_err()
        );
    }

    #[test]
    fn ssh_grants_require_explicit_peer_and_account_scopes() {
        let mut editor = SshEditor::new(Some("example"));
        assert!(editor.command().is_err());
        editor.peer = "*".into();
        editor.usernames = "local-user".into();
        assert!(editor.command().is_err());
        editor.scope = SshPeerScope::All;
        assert!(
            matches!(editor.command().unwrap(), IpcMessage::FirewallSshAllow {
            peer, users, allow: true, ..
        } if peer == "*" && users == ["local-user"])
        );
        editor.usernames = "*".into();
        assert!(editor.command().is_err());
        editor.accounts = SshAccounts::NonAdministrator;
        assert!(
            matches!(editor.command().unwrap(), IpcMessage::FirewallSshAllow { users, .. } if users.is_empty())
        );
        editor.accounts = SshAccounts::All;
        assert!(
            matches!(editor.command().unwrap(), IpcMessage::FirewallSshAllow { users, .. } if users == ["*"])
        );
    }

    #[test]
    fn editing_ssh_access_updates_the_same_scope_and_preserves_local_names() {
        let mut editor = SshEditor::edit(SshRule {
            network: "example".into(),
            peer: "example-peer".into(),
            users: vec!["local-user".into()],
        });
        editor.usernames = " Local User, local-user, Local User ".into();
        assert!(
            matches!(editor.command().unwrap(), IpcMessage::FirewallSshAllow {
            network, peer, users, allow: true,
        } if network == "example" && peer == "example-peer" && users == ["Local User", "local-user"])
        );
    }

    #[test]
    fn firewall_form_starts_with_one_tcp_port_and_blank_any_scopes() {
        let values = FormKind::Firewall.initial_values();
        assert_eq!(values, ["in", "allow", "tcp", "443", "", ""]);
        assert!(matches!(
            FormKind::Firewall.command(&values, None).unwrap(),
            IpcMessage::FirewallAdd {
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                port: Some(port), peer: None, network: None,
            } if port == "443"
        ));
        assert!(FormKind::Firewall.fields()[4].label.contains("Any"));
        assert!(FormKind::Firewall.fields()[5].label.contains("Any"));
    }

    #[test]
    fn selecting_icmp_does_not_keep_the_tcp_port_filter() {
        let mut values = FormKind::Firewall.initial_values();
        values[2] = "icmp".into();
        assert!(matches!(
            FormKind::Firewall.command(&values, None).unwrap(),
            IpcMessage::FirewallAdd {
                protocol: Protocol::Icmp,
                port: None,
                ..
            }
        ));
    }

    #[test]
    fn firewall_form_trims_scopes_and_preserves_explicit_ranges() {
        use crate::model::words;
        assert!(matches!(
            FormKind::Firewall.command(&words(&["out", "deny", "udp", " 8000-9000 ", " example-peer ", " example "]), None).unwrap(),
            IpcMessage::FirewallAdd {
                direction: Direction::Out, action: Action::Deny, protocol: Protocol::Udp,
                port: Some(port), peer: Some(peer), network: Some(network),
            } if port == "8000-9000" && peer == "example-peer" && network == "example"
        ));
        assert!(matches!(
            FormKind::Firewall
                .command(&words(&["in", "allow", "any", "  ", " ", " "]), None)
                .unwrap(),
            IpcMessage::FirewallAdd {
                port: None,
                peer: None,
                network: None,
                ..
            }
        ));
        assert!(
            FormKind::Firewall
                .command(&words(&["in", "allow", "unknown", "", "", ""]), None)
                .is_err()
        );
    }

    #[test]
    fn forms_build_typed_daemon_requests() {
        use crate::model::words;
        assert!(FormKind::Join.command(&words(&["", ""]), None).is_err());
        assert!(matches!(
            FormKind::Create.command(&words(&["example", "pc"]), None).unwrap(),
            IpcMessage::Create { name: Some(name), hostname: Some(hostname), .. } if name == "example" && hostname == "pc"
        ));
        assert!(matches!(
            FormKind::Join.command(&words(&["network-key", ""]), None).unwrap(),
            IpcMessage::Join { network_key, hostname: None, invite: None, .. } if network_key == "network-key"
        ));
        assert!(matches!(
            FormKind::Rename.command(&words(&["new-name"]), Some("example")).unwrap(),
            IpcMessage::SetHostname { network, hostname } if network == "example" && hostname == "new-name"
        ));
        assert!(
            FormKind::Firewall
                .command(&words(&["in", "oops", "tcp", "", "", ""]), None)
                .is_err()
        );
        assert!(
            matches!(FormKind::Firewall.command(&words(&["in", "allow", "tcp", "443", "", "example"]), None).unwrap(),
            IpcMessage::FirewallAdd { direction: Direction::In, action: Action::Allow, protocol: Protocol::Tcp, network: Some(network), .. } if network == "example")
        );
    }
}
