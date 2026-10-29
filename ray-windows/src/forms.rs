use anyhow::{Result, bail};

use crate::model::words;

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
}

impl Field {
    const fn text(label: &'static str, required: bool) -> Self {
        Self {
            label,
            choices: &[],
            required,
        }
    }

    const fn choice(label: &'static str, choices: &'static [&'static str]) -> Self {
        Self {
            label,
            choices,
            required: true,
        }
    }
}

impl FormKind {
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
            Field::choice("Direction", &["in", "out"]),
            Field::choice("Action", &["allow", "deny"]),
            Field::choice("Protocol", &["tcp", "udp", "icmp", "any"]),
            Field::text("Ports (optional)", false),
            Field::text("Peer (optional)", false),
            Field::text("Network (optional)", false),
        ];
        match self {
            Self::Create => CREATE,
            Self::Join => JOIN,
            Self::Connect => CONNECT,
            Self::Rename => RENAME,
            Self::Firewall => FIREWALL,
        }
    }

    pub fn command(self, values: &[String], network: Option<&str>) -> Result<Vec<String>> {
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
        let mut args = match self {
            Self::Create => words(&["create"]),
            Self::Join => words(&["join", values[0].trim()]),
            Self::Connect => words(&["connect", values[0].trim()]),
            Self::Rename => words(&[
                "hostname",
                network.ok_or_else(|| anyhow::anyhow!("Select a network."))?,
                values[0].trim(),
            ]),
            Self::Firewall => words(&[
                "firewall", "add", &values[0], &values[1], "--proto", &values[2],
            ]),
        };
        let options: &[(usize, &str)] = match self {
            Self::Create => &[(0, "--name"), (1, "--hostname")],
            Self::Join | Self::Connect => &[(1, "--hostname")],
            Self::Rename => &[],
            Self::Firewall => &[(3, "--port"), (4, "--peer"), (5, "--network")],
        };
        for (index, flag) in options {
            if !values[*index].trim().is_empty() {
                args.extend(words(&[flag, values[*index].trim()]));
            }
        }
        Ok(args)
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
    fn forms_validate_required_fields_and_pass_arguments_without_a_shell() {
        assert!(FormKind::Join.command(&words(&["", ""]), None).is_err());
        assert_eq!(
            FormKind::Create
                .command(&words(&["example", "pc"]), None)
                .unwrap(),
            ["create", "--name", "example", "--hostname", "pc"]
        );
        assert_eq!(
            FormKind::Join
                .command(&words(&["invite-code", ""]), None)
                .unwrap(),
            ["join", "invite-code"]
        );
        assert_eq!(
            FormKind::Rename
                .command(&words(&["new-name"]), Some("example"))
                .unwrap(),
            ["hostname", "example", "new-name"]
        );
        assert!(
            FormKind::Firewall
                .command(&words(&["in", "oops", "tcp", "", "", ""]), None)
                .is_err()
        );
    }
}
