//! `ray exit-node ...`: offer this node as an internet gateway, or route this
//! node's non-mesh traffic through a peer that offers one.

use crate::*;

#[derive(serde::Serialize)]
struct ExitNodeOutput<'a> {
    networks: Vec<ExitNodeRow<'a>>,
    #[serde(skip)]
    status: &'a [ipc::ExitNodeStatusView],
}

#[derive(serde::Serialize)]
struct ExitNodeRow<'a> {
    network: &'a str,
    offering: bool,
    allow: &'a [String],
    using: &'a Option<String>,
    available: &'a [String],
    available_v6: &'a [String],
    available_v4: &'a [String],
    refused: &'a [String],
    not_in_effect: &'a Option<String>,
    tunnel_v4: bool,
    tunnel_v6: bool,
}

impl<'a> ExitNodeOutput<'a> {
    fn new(status: &'a [ipc::ExitNodeStatusView]) -> Self {
        Self {
            networks: status
                .iter()
                .map(|n| ExitNodeRow {
                    network: &n.network,
                    offering: !n.allow.is_empty(),
                    allow: &n.allow,
                    using: &n.using,
                    available: &n.available,
                    available_v6: &n.available_v6,
                    available_v4: &n.available_v4,
                    refused: &n.refused,
                    not_in_effect: &n.not_in_effect,
                    tunnel_v4: n.tunnel_v4,
                    tunnel_v6: n.tunnel_v6,
                })
                .collect(),
            status,
        }
    }
}

pub(crate) async fn ipc_exit_node(action: ExitNodeAction) -> Result<()> {
    // `none`/`off`/`disable` with no network clears every network that has a
    // selection, resolved client-side so the daemon keeps its per-network API.
    if let ExitNodeAction::None { network: None } = &action {
        return clear_all_exit_selections().await;
    }
    let req = match action {
        ExitNodeAction::Allow { network, peer } => ipc::IpcMessage::ExitNodeAllow {
            network,
            peer,
            allow: true,
        },
        ExitNodeAction::Disallow { network, peer } => ipc::IpcMessage::ExitNodeAllow {
            network,
            peer,
            allow: false,
        },
        ExitNodeAction::Use { network, peer } => ipc::IpcMessage::ExitNodeUse {
            network,
            peer: Some(peer),
        },
        ExitNodeAction::None { network } => ipc::IpcMessage::ExitNodeUse {
            network: network.expect("bare `none` handled above"),
            peer: None,
        },
        ExitNodeAction::Status { network } => ipc::IpcMessage::ExitNodeStatus { network },
    };
    match ipc_request(req).await? {
        ipc::IpcMessage::Ok { message } => print_message(&message)?,
        ipc::IpcMessage::ExitNodeState { networks } => printout(&ExitNodeOutput::new(&networks))?,
        ipc::IpcMessage::Error { message } => fail_with("exit-node", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Clear the exit selection on every network that currently has one. Queries
/// status first, then sends one `none` per active network. No-op with a friendly
/// note when nothing is routed through an exit.
async fn clear_all_exit_selections() -> Result<()> {
    let active: Vec<String> =
        match ipc_request(ipc::IpcMessage::ExitNodeStatus { network: None }).await? {
            ipc::IpcMessage::ExitNodeState { networks } => networks
                .into_iter()
                .filter(|n| n.using.is_some())
                .map(|n| n.network)
                .collect(),
            ipc::IpcMessage::Error { message } => fail_with("exit-node", &message),
            other => fail_unexpected(&other),
        };
    if active.is_empty() {
        println!("no exit node in use");
        return Ok(());
    }
    // Every network is attempted even after one fails, and the exit code comes
    // at the end. Stopping at the first would leave the rest still routing
    // through their exit nodes, which is the opposite of what was asked, and
    // would say so only about the network it got to.
    let mut failed = 0usize;
    for network in active {
        let reply = ipc_request(ipc::IpcMessage::ExitNodeUse {
            network: network.clone(),
            peer: None,
        })
        .await?;
        match reply {
            ipc::IpcMessage::Ok { message } => println!("{}", style::printable_lines(&message)),
            ipc::IpcMessage::Error { message } => {
                print_error("exit-node", &format!("{network}: {message}"), None);
                failed += 1;
            }
            // Counted, not exited, for the same reason as the arm above.
            other => {
                print_error(
                    "exit-node",
                    &format!("{network}: {}", unexpected_detail(&other)),
                    None,
                );
                failed += 1;
            }
        }
    }
    anyhow::ensure!(
        failed == 0,
        "{failed} network(s) are still using an exit node"
    );
    Ok(())
}

impl DisplayOut for ExitNodeOutput<'_> {
    fn print_human(&self) {
        if self.status.is_empty() {
            println!("(no networks)");
            return;
        }
        for n in self.status {
            println!("{}:", n.network);
            if n.allow.is_empty() {
                println!("  offering: no");
            } else {
                // Allow entries are `*` or a 64-char identity hex; abbreviate the hex.
                let peers: Vec<String> = n
                    .allow
                    .iter()
                    .map(|p| match p.len() > 12 {
                        true => format!("{}...", &p[..12]),
                        false => p.clone(),
                    })
                    .collect();
                println!("  offering: yes (allow: {})", peers.join(", "));
            }
            match (&n.using, n.not_in_effect.as_deref()) {
                // The reason describes whether traffic is blocked or routing
                // could not be installed. Do not assume a direct fallback.
                (Some(peer), Some(why)) => {
                    println!("  using: {peer} (NOT in effect: {why})")
                }
                // Unsupported families stay captured and blocked.
                (Some(peer), None) => match (n.tunnel_v4, n.tunnel_v6) {
                    (true, true) => println!("  using: {peer}"),
                    (false, true) => println!("  using: {peer} (IPv6 only; IPv4 blocked)"),
                    (true, false) => println!("  using: {peer} (IPv4 only; IPv6 blocked)"),
                    (false, false) => println!("  using: {peer} (carries neither family)"),
                },
                (None, _) => println!("  using: direct egress"),
            }
            if n.available.is_empty() {
                println!("  available: (none advertised)");
            } else {
                let listed: Vec<String> = n
                    .available
                    .iter()
                    .map(|peer| available_gateway(n, peer))
                    .collect();
                println!("  available: {}", listed.join(", "));
            }
        }
    }
}

fn available_gateway(status: &ipc::ExitNodeStatusView, peer: &str) -> String {
    let contains = |peers: &[String]| peers.iter().any(|name| name == peer);
    let families = match (
        contains(&status.available_v4),
        contains(&status.available_v6),
    ) {
        (true, true) => "IPv4, IPv6",
        (true, false) => "IPv4",
        (false, true) => "IPv6",
        (false, false) => "capabilities unknown",
    };
    if contains(&status.refused) {
        format!("{peer} (unusable from this node)")
    } else {
        format!("{peer} ({families})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_gateways_name_both_families_and_missing_claims() {
        let status = ipc::ExitNodeStatusView {
            network: "example".into(),
            allow: vec![],
            using: None,
            available: vec![],
            available_v4: vec!["dual".into(), "v4".into()],
            available_v6: vec!["dual".into(), "v6".into()],
            refused: vec!["down".into()],
            not_in_effect: None,
            tunnel_v4: false,
            tunnel_v6: false,
        };
        for (peer, expected) in [
            ("dual", "dual (IPv4, IPv6)"),
            ("v4", "v4 (IPv4)"),
            ("v6", "v6 (IPv6)"),
            ("legacy", "legacy (capabilities unknown)"),
            ("down", "down (unusable from this node)"),
        ] {
            assert_eq!(available_gateway(&status, peer), expected);
        }
    }
}
