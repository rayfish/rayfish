//! `ray exit-node ...`: offer this node as an internet gateway, or route this
//! node's non-mesh traffic through a peer that offers one.

use crate::*;

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
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::ExitNodeState { networks } => render_exit_node_state(networks),
        ipc::IpcMessage::Error { message } => fail_with("exit-node", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Clear the exit selection on every network that currently has one. Queries
/// status first, then sends one `none` per active network. No-op with a friendly
/// note when nothing is routed through an exit.
async fn clear_all_exit_selections() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::ExitNodeStatus { network: None },
    )
    .await?;
    let active: Vec<String> = match ipc::recv(&mut stream).await? {
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
        let mut s = ipc::connect().await?;
        ipc::send(
            &mut s,
            ipc::IpcMessage::ExitNodeUse {
                network: network.clone(),
                peer: None,
            },
        )
        .await?;
        match ipc::recv(&mut s).await? {
            ipc::IpcMessage::Ok { message } => println!("{message}"),
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

/// Render the daemon's reply (already filtered to the requested network, if any).
fn render_exit_node_state(networks: Vec<ipc::ExitNodeStatusView>) {
    if json_enabled() {
        print_json(&serde_json::json!({
            "networks": networks.iter().map(|n| serde_json::json!({
                "network": n.network,
                "offering": !n.allow.is_empty(),
                "allow": n.allow,
                "using": n.using,
                "available": n.available,
                "available_v6": n.available_v6,
                "refused": n.refused,
                "not_in_effect": n.not_in_effect,
                "tunnel_v4": n.tunnel_v4,
                "tunnel_v6": n.tunnel_v6,
            })).collect::<Vec<_>>(),
        }));
        return;
    }
    if networks.is_empty() {
        println!("(no networks)");
        return;
    }
    for n in &networks {
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
            // A selection the daemon is not acting on is the one thing this line
            // must not print bare: the config says `gw` and the packets leave
            // directly, and nothing else on screen says so.
            (Some(peer), Some(why)) => {
                println!("  using: {peer} (NOT in effect: {why}; traffic leaves directly)")
            }
            // A tunnel takes only the families both ends carry, so a bare
            // "using: <peer>" would read as a full tunnel over both when it is
            // one family and a direct path for the other.
            (Some(peer), None) => match (n.tunnel_v4, n.tunnel_v6) {
                (true, true) => println!("  using: {peer}"),
                (false, true) => println!("  using: {peer} (IPv6 only; IPv4 leaves directly)"),
                (true, false) => println!("  using: {peer} (IPv4 only; IPv6 leaves directly)"),
                (false, false) => println!("  using: {peer} (carries neither family)"),
            },
            (None, _) => println!("  using: direct egress"),
        }
        if n.available.is_empty() {
            println!("  available: (none advertised)");
        } else {
            // A gateway this node would refuse is marked as such, and that beats
            // marking the ones that carry IPv6: the two lists stopped agreeing
            // once a gateway could be IPv6-only itself, and it is the refusal
            // that decides whether `ray exit-node use` works.
            let listed: Vec<String> = n
                .available
                .iter()
                .map(|peer| {
                    if n.refused.contains(peer) {
                        format!("{peer} (unusable from this node)")
                    } else if n.available_v6.contains(peer) {
                        format!("{peer} (IPv6)")
                    } else {
                        peer.clone()
                    }
                })
                .collect();
            println!("  available: {}", listed.join(", "));
        }
    }
}
