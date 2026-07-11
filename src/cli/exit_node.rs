//! `ray exit-node ...`: offer this node as an internet gateway, or route this
//! node's non-mesh traffic through a peer that offers one.

use crate::*;

pub(crate) async fn ipc_exit_node(action: ExitNodeAction) -> Result<()> {
    let mut filter: Option<String> = None;
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
            network,
            peer: None,
        },
        ExitNodeAction::Status { network } => {
            filter = network.clone();
            ipc::IpcMessage::ExitNodeStatus { network }
        }
    };
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::ExitNodeState { networks } => {
            render_exit_node_state(networks, filter.as_deref())
        }
        ipc::IpcMessage::Error { message } => print_error("exit-node", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

fn render_exit_node_state(networks: Vec<ipc::ExitNodeStatusView>, filter: Option<&str>) {
    let networks: Vec<ipc::ExitNodeStatusView> = networks
        .into_iter()
        .filter(|n| filter.is_none_or(|f| f == n.network))
        .collect();
    if json_enabled() {
        print_json(&serde_json::json!({
            "networks": networks.iter().map(|n| serde_json::json!({
                "network": n.network,
                "offering": !n.allow.is_empty(),
                "allow": n.allow,
                "using": n.using,
                "available": n.available,
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
            let peers: Vec<String> = n
                .allow
                .iter()
                .map(|p| {
                    if p == "*" || p.len() <= 12 {
                        p.clone()
                    } else {
                        format!("{}...", &p[..12])
                    }
                })
                .collect();
            println!("  offering: yes (allow: {})", peers.join(", "));
        }
        match &n.using {
            Some(peer) => println!("  using: {peer}"),
            None => println!("  using: direct egress"),
        }
        if n.available.is_empty() {
            println!("  available: (none advertised)");
        } else {
            println!("  available: {}", n.available.join(", "));
        }
    }
}
