//! CLI direct-connection, contact, ping/netcheck and admin handlers.

use crate::*;

pub(crate) async fn ipc_connect(contact_id: &str, hostname: Option<String>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Connect {
            contact_id: contact_id.to_string(),
            hostname,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Joined { name, my_ip, .. } => {
            println!(
                "  {} connected — direct network {} ({})",
                style::green("✓"),
                style::value(&name),
                style::faint(&my_ip.to_string()),
            );
        }
        ipc::IpcMessage::Error { message } => print_error("connect failed", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_connections(action: Option<ConnectionsAction>) -> Result<()> {
    match action.unwrap_or(ConnectionsAction::List) {
        ConnectionsAction::List => ipc_connections_list().await,
        ConnectionsAction::Approve { id } => ipc_connections_approve(&id).await,
    }
}

pub(crate) async fn ipc_connections_list() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Connections).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PendingRequests { requests } => {
            if json_enabled() {
                print_json(&serde_json::json!(requests
                    .iter()
                    .map(|r| serde_json::json!({
                        "id": r.short_id, "hostname": r.hostname, "waiting_secs": r.waiting_secs,
                    }))
                    .collect::<Vec<_>>()));
            } else if requests.is_empty() {
                println!("\n  {}\n", style::faint("no pending connection requests"));
            } else {
                let rows = requests
                    .iter()
                    .map(|r| {
                        let host = r.hostname.clone().unwrap_or_else(|| "—".to_string());
                        let wait = format!("{}s", r.waiting_secs);
                        vec![
                            layout::Cell::new(r.short_id.clone(), style::rose(&r.short_id)),
                            layout::Cell::new(host.clone(), style::value(&host)),
                            layout::Cell::right(wait.clone(), style::faint(&wait)),
                        ]
                    })
                    .collect();
                println!();
                print!("{}", table(&["id", "host", "waiting"], rows, 2));
                println!(
                    "\n  {}",
                    style::faint("approve with: ray connections approve <id>")
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_connections_approve(id: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::ApproveConnection { id: id.to_string() },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_contact(action: Option<ContactAction>) -> Result<()> {
    let req = match action.unwrap_or(ContactAction::Id) {
        ContactAction::Id => ipc::IpcMessage::ContactId,
        ContactAction::Rotate => ipc::IpcMessage::RotateContact,
    };
    let rotating = matches!(req, ipc::IpcMessage::RotateContact);
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::ContactIdResponse { contact_id } => {
            if json_enabled() {
                print_json(&serde_json::json!({ "contact_id": contact_id }));
            } else {
                if rotating {
                    println!("  {} contact id rotated", style::green("✓"));
                }
                println!("{}", contact_id);
                println!(
                    "  {}",
                    style::faint("share this so others can: ray connect <contact-id>")
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_ping(peer: &str, count: u32, interval: u64) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Ping {
            peer: peer.to_string(),
            count,
            interval_ms: interval,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PingResponse {
            peer_name,
            conn_type,
            remote_addr,
            network,
            probes,
        } => {
            let conn_str = match conn_type {
                ipc::ConnType::Direct => "direct",
                ipc::ConnType::Relay => "relay",
                ipc::ConnType::Tor => "tor",
                ipc::ConnType::Unknown => "?",
            };
            let sent = probes.len();
            let rtts: Vec<f64> = probes.iter().filter_map(|p| *p).collect();
            let received = rtts.len();

            if json_enabled() {
                print_json(&serde_json::json!({
                    "peer": peer_name,
                    "network": network,
                    "conn_type": conn_str,
                    "remote_addr": remote_addr,
                    "sent": sent,
                    "received": received,
                    "rtts_ms": probes,
                }));
                return Ok(());
            }

            let addr = remote_addr.unwrap_or_else(|| "?".to_string());
            for (seq, probe) in probes.iter().enumerate() {
                match probe {
                    Some(ms) => println!(
                        "  {} pong from {} via {} {}  seq={seq} rtt={}",
                        style::green("✓"),
                        style::value(&peer_name),
                        conn_str,
                        style::faint(&addr),
                        style::latency(*ms),
                    ),
                    None => println!(
                        "  {} no reply from {}  seq={seq} {}",
                        style::red("✗"),
                        style::value(&peer_name),
                        style::faint("(timeout)"),
                    ),
                }
            }

            let loss = if sent > 0 {
                (sent - received) as f64 * 100.0 / sent as f64
            } else {
                0.0
            };
            println!();
            println!("  --- {peer_name} ping statistics ---");
            if rtts.is_empty() {
                println!("  {sent} sent, {received} received, {loss:.0}% loss");
                println!(
                    "  {}",
                    style::faint(
                        "no replies — the peer may be offline, firewalled, or on an \
                         incompatible version (run ray update)"
                    )
                );
            } else {
                let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
                let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                let avg = rtts.iter().sum::<f64>() / received as f64;
                println!(
                    "  {sent} sent, {received} received, {loss:.0}% loss, \
                     rtt min/avg/max {min:.0}/{avg:.0}/{max:.0} ms"
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_netcheck() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Netcheck).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::NetcheckResponse {
            bound_port,
            port_is_fixed,
            home_relay,
            relay_latency_ms,
            public_ipv4,
            public_ipv6,
            udp,
        } => {
            if json_enabled() {
                print_json(&serde_json::json!({
                    "bound_port": bound_port,
                    "port_is_fixed": port_is_fixed,
                    "home_relay": home_relay,
                    "relay_latency_ms": relay_latency_ms,
                    "public_ipv4": public_ipv4,
                    "public_ipv6": public_ipv6,
                    "udp": udp,
                }));
                return Ok(());
            }
            let na = || style::faint("—").to_string();
            let port_note = if port_is_fixed {
                style::faint("  (fixed, forwardable)")
            } else {
                style::faint("  (ephemeral fallback)")
            };
            println!(
                "  {:<15}{}{port_note}",
                "UDP port",
                style::value(&bound_port.to_string())
            );
            println!(
                "  {:<15}{}",
                "UDP working",
                if udp {
                    style::green("yes")
                } else {
                    style::red("no")
                }
            );
            println!(
                "  {:<15}{}",
                "Home relay",
                home_relay.map(|s| style::value(&s)).unwrap_or_else(na)
            );
            println!(
                "  {:<15}{}",
                "Relay latency",
                relay_latency_ms.map(style::latency).unwrap_or_else(na)
            );
            println!(
                "  {:<15}{}",
                "Public IPv4",
                public_ipv4.map(|s| style::value(&s)).unwrap_or_else(na)
            );
            println!(
                "  {:<15}{}",
                "Public IPv6",
                public_ipv6.map(|s| style::value(&s)).unwrap_or_else(na)
            );
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_admin(network: &str, action: AdminAction) -> Result<()> {
    let req = match action {
        AdminAction::Add { identity } => ipc::IpcMessage::AdminAdd {
            network: network.to_string(),
            identity,
        },
        AdminAction::List => ipc::IpcMessage::AdminList {
            network: network.to_string(),
        },
    };
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::AdminListResponse { admins } => {
            if json_enabled() {
                print_json(&serde_json::json!(
                    admins
                        .iter()
                        .map(|a| serde_json::json!({ "id": a.short_id, "self": a.self_node }))
                        .collect::<Vec<_>>()
                ));
            } else if admins.is_empty() {
                println!("\n  {}\n", style::faint("no admins recorded"));
            } else {
                println!();
                let mut rows = Vec::new();
                for a in &admins {
                    let (glyph, tag) = if a.self_node {
                        (style::dot_online(), style::marker("this device"))
                    } else {
                        (style::dot_offline(), String::new())
                    };
                    rows.push(vec![
                        layout::Cell::new("●", glyph),
                        layout::Cell::new(a.short_id.clone(), style::value(&a.short_id)),
                        layout::Cell::new(if a.self_node { "this device" } else { "" }, tag),
                    ]);
                }
                print!("{}", indent(&layout::columns(&rows, 2), 2));
                println!();
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}
