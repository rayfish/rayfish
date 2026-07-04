//! CLI invite + join-request handlers: mint/list/revoke, requests/accept/deny.

use crate::*;

/// Parse a duration like `30m`, `24h`, `7d`, `90s` into seconds.
pub(crate) fn parse_duration_secs(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(rest) = s.strip_suffix('s') {
        (rest, 1u64)
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = s.strip_suffix('h') {
        (rest, 3600)
    } else if let Some(rest) = s.strip_suffix('d') {
        (rest, 86400)
    } else {
        (s, 1)
    };
    let value: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration '{s}': use e.g. 30m, 24h, 7d"))?;
    Ok(value * mult)
}

pub(crate) async fn ipc_invite(network: &str, action: Option<InviteAction>) -> Result<()> {
    let show_qr = matches!(&action, Some(InviteAction::Create { qr: true, .. }));
    let action = action.unwrap_or(InviteAction::Create {
        expires: None,
        hostname: None,
        reusable: false,
        qr: false,
    });
    let hostname_opt = match &action {
        InviteAction::Create { hostname, .. } => hostname.clone(),
        _ => None,
    };
    let reusable_requested = matches!(&action, InviteAction::Create { reusable: true, .. });
    let req = match action {
        InviteAction::Create {
            expires,
            hostname,
            reusable,
            qr: _,
        } => {
            // Reusable keys default to a longer 30d TTL; single-use to 7d.
            let ttl = expires.unwrap_or_else(|| {
                if reusable {
                    "30d".to_string()
                } else {
                    "7d".to_string()
                }
            });
            ipc::IpcMessage::InviteCreate {
                network: network.to_string(),
                expires_secs: parse_duration_secs(&ttl)?,
                hostname,
                reusable,
            }
        }
        InviteAction::List => ipc::IpcMessage::InviteList {
            network: network.to_string(),
        },
        InviteAction::Revoke { id } => ipc::IpcMessage::InviteRevoke {
            network: network.to_string(),
            id,
        },
    };
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::InviteCreated {
            code,
            id,
            expires_secs,
        } => print_invite_created(
            &code,
            &id,
            expires_secs,
            show_qr,
            reusable_requested,
            &hostname_opt,
        ),
        ipc::IpcMessage::InviteListResponse { invites } => print_invite_list(&invites),
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Render a freshly minted invite: id, join code, optional QR, TTL, and the
/// reusable/single-use + hostname-binding notes.
fn print_invite_created(
    code: &str,
    id: &str,
    expires_secs: u64,
    show_qr: bool,
    reusable_requested: bool,
    hostname_opt: &Option<String>,
) {
    println!();
    println!(
        "  {} {} {}",
        style::check(),
        style::value("invite"),
        style::faint(id)
    );
    println!();
    println!("  {}", style::bold(code));
    println!();
    if show_qr {
        qr2term::print_qr(code).ok();
    }
    print_next(&[(&format!("ray join {code}"), "the holder runs this to join")]);
    if !show_qr {
        println!("  {}", style::faint("add --qr for a scannable QR code"));
    }
    println!();
    let days = expires_secs / 86400;
    let hours = (expires_secs % 86400) / 3600;
    let ttl = if days > 0 {
        format!("{days}d")
    } else if hours > 0 {
        format!("{hours}h")
    } else {
        format!("{}m", expires_secs / 60)
    };
    if reusable_requested {
        println!("  reusable (multi-use), expires in {ttl}");
        println!(
            "  servers join unattended with: {}",
            style::faint(&format!(
                "ray join {code} --hostname <h> --auto-accept-firewall"
            ))
        );
    } else {
        println!("  single-use, expires in {ttl}");
    }
    if let Some(h) = hostname_opt {
        println!("  binds hostname: {}", style::bold(h));
    }
}

/// Render the invite ledger as JSON (when `--json`) or an aligned table.
fn print_invite_list(invites: &[ipc::InviteInfo]) {
    if json_enabled() {
        print_json(&serde_json::json!(
            invites
                .iter()
                .map(|i| serde_json::json!({
                    "id": i.id, "status": i.status, "redeemer": i.redeemer,
                    "hostname": i.hostname, "reusable": i.reusable,
                    "created": i.created, "expires": i.expires,
                }))
                .collect::<Vec<_>>()
        ));
    } else if invites.is_empty() {
        println!("\n  {}\n", style::faint("no invites"));
    } else {
        let rows = invites
            .iter()
            .map(|inv| {
                let kind = if inv.reusable {
                    "reusable"
                } else {
                    "single-use"
                };
                let host = inv.hostname.clone().unwrap_or_else(|| "—".to_string());
                let who = inv.redeemer.clone().unwrap_or_else(|| "—".to_string());
                vec![
                    layout::Cell::new(inv.id.clone(), style::rose(&inv.id)),
                    layout::Cell::new(inv.status.clone(), style::value(&inv.status)),
                    layout::Cell::new(kind, style::faint(kind)),
                    layout::Cell::new(host.clone(), style::faint(&host)),
                    layout::Cell::new(who.clone(), style::faint(&who)),
                ]
            })
            .collect();
        println!();
        print!(
            "{}",
            table(&["id", "status", "kind", "host", "redeemer"], rows, 2)
        );
        println!();
    }
}

pub(crate) async fn ipc_requests(network: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Requests {
            network: network.to_string(),
        },
    )
    .await?;
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
                println!("\n  {}\n", style::faint("no pending join requests"));
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
                    style::faint(&format!("admit with: ray accept {network} <id>"))
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_accept_request(network: &str, id: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::AcceptRequest {
            network: network.to_string(),
            id: id.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_deny_request(network: &str, id: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::DenyRequest {
            network: network.to_string(),
            id: id.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}
