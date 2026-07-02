//! CLI status & diagnostics output plus shared presentation helpers
//! (`table`, `print_error`, …): status, down, report, set-hostname.

use std::collections::HashMap;

use crate::*;

/// Human-readable byte size (GiB/MiB/KiB/B) for traffic and transfer counters.
pub(crate) fn format_bytes(b: u64) -> String {
    bytesize::ByteSize(b).to_string()
}

/// Render a styled error block to stderr:
/// ```text
///   ✗ <title>
///     <detail>
///     hint  <hint>
/// ```
/// When `hint` is `None`, a hint is inferred from common daemon error strings.
pub(crate) fn print_error(title: &str, detail: &str, hint: Option<&str>) {
    eprintln!("  {} {}", style::cross(), style::bold(title));
    if !detail.is_empty() {
        eprintln!("    {}", style::value(detail));
    }
    let hint = hint.map(str::to_string).or_else(|| infer_hint(detail));
    if let Some(h) = hint {
        eprintln!("    {}  {}", style::label("hint"), style::faint(&h));
    }
}

/// Map a daemon error message to an actionable hint, best-effort.
pub(crate) fn infer_hint(message: &str) -> Option<String> {
    let m = message.to_lowercase();
    if m.contains("daemon") && (m.contains("not running") || m.contains("connect")) {
        Some("start the service: sudo ray up".into())
    } else if m.contains("expired") || m.contains("invite") {
        Some("ask the coordinator for a fresh code: ray invite <net>".into())
    } else if m.contains("root") || m.contains("permission") || m.contains("operator") {
        Some("run with sudo, or `sudo ray set-operator <you>` once".into())
    } else if m.contains("hostname") && m.contains("collision") {
        Some("pick another name: --hostname <name>".into())
    } else {
        None
    }
}

/// Render a "next steps" footer: an aligned list of suggested commands.
/// ```text
///     next  ray status   see who's online
///           ray up       activate the VPN
/// ```
pub(crate) fn print_next(steps: &[(&str, &str)]) {
    let rows: Vec<Vec<layout::Cell>> = steps
        .iter()
        .enumerate()
        .map(|(i, (cmd, blurb))| {
            let label = if i == 0 { "next" } else { "" };
            vec![
                layout::Cell::new(label, style::label(label)),
                layout::Cell::new(*cmd, style::rose(cmd)),
                layout::Cell::new(*blurb, style::faint(blurb)),
            ]
        })
        .collect();
    print!("{}", indent(&layout::columns(&rows, 2), 4));
}

/// Standard borderless table: a faint header row over `rows`, aligned via
/// [`layout::columns`] and indented `pad` spaces. Headers are styled here (so
/// `layout` stays presentation-free) and every list command shares this shape.
pub(crate) fn table(headers: &[&str], rows: Vec<Vec<layout::Cell>>, pad: usize) -> String {
    let header: Vec<layout::Cell> = headers
        .iter()
        .map(|h| layout::Cell::new(*h, style::faint(h)))
        .collect();
    let mut all = Vec::with_capacity(rows.len() + 1);
    all.push(header);
    all.extend(rows);
    indent(&layout::columns(&all, 2), pad)
}

/// Prefix every line of `block` with `indent` spaces (for nested table output).
pub(crate) fn indent(block: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    block
        .lines()
        .map(|l| format!("{pad}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Naively pluralize `noun` for a count (append `s` unless `n == 1`). The count
/// itself is shown separately, so this returns just the noun. Good enough for
/// the status pending summary's nouns.
pub(crate) fn pluralize(n: usize, noun: &str) -> String {
    if n == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

pub(crate) async fn ipc_status() -> Result<()> {
    let Ok(mut stream) = ipc::connect().await else {
        // Daemon not running — show saved config
        let app_config = config::load()?;
        println!();
        println!("  {}", style::red("✗ daemon not running"));
        if app_config.networks.is_empty() {
            println!("  {}", style::faint("no saved networks"));
            println!();
            return Ok(());
        }
        println!("  {}", style::faint("saved networks:"));
        for net in &app_config.networks {
            let ip_str = net
                .my_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!(
                "    {} {}  {}",
                style::value(&net.name),
                style::faint(&format!("({ip_str})")),
                style::faint(&format!("{} members", net.members.len()))
            );
        }
        println!();
        return Ok(());
    };

    ipc::send(&mut stream, ipc::IpcMessage::Status).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::StatusResponse {
            endpoint_id,
            mdns_enabled,
            active,
            contact_id,
            daemon_version,
            networks,
            packets_rx,
            packets_tx,
            bytes_rx,
            bytes_tx,
            pending_files,
            pending_connects,
        } => {
            if json_enabled() {
                print_json(&serde_json::json!({
                    "endpoint": endpoint_id.to_string(),
                    "mdns": mdns_enabled,
                    "active": active,
                    "contact_id": contact_id,
                    "daemon_version": daemon_version,
                    "networks": networks,
                    "traffic": {
                        "packets_rx": packets_rx, "packets_tx": packets_tx,
                        "bytes_rx": bytes_rx, "bytes_tx": bytes_tx,
                    },
                    "pending": {
                        "files": pending_files,
                        "connects": pending_connects,
                    },
                }));
                return Ok(());
            }
            let _ = (packets_rx, packets_tx, bytes_rx, bytes_tx);
            // Header: rayfish ● up    mDNS on    endpoint k7f2…9qx4
            let state = if active {
                format!("{} {}", style::dot_online(), style::value("up"))
            } else {
                format!("{} {}", style::dot_offline(), style::faint("standby"))
            };
            let mdns = if mdns_enabled {
                format!("{} {}", style::label("mDNS"), style::green("on"))
            } else {
                format!("{} {}", style::label("mDNS"), style::faint("off"))
            };
            println!();
            println!(
                "  {}  {}      {}      {} {}",
                style::bold("rayfish"),
                state,
                mdns,
                style::label("endpoint"),
                style::value(&endpoint_id.fmt_short().to_string()),
            );
            if !active {
                println!("  {}", style::faint("run `ray up` to activate"));
            }
            if let Some(ref cid) = contact_id {
                println!("  {} {}", style::label("contact"), style::rose(cid),);
            }

            if networks.is_empty() {
                println!();
                println!("  {}", style::faint("no active networks"));
            } else {
                for net in &networks {
                    print_network(net);
                }
            }

            // Show inactive networks from config that the daemon didn't restore
            let active_names: std::collections::HashSet<&str> =
                networks.iter().map(|n| n.name.as_str()).collect();
            if let Ok(app_config) = config::load() {
                let inactive: Vec<_> = app_config
                    .networks
                    .iter()
                    .filter(|n| !active_names.contains(n.name.as_str()))
                    .collect();
                for net in &inactive {
                    println!();
                    println!(
                        "  {}  {}",
                        style::faint(&net.name),
                        style::marker("inactive")
                    );
                }
            }

            print_pending_summary(&networks, pending_files, pending_connects);

            // Daemon/CLI version skew: after a self-update the CLI binary is new
            // but the long-running daemon may still be the old one (e.g. its
            // restart failed). Empty `daemon_version` means the daemon predates
            // this field — say nothing rather than guess.
            let cli_version = env!("CARGO_PKG_VERSION");
            if !daemon_version.is_empty() && daemon_version != cli_version {
                println!();
                println!(
                    "  {} daemon is v{} but CLI is v{}",
                    style::red("!"),
                    daemon_version,
                    cli_version,
                );
                println!(
                    "  {}",
                    style::faint("run `sudo ray update` to restart the daemon onto the new binary"),
                );
            }
            println!();
        }
        ipc::IpcMessage::Error { message } => print_error("status failed", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Render one network block: header (name · role · dns · ip · member count),
/// the aligned peer table, and the shareable join code (suppressed for direct
/// `ray connect` networks).
fn print_network(net: &ipc::NetworkStatus) {
    let role = net.role.to_string();
    let dns_name = net
        .my_hostname
        .as_ref()
        .map(|h| format!("{}.{}.{}", h, net.name, DNS_DOMAIN));
    // member count (self excluded) belongs on the network header row
    let online = net.peers.iter().filter(|p| p.connection.is_some()).count();
    println!();
    print!("  {}  {}", style::bold(&net.name), style::marker(&role));
    if let Some(ref dns) = dns_name {
        print!("   {}", style::value(dns));
    }
    print!("   {}", style::faint(&net.my_ip.to_string()));
    println!(
        "   {} {}",
        style::label("members"),
        style::value(&format!("{online}/{}", net.peers.len())),
    );

    // Invert the local alias map (alias -> identity) for identity -> alias
    // lookups when rendering peers.
    let alias_by_identity: HashMap<&str, &str> = net
        .aliases
        .iter()
        .map(|(alias, identity)| (identity.as_str(), alias.as_str()))
        .collect();

    // Peer rows as aligned columns: glyph · host · ipv4 · via · rtt · traffic
    let rows: Vec<Vec<layout::Cell>> = net
        .peers
        .iter()
        .map(|p| render_peer_row(&net.name, p, peer_alias(p, &alias_by_identity)))
        .collect();
    if rows.is_empty() {
        println!("    {}", style::faint("(no other members)"));
    } else {
        // `indent` strips the block's trailing newline, so use `println!` to
        // terminate the last peer row — otherwise the network's `join <room-id>`
        // line below gets glued onto it.
        println!("{}", indent(&layout::columns(&rows, 3), 4));
    }

    // join code. Direct (`ray connect`) networks have no shareable room id, so
    // the join code is suppressed for them.
    if let Some(ref key) = net.network_key
        && !net.role.is_direct()
    {
        println!("    {} {}", style::label("join"), style::rose(key));
    }
}

/// Resolve a peer's local alias, if any: match its identity (user identity when
/// paired, else device endpoint id) against the inverted alias map.
fn peer_alias<'a>(
    peer: &ipc::PeerStatus,
    alias_by_identity: &HashMap<&str, &'a str>,
) -> Option<&'a str> {
    let identity = peer
        .user_identity
        .unwrap_or(peer.endpoint_id)
        .to_string();
    alias_by_identity.get(identity.as_str()).copied()
}

/// Build one peer's status row (glyph · host · ipv4 · via · rtt · traffic). A
/// local alias, when set, is shown inline after the host as `host.net.ray [alias]`.
fn render_peer_row(net_name: &str, peer: &ipc::PeerStatus, alias: Option<&str>) -> Vec<layout::Cell> {
    let base = peer
        .hostname
        .as_ref()
        .map(|h| format!("{h}.{}.{}", net_name, DNS_DOMAIN))
        .unwrap_or_else(|| peer.ip.to_string());
    let host = match alias {
        Some(a) => format!("{base} [{a}]"),
        None => base,
    };
    match &peer.connection {
        Some(ci) => {
            let via = match ci.conn_type {
                ipc::ConnType::Direct => "direct",
                ipc::ConnType::Relay => "relay",
                ipc::ConnType::Tor => "tor",
                ipc::ConnType::Unknown => "?",
            };
            let (rtt_plain, rtt_styled) = match ci.rtt_ms {
                Some(ms) => (format!("{ms:.0}ms"), style::latency(ms)),
                None => ("—".into(), style::faint("—")),
            };
            let traffic_plain = format!(
                "↑ {}  ↓ {}",
                format_bytes(ci.bytes_tx),
                format_bytes(ci.bytes_rx)
            );
            vec![
                layout::Cell::new("●", style::dot_online()),
                layout::Cell::new(host.clone(), style::value(&host)),
                layout::Cell::new(peer.ip.to_string(), style::faint(&peer.ip.to_string())),
                layout::Cell::new(via, style::faint(via)),
                layout::Cell::right(rtt_plain, rtt_styled),
                layout::Cell::new(traffic_plain.clone(), style::faint(&traffic_plain)),
            ]
        }
        None => vec![
            layout::Cell::new("○", style::dot_offline()),
            layout::Cell::new(host.clone(), style::faint(&host)),
            layout::Cell::new(peer.ip.to_string(), style::faint(&peer.ip.to_string())),
            layout::Cell::new("—", style::faint("—")),
            layout::Cell::right("offline", style::faint("offline")),
            layout::Cell::plain(""),
        ],
    }
}

/// Render the trailing "pending" summary: things waiting on the user, each with
/// the command that clears it. Per-network items (firewall suggestions, join
/// requests) name their network; file/connect offers are global.
fn print_pending_summary(
    networks: &[ipc::NetworkStatus],
    pending_files: usize,
    pending_connects: usize,
) {
    let mut pending: Vec<(usize, String, String)> = Vec::new();
    for net in networks {
        if net.pending_suggestions > 0 {
            pending.push((
                net.pending_suggestions,
                pluralize(net.pending_suggestions, "firewall suggestion"),
                format!("ray firewall pending {}", net.name),
            ));
        }
        if net.pending_requests > 0 {
            pending.push((
                net.pending_requests,
                pluralize(net.pending_requests, "join request"),
                format!("ray requests {}", net.name),
            ));
        }
    }
    if pending_files > 0 {
        pending.push((
            pending_files,
            pluralize(pending_files, "file offer"),
            "ray files".to_string(),
        ));
    }
    if pending_connects > 0 {
        pending.push((
            pending_connects,
            pluralize(pending_connects, "connection request"),
            "ray connections".to_string(),
        ));
    }
    if pending.is_empty() {
        return;
    }
    println!();
    println!("  {}", style::label("pending"));
    let rows: Vec<Vec<layout::Cell>> = pending
        .iter()
        .map(|(n, what, cmd)| {
            let count = format!("({n})");
            vec![
                layout::Cell::new(count.clone(), style::rose(&count)),
                layout::Cell::new(what.clone(), style::value(what)),
                layout::Cell::new(cmd.clone(), style::faint(cmd)),
            ]
        })
        .collect();
    print!("{}", indent(&layout::columns(&rows, 3), 4));
}

/// `ray down`: put the daemon on standby (tear down the TUN, revert DNS, drop
/// connections) while leaving the daemon process running so `ray up` can
/// reactivate it without root.
pub(crate) async fn ipc_down() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Down).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Base repository for `ray report`. Swap this for a managed upload endpoint
/// once the diagnostics service exists; the rest of the flow stays the same.
pub(crate) const REPORT_REPO_URL: &str = "https://github.com/rayfish/rayfish";

/// Ask the daemon to build a diagnostic bundle, then open a pre-filled GitHub
/// issue so the user can attach it. The bundle is built daemon-side (logs are
/// root-owned) and written to a path owned by the invoking user.
pub(crate) async fn ipc_report() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Report).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::ReportBundle {
            path,
            issue_title,
            issue_body,
        } => {
            println!("Diagnostic bundle written to:\n  {path}\n");
            println!(
                "Review it before sharing — it contains your logs, virtual IPs, and peer IDs,\n\
                 but no private keys."
            );
            let url = url::Url::parse_with_params(
                &format!("{REPORT_REPO_URL}/issues/new"),
                &[
                    ("title", issue_title.as_str()),
                    ("body", issue_body.as_str()),
                ],
            )?;
            println!("\nOpening a pre-filled GitHub issue — attach the bundle above.");
            if !open_url(url.as_str()) {
                println!("\nCouldn't open a browser. Open this URL manually:\n{url}");
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Best-effort: open `url` in the user's default browser. Returns false if no
/// opener is available (e.g. headless), so the caller can print it instead.
pub(crate) fn open_url(url: &str) -> bool {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(url)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub(crate) async fn ipc_set_hostname(network: &str, hostname: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::SetHostname {
            network: network.to_string(),
            hostname: hostname.to_string(),
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

