//! CLI status & diagnostics output plus shared presentation helpers
//! (`table`, `print_error`, …): status, down, report, set-hostname.

use std::collections::HashMap;

use iroh::EndpointId;

use crate::config::Ipv6Only;
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
        // Daemon not running, show saved config
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
            auto_update,
            ipv6_only,
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
            lan_peers,
            ..
        } => {
            if json_enabled() {
                print_json(&serde_json::json!({
                    "endpoint": endpoint_id.to_string(),
                    "mdns": mdns_enabled,
                    "lan_peers": lan_peers
                        .iter()
                        .map(|p| serde_json::json!({
                            "endpoint_id": p.endpoint_id.to_string(),
                            "short_id": p.short_id,
                            "addrs": p.addrs,
                            "last_seen_secs": p.last_seen_secs,
                        }))
                        .collect::<Vec<_>>(),
                    "auto_update": auto_update,
                    // "on", "off", or "auto" (on, chosen by the daemon).
                    "ipv6_only": ipv6_only,
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
            // Only surface auto-update in the header when it is on (opt-in), so the
            // default line stays uncluttered.
            let auto = if auto_update {
                format!(
                    "      {} {}",
                    style::label("auto-update"),
                    style::green("on")
                )
            } else {
                String::new()
            };
            // Same treatment for IPv6-only: off is the default, so only say
            // something when the data plane is actually running without IPv4.
            // `(auto)` marks a mode the daemon chose on finding another VPN on
            // `100.64.0.0/10`, which nobody would otherwise know to expect.
            let v6only = match ipv6_only {
                Ipv6Only::Off => String::new(),
                mode => {
                    let how = match mode {
                        Ipv6Only::Auto => {
                            format!("{} {}", style::green("on"), style::faint("(auto)"))
                        }
                        _ => style::green("on").to_string(),
                    };
                    format!("      {} {how}", style::label("ipv6-only"))
                }
            };
            println!();
            println!(
                "  {}  {}      {}{}{}      {} {}",
                style::bold("rayfish"),
                state,
                mdns,
                auto,
                v6only,
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
                    print_network(net, ipv6_only.enabled());
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
                    // The marker alone reads like a setting rather than a fault.
                    // This state is always a failed restore: the network is saved
                    // but the daemon never registered it, so peers on it are
                    // unreachable and their packets are dropped as an unknown
                    // network. Say that, and say it is being worked on, so this
                    // doesn't read as something the user has to go fix.
                    println!(
                        "    {}",
                        style::faint(
                            "saved but not connected: peers on it are unreachable. \
                             The daemon keeps retrying; its log has the reason."
                        )
                    );
                }
            }

            print_nearby(&lan_peers);

            print_pending_summary(&networks, pending_files, pending_connects);

            // Daemon/CLI version skew: after a self-update the CLI binary is new
            // but the long-running daemon may still be the old one (e.g. its
            // restart failed). Empty `daemon_version` means the daemon predates
            // this field: say nothing rather than guess.
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

/// How many LAN neighbours `ray status` lists before deferring to `ray mdns
/// scan`. A busy office LAN shouldn't push your networks off the screen.
const NEARBY_SHOWN: usize = 5;

/// Render the "nearby" block: rayfish nodes seen on this LAN that we are not
/// already on a network with. Prints nothing when there are none, so the common
/// case (no strangers around) leaves status exactly as it was.
fn print_nearby(peers: &[ipc::LanPeerInfo]) {
    if peers.is_empty() {
        return;
    }
    println!();
    println!(
        "  {}  {}",
        style::bold("nearby"),
        style::faint("(on this LAN, not connected)")
    );
    let rows = peers
        .iter()
        .take(NEARBY_SHOWN)
        .map(|p| {
            let addrs = if p.addrs.is_empty() {
                "—".to_string()
            } else {
                p.addrs.join(", ")
            };
            let seen = format!("{}s", p.last_seen_secs);
            vec![
                layout::Cell::new(p.short_id.clone(), style::rose(&p.short_id)),
                layout::Cell::new(addrs.clone(), style::value(&addrs)),
                layout::Cell::right(seen.clone(), style::faint(&seen)),
            ]
        })
        .collect();
    print!("{}", table(&["peer", "addresses", "seen"], rows, 4));
    if peers.len() > NEARBY_SHOWN {
        println!(
            "    {}",
            style::faint(&format!(
                "and {} more — see them with: ray mdns scan",
                peers.len() - NEARBY_SHOWN
            ))
        );
    }
    println!(
        "    {}",
        style::faint("link up with: ray connect <peer> (they approve it)")
    );
}

/// Render one network block: header (name · role · dns · ip · member count),
/// the aligned peer table, and the shareable join code (suppressed for direct
/// `ray connect` networks).
fn print_network(net: &ipc::NetworkStatus, ipv6_only: bool) {
    let role = net.role.to_string();
    // Just the hostname: the network name is already the block header, so the
    // `.{network}.ray` suffix would only repeat it.
    let dns_name = net.my_hostname.clone();
    // member count (self excluded) belongs on the network header row. Reachable =
    // active + idle (everything not confirmed offline); on-demand nodes hold no
    // connections when idle, so counting only live connections would read "0/N".
    let reachable = net.peers.iter().filter(|p| !p.state.is_offline()).count();
    println!();
    print!("  {}  {}", style::bold(&net.name), style::marker(&role));
    if let Some(ref dns) = dns_name {
        print!("   {}", style::value(dns));
    }
    // In IPv6-only mode the mesh IPv4 carries no traffic, so showing it would
    // hand out an address that goes nowhere. Show the address actually in use.
    let my_addr = match (ipv6_only, net.my_ipv6) {
        (true, Some(v6)) => v6.to_string(),
        _ => net.my_ip.to_string(),
    };
    print!("   {}", style::faint(&my_addr));
    print!(
        "   {} {}",
        style::label("members"),
        style::value(&format!("{reachable}/{}", net.peers.len())),
    );
    if let Some(ttl) = net.ephemeral_ttl_secs {
        print!(
            "   {} {}",
            style::label("ephemeral"),
            style::value(&format_ttl(ttl)),
        );
    }
    // Both exit-node roles are worth seeing at a glance: the peer carrying our
    // internet traffic, and whether we are carrying someone else's.
    if let Some(ref gw) = net.my_exit_node {
        print!("   {} {}", style::label("exit via"), style::value(gw));
    }
    if net.exit_offering {
        print!("   {}", style::marker("exit node"));
    }
    println!();

    // Invert the local alias map (alias -> identity) for identity -> alias
    // lookups when rendering peers.
    let alias_by_identity: HashMap<&str, &str> = net
        .aliases
        .iter()
        .map(|(alias, identity)| (identity.as_str(), alias.as_str()))
        .collect();

    // Peer rows as aligned columns: glyph · host · ipv4 · via · rtt · ↑tx · ↓rx.
    // Pre-measure the widest up/down counter so each arrow hugs its number (one
    // space) while the digits still right-align across rows.
    let counter_width = |pick: fn(&ipc::ConnectionInfo) -> u64| {
        net.peers
            .iter()
            .filter_map(|p| p.connection.as_ref())
            .map(|c| format_bytes(pick(c)).len())
            .max()
            .unwrap_or(0)
    };
    let up_w = counter_width(|c| c.bytes_tx);
    let down_w = counter_width(|c| c.bytes_rx);
    let rows = grouped_peer_rows(net, &alias_by_identity, up_w, down_w, ipv6_only);
    if rows.is_empty() {
        println!("    {}", style::faint("(no other members)"));
    } else {
        // `indent` strips the block's trailing newline, so use `println!` to
        // terminate the last peer row, otherwise the network's `join <room-id>`
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
    let identity = peer.user_identity.unwrap_or(peer.endpoint_id).to_string();
    alias_by_identity.get(identity.as_str()).copied()
}

/// Build every peer row for a network, grouping paired devices (those sharing a
/// `user_identity`) under a parent user row; standalone members render flat.
/// Roster order is preserved: a group is anchored where its first device appears,
/// and within a group connected devices come before offline ones. The tree branch
/// lives inside each device row's first cell (before the glyph), so every following
/// column stays on one aligned grid across flat, parent, and nested rows.
fn grouped_peer_rows(
    net: &ipc::NetworkStatus,
    alias_by_identity: &HashMap<&str, &str>,
    up_w: usize,
    down_w: usize,
    ipv6_only: bool,
) -> Vec<Vec<layout::Cell>> {
    let mut rows = Vec::new();
    let mut emitted: std::collections::HashSet<EndpointId> = std::collections::HashSet::new();
    for peer in &net.peers {
        // Group every device by the identity it belongs to: a paired secondary
        // carries its primary's `user_identity`; a primary (or a plain member)
        // carries none, so it groups under its own endpoint id.
        let uid = peer.user_identity.unwrap_or(peer.endpoint_id);
        let group: Vec<&ipc::PeerStatus> = net
            .peers
            .iter()
            .filter(|p| p.user_identity.unwrap_or(p.endpoint_id) == uid)
            .collect();

        // A lone member with no paired devices renders as a flat row (its own
        // alias, if any, keyed on its endpoint id).
        if group.len() == 1 && peer.user_identity.is_none() {
            rows.push(device_row(
                peer,
                peer_alias(peer, alias_by_identity),
                "",
                up_w,
                down_w,
                ipv6_only,
            ));
            continue;
        }

        // Paired identity: emit the whole group the first time we reach any of its
        // devices, then skip its later devices.
        if !emitted.insert(uid) {
            continue;
        }
        // The primary is the device whose endpoint id *is* the user identity; the
        // rest are secondaries. Connected devices first (`false < true`); stable
        // sort preserves roster order within each half.
        let primary = group.iter().find(|p| p.endpoint_id == uid).copied();
        let mut secondaries: Vec<&ipc::PeerStatus> = group
            .iter()
            .filter(|p| p.endpoint_id != uid)
            .copied()
            .collect();
        secondaries.sort_by_key(|p| p.connection.is_none());

        match primary {
            // The primary is itself a visible member: anchor the group on its own
            // row (carrying its ip/rtt) and hang the secondaries beneath it, so the
            // user is named once, not as a bare rollup header plus a flat row.
            Some(primary) => {
                rows.push(device_row(
                    primary,
                    peer_alias(primary, alias_by_identity),
                    "",
                    up_w,
                    down_w,
                    ipv6_only,
                ));
                for (i, d) in secondaries.iter().enumerate() {
                    let branch = if i + 1 == secondaries.len() {
                        "   └─ "
                    } else {
                        "   ├─ "
                    };
                    rows.push(device_row(d, None, branch, up_w, down_w, ipv6_only));
                }
            }
            // The primary is not visible here (e.g. it is us, filtered out of our
            // own status): fall back to a synthetic rollup header over the
            // secondaries.
            None => {
                rows.push(user_parent_row(net, uid, &secondaries, alias_by_identity));
                for (i, d) in secondaries.iter().enumerate() {
                    let branch = if i + 1 == secondaries.len() {
                        "   └─ "
                    } else {
                        "   ├─ "
                    };
                    rows.push(device_row(d, None, branch, up_w, down_w, ipv6_only));
                }
            }
        }
    }
    rows
}

/// The parent row for a group of paired devices: `<glyph> <name>   N devices,
/// M online`. The glyph is online when any device in the group is. No ip/rtt on
/// the parent; the device rows beneath carry that.
fn user_parent_row(
    net: &ipc::NetworkStatus,
    uid: EndpointId,
    devices: &[&ipc::PeerStatus],
    alias_by_identity: &HashMap<&str, &str>,
) -> Vec<layout::Cell> {
    let active = devices.iter().filter(|d| d.state.is_active()).count();
    let reachable = devices.iter().filter(|d| !d.state.is_offline()).count();
    let name = user_display_name(net, uid, devices, alias_by_identity);
    // Glyph rolls up the group: any active device is online, else any idle device
    // is idle (presumed reachable), else offline.
    let (glyph_plain, glyph_styled) = if active > 0 {
        ("●", style::dot_online())
    } else if reachable > 0 {
        ("●", style::dot_idle())
    } else {
        ("○", style::dot_offline())
    };
    let name_plain = format!("{glyph_plain} {name}");
    let name_styled = format!("{glyph_styled} {}", style::value(&name));
    let n = devices.len();
    // Show connected devices when any, else the reachable (idle) count so an
    // all-idle group doesn't read as "0 online".
    let rollup = if active > 0 || reachable == 0 {
        format!(
            "{n} device{}, {active} online",
            if n == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{n} device{}, {reachable} idle",
            if n == 1 { "" } else { "s" }
        )
    };
    vec![
        layout::Cell::new(name_plain, name_styled),
        layout::Cell::new(rollup.clone(), style::faint(&rollup)),
    ]
}

/// Resolve a paired-device group's display name: a local alias on the user
/// identity, else your own hostname when it is your identity, else the primary
/// device's hostname if it is itself a member, else a short `user <id>` fallback.
fn user_display_name(
    net: &ipc::NetworkStatus,
    uid: EndpointId,
    devices: &[&ipc::PeerStatus],
    alias_by_identity: &HashMap<&str, &str>,
) -> String {
    if let Some(alias) = alias_by_identity.get(uid.to_string().as_str()) {
        return (*alias).to_string();
    }
    if devices.iter().any(|d| d.is_own_device)
        && let Some(h) = &net.my_hostname
    {
        return h.clone();
    }
    if let Some(h) = net
        .peers
        .iter()
        .find(|p| p.endpoint_id == uid)
        .and_then(|p| p.hostname.clone())
    {
        return h;
    }
    format!("user {}", uid.fmt_short())
}

/// One device's status row: a merged `prefix + glyph + host` first cell, then
/// ipv4 · via · rtt · ↑tx · ↓rx. `prefix` is the tree branch when the device is
/// nested under a user (empty for a top-level member). A local `alias`, when set,
/// shows as `host [alias]` (only for standalone members; a paired device's alias
/// rides its parent row). No ownership marker: an own device always nests under
/// your own parent row, which already names you, so a per-device `(your device)`
/// would just repeat it. The host is the bare hostname (no `.{network}.ray`): the
/// header names the network.
fn device_row(
    peer: &ipc::PeerStatus,
    alias: Option<&str>,
    prefix: &str,
    up_w: usize,
    down_w: usize,
    ipv6_only: bool,
) -> Vec<layout::Cell> {
    // The address column carries whatever this node can actually reach the peer
    // on, matching the network header: in IPv6-only mode the peer's mesh IPv4 is
    // an address nothing here can send to, and it is the column people copy into
    // `ssh` and `ping`. Wider rows are the price; a wrong address is not.
    let addr = match (ipv6_only, peer.ipv6) {
        (true, Some(v6)) => v6.to_string(),
        _ => peer.ip.to_string(),
    };
    let base = peer.hostname.clone().unwrap_or_else(|| addr.clone());
    let host = match alias {
        Some(a) => format!("{base} [{a}]"),
        None => base,
    };
    let (glyph_plain, glyph_styled) = match peer.state {
        ipc::PeerState::Active => ("●", style::dot_online()),
        ipc::PeerState::Idle => ("●", style::dot_idle()),
        ipc::PeerState::Offline => ("○", style::dot_offline()),
    };
    // Active + idle peers get bright names (idle is presumed reachable); only a
    // confirmed-offline peer is faded.
    let host_style: fn(&str) -> String = if peer.state.is_offline() {
        style::faint
    } else {
        style::value
    };
    // Merge branch + glyph + host into the first cell so the branch sits before
    // the glyph and the columns after it (ip, via, …) still align across all rows.
    let name = layout::Cell::new(
        format!("{prefix}{glyph_plain} {host}"),
        format!("{prefix}{glyph_styled} {}", host_style(&host)),
    );
    let ip = layout::Cell::new(addr.clone(), style::faint(&addr));
    let mut cells = match &peer.connection {
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
            // One cell per direction: the counter is right-padded to the column's
            // widest value so the arrow hugs its number (single space) while the
            // digits still right-align down the column.
            let up = format!("↑ {:>up_w$}", format_bytes(ci.bytes_tx));
            let down = format!("↓ {:>down_w$}", format_bytes(ci.bytes_rx));
            vec![
                name,
                ip,
                layout::Cell::new(via, style::faint(via)),
                layout::Cell::right(rtt_plain, rtt_styled),
                layout::Cell::new(up.clone(), style::faint(&up)),
                layout::Cell::new(down.clone(), style::faint(&down)),
            ]
        }
        // Offline, but a dial hit the mesh-version gate: flag it as incompatible
        // (with a `ray update` nudge) rather than a plain offline peer.
        None if peer.incompatible => vec![
            name,
            ip,
            layout::Cell::new("—", style::faint("—")),
            layout::Cell::right("incompatible", style::red("incompatible")),
            layout::Cell::new("ray update", style::faint("ray update")),
        ],
        // No live connection: idle (presumed reachable, dialed on demand) vs a
        // confirmed-offline peer whose last reach failed.
        None => {
            let (label_plain, label_styled) = if peer.state.is_idle() {
                ("idle", style::faint("idle"))
            } else {
                ("offline", style::faint("offline"))
            };
            vec![
                name,
                ip,
                layout::Cell::new("—", style::faint("—")),
                layout::Cell::right(label_plain, label_styled),
                layout::Cell::plain(""),
            ]
        }
    };
    // Trailing exit-node column: which peer is carrying our internet traffic, and
    // which merely offer to. Short rows (no live connection) are padded to the
    // connected width first, so the column lands in the same place on every row.
    while cells.len() < CONNECTED_CELLS {
        cells.push(layout::Cell::plain(""));
    }
    cells.push(match (peer.exit_in_use, peer.exit_node) {
        (true, _) => layout::Cell::new("in use", style::green("in use")),
        (false, true) => layout::Cell::new("offers", style::faint("offers")),
        (false, false) => layout::Cell::plain(""),
    });
    cells
}

/// Cells in a peer row with a live connection (name, ip, via, rtt, up, down): the
/// widest row shape, and the width every row is padded to before the exit column.
const CONNECTED_CELLS: usize = 6;

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
            "ray connect".to_string(),
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

#[cfg(test)]
mod grouping_tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn conn() -> ipc::ConnectionInfo {
        ipc::ConnectionInfo {
            conn_type: ipc::ConnType::Direct,
            remote_addr: None,
            rtt_ms: Some(20.0),
            bytes_tx: 0,
            bytes_rx: 0,
            datagrams_tx: 0,
            datagrams_rx: 0,
            lost_packets: 0,
        }
    }

    fn peer(
        host: &str,
        user: Option<EndpointId>,
        own: bool,
        online: bool,
        incompatible: bool,
    ) -> ipc::PeerStatus {
        ipc::PeerStatus {
            endpoint_id: iroh::SecretKey::generate().public(),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            ipv6: None,
            hostname: Some(host.to_string()),
            user_identity: user,
            is_own_device: own,
            incompatible,
            connection: online.then(conn),
            // Mirror the daemon's derivation so the render tests see realistic state.
            state: if online {
                ipc::PeerState::Active
            } else if incompatible {
                ipc::PeerState::Offline
            } else {
                ipc::PeerState::Idle
            },
            exit_node: false,
            exit_in_use: false,
        }
    }

    fn net(my_hostname: &str, peers: Vec<ipc::PeerStatus>) -> ipc::NetworkStatus {
        ipc::NetworkStatus {
            name: "n".to_string(),
            role: ipc::NetworkRole::Coordinator,
            my_ip: Ipv4Addr::new(100, 64, 0, 1),
            my_ipv6: None,
            my_hostname: Some(my_hostname.to_string()),
            network_key: None,
            member_count: peers.len(),
            peers,
            pending_suggestions: 0,
            pending_requests: 0,
            aliases: Default::default(),
            ephemeral_ttl_secs: None,
            my_exit_node: None,
            exit_offering: false,
        }
    }

    fn render(net: &ipc::NetworkStatus) -> String {
        render_in(net, false)
    }

    fn render_in(net: &ipc::NetworkStatus, ipv6_only: bool) -> String {
        layout::columns(&grouped_peer_rows(net, &HashMap::new(), 0, 0, ipv6_only), 3)
    }

    #[test]
    fn nests_own_paired_devices_under_user() {
        let me = iroh::SecretKey::generate().public();
        // Two of my devices (one online, one offline) plus a standalone member.
        let net = net(
            "dario",
            vec![
                peer("phone", Some(me), true, true, false),
                peer("tablet", Some(me), true, false, false),
                peer("server", None, false, true, false),
            ],
        );
        let out = render(&net);
        // Parent row labelled by my hostname with a rollup, and a tree branch.
        assert!(out.contains("dario"), "{out}");
        assert!(out.contains("2 devices, 1 online"), "{out}");
        assert!(out.contains("└─"), "{out}");
        // Parent sits before its devices; connected device before the offline one.
        let at = |s: &str| out.find(s).unwrap();
        assert!(at("dario") < at("phone"));
        assert!(at("phone") < at("tablet"));
        // Standalone member still renders flat.
        assert!(out.contains("server"));
    }

    /// The address column has to be one this node can send to. In IPv6-only mode
    /// the peer's mesh IPv4 is not routed here (another VPN owns the range), so
    /// printing it would hand out an address that goes nowhere, and this column
    /// is what people copy into `ssh`.
    #[test]
    fn peer_rows_carry_the_reachable_address() {
        let mut p = peer("dev", None, false, true, false);
        p.ipv6 = Some("200::9".parse().unwrap());
        let net = net("dario", vec![p]);

        let dual = render_in(&net, false);
        assert!(dual.contains("100.64.0.2"), "{dual}");
        assert!(!dual.contains("200::9"), "{dual}");

        let v6_only = render_in(&net, true);
        assert!(v6_only.contains("200::9"), "{v6_only}");
        assert!(!v6_only.contains("100.64.0.2"), "{v6_only}");
    }

    /// A peer whose roster entry predates the v6 address still has to render:
    /// falling back to its mesh IPv4 beats an empty column.
    #[test]
    fn peer_without_ipv6_falls_back_to_its_ipv4() {
        let net = net("dario", vec![peer("dev", None, false, true, false)]);
        assert!(render_in(&net, true).contains("100.64.0.2"));
    }

    #[test]
    fn visible_primary_anchors_its_own_group() {
        // Viewing a *foreign* user whose primary device is itself a visible member
        // (endpoint id == user identity) plus one paired secondary. The primary
        // must anchor the group on its own row, not appear once flat and once as a
        // separate rollup header (the `dario ... / dario ...` duplication bug).
        let dario = iroh::SecretKey::generate().public();
        let primary = ipc::PeerStatus {
            endpoint_id: dario,
            ip: Ipv4Addr::new(100, 64, 0, 3),
            ipv6: None,
            hostname: Some("dario".to_string()),
            user_identity: None,
            is_own_device: false,
            incompatible: false,
            connection: Some(conn()),
            state: ipc::PeerState::Active,
            exit_node: false,
            exit_in_use: false,
        };
        let secondary = peer("sm-f966b", Some(dario), false, false, false);
        let net = net("umbrel", vec![primary, secondary]);
        let out = render(&net);

        // "dario" is named exactly once, and there is no synthetic rollup header.
        assert_eq!(out.matches("dario").count(), 1, "{out}");
        assert!(!out.contains("device"), "unexpected rollup header:\n{out}");
        // The secondary nests under the primary's row.
        assert!(out.contains("└─"), "{out}");
        let at = |s: &str| out.find(s).unwrap();
        assert!(at("dario") < at("sm-f966b"), "{out}");
    }

    #[test]
    fn names_the_exit_node_actually_carrying_our_traffic() {
        // Two peers offer an exit; only one is carrying us. With several exit nodes
        // on a network, "(exit)" on both would say nothing about where our packets
        // are going, so the one in use is called out.
        let mut offering = peer("gw-a", None, false, true, false);
        offering.exit_node = true;
        let mut in_use = peer("gw-b", None, false, true, false);
        in_use.exit_node = true;
        in_use.exit_in_use = true;
        let plain = peer("srv", None, false, true, false);
        let out = render(&net("dario", vec![offering, in_use, plain]));
        let row = |host: &str| {
            out.lines()
                .find(|l| l.contains(host))
                .unwrap_or_else(|| panic!("no row for {host}:\n{out}"))
                .to_string()
        };
        assert!(row("gw-a").contains("offers"), "{out}");
        assert!(row("gw-b").contains("in use"), "{out}");
        // A peer with no exit role gets a blank cell, not a stray label.
        let plain = row("srv");
        assert!(
            !plain.contains("offers") && !plain.contains("in use"),
            "{out}"
        );
    }

    #[test]
    fn flags_incompatible_offline_peer() {
        let net = net("dario", vec![peer("oldbox", None, false, false, true)]);
        let out = render(&net);
        assert!(out.contains("oldbox"));
        assert!(out.contains("incompatible"), "{out}");
        assert!(out.contains("ray update"), "{out}");
        assert!(!out.contains("offline"), "{out}");
    }

    #[test]
    fn single_device_group_reads_singular() {
        let me = iroh::SecretKey::generate().public();
        let net = net("dario", vec![peer("phone", Some(me), true, true, false)]);
        let out = render(&net);
        assert!(out.contains("1 device, 1 online"), "{out}");
    }
}
