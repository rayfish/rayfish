//! CLI status & diagnostics output plus shared presentation helpers
//! (`table`, `print_error`, …): status, down, report, set-hostname.

use std::collections::HashMap;

use iroh::EndpointId;

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

/// [`print_error`] for a daemon-side `IpcMessage::Error`, which ends the command
/// non-zero.
///
/// The daemon rejecting a request is a failed command, and a CLI that says so on
/// stderr alone is one no script can check: `ray join` on a spent invite, or
/// `ray exit-node use` on a gateway that cannot carry IPv6, printed the reason
/// and exited 0 exactly like a success. Returns `!`, so it drops into a match arm
/// of any type.
pub(crate) fn fail_with(title: &str, detail: &str) -> ! {
    print_error(title, detail, None);
    std::process::exit(1);
}

/// [`fail_with`] for a reply the command does not know how to read.
///
/// Reaching this arm means the CLI and the daemon disagree about the protocol,
/// and IPC has no version negotiation to catch it: the binary is swapped before
/// the service restarts, so the window is routine rather than exotic. Printing to
/// stderr and returning 0 told the caller the command worked, which is the same
/// failure [`fail_with`] exists to stop, one match arm over.
pub(crate) fn fail_unexpected(reply: &impl std::fmt::Debug) -> ! {
    print_error(
        "unexpected reply from the daemon",
        &unexpected_detail(reply),
        Some("the CLI and the daemon are probably different versions: sudo ray restart"),
    );
    std::process::exit(1);
}

/// The same complaint as [`fail_unexpected`] as a string, for the two callers
/// that must not exit: they sit in loops written to attempt every item, so
/// ending the process would abandon the rest of the work the user asked for.
pub(crate) fn unexpected_detail(reply: &impl std::fmt::Debug) -> String {
    format!(
        "unexpected reply from the daemon: {reply:?}\n    \
         the CLI and the daemon are probably different versions"
    )
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

/// Did the connection fail because this account may not have it, rather than
/// because there was nothing to connect to?
///
/// Both platforms let any local user reach the daemon (`chmod 0666` on the Unix
/// socket, an Authenticated Users ACE on the Windows pipe), so this is not the
/// everyday case for either. It still happens: a Windows service still running
/// an older build hands out a pipe whose DACL names only LocalSystem, the
/// Administrators group and the operator, and refuses everyone else at `open()`.
fn connect_was_refused(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
}

fn print_not_authorized() {
    println!();
    println!(
        "  {}",
        style::red("✗ not authorized to query the rayfish service")
    );
    #[cfg(windows)]
    println!(
        "  {}",
        style::faint("grant access from an Administrator terminal with: ray set-operator <user>")
    );
    #[cfg(unix)]
    println!(
        "  {}",
        style::faint("grant access with: sudo ray set-operator <user>")
    );
    println!();
}

pub(crate) async fn ipc_status() -> Result<()> {
    let connected = match ipc::connect().await {
        Ok(stream) => Some(stream),
        // Being refused is not the same as nothing being there, and reporting a
        // running daemon as down sends the reader after the wrong problem. The
        // IPC layer already tells the two apart, so keep its answer rather than
        // flattening every failure into one message.
        Err(error) if connect_was_refused(&error) => {
            print_not_authorized();
            return Ok(());
        }
        Err(_) => None,
    };
    let Some(mut stream) = connected else {
        // Daemon not running, so its config is all there is to show. Read-only:
        // `config::load` would create the directory it resolves, and this process
        // is not the daemon.
        let app_config = config::load_for_read()?;
        println!();
        println!("  {}", style::red("✗ daemon not running"));
        if app_config.networks.is_empty() {
            println!("  {}", style::faint("no saved networks"));
            println!();
            return Ok(());
        }
        println!("  {}", style::faint("saved networks:"));
        for net in &app_config.networks {
            // No address here: it derives from our identity, which this path
            // deliberately does not load (the daemon is down and the config is
            // all we have). The name and member count are what the listing is
            // for; `ray status` with the daemon up prints the address.
            println!(
                "    {}  {}",
                style::value(&net.name),
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
            private_mode,
            tor,
            auto_update,
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
            inactive_networks,
            lan_peers,
            ..
        } => {
            if json_enabled() {
                print_json(&serde_json::json!({
                    "endpoint": endpoint_id.to_string(),
                    "mdns": mdns_enabled,
                    "private": private_mode,
                    "tor": tor,
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
                    "active": active,
                    "contact_id": contact_id,
                    "daemon_version": daemon_version,
                    "networks": networks,
                    "inactive_networks": inactive_networks,
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
            // Shown only when on, like auto-update below: it is opt-in, and the
            // default header stays uncluttered. Worth a chip at all because the
            // setting is sticky across restarts, so the machine can be in it
            // long after anyone remembers typing the flag.
            let private = if private_mode {
                format!("      {} {}", style::label("private"), style::green("on"))
            } else {
                String::new()
            };
            // Its own chip rather than folded into `private`: the two are
            // independent, and `tor on` without `private` is a real state.
            let tor_chip = if tor {
                format!("      {} {}", style::label("tor"), style::green("on"))
            } else {
                String::new()
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
            println!();
            println!(
                "  {}  {}      {}{}{}{}      {} {}",
                style::bold("rayfish"),
                state,
                mdns,
                private,
                tor_chip,
                auto,
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

            // Saved networks the daemon never registered. The list comes from the
            // daemon: reading config here resolves the *calling user's* config
            // directory, which is empty (and gets created) wherever the daemon's
            // is root-owned, so every failed restore rendered as no mention at all.
            for net in &inactive_networks {
                println!();
                print!("{}", inactive_network_block(net));
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
        ipc::IpcMessage::Error { message } => fail_with("status failed", &message),
        other => fail_unexpected(&other),
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

/// Where a network block's contents come from, which is also how much of it can
/// be believed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Liveness {
    /// The daemon has the network registered: the peer rows carry real links.
    Live,
    /// Saved on disk but not registered, and no restore attempt has failed yet.
    Connecting,
    /// Saved on disk but not registered, and the last restore attempt failed.
    Offline,
}

/// The block for one saved network the daemon has not registered, ending in a
/// newline.
///
/// A restore needs the network's signed record and a coordinator that answers,
/// which after a reboot is a minute of backoff (`restore_member_network`).
/// Rendering that minute as a bare name over one line of apology hid a group the
/// config describes in full: its roster, our address on it and its join code are
/// all on disk. So draw the same block a live network gets, marked `connecting…`
/// until an attempt has actually failed and `offline` after, with every peer row
/// offline because nothing on an unregistered network is reachable. The reason,
/// when the daemon has one, is what the reader would otherwise go find in the log.
fn inactive_network_block(net: &ipc::InactiveNetwork) -> String {
    let live = if net.reason.is_some() {
        Liveness::Offline
    } else {
        Liveness::Connecting
    };
    // The caption and the reason sit directly under the header, above the roster,
    // so the group is explained before it is listed.
    let mut note = format!(
        "    {}\n",
        style::faint(match (&net.saved, live) {
            // Without a roster to show, the caption is the only place the block
            // can say that nothing on the network is reachable.
            (None, _) => {
                "saved but not connected: peers on it are unreachable. The daemon keeps retrying."
            }
            (Some(_), Liveness::Offline) => "saved but not connected: the daemon keeps retrying.",
            (Some(_), _) => "saved roster: syncing with the coordinator.",
        })
    );
    if let Some(ref reason) = net.reason {
        note.push_str(&format!(
            "    {} {}\n",
            style::label("reason"),
            style::faint(reason)
        ));
    }
    match net.saved {
        Some(ref saved) => network_block(saved, live, Some(&note)),
        // A daemon predating the saved projection sends the name alone. Say what
        // little there is rather than drop the group from the listing.
        None => format!(
            "  {}  {}\n{note}",
            style::faint(&net.name),
            style::marker("inactive"),
        ),
    }
}

/// A network's header block: the name/role/address line, plus the line that says
/// why nothing on it works when the network runs a mesh protocol version this
/// build does not speak.
///
/// Built as a string rather than printed so the flags can be tested, the way the
/// peer rows already are.
fn network_header(net: &ipc::NetworkStatus, live: Liveness) -> String {
    use std::fmt::Write as _;

    let role = net.role.to_string();
    // member count (self excluded) belongs on the network header row. Reachable =
    // active + idle (everything not confirmed offline); on-demand nodes hold no
    // connections when idle, so counting only live connections would read "0/N".
    let reachable = net.peers.iter().filter(|p| !p.state.is_offline()).count();
    // A group drawn from disk is dimmed and says which of the two not-registered
    // states it is in, so it never reads as a working network with everyone down.
    let name = match live {
        Liveness::Live => style::bold(&net.name),
        _ => style::faint(&net.name),
    };
    let mut out = format!("  {}  {}", name, style::marker(&role));
    match live {
        Liveness::Live => {}
        Liveness::Connecting => {
            let _ = write!(out, "  {}", style::marker("connecting…"));
        }
        Liveness::Offline => {
            let _ = write!(out, "  {}", style::red("offline"));
        }
    }
    // Just the hostname: the network name is already the block header, so the
    // `.{network}.ray` suffix would only repeat it.
    if let Some(ref dns) = net.my_hostname {
        let _ = write!(out, "   {}", style::value(dns));
    }
    let my_addr = net.my_ipv6.to_string();
    let _ = write!(out, "   {}", style::faint(&my_addr));
    // `reachable/total` is a live reading. On a group with no registration there
    // is nothing to reach yet, and "0/3" would send the reader looking for three
    // members that are down rather than one network that has not come up.
    let members = match live {
        Liveness::Live => format!("{reachable}/{}", net.peers.len()),
        _ => net.peers.len().to_string(),
    };
    let _ = write!(
        out,
        "   {} {}",
        style::label("members"),
        style::value(&members),
    );
    if let Some(ttl) = net.ephemeral_ttl_secs {
        let _ = write!(
            out,
            "   {} {}",
            style::label("ephemeral"),
            style::value(&format_ttl(ttl)),
        );
    }
    // Both exit-node roles are worth seeing at a glance: the peer carrying our
    // internet traffic, and whether we are carrying someone else's.
    if let Some(ref gw) = net.my_exit_node {
        let _ = write!(out, "   {} {}", style::label("exit via"), style::value(gw));
    }
    if net.exit_offering {
        let _ = write!(out, "   {}", style::marker("exit node"));
    }
    // A version-incompatible network is registered but carries nothing: its
    // roster came from the signed blob, and the versioned mesh ALPN refuses
    // every dial on it. The marker mirrors the one on an incompatible peer row,
    // and the line under it names both versions, since "incompatible" alone
    // doesn't say which side is behind.
    if let Some(ref m) = net.incompatible {
        let _ = write!(out, "   {}", style::red("incompatible"));
        let _ = write!(
            out,
            "\n    {}",
            style::faint(&format!(
                "runs mesh protocol v{}, this build speaks v{}: no peer on it is reachable. \
                 Run `ray update` so both sides match.",
                m.network, m.ours
            )),
        );
    }
    out
}

fn print_network(net: &ipc::NetworkStatus) {
    println!();
    print!("{}", network_block(net, Liveness::Live, None));
}

/// Render one network block, ending in a newline: header (name · role · dns · ip
/// · member count), the aligned peer table, and the shareable join code
/// (suppressed for direct `ray connect` networks).
///
/// Shared by live networks and by the ones still being restored, so a group does
/// not change shape the moment its coordinator answers. `note`, when given, is a
/// block of already-indented lines placed between the header and the roster.
fn network_block(net: &ipc::NetworkStatus, live: Liveness, note: Option<&str>) -> String {
    use std::fmt::Write as _;

    let mut out = format!("{}\n", network_header(net, live));
    if let Some(note) = note {
        out.push_str(note);
    }

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
    let rows = grouped_peer_rows(net, &alias_by_identity, up_w, down_w);
    if rows.is_empty() {
        let _ = writeln!(out, "    {}", style::faint("(no other members)"));
    } else {
        // `indent` strips the block's trailing newline, so terminate the last
        // peer row here, otherwise the network's `join <room-id>` line below gets
        // glued onto it.
        let _ = writeln!(out, "{}", indent(&layout::columns(&rows, 3), 4));
    }

    // join code. Direct (`ray connect`) networks have no shareable room id, so
    // the join code is suppressed for them.
    if let Some(ref key) = net.network_key
        && !net.role.is_direct()
    {
        let _ = writeln!(out, "    {} {}", style::label("join"), style::rose(key));
    }
    out
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
                ));
                for (i, d) in secondaries.iter().enumerate() {
                    let branch = if i + 1 == secondaries.len() {
                        "   └─ "
                    } else {
                        "   ├─ "
                    };
                    rows.push(device_row(d, None, branch, up_w, down_w));
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
                    rows.push(device_row(d, None, branch, up_w, down_w));
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
) -> Vec<layout::Cell> {
    // The address column is the peer's mesh IPv6, which is the only address it
    // can be reached on and the one people copy into `ssh` and `ping`. It is
    // three times the width of the dotted quad it replaces: wider rows are the
    // price, a wrong address is not.
    let addr = peer.ipv6.to_string();
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
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
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
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Best-effort: open `url` in the user's default browser. Returns false if no
/// opener is available (e.g. headless), so the caller can print it instead.
pub(crate) fn open_url(url: &str) -> bool {
    // Windows has no `xdg-open`, and this is the one that matters most there:
    // the browser GUI is the only interface Windows gets. `url.dll` rather than
    // `cmd /c start`, which needs an empty title argument before the URL and
    // treats `&` in one as a command separator.
    #[cfg(windows)]
    let (opener, args): (&str, [&str; 2]) = ("rundll32.exe", ["url.dll,FileProtocolHandler", url]);
    #[cfg(target_os = "macos")]
    let (opener, args): (&str, [&str; 1]) = ("open", [url]);
    #[cfg(not(any(windows, target_os = "macos")))]
    let (opener, args): (&str, [&str; 1]) = ("xdg-open", [url]);
    std::process::Command::new(opener)
        .args(args)
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
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

#[cfg(test)]
mod grouping_tests {

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
            ipv6: "200::2".parse().unwrap(),
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
            my_ipv6: "200::1".parse().unwrap(),
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
            incompatible: None,
        }
    }

    fn render(net: &ipc::NetworkStatus) -> String {
        layout::columns(&grouped_peer_rows(net, &HashMap::new(), 0, 0), 3)
    }

    #[test]
    fn nests_own_paired_devices_under_user() {
        let me = iroh::SecretKey::generate().public();
        // Two of my devices (one online, one offline) plus a standalone member.
        let net = net(
            "laptop",
            vec![
                peer("phone", Some(me), true, true, false),
                peer("tablet", Some(me), true, false, false),
                peer("server", None, false, true, false),
            ],
        );
        let out = render(&net);
        // Parent row labelled by my hostname with a rollup, and a tree branch.
        assert!(out.contains("laptop"), "{out}");
        assert!(out.contains("2 devices, 1 online"), "{out}");
        assert!(out.contains("└─"), "{out}");
        // Parent sits before its devices; connected device before the offline one.
        let at = |s: &str| out.find(s).unwrap();
        assert!(at("laptop") < at("phone"));
        assert!(at("phone") < at("tablet"));
        // Standalone member still renders flat.
        assert!(out.contains("server"));
    }

    /// The address column has to be one this node can send to, and the mesh
    /// IPv6 is the only one there is. It is also the column people copy into
    /// `ssh`, so a stale IPv4 here would be worse than a wide row.
    #[test]
    fn peer_rows_carry_the_reachable_address() {
        let mut p = peer("dev", None, false, true, false);
        p.ipv6 = "200::9".parse().unwrap();
        let net = net("laptop", vec![p]);

        let out = render(&net);
        assert!(out.contains("200::9"), "{out}");
        assert!(!out.contains("100.64."), "{out}");
    }

    #[test]
    fn visible_primary_anchors_its_own_group() {
        // Viewing a *foreign* user whose primary device is itself a visible member
        // (endpoint id == user identity) plus one paired secondary. The primary
        // must anchor the group on its own row, not appear once flat and once as a
        // separate rollup header (the `laptop ... / laptop ...` duplication bug).
        let laptop = iroh::SecretKey::generate().public();
        let primary = ipc::PeerStatus {
            endpoint_id: laptop,
            ipv6: "200::3".parse().unwrap(),
            hostname: Some("laptop".to_string()),
            user_identity: None,
            is_own_device: false,
            incompatible: false,
            connection: Some(conn()),
            state: ipc::PeerState::Active,
            exit_node: false,
            exit_in_use: false,
        };
        let secondary = peer("sm-f966b", Some(laptop), false, false, false);
        let net = net("umbrel", vec![primary, secondary]);
        let out = render(&net);

        // "laptop" is named exactly once, and there is no synthetic rollup header.
        assert_eq!(out.matches("laptop").count(), 1, "{out}");
        assert!(!out.contains("device"), "unexpected rollup header:\n{out}");
        // The secondary nests under the primary's row.
        assert!(out.contains("└─"), "{out}");
        let at = |s: &str| out.find(s).unwrap();
        assert!(at("laptop") < at("sm-f966b"), "{out}");
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
        let out = render(&net("laptop", vec![offering, in_use, plain]));
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
        let net = net("laptop", vec![peer("oldbox", None, false, false, true)]);
        let out = render(&net);
        assert!(out.contains("oldbox"));
        assert!(out.contains("incompatible"), "{out}");
        assert!(out.contains("ray update"), "{out}");
        assert!(!out.contains("offline"), "{out}");
    }

    /// A network whose record advertises a mesh version this build doesn't speak
    /// registers from its signed blob but carries nothing, so the header has to
    /// say so. Rendering it as an ordinary network is how a mesh that moved on
    /// without you looks exactly like one that works.
    #[test]
    fn flags_an_incompatible_network() {
        let mut n = net("laptop", vec![peer("oldbox", None, false, false, true)]);
        n.incompatible = Some(ipc::MeshVersionMismatch {
            network: 2,
            ours: 4,
        });
        let out = network_header(&n, Liveness::Live);
        assert!(out.contains("incompatible"), "{out}");
        // Both versions, so the reader can tell which side is behind.
        assert!(out.contains("v2"), "{out}");
        assert!(out.contains("v4"), "{out}");
        assert!(out.contains("ray update"), "{out}");
    }

    /// The same header on a healthy network carries none of that.
    #[test]
    fn a_compatible_network_header_carries_no_version_flag() {
        let out = network_header(
            &net("laptop", vec![peer("srv", None, false, true, false)]),
            Liveness::Live,
        );
        assert!(!out.contains("incompatible"), "{out}");
        assert!(!out.contains("ray update"), "{out}");
    }

    /// A saved network the daemon never registered still has to appear. The
    /// daemon reports it (the CLI cannot read the daemon's config: on macOS it
    /// is root-owned and `ray status` runs as someone else), and the reason it
    /// carries is what the reader would otherwise have to go find in the log.
    #[test]
    fn lists_a_saved_network_the_daemon_never_registered() {
        let out = inactive_network_block(&ipc::InactiveNetwork {
            name: "homelab".to_string(),
            reason: Some("runs mesh protocol v2, this build speaks v4".to_string()),
            saved: None,
        });
        assert!(out.contains("homelab"), "{out}");
        assert!(out.contains("inactive"), "{out}");
        assert!(out.contains("peers on it are unreachable"), "{out}");
        assert!(out.contains("runs mesh protocol v2"), "{out}");
    }

    /// Before the first attempt fails there is no reason to give, and an empty
    /// `reason` line would read as one.
    #[test]
    fn an_inactive_network_without_a_reason_prints_no_reason_line() {
        let out = inactive_network_block(&ipc::InactiveNetwork {
            name: "homelab".to_string(),
            reason: None,
            saved: None,
        });
        assert!(out.contains("homelab"), "{out}");
        assert!(!out.contains("reason"), "{out}");
    }

    #[test]
    fn single_device_group_reads_singular() {
        let me = iroh::SecretKey::generate().public();
        let net = net("laptop", vec![peer("phone", Some(me), true, true, false)]);
        let out = render(&net);
        assert!(out.contains("1 device, 1 online"), "{out}");
    }

    /// The roster a saved-but-unregistered network carries: every peer known
    /// from disk, none of them reachable yet.
    fn saved_roster(hosts: &[&str]) -> ipc::NetworkStatus {
        let peers = hosts
            .iter()
            .map(|h| ipc::PeerStatus {
                endpoint_id: iroh::SecretKey::generate().public(),
                ipv6: "200::2".parse().unwrap(),
                hostname: Some((*h).to_string()),
                user_identity: None,
                is_own_device: false,
                incompatible: false,
                connection: None,
                state: ipc::PeerState::Offline,
                exit_node: false,
                exit_in_use: false,
            })
            .collect();
        let mut n = net("laptop", peers);
        n.name = "homelab".to_string();
        n.role = ipc::NetworkRole::Member;
        n.network_key = Some("ray1abcd".to_string());
        n
    }

    /// A group the daemon is still restoring has to look like a group, not like
    /// a one-line apology: the roster is on disk, so the members, our address
    /// and the join code are all knowable before the coordinator answers.
    #[test]
    fn a_connecting_group_lists_its_saved_roster() {
        let out = inactive_network_block(&ipc::InactiveNetwork {
            name: "homelab".to_string(),
            reason: None,
            saved: Some(saved_roster(&["desktop", "phone"])),
        });
        assert!(out.contains("homelab"), "{out}");
        assert!(out.contains("connecting"), "{out}");
        assert!(out.contains("desktop") && out.contains("phone"), "{out}");
        assert!(out.contains("ray1abcd"), "{out}");
        // Nothing has failed yet, so the header does not claim it has. The peer
        // rows still read offline: nothing on an unregistered network is
        // reachable.
        let header = out.lines().next().unwrap();
        assert!(header.contains("connecting"), "{out}");
        assert!(!header.contains("offline"), "{out}");
        assert!(!out.contains("reason"), "{out}");
    }

    /// Once a restore attempt has actually failed, "connecting" is a lie: the
    /// group reads offline and says why.
    #[test]
    fn a_group_whose_restore_failed_reads_offline() {
        let out = inactive_network_block(&ipc::InactiveNetwork {
            name: "homelab".to_string(),
            reason: Some("runs mesh protocol v2, this build speaks v4".to_string()),
            saved: Some(saved_roster(&["desktop"])),
        });
        let header = out.lines().next().unwrap();
        assert!(header.contains("offline"), "{out}");
        assert!(!header.contains("connecting"), "{out}");
        assert!(out.contains("runs mesh protocol v2"), "{out}");
        assert!(out.contains("desktop"), "{out}");
    }

    /// The member count on a group with no live link is a plain total: the
    /// live header's `reachable/total` would read `0/3` and invite the reader
    /// to go looking for the three that are down.
    #[test]
    fn a_connecting_group_counts_members_without_a_reachable_split() {
        let out = network_header(&saved_roster(&["a", "b", "c"]), Liveness::Connecting);
        assert!(out.contains("members 3"), "{out}");
        assert!(!out.contains("0/3"), "{out}");
    }

    /// A daemon predating the saved projection sends no roster. The group still
    /// has to be named rather than vanish.
    #[test]
    fn a_group_from_a_daemon_without_a_saved_roster_still_gets_named() {
        let out = inactive_network_block(&ipc::InactiveNetwork {
            name: "homelab".to_string(),
            reason: None,
            saved: None,
        });
        assert!(out.contains("homelab"), "{out}");
        assert!(out.contains("inactive"), "{out}");
    }
}
