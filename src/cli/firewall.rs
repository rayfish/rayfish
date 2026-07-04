//! CLI firewall + declarative-apply handlers and their parsers/renderers.

use crate::*;

pub(crate) async fn ipc_firewall(action: FirewallAction) -> Result<()> {
    if let FirewallAction::Suggest {
        network,
        subject,
        allow,
        deny,
    } = action
    {
        return ipc_firewall_suggest(&network, &subject, allow, deny).await;
    }
    if let FirewallAction::Pending { network } = action {
        return ipc_firewall_pending(&network).await;
    }
    if let FirewallAction::Ssh { action } = action {
        return ipc_firewall_ssh(action).await;
    }
    let mut stream = ipc::connect().await?;
    let req = match action {
        FirewallAction::Add {
            direction,
            action,
            proto,
            port,
            peer,
            network,
        } => ipc::IpcMessage::FirewallAdd {
            direction: direction.parse().map_err(anyhow::Error::msg)?,
            action: action.parse().map_err(anyhow::Error::msg)?,
            protocol: proto.parse().map_err(anyhow::Error::msg)?,
            port,
            peer,
            network,
        },
        FirewallAction::Remove { index } => ipc::IpcMessage::FirewallRemove { index },
        FirewallAction::Show => ipc::IpcMessage::FirewallShow,
        FirewallAction::Default { action } => ipc::IpcMessage::FirewallDefault {
            action: action.parse().map_err(anyhow::Error::msg)?,
        },
        FirewallAction::Reject { state } => {
            let enabled = match state.to_ascii_lowercase().as_str() {
                "on" | "true" | "yes" => true,
                "off" | "false" | "no" => false,
                other => anyhow::bail!("expected `on` or `off`, got '{other}'"),
            };
            ipc::IpcMessage::FirewallReject { enabled }
        }
        FirewallAction::On => ipc::IpcMessage::FirewallSetEnabled { enabled: true },
        FirewallAction::Off => ipc::IpcMessage::FirewallSetEnabled { enabled: false },
        FirewallAction::Accept { network } => ipc::IpcMessage::FirewallAccept { network },
        FirewallAction::Deny { network } => ipc::IpcMessage::FirewallDeny { network },
        FirewallAction::AutoAccept { network, state } => {
            let enabled = match state.to_ascii_lowercase().as_str() {
                "on" | "true" | "yes" => true,
                "off" | "false" | "no" => false,
                other => anyhow::bail!("expected `on` or `off`, got '{other}'"),
            };
            ipc::IpcMessage::FirewallAutoAccept { network, enabled }
        }
        // Handled above by early return (need extra round trips / interaction).
        FirewallAction::Suggest { .. }
        | FirewallAction::Pending { .. }
        | FirewallAction::Ssh { .. } => unreachable!(),
    };
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::FirewallState {
            default_inbound,
            default_outbound,
            reject,
            disabled,
            rules,
        } => {
            if json_enabled() {
                print_json(&serde_json::json!({
                    "default_inbound": default_inbound,
                    "default_outbound": default_outbound,
                    "reject": reject,
                    "disabled": disabled,
                    "rules": rules,
                }));
            } else {
                print!(
                    "{}",
                    render_firewall_rules(
                        Some((default_inbound, default_outbound)),
                        reject,
                        disabled,
                        &rules
                    )
                );
            }
        }
        ipc::IpcMessage::Error { message } => print_error("firewall", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// `ray firewall ssh ...`: toggle the embedded mesh SSH server and manage
/// per-network allow lists.
async fn ipc_firewall_ssh(action: SshAction) -> Result<()> {
    let mut filter: Option<String> = None;
    let req = match action {
        SshAction::On => ipc::IpcMessage::FirewallSshSet { enabled: true },
        SshAction::Off => ipc::IpcMessage::FirewallSshSet { enabled: false },
        SshAction::Allow {
            network,
            peer,
            user,
        } => ipc::IpcMessage::FirewallSshAllow {
            network,
            peer,
            users: user,
            allow: true,
        },
        SshAction::Deny { network, peer } => ipc::IpcMessage::FirewallSshAllow {
            network,
            peer,
            users: vec![],
            allow: false,
        },
        SshAction::Show { network } => {
            filter = network;
            ipc::IpcMessage::FirewallSshShow
        }
    };
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::FirewallSshState { enabled, networks } => {
            render_ssh_state(enabled, networks, filter.as_deref())
        }
        ipc::IpcMessage::Error { message } => print_error("firewall ssh", &message, None),
        other => eprintln!("Unexpected response: {other:?}"),
    }
    Ok(())
}

/// Render `ray firewall ssh show` output (or JSON), optionally filtered to one
/// network.
fn render_ssh_state(
    enabled: bool,
    networks: Vec<(String, Vec<ipc::SshAllowView>)>,
    filter: Option<&str>,
) {
    let networks: Vec<(String, Vec<ipc::SshAllowView>)> = networks
        .into_iter()
        .filter(|(n, _)| filter.is_none_or(|f| f == n))
        .collect();
    if json_enabled() {
        print_json(&serde_json::json!({
            "enabled": enabled,
            "networks": networks.iter().map(|(n, a)| serde_json::json!({
                "network": n,
                "allow": a.iter().map(|r| serde_json::json!({
                    "peer": r.peer,
                    "users": r.users,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }));
        return;
    }
    println!("mesh SSH: {}", if enabled { "on" } else { "off" });
    if networks.is_empty() {
        println!("  (no SSH allow rules)");
        return;
    }
    for (net, allow) in &networks {
        let entries: Vec<String> = allow
            .iter()
            .map(|r| {
                let peer = if r.peer == "*" || r.peer.len() <= 12 {
                    r.peer.clone()
                } else {
                    format!("{}…", &r.peer[..12])
                };
                // Empty users = the non-root default; `*` = any user incl. root.
                let users = if r.users.is_empty() {
                    "any non-root user".to_string()
                } else if r.users.iter().any(|u| u == "*") {
                    "any user".to_string()
                } else {
                    r.users.join(",")
                };
                format!("{peer} → {users}")
            })
            .collect();
        println!("  {net}: {}", entries.join("; "));
    }
}

/// Print a JSON value as one compact line to stdout (jq-friendly).
pub(crate) fn print_json(value: &serde_json::Value) {
    println!("{value}");
}

/// Render a firewall rule table as aligned columns. `default` is the catch-all
/// action shown as a header (omitted for the pending-suggestions list).
pub(crate) fn render_firewall_rules(
    default: Option<(firewall::Action, firewall::Action)>,
    reject: bool,
    disabled: bool,
    rules: &[ipc::FirewallRuleView],
) -> String {
    let mut out = String::from("\n");
    if default.is_some() {
        // The rayfish firewall is separate from (and applies on top of) the host
        // OS / kernel firewall; both must allow a packet for it to pass.
        out.push_str(&format!(
            "  {}\n\n",
            style::faint("mesh firewall (separate from your host/kernel firewall)")
        ));
    }
    if disabled && default.is_some() {
        out.push_str(&format!(
            "  {}  {}\n\n",
            style::label("status     "),
            style::red("disabled (all packets allowed; ray firewall on to re-enable)")
        ));
    }
    if let Some((inbound, outbound)) = default {
        let styled = |a: firewall::Action| {
            let s = a.to_string();
            if a.is_deny() {
                style::red(&s)
            } else {
                style::green(&s)
            }
        };
        out.push_str(&format!(
            "  {}  {}\n",
            style::label("default in "),
            styled(inbound)
        ));
        out.push_str(&format!(
            "  {}  {}\n",
            style::label("default out"),
            styled(outbound)
        ));
        let reject_styled = if reject {
            style::green("on")
        } else {
            style::faint("off")
        };
        out.push_str(&format!(
            "  {}  {}\n\n",
            style::label("reject    "),
            reject_styled
        ));
    }
    if rules.is_empty() {
        out.push_str(&format!("  {}\n", style::faint("(no rules)")));
        return out;
    }
    let rows = rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let direction = r.direction.to_string();
            let protocol = r.protocol.to_string();
            let action_s = r.action.to_string();
            let action = if r.action.is_deny() {
                style::red(&action_s)
            } else {
                style::green(&action_s)
            };
            let sugg = r
                .suggested_by
                .as_ref()
                .map(|s| style::marker(&format!("suggested by {s}")))
                .unwrap_or_default();
            let sugg_plain = r
                .suggested_by
                .as_ref()
                .map(|s| format!("·suggested by {s}·"))
                .unwrap_or_default();
            vec![
                layout::Cell::new(i.to_string(), style::faint(&i.to_string())),
                layout::Cell::new(direction.clone(), style::value(&direction)),
                layout::Cell::new(action_s.clone(), action),
                layout::Cell::new(protocol.clone(), style::value(&protocol)),
                layout::Cell::right(r.port.clone(), style::value(&r.port)),
                layout::Cell::new(r.peer.clone(), style::value(&r.peer)),
                layout::Cell::new(r.network.clone(), style::faint(&r.network)),
                layout::Cell::new(sugg_plain, sugg),
            ]
        })
        .collect();
    out.push_str(&table(
        &["#", "dir", "action", "proto", "port", "peer", "network", ""],
        rows,
        4,
    ));
    out.push('\n');
    out
}

/// `ray firewall pending`: fetch the queued suggestions, then either run the
/// interactive picker (TTY) or print a static table (piped / `--json`).
pub(crate) async fn ipc_firewall_pending(network: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallPending {
            network: network.to_string(),
        },
    )
    .await?;
    let rules = match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::FirewallPendingResponse { rules, .. } => rules,
        ipc::IpcMessage::Error { message } => {
            print_error("firewall pending", &message, None);
            return Ok(());
        }
        other => {
            eprintln!("Unexpected response: {other:?}");
            return Ok(());
        }
    };

    if json_enabled() {
        print_json(&serde_json::json!({ "network": network, "rules": rules }));
        return Ok(());
    }
    if rules.is_empty() {
        println!("\n  {}\n", style::faint("no pending suggested rules"));
        return Ok(());
    }
    // Non-interactive (piped / NO_COLOR): print the static table and stop.
    if !style::is_enabled() {
        print!("{}", render_firewall_rules(None, false, false, &rules));
        return Ok(());
    }

    // Interactive picker → resolve the user's per-rule decisions.
    let Some(resolution) = picker::run(network, &rules)? else {
        // Ctrl-C: leave the queue untouched.
        return Ok(());
    };
    if resolution.accept.is_empty() && resolution.deny.is_empty() {
        println!("  {}", style::faint("no changes"));
        return Ok(());
    }
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallResolveSuggestions {
            network: network.to_string(),
            accept: resolution.accept,
            deny: resolution.deny,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => {
            println!("  {} {}", style::check(), style::value(&message));
        }
        ipc::IpcMessage::Error { message } => print_error("firewall pending", &message, None),
        other => eprintln!("Unexpected response: {other:?}"),
    }
    Ok(())
}

/// Parse a `--allow`/`--deny` value into `(peer, proto:ports-list)`.
///
/// The grammar is `PEER:proto:ports`, but the leading `PEER:` is optional: when
/// the value begins with a protocol keyword (`tcp`/`udp`/`icmp`/`any`) the peer
/// defaults to `*` (any peer). So `tcp:22` is read as "tcp/22 from any peer" —
/// the intuitive form — instead of "any port from a peer named `tcp`", which
/// would silently drop on the joiner (unresolvable hostname) and materialize no
/// rule at all, inverting the intent.
pub(crate) fn parse_suggest_token(spec: &str, flag: &str) -> Result<(String, String)> {
    let spec = spec.trim();
    anyhow::ensure!(
        !spec.is_empty(),
        "{flag} expects PEER:proto:ports (e.g. '*:tcp:22'), got an empty value"
    );
    // A leading protocol keyword means the peer was omitted: treat the whole
    // value as the proto:ports list against any peer.
    let first = spec.split(':').next().unwrap_or("");
    if first.parse::<firewall::Protocol>().is_ok() {
        return Ok(("*".to_string(), spec.to_string()));
    }
    let (peer, ports) = spec
        .split_once(':')
        .with_context(|| format!("{flag} expects PEER:proto:ports, got '{spec}'"))?;
    anyhow::ensure!(
        !peer.is_empty() && !ports.is_empty(),
        "{flag} expects PEER:proto:ports, got '{spec}'"
    );
    Ok((peer.to_string(), ports.to_string()))
}

/// `ray firewall suggest`: read the network's current suggestions, merge the
/// requested subject edits, and publish the updated set (coordinator-only).
pub(crate) async fn ipc_firewall_suggest(
    network: &str,
    subject: &str,
    allow: Vec<String>,
    deny: Vec<String>,
) -> Result<()> {
    use ray_proto::HostSuggestions;

    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallSuggestions {
            network: network.to_string(),
        },
    )
    .await?;
    let mut suggestions = match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::FirewallSuggestionsResponse { suggestions } => suggestions,
        ipc::IpcMessage::Error { message } => {
            print_error("error", &message, None);
            std::process::exit(1);
        }
        other => {
            eprintln!("Unexpected response: {other:?}");
            std::process::exit(1);
        }
    };

    let entry = suggestions.entry(subject.to_string()).or_default();
    for a in &allow {
        let (peer, ports) = parse_suggest_token(a, "--allow")?;
        entry.allows.insert(peer, ports);
    }
    for d in &deny {
        let (peer, ports) = parse_suggest_token(d, "--deny")?;
        entry.denies.insert(peer, ports);
    }
    // Drop a now-empty subject so removing all of a host's rules clears it.
    if entry == &HostSuggestions::default() {
        suggestions.remove(subject);
    }

    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallSuggest {
            network: network.to_string(),
            suggestions,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {other:?}"),
    }
    Ok(())
}

/// `ray apply <spec>`: reconcile trusted networks against a deploy spec.
///
/// B2 — orchestrator: for each network in the spec, `Create { trusted }` if it
/// isn't active, then publish the spec's `firewall` block as suggestions
/// (idempotent — always replaces the live set). `--prune` limits the published
/// set to subjects present in the spec, dropping any live suggestions for
/// hosts no longer mentioned. Never joins.
///
/// B3 — membership diff: expected hosts = union of hostnames in the spec's
/// `firewall:` blocks; joined hosts = hostnames from `Status` (this node +
/// peers). Reports the gap and prints hostname-bound invite commands; with
/// `--invite-missing` mints them via IPC.
pub(crate) async fn ipc_apply(
    spec_path: Option<String>,
    prune: bool,
    dry_run: bool,
    invite_missing: bool,
    example: bool,
) -> Result<()> {
    if example {
        print!("{}", apply::EXAMPLE_SPEC);
        return Ok(());
    }
    let Some(spec_path) = spec_path else {
        anyhow::bail!("a spec file path is required (or use --example to print a template)");
    };
    let spec = apply::load(std::path::Path::new(&spec_path))?;
    if spec.networks.is_empty() {
        anyhow::bail!("spec contains no networks");
    }
    let has_dynamic = !spec.aliases.is_empty() || !spec.groups.is_empty();

    // A dry-run with no aliases/groups needs nothing from the daemon: just echo
    // the normalized spec (the historical behavior).
    if dry_run && !has_dynamic {
        println!("{}", style::bold("Spec (normalized):"));
        print!("{}", apply::to_yaml(&spec)?);
        println!("{}", style::faint("(dry-run; no changes applied)"));
        return Ok(());
    }

    // Validate alias identity strings CLI-side (where iroh parsing lives) and
    // canonicalize them so comparison against peer ids is format-insensitive.
    let aliases = canonicalize_aliases(&spec.aliases)?;

    // Fetch live state once: status gives this node's identity, active networks,
    // per-peer identities, and joined hostnames.
    let (self_id, status_networks) = ipc_status_full().await?;
    let active_names: std::collections::HashSet<&str> =
        status_networks.iter().map(|n| n.name.as_str()).collect();

    // Expand groups/aliases against live status into a pure hostname-keyed spec.
    let mut expanded = apply::DeploySpec::default();
    for (net_name, fw) in &spec.networks {
        // Seed from the network's stored `ray alias` map (already canonical), then
        // let the spec's own `aliases:` override on name conflict. Stored aliases
        // are node-local and never reach the blob.
        let stored_aliases = status_networks
            .iter()
            .find(|n| &n.name == net_name)
            .map(|n| n.aliases.clone())
            .unwrap_or_default();
        let net_aliases = apply::merge_aliases(&stored_aliases, &aliases);
        let resolve = |identity: &str| -> Vec<String> {
            resolve_identity_hosts(&status_networks, net_name, &self_id, identity)
        };
        let (efw, empty_aliases) = apply::expand_firewall(fw, &net_aliases, &spec.groups, &resolve);
        for a in empty_aliases {
            eprintln!(
                "{}  {net_name}: alias '{a}' has no joined devices yet; its rules are skipped",
                style::faint("note:")
            );
        }
        expanded.networks.insert(net_name.clone(), efw);
    }

    if dry_run {
        println!("{}", style::bold("Spec (expanded):"));
        print!("{}", apply::to_yaml(&expanded)?);
        println!("{}", style::faint("(dry-run; no changes applied)"));
        return Ok(());
    }

    let mut missing_hosts: Vec<(String, String)> = Vec::new(); // (network, hostname)

    for (net_name, net_firewall) in &expanded.networks {
        let is_active = active_names.contains(net_name.as_str());
        // Create-if-absent (always a closed network).
        if !is_active {
            println!(
                "{} {}: creating closed network",
                style::label("apply"),
                style::bold(net_name),
            );
            if let Err(e) = ipc_apply_create(net_name).await {
                eprintln!("{}  create failed: {e}", style::red("  !"));
                continue;
            }
        } else {
            println!(
                "{} {}: already active",
                style::label("apply"),
                style::bold(net_name)
            );
        }

        // Publish suggestions (idempotent). With --prune, publish exactly the
        // spec's set; without it, merge into the live set (so `apply` never
        // silently drops subjects authored out-of-band — use --prune for that).
        let to_publish = if prune {
            net_firewall.clone()
        } else {
            let mut live = ipc_firewall_suggestions_get(net_name)
                .await
                .unwrap_or_default();
            // Merge spec subjects over live (spec wins on conflict).
            for (subj, rules) in net_firewall {
                live.insert(subj.clone(), rules.clone());
            }
            live
        };
        match ipc_firewall_suggest_set(net_name, to_publish).await {
            Ok(msg) => println!("{}   {msg}", style::faint("→")),
            Err(e) => eprintln!("{}   suggest failed: {e}", style::red("  !")),
        }

        // B3 — membership diff for this network.
        let joined = joined_hostnames(&status_networks, net_name);
        for host in apply::expected_hosts(&expanded) {
            if !joined.iter().any(|j| j == &host) {
                missing_hosts.push((net_name.clone(), host));
            }
        }
    }

    // B3 — report the membership gap.
    if missing_hosts.is_empty() {
        println!("{}", style::green("All expected hosts have joined."));
    } else {
        println!(
            "\n{} Missing hosts (spec expects them):",
            style::label("diff")
        );
        for (net, host) in &missing_hosts {
            let cmd = format!("ray invite {net} --hostname {host}");
            if invite_missing {
                match ipc_invite_mint(net, Some(host.clone())).await {
                    Ok(code) => println!(
                        "  {}  {}  {}",
                        style::bold(host),
                        cmd,
                        style::faint(&format!("→ {code}"))
                    ),
                    Err(e) => eprintln!(
                        "  {}  {cmd}  {}",
                        style::red(host),
                        style::red(&e.to_string())
                    ),
                }
            } else {
                println!("  {}  {cmd}", style::bold(host));
            }
        }
        if !invite_missing {
            println!(
                "\n{} re-run with --invite-missing to mint these invites.",
                style::faint("tip:")
            );
        }
    }
    Ok(())
}

/// Joined hostnames on `network` (this node's hostname + every peer's hostname).
pub(crate) fn joined_hostnames(networks: &[ipc::NetworkStatus], network: &str) -> Vec<String> {
    let Some(net) = networks.iter().find(|n| n.name == network) else {
        return Vec::new();
    };
    let mut hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Some(h) = &net.my_hostname {
        hosts.insert(h.clone());
    }
    for p in &net.peers {
        if let Some(h) = &p.hostname {
            hosts.insert(h.clone());
        }
    }
    hosts.into_iter().collect()
}

/// `ray identityof <net> <host>`: print the identity string to paste into a
/// spec's `aliases:` map. Resolves to the user identity if the device is paired,
/// else the device's transport identity. Open read.
pub(crate) async fn cmd_identityof(network: &str, hostname: &str, json: bool) -> Result<()> {
    let (self_id, networks) = ipc_status_full().await?;
    let net = networks
        .iter()
        .find(|n| n.name == network)
        .ok_or_else(|| anyhow::anyhow!("network '{network}' not found (is it active?)"))?;

    let Some((identity, paired)) = resolve_host_identity(net, &self_id, hostname) else {
        anyhow::bail!(
            "host '{hostname}' is not currently joined on '{network}' \
             (an alias can only name an already-joined member)"
        );
    };

    if json {
        print_json(&serde_json::json!({
            "network": network,
            "hostname": hostname,
            "identity": identity,
            "paired": paired,
        }));
    } else {
        println!("{identity}");
    }
    Ok(())
}

/// Resolve a joined hostname to `(identity, paired)` on one network: self matches
/// by device identity; a peer prefers its user identity when paired, else its
/// device endpoint id. Shared by `ray identityof` and `ray alias set`.
pub(crate) fn resolve_host_identity(
    net: &ipc::NetworkStatus,
    self_id: &str,
    hostname: &str,
) -> Option<(String, bool)> {
    if net.my_hostname.as_deref() == Some(hostname) {
        Some((self_id.to_string(), false))
    } else {
        net.peers
            .iter()
            .find(|p| p.hostname.as_deref() == Some(hostname))
            .map(|p| match p.user_identity {
                Some(u) => (u.to_string(), true),
                None => (p.endpoint_id.to_string(), false),
            })
    }
}

/// Fetch live status: this node's own device identity (as a canonical string)
/// plus every network's roster. The identity is needed to resolve an alias that
/// names the coordinator itself.
pub(crate) async fn ipc_status_full() -> Result<(String, Vec<ipc::NetworkStatus>)> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Status).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::StatusResponse {
            endpoint_id,
            networks,
            ..
        } => Ok((endpoint_id.to_string(), networks)),
        other => anyhow::bail!("unexpected status response: {other:?}"),
    }
}

/// Parse and canonicalize each alias's identity value (`name -> identity`),
/// erroring on a value that isn't a valid identity so a typo fails fast instead
/// of silently resolving to nothing.
fn canonicalize_aliases(
    aliases: &std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>> {
    aliases
        .iter()
        .map(|(name, id)| {
            let parsed = id.parse::<iroh::EndpointId>().map_err(|_| {
                anyhow::anyhow!(
                    "alias '{name}' has an invalid identity '{id}' (copy it from `ray identityof <net> <host>`)"
                )
            })?;
            Ok((name.clone(), parsed.to_string()))
        })
        .collect()
}

/// Collect the hostnames currently joined for `identity` in `network`: every
/// peer whose device or user identity matches, plus this node itself when the
/// alias names the coordinator's own device. Returns sorted, unique hostnames.
fn resolve_identity_hosts(
    networks: &[ipc::NetworkStatus],
    network: &str,
    self_id: &str,
    identity: &str,
) -> Vec<String> {
    let Some(net) = networks.iter().find(|n| n.name == network) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    if self_id == identity
        && let Some(h) = &net.my_hostname
    {
        out.push(h.clone());
    }
    for p in &net.peers {
        let dev = p.endpoint_id.to_string();
        let usr = p.user_identity.map(|u| u.to_string());
        if (dev == identity || usr.as_deref() == Some(identity))
            && let Some(h) = &p.hostname
        {
            out.push(h.clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) async fn ipc_apply_create(name: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Create {
            mode: ray_proto::GroupMode::Restricted,
            name: Some(name.to_string()),
            hostname: None,
            transport: None,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Created { name: n, .. } => {
            println!("{}   created '{n}'", style::faint("→"));
            Ok(())
        }
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected create response: {other:?}"),
    }
}

pub(crate) async fn ipc_firewall_suggestions_get(
    network: &str,
) -> Result<ray_proto::SuggestedFirewall> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallSuggestions {
            network: network.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::FirewallSuggestionsResponse { suggestions } => Ok(suggestions),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected suggestions response: {other:?}"),
    }
}

pub(crate) async fn ipc_firewall_suggest_set(
    network: &str,
    suggestions: ray_proto::SuggestedFirewall,
) -> Result<String> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::FirewallSuggest {
            network: network.to_string(),
            suggestions,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => Ok(message),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected suggest response: {other:?}"),
    }
}

pub(crate) async fn ipc_invite_mint(network: &str, hostname: Option<String>) -> Result<String> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::InviteCreate {
            network: network.to_string(),
            expires_secs: 7 * 24 * 3600,
            hostname,
            reusable: false,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::InviteCreated { code, .. } => Ok(code),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected invite response: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer(hostname: &str, user: Option<iroh::EndpointId>) -> ipc::PeerStatus {
        ipc::PeerStatus {
            endpoint_id: iroh::SecretKey::generate().public(),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            ipv6: None,
            hostname: Some(hostname.to_string()),
            user_identity: user,
            is_own_device: false,
            connection: None,
        }
    }

    fn net(my_hostname: Option<&str>, peers: Vec<ipc::PeerStatus>) -> ipc::NetworkStatus {
        ipc::NetworkStatus {
            name: "n".to_string(),
            role: ipc::NetworkRole::Member,
            my_ip: Ipv4Addr::new(100, 64, 0, 1),
            my_ipv6: None,
            my_hostname: my_hostname.map(|s| s.to_string()),
            network_key: None,
            member_count: 0,
            peers,
            pending_suggestions: 0,
            pending_requests: 0,
            aliases: Default::default(),
        }
    }

    #[test]
    fn resolve_self_hostname_returns_self_id() {
        let n = net(Some("me"), vec![]);
        let got = resolve_host_identity(&n, "self-id", "me");
        assert_eq!(got, Some(("self-id".to_string(), false)));
    }

    #[test]
    fn resolve_paired_peer_prefers_user_identity() {
        let user = iroh::SecretKey::generate().public();
        let n = net(Some("me"), vec![peer("alice", Some(user))]);
        let got = resolve_host_identity(&n, "self-id", "alice");
        assert_eq!(got, Some((user.to_string(), true)));
    }

    #[test]
    fn resolve_unpaired_peer_uses_endpoint_id() {
        let p = peer("bob", None);
        let want = p.endpoint_id.to_string();
        let n = net(Some("me"), vec![p]);
        let got = resolve_host_identity(&n, "self-id", "bob");
        assert_eq!(got, Some((want, false)));
    }

    #[test]
    fn resolve_unknown_hostname_is_none() {
        let n = net(Some("me"), vec![peer("alice", None)]);
        assert_eq!(resolve_host_identity(&n, "self-id", "ghost"), None);
    }
}
