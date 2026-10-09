//! CLI firewall + declarative-apply handlers and their parsers/renderers.

use std::collections::{BTreeSet, HashSet};

use crate::*;
use firewall::Action;
use ipc::{FirewallKey, GlobalKey, NetworkKey, NodeKey};

#[derive(serde::Serialize)]
struct FirewallStateOutput<'a> {
    default_inbound: Action,
    default_outbound: Action,
    reject: bool,
    disabled: bool,
    rules: &'a [ipc::FirewallRuleView],
}

impl DisplayOut for FirewallStateOutput<'_> {
    fn print_human(&self) {
        print!(
            "{}",
            render_firewall_rules(
                Some((self.default_inbound, self.default_outbound)),
                self.reject,
                self.disabled,
                self.rules,
            )
        );
    }
}

#[derive(serde::Serialize)]
struct SshNetworkOutput<'a> {
    network: &'a str,
    allow: &'a [ipc::SshAllowView],
}

#[derive(serde::Serialize)]
struct SshStateOutput<'a> {
    enabled: bool,
    port: u16,
    networks: Vec<SshNetworkOutput<'a>>,
}

impl DisplayOut for SshStateOutput<'_> {
    fn print_human(&self) {
        println!(
            "mesh SSH: {} (port {})",
            if self.enabled { "on" } else { "off" },
            self.port
        );
        if self.networks.is_empty() {
            println!("  (no SSH allow rules)");
            return;
        }
        for network in &self.networks {
            let entries: Vec<String> = network
                .allow
                .iter()
                .map(|rule| {
                    let peer = if rule.peer == "*" || rule.peer.len() <= 12 {
                        rule.peer.clone()
                    } else {
                        format!("{}…", &rule.peer[..12])
                    };
                    // Empty users permits the non-root default; `*` includes root.
                    let users = if rule.users.is_empty() {
                        "any non-root user".to_string()
                    } else if rule.users.iter().any(|user| user == "*") {
                        "any user".to_string()
                    } else {
                        rule.users.join(",")
                    };
                    format!("{peer} → {users}")
                })
                .collect();
            println!("  {}: {}", network.network, entries.join("; "));
        }
        // Rules on an off server do not affect mesh traffic.
        if !self.enabled {
            println!("\nThese rules are not in effect: mesh SSH is off.");
            println!("Start the server with `ray ssh on`.");
            return;
        }
        println!("\nSelf-SSH permits your local account; root may select any account.");
    }
}

#[derive(serde::Serialize)]
struct PendingFirewallOutput<'a> {
    network: &'a str,
    rules: &'a [ipc::FirewallRuleView],
}

impl DisplayOut for PendingFirewallOutput<'_> {
    fn print_human(&self) {
        if self.rules.is_empty() {
            println!("\n  {}\n", style::faint("no pending suggested rules"));
        } else {
            print!("{}", render_firewall_rules(None, false, false, self.rules));
        }
    }
}

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
    let req = to_ipc(action)?;
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::FirewallState {
            default_inbound,
            default_outbound,
            reject,
            disabled,
            mut rules,
        } => {
            if !json_enabled()
                && let Ok((self_id, networks)) = ipc_status_full().await
            {
                for rule in &mut rules {
                    rule.peer = firewall_peer_name(rule, &self_id, &networks);
                }
            }
            printout(&FirewallStateOutput {
                default_inbound,
                default_outbound,
                reject,
                disabled,
                rules: &rules,
            })?;
        }
        ipc::IpcMessage::Error { message } => fail_with("firewall", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Map a `ray firewall` subcommand onto the IPC request that serves it. The
/// single-value toggles carry no variant of their own: they name a settings key
/// and hand the raw `on|off` / `allow|deny` word to the daemon, which parses it
/// through the registry (`config::settings`). Kept as its own function so the
/// mapping is unit-testable without a daemon.
///
/// A bad word is still rejected here, by [`parse_on_off`]: `ray firewall` prints
/// a daemon error without failing the command, so a typo caught only
/// server-side would exit 0 instead of 1.
fn to_ipc(action: FirewallAction) -> Result<ipc::IpcMessage> {
    Ok(match action {
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
        FirewallAction::Default { action } => {
            // Lowercased to match the daemon's own parse (`settings::apply_firewall`):
            // otherwise `ray firewall default ALLOW` fails here while
            // `ray config set firewall.default-in ALLOW`, the same setting, works.
            let action = action.to_lowercase();
            action
                .parse::<firewall::Action>()
                .map_err(anyhow::Error::msg)?;
            ipc::IpcMessage::ConfigSet {
                key: NodeKey::Firewall(FirewallKey::DefaultIn),
                value: action,
                replace: false,
            }
        }
        FirewallAction::Reject { state } => {
            parse_on_off(&state)?;
            ipc::IpcMessage::ConfigSet {
                key: NodeKey::Firewall(FirewallKey::Reject),
                value: state,
                replace: false,
            }
        }
        FirewallAction::On => ipc::IpcMessage::ConfigSet {
            key: NodeKey::Firewall(FirewallKey::Enabled),
            value: "on".to_string(),
            replace: false,
        },
        FirewallAction::Off => ipc::IpcMessage::ConfigSet {
            key: NodeKey::Firewall(FirewallKey::Enabled),
            value: "off".to_string(),
            replace: false,
        },
        FirewallAction::Accept { network } => ipc::IpcMessage::FirewallAccept { network },
        FirewallAction::Deny { network } => ipc::IpcMessage::FirewallDeny { network },
        FirewallAction::AutoAccept { network, state } => {
            parse_on_off(&state)?;
            ipc::IpcMessage::NetConfigSet {
                network,
                key: NetworkKey::AutoAcceptFirewall,
                value: state,
            }
        }
        // Handled above by early return (need extra round trips / interaction).
        FirewallAction::Suggest { .. }
        | FirewallAction::Pending { .. }
        | FirewallAction::Ssh { .. } => unreachable!(),
    })
}

/// Map a `ray firewall ssh` subcommand onto its IPC request. `on|off` is the
/// `ssh` settings key: the daemon serves it through the handler that also seeds
/// the configured port's passthrough and starts/stops the listener.
fn ssh_to_ipc(action: SshAction) -> ipc::IpcMessage {
    match action {
        SshAction::On => ipc::IpcMessage::ConfigSet {
            key: NodeKey::Global(GlobalKey::Ssh),
            value: "on".to_string(),
            replace: false,
        },
        SshAction::Off => ipc::IpcMessage::ConfigSet {
            key: NodeKey::Global(GlobalKey::Ssh),
            value: "off".to_string(),
            replace: false,
        },
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
        SshAction::Show { .. } => ipc::IpcMessage::FirewallSshShow,
    }
}

/// Toggle the embedded mesh SSH server or manage per-network allow lists.
pub(crate) async fn ipc_firewall_ssh(action: SshAction) -> Result<()> {
    // `show` filters the reply client-side, so keep its network before the move.
    let filter = match &action {
        SshAction::Show { network } => network.clone(),
        _ => None,
    };
    let req = ssh_to_ipc(action);
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::FirewallSshState {
            enabled,
            port,
            networks,
        } => render_ssh_state(enabled, port, networks, filter.as_deref())?,
        ipc::IpcMessage::Error { message } => fail_with("ssh", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Render `ray firewall ssh show` output (or JSON), optionally filtered to one
/// network.
fn render_ssh_state(
    enabled: bool,
    port: u16,
    networks: Vec<(String, Vec<ipc::SshAllowView>)>,
    filter: Option<&str>,
) -> Result<()> {
    let networks = networks
        .iter()
        .filter(|(network, _)| filter.is_none_or(|name| name == network))
        .map(|(network, allow)| SshNetworkOutput { network, allow })
        .collect();
    printout(&SshStateOutput {
        enabled,
        port,
        networks,
    })
}

/// Resolve within the rule's network, including every device for a user grant.
/// Keep the short identity if it is unknown or matches more than one identity.
fn firewall_peer_name(
    rule: &ipc::FirewallRuleView,
    self_id: &EndpointId,
    networks: &[ipc::NetworkStatus],
) -> String {
    let mut identities = HashSet::new();
    let mut names = BTreeSet::new();
    for network in networks {
        if rule.network != "any" && rule.network != network.name {
            continue;
        }
        if rule.peer == self_id.fmt_short().to_string() {
            identities.insert(*self_id);
            if let Some(hostname) = &network.my_hostname {
                names.insert(hostname.as_str());
            }
        }
        for peer in &network.peers {
            for identity in [Some(peer.endpoint_id), peer.user_identity]
                .into_iter()
                .flatten()
            {
                if rule.peer == identity.fmt_short().to_string() {
                    identities.insert(identity);
                    if let Some(hostname) = &peer.hostname {
                        names.insert(hostname.as_str());
                    }
                }
            }
        }
    }
    if identities.len() == 1 && !names.is_empty() {
        names.into_iter().collect::<Vec<_>>().join(", ")
    } else {
        rule.peer.clone()
    }
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
        ipc::IpcMessage::Error { message } => fail_with("firewall pending", &message),
        other => fail_unexpected(&other),
    };

    // JSON and non-interactive output stop before the picker can mutate rules.
    if json_enabled() || rules.is_empty() || !style::is_enabled() {
        printout(&PendingFirewallOutput {
            network,
            rules: &rules,
        })?;
        return Ok(());
    }

    // Interactive picker → resolve the user's per-rule decisions.
    let Some(resolution) = picker::run(network, &rules)? else {
        // Ctrl-C: leave the queue untouched.
        return Ok(());
    };
    if resolution.is_empty() {
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
        ipc::IpcMessage::Error { message } => fail_with("firewall pending", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Parse a `--allow`/`--deny` value into `(peer, proto:ports-list)`.
///
/// The grammar is `PEER:proto:ports`, but the leading `PEER:` is optional: when
/// the value begins with a protocol keyword (`tcp`/`udp`/`icmp`/`any`) the peer
/// defaults to `*` (any peer). So `tcp:22` is read as "tcp/22 from any peer"
/// (the intuitive form) instead of "any port from a peer named `tcp`", which
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
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    };

    let entry = suggestions.entry(subject.to_string()).or_default();
    for a in &allow {
        let (peer, ports) = parse_suggest_token(a, "--allow")?;
        firewall::parse_excluded_peers(&peer)?;
        entry.allows.insert(peer, ports);
    }
    for d in &deny {
        let (peer, ports) = parse_suggest_token(d, "--deny")?;
        anyhow::ensure!(
            firewall::parse_excluded_peers(&peer)?.is_none(),
            "excluded-peer selector '{peer}' is only valid in allows"
        );
        entry.denies.insert(peer, ports);
    }
    // Drop a now-empty subject so removing all of a host's rules clears it.
    if entry == &HostSuggestions::default() {
        suggestions.remove(subject);
    }

    let response = ipc_request(ipc::IpcMessage::FirewallSuggest {
        network: network.to_string(),
        suggestions,
    })
    .await?;
    print_ok_reply(response)
}

/// `ray apply <spec>`: reconcile trusted networks against a deploy spec.
///
/// B2, orchestrator: for each network in the spec, `Create { trusted }` if it
/// isn't active, then publish the spec's `firewall` block as suggestions
/// (idempotent: always replaces the live set). `--prune` limits the published
/// set to subjects present in the spec, dropping any live suggestions for
/// hosts no longer mentioned. Enrolled machines are joined or removed from the
/// per-network membership diff.
///
/// B3, membership diff: expected hosts = union of hostnames in the spec's
/// network firewall block; joined hosts = hostnames from `Status` (this node +
/// peers). Controlled machines are reconciled directly. Other missing hosts get
/// hostname-bound invite commands; `--invite-missing` mints those via IPC.
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
    // Validate alias identity strings CLI-side (where iroh parsing lives) and
    // canonicalize them so comparison against peer ids is format-insensitive.
    let aliases = canonicalize_aliases(&spec.aliases)?;

    // Fetch live state once: status gives this node's identity, active networks,
    // per-peer identities, and joined hostnames.
    let (self_id, status_networks) = ipc_status_full().await?;
    let self_id = self_id.to_string();
    let managed_machines = ipc_managed_machines_for_apply().await?;
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
        let current = joined_hostnames(&status_networks, net_name)
            .into_iter()
            .map(|hostname| hostname.parse())
            .collect::<Result<HashSet<ipc::MachineHostname>, _>>()?;
        let (efw, empty_aliases) =
            apply::expand_firewall(fw, &net_aliases, &spec.groups, &resolve, &current)?;
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
        println!("{}", style::bold("Membership diff:"));
        let mut changes = 0usize;
        for (network_name, firewall) in &expanded.networks {
            let current: HashSet<ipc::MachineHostname> =
                joined_hostnames(&status_networks, network_name)
                    .into_iter()
                    .map(|hostname| hostname.parse())
                    .collect::<std::result::Result<_, _>>()?;
            let status_network = status_networks
                .iter()
                .find(|network| network.name == *network_name);
            let membership = membership_diff_for_apply(
                firewall,
                &current,
                status_network,
                &managed_machines,
                network_name,
            )?;
            for hostname in membership.joins {
                changes += 1;
                println!("  join   {hostname} to {network_name}");
            }
            let local_hostname = status_networks
                .iter()
                .find(|network| network.name == *network_name)
                .and_then(|network| network.my_hostname.as_deref());
            for hostname in membership.leaves {
                if local_hostname == Some(hostname.as_ref()) {
                    continue;
                }
                changes += 1;
                println!("  leave  {hostname} from {network_name}");
            }
        }
        if changes == 0 {
            println!("  no membership changes");
        }
        println!("{}", style::faint("(dry-run; no changes applied)"));
        return Ok(());
    }

    let mut missing_hosts: Vec<(String, String)> = Vec::new(); // (network, hostname)
    let mut removal_failures = false;
    let mut ssh_failures = false;
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
        // silently drops subjects authored out-of-band - use --prune for that).
        let to_publish = if prune {
            apply::suggested_firewall(net_firewall)
        } else {
            let mut live = ipc_firewall_suggestions_get(net_name)
                .await
                .unwrap_or_default();
            // Merge spec subjects over live (spec wins on conflict).
            for (subj, rules) in net_firewall {
                live.insert(
                    subj.clone(),
                    ray_proto::policy::HostSuggestions {
                        allows: rules.allows.clone(),
                        denies: rules.denies.clone(),
                    },
                );
            }
            live
        };
        match ipc_firewall_suggest_set(net_name, to_publish).await {
            Ok(msg) => println!("{}   {msg}", style::faint("→")),
            Err(e) => eprintln!("{}   suggest failed: {e}", style::red("  !")),
        }

        // Reconcile this network's concrete hostnames against both the
        // coordinator roster and each online managed machine's own state.
        let current: HashSet<ipc::MachineHostname> = joined_hostnames(&status_networks, net_name)
            .into_iter()
            .map(|hostname| hostname.parse())
            .collect::<std::result::Result<_, _>>()?;
        let status_network = status_networks
            .iter()
            .find(|network| network.name == *net_name);
        let membership = membership_diff_for_apply(
            net_firewall,
            &current,
            status_network,
            &managed_machines,
            net_name,
        )?;

        let mut active_hosts = current.clone();
        for host in membership.joins {
            if let Some(managed_machine) =
                managed_machine_for_hostname(status_network, &host, &managed_machines)
            {
                let machine = managed_machine.identity.into();
                let network = ipc::NetworkName::new(net_name.clone());
                match ipc_delegated_join_request(&machine, &network, Some(host.clone()), true, true)
                    .await
                {
                    Ok(message) => {
                        active_hosts.insert(host.clone());
                        println!("{}  {message}", style::faint("managed:"));
                    }
                    Err(error) => {
                        eprintln!(
                            "{}  {net_name}: failed to join managed machine '{host}': {error}",
                            style::red("  !")
                        );
                        missing_hosts.push((net_name.clone(), host.to_string()));
                    }
                }
            } else {
                missing_hosts.push((net_name.clone(), host.to_string()));
            }
        }

        for host in membership.leaves {
            active_hosts.remove(&host);
            let is_local = status_network.and_then(|network| network.my_hostname.as_deref())
                == Some(host.as_ref());
            if is_local {
                continue;
            }
            if let Some(managed_machine) =
                managed_machine_for_hostname(status_network, &host, &managed_machines)
            {
                let machine = managed_machine.identity.into();
                let network = ipc::NetworkName::new(net_name.clone());
                match ipc_delegated_leave_request(&machine, &network).await {
                    Ok(message) => println!("{}  {message}", style::faint("managed:")),
                    Err(error) => {
                        removal_failures = true;
                        eprintln!(
                            "{}  {net_name}: failed to remove managed machine '{host}': {error}",
                            style::red("  !")
                        );
                    }
                }
            } else {
                let peer = status_network.and_then(|network| {
                    network
                        .peers
                        .iter()
                        .find(|peer| peer.hostname.as_deref() == Some(host.as_ref()))
                });
                if let Some(peer) = peer {
                    match ipc_request(ipc::IpcMessage::Kick {
                        network: net_name.clone(),
                        peer: peer.endpoint_id.to_string(),
                        confirm: true,
                    })
                    .await
                    {
                        Ok(ipc::IpcMessage::Ok { message }) => {
                            println!("{}  {message}", style::faint("kicked:"));
                        }
                        Ok(ipc::IpcMessage::Error { message }) => {
                            removal_failures = true;
                            eprintln!(
                                "{}  {net_name}: failed to kick '{host}': {message}",
                                style::red("  !")
                            );
                        }
                        Ok(other) => {
                            removal_failures = true;
                            eprintln!(
                                "{}  {net_name}: unexpected kick response for '{host}': {other:?}",
                                style::red("  !")
                            );
                        }
                        Err(error) => {
                            removal_failures = true;
                            eprintln!(
                                "{}  {net_name}: failed to kick '{host}': {error}",
                                style::red("  !")
                            );
                        }
                    }
                } else {
                    removal_failures = true;
                    eprintln!(
                        "{}  {net_name}: host '{host}' is not in the roster and is not controlled",
                        style::red("  !")
                    );
                }
            }
        }

        for host in active_hosts {
            // SSH apply manages remote machines, not the local controller.
            if status_network.and_then(|network| network.my_hostname.as_deref())
                == Some(host.as_ref())
            {
                continue;
            }
            let grants = apply::ssh_grants_for_host(net_firewall, host.as_ref());
            let Some(machine) =
                managed_machine_for_hostname(status_network, &host, &managed_machines)
            else {
                if !grants.is_empty() {
                    ssh_failures = true;
                    eprintln!(
                        "{}  {net_name}: SSH grants for '{host}' need a controlled machine",
                        style::red("  !")
                    );
                }
                continue;
            };
            let has_grants = !grants.is_empty();
            let request = ipc::IpcMessage::DelegatedSshApply {
                machine: machine.identity,
                network: ipc::NetworkName::new(net_name.clone()),
                grants,
            };
            match ipc_request(request).await {
                Ok(ipc::IpcMessage::Ok { message }) => {
                    if has_grants {
                        println!("{}  {message}", style::faint("managed:"));
                    }
                }
                Ok(ipc::IpcMessage::Error { message }) => {
                    ssh_failures |= has_grants;
                    eprintln!(
                        "{}  {net_name}: SSH apply failed on '{host}': {message}",
                        style::red("  !")
                    );
                }
                Ok(other) => {
                    ssh_failures |= has_grants;
                    eprintln!(
                        "{}  {net_name}: unexpected SSH apply response for '{host}': {other:?}",
                        style::red("  !")
                    );
                }
                Err(error) => {
                    ssh_failures |= has_grants;
                    eprintln!(
                        "{}  {net_name}: SSH apply failed on '{host}': {error}",
                        style::red("  !")
                    );
                }
            }
        }
    }

    // B3, report the membership gap.
    if missing_hosts.is_empty() {
        if removal_failures {
            eprintln!(
                "{} some managed removals remain unresolved",
                style::red("  !")
            );
        } else {
            println!("{}", style::green("All expected hosts have joined."));
        }
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
    anyhow::ensure!(!removal_failures, "some members could not be removed");
    anyhow::ensure!(!ssh_failures, "some SSH grants could not be applied");
    Ok(())
}

fn managed_machine_for_hostname<'a>(
    network: Option<&ipc::NetworkStatus>,
    hostname: &ipc::MachineHostname,
    managed_machines: &'a [ipc::ManagedMachineInfo],
) -> Option<&'a ipc::ManagedMachineInfo> {
    if let Some(network) = network {
        if network.my_hostname.as_deref() == Some(hostname.as_ref()) {
            return None;
        }
        if let Some(peer) = network
            .peers
            .iter()
            .find(|peer| peer.hostname.as_deref() == Some(hostname.as_ref()))
        {
            return managed_machines
                .iter()
                .find(|machine| machine.identity == peer.endpoint_id);
        }
    }
    managed_machines
        .iter()
        .find(|machine| machine.hostname == *hostname)
}

fn managed_machine_has_network(machine: &ipc::ManagedMachineInfo, network: &str) -> bool {
    machine
        .networks
        .iter()
        .any(|active| active.as_ref() == network)
}

fn membership_diff_for_apply(
    firewall: &apply::DeployNetwork,
    current: &HashSet<ipc::MachineHostname>,
    status_network: Option<&ipc::NetworkStatus>,
    managed_machines: &[ipc::ManagedMachineInfo],
    network: &str,
) -> Result<apply::MembershipDiff> {
    let mut diff = apply::membership_diff(firewall, current)?;
    let desired: HashSet<ipc::MachineHostname> = apply::expected_hosts_for_network(firewall)
        .into_iter()
        .map(|hostname| hostname.parse())
        .collect::<std::result::Result<_, _>>()?;

    for machine in managed_machines
        .iter()
        .filter(|machine| machine.state == ipc::ManagedMachineState::Online)
    {
        let hostname = status_network
            .and_then(|status| {
                status
                    .peers
                    .iter()
                    .find(|peer| peer.endpoint_id == machine.identity)
                    .and_then(|peer| peer.hostname.as_deref())
            })
            .unwrap_or(machine.hostname.as_ref())
            .parse::<ipc::MachineHostname>()?;
        let active = managed_machine_has_network(machine, network);
        if desired.contains(&hostname) && !active && !diff.joins.contains(&hostname) {
            diff.joins.push(hostname);
        } else if !desired.contains(&hostname) && active && !diff.leaves.contains(&hostname) {
            diff.leaves.push(hostname);
        }
    }
    diff.joins.sort();
    diff.leaves.sort();
    Ok(diff)
}

async fn ipc_managed_machines_for_apply() -> Result<Vec<ipc::ManagedMachineInfo>> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::ManagedMachines { probe: true },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::ManagedMachinesResponse { machines } => Ok(machines),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected managed-machines response: {other:?}"),
    }
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

#[derive(Debug, serde::Serialize)]
struct HostIdentityMatch<'a> {
    network: &'a str,
    hostname: &'a str,
    identity: EndpointId,
    paired: bool,
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct IdentityMatchesOutput<'a, 'b> {
    json: serde_json::Value,
    #[serde(skip)]
    matches: &'a [HostIdentityMatch<'b>],
}

impl DisplayOut for IdentityMatchesOutput<'_, '_> {
    fn print_human(&self) {
        println!("{}", identity_matches_text(self.matches));
    }
}

/// Search joined hostnames, optionally restricted to one network.
fn host_identity_matches<'a>(
    networks: &'a [ipc::NetworkStatus],
    self_id: &EndpointId,
    hostname: &'a str,
    network: Option<&str>,
) -> Result<Vec<HostIdentityMatch<'a>>> {
    if let Some(network) = network
        && !networks.iter().any(|net| net.name == network)
    {
        anyhow::bail!("network '{network}' not found (is it active?)");
    }
    let mut matches: Vec<_> = networks
        .iter()
        .filter(|net| network.is_none_or(|name| net.name == name))
        .filter_map(|net| {
            let (identity, paired) = resolve_host_identity(net, self_id, hostname)?;
            Some(HostIdentityMatch {
                network: &net.name,
                hostname,
                identity,
                paired,
            })
        })
        .collect();
    if matches.is_empty() {
        if let Some(network) = network {
            anyhow::bail!("host '{hostname}' is not currently joined on '{network}'");
        }
        anyhow::bail!("host '{hostname}' is not currently joined on any network");
    }
    matches.sort_by(|a, b| a.network.cmp(b.network));
    Ok(matches)
}

fn identity_matches_text(matches: &[HostIdentityMatch<'_>]) -> String {
    let Some(first) = matches.first() else {
        return String::new();
    };
    if matches.iter().all(|m| m.identity == first.identity) {
        return first.identity.to_string();
    }
    let rows = matches
        .iter()
        .map(|m| {
            let identity = m.identity.to_string();
            vec![
                layout::Cell::new(m.network, style::value(m.network)),
                layout::Cell::new(m.hostname, style::value(m.hostname)),
                layout::Cell::new(identity.clone(), style::rose(&identity)),
            ]
        })
        .collect();
    table(&["network", "name", "identity"], rows, 2)
}

/// JSON retains each matching network, even when identities are equal.
fn identity_matches_json(matches: &[HostIdentityMatch<'_>]) -> serde_json::Value {
    if let [single] = matches {
        serde_json::json!(single)
    } else {
        serde_json::json!(matches)
    }
}

#[derive(serde::Serialize)]
struct ContactIdentityOutput {
    contact_id: EndpointId,
    endpoint_id: EndpointId,
}

impl DisplayOut for ContactIdentityOutput {
    fn print_human(&self) {
        println!("{}", self.endpoint_id);
    }
}

pub(crate) async fn cmd_identityof(peer: &str, hostname: Option<&str>) -> Result<()> {
    if hostname.is_none()
        && let Ok(contact_id) = peer.parse::<EndpointId>()
    {
        let mut stream = ipc::connect().await?;
        ipc::send(&mut stream, ipc::IpcMessage::ResolveContact { contact_id }).await?;
        return match ipc::recv(&mut stream).await? {
            ipc::IpcMessage::ContactResolved { endpoint_id } => printout(&ContactIdentityOutput {
                contact_id,
                endpoint_id,
            }),
            ipc::IpcMessage::Error { message } => anyhow::bail!("{message}"),
            other => anyhow::bail!("unexpected contact lookup response: {other:?}"),
        };
    }
    let (self_id, networks) = ipc_status_full().await?;
    let network = hostname.map(|_| peer);
    let matches = host_identity_matches(&networks, &self_id, hostname.unwrap_or(peer), network)?;
    printout(&IdentityMatchesOutput {
        json: identity_matches_json(&matches),
        matches: &matches,
    })
}

/// Resolve a joined hostname to `(identity, paired)` on one network: self matches
/// by device identity; a peer prefers its user identity when paired, else its
/// device endpoint id. Shared by `ray identityof` and `ray alias set`.
pub(crate) fn resolve_host_identity(
    net: &ipc::NetworkStatus,
    self_id: &EndpointId,
    hostname: &str,
) -> Option<(EndpointId, bool)> {
    if net.my_hostname.as_deref() == Some(hostname) {
        Some((*self_id, false))
    } else {
        net.peers
            .iter()
            .find(|p| p.hostname.as_deref() == Some(hostname))
            .map(|p| match p.user_identity {
                Some(u) => (u, true),
                None => (p.endpoint_id, false),
            })
    }
}

/// Fetch live status: this node's own device identity
/// plus every network's roster. The identity is needed to resolve an alias that
/// names the coordinator itself.
pub(crate) async fn ipc_status_full() -> Result<(EndpointId, Vec<ipc::NetworkStatus>)> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Status).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::StatusResponse {
            endpoint_id,
            networks,
            ..
        } => Ok((endpoint_id, networks)),
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
                    "alias '{name}' has an invalid identity '{id}' (copy it from `ray identityof <host>`)"
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

    /// `IpcMessage` has no `PartialEq` (it carries wire types that don't want
    /// one), so compare the settings-key mapping as a tuple.
    fn config_set_of(action: FirewallAction) -> (NodeKey, String) {
        match to_ipc(action).unwrap() {
            ipc::IpcMessage::ConfigSet {
                key,
                value,
                replace,
            } => {
                assert!(!replace, "a toggle never replaces a list");
                (key, value)
            }
            other => panic!("expected ConfigSet, got {other:?}"),
        }
    }

    /// The single-value toggles must land on settings keys, not on bespoke IPC
    /// variants, and must pass the user's word through unparsed so the daemon's
    /// registry is the only place that decides what `on` means.
    #[test]
    fn firewall_subcommands_map_onto_the_settings_keys() {
        assert_eq!(
            config_set_of(FirewallAction::Off),
            (NodeKey::Firewall(FirewallKey::Enabled), "off".to_string())
        );
        assert_eq!(
            config_set_of(FirewallAction::On),
            (NodeKey::Firewall(FirewallKey::Enabled), "on".to_string())
        );
        assert_eq!(
            config_set_of(FirewallAction::Default {
                action: "deny".into()
            }),
            (
                NodeKey::Firewall(FirewallKey::DefaultIn),
                "deny".to_string()
            )
        );
        assert_eq!(
            config_set_of(FirewallAction::Reject { state: "on".into() }),
            (NodeKey::Firewall(FirewallKey::Reject), "on".to_string())
        );

        // Auto-accept is per-network, so it takes the network-scoped variant.
        match to_ipc(FirewallAction::AutoAccept {
            network: "gaming".into(),
            state: "off".into(),
        })
        .unwrap()
        {
            ipc::IpcMessage::NetConfigSet {
                network,
                key,
                value,
            } => {
                assert_eq!(network, "gaming");
                assert_eq!(key, NetworkKey::AutoAcceptFirewall);
                assert_eq!(value, "off");
            }
            other => panic!("expected NetConfigSet, got {other:?}"),
        }
    }

    /// A bad toggle word must still fail the command (exit 1, not a printed
    /// daemon error and exit 0) and must fail with the wording these commands
    /// have always used, which is not the settings registry's wording.
    #[test]
    fn a_bad_toggle_word_fails_with_the_original_message() {
        let err = to_ipc(FirewallAction::Reject {
            state: "maybe".into(),
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "expected `on` or `off`, got 'maybe'");

        let err = to_ipc(FirewallAction::AutoAccept {
            network: "gaming".into(),
            state: "maybe".into(),
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "expected `on` or `off`, got 'maybe'");

        // `firewall default` parses an allow/deny word, with its own message.
        let err = to_ipc(FirewallAction::Default {
            action: "maybe".into(),
        })
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid action 'maybe' (expected 'allow' or 'deny')"
        );
    }

    /// `ray firewall ssh on|off` must go through the `ssh` key, which is the
    /// only path that also seeds the configured port's passthrough and starts the listener.
    #[test]
    fn ssh_toggle_maps_onto_the_ssh_key() {
        for (action, want) in [(SshAction::On, "on"), (SshAction::Off, "off")] {
            match ssh_to_ipc(action) {
                ipc::IpcMessage::ConfigSet { key, value, .. } => {
                    assert_eq!(key, NodeKey::Global(GlobalKey::Ssh));
                    assert_eq!(value, want);
                }
                other => panic!("expected ConfigSet, got {other:?}"),
            }
        }
    }

    fn peer(hostname: &str, user: Option<iroh::EndpointId>) -> ipc::PeerStatus {
        ipc::PeerStatus {
            endpoint_id: iroh::SecretKey::generate().public(),
            ipv6: "200::2".parse().unwrap(),
            hostname: Some(hostname.to_string()),
            user_identity: user,
            is_own_device: false,
            incompatible: false,
            connection: None,
            rtt_high: false,
            state: ipc::PeerState::Idle,
            exit_node: false,
            exit_in_use: false,
            is_coordinator: false,
        }
    }

    fn net(my_hostname: Option<&str>, peers: Vec<ipc::PeerStatus>) -> ipc::NetworkStatus {
        ipc::NetworkStatus {
            name: "n".to_string(),
            role: ipc::NetworkRole::Member,
            mode: None,
            my_ipv6: "200::1".parse().unwrap(),
            my_hostname: my_hostname.map(|s| s.to_string()),
            network_key: None,
            member_count: 0,
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

    #[test]
    fn firewall_peer_names_respect_network_scope_and_shared_users() {
        let self_id = iroh::SecretKey::generate().public();
        let user_id = iroh::SecretKey::generate().public();
        let first = peer("build-box", Some(user_id));
        let mut other = first.clone();
        other.hostname = Some("other-name".into());
        let mut other_network = net(None, vec![other]);
        other_network.name = "other-network".into();
        let networks = [
            net(
                Some("coordinator"),
                vec![first.clone(), peer("gpu-box", Some(user_id))],
            ),
            other_network,
        ];
        let mut rule = ipc::FirewallRuleView {
            direction: firewall::Direction::In,
            action: firewall::Action::Allow,
            protocol: firewall::Protocol::Any,
            port: "*".into(),
            peer: first.endpoint_id.fmt_short().to_string(),
            network: "n".into(),
            suggested_by: None,
        };
        assert_eq!(firewall_peer_name(&rule, &self_id, &networks), "build-box");
        rule.network = "other-network".into();
        assert_eq!(firewall_peer_name(&rule, &self_id, &networks), "other-name");
        rule.network = "missing-network".into();
        assert_eq!(firewall_peer_name(&rule, &self_id, &networks), rule.peer);
        rule.network = "n".into();
        rule.peer = user_id.fmt_short().to_string();
        assert_eq!(
            firewall_peer_name(&rule, &self_id, &networks),
            "build-box, gpu-box"
        );
        rule.peer = self_id.fmt_short().to_string();
        assert_eq!(
            firewall_peer_name(&rule, &self_id, &networks),
            "coordinator"
        );
        for peer in ["any", "any except build-box", "unknown-id"] {
            rule.peer = peer.into();
            assert_eq!(firewall_peer_name(&rule, &self_id, &networks), peer);
        }
    }

    #[test]
    fn resolve_self_hostname_returns_self_id() {
        let n = net(Some("me"), vec![]);
        let self_id = iroh::SecretKey::generate().public();
        let got = resolve_host_identity(&n, &self_id, "me");
        assert_eq!(got, Some((self_id, false)));
    }

    #[test]
    fn resolve_paired_peer_prefers_user_identity() {
        let user = iroh::SecretKey::generate().public();
        let n = net(Some("me"), vec![peer("alice", Some(user))]);
        let got = resolve_host_identity(&n, &iroh::SecretKey::generate().public(), "alice");
        assert_eq!(got, Some((user, true)));
    }

    #[test]
    fn resolve_unpaired_peer_uses_endpoint_id() {
        let p = peer("bob", None);
        let want = p.endpoint_id;
        let n = net(Some("me"), vec![p]);
        let got = resolve_host_identity(&n, &iroh::SecretKey::generate().public(), "bob");
        assert_eq!(got, Some((want, false)));
    }

    #[test]
    fn resolve_unknown_hostname_is_none() {
        let n = net(Some("me"), vec![peer("alice", None)]);
        assert_eq!(
            resolve_host_identity(&n, &iroh::SecretKey::generate().public(), "ghost"),
            None
        );
    }

    #[test]
    fn identityof_lists_conflicting_names_with_full_identities() {
        let self_id = iroh::SecretKey::generate().public();
        let remote = peer("build-box", None);
        let remote_id = remote.endpoint_id;
        let mut first = net(None, vec![remote]);
        first.name = "network-b".into();
        let mut second = net(Some("build-box"), vec![]);
        second.name = "network-a".into();
        let networks = [first, second];
        let matches = host_identity_matches(&networks, &self_id, "build-box", None).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].network, "network-a");
        assert_eq!(matches[0].identity, self_id);
        assert_eq!(matches[1].identity, remote_id);
        let output = identity_matches_text(&matches);
        for value in [
            "network",
            "name",
            "identity",
            "network-a",
            "network-b",
            "build-box",
        ] {
            assert!(output.contains(value), "missing {value}: {output}");
        }
        assert!(output.contains(&self_id.to_string()));
        assert!(output.contains(&remote_id.to_string()));
        let json = identity_matches_json(&matches);
        assert_eq!(json.as_array().unwrap().len(), 2);
        assert_eq!(json[0]["network"], "network-a");
        assert_eq!(json[1]["identity"], remote_id.to_string());

        let scoped =
            host_identity_matches(&networks, &self_id, "build-box", Some("network-b")).unwrap();
        assert_eq!(identity_matches_text(&scoped), remote_id.to_string());
        let json = identity_matches_json(&scoped);
        assert_eq!(json["network"], "network-b");
        assert_eq!(json["hostname"], "build-box");
        assert_eq!(json["identity"], remote_id.to_string());
        assert_eq!(json["paired"], false);
    }

    #[test]
    fn identityof_prints_shared_user_identity_once_across_networks() {
        let user = iroh::SecretKey::generate().public();
        let mut first = net(None, vec![peer("build-box", Some(user))]);
        first.name = "network-a".into();
        let mut second = net(None, vec![peer("build-box", Some(user))]);
        second.name = "network-b".into();
        let networks = [first, second];
        let matches = host_identity_matches(&networks, &user, "build-box", None).unwrap();
        assert_eq!(identity_matches_text(&matches), user.to_string());
        let json = identity_matches_json(&matches);
        assert_eq!(json.as_array().unwrap().len(), 2);
        assert_eq!(json[0]["paired"], true);
        assert_eq!(json[1]["identity"], user.to_string());
    }

    #[test]
    fn identityof_reports_missing_hosts_and_networks() {
        let self_id = iroh::SecretKey::generate().public();
        let networks = [net(None, vec![peer("build-box", None)])];
        for networks in [&networks[..], &[]] {
            let error =
                host_identity_matches(networks, &self_id, "missing-host", None).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("not currently joined on any network")
            );
        }
        let error =
            host_identity_matches(&networks, &self_id, "build-box", Some("missing-network"))
                .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("network 'missing-network' not found")
        );
        let error =
            host_identity_matches(&networks, &self_id, "missing-host", Some("n")).unwrap_err();
        assert!(error.to_string().contains("not currently joined on 'n'"));
    }

    #[test]
    fn managed_machine_matches_network_hostname_by_endpoint_identity() {
        let identity = iroh::SecretKey::generate().public();
        let unrelated_identity = iroh::SecretKey::generate().public();
        let mut roster_peer = peer("web", None);
        roster_peer.endpoint_id = identity;
        let network = net(Some("controller"), vec![roster_peer]);
        let machines = vec![
            ipc::ManagedMachineInfo {
                identity: unrelated_identity,
                hostname: "web".parse().unwrap(),
                enrolled_at: ipc::UnixTimestampSecs::from_secs(100),
                last_seen: None,
                state: ipc::ManagedMachineState::Unknown,
                networks: Vec::new(),
            },
            ipc::ManagedMachineInfo {
                identity,
                hostname: "build-box".parse().unwrap(),
                enrolled_at: ipc::UnixTimestampSecs::from_secs(100),
                last_seen: None,
                state: ipc::ManagedMachineState::Unknown,
                networks: Vec::new(),
            },
        ];
        let hostname = "web".parse().unwrap();

        let machine = managed_machine_for_hostname(Some(&network), &hostname, &machines).unwrap();

        assert_eq!(machine.identity, identity);
        assert_eq!(machine.hostname.as_ref(), "build-box");
        assert!(managed_machine_for_hostname(Some(&network), &hostname, &machines[..1]).is_none());
    }

    #[test]
    fn online_managed_machine_missing_network_is_rejoined() {
        let identity = iroh::SecretKey::generate().public();
        let mut roster_peer = peer("web", None);
        roster_peer.endpoint_id = identity;
        let network = net(Some("controller"), vec![roster_peer]);
        let machine = ipc::ManagedMachineInfo {
            identity,
            hostname: "web".parse().unwrap(),
            enrolled_at: ipc::UnixTimestampSecs::from_secs(100),
            last_seen: None,
            state: ipc::ManagedMachineState::Online,
            networks: vec![ipc::NetworkName::new("other".to_string())],
        };
        let host: ipc::MachineHostname = "web".parse().unwrap();
        let current = HashSet::from([host.clone()]);
        let firewall = [("web".to_string(), apply::DeployHost::default())]
            .into_iter()
            .collect();

        let membership =
            membership_diff_for_apply(&firewall, &current, Some(&network), &[machine], "n")
                .unwrap();

        assert_eq!(membership.joins, vec![host]);
    }

    #[test]
    fn online_managed_machine_outside_spec_is_removed() {
        let machine = ipc::ManagedMachineInfo {
            identity: iroh::SecretKey::generate().public(),
            hostname: "web".parse().unwrap(),
            enrolled_at: ipc::UnixTimestampSecs::from_secs(100),
            last_seen: None,
            state: ipc::ManagedMachineState::Online,
            networks: vec![ipc::NetworkName::new("n".to_string())],
        };
        let host: ipc::MachineHostname = "web".parse().unwrap();
        let current = HashSet::new();
        let firewall = apply::DeployNetwork::new();

        let membership =
            membership_diff_for_apply(&firewall, &current, None, &[machine], "n").unwrap();

        assert_eq!(membership.leaves, vec![host]);
    }
}
