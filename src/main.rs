// The daemon's modules live in the `rayfish` library crate (`src/lib.rs`) so
// integration tests and benchmarks can reach them; this binary is the CLI/IPC
// client built on top.
use rayfish::term::{layout, picker, progress, style};
use rayfish::{
    DNS_DOMAIN, apply, config, daemon, firewall, hostname, invite, ipc, logdir, membership,
    onepassword, shutdown, stats,
};

use std::collections::BTreeMap;
use std::fmt::Display;
use std::sync::{Arc, atomic};

use anyhow::{Context, Result};
use clap::{FromArgMatches, Parser, Subcommand};
use iroh::EndpointId;
use ray_proto::settings::node_key_help;
#[cfg(target_os = "linux")]
use rayfish::rootless::{Expose, LocalForward, Options as RootlessOptions};
#[cfg(target_os = "linux")]
use std::net::SocketAddr;

use membership::GroupMode;

// The clap definitions, process setup and command handlers live in the `cli`
// module (`src/cli/`), which keeps this file to dispatch. `cli` re-exports each domain
// submodule's contents, and `use cli::*` flattens them into the crate root so
// every handler resolves the others (and the shared helpers here) by name.
mod cli;
use cli::*;

static JSON_FLAG: atomic::AtomicBool = atomic::AtomicBool::new(false);

/// Whether `--json` output mode is active (set once in `main`).
fn json_enabled() -> bool {
    JSON_FLAG.load(atomic::Ordering::Relaxed)
}

/// Print a CLI result in the format selected by `--json`.
trait DisplayOut: serde::Serialize {
    fn print_human(&self);
}

impl<T: serde::Serialize + Display> DisplayOut for T {
    fn print_human(&self) {
        print!("{self}");
    }
}

fn printout<T: DisplayOut>(data: &T) -> Result<()> {
    if json_enabled() {
        println!("{}", serde_json::to_value(data)?);
    } else {
        data.print_human();
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct PendingRequestOutput<'a> {
    id: &'a str,
    hostname: Option<&'a str>,
    waiting_secs: u64,
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct PendingRequestsOutput<'a> {
    requests: Vec<PendingRequestOutput<'a>>,
    #[serde(skip)]
    empty_message: &'a str,
    #[serde(skip)]
    footer: &'a str,
}

impl DisplayOut for PendingRequestsOutput<'_> {
    fn print_human(&self) {
        if self.requests.is_empty() {
            println!("\n  {}\n", style::faint(self.empty_message));
            return;
        }
        let rows = self
            .requests
            .iter()
            .map(|request| {
                let host = request.hostname.unwrap_or("—");
                let wait = format!("{}s", request.waiting_secs);
                vec![
                    layout::Cell::new(request.id, style::rose(request.id)),
                    layout::Cell::new(host, style::value(host)),
                    layout::Cell::right(wait.clone(), style::faint(&wait)),
                ]
            })
            .collect();
        println!();
        print!("{}", table(&["id", "host", "waiting"], rows, 2));
        println!("\n  {}", style::faint(self.footer));
    }
}

/// Render pending requests in JSON or the shared connection table.
fn print_pending_requests(
    requests: &[ipc::PendingRequestInfo],
    empty_message: &str,
    footer: &str,
) -> Result<()> {
    let output = PendingRequestsOutput {
        requests: requests
            .iter()
            .map(|request| PendingRequestOutput {
                id: &request.short_id,
                hostname: request.hostname.as_deref(),
                waiting_secs: request.waiting_secs,
            })
            .collect(),
        empty_message,
        footer,
    };
    printout(&output)
}

/// Whether the parsed command carried `--json`.
///
/// `--json` used to be a `global = true` flag on `Cli`, which meant every one of
/// the 44 commands accepted it and the 30-odd that render no JSON ignored it in
/// silence (`ray version --json` printed the same plain text). It is now declared
/// only on the commands that honour it, so the parser rejects it elsewhere. This
/// funnels those per-command flags into the one `JSON_FLAG` read by `printout`
/// and the interactive firewall pending command.
fn json_requested(command: &Command) -> bool {
    match command {
        Command::Status { json, .. }
        | Command::Blocked { json }
        | Command::Invite { json, .. }
        | Command::Invitations { json, .. }
        | Command::Requests { json, .. }
        | Command::Connect { json, .. }
        | Command::Connections { json, .. }
        | Command::Ping { json, .. }
        | Command::Netcheck { json }
        | Command::Admin { json, .. }
        | Command::Firewall { json, .. }
        | Command::Ssh { json, .. }
        | Command::ExitNode { json, .. }
        | Command::Mdns { json, .. }
        | Command::Dns { json, .. }
        | Command::Files { json, .. }
        | Command::Pair { json, .. }
        | Command::Machines { json, .. }
        | Command::Controller { json, .. }
        | Command::Identityof { json, .. }
        | Command::Alias { json, .. }
        | Command::Config { json, .. } => *json,
        _ => false,
    }
}

fn main() -> Result<()> {
    // Before anything else: before stdout is touched, before the arguments are
    // parsed (a completion request is not a command line this parser accepts),
    // and outside the runtime, since the completers build one of their own.
    complete::intercept();
    run()
}

#[tokio::main]
async fn run() -> Result<()> {
    // Not `Cli::parse()`: the command list in `-h` is grouped, which clap cannot
    // express on subcommands, so the parser comes from `cli::help` with a
    // template that renders the grouping in place of clap's flat list.
    let cli =
        Cli::from_arg_matches(&cli::help::command().get_matches()).unwrap_or_else(|e| e.exit());
    #[cfg(target_os = "linux")]
    {
        let system_operation = matches!(
            cli.command,
            Command::Daemon { .. }
                | Command::Start
                | Command::Restart
                | Command::Install { .. }
                | Command::Uninstall
                | Command::SetOperator { .. }
                | Command::Update { .. }
        );
        let rootless_daemon = matches!(cli.command, Command::Rootless { .. });
        anyhow::ensure!(
            !cli.system || !rootless_daemon,
            "ray rootless cannot use --system"
        );
        if cli.rootless || rootless_daemon {
            anyhow::ensure!(
                !system_operation,
                "rootless instances run in the foreground with ray rootless; system service operations are unavailable"
            );
            rayfish::instance::select_rootless()?;
        } else if !cli.system && !system_operation {
            rayfish::instance::detect_rootless().await?;
        }
    }
    if json_requested(&cli.command) {
        JSON_FLAG.store(true, atomic::Ordering::Relaxed);
        // JSON output must never be colorized or interrupted by spinners.
        style::set_plain(true);
    }
    #[cfg(all(target_os = "macos", feature = "macos-app"))]
    if matches!(cli.command, Command::AppSshHelper) {
        use tracing_oslog::OsLogger;
        use tracing_subscriber::prelude::*;
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("info,rayfish=debug"))
            .with(OsLogger::new(rayfish::macos_logs::SUBSYSTEM, "ssh-helper"))
            .init();
        return rayfish::ssh::app_helper::run().await;
    }
    // Keep the appender guard alive for the whole process so file logs flush.
    #[cfg(target_os = "linux")]
    let rootless_daemon = matches!(cli.command, Command::Rootless { .. });
    #[cfg(not(target_os = "linux"))]
    let rootless_daemon = false;
    #[cfg(target_os = "linux")]
    if rootless_daemon && let Some(instance) = rayfish::instance::user_instance() {
        for directory in [
            &instance.directory,
            &instance.runtime,
            &rayfish::logdir::log_dir(),
        ] {
            rayfish::instance::ensure_private_dir(directory, instance.owner_uid)?;
        }
    }
    let _log_guard = init_tracing(matches!(cli.command, Command::Daemon { .. }) || rootless_daemon);

    match cli.command {
        Command::Leave { name, delegate } => match delegate {
            Some(machine) => {
                let network = ipc::NetworkName::new(name);
                ipc_delegated_leave(&machine, &network).await
            }
            None => ipc_leave(&name).await,
        },
        Command::Create {
            open,
            closed: _,
            name,
            hostname,
            tor,
        } => {
            let mode = if open {
                GroupMode::Open
            } else {
                GroupMode::Restricted
            };
            ipc_create(mode, name, hostname, tor).await
        }
        Command::Join {
            network_key,
            name,
            hostname,
            tor,
            auto_accept_firewall,
            no_auto_accept_files,
            delegate,
        } => match delegate {
            Some(machine) => {
                if tor || name.is_some() {
                    anyhow::bail!("--delegate does not support --tor or --name")
                }
                let network = ipc::NetworkName::new(network_key);
                let hostname = hostname.map(|value| value.parse()).transpose()?;
                ipc_delegated_join(
                    &machine,
                    &network,
                    hostname,
                    auto_accept_firewall,
                    !no_auto_accept_files,
                )
                .await
            }
            None => {
                ipc_join(
                    &network_key,
                    name.as_deref(),
                    hostname,
                    tor,
                    auto_accept_firewall,
                    !no_auto_accept_files,
                )
                .await
            }
        },
        Command::Nuke { name, force } => ipc_nuke(&name, force).await,
        Command::Kick { network, peer, yes } => ipc_kick(&network, &peer, yes).await,
        Command::Ephemeral { network, arg } => ipc_ephemeral(&network, &arg).await,
        Command::Status {
            machines, with_ips, ..
        } => ipc_status(machines, with_ips).await,
        Command::Report => ipc_report().await,
        Command::Logs { since, follow } => ipc_logs(since, follow).await,
        #[cfg(target_os = "linux")]
        Command::Rootless {
            socks5,
            http,
            forward,
            expose,
        } => {
            install_panic_hook();
            daemon::run_rootless(
                RootlessOptions {
                    socks5,
                    http,
                    forwards: forward,
                    expose,
                },
                shutdown::token(),
            )
            .await
        }
        Command::Daemon { cleanup: true } => {
            check_root();
            cmd_daemon_cleanup()
        }
        Command::Daemon { cleanup: false } => {
            check_root();
            install_panic_hook();
            #[cfg(windows)]
            if rayfish::windows_service::run_if_service()? {
                return Ok(());
            }
            let token = shutdown::token();
            let stats = Arc::new(stats::ForwardMetrics::default());
            stats.spawn_logger(token.clone());
            daemon::run_daemon(token, stats).await
        }
        #[cfg(all(target_os = "macos", feature = "macos-app"))]
        Command::AppSshHelper => rayfish::ssh::app_helper::run().await,
        Command::Up {
            hostname,
            enable_ssh,
            settings,
            controller,
        } => cmd_up(hostname, controller, enable_ssh, settings).await,
        Command::Down => ipc_down().await,
        Command::Stop => cmd_stop().await,
        Command::Start => cmd_start().await,
        Command::Uninstall => cmd_uninstall_service(),
        Command::Install { auto_update } => cmd_install(auto_update).await,
        Command::Restart => cmd_restart().await,
        Command::Completions { shell, install } => complete::cmd_completions(shell, install),
        #[cfg(not(all(target_os = "macos", feature = "macos-app")))]
        Command::Gui { port, no_open } => cmd_gui(port, no_open),
        Command::Invite {
            network,
            action,
            json: _,
        } => ipc_invite(&network, action).await,
        Command::Invitations { action, json: _ } => ipc_invitations(action).await,
        Command::Requests {
            network,
            action,
            json: _,
        } => match action {
            None => ipc_requests(&network).await,
            Some(RequestsAction::Accept { id }) => ipc_accept_request(&network, &id).await,
            Some(RequestsAction::Deny { id }) => ipc_deny_request(&network, &id).await,
        },
        Command::Accept { network, id } => ipc_accept_request(&network, &id).await,
        Command::Deny { network, id } => ipc_deny_request(&network, &id).await,
        // An action is a request-queue verb, a bare identity dials that peer,
        // and with neither, show the queue, the same as `ray connections` did.
        // The two together parse (the positional fills, then the subcommand
        // does) and mean nothing, so they are rejected rather than served by
        // dropping one.
        Command::Connect {
            action,
            peer,
            hostname,
            json: _,
        } => match (action, peer) {
            (None, Some(id)) => ipc_connect(&id, hostname).await,
            (None, None) => ipc_connections(None).await,
            (Some(action), None) => ipc_connections(Some(action)).await,
            (Some(_), Some(id)) => {
                anyhow::bail!("`ray connect {id}` dials that peer; it takes no subcommand")
            }
        },
        Command::Connections { action, json: _ } => ipc_connections(action).await,
        Command::Block { peer } => ipc_block(&peer).await,
        Command::Unblock { peer } => ipc_unblock(&peer).await,
        Command::Blocked { json: _ } => ipc_blocked().await,
        Command::Ping {
            peer,
            count,
            interval,
            json: _,
        } => ipc_ping(&peer, count, interval).await,
        Command::Netcheck { json: _ } => ipc_netcheck().await,
        Command::Admin {
            network,
            action,
            json: _,
        } => ipc_admin(&network, action).await,
        Command::Firewall { action, json: _ } => ipc_firewall(action).await,
        Command::Ssh { action, json: _ } => ipc_firewall_ssh(action).await,
        Command::ExitNode { action, json: _ } => ipc_exit_node(action).await,
        Command::Apply {
            spec,
            prune,
            dry_run,
            invite_missing,
            example,
        } => ipc_apply(spec, prune, dry_run, invite_missing, example).await,
        Command::Hostname { network, name } => ipc_set_hostname(&network, &name).await,
        Command::Rename { network, new_name } => ipc_rename(&network, &new_name).await,
        Command::Identityof { peer, hostname, .. } => {
            cmd_identityof(&peer, hostname.as_deref()).await
        }
        Command::Alias {
            network, action, ..
        } => cmd_alias(&network, action).await,
        Command::Mdns { action, json: _ } => cmd_mdns(action).await,
        Command::Dns { action, json: _ } => cmd_dns(action).await,
        Command::AutoUpdate { state } => cmd_auto_update(&state).await,
        Command::Config { action, .. } => cmd_config(action).await,
        #[cfg(not(all(target_os = "macos", feature = "macos-app")))]
        Command::SetOperator { user } => cmd_set_operator(&user).await,
        Command::Send { peer, files } => ipc_send_files(&files, &peer).await,
        Command::Files { action, json: _ } => ipc_files(action).await,
        Command::Pair {
            action,
            ticket,
            json: _,
        } => cmd_pair(action, ticket).await,
        Command::Unpair { device } => ipc_unpair(&device).await,
        Command::Machines { action, json: _ } => ipc_machines(action).await,
        Command::Controller { action, json: _ } => ipc_controller(action).await,
        Command::Open { uri } => cmd_open(&uri).await,
        Command::Version => {
            println!("ray {FULL_VERSION}");
            Ok(())
        }
        Command::Update {
            force,
            check,
            nightly,
            list,
            version,
        } => cmd_update(force, check, nightly, list, version).await,
        #[cfg(windows)]
        Command::WindowsUpdateHelper {
            msi,
            identity,
            sha256,
            parent_pid,
        } => rayfish::update::run_msi_update_helper(&msi, &identity, &sha256, parent_pid).await,
    }
}

// ---------------------------------------------------------------------------
// Config-writing commands
//
// These change global daemon settings (`settings.toml`). They route through the
// daemon rather than writing the file client-side: on non-Linux, `config_dir()`
// is derived from the process environment, so a CLI writing from a different
// `HOME` than the service runs under would land the file where the daemon never
// reads it (rayfish#94). The daemon writes its own config dir, sidestepping the
// divergence. This makes a running daemon a prerequisite.
// ---------------------------------------------------------------------------

/// Send a mutating IPC request and print its `Ok`/`Error` reply.
pub(crate) async fn ipc_mutate(msg: ipc::IpcMessage) -> Result<()> {
    print_ok_reply(ipc_request(msg).await?)
}

/// `ray mdns on|off|scan`. The two toggles are the `mdns` settings key under
/// another name; `scan` is a read and goes its own way.
async fn cmd_mdns(action: MdnsAction) -> Result<()> {
    if matches!(action, MdnsAction::Scan) {
        return ipc_lan_peers().await;
    }
    ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: ipc::NodeKey::Global(ipc::GlobalKey::Mdns),
        value: action.to_string(),
        replace: false,
    })
    .await
}

/// `ray dns on|off`: apply or remove Magic DNS without changing the data plane.
async fn cmd_dns(action: DnsAction) -> Result<()> {
    ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: ipc::NodeKey::Global(ipc::GlobalKey::Dns),
        value: action.to_string(),
        replace: false,
    })
    .await
}

/// `ray auto-update on|off`: back-compat alias for `ray config set auto-update
/// <on|off>`. The daemon persists it and reads it at startup, so the change
/// takes effect on the next daemon restart.
async fn cmd_auto_update(state: &str) -> Result<()> {
    ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: ipc::NodeKey::Global(ipc::GlobalKey::AutoUpdate),
        value: state.to_string(),
        replace: false,
    })
    .await
}

/// `ray config get/set/unset`: view or change global daemon settings via the
/// daemon (see the module note above on why writes are not client-side). Changes
/// to relay/discovery/dns-upstreams all take effect on the next daemon restart.
#[derive(serde::Serialize)]
#[serde(transparent)]
struct ConfigOutput<'a> {
    values: BTreeMap<&'a str, &'a str>,
    #[serde(skip)]
    rows: &'a [(String, String)],
}

impl DisplayOut for ConfigOutput<'_> {
    fn print_human(&self) {
        for (key, value) in self.rows {
            println!("{key} = {value}");
        }
    }
}

async fn cmd_config(action: Option<ConfigAction>) -> Result<()> {
    match action.unwrap_or(ConfigAction::Get { key: None }) {
        ConfigAction::Get { key } => {
            // Before the connect, so a bad key reads the same whether or not the
            // daemon happens to be running (and the same as `set`/`unset`).
            let key = key.as_deref().map(parse_node_key);
            match ipc_request(ipc::IpcMessage::ConfigGet { key }).await? {
                ipc::IpcMessage::ConfigValues { rows } => {
                    let output = ConfigOutput {
                        values: rows
                            .iter()
                            .map(|(key, value)| (key.as_str(), value.as_str()))
                            .collect(),
                        rows: &rows,
                    };
                    printout(&output)?;
                }
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
            Ok(())
        }
        ConfigAction::Set {
            key,
            value,
            replace,
        } => {
            ipc_mutate(ipc::IpcMessage::ConfigSet {
                key: parse_node_key(&key),
                value,
                replace,
            })
            .await
        }
        ConfigAction::Unset { key } => {
            ipc_mutate(ipc::IpcMessage::ConfigUnset {
                key: parse_node_key(&key),
            })
            .await
        }
    }
}

/// Resolve a `ray config` key to the one the wire carries.
///
/// Reported here rather than by the daemon, with the registry's own wording:
/// the key type makes an unknown key unrepresentable on the wire, so without
/// this the request would fail to encode instead of explaining itself.
fn parse_node_key(key: &str) -> ipc::NodeKey {
    match key.parse() {
        Ok(k) => k,
        Err(e) => fail_with("error", &e),
    }
}

/// Resolve a username to its UID, falling back to parsing a numeric UID.
pub(crate) fn uid_for_user(user: &str) -> Option<u32> {
    #[cfg(windows)]
    return user.parse::<u32>().ok();
    #[cfg(unix)]
    {
        use std::{ffi::CString, mem::zeroed, ptr::null_mut};
        let cname = CString::new(user).ok()?;
        // getpwnam_r, not getpwnam, for the same reason rayfish_gid uses
        // getgrnam_r: the legacy call's answer lives in a process-wide buffer
        // that any other lookup is allowed to move or free mid-read, which
        // corrupts the heap on musl when callers run concurrently.
        let mut buf_len = 4096;
        loop {
            let mut buf = vec![0u8; buf_len];
            let mut pwbuf: libc::passwd = unsafe { zeroed() };
            let mut result: *mut libc::passwd = null_mut();
            let rc = unsafe {
                libc::getpwnam_r(
                    cname.as_ptr(),
                    &mut pwbuf,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == libc::ERANGE {
                buf_len *= 2;
                continue;
            }
            if rc == 0 && !result.is_null() {
                return Some(unsafe { (*result).pw_uid });
            }
            return user.parse::<u32>().ok();
        }
    }
}

/// `ray set-operator <user>`: authorize a local user to run mutating ray
/// commands without sudo (Tailscale's `--operator` model). The daemon enforces
/// that this call itself comes from root.
#[cfg(not(all(target_os = "macos", feature = "macos-app")))]
async fn cmd_set_operator(user: &str) -> Result<()> {
    // Windows writes the operator SID itself instead of asking the daemon. The
    // daemon has no Windows equivalent of the root check that authorizes
    // `SetOperator` over IPC, so the check that matters (an elevated
    // Administrator) happens here, in the process that has the caller's token.
    // This is the recovery path when the claim `ray up` makes goes to the wrong
    // account; the normal case never runs it.
    #[cfg(windows)]
    {
        let sid = rayfish::windows_service::set_operator_account(std::ffi::OsStr::new(user))?;
        println!("operator set to {user} ({sid})");
        Ok(())
    }
    #[cfg(unix)]
    {
        let uid = uid_for_user(user).ok_or_else(|| {
            anyhow::anyhow!("unknown user '{user}' (pass a valid username or UID)")
        })?;
        ipc_mutate(ipc::IpcMessage::SetOperator { uid }).await
    }
}

// ---------------------------------------------------------------------------
// IPC client commands (require daemon running)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::FirewallRuleView;
    use rayfish::update::{
        nightly_asset_name, normalize_version, release_asset_name, version_is_newer,
    };

    #[test]
    fn identityof_accepts_global_and_scoped_lookups() {
        for command in ["identityof", "whois"] {
            let cli = Cli::try_parse_from(["ray", command, "build-box"]).unwrap();
            assert!(matches!(
                cli.command,
                Command::Identityof { peer, hostname: None, json: false } if peer == "build-box"
            ));
            let cli =
                Cli::try_parse_from(["ray", command, "network-a", "build-box", "--json"]).unwrap();
            assert!(matches!(
                cli.command,
                Command::Identityof { peer, hostname: Some(hostname), json: true }
                    if peer == "network-a" && hostname == "build-box"
            ));
            let identity = iroh::SecretKey::from([7; 32]).public().to_string();
            let cli = Cli::try_parse_from(["ray", command, &identity, "--json"]).unwrap();
            assert!(matches!(
                cli.command,
                Command::Identityof { peer, hostname: None, json: true } if peer == identity
            ));
        }
        assert!(Cli::try_parse_from(["ray", "identityof"]).is_err());
    }

    #[test]
    fn file_auto_accept_supports_peers_and_legacy_network_toggle() {
        for operation in ["add", "remove"] {
            let cli = Cli::try_parse_from(["ray", "files", "auto-accept", operation, "build-box"])
                .unwrap();
            assert!(matches!(
                cli.command,
                Command::Files {
                    action: Some(FilesAction::AutoAccept {
                        action: Some(_),
                        ..
                    }),
                    ..
                }
            ));
        }
        for operation in ["list", "ls"] {
            assert!(Cli::try_parse_from(["ray", "files", "auto-accept", operation]).is_ok());
        }
        for state in ["on", "off"] {
            let cli =
                Cli::try_parse_from(["ray", "files", "auto-accept", "network-a", state]).unwrap();
            assert!(
                matches!(cli.command, Command::Files { action: Some(FilesAction::AutoAccept { action: None, network: Some(network), state: Some(_), }), .. } if network == "network-a")
            );
        }
        for args in [
            vec!["ray", "files", "auto-accept"],
            vec!["ray", "files", "auto-accept", "add"],
            vec!["ray", "files", "auto-accept", "network-a"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn status_ip_flags_are_opt_in_and_accept_both_spellings() {
        let cli = Cli::try_parse_from(["ray", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Status {
                with_ips: false,
                ..
            }
        ));
        for flag in ["--with-ips", "--ips"] {
            let cli = Cli::try_parse_from(["ray", "status", flag, "--machines", "--json"]).unwrap();
            assert!(matches!(
                cli.command,
                Command::Status {
                    with_ips: true,
                    machines: true,
                    json: true,
                }
            ));
        }
    }

    #[test]
    fn pair_backup_accepts_the_1password_flag_spellings() {
        for flag in ["--1p", "--1password", "--op"] {
            let cli = Cli::try_parse_from(["ray", "pair", "backup", flag]).unwrap();
            assert!(matches!(
                cli.command,
                Command::Pair {
                    action: Some(PairAction::Backup {
                        onepassword: true,
                        ..
                    }),
                    ..
                }
            ));
        }
    }

    #[test]
    fn delegated_network_commands_parse_machine_and_network_types() {
        let join =
            Cli::try_parse_from(["ray", "join", "--delegate", "build-box", "infra"]).unwrap();
        match join.command {
            Command::Join {
                network_key,
                delegate: Some(machine),
                ..
            } => {
                assert_eq!(network_key, "infra");
                assert_eq!(machine.as_ref(), "build-box");
            }
            _ => panic!("wrong command"),
        }

        let leave =
            Cli::try_parse_from(["ray", "leave", "--delegate", "build-box", "infra"]).unwrap();
        assert!(matches!(
            leave.command,
            Command::Leave {
                name,
                delegate: Some(machine),
            } if name == "infra" && machine.as_ref() == "build-box"
        ));
    }

    #[test]
    fn up_parses_controller_ticket() {
        let controller = iroh::EndpointAddr::from(iroh::SecretKey::generate().public());
        let expected = ipc::EnrollmentTicket::new(controller, [7; 32]);
        let encoded = expected.to_string();
        let cli = Cli::try_parse_from(["ray", "up", "--controller", encoded.as_str()]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Up {
                controller: Some(ticket),
                ..
            } if ticket == expected
        ));
    }

    #[test]
    fn up_settings_combine_with_controller_and_hostname() {
        let controller = iroh::EndpointAddr::from(iroh::SecretKey::generate().public());
        let ticket = ipc::EnrollmentTicket::new(controller, [7; 32]);
        let encoded = ticket.to_string();
        let cli = Cli::try_parse_from([
            "ray",
            "up",
            "--controller",
            &encoded,
            "--hostname",
            "build-box",
            "--enable",
            "v4-bridge",
            "--set",
            "dns=partial",
            "--enable",
            "firewall.reject",
            "--set",
            "dns=off",
        ])
        .unwrap();
        match cli.command {
            Command::Up {
                controller,
                hostname,
                settings,
                ..
            } => {
                assert_eq!(controller, Some(ticket));
                assert_eq!(hostname.as_deref(), Some("build-box"));
                let expected: Vec<UpSetting> = [
                    "v4-bridge=on",
                    "dns=partial",
                    "firewall.reject=on",
                    "dns=off",
                ]
                .into_iter()
                .map(|s| s.parse().unwrap())
                .collect();
                assert_eq!(settings, expected);
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn up_rejects_invalid_settings_before_contacting_the_daemon() {
        for flag in ["--set", "--enable"] {
            for assignment in [
                "unknown-key=on",
                "net.auto-accept-files=on",
                "dns=invalid",
                "v4-bridge=maybe",
                "ssh-port=0",
                "download-dir=relative",
                "firewall.default-in=invalid",
                "quic-engine",
                "=on",
            ] {
                assert!(
                    Cli::try_parse_from(["ray", "up", flag, assignment]).is_err(),
                    "{flag} {assignment}"
                );
            }
            assert!(Cli::try_parse_from(["ray", "up", flag]).is_err());
        }
    }

    #[test]
    fn up_enable_ssh_is_opt_in() {
        let cli = Cli::try_parse_from(["ray", "up"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Up {
                enable_ssh: false,
                ..
            }
        ));

        let cli = Cli::try_parse_from(["ray", "up", "--enable-ssh"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Up {
                enable_ssh: true,
                ..
            }
        ));
    }

    #[test]
    fn ssh_commands_parse_at_root_and_under_firewall() {
        for args in [&["ray", "ssh", "off"][..], &["ray", "fw", "ssh", "off"][..]] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(matches!(
                cli.command,
                Command::Ssh {
                    action: SshAction::Off,
                    ..
                } | Command::Firewall {
                    action: FirewallAction::Ssh {
                        action: SshAction::Off
                    },
                    ..
                }
            ));
        }
        let cli = Cli::try_parse_from(["ray", "ssh", "show", "--json"]).unwrap();
        assert!(json_requested(&cli.command));
    }

    #[test]
    fn strip_deleted_suffix_sanitizes_replaced_binary_path() {
        // After `self_replace` unlinks the running binary, Linux reports
        // `/proc/self/exe` with a trailing " (deleted)". The service unit must
        // not inherit it, or the daemon crash-loops on `ray (deleted) daemon`.
        assert_eq!(
            strip_deleted_suffix("/usr/local/bin/ray (deleted)"),
            "/usr/local/bin/ray"
        );
        // A normal path is untouched.
        assert_eq!(
            strip_deleted_suffix("/usr/local/bin/ray"),
            "/usr/local/bin/ray"
        );
        // Only an exact trailing marker is stripped, not the substring mid-path.
        assert_eq!(
            strip_deleted_suffix("/opt/ray (deleted)/ray"),
            "/opt/ray (deleted)/ray"
        );
    }

    #[test]
    fn parse_suggest_token_defaults_peer_to_any_for_bare_proto() {
        // A leading protocol keyword ⇒ peer defaults to `*` (any).
        assert_eq!(
            parse_suggest_token("tcp:22", "--allow").unwrap(),
            ("*".to_string(), "tcp:22".to_string())
        );
        assert_eq!(
            parse_suggest_token("udp:53", "--allow").unwrap(),
            ("*".to_string(), "udp:53".to_string())
        );
        // Bare port-less protocols too.
        assert_eq!(
            parse_suggest_token("icmp", "--allow").unwrap(),
            ("*".to_string(), "icmp".to_string())
        );
        assert_eq!(
            parse_suggest_token("any:*", "--allow").unwrap(),
            ("*".to_string(), "any:*".to_string())
        );
    }

    #[test]
    fn parse_suggest_token_keeps_explicit_peer() {
        // A non-protocol first segment is a peer hostname.
        assert_eq!(
            parse_suggest_token("earn01:tcp:9000,tcp:8123", "--allow").unwrap(),
            ("earn01".to_string(), "tcp:9000,tcp:8123".to_string())
        );
        // Explicit `*` peer still works.
        assert_eq!(
            parse_suggest_token("*:tcp:22", "--allow").unwrap(),
            ("*".to_string(), "tcp:22".to_string())
        );
        // Hostname with a bare proto spec.
        assert_eq!(
            parse_suggest_token("alice:icmp", "--deny").unwrap(),
            ("alice".to_string(), "icmp".to_string())
        );
    }

    #[test]
    fn parse_suggest_token_rejects_empty() {
        assert!(parse_suggest_token("", "--allow").is_err());
        assert!(parse_suggest_token("alice", "--allow").is_err());
    }

    #[test]
    fn release_asset_name_maps_supported_platforms() {
        assert_eq!(
            release_asset_name("linux", "x86_64").unwrap(),
            "ray-linux-x86_64"
        );
        assert_eq!(
            release_asset_name("linux", "aarch64").unwrap(),
            "ray-linux-aarch64"
        );
        assert_eq!(
            release_asset_name("macos", "x86_64").unwrap(),
            "ray-macos-x86_64"
        );
        assert_eq!(
            release_asset_name("macos", "aarch64").unwrap(),
            "ray-macos-aarch64"
        );
        assert_eq!(
            release_asset_name("windows", "x86_64").unwrap(),
            "ray-windows-x86_64.msi"
        );
        assert_eq!(
            nightly_asset_name("windows", "x86_64").unwrap(),
            "ray-windows-x86_64.exe"
        );
        assert_eq!(
            nightly_asset_name("windows", "aarch64").unwrap(),
            "ray-windows-aarch64.exe"
        );
    }

    #[test]
    fn release_asset_name_rejects_unsupported_platforms() {
        assert!(release_asset_name("windows", "aarch64").is_err());
        assert!(release_asset_name("linux", "riscv64").is_err());
    }

    #[test]
    fn normalize_version_strips_leading_v() {
        assert_eq!(normalize_version("v0.1.0"), "0.1.0");
        assert_eq!(normalize_version("0.1.0"), "0.1.0");
        assert_eq!(normalize_version("v1.2.3-rc1"), "1.2.3-rc1");
    }

    #[cfg(not(windows))]
    #[test]
    fn nightly_updates_show_both_commit_labels() {
        assert_eq!(
            update_label("0.4.2", "nightly (abcdef12)"),
            format!("nightly ({})", env!("RAY_GIT_SHA"))
        );
        assert_eq!(update_label("0.4.2", "v0.4.3"), "v0.4.2");
    }

    #[test]
    fn version_is_newer_orders_semver() {
        assert!(version_is_newer("0.2.0", "0.1.0"));
        assert!(version_is_newer("1.0.0", "0.9.9"));
        assert!(!version_is_newer("0.1.0", "0.1.0"));
        assert!(!version_is_newer("0.1.0", "0.2.0")); // older latest ⇒ no downgrade
        assert!(version_is_newer("0.1.0", "0.1.0-rc1")); // release beats prerelease
        // Unparseable tags fall back to inequality.
        assert!(version_is_newer("nightly", "0.1.0"));
        assert!(!version_is_newer("weird", "weird"));
    }

    fn view(
        dir: &str,
        action: &str,
        proto: &str,
        port: &str,
        peer: &str,
        net: &str,
        sugg: Option<&str>,
    ) -> FirewallRuleView {
        FirewallRuleView {
            direction: dir.parse().unwrap(),
            action: action.parse().unwrap(),
            protocol: proto.parse().unwrap(),
            port: port.into(),
            peer: peer.into(),
            network: net.into(),
            suggested_by: sugg.map(str::to_string),
        }
    }

    #[test]
    fn firewall_table_aligns_without_color() {
        style::set_plain(true);
        let rules = vec![
            view("in", "allow", "tcp", "443", "any", "any", None),
            view(
                "out",
                "deny",
                "udp",
                "53",
                "abc1",
                "homelab",
                Some("homelab"),
            ),
        ];
        let out = render_firewall_rules(
            Some((firewall::Action::Allow, firewall::Action::Allow)),
            false,
            false,
            &rules,
        );
        assert!(out.contains("default in   allow"));
        assert!(out.contains("default out  allow"));
        // Header present, columns aligned: the "action" column header and the
        // two action values start at the same offset on their lines.
        let lines: Vec<&str> = out
            .lines()
            .filter(|l| l.contains("allow") || l.contains("deny"))
            .collect();
        assert!(out.contains("·suggested by homelab·"));
        // No ANSI escapes in plain mode.
        assert!(!out.contains('\u{1b}'));
        assert!(lines.iter().any(|l| l.contains("443")));
    }

    #[test]
    fn empty_firewall_says_no_rules() {
        style::set_plain(true);
        let out = render_firewall_rules(
            Some((firewall::Action::Deny, firewall::Action::Allow)),
            false,
            false,
            &[],
        );
        assert!(out.contains("default in   deny"));
        assert!(out.contains("default out  allow"));
        assert!(out.contains("(no rules)"));
        // The posture header notes the firewall is separate from the host one.
        assert!(out.contains("separate from your host/kernel firewall"));
    }

    #[test]
    fn disabled_firewall_shows_banner() {
        style::set_plain(true);
        let out = render_firewall_rules(
            Some((firewall::Action::Deny, firewall::Action::Allow)),
            false,
            true,
            &[],
        );
        assert!(out.contains("disabled"));
        assert!(out.contains("all packets allowed"));
    }
}
