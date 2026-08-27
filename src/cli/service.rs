//! CLI service-management handlers: up, install, start/stop/restart, operator.

use crate::*;
#[cfg(target_os = "linux")]
use rayfish::init_system::InitSystem;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;

/// Create the `rayfish` system group if it doesn't already exist (Linux).
/// Best-effort: the daemon's config writer falls back to `root:root` ownership
/// when the group is missing, so a failure here only loosens the group-read
/// posture, never breaks startup.
#[cfg(target_os = "linux")]
pub(crate) fn ensure_rayfish_group() {
    // `getent group rayfish` exits 0 if the group exists.
    let exists = Command::new("getent")
        .args(["group", "rayfish"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !exists {
        let _ = Command::new("groupadd")
            .args(["--system", "rayfish"])
            .status();
    }
}

/// Write the system service unit/plist, substituting the path of the binary
/// currently running so the service execs the same `ray` the user invoked
/// (rather than a hardcoded /usr/local/bin/ray). Idempotent, safe to call on
/// every `ray up`, keeping the exec path fresh if the binary moves.
/// Strip the `" (deleted)"` marker Linux appends to `/proc/self/exe` once the
/// running binary's inode has been unlinked. `ray update` calls `self_replace`,
/// which unlinks the running binary, and *then* rewrites the service unit from
/// the running exe path. Without this strip the unit would get
/// `ExecStart=/usr/local/bin/ray (deleted) daemon` and the service would
/// crash-loop with `unrecognized subcommand '(deleted)'`, bricking remote
/// self-update.
pub(crate) fn strip_deleted_suffix(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

#[allow(unused_variables)]
pub(crate) fn ensure_service_installed() -> Result<()> {
    let exe = std::env::current_exe()
        .context("failed to determine current executable path")?
        .to_string_lossy()
        .into_owned();
    let exe = strip_deleted_suffix(&exe).to_owned();

    #[cfg(target_os = "linux")]
    {
        // Ensure the `rayfish` system group exists before the daemon writes its
        // config tree under /etc/rayfish (owned root:rayfish). Idempotent;
        // best-effort: the daemon falls back to root:root if the group is
        // absent (see config::set_owner).
        ensure_rayfish_group();
        // systemd, OpenRC and SysV each get their own template; `require` fails
        // with a "run `sudo ray daemon`" hint when the host runs none of them.
        InitSystem::require()?.install_unit(&exe)?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let path = Path::new("/Library/LaunchDaemons/com.rayfish.vpn.plist");
        let plist =
            include_str!("../../contrib/com.rayfish.vpn.plist").replace("/usr/local/bin/ray", &exe);
        std::fs::write(path, plist)
            .with_context(|| format!("failed to write {}", path.display()))?;
        return Ok(());
    }

    #[cfg(windows)]
    {
        rayfish::windows_service::install(std::path::Path::new(&exe))?;
        return Ok(());
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("system service not supported on this platform");
    }
}

/// Everything `ray up` accepts. A struct rather than six parameters, so the call
/// site names its values and the posture flags can be validated as one thing.
pub(crate) struct UpOptions {
    pub hostname: Option<String>,
    pub private: bool,
    pub no_private: bool,
    pub tor: bool,
    pub no_tor: bool,
    pub relay: Option<String>,
    pub pkarr: Option<String>,
    pub yes: bool,
}

impl UpOptions {
    /// Whether this invocation changes the node's posture rather than only
    /// bringing the data plane up. The common `ray up` answers `false` and skips
    /// the settings round trips entirely.
    fn touches_posture(&self) -> bool {
        self.private
            || self.no_private
            || self.tor
            || self.no_tor
            || self.relay.is_some()
            || self.pkarr.is_some()
    }
}

/// Write one global setting, returning the daemon's error instead of printing
/// it. `ray up` reports a single outcome; `ipc_mutate` would print a line per
/// key, and three "Restart the daemon" lines for one command reads like three
/// separate things happened.
async fn set_global(key: ipc::GlobalKey, value: &str, replace: bool) -> Result<()> {
    let mut stream = ipc::connect()
        .await
        .context("rayfish daemon is not running; start it with: sudo ray up")?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::ConfigSet {
            key: ipc::NodeKey::Global(key),
            value: value.to_string(),
            replace,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { .. } => Ok(()),
        ipc::IpcMessage::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!(
            "unexpected reply from the daemon: {other:?}\n    \
             the CLI and the daemon are probably different versions"
        ),
    }
}

/// Apply the posture flags, in the one order that works.
///
/// The servers go first and `private` last, because `config::settings::
/// apply_global` refuses to turn private mode on while either server list still
/// points at the defaults. So `ray up --private --relay <r> --pkarr <p>` only
/// succeeds once the two writes that satisfy that precondition have landed, and
/// `ray up --private` on a node with nothing configured fails with the daemon's
/// own message naming what is missing. That check lives in the daemon rather
/// than here on purpose: it is the same one that guards `ray config set private
/// on`, and an unprivileged CLI cannot reliably read the daemon's config to
/// repeat it.
async fn apply_posture(opts: &UpOptions) -> Result<()> {
    // `replace: true`: private mode means *only* these servers. Appending them
    // to n0's defaults would leave the node still talking to n0, which is the
    // one thing the mode promises it does not do.
    if let Some(relay) = &opts.relay {
        set_global(ipc::GlobalKey::Relay, relay, true)
            .await
            .context("setting the relay")?;
    }
    if let Some(pkarr) = &opts.pkarr {
        set_global(ipc::GlobalKey::DiscoveryDns, pkarr, true)
            .await
            .context("setting the discovery server")?;
    }
    // Tor before private, because what private mode demands depends on it: with
    // Tor it needs only a discovery server, without it a relay as well. Sending
    // them the other way round would reject `ray up --private --tor --pkarr <p>`
    // for a missing relay it is about to stop needing.
    if opts.tor {
        set_global(ipc::GlobalKey::Tor, "on", false).await?;
    }
    if opts.no_tor {
        set_global(ipc::GlobalKey::Tor, "off", false).await?;
    }
    if opts.private {
        set_global(ipc::GlobalKey::Private, "on", false).await?;
    }
    if opts.no_private {
        set_global(ipc::GlobalKey::Private, "off", false).await?;
    }
    Ok(())
}

/// Confirm leaving private mode.
///
/// Errors rather than prompting when there is no terminal, so a script cannot
/// pass the gate by having nothing to answer with. `--yes` is the way through
/// in that case, which keeps the decision explicit in the script's own text.
fn confirm_leaving_private(yes: bool) -> Result<()> {
    use std::io::{IsTerminal, Write};

    if yes {
        return Ok(());
    }
    let what = "this node will publish its addresses to the configured discovery \
                server, and mDNS comes back on";
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("leaving private mode exposes this node: {what}\n    rerun with --yes");
    }
    println!();
    println!("  {} leaving private mode", style::rose("!"));
    println!("    {what}");
    print!("  continue? [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        anyhow::bail!("cancelled; still in private mode");
    }
    Ok(())
}

/// Say what changed and that it needs a restart.
///
/// Not restarted for you: `ray up` is normally unprivileged and `ray restart` is
/// not, so an automatic bounce would work only when the caller happened to be
/// root. Dropping every peer connection as a side effect of `ray up`, sometimes,
/// is a worse surprise than a printed command.
fn announce_posture(opts: &UpOptions, restarting: bool) {
    println!();
    if opts.private {
        println!("  {} private mode on", style::check());
        println!(
            "    {}",
            style::faint(
                "only your relay and discovery server are contacted; mDNS and auto-update are off"
            )
        );
    } else if opts.no_private {
        println!("  {} private mode off", style::check());
    } else if !opts.tor && !opts.no_tor {
        println!("  {} servers updated", style::check());
    }
    if opts.tor {
        println!("  {} tor mode on", style::check());
        println!(
            "    {}",
            style::faint("peers are reached over Tor only; this node publishes no address")
        );
        // Worth saying because it is the one way a healthy-looking Tor node is
        // still unreachable, and the wait is long enough to look like a failure.
        println!(
            "    {}",
            style::faint(
                "needs a Tor daemon with ControlPort 9051; peers can reach you ~10s after start"
            )
        );
    } else if opts.no_tor {
        println!("  {} tor mode off", style::check());
    }
    println!(
        "    {}",
        style::faint(if restarting {
            "restarting to apply it"
        } else {
            "takes effect on restart: sudo ray restart"
        })
    );
    println!();
}

/// `ray up`: activate the VPN.
///
/// If the daemon is already running (the common case, the system service
/// starts it at boot), this is just an unprivileged IPC call asking the daemon
/// to bring the TUN up, configure DNS, and reconnect networks. Only when no
/// daemon is reachable do we fall back to installing/starting the system
/// service, which requires root.
///
/// The posture flags (`--private`, `--relay`, `--pkarr`) are settings writes,
/// not part of `Up`: they go over `ConfigSet` first, and are read again when the
/// endpoint next binds. See [`apply_posture`].
pub(crate) async fn cmd_up(opts: UpOptions) -> Result<()> {
    if opts.no_private {
        confirm_leaving_private(opts.yes)?;
    }

    #[cfg(windows)]
    let mut operator_claim = WindowsOperatorClaim::begin()?;
    if let Ok(mut stream) = ipc::connect().await {
        // Posture before `Up`, on its own connections (IPC is one request, one
        // response). A failure here stops the command: bringing the data plane
        // up on the old posture would be the opposite of what was asked.
        if opts.touches_posture() {
            drop(stream);
            apply_posture(&opts).await?;
            announce_posture(&opts, false);
            stream = ipc::connect().await?;
        }
        ipc::send(
            &mut stream,
            ipc::IpcMessage::Up {
                hostname: opts.hostname,
            },
        )
        .await?;
        match ipc::recv(&mut stream).await? {
            ipc::IpcMessage::Ok { message } => {
                // The daemon accepted the request, so the operator SID this
                // process claimed is the one it authorized against. Anything
                // else leaves the claim to be rolled back on drop.
                #[cfg(windows)]
                operator_claim.commit();
                println!("{message}")
            }
            ipc::IpcMessage::Error { message } => fail_with("error", &message),
            other => fail_unexpected(&other),
        }
        return Ok(());
    }

    #[cfg(windows)]
    drop(operator_claim);

    // No daemon reachable, install and start the system service (needs root).
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "rayfish service is not running. Start it with: sudo ray up\n\
             (the daemon needs root to install the system service and create the TUN device)"
        );
        std::process::exit(1);
    }
    install_and_start_service(opts.hostname.clone()).await?;

    // The daemon is up and reachable now, so the posture can be written and made
    // to take effect. Unlike the path above, this one already required root and
    // just started the service itself, so bouncing it is neither a privilege
    // problem nor a surprise: nothing was connected a moment ago.
    if opts.touches_posture() {
        apply_posture(&opts).await?;
        announce_posture(&opts, true);
        restart_service_and_wait().await?;
    }
    Ok(())
}

/// Install/refresh the system service and (re)start it. Requires root.
///
/// Starting the service is fire-and-forget at the OS level, so we then wait for
/// the daemon to actually accept an IPC connection before declaring success. If
/// it never comes up (e.g. it crashed on a port/route conflict with another
/// VPN), we surface the tail of its log so the user knows what went wrong
/// instead of seeing a cheerful "started" followed by a dead `ray status`.
pub(crate) async fn install_and_start_service(hostname: Option<String>) -> Result<()> {
    // The Windows counterpart of the `geteuid() != 0` precheck in `cmd_up`, kept
    // here because every caller reaches the SCM through this function. Without
    // it the failure surfaces as a raw access-denied from `OpenSCManager`, which
    // does not tell anyone what to do about it.
    #[cfg(windows)]
    if !rayfish::windows_identity::is_current_process_elevated_admin() {
        anyhow::bail!(
            "rayfish service is not running, and installing it needs Administrator.\n\
             Reopen this terminal as Administrator and rerun: ray up"
        );
    }
    #[cfg(windows)]
    let mut operator_claim = WindowsOperatorClaim::begin()?;
    ensure_service_installed()?;
    // We are root here, which is what it takes to write into the directories
    // the shells already search. Doing it from the service installer is what
    // makes tab completion something you have rather than something you set up,
    // and `ray update` comes back through here, so the stubs stay current.
    complete::install_with_service();

    #[cfg(target_os = "linux")]
    {
        let init = InitSystem::require()?;
        init.enable();
        init.restart();
        if !init.supervises() {
            println!(
                "note: {} does not restart the daemon if it exits; \
                 use `sudo ray start` to bring it back.",
                init.label()
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        let path = "/Library/LaunchDaemons/com.rayfish.vpn.plist";
        // Tear down any previously loaded job (e.g. one pointing at a stale
        // binary path) before loading the freshly written plist.
        run_cmd_quiet("launchctl", &["unload", path]);
        run_cmd("launchctl", &["load", "-w", path]);
    }

    #[cfg(windows)]
    {
        rayfish::windows_service::start()?;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        anyhow::bail!("system service not supported on this platform");
    }

    // Wait for the freshly started daemon to accept IPC, then activate the VPN.
    let spinner = progress::spinner("starting service…");
    let daemon = wait_for_daemon(DAEMON_REACHABLE_TIMEOUT).await;
    spinner.finish_and_clear();
    match daemon {
        Some(mut stream) => {
            ipc::send(&mut stream, ipc::IpcMessage::Up { hostname }).await?;
            // A failed `up` still exits non-zero, but not before the grant below:
            // the service is installed and running by this point, and the user's
            // next move is to retry `ray up` without sudo. Taking that away as
            // well would make the failure harder to recover from than it is.
            let failed = match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => {
                    // Windows' equivalent of the grant below: the daemon
                    // authorized against the SID this process claimed, so make
                    // the claim permanent. Anything else rolls it back on drop.
                    #[cfg(windows)]
                    operator_claim.commit();
                    println!("rayfish service started. {message}");
                    None
                }
                ipc::IpcMessage::Error { message } => Some(message),
                // Not `fail_unexpected`: exiting here would skip the grant below,
                // and the ordering above is the whole point. Same treatment as a
                // daemon-side error, so it exits non-zero after the grant.
                other => Some(format!(
                    "unexpected reply from the daemon: {other:?}\n    \
                     the CLI and the daemon are probably different versions"
                )),
            };
            // We're root here (installing the service). Grant the invoking user
            // operator access so they can run `ray` without sudo from now on,
            // the way `tailscale up --operator=$USER` does.
            grant_operator_to_invoking_user().await;
            if let Some(message) = failed {
                fail_with("error", &message);
            }
            Ok(())
        }
        None => {
            #[cfg(windows)]
            drop(operator_claim);
            eprintln!(
                "rayfish service was started but the daemon never became reachable.\n\
                 It likely crashed on startup. Common causes are DNS port 53 already in\n\
                 use, a conflicting route, or no permission to create the TUN device."
            );
            print_daemon_log_tail();
            std::process::exit(1);
        }
    }
}

/// When the service is (re)installed under `sudo`, grant the invoking user
/// (`$SUDO_USER`) operator access so subsequent `ray` commands work without
/// root. Best-effort: silent if there is no `$SUDO_USER` or the daemon refuses.
pub(crate) async fn grant_operator_to_invoking_user() {
    let Ok(user) = std::env::var("SUDO_USER") else {
        return;
    };
    if user == "root" {
        return;
    }
    let Some(uid) = uid_for_user(&user) else {
        return;
    };
    if let Ok(mut stream) = ipc::connect().await {
        let _ = ipc::send(&mut stream, ipc::IpcMessage::SetOperator { uid }).await;
        if let Ok(ipc::IpcMessage::Ok { .. }) = ipc::recv(&mut stream).await {
            println!("granted operator access to '{user}' — run ray without sudo");
        }
    }
}

/// Ensure the process is running as root for service-manager operations.
/// Prints a clear `sudo` hint and exits non-zero otherwise.
#[allow(unreachable_code)]
pub(crate) fn require_root() -> Result<()> {
    #[cfg(windows)]
    {
        anyhow::ensure!(
            rayfish::windows_identity::is_current_process_elevated_admin(),
            "this command requires an elevated Administrator terminal"
        );
        return Ok(());
    }
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "this command manages the system service and needs root.\n\
             Re-run with: sudo ray <command>"
        );
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsOperatorClaim {
    sid: Option<String>,
}

#[cfg(windows)]
impl WindowsOperatorClaim {
    fn begin() -> Result<Self> {
        if !rayfish::windows_identity::is_current_process_elevated_admin() {
            return Ok(Self { sid: None });
        }
        let sid = rayfish::windows_identity::current_user_sid()
            .context("elevated Windows process has no user SID")?;
        Ok(Self {
            sid: config::claim_operator_sid(&sid)?.then_some(sid),
        })
    }

    fn commit(&mut self) {
        self.sid = None;
    }
}

#[cfg(windows)]
impl Drop for WindowsOperatorClaim {
    fn drop(&mut self) {
        if let Some(sid) = self.sid.take()
            && let Err(error) = config::remove_operator_sid_if_matches(&sid)
        {
            tracing::error!(%error, "failed to compensate Windows operator claim");
        }
    }
}

/// `ray install`: install the system service if needed (or refresh an existing
/// install), then start it and verify the daemon comes up. Requires root.
///
/// `--auto-update` opts this node into automatic stable updates: it is persisted
/// to `settings.toml` *before* the (re)start so the freshly launched daemon
/// reads it at boot and spawns the periodic update task. Unlike the other
/// config-writing commands (which route through the daemon, see main.rs), this
/// one writes directly: there is no daemon to route to yet, and it runs as root
/// immediately before starting the service, so it shares the service's config
/// dir.
pub(crate) async fn cmd_install(auto_update: bool) -> Result<()> {
    require_root()?;
    if auto_update {
        // A no-op when it is already on: the update skips the write.
        config::update_settings(|cfg| {
            cfg.auto_update = true;
            Ok(())
        })?;
        println!("automatic stable updates enabled for this node");
    }
    install_and_start_service(None).await
}

/// Whether the system service unit/plist is installed on this host.
pub(crate) fn service_unit_exists() -> bool {
    #[cfg(target_os = "linux")]
    {
        return InitSystem::installed().is_some();
    }
    #[cfg(target_os = "macos")]
    {
        return Path::new("/Library/LaunchDaemons/com.rayfish.vpn.plist").exists();
    }
    #[cfg(windows)]
    {
        return rayfish::windows_service::exists();
    }
    #[allow(unreachable_code)]
    false
}

/// Restart the installed service via the OS service manager (without rewriting
/// the unit file) and wait for the daemon to accept IPC again. Shared by
/// `ray restart` and `ray update`; mirrors the `up`/`install` diagnostics.
#[allow(unreachable_code)]
pub(crate) async fn restart_service_and_wait() -> Result<()> {
    #[cfg(target_os = "linux")]
    InitSystem::require()?.restart();

    #[cfg(target_os = "macos")]
    run_cmd("launchctl", &["kickstart", "-k", "system/com.rayfish.vpn"]);

    #[cfg(windows)]
    rayfish::windows_service::stop().and_then(|_| rayfish::windows_service::start())?;

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    anyhow::bail!("system service not supported on this platform");

    match wait_for_daemon(DAEMON_REACHABLE_TIMEOUT).await {
        Some(_) => {
            println!("rayfish service restarted.");
            Ok(())
        }
        None => {
            eprintln!("rayfish service was restarted but the daemon never became reachable.");
            print_daemon_log_tail();
            std::process::exit(1);
        }
    }
}

/// `ray restart`: restart the already-installed system service via the OS
/// service manager (does not rewrite the unit file). Requires root. The daemon
/// comes back up active.
pub(crate) async fn cmd_restart() -> Result<()> {
    require_root()?;
    if !service_unit_exists() {
        eprintln!("rayfish service is not installed. Run: sudo ray up");
        std::process::exit(1);
    }
    restart_service_and_wait().await
}

/// `ray stop`: stop the installed system service so the daemon exits and all
/// peer connections close cleanly (a clean offline, distinct from `ray down`
/// standby). Does not disable or uninstall the unit. Requires root.
#[allow(unreachable_code)]
pub(crate) async fn cmd_stop() -> Result<()> {
    require_root()?;
    if !service_unit_exists() {
        eprintln!("rayfish service is not installed. Nothing to stop.");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    InitSystem::require()?.stop();

    #[cfg(target_os = "macos")]
    run_cmd(
        "launchctl",
        &["unload", "/Library/LaunchDaemons/com.rayfish.vpn.plist"],
    );

    #[cfg(windows)]
    rayfish::windows_service::stop()?;

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    anyhow::bail!("system service not supported on this platform");

    println!("rayfish service stopped.");
    Ok(())
}

/// `ray start`: start the already-installed system service via the OS service
/// manager and wait for the daemon to accept IPC. The daemon comes back up with
/// the control and data planes on. Requires root.
#[allow(unreachable_code)]
pub(crate) async fn cmd_start() -> Result<()> {
    require_root()?;
    if !service_unit_exists() {
        eprintln!("rayfish service is not installed. Run: sudo ray up");
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    InitSystem::require()?.start();

    #[cfg(target_os = "macos")]
    run_cmd(
        "launchctl",
        &["load", "-w", "/Library/LaunchDaemons/com.rayfish.vpn.plist"],
    );

    #[cfg(windows)]
    rayfish::windows_service::start()?;

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    anyhow::bail!("system service not supported on this platform");

    match wait_for_daemon(DAEMON_REACHABLE_TIMEOUT).await {
        Some(_) => {
            println!("rayfish service started.");
            Ok(())
        }
        None => {
            eprintln!("rayfish service was started but the daemon never became reachable.");
            print_daemon_log_tail();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UpOptions;

    fn opts() -> UpOptions {
        UpOptions {
            hostname: None,
            private: false,
            no_private: false,
            tor: false,
            no_tor: false,
            relay: None,
            pkarr: None,
            yes: false,
        }
    }

    /// The plain `ray up` must not touch settings at all. It is the command
    /// people run on every boot, and a settings round trip there would make a
    /// posture change out of something that was only meant to raise the link.
    #[test]
    fn plain_up_touches_no_settings() {
        assert!(!opts().touches_posture());
        assert!(
            !UpOptions {
                hostname: Some("laptop".into()),
                ..opts()
            }
            .touches_posture(),
            "--hostname is not a posture flag"
        );
    }

    #[test]
    fn every_posture_flag_is_recognized() {
        for o in [
            UpOptions {
                private: true,
                ..opts()
            },
            UpOptions {
                no_private: true,
                ..opts()
            },
            UpOptions {
                tor: true,
                ..opts()
            },
            UpOptions {
                no_tor: true,
                ..opts()
            },
            UpOptions {
                relay: Some("http://r.example".into()),
                ..opts()
            },
            UpOptions {
                pkarr: Some("http://d.example".into()),
                ..opts()
            },
        ] {
            assert!(o.touches_posture());
        }
    }
}
