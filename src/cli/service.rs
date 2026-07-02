//! CLI service-management handlers: up, install, start/stop/restart, operator.

use crate::*;
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
/// (rather than a hardcoded /usr/local/bin/ray). Idempotent — safe to call on
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
        // best-effort — the daemon falls back to root:root if the group is
        // absent (see config::set_owner).
        ensure_rayfish_group();
        let path = Path::new("/etc/systemd/system/rayfish.service");
        let service =
            include_str!("../../contrib/rayfish.service").replace("/usr/local/bin/ray", &exe);
        std::fs::write(path, service)
            .with_context(|| format!("failed to write {}", path.display()))?;
        run_cmd("systemctl", &["daemon-reload"]);
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

    #[allow(unreachable_code)]
    {
        anyhow::bail!("system service not supported on this platform");
    }
}

/// `ray up`: activate the VPN.
///
/// If the daemon is already running (the common case — the system service
/// starts it at boot), this is just an unprivileged IPC call asking the daemon
/// to bring the TUN up, configure DNS, and reconnect networks. Only when no
/// daemon is reachable do we fall back to installing/starting the system
/// service, which requires root.
pub(crate) async fn cmd_up(hostname: Option<String>) -> Result<()> {
    if let Ok(mut stream) = ipc::connect().await {
        ipc::send(&mut stream, ipc::IpcMessage::Up { hostname }).await?;
        match ipc::recv(&mut stream).await? {
            ipc::IpcMessage::Ok { message } => println!("{message}"),
            ipc::IpcMessage::Error { message } => print_error("error", &message, None),
            other => eprintln!("Unexpected response: {other:?}"),
        }
        return Ok(());
    }

    // No daemon reachable — install and start the system service (needs root).
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "rayfish service is not running. Start it with: sudo ray up\n\
             (the daemon needs root to install the system service and create the TUN device)"
        );
        std::process::exit(1);
    }
    install_and_start_service(hostname).await
}

/// Install/refresh the system service and (re)start it. Requires root.
///
/// Starting the service is fire-and-forget at the OS level, so we then wait for
/// the daemon to actually accept an IPC connection before declaring success. If
/// it never comes up (e.g. it crashed on a port/route conflict with another
/// VPN), we surface the tail of its log so the user knows what went wrong
/// instead of seeing a cheerful "started" followed by a dead `ray status`.
pub(crate) async fn install_and_start_service(hostname: Option<String>) -> Result<()> {
    ensure_service_installed()?;

    #[cfg(target_os = "linux")]
    {
        run_cmd("systemctl", &["enable", "rayfish"]);
        run_cmd("systemctl", &["restart", "rayfish"]);
    }

    #[cfg(target_os = "macos")]
    {
        let path = "/Library/LaunchDaemons/com.rayfish.vpn.plist";
        // Tear down any previously loaded job (e.g. one pointing at a stale
        // binary path) before loading the freshly written plist.
        run_cmd_quiet("launchctl", &["unload", path]);
        run_cmd("launchctl", &["load", "-w", path]);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => println!("rayfish service started. {message}"),
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {other:?}"),
            }
            // We're root here (installing the service). Grant the invoking user
            // operator access so they can run `ray` without sudo from now on,
            // the way `tailscale up --operator=$USER` does.
            grant_operator_to_invoking_user().await;
            Ok(())
        }
        None => {
            eprintln!(
                "rayfish service was started but the daemon never became reachable.\n\
                 It likely crashed on startup — a common cause is another VPN (e.g. Tailscale)\n\
                 already using the 100.64.0.0/10 range, DNS port 53, or a conflicting route."
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
pub(crate) fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "this command manages the system service and needs root.\n\
             Re-run with: sudo ray <command>"
        );
        std::process::exit(1);
    }
    Ok(())
}

/// `ray install`: install the system service if needed (or refresh an existing
/// install), then start it and verify the daemon comes up. Requires root.
pub(crate) async fn cmd_install() -> Result<()> {
    require_root()?;
    install_and_start_service(None).await
}

/// Whether the system service unit/plist is installed on this host.
pub(crate) fn service_unit_exists() -> bool {
    #[cfg(target_os = "linux")]
    {
        return Path::new("/etc/systemd/system/rayfish.service").exists();
    }
    #[cfg(target_os = "macos")]
    {
        return Path::new("/Library/LaunchDaemons/com.rayfish.vpn.plist").exists();
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
    run_cmd("systemctl", &["restart", "rayfish"]);

    #[cfg(target_os = "macos")]
    run_cmd("launchctl", &["kickstart", "-k", "system/com.rayfish.vpn"]);

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
    run_cmd("systemctl", &["stop", "rayfish"]);

    #[cfg(target_os = "macos")]
    run_cmd(
        "launchctl",
        &["unload", "/Library/LaunchDaemons/com.rayfish.vpn.plist"],
    );

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
    run_cmd("systemctl", &["start", "rayfish"]);

    #[cfg(target_os = "macos")]
    run_cmd(
        "launchctl",
        &["load", "-w", "/Library/LaunchDaemons/com.rayfish.vpn.plist"],
    );

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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

// ---------------------------------------------------------------------------
// Self-update (`ray update`)
// ---------------------------------------------------------------------------

/// owner/repo slug for the GitHub releases this binary updates from. Matches
/// `REPORT_REPO_URL` and the `install.sh` bootstrap installer.
pub(crate) const REPO_SLUG: &str = "rayfish/rayfish";

