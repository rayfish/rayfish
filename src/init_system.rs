//! Linux init-system abstraction for service management.
//!
//! rayfish runs as a system service, but not every Linux host runs systemd:
//! Alpine and Gentoo use OpenRC, MX Linux and Devuan ship SysV init. The unit
//! layout, the enable/start commands, and even the file that has to be written
//! differ per init, so every `ray up`/`install`/`start`/`stop`/`restart`/
//! `uninstall` path goes through [`InitSystem`] instead of shelling out to
//! `systemctl` directly.
//!
//! Detection is about what is *running*, not what is installed: a Debian host
//! booted with systemd still has `/etc/init.d`, so the `/run` markers are
//! checked first. When nothing is recognised, callers report the failure and
//! point the user at `sudo ray daemon`, which needs no service manager at all.
//!
//! macOS (launchd) is not modelled here; it has a single service manager and
//! its call sites stay `#[cfg(target_os = "macos")]`.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// Service name used by every init: `rayfish.service` under systemd,
/// `/etc/init.d/rayfish` under OpenRC and SysV.
pub const SERVICE_NAME: &str = "rayfish";

/// Path placeholder in the bundled unit/init templates, replaced with the path
/// of the `ray` binary that is actually running.
const EXE_PLACEHOLDER: &str = "/usr/local/bin/ray";

const SYSTEMD_UNIT: &str = "/etc/systemd/system/rayfish.service";
const INITD_SCRIPT: &str = "/etc/init.d/rayfish";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    OpenRc,
    SysVInit,
}

impl InitSystem {
    /// The init system this host is running under, or `None` if it is one we
    /// have no template for.
    pub fn detect() -> Option<Self> {
        // `/run/systemd/system` exists only when PID 1 is systemd, which is the
        // check systemd itself documents for "booted with systemd".
        if Path::new("/run/systemd/system").is_dir() {
            return Some(Self::Systemd);
        }
        if Path::new("/run/openrc").exists() || Path::new("/sbin/openrc-run").exists() {
            return Some(Self::OpenRc);
        }
        if Path::new("/etc/init.d").is_dir() {
            return Some(Self::SysVInit);
        }
        None
    }

    /// Same as [`detect`](Self::detect), with an error that tells the user how
    /// to run rayfish without a service manager.
    pub fn require() -> Result<Self> {
        Self::detect().context(
            "no supported init system found (systemd, OpenRC or SysV init).\n\
             Run the daemon directly instead: sudo ray daemon",
        )
    }

    /// The init a rayfish service is *already* installed under, if any. Falls
    /// back to the detected init so a fresh host still reports a target.
    ///
    /// This matters when a host is switched between inits (or when a unit was
    /// left behind by a previous install): teardown has to act on the file that
    /// is really there, not on the one the current init would have written.
    pub fn installed() -> Option<Self> {
        if Path::new(SYSTEMD_UNIT).exists() {
            return Some(Self::Systemd);
        }
        if Path::new(INITD_SCRIPT).exists() {
            // Both OpenRC and SysV live at the same path; the running init
            // decides how to drive it.
            return match Self::detect() {
                Some(Self::Systemd) | None => Some(Self::SysVInit),
                other => other,
            };
        }
        None
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::OpenRc => "OpenRC",
            Self::SysVInit => "SysV init",
        }
    }

    /// Where this init's service definition lives.
    pub fn unit_path(self) -> &'static Path {
        match self {
            Self::Systemd => Path::new(SYSTEMD_UNIT),
            Self::OpenRc | Self::SysVInit => Path::new(INITD_SCRIPT),
        }
    }

    /// Write (or refresh) the service definition, pointing it at `exe`.
    /// Idempotent, so it is safe on every `ray up`.
    pub fn install_unit(self, exe: &str) -> Result<()> {
        let template = match self {
            Self::Systemd => include_str!("../contrib/rayfish.service"),
            Self::OpenRc => include_str!("../contrib/rayfish.openrc"),
            Self::SysVInit => include_str!("../contrib/rayfish.init"),
        };
        let path = self.unit_path();
        std::fs::write(path, template.replace(EXE_PLACEHOLDER, exe))
            .with_context(|| format!("failed to write {}", path.display()))?;

        match self {
            Self::Systemd => run("systemctl", &["daemon-reload"]),
            // Init scripts are executed directly by the init system, so they
            // have to carry the exec bit.
            Self::OpenRc | Self::SysVInit => {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                    .with_context(|| format!("failed to chmod {}", path.display()))?;
            }
        }
        Ok(())
    }

    /// Start the service at boot. Best-effort: a failure here costs the boot
    /// start, not the running daemon.
    pub fn enable(self) {
        match self {
            Self::Systemd => run("systemctl", &["enable", SERVICE_NAME]),
            Self::OpenRc => run("rc-update", &["add", SERVICE_NAME, "default"]),
            // Debian-family and RH-family SysV hosts have different registration
            // tools; try both and let the absent one fail quietly.
            Self::SysVInit => {
                run_quiet("update-rc.d", &[SERVICE_NAME, "defaults"]);
                run_quiet("chkconfig", &["--add", SERVICE_NAME]);
            }
        }
    }

    /// Stop the service and remove it from boot.
    pub fn disable(self) {
        match self {
            Self::Systemd => run("systemctl", &["disable", "--now", SERVICE_NAME]),
            Self::OpenRc => {
                run_quiet("rc-service", &[SERVICE_NAME, "stop"]);
                run("rc-update", &["del", SERVICE_NAME, "default"]);
            }
            Self::SysVInit => {
                run_quiet(INITD_SCRIPT, &["stop"]);
                run_quiet("update-rc.d", &["-f", SERVICE_NAME, "remove"]);
                run_quiet("chkconfig", &["--del", SERVICE_NAME]);
            }
        }
    }

    pub fn start(self) {
        self.action("start");
    }

    pub fn stop(self) {
        self.action("stop");
    }

    pub fn restart(self) {
        self.action("restart");
    }

    fn action(self, verb: &str) {
        match self {
            Self::Systemd => run("systemctl", &[verb, SERVICE_NAME]),
            Self::OpenRc => run("rc-service", &[SERVICE_NAME, verb]),
            Self::SysVInit => run(INITD_SCRIPT, &[verb]),
        }
    }

    /// A restart command the *daemon itself* can spawn and walk away from (used
    /// by the auto-updater, which cannot wait for its own replacement).
    ///
    /// Under systemd the restart runs in a transient `systemd-run --scope` unit
    /// so it sits **outside** `rayfish.service`'s cgroup: the service teardown
    /// (`KillMode=control-group`) would otherwise kill this client before it
    /// enqueued the restart job with PID 1. OpenRC and SysV kill by pidfile, so
    /// a plain detached child survives on its own.
    pub fn detached_restart_command(self) -> Command {
        match self {
            Self::Systemd => {
                let mut c = Command::new("systemd-run");
                c.args(["--scope", "systemctl", "restart", SERVICE_NAME]);
                c
            }
            Self::OpenRc => {
                let mut c = Command::new("rc-service");
                c.args([SERVICE_NAME, "restart"]);
                c
            }
            Self::SysVInit => {
                let mut c = Command::new(INITD_SCRIPT);
                c.arg("restart");
                c
            }
        }
    }

    /// Whether this init supervises the daemon (restarting it after the panic
    /// hook aborts). SysV init does not, so a crash there stays down until the
    /// next `ray start`.
    pub fn supervises(self) -> bool {
        !matches!(self, Self::SysVInit)
    }
}

/// Run a command, reporting a non-zero exit but not treating it as fatal.
fn run(program: &str, args: &[&str]) {
    match Command::new(program).args(args).status() {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("warning: {program} {} exited with {status}", args.join(" ")),
        Err(e) => eprintln!("warning: failed to run {program}: {e}"),
    }
}

/// Run a command, ignoring output and exit status (best-effort teardown, or a
/// tool that may not exist on this distro flavour).
fn run_quiet(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every template must carry the placeholder the installer rewrites; a
    /// typo there would silently install a unit pointing at a binary that may
    /// not exist.
    #[test]
    fn templates_carry_the_exe_placeholder() {
        for init in [
            InitSystem::Systemd,
            InitSystem::OpenRc,
            InitSystem::SysVInit,
        ] {
            let template = match init {
                InitSystem::Systemd => include_str!("../contrib/rayfish.service"),
                InitSystem::OpenRc => include_str!("../contrib/rayfish.openrc"),
                InitSystem::SysVInit => include_str!("../contrib/rayfish.init"),
            };
            assert!(
                template.contains(EXE_PLACEHOLDER),
                "{} template has no {EXE_PLACEHOLDER} placeholder",
                init.label()
            );
        }
    }

    #[test]
    fn initd_inits_share_one_path() {
        assert_eq!(
            InitSystem::OpenRc.unit_path(),
            InitSystem::SysVInit.unit_path()
        );
        assert_ne!(
            InitSystem::Systemd.unit_path(),
            InitSystem::SysVInit.unit_path()
        );
    }
}
