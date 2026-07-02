//! CLI self-update + GitHub release plumbing and small process helpers.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Error;
use reqwest::{Client, RequestBuilder};
use semver::Version;

use crate::*;

/// Map the host OS/arch to the release asset name CI publishes
/// (`ray-{os}-{arch}`, e.g. `ray-linux-x86_64`). Errors on platforms we don't
/// build binaries for, so the user falls back to building from source.
pub(crate) fn release_asset_name(os: &str, arch: &str) -> Result<String> {
    let os = match os {
        "linux" => "linux",
        "macos" => "macos",
        other => anyhow::bail!("no rayfish release binary for OS '{other}'; build from source"),
    };
    let arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => {
            anyhow::bail!("no rayfish release binary for architecture '{other}'; build from source")
        }
    };
    Ok(format!("ray-{os}-{arch}"))
}

/// Strip a leading `v` from a release tag for comparison with
/// `CARGO_PKG_VERSION` (`v0.1.0` → `0.1.0`).
pub(crate) fn normalize_version(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Whether `latest` is a strictly newer semver than `current`. Falls back to a
/// plain string inequality if either side fails to parse, so an unusual tag
/// still triggers an update rather than being silently ignored.
pub(crate) fn version_is_newer(latest: &str, current: &str) -> bool {
    match (
        Version::parse(latest),
        Version::parse(current),
    ) {
        (Ok(l), Ok(c)) => l > c,
        _ => latest != current,
    }
}

/// Whether a sibling temp file can be created in `dir` (i.e. it is writable by
/// us). `self_replace` writes a temp next to the running binary then renames, so
/// directory write permission is what decides if we need root.
pub(crate) fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(".ray-update-probe");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct GhRelease {
    tag_name: String,
    /// The release's display name. For the rolling nightly this carries the
    /// source commit (`nightly (abc12345)`), so we surface it instead of the
    /// bare `nightly` tag.
    #[serde(default)]
    name: Option<String>,
    /// Whether GitHub marks this a pre-release (nightlies and `-rc`/`-` tags),
    /// used to annotate `ray update --list`.
    #[serde(default)]
    prerelease: bool,
    /// The release notes (git-cliff renders these from conventional commits in
    /// `release.yml`). Printed by `ray update` so the user sees what each pending
    /// version changes; `None`/empty for releases without notes.
    #[serde(default)]
    body: Option<String>,
}

/// Print one release's notes, indented under its tag. A blank or missing body
/// prints just the tag line.
pub(crate) fn print_release_notes(tag: &str, body: Option<&str>) {
    println!("\n  {tag}");
    if let Some(b) = body.map(str::trim).filter(|b| !b.is_empty()) {
        for line in b.lines() {
            println!("    {line}");
        }
    }
}

/// Print the release notes the user would gain by updating. For the stable
/// channel this walks every published release in `(current, latest]`, newest
/// first; for `--nightly` or a pinned `--version` it prints the single resolved
/// release's body. Best-effort: any failure (network, missing notes) prints
/// nothing rather than blocking the update.
pub(crate) async fn print_pending_changelog(
    client: &Client,
    token: &Option<String>,
    current: &str,
    latest: &str,
    release: &GhRelease,
    nightly: bool,
    pinned: bool,
) {
    // Nightly and pinned resolve to a single release we already fetched — just
    // surface its body. (A semver walk doesn't apply: nightlies share a version,
    // and a pinned target may be a downgrade.)
    if nightly || pinned {
        if release.body.as_deref().map(str::trim).unwrap_or("").is_empty() {
            return;
        }
        println!("\nRelease notes for {}:", release.tag_name);
        print_release_notes(&release.tag_name, release.body.as_deref());
        println!();
        return;
    }

    // Stable: fetch the recent releases and keep the stable ones strictly newer
    // than what we run, up to and including the target.
    let api = format!("https://api.github.com/repos/{REPO_SLUG}/releases?per_page=100");
    // Bound the whole request so a slow/unreachable API can't freeze the update;
    // on timeout (or any error) we just skip the notes.
    let req = authed(client.get(&api), token).timeout(Duration::from_secs(5));
    let releases: Vec<GhRelease> = match req.send().await {
        Ok(resp) => match resp.error_for_status() {
            Ok(resp) => resp.json().await.unwrap_or_default(),
            Err(_) => return,
        },
        Err(_) => return,
    };
    let relevant: Vec<&GhRelease> = releases
        .iter()
        .filter(|r| !r.prerelease)
        .filter(|r| {
            let v = normalize_version(&r.tag_name);
            version_is_newer(v, current) && !version_is_newer(v, latest)
        })
        .collect();
    if relevant.is_empty() {
        return;
    }
    println!("\nChanges in v{current} → v{latest}:");
    for r in relevant {
        print_release_notes(&r.tag_name, r.body.as_deref());
    }
    println!();
}

/// SHA-256 of a byte slice as lowercase hex — used both to verify a download
/// and to fingerprint the running binary on the nightly channel.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A GitHub token for authenticating REST API calls, which lifts the
/// unauthenticated 60-request/hour-per-IP rate limit to 5000/hour. Prefers an
/// explicit env var (the same `GH_TOKEN`/`GITHUB_TOKEN` precedence `gh` uses),
/// then falls back to the `gh` CLI's stored credential when it is installed and
/// logged in. Returns `None` if no token is available, leaving calls anonymous.
pub(crate) fn github_token() -> Option<String> {
    for var in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    // `gh auth token` prints the active token to stdout (and exits non-zero if
    // `gh` is unauthenticated). A missing `gh` makes `output()` error → `None`.
    let out = Command::new("gh")
        .args(["auth", "token"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let token = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!token.is_empty()).then_some(token)
}

/// Attach `Authorization: Bearer <token>` to a GitHub REST request when a token
/// is present; otherwise leave the request anonymous. Only used for the
/// api.github.com calls — the release-asset downloads on github.com aren't
/// subject to the API rate limit and are left unauthenticated.
pub(crate) fn authed(req: RequestBuilder, token: &Option<String>) -> RequestBuilder {
    match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}

/// `ray update`: replace this binary with a GitHub release and, if the system
/// service is installed, restart the daemon onto the new binary.
///
/// Stable (default) tracks the latest published release and gates on semver.
/// `--nightly` tracks the rolling `nightly` pre-release (rebuilt on every commit
/// to master); since nightlies share a crate version, the swap decision compares
/// the published checksum against the *running* binary rather than the version.
///
/// `--check` only reports current vs latest (no root, no install); `--force`
/// reinstalls even when already current. `--list` prints the available releases
/// and exits; `--version X` pins a specific release (downgrades allowed).
pub(crate) async fn cmd_update(
    force: bool,
    check: bool,
    nightly: bool,
    list: bool,
    version: Option<String>,
) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    // Fail fast on unsupported platforms before any network I/O.
    let asset = release_asset_name(std::env::consts::OS, std::env::consts::ARCH)?;

    // reqwest is built with `rustls-no-provider`, so it relies on a process-level
    // default CryptoProvider. Install ring (already in the tree via iroh) before
    // building the client. `install_default` errors only if one is already set —
    // harmless here, so ignore it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client = Client::builder()
        .user_agent(concat!("ray/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")?;

    // Authenticate the api.github.com calls below when a token is available so
    // repeated `ray update` runs don't trip the 60/hr-per-IP anonymous limit.
    let token = github_token();

    // `--list`: enumerate published releases (newest first) and exit. No root,
    // no install.
    if list {
        return cmd_update_list(&client, &token, current).await;
    }

    // A pinned `--version` resolves to a `v`-prefixed tag (releases are tagged
    // `vX.Y.Z`); accept the version with or without the leading `v`.
    let pinned_tag = version.as_ref().map(|v| {
        let v = v.strip_prefix('v').unwrap_or(v);
        format!("v{v}")
    });

    // Resolve the release: pinned version → that tag; nightly → the rolling
    // `nightly` pre-release; otherwise the latest published release.
    let spinner = progress::spinner("checking for updates…");
    let api = if let Some(tag) = &pinned_tag {
        format!("https://api.github.com/repos/{REPO_SLUG}/releases/tags/{tag}")
    } else if nightly {
        format!("https://api.github.com/repos/{REPO_SLUG}/releases/tags/nightly")
    } else {
        format!("https://api.github.com/repos/{REPO_SLUG}/releases/latest")
    };
    let release: GhRelease = (async {
        authed(client.get(&api), &token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    })
    .await
    .context(if let Some(tag) = &pinned_tag {
        format!("failed to find release {tag} (see `ray update --list`)")
    } else if nightly {
        "failed to query the nightly pre-release (is one published yet?)".to_string()
    } else {
        "failed to query the GitHub releases API (is a release published yet?)".to_string()
    })?;
    spinner.finish_and_clear();

    let tag = release.tag_name.clone();
    let latest = normalize_version(&tag);
    // Human label for messages: nightly carries its commit in the release name.
    let remote_label = if nightly {
        release.name.clone().unwrap_or_else(|| "nightly".to_string())
    } else {
        format!("v{latest}")
    };

    // Fetch the published checksum sidecar first (it is tiny) so the swap
    // decision — especially the nightly checksum compare — can run before
    // downloading the whole binary.
    let base = format!("https://github.com/{REPO_SLUG}/releases/download/{tag}");
    let bin_url = format!("{base}/{asset}");
    let sha_url = format!("{bin_url}.sha256");
    let spinner = progress::spinner("checking for updates…");
    let sha_text = (async {
        client
            .get(&sha_url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("no checksum at {sha_url}"))?
            .text()
            .await
            .map_err(Error::from)
    })
    .await
    .context("failed to fetch the published checksum")?;
    spinner.finish_and_clear();

    // The first whitespace field of the `.sha256` is the digest.
    let expected = sha_text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    if expected.is_empty() {
        anyhow::bail!("no checksum published for {asset}; aborting for safety");
    }

    // "Up to date?" — a pinned version is "current" only if it equals what we
    // run (so `--version` can downgrade); nightly compares the running binary's
    // checksum to the published one (two nightlies share a crate version, so
    // semver can't tell them apart); stable gates on semver. If we can't read
    // our own executable on the nightly path, proceed rather than assume current.
    let up_to_date = if pinned_tag.is_some() {
        latest == current
    } else if nightly {
        match std::env::current_exe().and_then(std::fs::read) {
            Ok(bytes) => sha256_hex(&bytes) == expected,
            Err(_) => false,
        }
    } else {
        !version_is_newer(latest, current)
    };

    if check {
        println!("current: {FULL_VERSION}");
        println!("latest:  {remote_label}");
        // Best-effort: report the running daemon's version too. If it differs
        // from this CLI binary the daemon is stale (e.g. a prior update never
        // restarted it) — a restart, not a download, is what's needed.
        if let Some(daemon_version) = daemon_version().await
            && daemon_version != current
        {
            println!("daemon:  {daemon_version} (stale — run `sudo ray update` to restart it)");
        }
        if up_to_date {
            println!("rayfish is up to date");
        } else {
            print_pending_changelog(
                &client,
                &token,
                current,
                latest,
                &release,
                nightly,
                pinned_tag.is_some(),
            )
            .await;
            let flag = if nightly {
                " --nightly".to_string()
            } else if let Some(v) = &version {
                format!(" --version {v}")
            } else {
                String::new()
            };
            println!("run `sudo ray update{flag}` to upgrade");
        }
        return Ok(());
    }

    if up_to_date && !force {
        println!("rayfish is already up to date ({remote_label})");
        return Ok(());
    }

    // Show what this update brings before touching the binary.
    print_pending_changelog(
        &client,
        &token,
        current,
        latest,
        &release,
        nightly,
        pinned_tag.is_some(),
    )
    .await;

    download_verify_and_install(&client, &bin_url, &expected, &asset, current, &remote_label).await
}

/// `ray update --list`: enumerate published releases (newest first) and exit.
/// No root, no install.
async fn cmd_update_list(
    client: &Client,
    token: &Option<String>,
    current: &str,
) -> Result<()> {
    let spinner = progress::spinner("fetching releases…");
    let api = format!("https://api.github.com/repos/{REPO_SLUG}/releases?per_page=30");
    let releases: Vec<GhRelease> = (async {
        authed(client.get(&api), token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
    })
    .await
    .context("failed to list releases")?;
    spinner.finish_and_clear();

    if releases.is_empty() {
        println!("no releases published yet");
        return Ok(());
    }
    for r in &releases {
        let installed = if normalize_version(&r.tag_name) == current {
            "  (installed)"
        } else {
            ""
        };
        let kind = if r.prerelease { "  [pre-release]" } else { "" };
        println!("{}{kind}{installed}", r.tag_name);
    }
    Ok(())
}

/// Download the release asset, verify it against the (already-fetched) checksum,
/// atomically swap it in for the running binary, then restart the service onto
/// the new binary if one is installed. Acquires root up front (the swap +
/// restart need it) so we fail with a clean sudo hint before downloading.
async fn download_verify_and_install(
    client: &Client,
    bin_url: &str,
    expected: &str,
    asset: &str,
    current: &str,
    remote_label: &str,
) -> Result<()> {
    // Replacing the installed binary (typically root-owned) and restarting the
    // service both need root. Decide up front so we exit with a clean sudo hint
    // before downloading.
    let service_installed = service_unit_exists();
    let exe = std::env::current_exe().context("failed to determine current executable path")?;
    let needs_root =
        service_installed || exe.parent().map(|dir| !dir_writable(dir)).unwrap_or(true);
    if needs_root {
        require_root()?;
    }

    // Download the binary from the same tagged release (the checksum was already
    // fetched above to make the up-to-date decision).
    let spinner = progress::spinner(format!("downloading {asset} ({remote_label})…"));
    let bytes = (async {
        client
            .get(bin_url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("no release asset at {bin_url}"))?
            .bytes()
            .await
            .map_err(Error::from)
    })
    .await;
    spinner.finish_and_clear();
    let bytes = bytes.context("download failed")?;

    // Verify the download against the checksum we already fetched and validated.
    let actual = sha256_hex(&bytes);
    if actual != expected {
        anyhow::bail!(
            "checksum mismatch for {asset}\n  expected: {expected}\n  got:      {actual}"
        );
    }

    // Stage the new binary in a temp file, make it executable, then atomically
    // swap it in for the running binary (handles the "can't overwrite a running
    // executable" problem via rename).
    let tmp = std::env::temp_dir().join(format!("{asset}.new"));
    std::fs::write(&tmp, &bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .context("failed to set executable permissions on the downloaded binary")?;
    }
    self_replace::self_replace(&tmp).context("failed to replace the running binary")?;
    let _ = std::fs::remove_file(&tmp);

    println!("updated rayfish v{current} → {remote_label}");

    // If the service is installed, the daemon is still running the old binary.
    // Go through the full install path: rewrite the unit (its exec path may have
    // changed when `ray update` runs from a different location than the
    // installed binary) and fully reload it via unload+load (launchctl) /
    // daemon-reload+restart (systemd) so the service manager honors the
    // rewritten unit. A bare `kickstart`/in-place restart would relaunch the
    // stale cached unit, leaving the daemon on the old binary. `wait_for_daemon`
    // then confirms the new daemon actually comes up.
    if service_installed {
        install_and_start_service(None).await
    } else {
        println!("run `sudo ray up` to start the service with the new binary");
        Ok(())
    }
}

/// Best-effort fetch of the running daemon's compiled version over IPC.
/// Returns `None` if no daemon is reachable or it predates the version field
/// (empty string). Used by `ray update --check` and never fails the caller.
pub(crate) async fn daemon_version() -> Option<String> {
    let mut stream = ipc::connect().await.ok()?;
    ipc::send(&mut stream, ipc::IpcMessage::Status).await.ok()?;
    match ipc::recv(&mut stream).await.ok()? {
        ipc::IpcMessage::StatusResponse { daemon_version, .. } if !daemon_version.is_empty() => {
            Some(daemon_version)
        }
        _ => None,
    }
}

/// How long to wait for a freshly (re)started daemon to accept IPC before
/// declaring it unreachable. Must comfortably exceed the service manager's
/// stop-then-relaunch latency (SIGTERM → exit → respawn); the old 8s value was
/// shorter than an ungraceful shutdown could take, so a healthy daemon was
/// reported as "never became reachable" and a re-run would kill the one that
/// had just come up.
pub(crate) const DAEMON_REACHABLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll the IPC socket until the daemon answers or the deadline passes.
pub(crate) async fn wait_for_daemon(timeout: Duration) -> Option<ipc::IpcFramed> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(stream) = ipc::connect().await {
            return Some(stream);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Print the last few lines of the daemon log so a failed startup is diagnosable.
pub(crate) fn print_daemon_log_tail() {
    #[cfg(target_os = "macos")]
    {
        let path = "/var/log/rayfish.log";
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let tail: Vec<&str> = contents.lines().rev().take(15).collect();
                if tail.is_empty() {
                    eprintln!("\n(daemon log {path} is empty)");
                } else {
                    eprintln!("\nLast lines of {path}:");
                    for line in tail.into_iter().rev() {
                        eprintln!("  {line}");
                    }
                }
            }
            Err(e) => eprintln!("\n(could not read daemon log {path}: {e})"),
        }
    }

    #[cfg(target_os = "linux")]
    {
        eprintln!("\nRecent daemon log (journalctl -u rayfish):");
        run_cmd("journalctl", &["-u", "rayfish", "-n", "15", "--no-pager"]);
    }
}

#[allow(dead_code)]
pub(crate) fn run_cmd(program: &str, args: &[&str]) {
    match Command::new(program).args(args).status() {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("warning: `{program}` exited with {status}"),
        Err(e) => eprintln!("warning: failed to run `{program}`: {e}"),
    }
}

/// Run a command, ignoring its exit status (used for best-effort teardown).
#[allow(dead_code)]
pub(crate) fn run_cmd_quiet(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub(crate) fn cmd_uninstall_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = Path::new("/etc/systemd/system/rayfish.service");
        if path.exists() {
            run_cmd("systemctl", &["disable", "--now", "rayfish"]);
            std::fs::remove_file(path)?;
            run_cmd("systemctl", &["daemon-reload"]);
            println!("Removed systemd service.");
        } else {
            println!("Service not installed.");
        }
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let path = Path::new("/Library/LaunchDaemons/com.rayfish.vpn.plist");
        if path.exists() {
            run_cmd("launchctl", &["unload", "-w", &path.to_string_lossy()]);
            std::fs::remove_file(path)?;
            println!("Removed launchd daemon.");
        } else {
            println!("Service not installed.");
        }
        return Ok(());
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("service uninstallation not supported on this platform");
    }
}

