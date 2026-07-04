//! Reusable self-update engine shared by the `ray update` CLI and the daemon's
//! opt-in auto-updater. Pure GitHub-release plumbing: resolve a release, fetch
//! and verify its SHA-256 sidecar, and atomically swap the running binary. No
//! printing, no root checks, no service restart — those belong to the callers
//! (the CLI in `src/cli/update.rs`, the daemon task in `src/daemon`).

use std::process::{Command, Stdio};

use anyhow::{Context, Error, Result};
use reqwest::{Client, RequestBuilder};
use semver::Version;

/// GitHub `owner/repo` the release binaries are published under (the same repo
/// `install.sh` pulls from).
pub const REPO_SLUG: &str = "rayfish/rayfish";

/// Map the host OS/arch to the release asset name CI publishes
/// (`ray-{os}-{arch}`, e.g. `ray-linux-x86_64`). Errors on platforms we don't
/// build binaries for, so the user falls back to building from source.
pub fn release_asset_name(os: &str, arch: &str) -> Result<String> {
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
/// `CARGO_PKG_VERSION` (`v0.1.0` -> `0.1.0`).
pub fn normalize_version(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// Whether `latest` is a strictly newer semver than `current`. Falls back to a
/// plain string inequality if either side fails to parse, so an unusual tag
/// still triggers an update rather than being silently ignored.
pub fn version_is_newer(latest: &str, current: &str) -> bool {
    match (Version::parse(latest), Version::parse(current)) {
        (Ok(l), Ok(c)) => l > c,
        _ => latest != current,
    }
}

/// SHA-256 of a byte slice as lowercase hex — used both to verify a download
/// and to fingerprint the running binary on the nightly channel.
pub fn sha256_hex(bytes: &[u8]) -> String {
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
pub fn github_token() -> Option<String> {
    for var in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    // `gh auth token` prints the active token to stdout (and exits non-zero if
    // `gh` is unauthenticated). A missing `gh` makes `output()` error -> `None`.
    let out = Command::new("gh").args(["auth", "token"]).output().ok()?;
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
pub fn authed(req: RequestBuilder, token: &Option<String>) -> RequestBuilder {
    match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}

#[derive(serde::Deserialize)]
pub struct GhRelease {
    pub tag_name: String,
    /// The release's display name. For the rolling nightly this carries the
    /// source commit (`nightly (abc12345)`), so we surface it instead of the
    /// bare `nightly` tag.
    #[serde(default)]
    pub name: Option<String>,
    /// Whether GitHub marks this a pre-release (nightlies and `-rc`/`-` tags),
    /// used to annotate `ray update --list`.
    #[serde(default)]
    pub prerelease: bool,
    /// The release notes (git-cliff renders these from conventional commits in
    /// `release.yml`). Printed by `ray update` so the user sees what each pending
    /// version changes; `None`/empty for releases without notes.
    #[serde(default)]
    pub body: Option<String>,
}

/// Build the HTTP client used for all release queries + downloads. reqwest is
/// built with `rustls-no-provider`, so it relies on a process-level default
/// CryptoProvider; install ring (already in the tree via iroh) before building.
/// `install_default` errors only if one is already set — harmless, so ignore it.
pub fn build_http_client() -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::builder()
        .user_agent(concat!("ray/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")
}

/// Resolve the latest published **stable** release. GitHub's `/releases/latest`
/// excludes pre-releases by definition, so nightlies are never returned.
pub async fn resolve_stable_release(client: &Client, token: &Option<String>) -> Result<GhRelease> {
    let api = format!("https://api.github.com/repos/{REPO_SLUG}/releases/latest");
    let release: GhRelease = authed(client.get(&api), token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed to query the GitHub releases API (is a release published yet?)")?;
    Ok(release)
}

/// The github.com download URL for a release asset.
pub fn asset_download_url(tag: &str, asset: &str) -> String {
    format!("https://github.com/{REPO_SLUG}/releases/download/{tag}/{asset}")
}

/// Fetch and parse the published `.sha256` sidecar for a release asset. The
/// first whitespace field is the digest. Bails if none is published (aborting a
/// swap we can't verify).
pub async fn fetch_checksum(client: &Client, tag: &str, asset: &str) -> Result<String> {
    let sha_url = format!("{}.sha256", asset_download_url(tag, asset));
    let sha_text = client
        .get(&sha_url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("no checksum at {sha_url}"))?
        .text()
        .await
        .context("failed to fetch the published checksum")?;
    let expected = sha_text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    if expected.is_empty() {
        anyhow::bail!("no checksum published for {asset}; aborting for safety");
    }
    Ok(expected)
}

/// Download the release asset, verify it against the (already-fetched)
/// checksum, and atomically swap it in for the running binary. Stages the new
/// binary in a temp file, marks it executable, then `self_replace`s (handles the
/// "can't overwrite a running executable" problem via rename). Does NOT restart
/// any service and prints nothing — callers own presentation and restart.
pub async fn download_and_swap(
    client: &Client,
    bin_url: &str,
    expected: &str,
    asset: &str,
) -> Result<()> {
    let bytes = client
        .get(bin_url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("no release asset at {bin_url}"))?
        .bytes()
        .await
        .map_err(Error::from)
        .context("download failed")?;

    let actual = sha256_hex(&bytes);
    if actual != expected {
        anyhow::bail!(
            "checksum mismatch for {asset}\n  expected: {expected}\n  got:      {actual}"
        );
    }

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
    Ok(())
}

/// Whether the auto-updater should attempt `target` now, given the last target
/// it tried and when. Refuses a repeat of the *same* target inside `backoff_secs`
/// so a swapped binary that keeps reporting an older/equal version than the
/// release advertises is retried at most once per window instead of tight-looping
/// download + restart. A different (newer) target is always allowed through.
pub fn should_attempt_target(
    target: &str,
    last_target: Option<&str>,
    last_attempt_unix: Option<i64>,
    now_unix: i64,
    backoff_secs: i64,
) -> bool {
    match (last_target, last_attempt_unix) {
        (Some(t), Some(at)) if t == target => now_unix.saturating_sub(at) >= backoff_secs,
        _ => true,
    }
}

/// Trigger a restart of the installed rayfish service from *inside* the daemon,
/// without waiting (the daemon is the process being restarted, so it can't wait
/// for itself). Fire-and-forget and detached.
///
/// On Linux the restart runs in a transient `systemd-run --scope` unit so it is
/// **outside** `rayfish.service`'s cgroup: the service teardown
/// (`KillMode=control-group`) can't kill this client before it enqueues the
/// restart job with PID 1. On macOS `launchctl kickstart -k` asks launchd to do
/// the kill+relaunch, so the client only submits the request and no in-cgroup
/// kill hazard exists.
pub fn trigger_detached_restart() {
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = Command::new("systemd-run");
        c.args(["--scope", "systemctl", "restart", "rayfish"]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("launchctl");
        c.args(["kickstart", "-k", "system/com.rayfish.vpn"]);
        c
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        tracing::error!("auto-update: self-restart not supported on this platform");
        return;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(_) => tracing::info!("auto-update: service restart scheduled"),
            Err(e) => {
                tracing::error!(error = %e, "auto-update: failed to schedule service restart")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_a_fresh_target() {
        // Never attempted before -> allowed.
        assert!(should_attempt_target("v1.0.0", None, None, 1000, 86_400));
    }

    #[test]
    fn attempts_a_different_target_immediately() {
        // A newer target than the last one is allowed even within the window.
        assert!(should_attempt_target(
            "v2.0.0",
            Some("v1.0.0"),
            Some(1000),
            1001,
            86_400
        ));
    }

    #[test]
    fn backs_off_repeat_of_same_target_inside_window() {
        // Same target, only 1s later, 24h window -> refused (no tight loop).
        assert!(!should_attempt_target(
            "v1.0.0",
            Some("v1.0.0"),
            Some(1000),
            1001,
            86_400
        ));
    }

    #[test]
    fn retries_same_target_after_window() {
        // Same target but the backoff window has elapsed -> allowed again.
        assert!(should_attempt_target(
            "v1.0.0",
            Some("v1.0.0"),
            Some(1000),
            1000 + 86_400,
            86_400
        ));
    }
}
