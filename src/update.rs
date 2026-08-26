//! Reusable self-update engine shared by the `ray update` CLI and the daemon's
//! opt-in auto-updater. Pure GitHub-release plumbing: resolve a release, fetch
//! and verify its SHA-256 sidecar, and atomically swap the running binary (or
//! stage a verified MSI on Windows). No
//! printing, no root checks, no service restart - those belong to the callers
//! (the CLI in `src/cli/update.rs`, the daemon task in `src/daemon`).

#[cfg(windows)]
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Stdio;

#[cfg(target_os = "linux")]
use crate::init_system::InitSystem;
use anyhow::{Context, Error, Result};
use reqwest::{Client, RequestBuilder};
use semver::Version;

/// GitHub `owner/repo` the release binaries are published under (the same repo
/// `install.sh` pulls from).
pub const REPO_SLUG: &str = "rayfish/rayfish";

/// Map the host OS/arch to the release asset name CI publishes
/// (`ray-{os}-{arch}`, e.g. `ray-linux-x86_64`). Errors on platforms we don't
/// build binaries for, so the user falls back to building from source.
///
/// On Linux the libc flavour is a compile-time fact of the running binary, not
/// of the host: a binary built against musl self-updates to the `-musl` asset
/// (which runs on any Linux) and a glibc binary to the plain gnu asset. Getting
/// this wrong would hand a musl-only host a glibc binary that can't start.
pub fn release_asset_name(os: &str, arch: &str) -> Result<String> {
    if os == "windows" {
        if arch != "x86_64" {
            anyhow::bail!("no rayfish Windows MSI for architecture '{arch}'; build from source");
        }
        return Ok("ray-windows-x86_64.msi".to_string());
    }
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
    let libc = if cfg!(all(target_os = "linux", target_env = "musl")) {
        "-musl"
    } else {
        ""
    };
    Ok(format!("ray-{os}-{arch}{libc}"))
}

/// Parse a release version sidecar. Windows MSI assets use this because the
/// installer checksum cannot be compared with the installed `ray.exe` bytes.
pub fn parse_version_manifest(text: &str) -> Result<String> {
    let version = text.trim();
    Version::parse(version)
        .with_context(|| format!("invalid release version sidecar: {version:?}"))?;
    Ok(version.to_owned())
}

/// Parse the single release-identity line returned by the Windows registry
/// query. Multiple Rayfish entries are ambiguous and fail closed.
pub fn parse_installed_version(output: &str) -> Result<Option<String>> {
    let versions: Vec<_> = output
        .lines()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    match versions.as_slice() {
        [] => Ok(None),
        [version] => parse_version_manifest(version).map(Some),
        _ => anyhow::bail!("multiple Rayfish MSI versions are installed"),
    }
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

/// SHA-256 of a byte slice as lowercase hex, used both to verify a download
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
/// api.github.com calls: the release-asset downloads on github.com aren't
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
/// `install_default` errors only if one is already set (harmless, so ignore it).
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

/// Fetch and validate a release asset's version sidecar.
pub async fn fetch_version_manifest(client: &Client, tag: &str, asset: &str) -> Result<String> {
    let url = format!("{}.version", asset_download_url(tag, asset));
    let text = client
        .get(&url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("no version manifest at {url}"))?
        .text()
        .await
        .context("failed to fetch the published version manifest")?;
    parse_version_manifest(&text)
}

#[cfg(windows)]
pub fn installed_msi_version() -> Result<Option<String>> {
    let output = Command::new("powershell.exe")
        .creation_flags(0x0800_0000)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$identity=(Get-ItemProperty -LiteralPath 'HKLM:\\Software\\Rayfish' -Name ReleaseIdentity -ErrorAction SilentlyContinue).ReleaseIdentity; if ($identity) { $identity } else { @(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Where-Object { $_.DisplayName -eq 'Rayfish' } | Select-Object -ExpandProperty DisplayVersion) }",
        ])
        .output()
        .context("query installed Rayfish MSI version")?;
    anyhow::ensure!(
        output.status.success(),
        "Windows registry query for Rayfish MSI failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    parse_installed_version(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(windows)]
pub async fn download_msi_to_temp(
    client: &Client,
    bin_url: &str,
    expected: &str,
    asset: &str,
) -> Result<PathBuf> {
    let bytes = client
        .get(bin_url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("no release asset at {bin_url}"))?
        .bytes()
        .await
        .map_err(Error::from)
        .context("MSI download failed")?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        anyhow::bail!(
            "checksum mismatch for {asset}\n  expected: {expected}\n  got:      {actual}"
        );
    }
    let path = random_system_stage_path("rayfish-update", ".msi");
    let mut file = crate::windows_security::create_protected_new_file(&path)?;
    let write_result = (|| -> Result<()> {
        file.write_all(&bytes)
            .with_context(|| format!("write protected MSI stage {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("flush protected MSI stage {}", path.display()))
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

#[cfg(windows)]
pub fn msi_install_args(path: &Path, log: &Path) -> [String; 6] {
    [
        "/i".to_string(),
        path.to_string_lossy().into_owned(),
        "/qn".to_string(),
        "/norestart".to_string(),
        "/L*v".to_string(),
        log.to_string_lossy().into_owned(),
    ]
}

#[cfg(windows)]
fn system_temp_dir() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| root.join("Temp"))
        .unwrap_or_else(std::env::temp_dir)
}

#[cfg(windows)]
fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let bits = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        encoded.push(TABLE[((bits >> 18) & 0x3f) as usize] as char);
        encoded.push(TABLE[((bits >> 12) & 0x3f) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            TABLE[((bits >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            TABLE[(bits & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

#[cfg(windows)]
fn encoded_powershell_command(script: &str) -> Command {
    let utf16le: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut command = Command::new("powershell.exe");
    command.creation_flags(0x0800_0000).args([
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        &base64_encode(&utf16le),
    ]);
    command
}

#[cfg(windows)]
fn random_system_stage_path(prefix: &str, suffix: &str) -> PathBuf {
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    system_temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
}

#[cfg(windows)]
fn sha256_reader(mut reader: impl Read) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .context("read staged MSI for SHA-256")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(windows)]
pub fn msi_failure_message(code: Option<i32>) -> String {
    match code {
        Some(1603) => "Windows Installer failed with exit code 1603; confirm this helper is elevated and inspect the retained MSI log for the failing custom action or locked file".to_string(),
        Some(1638) => "Windows Installer failed with exit code 1638; another Rayfish version is registered and the MSI upgrade ordering or UpgradeCode is incompatible".to_string(),
        Some(code) => format!("Windows Installer failed with exit code {code}; inspect the retained MSI log"),
        None => "Windows Installer terminated without an exit code; inspect the retained MSI log".to_string(),
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MsiInstallOutcome {
    Installed,
    RebootRequired(i32),
}

#[cfg(windows)]
fn classify_msi_exit_code(code: Option<i32>) -> Result<MsiInstallOutcome> {
    match code {
        Some(0) => Ok(MsiInstallOutcome::Installed),
        Some(code @ (1641 | 3010)) => Ok(MsiInstallOutcome::RebootRequired(code)),
        code => anyhow::bail!("{}", msi_failure_message(code)),
    }
}

#[cfg(windows)]
fn install_msi(path: &Path, log: &Path) -> Result<MsiInstallOutcome> {
    let mut command = Command::new("msiexec.exe");
    let args = msi_install_args(path, log);
    command.creation_flags(0x0800_0000).args(args);
    let status = command.status().context("launch Windows Installer")?;
    classify_msi_exit_code(status.code())
        .with_context(|| format!("Windows MSI installation failed; log: {}", log.display()))
}

#[cfg(windows)]
fn wait_for_parent(parent_pid: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_FAILED, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};

    let handle = unsafe { OpenProcess(0x0010_0000, 0, parent_pid) };
    if handle.is_null() {
        return Ok(());
    }
    let wait = unsafe { WaitForSingleObject(handle, 120_000) };
    unsafe { CloseHandle(handle) };
    anyhow::ensure!(
        wait != WAIT_FAILED,
        "wait for updater parent process failed"
    );
    anyhow::ensure!(
        wait != WAIT_TIMEOUT,
        "timed out waiting for updater parent process to exit"
    );
    Ok(())
}

#[cfg(windows)]
fn updater_helper_args(
    path: &Path,
    release_identity: &str,
    expected_sha256: &str,
    parent_pid: u32,
) -> [std::ffi::OsString; 8] {
    [
        "windows-update-helper".into(),
        "--msi".into(),
        path.as_os_str().to_owned(),
        "--identity".into(),
        release_identity.into(),
        "--sha256".into(),
        expected_sha256.into(),
        format!("--parent-pid={parent_pid}").into(),
    ]
}

/// Copy this verified binary to the system temp directory and detach it. Both
/// manual updates and daemon auto-updates use this exact scheduling path.
#[cfg(windows)]
pub fn schedule_msi_update(
    path: &Path,
    release_identity: &str,
    expected_sha256: &str,
) -> Result<PathBuf> {
    let helper_dir = system_temp_dir();
    let helper = random_system_stage_path("rayfish-updater", ".exe");
    let result = (|| -> Result<()> {
        std::fs::create_dir_all(&helper_dir)
            .with_context(|| format!("create system temp directory {}", helper_dir.display()))?;
        let mut source = std::fs::File::open(std::env::current_exe()?)
            .context("open current executable for updater staging")?;
        let mut staged_helper = crate::windows_security::create_protected_new_file(&helper)?;
        std::io::copy(&mut source, &mut staged_helper)
            .with_context(|| format!("copy updater helper to {}", helper.display()))?;
        staged_helper
            .sync_all()
            .with_context(|| format!("flush updater helper {}", helper.display()))?;
        drop(staged_helper);
        let helper_guard = crate::windows_security::open_protected_file_no_follow(&helper)?;
        Command::new(&helper)
            .creation_flags(0x0800_0000 | 0x0000_0008 | 0x0000_0200)
            .args(updater_helper_args(
                path,
                release_identity,
                expected_sha256,
                std::process::id(),
            ))
            .spawn()
            .context("launch detached Windows updater helper")?;
        drop(helper_guard);
        Ok(())
    })();
    if let Err(error) = result {
        cleanup_scheduling_failure(path, &helper);
        return Err(error);
    }
    Ok(helper)
}

#[cfg(windows)]
fn cleanup_scheduling_failure(msi: &Path, helper: &Path) {
    let _ = std::fs::remove_file(helper);
    let _ = std::fs::remove_file(msi);
}

#[cfg(windows)]
fn pending_reboot_script() -> &'static str {
    "$ErrorActionPreference='Stop'; & { param([string]$Identity, [int]$Code) $key='HKLM:\\Software\\Rayfish'; if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key | Out-Null }; New-ItemProperty -Path $key -Name PendingRebootIdentity -Value $Identity -PropertyType String -Force | Out-Null; New-ItemProperty -Path $key -Name PendingRebootCode -Value $Code -PropertyType DWord -Force | Out-Null } -Identity $env:RAYFISH_PENDING_IDENTITY -Code ([int]$env:RAYFISH_PENDING_CODE)"
}

#[cfg(windows)]
fn pending_reboot_command(release_identity: &str, code: i32) -> Command {
    let mut command = encoded_powershell_command(pending_reboot_script());
    command
        .env("RAYFISH_PENDING_IDENTITY", release_identity)
        .env("RAYFISH_PENDING_CODE", code.to_string());
    command
}

#[cfg(windows)]
fn update_pending_reboot_state(release_identity: &str, code: i32) -> Result<()> {
    let output = pending_reboot_command(release_identity, code)
        .output()
        .context("record pending Rayfish reboot state")?;
    anyhow::ensure!(
        output.status.success(),
        "record pending Rayfish reboot state failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(windows)]
fn clear_pending_reboot_script() -> &'static str {
    "$ErrorActionPreference='Stop'; $path='HKLM:\\Software\\Rayfish'; if (Test-Path -LiteralPath $path) { $key=Get-Item -LiteralPath $path -ErrorAction Stop; foreach($name in @('PendingRebootIdentity','PendingRebootCode','PendingRebootLog')) { if ($key.GetValueNames() -contains $name) { Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop } } }"
}

#[cfg(windows)]
fn clear_pending_reboot_state() -> Result<()> {
    let output = encoded_powershell_command(clear_pending_reboot_script())
        .output()
        .context("clear pending Rayfish reboot state")?;
    anyhow::ensure!(
        output.status.success(),
        "clear pending Rayfish reboot state failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(windows)]
fn update_failure_script() -> &'static str {
    "$ErrorActionPreference='Stop'; & { param([string]$Identity, [string]$Message, [string]$Log) $key='HKLM:\\Software\\Rayfish'; if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key | Out-Null }; New-ItemProperty -Path $key -Name UpdateFailureIdentity -Value $Identity -PropertyType String -Force | Out-Null; New-ItemProperty -Path $key -Name UpdateFailureMessage -Value $Message -PropertyType String -Force | Out-Null; New-ItemProperty -Path $key -Name UpdateFailureLog -Value $Log -PropertyType String -Force | Out-Null; New-ItemProperty -Path $key -Name UpdateFailureTimestamp -Value ([DateTimeOffset]::UtcNow.ToString('o')) -PropertyType String -Force | Out-Null } -Identity $env:RAYFISH_FAILURE_IDENTITY -Message $env:RAYFISH_FAILURE_MESSAGE -Log $env:RAYFISH_FAILURE_LOG"
}

#[cfg(windows)]
fn update_failure_command(release_identity: &str, message: &str, log: Option<&Path>) -> Command {
    let mut command = encoded_powershell_command(update_failure_script());
    command
        .env("RAYFISH_FAILURE_IDENTITY", release_identity)
        .env("RAYFISH_FAILURE_MESSAGE", message)
        .env(
            "RAYFISH_FAILURE_LOG",
            log.map(|path| path.as_os_str()).unwrap_or_default(),
        );
    command
}

#[cfg(windows)]
fn record_update_failure_state(
    release_identity: &str,
    message: &str,
    log: Option<&Path>,
) -> Result<()> {
    let output = update_failure_command(release_identity, message, log)
        .output()
        .context("record Windows updater failure state")?;
    anyhow::ensure!(
        output.status.success(),
        "record Windows updater failure state failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(windows)]
fn clear_update_failure_script() -> &'static str {
    "$ErrorActionPreference='Stop'; $path='HKLM:\\Software\\Rayfish'; if (Test-Path -LiteralPath $path) { $key=Get-Item -LiteralPath $path -ErrorAction Stop; foreach($name in @('UpdateFailureIdentity','UpdateFailureMessage','UpdateFailureLog','UpdateFailureTimestamp')) { if ($key.GetValueNames() -contains $name) { Remove-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop } } }"
}

#[cfg(windows)]
fn clear_update_failure_command() -> Command {
    encoded_powershell_command(clear_update_failure_script())
}

#[cfg(windows)]
fn clear_update_failure_state() -> Result<()> {
    let output = clear_update_failure_command()
        .output()
        .context("clear Windows updater failure state")?;
    anyhow::ensure!(
        output.status.success(),
        "clear Windows updater failure state failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(windows)]
struct RemoveFileOnDrop(PathBuf);

#[cfg(windows)]
impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.0)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            let _ = schedule_delete_on_reboot(&self.0);
        }
    }
}

#[cfg(windows)]
fn schedule_delete_on_reboot(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let ok = unsafe { MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
    anyhow::ensure!(
        ok != 0,
        "schedule delete-on-reboot for {} failed: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(windows)]
fn is_staged_updater_helper(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if !parent
        .to_string_lossy()
        .eq_ignore_ascii_case(&system_temp_dir().to_string_lossy())
    {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(nonce) = name
        .strip_prefix("rayfish-updater-")
        .and_then(|name| name.strip_suffix(".exe"))
    else {
        return false;
    };
    nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(windows)]
fn self_delete_script() -> &'static str {
    "$ErrorActionPreference='SilentlyContinue'; & { param([string]$Path, [int]$ProcessId) Wait-Process -Id $ProcessId -ErrorAction SilentlyContinue; for($attempt=0; $attempt -lt 60; $attempt++){ Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue; if(-not (Test-Path -LiteralPath $Path)){ exit 0 }; Start-Sleep -Milliseconds 250 }; exit 1 } -Path $env:RAYFISH_HELPER_PATH -ProcessId ([int]$env:RAYFISH_HELPER_PID)"
}

#[cfg(windows)]
fn self_delete_command(helper: &Path, helper_pid: u32) -> Command {
    let mut command = encoded_powershell_command(self_delete_script());
    command
        .creation_flags(0x0800_0000 | 0x0000_0008 | 0x0000_0200)
        .env("RAYFISH_HELPER_PATH", helper)
        .env("RAYFISH_HELPER_PID", helper_pid.to_string());
    command
}

#[cfg(windows)]
fn schedule_self_delete(helper: &Path) -> Result<()> {
    self_delete_command(helper, std::process::id())
        .spawn()
        .context("schedule updater helper self-delete")?;
    Ok(())
}

#[cfg(windows)]
fn cleanup_helper_log(log: Option<&Path>, success: bool) {
    if success && let Some(log) = log {
        let _ = std::fs::remove_file(log);
    }
}

#[cfg(windows)]
async fn wait_for_daemon_ipc_ready() -> Result<()> {
    wait_for_daemon_ipc_ready_with(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_millis(250),
        || async {
            let stream = ray_proto::ipc::connect().await?;
            drop(stream);
            Ok(())
        },
    )
    .await
}

#[cfg(windows)]
async fn wait_for_daemon_ipc_ready_with<F, Fut>(
    ready_timeout: std::time::Duration,
    retry_delay: std::time::Duration,
    mut connect: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let deadline = tokio::time::Instant::now() + ready_timeout;
    loop {
        let detail = match connect().await {
            Ok(()) => return Ok(()),
            Err(error) => error.to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Rayfish service reached SCM Running but IPC was not ready within {} seconds: {detail}",
                ready_timeout.as_secs_f64()
            );
        }
        tokio::time::sleep(retry_delay).await;
    }
}

/// Detached helper entry point. It waits for the caller/daemon to release the
/// installed executable, runs MSI, restarts the service, then verifies identity.
#[cfg(windows)]
pub async fn run_msi_update_helper(
    msi: &Path,
    release_identity: &str,
    expected_sha256: &str,
    parent_pid: u32,
) -> Result<()> {
    anyhow::ensure!(
        crate::windows_identity::is_current_process_elevated_admin(),
        "Windows update helper requires an elevated Administrator token"
    );
    let helper = std::env::current_exe().context("locate updater helper executable")?;
    anyhow::ensure!(
        is_staged_updater_helper(&helper),
        "refusing updater self-delete outside the protected system-temp staging pattern"
    );
    let _msi_cleanup = RemoveFileOnDrop(msi.to_owned());
    let _helper_cleanup = RemoveFileOnDrop(helper.clone());
    schedule_self_delete(&helper)?;
    let mut log_path = None;
    let result = async {
        wait_for_parent(parent_pid)?;
        let mut staged_msi = crate::windows_security::open_protected_file_no_follow(msi)?;
        let actual_sha256 = sha256_reader(&mut staged_msi)?;
        anyhow::ensure!(
            actual_sha256.eq_ignore_ascii_case(expected_sha256),
            "staged MSI SHA-256 changed before install: expected {expected_sha256}, got {actual_sha256}"
        );
        let log = random_system_stage_path("rayfish-msi-update", ".log");
        drop(crate::windows_security::create_protected_new_file(&log)?);
        log_path = Some(log.clone());
        let outcome = install_msi(msi, &log)?;
        if let MsiInstallOutcome::RebootRequired(code) = outcome {
            update_pending_reboot_state(release_identity, code)?;
            tracing::warn!(
                code,
                identity = release_identity,
                "Windows MSI update succeeded but requires reboot; service reachability and running identity are pending"
            );
            return Ok(());
        }
        clear_pending_reboot_state()?;
        crate::windows_service::start()
            .context("restart rayfish Windows service after MSI update")?;
        wait_for_daemon_ipc_ready().await
            .context("wait for Rayfish service IPC after MSI update")?;
        let installed = installed_msi_version()?
            .context("Rayfish release identity missing after MSI update")?;
        anyhow::ensure!(
            installed == release_identity,
            "installed Rayfish identity {installed:?} does not match expected {release_identity:?}; log: {}",
            log.display()
        );
        clear_update_failure_state()?;
        Ok(())
    }
    .await;
    let result = match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let message = format!("{error:#}");
            match record_update_failure_state(release_identity, &message, log_path.as_deref()) {
                Ok(()) => Err(error),
                Err(record_error) => Err(anyhow::anyhow!(
                    "{message}; additionally failed to record updater failure state: {record_error:#}"
                )),
            }
        }
    };
    cleanup_helper_log(log_path.as_deref(), result.is_ok());
    result
}

#[cfg(not(windows))]
/// Download the release asset, verify it against the (already-fetched)
/// checksum, and atomically swap it in for the running binary. Stages the new
/// binary in a temp file, marks it executable, then `self_replace`s (handles the
/// "can't overwrite a running executable" problem via rename). Does NOT restart
/// any service and prints nothing: callers own presentation and restart.
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
/// On Linux the command comes from the detected init system (see
/// [`InitSystem::detached_restart_command`], which handles systemd's cgroup
/// kill hazard). On macOS `launchctl kickstart -k` asks launchd to do the
/// kill+relaunch, so the client only submits the request.
pub fn trigger_detached_restart() {
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let Some(init) = InitSystem::installed() else {
            tracing::error!("auto-update: no init system found, cannot restart the service");
            return;
        };
        init.detached_restart_command()
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

    #[test]
    fn windows_asset_and_version_contracts_are_stable() {
        assert_eq!(
            release_asset_name("windows", "x86_64").unwrap(),
            "ray-windows-x86_64.msi"
        );
        assert!(release_asset_name("windows", "aarch64").is_err());
        assert_eq!(parse_version_manifest("0.2.17\n").unwrap(), "0.2.17");
        assert_eq!(
            parse_version_manifest("0.2.17-nightly.42+abc12345\n").unwrap(),
            "0.2.17-nightly.42+abc12345"
        );
        assert!(parse_version_manifest("nightly").is_err());
    }

    #[test]
    fn installed_version_parser_is_zero_one_many_and_fail_closed() {
        assert_eq!(parse_installed_version("").unwrap(), None);
        assert_eq!(
            parse_installed_version("0.2.17\r\n").unwrap(),
            Some("0.2.17".to_string())
        );
        assert!(parse_installed_version("0.2.17\n0.2.18").is_err());
        assert!(parse_installed_version("not-a-version").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn msi_install_args_are_quiet_and_no_restart() {
        assert_eq!(
            msi_install_args(
                Path::new(r"C:\Temp\rayfish.msi"),
                Path::new(r"C:\Temp\rayfish.log")
            ),
            [
                "/i".to_string(),
                r"C:\Temp\rayfish.msi".to_string(),
                "/qn".to_string(),
                "/norestart".to_string(),
                "/L*v".to_string(),
                r"C:\Temp\rayfish.log".to_string()
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn msi_failure_message_is_actionable_for_common_upgrade_codes() {
        assert!(msi_failure_message(Some(1603)).contains("elevated"));
        assert!(msi_failure_message(Some(1603)).contains("MSI log"));
        assert!(msi_failure_message(Some(1638)).contains("upgrade ordering"));
        assert!(msi_failure_message(None).contains("without an exit code"));
    }

    #[cfg(windows)]
    #[test]
    fn helper_carries_the_expected_digest_and_uses_unguessable_names() {
        let first = random_system_stage_path("rayfish-update", ".msi");
        let second = random_system_stage_path("rayfish-update", ".msi");
        assert_ne!(first, second);
        let name = first.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("rayfish-update-"));
        assert_eq!(name.len(), "rayfish-update-".len() + 32 + ".msi".len());

        let args = updater_helper_args(
            Path::new(r"C:\Windows\Temp\stage.msi"),
            "0.2.1-nightly.7+abc12345",
            "0123456789abcdef",
            42,
        );
        assert!(args.iter().any(|arg| arg == "0123456789abcdef"));
        assert!(args.iter().any(|arg| arg == "--parent-pid=42"));
    }

    #[cfg(windows)]
    #[test]
    fn helper_rehash_and_reboot_outcome_contracts_are_explicit() {
        let digest = sha256_reader(std::io::Cursor::new(b"verified MSI".as_slice())).unwrap();
        assert_eq!(digest, sha256_hex(b"verified MSI"));
        assert_eq!(
            classify_msi_exit_code(Some(0)).unwrap(),
            MsiInstallOutcome::Installed
        );
        assert_eq!(
            classify_msi_exit_code(Some(3010)).unwrap(),
            MsiInstallOutcome::RebootRequired(3010)
        );
        assert_eq!(
            classify_msi_exit_code(Some(1641)).unwrap(),
            MsiInstallOutcome::RebootRequired(1641)
        );
        assert!(classify_msi_exit_code(Some(1603)).is_err());
        assert!(classify_msi_exit_code(Some(1638)).is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn updater_waits_for_ipc_and_reports_the_last_failure() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&attempts);
        wait_for_daemon_ipc_ready_with(
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(1),
            move || {
                let observed = Arc::clone(&observed);
                async move {
                    if observed.fetch_add(1, Ordering::SeqCst) < 2 {
                        anyhow::bail!("pipe absent")
                    }
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        let error = wait_for_daemon_ipc_ready_with(
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(1),
            || async { anyhow::bail!("pipe still absent") },
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("SCM Running"));
        assert!(message.contains("pipe still absent"));
    }

    #[cfg(windows)]
    #[test]
    fn encoded_powershell_binds_pending_and_self_delete_arguments_via_environment() {
        let identity = "0.2.1-nightly.7+quote'is-data";
        let pending = pending_reboot_command(identity, 3010);
        let pending_env: std::collections::HashMap<_, _> = pending
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect();
        assert_eq!(
            pending_env.get(std::ffi::OsStr::new("RAYFISH_PENDING_IDENTITY")),
            Some(&std::ffi::OsString::from(identity))
        );
        assert_eq!(
            pending_env.get(std::ffi::OsStr::new("RAYFISH_PENDING_CODE")),
            Some(&std::ffi::OsString::from("3010"))
        );
        let pending_args: Vec<_> = pending
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert!(pending_args.iter().any(|arg| arg == "-EncodedCommand"));
        assert!(!pending_args.iter().any(|arg| arg.contains(identity)));
        assert!(pending_reboot_script().contains("if (-not (Test-Path -LiteralPath $key))"));
        assert!(clear_pending_reboot_script().contains("GetValueNames()"));
        assert!(clear_pending_reboot_script().contains("-ErrorAction Stop"));
        assert_eq!(base64_encode(&[b'A', 0]), "QQA=");

        let helper = random_system_stage_path("rayfish-updater", ".exe");
        assert!(is_staged_updater_helper(&helper));
        assert!(!is_staged_updater_helper(Path::new(
            r"C:\Program Files\Rayfish\ray.exe"
        )));
        let cleanup = self_delete_command(&helper, 42);
        assert!(self_delete_script().contains("Wait-Process -Id $ProcessId"));
        assert!(!self_delete_script().contains("-Timeout"));
        let cleanup_env: std::collections::HashMap<_, _> = cleanup
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect();
        assert_eq!(
            cleanup_env.get(std::ffi::OsStr::new("RAYFISH_HELPER_PATH")),
            Some(&helper.into_os_string())
        );
        assert_eq!(
            cleanup_env.get(std::ffi::OsStr::new("RAYFISH_HELPER_PID")),
            Some(&std::ffi::OsString::from("42"))
        );

        let failure = update_failure_command(
            identity,
            "IPC timeout; quote'is-data",
            Some(Path::new(r"C:\Windows\Temp\update.log")),
        );
        let failure_env: std::collections::HashMap<_, _> = failure
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect();
        assert_eq!(
            failure_env.get(std::ffi::OsStr::new("RAYFISH_FAILURE_IDENTITY")),
            Some(&std::ffi::OsString::from(identity))
        );
        assert_eq!(
            failure_env.get(std::ffi::OsStr::new("RAYFISH_FAILURE_MESSAGE")),
            Some(&std::ffi::OsString::from("IPC timeout; quote'is-data"))
        );
        for property in [
            "UpdateFailureIdentity",
            "UpdateFailureMessage",
            "UpdateFailureLog",
            "UpdateFailureTimestamp",
        ] {
            assert!(update_failure_script().contains(property));
            assert!(clear_update_failure_script().contains(property));
        }
        assert!(update_failure_script().contains("if (-not (Test-Path -LiteralPath $key))"));
        assert!(clear_update_failure_script().contains("GetValueNames()"));
        assert!(clear_update_failure_script().contains("-ErrorAction Stop"));
        assert!(
            clear_update_failure_command()
                .get_args()
                .any(|argument| argument == "-EncodedCommand")
        );
    }

    #[cfg(windows)]
    #[test]
    fn updater_cleanup_policy_removes_success_artifacts_and_preserves_failure_log() {
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let msi = std::env::temp_dir().join(format!("rayfish-cleanup-{nonce}.msi"));
        let helper = std::env::temp_dir().join(format!("rayfish-cleanup-{nonce}.exe"));
        std::fs::write(&msi, b"msi").unwrap();
        std::fs::write(&helper, b"helper").unwrap();
        cleanup_scheduling_failure(&msi, &helper);
        assert!(!msi.exists());
        assert!(!helper.exists());

        let log = std::env::temp_dir().join(format!("rayfish-cleanup-{nonce}.log"));
        std::fs::write(&log, b"log").unwrap();
        cleanup_helper_log(Some(&log), false);
        assert!(log.exists());
        cleanup_helper_log(Some(&log), true);
        assert!(!log.exists());

        let guarded = std::env::temp_dir().join(format!("rayfish-cleanup-{nonce}.guard"));
        std::fs::write(&guarded, b"guarded").unwrap();
        {
            let _cleanup = RemoveFileOnDrop(guarded.clone());
        }
        assert!(!guarded.exists());
    }
}
