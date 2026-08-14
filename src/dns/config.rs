//! OS-level DNS resolver configuration for Magic DNS.
//!
//! Configures the system to route `.ray` queries to our local resolver at 100.100.100.53:53.
//! macOS: SCDynamicStore with session keys (auto-cleanup on process exit).
//! Linux: systemd-resolved / resolvconf / direct /etc/resolv.conf.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::path::Path;
// Only the macOS/Linux configurators build resolver/backup file paths; Android
// does no OS-level DNS configuration.
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::PathBuf;

#[allow(unused_imports)]
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use zbus::Connection;
#[cfg(target_os = "linux")]
use zbus::zvariant::Value;

use crate::DNS_DOMAIN;

// Must equal dns::MAGIC_DNS_V4.
const RESOLVER_IP: &str = "100.100.100.53";

#[async_trait]
pub trait DnsConfigurator: Send + Sync {
    async fn apply(&self) -> Result<()>;
    async fn revert(&self) -> Result<()>;
    fn name(&self) -> &'static str;
    /// Return the upstream DNS servers captured from the system before rayfish
    /// overwrote resolv.conf. Used by the resolver forwarder (Task 11).
    /// Default: empty (all other configurators use split-DNS and don't capture).
    fn captured_upstreams(&self) -> Vec<Ipv4Addr> {
        Vec::new()
    }
    /// Search domains this configurator wrote into resolv.conf (direct mode
    /// only). Threaded into the re-assert loop so a trample-repair preserves
    /// them instead of dropping back to a bare `nameserver` line.
    /// Default: empty (split-DNS backends manage search domains out of band).
    fn search_domains(&self) -> Vec<String> {
        Vec::new()
    }
    /// The real resolver listed after ours in resolv.conf (direct mode only), so
    /// the host still resolves names if our resolver stops answering. Threaded
    /// into the re-assert loop so a trample-repair rewrites the same file we
    /// installed. Default: none (split-DNS backends don't write the file).
    fn fallback_upstream(&self) -> Option<Ipv4Addr> {
        None
    }
}

/// Revert a DNS configuration.
pub async fn revert(configurator: &dyn DnsConfigurator) -> Result<()> {
    configurator.revert().await
}

pub async fn detect_and_configure(tun_name: &str) -> Result<Box<dyn DnsConfigurator>> {
    // Only the macOS/Linux branches consume `tun_name`; on any other target
    // (e.g. Android) the function falls through to the unsupported-platform bail.
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = tun_name;

    #[cfg(target_os = "macos")]
    {
        let _ = tun_name;
        let configurator = MacosDynamicStoreDns::new();
        configurator.apply().await?;
        return Ok(Box::new(configurator));
    }

    #[cfg(target_os = "linux")]
    {
        // Every backend below hands `.ray` to a DNS manager, which only helps if
        // the C library actually asks that manager. When resolved is running but
        // out of the resolution path, all three resolved-backed paths (D-Bus,
        // resolvectl, and the resolvconf shim that redirects into resolved) apply
        // cleanly and resolve nothing: `resolvectl query x.ray` answers while
        // `getent hosts x.ray` fails. Skip them so we fall through to writing
        // resolv.conf ourselves, which is what the host is really reading.
        let resolved_in_path = resolved_is_in_resolution_path().await;
        if !resolved_in_path {
            tracing::info!(
                "systemd-resolved is not in this host's resolution path \
                 (/etc/resolv.conf does not point at the stub and nsswitch.conf has no \
                 `resolve`); configuring /etc/resolv.conf directly instead"
            );
        }

        if resolved_in_path && let Some(c) = try_systemd_resolved_dbus(tun_name).await {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        if let Some(c) = try_networkmanager_dbus(tun_name).await {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        if resolved_in_path && let Some(c) = try_systemd_resolved_cli(tun_name) {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        if (resolved_in_path || !resolvconf_is_resolved_shim())
            && let Some(c) = try_resolvconf()
        {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        let c = DirectResolvConf::new().await;
        c.apply().await?;
        return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
    }

    #[cfg(windows)]
    {
        let configurator = WindowsDns::new(tun_name).await?;
        configurator.apply().await?;
        return Ok(Box::new(configurator));
    }

    #[allow(unreachable_code)]
    {
        anyhow::bail!("DNS configuration not supported on this platform");
    }
}

pub fn restore_stale_backups() {
    // macOS: clean up leftover /etc/resolver/pi from the old file-based approach.
    // SCDynamicStore session keys self-clean, so this is only needed once after upgrade.
    #[cfg(target_os = "macos")]
    {
        let resolver_file = PathBuf::from(format!("/etc/resolver/{DNS_DOMAIN}"));
        let backup = PathBuf::from(format!("/etc/resolver/{DNS_DOMAIN}.before-rayfish"));
        if backup.exists() {
            tracing::info!("removing stale /etc/resolver backup from old DNS approach");
            let _ = std::fs::copy(&backup, &resolver_file);
            let _ = std::fs::remove_file(&backup);
        }
        if resolver_file.exists()
            && let Ok(content) = std::fs::read_to_string(&resolver_file)
            && content.contains("rayfish")
        {
            tracing::info!("removing old /etc/resolver/{DNS_DOMAIN} (migrated to SCDynamicStore)");
            let _ = std::fs::remove_file(&resolver_file);
        }
    }

    // Linux: backup files may be left from a previous crash.
    #[cfg(target_os = "linux")]
    {
        let path = PathBuf::from("/etc/resolv.conf");
        let backup = backup_path(&path);
        if backup.exists() {
            tracing::info!(path = %path.display(), "restoring stale DNS backup from previous crash");
            if let Err(e) = std::fs::copy(&backup, &path) {
                tracing::warn!(error = %e, "failed to restore DNS backup");
            }
            let _ = std::fs::remove_file(&backup);
        }
        // Drop a stale `dns=none` NM snippet left by a hard kill (a panic would
        // have cleaned it via emergency_restore_resolv_conf). Marker-guarded so
        // we never touch an operator's own NM config. If we're about to
        // re-activate, apply() reinstalls it; if we boot into standby, this stops
        // NM staying quieted while the VPN is down.
        if std::fs::read_to_string(NM_DROPIN)
            .map(|c| resolv_conf_is_ours(&c))
            .unwrap_or(false)
        {
            tracing::info!("removing stale NetworkManager dns=none drop-in from previous crash");
            let _ = std::fs::remove_file(NM_DROPIN);
        }
    }
}

/// Update system DNS routing so bare hostnames resolve. Configures search
/// domains (`<network>.ray`, then `ray`) so a bare `<host>` is tried as
/// `<host>.<network>.ray` and `<host>.ray`; `.ray` itself is the only domain
/// routed to us. Bare network names are deliberately never registered: a
/// network called `dev` would otherwise capture every `*.dev` lookup.
/// Call whenever networks are joined or left.
pub async fn update_search_domains(network_names: &[String], tun_name: &str) {
    let mut search: Vec<String> = network_names
        .iter()
        .map(|n| format!("{n}.{DNS_DOMAIN}"))
        .collect();
    search.push(DNS_DOMAIN.to_string());

    if let Err(e) = set_search_domains(&search, tun_name).await {
        tracing::warn!(error = %e, "failed to update search domains");
    } else {
        tracing::info!(search = ?search, "updated search domains");
    }
}

/// Remove all rayfish search domains (called on daemon shutdown).
pub async fn clear_search_domains(tun_name: &str) {
    if let Err(e) = set_search_domains(&[], tun_name).await {
        tracing::warn!(error = %e, "failed to clear search domains");
    }
}

async fn set_search_domains(rayfish_domains: &[String], tun_name: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = tun_name;
        write_dns_config_macos(rayfish_domains)
    }
    #[cfg(target_os = "linux")]
    {
        set_search_domains_linux(rayfish_domains, tun_name).await
    }
    #[cfg(windows)]
    {
        set_search_domains_windows(rayfish_domains, network_names, tun_name).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (rayfish_domains, tun_name);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windows: Wintun adapter DNS + NRPT split-DNS rules
// ---------------------------------------------------------------------------

#[cfg(windows)]
struct WindowsDns {
    interface_alias: String,
    upstreams: Vec<Ipv4Addr>,
}

#[cfg(windows)]
impl WindowsDns {
    async fn new(tun_name: &str) -> Result<Self> {
        let interface_alias = powershell_text(&format!(
            "$ErrorActionPreference='Stop'; @(Get-NetAdapter | Where-Object {{ $_.Name -eq '{}' }} | Select-Object -ExpandProperty Name)",
            ps_quote(tun_name)
        ))
        .await?;
        anyhow::ensure!(
            !interface_alias.is_empty() && !interface_alias.contains('\n'),
            "Windows TUN adapter {tun_name:?} was not uniquely found"
        );
        // Wintun has no upstream resolver of its own. Capture the host's
        // physical-interface DNS servers before pointing the system at Magic DNS.
        let upstreams = powershell_host_dns_servers(&interface_alias).await?;
        Ok(Self {
            interface_alias,
            upstreams,
        })
    }
}

#[cfg(windows)]
#[async_trait]
impl DnsConfigurator for WindowsDns {
    async fn apply(&self) -> Result<()> {
        let result = powershell_status(&format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses '{}'",
            ps_quote(&self.interface_alias),
            RESOLVER_IP
        ))
        .await;
        if result.is_err() {
            let _ = reset_wintun_dns(&self.interface_alias).await;
        }
        result
    }

    async fn revert(&self) -> Result<()> {
        reset_wintun_dns(&self.interface_alias).await
    }

    fn name(&self) -> &'static str {
        "windows-powershell-dns"
    }

    fn captured_upstreams(&self) -> Vec<Ipv4Addr> {
        self.upstreams.clone()
    }
}

#[cfg(windows)]
fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(windows)]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct WindowsNrptRuleSnapshot {
    name: String,
    display_name: String,
    namespace: Vec<String>,
    name_servers: Vec<String>,
    comment: Option<String>,
}

#[cfg(windows)]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct WindowsDnsSnapshot {
    nrpt_rules: Vec<WindowsNrptRuleSnapshot>,
    suffix_search_list: Vec<String>,
    managed_suffixes: Option<Vec<String>>,
}

#[cfg(windows)]
static WINDOWS_DNS_TRANSACTION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(windows)]
static WINDOWS_DNS_TXN_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

#[cfg(windows)]
fn ps_array(values: &[String]) -> String {
    format!(
        "@({})",
        values
            .iter()
            .map(|value| format!("'{}'", ps_quote(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(windows)]
fn windows_dns_snapshot_script() -> &'static str {
    "$ErrorActionPreference='Stop'; $statePath='HKLM:\\SOFTWARE\\Rayfish'; $marker=$null; if (Test-Path $statePath) { $marker=Get-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -ErrorAction SilentlyContinue }; [pscustomobject]@{ nrpt_rules=@(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -like 'rayfish:*' } | ForEach-Object { [pscustomobject]@{ name=$_.Name; display_name=$_.DisplayName; namespace=@($_.Namespace); name_servers=@($_.NameServers); comment=$_.Comment } }); suffix_search_list=@((Get-DnsClientGlobalSetting).SuffixSearchList); managed_suffixes=if ($null -eq $marker) { $null } else { @($marker.ManagedDnsSuffixes) } } | ConvertTo-Json -Compress -Depth 5"
}

#[cfg(windows)]
fn next_windows_dns_transaction_id() -> String {
    let sequence = WINDOWS_DNS_TXN_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("rayfish-txn-{}-{sequence}", std::process::id())
}

#[cfg(windows)]
fn next_managed_suffixes(snapshot: &WindowsDnsSnapshot, desired: &[String]) -> Vec<String> {
    let prior = snapshot.managed_suffixes.as_deref().unwrap_or_default();
    desired
        .iter()
        .filter(|domain| prior.contains(domain) || !snapshot.suffix_search_list.contains(domain))
        .cloned()
        .collect()
}

#[cfg(windows)]
fn windows_nrpt_domains(rayfish_domains: &[String], network_names: &[String]) -> Vec<String> {
    let mut domains = rayfish_domains.to_vec();
    for name in network_names {
        if !domains.contains(name) {
            domains.push(name.clone());
        }
    }
    domains
}

#[cfg(windows)]
fn expected_suffixes_after(snapshot: &WindowsDnsSnapshot, desired: &[String]) -> Vec<String> {
    let prior_managed = snapshot.managed_suffixes.as_deref().unwrap_or_default();
    let mut expected = snapshot
        .suffix_search_list
        .iter()
        .filter(|suffix| !prior_managed.contains(suffix))
        .cloned()
        .collect::<Vec<_>>();
    for suffix in desired {
        if !expected.contains(suffix) {
            expected.push(suffix.clone());
        }
    }
    expected
}

#[cfg(all(windows, test))]
fn suffix_rollback_cas_matches(
    current_marker: Option<&str>,
    transaction_id: &str,
    current_suffixes: &[String],
    expected_suffixes: &[String],
) -> bool {
    current_marker == Some(transaction_id)
        && current_suffixes.len() == expected_suffixes.len()
        && current_suffixes
            .iter()
            .all(|item| expected_suffixes.contains(item))
}

#[cfg(windows)]
fn touched_rule_displays(
    snapshot: &WindowsDnsSnapshot,
    desired: &[String],
) -> std::collections::BTreeSet<String> {
    let desired_set = desired
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let mut touched = snapshot
        .nrpt_rules
        .iter()
        .filter_map(|rule| {
            let domain = rule.display_name.strip_prefix("rayfish:")?;
            (!desired_set.contains(domain)).then(|| rule.display_name.clone())
        })
        .collect::<std::collections::BTreeSet<_>>();
    for domain in desired {
        let display = format!("rayfish:{domain}");
        let rules = snapshot
            .nrpt_rules
            .iter()
            .filter(|rule| rule.display_name == display)
            .collect::<Vec<_>>();
        let namespace = format!(".{domain}");
        let exact = rules.len() == 1
            && rules[0].namespace.len() == 1
            && rules[0].namespace[0] == namespace
            && rules[0].name_servers.len() == 1
            && rules[0].name_servers[0] == RESOLVER_IP;
        if !exact {
            touched.insert(display);
        }
    }
    touched
}

#[cfg(windows)]
fn windows_dns_reconcile_script(
    nrpt_domains: &[String],
    suffix_domains: &[String],
    managed_suffixes: &[String],
    transaction_id: &str,
) -> String {
    let desired = ps_array(nrpt_domains);
    let suffix_desired = ps_array(suffix_domains);
    let next_managed = ps_array(managed_suffixes);
    let transaction_id = ps_quote(transaction_id);
    format!(
        "$statePath='HKLM:\\SOFTWARE\\Rayfish'; $desired={desired}; $suffixDesired={suffix_desired}; $nextManaged={next_managed}; $txnMarker='{transaction_id}'; $current=@((Get-DnsClientGlobalSetting).SuffixSearchList); $marker=$null; if (Test-Path $statePath) {{ $marker=Get-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -ErrorAction SilentlyContinue }}; $previousManaged=if ($null -eq $marker) {{ @() }} else {{ @($marker.ManagedDnsSuffixes) }}; $foreign=@($current | Where-Object {{ $previousManaged -notcontains $_ }}); $next=@($foreign + $suffixDesired | Select-Object -Unique); $owned=@(Get-DnsClientNrptRule | Where-Object {{ $_.DisplayName -like 'rayfish:*' }}); foreach ($rule in $owned) {{ $domain=$rule.DisplayName.Substring(8); if ($desired -notcontains $domain) {{ Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop }} }}; foreach ($domain in $desired) {{ $display='rayfish:'+$domain; $namespace='.'+$domain; $matches=@(Get-DnsClientNrptRule | Where-Object {{ $_.DisplayName -eq $display }}); $valid=@($matches | Where-Object {{ @($_.Namespace).Count -eq 1 -and @($_.Namespace)[0] -eq $namespace -and @($_.NameServers).Count -eq 1 -and @($_.NameServers)[0] -eq '{RESOLVER_IP}' }}); if ($matches.Count -ne 1 -or $valid.Count -ne 1) {{ foreach ($rule in $matches) {{ Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop }}; Add-DnsClientNrptRule -Namespace $namespace -NameServers '{RESOLVER_IP}' -DisplayName $display -Comment $txnMarker -ErrorAction Stop }} }}; New-Item -Path $statePath -Force -ErrorAction Stop | Out-Null; Set-ItemProperty -Path $statePath -Name ManagedDnsSuffixTransaction -Value $txnMarker -ErrorAction Stop; Set-ItemProperty -Path $statePath -Name ManagedDnsSuffixExpected -Value ([string[]]$next) -ErrorAction Stop; if ($nextManaged.Count -eq 0) {{ Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -ErrorAction SilentlyContinue }} else {{ Set-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -Value ([string[]]$nextManaged) -ErrorAction Stop }}; Set-DnsClientGlobalSetting -SuffixSearchList $next -ErrorAction Stop; Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixTransaction -ErrorAction SilentlyContinue; Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixExpected -ErrorAction SilentlyContinue"
    )
}

#[cfg(windows)]
fn windows_dns_rollback_script(
    snapshot: &WindowsDnsSnapshot,
    touched_displays: &std::collections::BTreeSet<String>,
    expected_suffixes: &[String],
    transaction_id: &str,
) -> String {
    let mut groups = std::collections::BTreeMap::<&str, Vec<&WindowsNrptRuleSnapshot>>::new();
    for rule in &snapshot.nrpt_rules {
        if touched_displays.contains(&rule.display_name) {
            groups.entry(&rule.display_name).or_default().push(rule);
        }
    }
    let restore_rules = groups
        .into_iter()
        .map(|(display, rules)| {
            let prior_names = ps_array(
                &rules
                    .iter()
                    .map(|rule| rule.name.clone())
                    .collect::<Vec<_>>(),
            );
            let adds = rules
                .into_iter()
                .map(|rule| {
                    let comment = rule.comment.as_deref().map_or_else(String::new, |comment| {
                        format!(" -Comment '{}'", ps_quote(comment))
                    });
                    format!(
                        "Add-DnsClientNrptRule -Namespace {} -NameServers {} -DisplayName '{}'{} -ErrorAction Stop",
                        ps_array(&rule.namespace),
                        ps_array(&rule.name_servers),
                        ps_quote(&rule.display_name),
                        comment
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            format!(
                "$priorNames={prior_names}; $current=@(Get-DnsClientNrptRule | Where-Object {{ $_.DisplayName -eq '{}' }}); if ($current.Count -eq 0 -and $priorNames.Count -gt 0) {{ {adds} }}",
                ps_quote(display)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let prior_managed = ps_array(snapshot.managed_suffixes.as_deref().unwrap_or_default());
    let prior_suffixes = ps_array(&snapshot.suffix_search_list);
    let expected_suffixes = ps_array(expected_suffixes);
    let transaction_id = ps_quote(transaction_id);
    format!(
        "$ErrorActionPreference='Stop'; $statePath='HKLM:\\SOFTWARE\\Rayfish'; $txnMarker='{transaction_id}'; Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq $txnMarker }} | Remove-DnsClientNrptRule -Force -ErrorAction Stop; {restore_rules}; $priorManaged={prior_managed}; $priorSuffix={prior_suffixes}; $expectedSuffix={expected_suffixes}; $currentSuffix=@((Get-DnsClientGlobalSetting).SuffixSearchList); $state=if (Test-Path $statePath) {{ Get-ItemProperty -Path $statePath -ErrorAction SilentlyContinue }} else {{ $null }}; $recordedExpected=if ($null -eq $state) {{ @() }} else {{ @($state.ManagedDnsSuffixExpected) }}; $markerMatches=$null -ne $state -and $state.ManagedDnsSuffixTransaction -eq $txnMarker; $recordMatches=$recordedExpected.Count -eq $expectedSuffix.Count -and @($recordedExpected | Where-Object {{ $expectedSuffix -notcontains $_ }}).Count -eq 0; $suffixMatches=$currentSuffix.Count -eq $expectedSuffix.Count -and @($currentSuffix | Where-Object {{ $expectedSuffix -notcontains $_ }}).Count -eq 0; if ($markerMatches -and $recordMatches -and $suffixMatches) {{ Set-DnsClientGlobalSetting -SuffixSearchList $priorSuffix -ErrorAction Stop; if ($priorManaged.Count -eq 0) {{ Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -ErrorAction SilentlyContinue }} else {{ Set-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -Value ([string[]]$priorManaged) -ErrorAction Stop }}; Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixTransaction -ErrorAction SilentlyContinue; Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixExpected -ErrorAction SilentlyContinue }}"
    )
}

#[cfg(windows)]
async fn rollback_on_error(
    mutation: Result<()>,
    rollback: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    match mutation {
        Ok(()) => Ok(()),
        Err(error) => match rollback.await {
            Ok(()) => Err(error.context("Windows DNS mutation failed; snapshot restored")),
            Err(rollback_error) => anyhow::bail!(
                "Windows DNS mutation failed: {error:#}; snapshot rollback failed: {rollback_error:#}"
            ),
        },
    }
}

#[cfg(windows)]
async fn powershell_text(script: &str) -> Result<String> {
    crate::windows_process::WindowsProcessRunner::default()
        .powershell(script, "run DNS PowerShell")
        .await
}

#[cfg(windows)]
async fn powershell_status(script: &str) -> Result<()> {
    powershell_text(&format!("$ErrorActionPreference='Stop'; {script}")).await?;
    Ok(())
}

#[cfg(windows)]
async fn powershell_host_dns_servers(exclude_alias: &str) -> Result<Vec<Ipv4Addr>> {
    let text = powershell_text(&format!(
        "@(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -ne '{}' }} | Select-Object -ExpandProperty ServerAddresses) | ConvertTo-Json -Compress",
        ps_quote(exclude_alias)
    ))
    .await?;
    let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    Ok(parse_dns_server_values(value))
}

#[cfg(windows)]
fn parse_dns_server_values(value: serde_json::Value) -> Vec<Ipv4Addr> {
    let values = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::String(item) => vec![serde_json::Value::String(item)],
        _ => Vec::new(),
    };
    values
        .into_iter()
        .filter_map(|item| item.as_str().and_then(|s| s.parse().ok()))
        .collect()
}

#[cfg(windows)]
fn reset_wintun_dns_script(interface_alias: &str) -> String {
    format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
        ps_quote(interface_alias)
    )
}

#[cfg(windows)]
async fn reset_wintun_dns(interface_alias: &str) -> Result<()> {
    powershell_status(&reset_wintun_dns_script(interface_alias)).await
}

#[cfg(windows)]
async fn set_search_domains_windows(
    rayfish_domains: &[String],
    network_names: &[String],
    _tun_name: &str,
) -> Result<()> {
    let _transaction = WINDOWS_DNS_TRANSACTION.lock().await;
    let snapshot_text = powershell_text(windows_dns_snapshot_script()).await?;
    let snapshot: WindowsDnsSnapshot =
        serde_json::from_str(&snapshot_text).context("parse Windows DNS snapshot")?;
    let transaction_id = next_windows_dns_transaction_id();
    let nrpt_domains = windows_nrpt_domains(rayfish_domains, network_names);
    let managed_suffixes = next_managed_suffixes(&snapshot, rayfish_domains);
    let expected_suffixes = expected_suffixes_after(&snapshot, rayfish_domains);
    let touched_displays = touched_rule_displays(&snapshot, &nrpt_domains);
    let mutation = powershell_status(&windows_dns_reconcile_script(
        &nrpt_domains,
        rayfish_domains,
        &managed_suffixes,
        &transaction_id,
    ))
    .await;
    rollback_on_error(
        mutation,
        powershell_status(&windows_dns_rollback_script(
            &snapshot,
            &touched_displays,
            &expected_suffixes,
            &transaction_id,
        )),
    )
    .await
}

// ---------------------------------------------------------------------------
// macOS: SCDynamicStore
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use std::sync::{Mutex, OnceLock};

    use anyhow::{Context, Result};
    use core_foundation::{
        array::CFArray, base::TCFType, dictionary::CFDictionary, string::CFString,
    };
    use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
    use system_configuration::sys::schema_definitions::{
        kSCPropNetDNSSearchDomains, kSCPropNetDNSServerAddresses,
        kSCPropNetDNSSupplementalMatchDomains,
    };

    use async_trait::async_trait;

    use super::{DNS_DOMAIN, DnsConfigurator, RESOLVER_IP};

    const SC_DNS_KEY: &str = "State:/Network/Service/rayfish/DNS";

    struct SendSyncStore(SCDynamicStore);

    // SCDynamicStore communicates with configd via Mach IPC. The set/remove
    // calls are thread-safe when no callback context is registered (our case).
    unsafe impl Send for SendSyncStore {}
    unsafe impl Sync for SendSyncStore {}

    static STORE: OnceLock<Mutex<SendSyncStore>> = OnceLock::new();

    fn get_or_init_store() -> Result<&'static Mutex<SendSyncStore>> {
        STORE
            .get()
            .context("SCDynamicStore not initialized (call detect_and_configure first)")
    }

    fn init_store() -> Result<&'static Mutex<SendSyncStore>> {
        if let Some(existing) = STORE.get() {
            return Ok(existing);
        }
        let store = SCDynamicStoreBuilder::new("rayfish")
            .session_keys(true)
            .build()
            .context("failed to create SCDynamicStore session")?;
        let _ = STORE.set(Mutex::new(SendSyncStore(store)));
        Ok(STORE.get().unwrap())
    }

    pub fn write_dns_config(search_domains: &[String]) -> Result<()> {
        let store = get_or_init_store()?;
        let store = store.lock().unwrap();

        let server_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
        let server_val = CFArray::from_CFTypes(&[CFString::from_static_string(RESOLVER_IP)]);

        // Route .ray to our resolver. Only .ray: a bare network name as a match
        // domain would hijack the public domain of the same name.
        let match_key =
            unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSupplementalMatchDomains) };
        let mut match_domains: Vec<CFString> = vec![CFString::new(DNS_DOMAIN)];
        // Full tunnel (an exit node is selected): become the default resolver for
        // *all* queries too. An empty match domain is macOS's catch-all: it makes
        // our resolver handle everything not matched more specifically, so name
        // resolution is forwarded upstream *through the tunnel* (from the daemon)
        // instead of leaking out the physical link, where macOS scopes the query
        // and it never traverses the exit. Split (.ray only) when no exit is up.
        if crate::exit_node::full_tunnel_active() {
            match_domains.push(CFString::new(""));
        }
        let match_val = CFArray::from_CFTypes(&match_domains);

        let search_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSearchDomains) };
        let search_cfstrings: Vec<CFString> =
            search_domains.iter().map(|s| CFString::new(s)).collect();
        let search_val = CFArray::from_CFTypes(&search_cfstrings);

        let typed_dict = CFDictionary::from_CFType_pairs(&[
            (server_key, server_val),
            (match_key, match_val),
            (search_key, search_val),
        ]);
        let dict = unsafe { CFDictionary::wrap_under_get_rule(typed_dict.as_concrete_TypeRef()) };

        anyhow::ensure!(
            store.0.set(SC_DNS_KEY, dict),
            "SCDynamicStoreSetValue failed for {SC_DNS_KEY}"
        );
        Ok(())
    }

    /// Read the system's current default-resolver upstreams from `scutil --dns`,
    /// so a full-tunnel catch-all can forward non-`.ray` queries to them. Captured
    /// once, before we install our own config, so we never capture ourselves.
    /// `resolver #1` is macOS's primary (default) resolver; skip our magic IP.
    fn capture_system_upstreams() -> Vec<std::net::Ipv4Addr> {
        let out = std::process::Command::new("scutil")
            .arg("--dns")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let magic: std::net::Ipv4Addr = super::RESOLVER_IP.parse().unwrap();
        let mut ups = Vec::new();
        let mut in_first = false;
        for line in out.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("resolver #") {
                // Stop once we pass the first resolver block; take only #1.
                if in_first {
                    break;
                }
                in_first = rest.trim() == "1";
                continue;
            }
            if in_first
                && t.starts_with("nameserver[")
                && let Some(ip) = t.split(':').nth(1).and_then(|s| s.trim().parse().ok())
                && ip != magic
                && !ups.contains(&ip)
            {
                ups.push(ip);
            }
        }
        ups
    }

    pub struct MacosDynamicStoreDns {
        captured: Vec<std::net::Ipv4Addr>,
    }

    impl MacosDynamicStoreDns {
        pub fn new() -> Self {
            Self {
                captured: capture_system_upstreams(),
            }
        }
    }

    #[async_trait]
    impl DnsConfigurator for MacosDynamicStoreDns {
        async fn apply(&self) -> Result<()> {
            init_store()?;
            write_dns_config(&[DNS_DOMAIN.to_string()])?;
            tracing::info!(
                key = SC_DNS_KEY,
                full_tunnel = crate::exit_node::full_tunnel_active(),
                "configured macOS DNS via SCDynamicStore"
            );
            Ok(())
        }

        fn captured_upstreams(&self) -> Vec<std::net::Ipv4Addr> {
            self.captured.clone()
        }

        async fn revert(&self) -> Result<()> {
            if let Some(store) = STORE.get() {
                let store = store.lock().unwrap();
                store.0.remove(SC_DNS_KEY);
            }
            tracing::info!("removed SCDynamicStore DNS configuration");
            Ok(())
        }

        fn name(&self) -> &'static str {
            "macos-scdynamicstore"
        }
    }
}

#[cfg(target_os = "macos")]
use macos::MacosDynamicStoreDns;

#[cfg(target_os = "macos")]
fn write_dns_config_macos(search_domains: &[String]) -> Result<()> {
    macos::write_dns_config(search_domains)
}

// ---------------------------------------------------------------------------
// Linux: search domains
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
async fn set_search_domains_linux(rayfish_domains: &[String], tun_name: &str) -> Result<()> {
    let ifindex = linux::get_ifindex(tun_name);

    // Try D-Bus first
    if let Some(idx) = ifindex
        && let Ok(conn) = Connection::system().await
    {
        // `.ray` is the only routing domain (~ray); bare network names are not
        // registered, so a network named `dev` never captures `*.dev`.
        let mut domains: Vec<(String, bool)> = vec![(DNS_DOMAIN.to_string(), true)];
        for d in rayfish_domains {
            domains.push((d.clone(), false));
        }
        let reply = conn
            .call_method(
                Some("org.freedesktop.resolve1"),
                "/org/freedesktop/resolve1",
                Some("org.freedesktop.resolve1.Manager"),
                "SetLinkDomains",
                &(idx as i32, &domains),
            )
            .await;
        if reply.is_ok() {
            return Ok(());
        }
    }

    // Fall back to resolvectl CLI
    use std::process::Command;
    if Command::new("resolvectl")
        .arg("status")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        let mut args = vec!["domain".to_string(), tun_name.to_string()];
        args.push(format!("~{DNS_DOMAIN}"));
        args.extend(rayfish_domains.iter().cloned());
        let status = Command::new("resolvectl")
            .args(&args)
            .status()
            .context("resolvectl domain")?;
        anyhow::ensure!(status.success(), "resolvectl domain failed");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux: shared helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    pub fn get_ifindex(tun_name: &str) -> Option<u32> {
        use std::ffi::CString;
        let cname = CString::new(tun_name).ok()?;
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 { None } else { Some(idx) }
    }
}

// ---------------------------------------------------------------------------
// Linux: systemd-resolved via D-Bus
// ---------------------------------------------------------------------------

/// The stub listeners systemd-resolved binds. A `nameserver` line naming either
/// one means glibc queries reach resolved.
#[cfg(target_os = "linux")]
const RESOLVED_STUB_IPS: [Ipv4Addr; 2] =
    [Ipv4Addr::new(127, 0, 0, 53), Ipv4Addr::new(127, 0, 0, 54)];

/// Whether name lookups on this host actually reach systemd-resolved.
///
/// Resolved running is not the same as resolved being consulted: cloud images
/// ship it enabled while leaving a static `/etc/resolv.conf` full of upstream
/// servers (`resolvectl status` calls this `resolv.conf mode: foreign`). There
/// glibc talks to the upstreams directly and every split-DNS domain we register
/// is dead on arrival. Two ways in, either is enough:
///   - `/etc/resolv.conf` names a stub listener, so the normal DNS path lands on
///     resolved;
///   - `/etc/nsswitch.conf` lists the `resolve` module, so glibc calls resolved
///     over D-Bus before it ever reads resolv.conf.
#[cfg(target_os = "linux")]
async fn resolved_is_in_resolution_path() -> bool {
    let resolv = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .unwrap_or_default();
    if resolv_conf_points_at_resolved(&resolv) {
        return true;
    }

    let nsswitch = tokio::fs::read_to_string("/etc/nsswitch.conf")
        .await
        .unwrap_or_default();
    nsswitch_uses_resolve(&nsswitch)
}

#[cfg(target_os = "linux")]
fn resolv_conf_points_at_resolved(contents: &str) -> bool {
    parse_resolv_nameservers(contents)
        .iter()
        .any(|ip| RESOLVED_STUB_IPS.contains(ip))
}

#[cfg(target_os = "linux")]
fn nsswitch_uses_resolve(contents: &str) -> bool {
    contents
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| l.strip_prefix("hosts:"))
        .any(|l| l.split_whitespace().any(|m| m == "resolve"))
}

/// Whether the `resolvconf` binary is systemd's compatibility symlink to
/// `resolvectl`. If it is, the resolvconf backend is just another door into
/// resolved and inherits its "not in the resolution path" problem.
#[cfg(target_os = "linux")]
fn resolvconf_is_resolved_shim() -> bool {
    ["/sbin/resolvconf", "/usr/sbin/resolvconf"]
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .any(|p| p.file_name().is_some_and(|n| n == "resolvectl"))
}

#[cfg(target_os = "linux")]
struct SystemdResolvedDBus {
    ifindex: i32,
}

#[cfg(target_os = "linux")]
async fn try_systemd_resolved_dbus(tun_name: &str) -> Option<SystemdResolvedDBus> {
    let ifindex = linux::get_ifindex(tun_name)? as i32;
    let conn = Connection::system().await.ok()?;
    // Check that resolved is available on the bus
    let reply = conn
        .call_method(
            Some("org.freedesktop.resolve1"),
            "/org/freedesktop/resolve1",
            Some("org.freedesktop.DBus.Peer"),
            "Ping",
            &(),
        )
        .await;
    if reply.is_err() {
        return None;
    }
    Some(SystemdResolvedDBus { ifindex })
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for SystemdResolvedDBus {
    async fn apply(&self) -> Result<()> {
        let conn = Connection::system()
            .await
            .context("failed to connect to system D-Bus")?;

        // SetLinkDNS(ifindex, [(family, address)])
        // AF_INET = 2; the address is the magic resolver IP, routed into the TUN.
        let dns_addrs: Vec<(i32, Vec<u8>)> =
            vec![(2i32, crate::dns::MAGIC_DNS_V4.octets().to_vec())];
        conn.call_method(
            Some("org.freedesktop.resolve1"),
            "/org/freedesktop/resolve1",
            Some("org.freedesktop.resolve1.Manager"),
            "SetLinkDNS",
            &(self.ifindex, &dns_addrs),
        )
        .await
        .context("SetLinkDNS failed")?;

        // SetLinkDomains(ifindex, [(domain, routing_only)])
        let domains: Vec<(&str, bool)> = vec![(DNS_DOMAIN, true)];
        conn.call_method(
            Some("org.freedesktop.resolve1"),
            "/org/freedesktop/resolve1",
            Some("org.freedesktop.resolve1.Manager"),
            "SetLinkDomains",
            &(self.ifindex, &domains),
        )
        .await
        .context("SetLinkDomains failed")?;

        tracing::info!(
            ifindex = self.ifindex,
            "configured systemd-resolved via D-Bus for .{DNS_DOMAIN}"
        );
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        if let Ok(conn) = Connection::system().await {
            let _ = conn
                .call_method(
                    Some("org.freedesktop.resolve1"),
                    "/org/freedesktop/resolve1",
                    Some("org.freedesktop.resolve1.Manager"),
                    "RevertLink",
                    &(self.ifindex,),
                )
                .await;
        }
        tracing::info!("reverted systemd-resolved D-Bus configuration");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "systemd-resolved-dbus"
    }
}

// ---------------------------------------------------------------------------
// Linux: NetworkManager via D-Bus
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
struct NetworkManagerDns {
    tun_iface: String,
}

/// Returns true only for NM DNS modes that support per-domain split-DNS.
/// `"dnsmasq"` routes specific domains to specific resolvers (what we need).
/// `"systemd-resolved"` also supports split-DNS but is handled by its own
/// configurator earlier in the detection chain, so including it here is
/// harmless (the call site already returns `None` for it first).
#[cfg(target_os = "linux")]
fn nm_supports_split_dns(mode: &str) -> bool {
    matches!(mode, "dnsmasq" | "systemd-resolved")
}

#[cfg(target_os = "linux")]
async fn try_networkmanager_dbus(tun_name: &str) -> Option<NetworkManagerDns> {
    let conn = Connection::system().await.ok()?;

    // Check that NetworkManager is on the bus
    conn.call_method(
        Some("org.freedesktop.NetworkManager"),
        "/org/freedesktop/NetworkManager",
        Some("org.freedesktop.DBus.Peer"),
        "Ping",
        &(),
    )
    .await
    .ok()?;

    // Check NM DNS mode: if "systemd-resolved" or "none", skip (resolved handles it)
    let dns_reply = conn
        .call_method(
            Some("org.freedesktop.NetworkManager"),
            "/org/freedesktop/NetworkManager/DnsManager",
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.NetworkManager.DnsManager", "Mode"),
        )
        .await
        .ok()?;

    // Extract the mode string. If we can't read it at all, conservatively
    // return None - safer to fall through to direct /etc/resolv.conf than
    // to claim NM supports split-DNS when we can't confirm it.
    let body = dns_reply.body();
    let mode_val = body.deserialize::<Value>().ok()?;
    let mode = mode_val.downcast_ref::<String>().ok()?.to_string();

    // If NM delegates to systemd-resolved, skip: the resolved D-Bus path handles it.
    // If NM DNS is "none", it's not managing DNS at all.
    if mode == "systemd-resolved" || mode == "none" {
        return None;
    }

    // Only proceed if this mode supports per-domain split-DNS.
    // "default" and "unbound" modes do not, so fall through to direct mode.
    if !nm_supports_split_dns(&mode) {
        return None;
    }

    // NM is managing DNS in a split-DNS-capable mode (dnsmasq).
    Some(NetworkManagerDns {
        tun_iface: tun_name.to_string(),
    })
}

#[cfg(target_os = "linux")]
impl NetworkManagerDns {
    async fn get_device_path(&self, conn: &Connection) -> Result<zbus::zvariant::OwnedObjectPath> {
        let reply = conn
            .call_method(
                Some("org.freedesktop.NetworkManager"),
                "/org/freedesktop/NetworkManager",
                Some("org.freedesktop.NetworkManager"),
                "GetDeviceByIpIface",
                &(&*self.tun_iface,),
            )
            .await
            .context("GetDeviceByIpIface")?;
        reply
            .body()
            .deserialize()
            .context("deserialize device path")
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for NetworkManagerDns {
    async fn apply(&self) -> Result<()> {
        let conn = Connection::system().await.context("D-Bus system bus")?;

        let device_path = self.get_device_path(&conn).await?;

        // Get the Ip4Config object path for this device
        let reply = conn
            .call_method(
                Some("org.freedesktop.NetworkManager"),
                device_path.as_str(),
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.NetworkManager.Device", "Ip4Config"),
            )
            .await
            .context("get Ip4Config")?;

        let config_val: zbus::zvariant::OwnedValue = reply
            .body()
            .deserialize()
            .context("deserialize Ip4Config")?;

        if let Ok(config_path) = <&zbus::zvariant::ObjectPath>::try_from(&*config_val)
            && config_path.as_str() != "/"
        {
            // Set DNS nameservers via D-Bus Properties: magic DNS IP as u32 (NM host u32 of network-order bytes)
            let dns_servers: Vec<u32> = vec![u32::from_le_bytes(crate::dns::MAGIC_DNS_V4.octets())]; // NM wants the address as a host u32 of its network-order bytes
            let _ = conn
                .call_method(
                    Some("org.freedesktop.NetworkManager"),
                    config_path.as_str(),
                    Some("org.freedesktop.DBus.Properties"),
                    "Set",
                    &(
                        "org.freedesktop.NetworkManager.IP4Config",
                        "Nameservers",
                        Value::from(dns_servers),
                    ),
                )
                .await;
        }

        // Also set DNS search domain on the device connection settings
        let _ = conn
            .call_method(
                Some("org.freedesktop.NetworkManager"),
                device_path.as_str(),
                Some("org.freedesktop.NetworkManager.Device"),
                "Reapply",
                &(HashMap::<String, HashMap<String, Value>>::new(), 0u64, 0u32),
            )
            .await;

        tracing::info!("configured NetworkManager DNS via D-Bus for .{DNS_DOMAIN}");
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        tracing::info!("NetworkManager DNS reverts on interface removal");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "networkmanager-dbus"
    }
}

// ---------------------------------------------------------------------------
// Linux: systemd-resolved via resolvectl CLI (fallback)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
struct SystemdResolvedCli {
    tun_iface: String,
}

#[cfg(target_os = "linux")]
fn try_systemd_resolved_cli(tun_name: &str) -> Option<SystemdResolvedCli> {
    use std::process::Command;
    let output = Command::new("resolvectl").arg("status").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(SystemdResolvedCli {
        tun_iface: tun_name.to_string(),
    })
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for SystemdResolvedCli {
    async fn apply(&self) -> Result<()> {
        use tokio::process::Command;
        let status = Command::new("resolvectl")
            .args(["dns", &self.tun_iface, RESOLVER_IP])
            .status()
            .await
            .context("resolvectl dns")?;
        anyhow::ensure!(status.success(), "resolvectl dns failed");

        let status = Command::new("resolvectl")
            .args(["domain", &self.tun_iface, &format!("~{DNS_DOMAIN}")])
            .status()
            .await
            .context("resolvectl domain")?;
        anyhow::ensure!(status.success(), "resolvectl domain failed");

        tracing::info!(
            "configured systemd-resolved (CLI) for .{DNS_DOMAIN} via {}",
            self.tun_iface
        );
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        use tokio::process::Command;
        let _ = Command::new("resolvectl")
            .args(["revert", &self.tun_iface])
            .status()
            .await;
        tracing::info!("reverted systemd-resolved CLI configuration");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "systemd-resolved-cli"
    }
}

// ---------------------------------------------------------------------------
// Linux: resolvconf (Debian and openresolv)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
enum ResolvconfVariant {
    Debian,
    Openresolv,
}

#[cfg(target_os = "linux")]
struct Resolvconf {
    variant: ResolvconfVariant,
}

#[cfg(target_os = "linux")]
fn try_resolvconf() -> Option<Resolvconf> {
    use std::process::Command;
    let paths = ["/sbin/resolvconf", "/usr/sbin/resolvconf"];
    if !paths.iter().any(|p| Path::new(p).exists()) {
        return None;
    }
    let variant = match Command::new("resolvconf").arg("--version").output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stdout.contains("openresolv") || stderr.contains("openresolv") {
                ResolvconfVariant::Openresolv
            } else {
                ResolvconfVariant::Debian
            }
        }
        Err(_) => ResolvconfVariant::Debian,
    };
    Some(Resolvconf { variant })
}

#[cfg(target_os = "linux")]
impl Resolvconf {
    fn iface_name(&self) -> &str {
        match self.variant {
            ResolvconfVariant::Debian => "tun-rayfish.inet",
            ResolvconfVariant::Openresolv => "tun-rayfish",
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for Resolvconf {
    async fn apply(&self) -> Result<()> {
        use std::process::Stdio;

        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;
        let config = format!("nameserver {RESOLVER_IP}\nsearch {DNS_DOMAIN}\n");
        let iface = self.iface_name();
        let mut child = Command::new("resolvconf")
            .args(["-a", iface])
            .stdin(Stdio::piped())
            .spawn()
            .context("spawning resolvconf")?;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(config.as_bytes())
            .await?;
        let status = child.wait().await?;
        anyhow::ensure!(status.success(), "resolvconf -a failed");
        let variant_name = match self.variant {
            ResolvconfVariant::Debian => "debian",
            ResolvconfVariant::Openresolv => "openresolv",
        };
        tracing::info!(
            variant = variant_name,
            "configured resolvconf for .{DNS_DOMAIN}"
        );
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        use tokio::process::Command;
        let iface = self.iface_name();
        let _ = Command::new("resolvconf")
            .args(["-d", iface])
            .status()
            .await;
        tracing::info!("reverted resolvconf configuration");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "resolvconf"
    }
}

// ---------------------------------------------------------------------------
// Linux fallback: direct /etc/resolv.conf
// ---------------------------------------------------------------------------

// Pure helpers, NOT cfg-gated so their unit tests run on macOS (the dev host).

/// Extract IPv4 `nameserver` entries from resolv.conf contents, excluding our
/// own magic IP (so we never capture ourselves as an upstream → no forward loop).
///
/// `resolv.conf(5)` separates the keyword from its value by any run of spaces or
/// tabs, and plenty of generators emit a tab. Splitting on whitespace rather
/// than matching `"nameserver "` matters more than it looks: missing an entry
/// here doesn't degrade anything, it silently leaves the forwarder with nothing
/// to forward to.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_resolv_nameservers(contents: &str) -> Vec<Ipv4Addr> {
    contents
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            (f.next()? == "nameserver").then(|| f.next())?
        })
        // IPv6 nameservers parse as None and are skipped: the forwarder is v4-only.
        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
        .filter(|ip| *ip != crate::dns::MAGIC_DNS_V4)
        .collect()
}

/// Render a direct-mode resolv.conf pointing at the magic resolver IP, with a
/// verified upstream listed after it as a fallback.
///
/// The fallback is what keeps a box that trusts us from losing DNS outright. We
/// answer `.ray` authoritatively so it never reaches the second entry, but if
/// our resolver is dead, wedged, or the daemon is gone, the libc resolver moves
/// on to a real server instead of the machine having no DNS at all.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn render_direct_resolv_conf(search: &[String], fallback: Option<Ipv4Addr>) -> String {
    let mut s = String::from(HEADER_COMMENT);
    s.push_str(&format!("nameserver {RESOLVER_IP}\n"));
    if let Some(ip) = fallback {
        s.push_str(&format!("nameserver {ip}\n"));
    }
    if !search.is_empty() {
        s.push_str(&format!("search {}\n", search.join(" ")));
    }
    s
}

#[cfg(target_os = "linux")]
const BACKUP_SUFFIX: &str = ".before-rayfish";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const HEADER_COMMENT: &str = "# Added by rayfish - do not edit\n";

/// True iff `/etc/resolv.conf` contents are ours (carry the rayfish marker).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn resolv_conf_is_ours(contents: &str) -> bool {
    contents.contains(HEADER_COMMENT.trim_end())
}

#[cfg(target_os = "linux")]
async fn reassert_resolv_conf(search: &[String], fallback: Option<Ipv4Addr>) -> Result<()> {
    let path = Path::new("/etc/resolv.conf");
    let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
    if !resolv_conf_is_ours(&current) {
        tracing::warn!("/etc/resolv.conf was overwritten; re-asserting rayfish DNS");
        tokio::fs::write(path, render_direct_resolv_conf(search, fallback))
            .await
            .context("re-asserting /etc/resolv.conf")?;
    }
    Ok(())
}

/// Re-assert our resolv.conf the instant another program (NetworkManager,
/// dhclient) tramples it, repairing in ~ms via an inotify watch on `/etc`
/// instead of a fixed-interval poll. A 30s tick backstops the watch in case a
/// trample slips past inotify (or the watch fails to arm), and we re-assert
/// once on entry. Runs until cancelled.
///
/// NM is told to stop owning resolv.conf (`dns=none`, see [`nm_quiet_install`])
/// in direct mode, so on an NM host this watch mostly fires for dhclient or
/// other writers; it remains the catch-all repair either way.
#[cfg(target_os = "linux")]
pub async fn run_resolv_reassert(
    search: Vec<String>,
    fallback: Option<Ipv4Addr>,
    token: tokio_util::sync::CancellationToken,
) {
    use futures::StreamExt;

    // Re-assert immediately: covers any trample between apply() and our arrival.
    if let Err(e) = reassert_resolv_conf(&search, fallback).await {
        tracing::warn!(error = %e, "initial resolv.conf re-assert failed");
    }

    // Watch the parent directory, not the file: NetworkManager/resolvconf
    // replace resolv.conf via atomic rename, which a file-level watch stops
    // seeing after the first swap (the watched inode is gone). A directory
    // watch catches the create/rename of a fresh `resolv.conf`.
    let stream = (|| {
        use inotify::{Inotify, WatchMask};
        let inotify = Inotify::init()?;
        inotify.watches().add(
            Path::new("/etc"),
            WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::CREATE,
        )?;
        inotify.into_event_stream([0u8; 1024])
    })();

    let mut stream = match stream {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "inotify watch on /etc failed; falling back to 30s poll only");
            None
        }
    };

    loop {
        // When inotify armed, wait on it; otherwise this future never resolves
        // and only the 30s tick + cancel drive the loop.
        let event = async {
            match stream.as_mut() {
                Some(s) => s.next().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = token.cancelled() => break,
            ev = event => {
                // Only react to events naming resolv.conf (the /etc watch is broad).
                let relevant = match ev {
                    Some(Ok(e)) => e.name.as_deref().is_none_or(|n| n == "resolv.conf"),
                    Some(Err(e)) => { tracing::warn!(error = %e, "inotify stream error"); false }
                    None => { stream = None; false } // stream ended; rely on the tick
                };
                if relevant
                    && let Err(e) = reassert_resolv_conf(&search, fallback).await {
                    tracing::warn!(error = %e, "resolv.conf re-assert failed");
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                if let Err(e) = reassert_resolv_conf(&search, fallback).await {
                    tracing::warn!(error = %e, "resolv.conf re-assert failed");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NetworkManager quieting (direct mode): stop NM regenerating resolv.conf.
//
// When we fall to the direct /etc/resolv.conf takeover it's because no
// split-DNS backend was found: on an NM host that means NM is in plain
// `default` mode and owns resolv.conf, regenerating it on every connection /
// DHCP-lease event and trampling our `nameserver 100.100.100.53`. Dropping a
// `dns=none` config snippet makes NM leave resolv.conf entirely to us
// (Tailscale takes the same "stop the fight" stance over re-asserting forever).
// Reversible: removed + reloaded on revert. The inotify re-assert remains the
// backstop for non-NM writers (dhclient).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const NM_CONF_DIR: &str = "/etc/NetworkManager/conf.d";
#[cfg(target_os = "linux")]
const NM_DROPIN: &str = "/etc/NetworkManager/conf.d/rayfish-dns.conf";

/// The `dns=none` drop-in that tells NetworkManager to stop managing resolv.conf.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn nm_dns_none_dropin() -> String {
    format!("{HEADER_COMMENT}[main]\ndns=none\n")
}

/// True iff NetworkManager appears installed (its conf.d dir exists). Best-effort
/// gate so we only quiet NM on hosts that actually run it.
#[cfg(target_os = "linux")]
fn nm_present() -> bool {
    Path::new(NM_CONF_DIR).is_dir()
}

/// Ask NetworkManager to reload its configuration so a conf.d change takes effect.
#[cfg(target_os = "linux")]
async fn nm_reload() {
    use tokio::process::Command;
    if Command::new("nmcli")
        .args(["general", "reload"])
        .status()
        .await
        .is_ok_and(|s| s.success())
    {
        return;
    }
    let _ = Command::new("systemctl")
        .args(["reload", "NetworkManager"])
        .status()
        .await;
}

/// Install the `dns=none` drop-in and reload NM (no-op if NM isn't present, or
/// the drop-in already exists). Best-effort: logs and returns on any error so a
/// failure here never blocks bringing the VPN up.
#[cfg(target_os = "linux")]
async fn nm_quiet_install() {
    if !nm_present() {
        return;
    }
    let path = Path::new(NM_DROPIN);
    let already = tokio::fs::read_to_string(path)
        .await
        .map(|c| resolv_conf_is_ours(&c))
        .unwrap_or(false);
    if already {
        return;
    }
    if let Err(e) = tokio::fs::write(path, nm_dns_none_dropin()).await {
        tracing::warn!(error = %e, "failed to install NetworkManager dns=none drop-in");
        return;
    }
    tracing::info!("told NetworkManager to stop managing resolv.conf (dns=none); reloading NM");
    nm_reload().await;
}

/// Remove our `dns=none` drop-in and reload NM so it resumes managing DNS.
/// Only removes a file carrying our marker, so we never delete an operator's
/// own NM config. Best-effort.
#[cfg(target_os = "linux")]
async fn nm_quiet_remove() {
    let path = Path::new(NM_DROPIN);
    match tokio::fs::read_to_string(path).await {
        Ok(c) if resolv_conf_is_ours(&c) => {}
        _ => return, // absent or not ours, leave it
    }
    if let Err(e) = tokio::fs::remove_file(path).await {
        tracing::warn!(error = %e, "failed to remove NetworkManager dns=none drop-in");
        return;
    }
    tracing::info!(
        "restored NetworkManager DNS management (removed dns=none drop-in); reloading NM"
    );
    nm_reload().await;
}

#[cfg(target_os = "linux")]
fn backup_path(original: &Path) -> PathBuf {
    let mut s = original.as_os_str().to_owned();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

#[cfg(target_os = "linux")]
async fn backup_file(path: &Path) -> Result<()> {
    let backup = backup_path(path);
    if path.exists() && !backup.exists() {
        tokio::fs::copy(path, &backup)
            .await
            .with_context(|| format!("backing up {}", path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn restore_file(path: &Path) -> Result<()> {
    let backup = backup_path(path);
    if backup.exists() {
        tokio::fs::copy(&backup, path)
            .await
            .with_context(|| format!("restoring {}", path.display()))?;
        tokio::fs::remove_file(&backup).await?;
        return Ok(());
    }
    // No backup (it was lost, or apply() never made one). Deleting the file was
    // the old behaviour and it is the worst option available: `/etc/resolv.conf`
    // is how every non-resolved host finds a nameserver, and removing it takes
    // that host's DNS down completely for something that was only supposed to
    // undo our edit. Edit in place instead, dropping only the lines we wrote and
    // keeping whatever else the file holds. A file that isn't ours is left
    // untouched: with no backup and no marker we cannot tell our edit from the
    // operator's own configuration, and guessing risks discarding theirs.
    let Ok(current) = tokio::fs::read_to_string(path).await else {
        return Ok(());
    };
    if !resolv_conf_is_ours(&current) {
        tracing::warn!(
            path = %path.display(),
            "no DNS backup to restore and the file is not ours; leaving it untouched"
        );
        return Ok(());
    }
    tokio::fs::write(path, strip_our_resolv_entries(&current))
        .await
        .with_context(|| format!("restoring {}", path.display()))?;
    tracing::warn!(
        path = %path.display(),
        "no DNS backup to restore; removed our entries in place instead of deleting the file"
    );
    Ok(())
}

/// Drop the lines [`DirectResolvConf`] adds (our marker comment and the
/// `nameserver` line pointing at our resolver) and keep everything else, so a
/// backup-less revert leaves the host with its other nameservers and search
/// domains rather than an empty or missing file.
#[cfg(target_os = "linux")]
fn strip_our_resolv_entries(contents: &str) -> String {
    let magic = crate::dns::MAGIC_DNS_V4.to_string();
    let kept: Vec<&str> = contents
        .lines()
        .filter(|l| {
            let t = l.trim();
            if t == HEADER_COMMENT.trim() || t.starts_with("# Added by rayfish") {
                return false;
            }
            // `nameserver <our ip>` in any spacing; other nameservers stay.
            !matches!(t.split_whitespace().collect::<Vec<_>>().as_slice(),
                ["nameserver", ip] if *ip == magic)
        })
        .collect();
    let mut out = kept.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Synchronous emergency restore of the direct-mode DNS artifacts, safe to call
/// from the panic hook just before `abort()`. Undoes exactly what
/// [`DirectResolvConf`] installs: copies the backed-up `/etc/resolv.conf` back
/// (so it stops pointing at our now-dead resolver) and removes the `dns=none`
/// NetworkManager drop-in (so NM resumes owning DNS). No async, best-effort.
///
/// This is the safety net the user asked for: with NM quieting, a panic that
/// left `dns=none` in place **and** resolv.conf pointing at 100.100.100.53 would
/// blackhole all DNS until the service restarts and `restore_stale_backups()`
/// runs. Restoring synchronously here closes that window immediately. A no-op
/// when no backup exists (split-DNS modes never overwrite resolv.conf).
#[cfg(target_os = "linux")]
pub fn emergency_restore_resolv_conf() {
    let path = Path::new("/etc/resolv.conf");
    let backup = backup_path(path);
    if backup.exists() {
        let _ = std::fs::copy(&backup, path);
        let _ = std::fs::remove_file(&backup);
    }
    // Remove our NM drop-in, but only if it carries our marker (never an
    // operator's own NM config).
    if let Ok(c) = std::fs::read_to_string(NM_DROPIN)
        && resolv_conf_is_ours(&c)
    {
        let _ = std::fs::remove_file(NM_DROPIN);
    }
}

/// No-op on non-Linux: only the direct `/etc/resolv.conf` takeover has artifacts
/// to restore.
#[cfg(not(target_os = "linux"))]
pub fn emergency_restore_resolv_conf() {}

#[cfg(target_os = "linux")]
struct DirectResolvConf {
    captured_upstreams: Vec<Ipv4Addr>,
    search: Vec<String>,
    /// The operator named `dns_upstreams` in the config. Their explicit choice
    /// overrides our refusal to take over with no verified upstream of our own:
    /// [`DnsService::configure`] merges theirs in after detection, so the
    /// forwarder does get somewhere to send queries.
    operator_upstreams: bool,
}

#[cfg(target_os = "linux")]
impl DirectResolvConf {
    /// Read the current resolv.conf to capture upstreams + existing search
    /// domains BEFORE we overwrite it, then keep only the upstreams that answer.
    /// Call this in detect_and_configure before apply().
    ///
    /// The probe is the whole point of this backend being careful. Every other
    /// backend hands DNS to a manager that knows where the real resolvers are;
    /// this one infers them from a file that some other program rendered, which
    /// can name a server that no longer answers from this host. Forwarding to a
    /// dead entry takes the machine's DNS down completely (#111), so an upstream
    /// has to prove it is alive before we bet the box on it.
    async fn new() -> Self {
        let contents = tokio::fs::read_to_string("/etc/resolv.conf")
            .await
            .unwrap_or_default();
        let search = contents
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("search ")
                    .or_else(|| l.trim().strip_prefix("domain "))
            })
            .flat_map(|s| s.split_whitespace().map(|x| x.to_string()))
            .collect();

        let captured = parse_resolv_nameservers(&contents);
        let live = crate::dns::resolver::live_upstreams(&captured).await;
        if live.len() != captured.len() {
            let dead: Vec<_> = captured.iter().filter(|ip| !live.contains(ip)).collect();
            tracing::warn!(
                ?dead,
                "resolv.conf names DNS servers that do not answer; ignoring them"
            );
        }
        Self {
            captured_upstreams: live,
            search,
            operator_upstreams: crate::config::load()
                .map(|c| !c.dns_upstreams.servers.is_empty())
                .unwrap_or(false),
        }
    }

    /// The upstream written into resolv.conf as the second nameserver, so the
    /// host keeps resolving if our resolver stops answering.
    fn fallback(&self) -> Option<Ipv4Addr> {
        self.captured_upstreams.first().copied()
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for DirectResolvConf {
    async fn apply(&self) -> Result<()> {
        // Refuse the takeover rather than install a black hole. Taking over
        // resolv.conf routes every name on the box through us, so with no
        // upstream that answers we would break all non-`.ray` resolution, and
        // the re-assert watcher would undo any manual repair. A host with
        // working DNS and no Magic DNS is the better failure. Bail before
        // touching anything so there is nothing to undo.
        anyhow::ensure!(
            !self.captured_upstreams.is_empty() || self.operator_upstreams,
            "no working DNS server found in /etc/resolv.conf, so taking it over would leave \
             this host unable to resolve anything; set `dns_upstreams` in the config to \
             name one explicitly"
        );

        let path = Path::new("/etc/resolv.conf");
        backup_file(path).await?;
        // Quiet NM first so it doesn't regenerate the file out from under the
        // write we're about to make (the inotify re-assert covers any residual).
        nm_quiet_install().await;
        let new_content = render_direct_resolv_conf(&self.search, self.fallback());
        tokio::fs::write(path, new_content)
            .await
            .context("writing /etc/resolv.conf")?;
        tracing::info!(
            upstreams = ?self.captured_upstreams,
            "configured /etc/resolv.conf directly (fallback); verified upstream resolvers"
        );
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        let path = Path::new("/etc/resolv.conf");
        restore_file(path).await?;
        // Hand resolv.conf back to NetworkManager before it regenerates one.
        nm_quiet_remove().await;
        tracing::info!("reverted /etc/resolv.conf");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "direct-resolv.conf"
    }

    fn captured_upstreams(&self) -> Vec<Ipv4Addr> {
        self.captured_upstreams.clone()
    }

    fn search_domains(&self) -> Vec<String> {
        self.search.clone()
    }

    fn fallback_upstream(&self) -> Option<Ipv4Addr> {
        self.fallback()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        RESOLVER_IP, nm_dns_none_dropin, parse_resolv_nameservers, render_direct_resolv_conf,
        resolv_conf_is_ours,
    };
    #[cfg(target_os = "linux")]
    use super::{nsswitch_uses_resolve, resolv_conf_points_at_resolved, strip_our_resolv_entries};

    #[test]
    fn resolv_conf_is_ours_detects_marker() {
        assert!(resolv_conf_is_ours(
            "# Added by rayfish - do not edit\nnameserver 100.100.100.53\n"
        ));
        assert!(!resolv_conf_is_ours(
            "# Generated by NetworkManager\nnameserver 192.168.1.1\n"
        ));
    }

    #[test]
    fn resolver_ip_matches_magic_dns_constant() {
        assert_eq!(
            RESOLVER_IP.parse::<Ipv4Addr>().unwrap(),
            crate::dns::MAGIC_DNS_V4
        );
    }

    #[test]
    fn parse_resolv_nameservers_extracts_ipv4_excluding_magic() {
        let c = "# Generated by NetworkManager\nsearch home\nnameserver 192.168.1.1\nnameserver 8.8.8.8\nnameserver 100.100.100.53\n";
        assert_eq!(
            parse_resolv_nameservers(c),
            vec![
                "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
                "8.8.8.8".parse::<Ipv4Addr>().unwrap()
            ]
        ); // 100.100.100.53 (magic) excluded
    }

    #[test]
    fn render_direct_resolv_conf_points_at_magic_ip() {
        let out = render_direct_resolv_conf(&["homelab.ray".to_string(), "ray".to_string()], None);
        assert!(out.starts_with("# Added by rayfish"));
        assert!(out.contains("nameserver 100.100.100.53"));
        assert!(out.contains("search homelab.ray ray"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn backup_less_revert_keeps_the_other_nameservers() {
        // Verbatim from a host running direct mode. A revert with no backup used
        // to delete this file outright, leaving the machine with no resolver at
        // all; it must come back as the upstream it had before we prepended ours.
        let ours = "# Added by rayfish - do not edit\nnameserver 100.100.100.53\nnameserver 108.61.10.10\n";
        assert_eq!(strip_our_resolv_entries(ours), "nameserver 108.61.10.10\n");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn backup_less_revert_preserves_search_domains_and_options() {
        let ours = "# Added by rayfish - do not edit\nsearch home lan\nnameserver 100.100.100.53\nnameserver 1.1.1.1\noptions ndots:2\n";
        let out = strip_our_resolv_entries(ours);
        assert!(out.contains("search home lan"));
        assert!(out.contains("nameserver 1.1.1.1"));
        assert!(out.contains("options ndots:2"));
        assert!(!out.contains("100.100.100.53"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn backup_less_revert_can_empty_the_server_list_without_losing_the_file() {
        // Our resolver was the only entry. The result is a file with no servers,
        // which lets NetworkManager/resolvconf regenerate one. Still not a delete.
        let ours = "# Added by rayfish - do not edit\nnameserver 100.100.100.53\n";
        assert_eq!(strip_our_resolv_entries(ours), "\n");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn foreign_resolv_conf_does_not_count_as_reaching_resolved() {
        // Verbatim from a Vultr Ubuntu image where resolved runs but nothing
        // asks it: registering `.ray` on the tun link there resolves nothing.
        let c = "nameserver 108.61.10.10\nnameserver 9.9.9.9\nnameserver 2001:19f0:300:1704::6\n";
        assert!(!resolv_conf_points_at_resolved(c));
        assert!(!nsswitch_uses_resolve("hosts:          files dns\n"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn stub_resolv_conf_counts_as_reaching_resolved() {
        assert!(resolv_conf_points_at_resolved(
            "nameserver 127.0.0.53\noptions edns0\n"
        ));
        assert!(resolv_conf_points_at_resolved("nameserver 127.0.0.54\n"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn nsswitch_resolve_module_counts_as_reaching_resolved() {
        // glibc calls resolved over D-Bus here, so resolv.conf never matters.
        assert!(nsswitch_uses_resolve(
            "passwd: files\nhosts: mymachines resolve [!UNAVAIL=return] files dns\n"
        ));
        // A commented-out line is not configuration, and `resolve` has to be a
        // whole module name rather than a substring of another one.
        assert!(!nsswitch_uses_resolve("# hosts: resolve files\n"));
        assert!(!nsswitch_uses_resolve("hosts: files resolvectl dns\n"));
    }

    #[test]
    fn render_direct_resolv_conf_no_search_line_when_empty() {
        let out = render_direct_resolv_conf(&[], None);
        assert!(out.contains("nameserver 100.100.100.53"));
        assert!(!out.contains("search "));
    }

    #[test]
    fn render_direct_resolv_conf_lists_fallback_after_magic_ip() {
        let out = render_direct_resolv_conf(&[], Some("192.168.1.1".parse().unwrap()));
        // Order is load-bearing: the resolver library tries entries top-down, so
        // ours must come first or `.ray` names go to the upstream and NXDOMAIN.
        let magic = out.find("nameserver 100.100.100.53").unwrap();
        let fallback = out.find("nameserver 192.168.1.1").unwrap();
        assert!(magic < fallback, "magic IP must be listed first:\n{out}");
    }

    #[test]
    fn parse_resolv_nameservers_accepts_tabs_and_runs_of_spaces() {
        // A generator that emits a tab, or aligns its columns, must not read as
        // "this host has no DNS servers" — that silently empties the upstream
        // set and takes the box's resolution down with it.
        let c = "nameserver\t192.168.1.1\nnameserver   8.8.8.8\n";
        assert_eq!(
            parse_resolv_nameservers(c),
            vec![
                "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
                "8.8.8.8".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn parse_resolv_nameservers_ignores_non_nameserver_lines() {
        // `nameserver` must be the whole keyword: a prefix match would let
        // `nameservers-are-fun 1.2.3.4` or a comment through.
        let c = "# nameserver 9.9.9.9\noptions ndots:2\nsearch example.com\nnameserver 1.1.1.1\n";
        assert_eq!(
            parse_resolv_nameservers(c),
            vec!["1.1.1.1".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn nm_dns_none_dropin_carries_marker_and_setting() {
        let out = nm_dns_none_dropin();
        // Marker so revert only removes a file we own (nm_quiet_remove guard).
        assert!(resolv_conf_is_ours(&out));
        assert!(out.contains("[main]"));
        assert!(out.contains("dns=none"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nm_split_dns_only_for_capable_modes() {
        use super::nm_supports_split_dns;
        assert!(nm_supports_split_dns("dnsmasq"));
        assert!(nm_supports_split_dns("systemd-resolved"));
        assert!(!nm_supports_split_dns("default"));
        assert!(!nm_supports_split_dns("unbound"));
        assert!(!nm_supports_split_dns(""));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_upstreams_cover_zero_one_many_and_invalid_values() {
        use super::parse_dns_server_values;
        use serde_json::json;

        assert!(parse_dns_server_values(serde_json::Value::Null).is_empty());
        assert_eq!(
            parse_dns_server_values(json!("1.1.1.1")),
            vec!["1.1.1.1".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            parse_dns_server_values(json!(["8.8.8.8", "not-an-ip", "9.9.9.9"])),
            vec![
                "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
                "9.9.9.9".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn zombie_windows_dns_reconcile_is_scoped_transactional_and_quotes_boundaries() {
        use super::{
            WindowsDnsSnapshot, WindowsNrptRuleSnapshot, expected_suffixes_after,
            next_managed_suffixes, ps_quote, suffix_rollback_cas_matches, touched_rule_displays,
            windows_dns_reconcile_script, windows_dns_rollback_script, windows_dns_snapshot_script,
            windows_nrpt_domains,
        };

        assert_eq!(ps_quote(""), "");
        assert_eq!(ps_quote("O'Brien"), "O''Brien");

        let zero = windows_dns_reconcile_script(&[], &[], &[], "txn-zero");
        assert!(zero.contains("DisplayName -like 'rayfish:*'"));
        assert!(!zero.contains("Where-Object { $_.DisplayName -notlike"));
        assert!(zero.contains("ManagedDnsSuffixes"));
        assert!(zero.contains("$foreign=@($current | Where-Object"));
        assert!(windows_dns_snapshot_script().starts_with("$ErrorActionPreference='Stop';"));
        assert!(windows_dns_snapshot_script().contains("ConvertTo-Json"));

        let one = windows_dns_reconcile_script(
            &["corp.ray".to_string()],
            &["corp.ray".to_string()],
            &["corp.ray".to_string()],
            "txn-one",
        );
        assert!(one.contains("$desired=@('corp.ray')"));
        assert!(one.contains("$matches.Count -ne 1 -or $valid.Count -ne 1"));
        assert!(one.contains("@($_.Namespace).Count -eq 1"));
        assert!(one.contains("@($_.Namespace)[0] -eq $namespace"));
        assert!(one.contains("@($_.NameServers).Count -eq 1"));
        assert!(one.contains("@($_.NameServers)[0] -eq '100.100.100.53'"));
        assert!(one.contains("foreach ($rule in $matches)"));
        assert!(one.contains("-Comment $txnMarker"));

        let many = windows_dns_reconcile_script(
            &["a.ray".to_string(), "O'Brian.ray".to_string()],
            &["a.ray".to_string(), "O'Brian.ray".to_string()],
            &["a.ray".to_string(), "O'Brian.ray".to_string()],
            "txn-many",
        );
        assert!(many.contains("$desired=@('a.ray','O''Brian.ray')"));
        assert!(many.contains("$display='rayfish:'+$domain"));

        let nrpt_domains = windows_nrpt_domains(
            &["corp.ray".to_owned(), "ray".to_owned()],
            &["corp".to_owned(), "other".to_owned()],
        );
        assert_eq!(nrpt_domains, ["corp.ray", "ray", "corp", "other"]);
        let match_domains = windows_dns_reconcile_script(
            &nrpt_domains,
            &["corp.ray".to_owned(), "ray".to_owned()],
            &["corp.ray".to_owned(), "ray".to_owned()],
            "txn-match",
        );
        assert!(match_domains.contains("$desired=@('corp.ray','ray','corp','other')"));
        assert!(match_domains.contains("$suffixDesired=@('corp.ray','ray')"));
        assert!(match_domains.contains("$nextManaged=@('corp.ray','ray')"));
        assert!(match_domains.contains("$next=@($foreign + $suffixDesired"));
        assert!(!match_domains.contains("$suffixDesired=@('corp.ray','ray','corp','other')"));

        let snapshot = WindowsDnsSnapshot {
            nrpt_rules: vec![WindowsNrptRuleSnapshot {
                name: "prior-rule-guid".to_owned(),
                display_name: "rayfish:old.ray".to_owned(),
                namespace: vec![".old.ray".to_owned()],
                name_servers: vec!["100.100.100.53".to_owned()],
                comment: Some("operator note".to_owned()),
            }],
            suffix_search_list: vec!["foreign.example".to_owned(), "old.ray".to_owned()],
            managed_suffixes: Some(vec!["old.ray".to_owned()]),
        };
        let touched = touched_rule_displays(&snapshot, &[]);
        let rollback = windows_dns_rollback_script(
            &snapshot,
            &touched,
            &["new.ray".to_owned()],
            "txn-rollback",
        );
        assert!(rollback.contains("DisplayName 'rayfish:old.ray'"));
        assert!(rollback.contains("Comment -eq $txnMarker"));
        assert!(!rollback.contains("DisplayName -like 'rayfish:*'"));
        assert!(rollback.contains("$markerMatches -and $recordMatches -and $suffixMatches"));
        assert!(rollback.contains("ManagedDnsSuffixExpected"));
        assert!(rollback.contains("Set-DnsClientGlobalSetting -SuffixSearchList $priorSuffix"));
        assert!(rollback.contains("$current.Count -eq 0"));
        assert!(rollback.contains("$priorNames=@('prior-rule-guid')"));
        assert!(rollback.contains("ManagedDnsSuffixes"));

        let desired = vec!["foreign.example".to_owned(), "new.ray".to_owned()];
        assert_eq!(next_managed_suffixes(&snapshot, &desired), vec!["new.ray"]);
        let expected = expected_suffixes_after(&snapshot, &desired);
        assert!(suffix_rollback_cas_matches(
            Some("txn-rollback"),
            "txn-rollback",
            &expected,
            &expected
        ));
        let mut external_add = expected.clone();
        external_add.push("external-desired.ray".to_owned());
        assert!(!suffix_rollback_cas_matches(
            Some("txn-rollback"),
            "txn-rollback",
            &external_add,
            &expected
        ));
        let retain_prior = vec!["foreign.example".to_owned(), "old.ray".to_owned()];
        let after_external_remove = vec!["foreign.example".to_owned()];
        assert!(!suffix_rollback_cas_matches(
            Some("txn-rollback"),
            "txn-rollback",
            &after_external_remove,
            &retain_prior
        ));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn ddd_failed_or_timed_out_mutation_always_runs_external_rollback() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let rolled_back = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&rolled_back);
        let result = super::rollback_on_error(Err(anyhow::anyhow!("timed out")), async move {
            marker.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert!(rolled_back.load(Ordering::SeqCst));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn zombie_dns_transaction_lock_serializes_snapshot_through_rollback() {
        let first = super::WINDOWS_DNS_TRANSACTION.lock().await;
        let mut waiter = tokio::spawn(async {
            let _second = super::WINDOWS_DNS_TRANSACTION.lock().await;
            true
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut waiter)
                .await
                .is_err(),
            "second reconcile entered while the first transaction was live"
        );
        drop(first);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn ddd_wintun_cleanup_resets_adapter_dns_instead_of_copying_host_upstreams() {
        let reset = super::reset_wintun_dns_script("Rayfish Tunnel");
        assert!(reset.contains("-ResetServerAddresses"));
        assert!(!reset.contains("-ServerAddresses '192."));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dns_adapter_exposes_stable_interface_contract() {
        use super::{DnsConfigurator, WindowsDns};

        let dns = WindowsDns {
            interface_alias: "Rayfish Tunnel".to_string(),
            upstreams: vec!["192.168.1.1".parse().unwrap()],
        };
        assert_eq!(dns.name(), "windows-powershell-dns");
        assert_eq!(dns.captured_upstreams(), dns.upstreams);
    }
}
