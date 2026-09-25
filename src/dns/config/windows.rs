use super::*;

// ---------------------------------------------------------------------------
// Windows: Wintun adapter DNS + NRPT split-DNS rules
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub(super) struct WindowsDns {
    pub(super) interface_alias: String,
    pub(super) upstreams: Vec<Ipv4Addr>,
}

#[cfg(windows)]
impl WindowsDns {
    pub(super) async fn new(tun_name: &str) -> Result<Self> {
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
            resolver_addr()
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
pub(super) fn ps_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(windows)]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct WindowsNrptRuleSnapshot {
    pub(super) name: String,
    pub(super) display_name: String,
    pub(super) namespace: Vec<String>,
    #[serde(deserialize_with = "deserialize_name_servers")]
    pub(super) name_servers: Vec<String>,
    pub(super) comment: Option<String>,
}

/// `Get-DnsClientNrptRule` hands `NameServers` back as `IPAddress` objects, not
/// strings, so `ConvertTo-Json` writes the whole object out and the snapshot
/// fails to parse against `Vec<String>`. The snapshot script coerces them, but
/// accept both shapes anyway: the CIM typing has differed across Windows builds,
/// and the failure mode is quiet enough to be worth belt and braces. A snapshot
/// that will not parse only parses while no rule exists, which is exactly the
/// first apply on a clean machine, so the daemon looks fine and then fails every
/// reconcile after it, leaving stale rules and suffixes behind on leave and stop.
#[cfg(windows)]
pub(super) fn deserialize_name_servers<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NameServer {
        Text(String),
        Address {
            #[serde(rename = "IPAddressToString")]
            address: String,
        },
    }

    Ok(Vec::<NameServer>::deserialize(deserializer)?
        .into_iter()
        .map(|entry| match entry {
            NameServer::Text(text) => text,
            NameServer::Address { address } => address,
        })
        .collect())
}

#[cfg(windows)]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(super) struct WindowsDnsSnapshot {
    pub(super) nrpt_rules: Vec<WindowsNrptRuleSnapshot>,
    pub(super) suffix_search_list: Vec<String>,
    pub(super) managed_suffixes: Option<Vec<String>>,
}

#[cfg(windows)]
pub(super) static WINDOWS_DNS_TRANSACTION: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

#[cfg(windows)]
pub(super) static WINDOWS_DNS_TXN_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

#[cfg(windows)]
pub(super) fn ps_array(values: &[String]) -> String {
    format!(
        "@({})",
        values
            .iter()
            .map(|value| format!("'{}'", ps_quote(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Reads the DNS state this daemon owns, as JSON, for `WindowsDnsSnapshot`.
///
/// The `ForEach-Object { "$_" }` over `NameServers` is load-bearing: those are
/// `IPAddress` objects, and without it `ConvertTo-Json` writes the object rather
/// than `200::53`. See `deserialize_name_servers`, which tolerates both.
#[cfg(windows)]
pub(super) fn windows_dns_snapshot_script() -> &'static str {
    "$ErrorActionPreference='Stop'; $statePath='HKLM:\\SOFTWARE\\Rayfish'; $marker=$null; if (Test-Path $statePath) { $marker=Get-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -ErrorAction SilentlyContinue }; [pscustomobject]@{ nrpt_rules=@(Get-DnsClientNrptRule | Where-Object { $_.DisplayName -like 'rayfish:*' } | ForEach-Object { [pscustomobject]@{ name=$_.Name; display_name=$_.DisplayName; namespace=@($_.Namespace); name_servers=@($_.NameServers | ForEach-Object { \"$_\" }); comment=$_.Comment } }); suffix_search_list=@((Get-DnsClientGlobalSetting).SuffixSearchList); managed_suffixes=if ($null -eq $marker) { $null } else { @($marker.ManagedDnsSuffixes) } } | ConvertTo-Json -Compress -Depth 5"
}

#[cfg(windows)]
pub(super) fn next_windows_dns_transaction_id() -> String {
    let sequence = WINDOWS_DNS_TXN_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("rayfish-txn-{}-{sequence}", std::process::id())
}

#[cfg(windows)]
pub(super) fn next_managed_suffixes(
    snapshot: &WindowsDnsSnapshot,
    desired: &[String],
) -> Vec<String> {
    let prior = snapshot.managed_suffixes.as_deref().unwrap_or_default();
    desired
        .iter()
        .filter(|domain| prior.contains(domain) || !snapshot.suffix_search_list.contains(domain))
        .cloned()
        .collect()
}

#[cfg(windows)]
pub(super) fn windows_nrpt_domains(
    rayfish_domains: &[String],
    network_names: &[String],
) -> Vec<String> {
    let mut domains = rayfish_domains.to_vec();
    for name in network_names {
        if !domains.contains(name) {
            domains.push(name.clone());
        }
    }
    domains
}

#[cfg(windows)]
pub(super) fn expected_suffixes_after(
    snapshot: &WindowsDnsSnapshot,
    desired: &[String],
) -> Vec<String> {
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
pub(super) fn suffix_rollback_cas_matches(
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
pub(super) fn touched_rule_displays(
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
            && rules[0].name_servers[0] == resolver_addr().to_string();
        if !exact {
            touched.insert(display);
        }
    }
    touched
}

#[cfg(windows)]
pub(super) fn windows_dns_reconcile_script(
    nrpt_domains: &[String],
    suffix_domains: &[String],
    managed_suffixes: &[String],
    transaction_id: &str,
) -> String {
    let desired = ps_array(nrpt_domains);
    let suffix_desired = ps_array(suffix_domains);
    let next_managed = ps_array(managed_suffixes);
    let transaction_id = ps_quote(transaction_id);
    // The `.ray` nameserver every NRPT rule points at. Rendered once so the two
    // places the script names it cannot drift apart.
    let resolver = resolver_addr();
    format!(
        "$statePath='HKLM:\\SOFTWARE\\Rayfish'; $desired={desired}; $suffixDesired={suffix_desired}; $nextManaged={next_managed}; $txnMarker='{transaction_id}'; $current=@((Get-DnsClientGlobalSetting).SuffixSearchList); $marker=$null; if (Test-Path $statePath) {{ $marker=Get-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -ErrorAction SilentlyContinue }}; $previousManaged=if ($null -eq $marker) {{ @() }} else {{ @($marker.ManagedDnsSuffixes) }}; $foreign=@($current | Where-Object {{ $previousManaged -notcontains $_ }}); $next=@($foreign + $suffixDesired | Select-Object -Unique); $owned=@(Get-DnsClientNrptRule | Where-Object {{ $_.DisplayName -like 'rayfish:*' }}); foreach ($rule in $owned) {{ $domain=$rule.DisplayName.Substring(8); if ($desired -notcontains $domain) {{ Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop }} }}; foreach ($domain in $desired) {{ $display='rayfish:'+$domain; $namespace='.'+$domain; $matches=@(Get-DnsClientNrptRule | Where-Object {{ $_.DisplayName -eq $display }}); $valid=@($matches | Where-Object {{ @($_.Namespace).Count -eq 1 -and @($_.Namespace)[0] -eq $namespace -and @($_.NameServers).Count -eq 1 -and @($_.NameServers)[0] -eq '{resolver}' }}); if ($matches.Count -ne 1 -or $valid.Count -ne 1) {{ foreach ($rule in $matches) {{ Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop }}; Add-DnsClientNrptRule -Namespace $namespace -NameServers '{resolver}' -DisplayName $display -Comment $txnMarker -ErrorAction Stop }} }}; New-Item -Path $statePath -Force -ErrorAction Stop | Out-Null; Set-ItemProperty -Path $statePath -Name ManagedDnsSuffixTransaction -Value $txnMarker -ErrorAction Stop; Set-ItemProperty -Path $statePath -Name ManagedDnsSuffixExpected -Value ([string[]]$next) -ErrorAction Stop; if ($nextManaged.Count -eq 0) {{ Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -ErrorAction SilentlyContinue }} else {{ Set-ItemProperty -Path $statePath -Name ManagedDnsSuffixes -Value ([string[]]$nextManaged) -ErrorAction Stop }}; Set-DnsClientGlobalSetting -SuffixSearchList $next -ErrorAction Stop; Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixTransaction -ErrorAction SilentlyContinue; Remove-ItemProperty -Path $statePath -Name ManagedDnsSuffixExpected -ErrorAction SilentlyContinue"
    )
}

#[cfg(windows)]
pub(super) fn windows_dns_rollback_script(
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
pub(super) async fn rollback_on_error(
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
pub(super) async fn powershell_text(script: &str) -> Result<String> {
    crate::windows_process::WindowsProcessRunner::default()
        .powershell(script, "run DNS PowerShell")
        .await
}

#[cfg(windows)]
pub(super) async fn powershell_status(script: &str) -> Result<()> {
    powershell_text(&format!("$ErrorActionPreference='Stop'; {script}")).await?;
    Ok(())
}

#[cfg(windows)]
pub(super) async fn powershell_host_dns_servers(exclude_alias: &str) -> Result<Vec<Ipv4Addr>> {
    let text = powershell_text(&format!(
        "@(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -ne '{}' }} | Select-Object -ExpandProperty ServerAddresses) | ConvertTo-Json -Compress",
        ps_quote(exclude_alias)
    ))
    .await?;
    let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    Ok(parse_dns_server_values(value))
}

#[cfg(windows)]
pub(super) fn parse_dns_server_values(value: serde_json::Value) -> Vec<Ipv4Addr> {
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
pub(super) fn reset_wintun_dns_script(interface_alias: &str) -> String {
    format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
        ps_quote(interface_alias)
    )
}

#[cfg(windows)]
pub(super) async fn reset_wintun_dns(interface_alias: &str) -> Result<()> {
    powershell_status(&reset_wintun_dns_script(interface_alias)).await
}

/// Reconcile the machine's NRPT rules and DNS suffix search list.
///
/// The two lists are deliberately different. NRPT namespaces route a query to
/// our resolver, and get the bare network names as well as the `.ray` domains,
/// so `box.homelab` resolves and not only `box.homelab.ray`. The suffix search
/// list is machine-wide and only gets the `.ray` domains: a bare `homelab` in
/// there would be appended to every unqualified lookup on the host, and it is
/// not a suffix anyone else's names live under.
#[cfg(windows)]
pub(super) async fn set_search_domains_windows(
    domains: &[SearchDomain],
    _tun_name: &str,
) -> Result<()> {
    let rayfish_domains: Vec<String> = domains.iter().map(|d| d.as_str().to_owned()).collect();
    let network_names: Vec<String> = domains
        .iter()
        .filter_map(|d| d.network_name().map(str::to_owned))
        .collect();
    let _transaction = WINDOWS_DNS_TRANSACTION.lock().await;
    let snapshot_text = powershell_text(windows_dns_snapshot_script()).await?;
    let snapshot: WindowsDnsSnapshot =
        serde_json::from_str(&snapshot_text).context("parse Windows DNS snapshot")?;
    let transaction_id = next_windows_dns_transaction_id();
    let nrpt_domains = windows_nrpt_domains(&rayfish_domains, &network_names);
    let managed_suffixes = next_managed_suffixes(&snapshot, &rayfish_domains);
    let expected_suffixes = expected_suffixes_after(&snapshot, &rayfish_domains);
    let touched_displays = touched_rule_displays(&snapshot, &nrpt_domains);
    let mutation = powershell_status(&windows_dns_reconcile_script(
        &nrpt_domains,
        &rayfish_domains,
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
