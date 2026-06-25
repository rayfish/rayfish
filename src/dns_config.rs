//! OS-level DNS resolver configuration for Magic DNS.
//!
//! Configures the system to route `.ray` queries to our local resolver at 100.100.100.53:53.
//! macOS: SCDynamicStore with session keys (auto-cleanup on process exit).
//! Linux: systemd-resolved / resolvconf / direct /etc/resolv.conf.

#[allow(unused_imports)]
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;

use crate::DNS_DOMAIN;

// Must equal dns::MAGIC_DNS_V4.
const RESOLVER_IP: &str = "100.100.100.53";

#[async_trait]
pub trait DnsConfigurator: Send + Sync {
    async fn apply(&self) -> Result<()>;
    async fn revert(&self) -> Result<()>;
    fn name(&self) -> &'static str;
}

/// Revert a DNS configuration.
pub async fn revert(configurator: &dyn DnsConfigurator) -> Result<()> {
    configurator.revert().await
}

pub async fn detect_and_configure(tun_name: &str) -> Result<Box<dyn DnsConfigurator>> {
    #[cfg(target_os = "macos")]
    {
        let _ = tun_name;
        let configurator = MacosDynamicStoreDns;
        configurator.apply().await?;
        return Ok(Box::new(configurator));
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(c) = try_systemd_resolved_dbus(tun_name).await {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        if let Some(c) = try_networkmanager_dbus(tun_name).await {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        if let Some(c) = try_systemd_resolved_cli(tun_name) {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        if let Some(c) = try_resolvconf() {
            c.apply().await?;
            return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
        }
        let c = DirectResolvConf;
        c.apply().await?;
        return Ok(Box::new(c) as Box<dyn DnsConfigurator>);
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
        use std::path::PathBuf;
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
        use std::path::PathBuf;
        let path = PathBuf::from("/etc/resolv.conf");
        let backup = backup_path(&path);
        if backup.exists() {
            tracing::info!(path = %path.display(), "restoring stale DNS backup from previous crash");
            if let Err(e) = std::fs::copy(&backup, &path) {
                tracing::warn!(error = %e, "failed to restore DNS backup");
            }
            let _ = std::fs::remove_file(&backup);
        }
    }
}

/// Update system DNS routing so bare hostnames and `<host>.<network>` resolve.
/// Configures search domains (`<network>.ray`, `pi`) and supplemental match
/// domains (each network name + `pi`) so the OS routes queries to rayfish.
/// Call whenever networks are joined or left.
pub async fn update_search_domains(network_names: &[String], tun_name: &str) {
    let mut search: Vec<String> = network_names
        .iter()
        .map(|n| format!("{n}.{DNS_DOMAIN}"))
        .collect();
    search.push(DNS_DOMAIN.to_string());

    if let Err(e) = set_search_domains(&search, network_names, tun_name).await {
        tracing::warn!(error = %e, "failed to update search domains");
    } else {
        tracing::info!(search = ?search, match_domains = ?network_names, "updated search domains");
    }
}

/// Remove all rayfish search domains (called on daemon shutdown).
pub async fn clear_search_domains(tun_name: &str) {
    if let Err(e) = set_search_domains(&[], &[], tun_name).await {
        tracing::warn!(error = %e, "failed to clear search domains");
    }
}

async fn set_search_domains(
    rayfish_domains: &[String],
    network_names: &[String],
    tun_name: &str,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = tun_name;
        write_dns_config_macos(rayfish_domains, network_names)
    }
    #[cfg(target_os = "linux")]
    {
        set_search_domains_linux(rayfish_domains, network_names, tun_name).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (rayfish_domains, network_names, tun_name);
        Ok(())
    }
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

    pub fn write_dns_config(search_domains: &[String], network_names: &[String]) -> Result<()> {
        let store = get_or_init_store()?;
        let store = store.lock().unwrap();

        let server_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
        let server_val = CFArray::from_CFTypes(&[CFString::from_static_string(RESOLVER_IP)]);

        // Route .ray + each bare network name to our resolver
        let match_key =
            unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSupplementalMatchDomains) };
        let mut match_domains: Vec<CFString> = vec![CFString::new(DNS_DOMAIN)];
        for name in network_names {
            match_domains.push(CFString::new(name));
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

    pub struct MacosDynamicStoreDns;

    #[async_trait]
    impl DnsConfigurator for MacosDynamicStoreDns {
        async fn apply(&self) -> Result<()> {
            init_store()?;
            write_dns_config(&[DNS_DOMAIN.to_string()], &[])?;
            tracing::info!(
                key = SC_DNS_KEY,
                "configured macOS DNS via SCDynamicStore for .{DNS_DOMAIN}"
            );
            Ok(())
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
fn write_dns_config_macos(search_domains: &[String], network_names: &[String]) -> Result<()> {
    macos::write_dns_config(search_domains, network_names)
}

// ---------------------------------------------------------------------------
// Linux: search domains
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
async fn set_search_domains_linux(
    rayfish_domains: &[String],
    network_names: &[String],
    tun_name: &str,
) -> Result<()> {
    let ifindex = linux::get_ifindex(tun_name);

    // Try D-Bus first
    if let Some(idx) = ifindex
        && let Ok(conn) = zbus::Connection::system().await
    {
        let mut domains: Vec<(String, bool)> = vec![(DNS_DOMAIN.to_string(), true)];
        // Each network name as a routing domain (~network)
        for name in network_names {
            domains.push((name.clone(), true));
        }
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
        for name in network_names {
            args.push(format!("~{name}"));
        }
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

#[cfg(target_os = "linux")]
struct SystemdResolvedDBus {
    ifindex: i32,
}

#[cfg(target_os = "linux")]
async fn try_systemd_resolved_dbus(tun_name: &str) -> Option<SystemdResolvedDBus> {
    let ifindex = linux::get_ifindex(tun_name)? as i32;
    let conn = zbus::Connection::system().await.ok()?;
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
        let conn = zbus::Connection::system()
            .await
            .context("failed to connect to system D-Bus")?;

        // SetLinkDNS(ifindex, [(family, address)])
        // AF_INET = 2, address = [127, 0, 0, 1]
        let dns_addrs: Vec<(i32, Vec<u8>)> = vec![(2i32, vec![127, 0, 0, 1])];
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
        if let Ok(conn) = zbus::Connection::system().await {
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
    let conn = zbus::Connection::system().await.ok()?;

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

    // Check NM DNS mode — if "systemd-resolved" or "none", skip (resolved handles it)
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
    // return None — safer to fall through to direct /etc/resolv.conf than
    // to claim NM supports split-DNS when we can't confirm it.
    let mode_val = dns_reply
        .body()
        .deserialize::<zbus::zvariant::Value>()
        .ok()?;
    let mode = mode_val.downcast_ref::<String>().ok()?;

    // If NM delegates to systemd-resolved, skip — the resolved D-Bus path handles it.
    // If NM DNS is "none", it's not managing DNS at all.
    if mode == "systemd-resolved" || mode == "none" {
        return None;
    }

    // Only proceed if this mode supports per-domain split-DNS.
    // "default" and "unbound" modes do not, so fall through to direct mode.
    if !nm_supports_split_dns(mode) {
        return None;
    }

    // NM is managing DNS in a split-DNS-capable mode (dnsmasq).
    Some(NetworkManagerDns {
        tun_iface: tun_name.to_string(),
    })
}

#[cfg(target_os = "linux")]
impl NetworkManagerDns {
    async fn get_device_path(
        &self,
        conn: &zbus::Connection,
    ) -> Result<zbus::zvariant::OwnedObjectPath> {
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
        let conn = zbus::Connection::system()
            .await
            .context("D-Bus system bus")?;

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
            // Set DNS nameservers via D-Bus Properties — magic DNS IP as u32 (NM host u32 of network-order bytes)
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
                        zbus::zvariant::Value::from(dns_servers),
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
                &(
                    std::collections::HashMap::<
                        String,
                        std::collections::HashMap<String, zbus::zvariant::Value>,
                    >::new(),
                    0u64,
                    0u32,
                ),
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
    use std::path::Path;
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

#[cfg(target_os = "linux")]
const BACKUP_SUFFIX: &str = ".before-rayfish";
#[cfg(target_os = "linux")]
const HEADER_COMMENT: &str = "# Added by rayfish - do not edit\n";

#[cfg(target_os = "linux")]
fn backup_path(original: &std::path::Path) -> std::path::PathBuf {
    let mut s = original.as_os_str().to_owned();
    s.push(BACKUP_SUFFIX);
    std::path::PathBuf::from(s)
}

#[cfg(target_os = "linux")]
async fn backup_file(path: &std::path::Path) -> Result<()> {
    let backup = backup_path(path);
    if path.exists() {
        tokio::fs::copy(path, &backup)
            .await
            .with_context(|| format!("backing up {}", path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn restore_file(path: &std::path::Path) -> Result<()> {
    let backup = backup_path(path);
    if backup.exists() {
        tokio::fs::copy(&backup, path)
            .await
            .with_context(|| format!("restoring {}", path.display()))?;
        tokio::fs::remove_file(&backup).await?;
    } else if path.exists() {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct DirectResolvConf;

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for DirectResolvConf {
    async fn apply(&self) -> Result<()> {
        use std::path::Path;
        let path = Path::new("/etc/resolv.conf");
        backup_file(path).await?;
        let existing = tokio::fs::read_to_string(path).await.unwrap_or_default();
        let new_content = format!("{HEADER_COMMENT}nameserver {RESOLVER_IP}\n{existing}");
        tokio::fs::write(path, new_content)
            .await
            .context("writing /etc/resolv.conf")?;
        tracing::info!("configured /etc/resolv.conf directly (fallback)");
        Ok(())
    }

    async fn revert(&self) -> Result<()> {
        use std::path::Path;
        let path = Path::new("/etc/resolv.conf");
        restore_file(path).await?;
        tracing::info!("reverted /etc/resolv.conf");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "direct-resolv.conf"
    }
}

#[cfg(test)]
mod tests {
    use super::RESOLVER_IP;

    #[test]
    fn resolver_ip_matches_magic_dns_constant() {
        assert_eq!(
            RESOLVER_IP.parse::<std::net::Ipv4Addr>().unwrap(),
            crate::dns::MAGIC_DNS_V4
        );
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
}
