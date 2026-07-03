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
        let c = DirectResolvConf::new().await;
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
        && let Ok(conn) = Connection::system().await
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
    let body = dns_reply.body();
    let mode_val = body.deserialize::<Value>().ok()?;
    let mode = mode_val.downcast_ref::<String>().ok()?.to_string();

    // If NM delegates to systemd-resolved, skip — the resolved D-Bus path handles it.
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

// Pure helpers — NOT cfg-gated so their unit tests run on macOS (the dev host).

/// Extract IPv4 `nameserver` entries from resolv.conf contents, excluding our
/// own magic IP (so we never capture ourselves as an upstream → no forward loop).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_resolv_nameservers(contents: &str) -> Vec<Ipv4Addr> {
    contents
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver "))
        .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
        .filter(|ip| *ip != crate::dns::MAGIC_DNS_V4)
        .collect()
}

/// Render a direct-mode resolv.conf that points only at the magic resolver IP.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn render_direct_resolv_conf(search: &[String]) -> String {
    let mut s = String::from(HEADER_COMMENT);
    s.push_str(&format!("nameserver {RESOLVER_IP}\n"));
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
async fn reassert_resolv_conf(search: &[String]) -> Result<()> {
    let path = Path::new("/etc/resolv.conf");
    let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
    if !resolv_conf_is_ours(&current) {
        tracing::warn!("/etc/resolv.conf was overwritten; re-asserting rayfish DNS");
        tokio::fs::write(path, render_direct_resolv_conf(search))
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
pub async fn run_resolv_reassert(search: Vec<String>, token: tokio_util::sync::CancellationToken) {
    use futures::StreamExt;

    // Re-assert immediately: covers any trample between apply() and our arrival.
    if let Err(e) = reassert_resolv_conf(&search).await {
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
                    && let Err(e) = reassert_resolv_conf(&search).await {
                    tracing::warn!(error = %e, "resolv.conf re-assert failed");
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                if let Err(e) = reassert_resolv_conf(&search).await {
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
// split-DNS backend was found — on an NM host that means NM is in plain
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
        _ => return, // absent or not ours — leave it
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
    } else if path.exists() {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
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
}

#[cfg(target_os = "linux")]
impl DirectResolvConf {
    /// Read the current resolv.conf to capture upstreams + existing search
    /// domains BEFORE we overwrite it. Call this in detect_and_configure
    /// before apply().
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
        Self {
            captured_upstreams: parse_resolv_nameservers(&contents),
            search,
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for DirectResolvConf {
    async fn apply(&self) -> Result<()> {
        let path = Path::new("/etc/resolv.conf");
        backup_file(path).await?;
        // Quiet NM first so it doesn't regenerate the file out from under the
        // write we're about to make (the inotify re-assert covers any residual).
        nm_quiet_install().await;
        let new_content = render_direct_resolv_conf(&self.search);
        tokio::fs::write(path, new_content)
            .await
            .context("writing /etc/resolv.conf")?;
        tracing::info!(
            upstreams = ?self.captured_upstreams,
            "configured /etc/resolv.conf directly (fallback); captured upstream resolvers"
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
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        RESOLVER_IP, nm_dns_none_dropin, parse_resolv_nameservers, render_direct_resolv_conf,
        resolv_conf_is_ours,
    };

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
        let out = render_direct_resolv_conf(&["homelab.ray".to_string(), "ray".to_string()]);
        assert!(out.starts_with("# Added by rayfish"));
        assert!(out.contains("nameserver 100.100.100.53"));
        assert!(out.contains("search homelab.ray ray"));
    }

    #[test]
    fn render_direct_resolv_conf_no_search_line_when_empty() {
        let out = render_direct_resolv_conf(&[]);
        assert!(out.contains("nameserver 100.100.100.53"));
        assert!(!out.contains("search "));
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
}
