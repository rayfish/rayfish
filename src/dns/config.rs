//! OS-level DNS resolver configuration for Magic DNS.
//!
//! Configures the system to route `.ray` queries to our local resolver at 100.100.100.53:53.
//! macOS: SCDynamicStore with session keys (auto-cleanup on process exit).
//! Linux: systemd-resolved / resolvconf / direct /etc/resolv.conf.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
// Only the macOS/Linux configurators build resolver/backup file paths; Android
// does no OS-level DNS configuration.
#[cfg(not(target_os = "android"))]
use std::path::PathBuf;

#[allow(unused_imports)]
use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "linux")]
use arc_swap::ArcSwap;
use async_trait::async_trait;
use smol_str::SmolStr;
#[cfg(target_os = "linux")]
use zbus::Connection;
#[cfg(target_os = "linux")]
use zbus::zvariant::Value;

use crate::DNS_DOMAIN;

/// Whether this node's data plane is IPv6-only, which decides *which* magic
/// resolver address the OS is pointed at. Set once at daemon start, before any
/// backend is detected; process-wide because every configurator below needs it
/// and none of them is constructed anywhere the daemon's config is in scope.
static IPV6_ONLY: AtomicBool = AtomicBool::new(false);

/// Record the data-plane mode for the DNS backends. Called at daemon start.
pub fn set_ipv6_only(on: bool) {
    IPV6_ONLY.store(on, Ordering::Relaxed);
}

/// The address to hand the OS as the `.ray` nameserver.
///
/// IPv6-only hosts must not be given the v4 one: it lives in `100.64.0.0/10`,
/// and the VPN that owns that range on such a host drops our reply before it
/// reaches the stub resolver. See [`crate::dns::MAGIC_DNS_V6`].
/// Read by the macOS configurator, which scopes its resolver to the utun in
/// this mode; the other backends only ever need [`resolver_addr`].
#[cfg(target_os = "macos")]
pub(crate) fn ipv6_only() -> bool {
    IPV6_ONLY.load(Ordering::Relaxed)
}

pub fn resolver_addr() -> IpAddr {
    if IPV6_ONLY.load(Ordering::Relaxed) {
        IpAddr::V6(crate::dns::MAGIC_DNS_V6)
    } else {
        IpAddr::V4(crate::dns::MAGIC_DNS_V4)
    }
}

/// A DNS search domain: a suffix the resolver appends to a bare name before
/// giving up on it. `homelab.ray`, `ray`, or one the host already had.
///
/// Its own type because the strings either side of [`search_domains_for`] are
/// otherwise indistinguishable: a *network name* goes in and a *search domain*
/// comes out, both `String`, and nothing stopped the output being fed back in
/// to produce `homelab.ray.ray`. The constructors are the only way to build
/// one, so the `.{DNS_DOMAIN}` suffix is applied exactly once, in one place.
///
/// `SmolStr` for the same reason network names use it in `peers.rs`: a search
/// domain is short enough to live inline, and the whole list is cloned on every
/// join and leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchDomain(SmolStr);

impl SearchDomain {
    /// `<network>.ray`: what makes a bare `box` resolve inside one network.
    fn for_network(network: &str) -> Self {
        Self(SmolStr::new(format!("{network}.{DNS_DOMAIN}")))
    }

    /// `ray`: the catch-all every node carries, so `box.homelab` resolves too.
    fn root() -> Self {
        Self(SmolStr::new_static(DNS_DOMAIN))
    }

    /// One the host already had, read back from its own resolver configuration.
    /// Unvalidated on purpose: it is the host's, and we only carry it along.
    ///
    /// Only the backends that read a file back capture these, and only Linux
    /// has one.
    #[cfg(any(target_os = "linux", test))]
    fn from_host(domain: &str) -> Self {
        Self(SmolStr::new(domain))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Ours to manage rather than the host's.
    ///
    /// It matters when reading back a file we wrote: a daemon restarted while
    /// our own resolv.conf is in place captures its `search` line as "the
    /// host's", and without this the networks that line named would stay in the
    /// list forever, surviving the `ray leave` that should have dropped them.
    #[cfg(any(target_os = "linux", test))]
    fn is_ours(&self) -> bool {
        self.0 == DNS_DOMAIN || self.0.ends_with(&format!(".{DNS_DOMAIN}"))
    }
}

impl std::fmt::Display for SearchDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Render a list the way `resolv.conf` and `resolvconf` want it: space-separated.
#[cfg(any(target_os = "linux", test))]
fn join_domains(domains: &[SearchDomain]) -> String {
    domains
        .iter()
        .map(SearchDomain::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The search domains a file-owning backend currently renders, shared between
/// the configurator and its re-assert task. Swapped whole on every join/leave,
/// so the watcher reads the current list without being restarted.
#[cfg(target_os = "linux")]
pub type SearchDomains = Arc<ArcSwap<Vec<SearchDomain>>>;

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
    /// Install the OS search domains for the currently joined networks.
    ///
    /// The default is the split-DNS path: hand them to the manager that already
    /// holds `.ray`, out of band from the file. The two backends that own a
    /// file of their own write the domains into it instead and override this,
    /// because nothing else would: `set_manager_search_domains` only speaks
    /// resolved, so on a host that fell past it the domains went nowhere and a
    /// bare `box` did not resolve.
    async fn set_search_domains(&self, domains: &[SearchDomain], tun_name: &str) -> Result<()> {
        set_manager_search_domains(domains, tun_name).await
    }
    /// The live search-domain list this configurator renders into
    /// `/etc/resolv.conf` (direct mode only), shared with the re-assert loop so
    /// a trample-repair writes the current domains rather than the ones that
    /// were current when the watcher started.
    /// Default: none (no other backend writes the file, and it is what tells
    /// the caller which backend to start that watcher for).
    #[cfg(target_os = "linux")]
    fn search_handle(&self) -> Option<SearchDomains> {
        None
    }
    /// The resolvers listed after ours in resolv.conf (direct mode only), so the
    /// host still resolves names if our resolver stops answering, and so the
    /// stub has somewhere to go when we decline. Threaded into the re-assert
    /// loop so a trample-repair rewrites the same file we installed.
    /// Default: empty (split-DNS backends don't write the file).
    fn fallback_upstreams(&self) -> Vec<Ipv4Addr> {
        Vec::new()
    }
    /// The other mesh's resolver, when this backend is sharing
    /// `/etc/resolv.conf` with one.
    ///
    /// Its presence is what lets the in-daemon resolver decline names outside
    /// `.ray` instead of forwarding them: the file lists it after ours, so the
    /// stub asks it directly the moment we refuse.
    /// Default: none (no other backend shares a file with anybody).
    fn shared_resolver(&self) -> Option<Ipv4Addr> {
        None
    }
}

/// Revert a DNS configuration.
pub async fn revert(configurator: &dyn DnsConfigurator) -> Result<()> {
    configurator.revert().await
}

/// `mesh_v6` is this node's mesh IPv6: macOS publishes it as the address of the
/// service its resolver belongs to, which is what gets that resolver asked for
/// AAAA records at all (see `macos::write_service_config`). The other backends
/// have no use for it.
pub async fn detect_and_configure(
    tun_name: &str,
    mesh_v6: std::net::Ipv6Addr,
) -> Result<Box<dyn DnsConfigurator>> {
    // Only the macOS/Linux branches consume `tun_name`; on any other target
    // (e.g. Android) the function falls through to the unsupported-platform bail.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = tun_name;
    #[cfg(not(target_os = "macos"))]
    let _ = mesh_v6;

    #[cfg(target_os = "macos")]
    {
        let configurator = MacosDynamicStoreDns::new(tun_name.to_string(), mesh_v6);
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
            // A hard kill skips the panic hook, so the file left behind can be
            // one we merged into another VPN's. Copying the backup over it would
            // undo their DNS as well as ours; subtract our lines instead. Same
            // rule as `restore_file`, arrived at from the other direction.
            let current = std::fs::read_to_string(&path).unwrap_or_default();
            if let Some(ip) = other_overlay_resolver(&current) {
                tracing::info!(
                    resolver = %ip,
                    "stale DNS backup, but another VPN's resolver is in the live file; \
                     removing only our entries"
                );
                let _ = std::fs::write(&path, strip_our_resolv_entries(&current));
            } else {
                tracing::info!(path = %path.display(), "restoring stale DNS backup from previous crash");
                if let Err(e) = std::fs::copy(&backup, &path) {
                    tracing::warn!(error = %e, "failed to restore DNS backup");
                }
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

/// The search domains that make bare hostnames resolve: `<network>.ray` for
/// each joined network, then `ray`, so a bare `<host>` is tried as
/// `<host>.<network>.ray` and `<host>.ray`. `.ray` itself is the only domain
/// routed to us. Bare network names are deliberately never registered: a
/// network called `dev` would otherwise capture every `*.dev` lookup.
///
/// Where these end up is the active backend's business ([`DnsConfigurator::set_search_domains`]).
pub fn search_domains_for(network_names: &[String]) -> Vec<SearchDomain> {
    let mut search: Vec<SearchDomain> = network_names
        .iter()
        .map(|n| SearchDomain::for_network(n))
        .collect();
    search.push(SearchDomain::root());
    search
}

/// Remove all rayfish search domains (called on daemon shutdown).
///
/// Only the manager path needs this. The backends that own a file undo their
/// domains by undoing the file: direct mode restores the backup, resolvconf
/// withdraws the whole stanza.
pub async fn clear_search_domains(tun_name: &str) {
    if let Err(e) = set_manager_search_domains(&[], tun_name).await {
        tracing::warn!(error = %e, "failed to clear search domains");
    }
}

/// Hand the search domains to the OS DNS manager that already holds `.ray`
/// (resolved on Linux, SCDynamicStore on macOS). The default for every
/// split-DNS backend, and a no-op on a host with no manager at all.
pub(crate) async fn set_manager_search_domains(
    rayfish_domains: &[SearchDomain],
    tun_name: &str,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        write_dns_config_macos(rayfish_domains, tun_name)
    }
    #[cfg(target_os = "linux")]
    {
        set_search_domains_linux(rayfish_domains, tun_name).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (rayfish_domains, tun_name);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// macOS: SCDynamicStore
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use std::net::Ipv6Addr;
    use std::sync::{Mutex, OnceLock};

    use anyhow::{Context, Result};
    use core_foundation::{
        array::CFArray,
        base::{CFType, TCFType},
        dictionary::CFDictionary,
        number::CFNumber,
        string::CFString,
    };
    use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
    use system_configuration::sys::schema_definitions::{
        kSCPropInterfaceName, kSCPropNetDNSSearchDomains, kSCPropNetDNSServerAddresses,
        kSCPropNetDNSSupplementalMatchDomains, kSCPropNetIPv6Addresses, kSCPropNetIPv6PrefixLength,
        kSCPropNetIPv6Router,
    };

    use async_trait::async_trait;

    use super::{DNS_DOMAIN, DnsConfigurator};

    const SC_DNS_KEY: &str = "State:/Network/Service/rayfish/DNS";
    /// The IPv6 half of the same service. Written alongside the DNS key in
    /// IPv6-only mode; see [`write_service_config`].
    const SC_IPV6_KEY: &str = "State:/Network/Service/rayfish/IPv6";
    /// The service itself, carrying only its rank. See [`write_service_config`].
    const SC_SERVICE_KEY: &str = "State:/Network/Service/rayfish";
    /// The service id, which is the last path component of the keys above.
    /// `ConfirmedServiceID` has to repeat it to be believed; see
    /// [`write_dns_config`].
    const SC_SERVICE_ID: &str = "rayfish";

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

    pub fn write_dns_config(search_domains: &[super::SearchDomain], tun_name: &str) -> Result<()> {
        let store = get_or_init_store()?;
        let store = store.lock().unwrap();

        let server_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
        let server_val =
            CFArray::from_CFTypes(&[CFString::new(&super::resolver_addr().to_string())]);

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
        let search_cfstrings: Vec<CFString> = search_domains
            .iter()
            .map(|s| CFString::new(s.as_str()))
            .collect();
        let search_val = CFArray::from_CFTypes(&search_cfstrings);

        // In IPv6-only mode, ask configd to trust this resolver, which is the
        // only way it is ever asked for AAAA. configd computes the per-resolver
        // "Request A / Request AAAA" flags, and for a supplemental resolver
        // there is exactly one branch that sets them from the resolver's own
        // service: the one guarded by an internal `__SCOPED_QUERY__` marker
        // (configd's dns-configuration.c). Fail it and configd strips the
        // InterfaceName below, assigns no families of its own, and falls back to
        // merging in the flags of the *default* resolver. On a Mac with no
        // native IPv6 that fallback is A-only, so `.ray` names resolve to
        // nothing in the one mode where AAAA is the only answer we have, while
        // `dig` against the same resolver answers fine.
        //
        // We cannot write that marker: configd rebuilds this dictionary from a
        // fixed list of keys and would drop it. It sets the marker itself for a
        // `State:`-only service (we have no `Setup:` half, and no
        // NetworkExtension) on one condition, that the dictionary names its own
        // service id back. Hence `ConfirmedServiceID`, which is also how another
        // VPN's supplemental resolver earns both families.
        //
        // Trust alone only carries the flags across; [`write_service_config`] is
        // what makes there be an AAAA flag to carry.
        //
        // Only in that mode: with the v4 magic address the fallback already
        // gives us the one family we need.
        //
        // Values are type-erased to `CFType` because these are strings where the
        // rest are arrays, and `from_CFType_pairs` takes one value type.
        let mut pairs: Vec<(CFString, CFType)> = vec![
            (server_key, server_val.as_CFType()),
            (match_key, match_val.as_CFType()),
            (search_key, search_val.as_CFType()),
        ];
        if super::ipv6_only() && !tun_name.is_empty() {
            let iface_key = unsafe { CFString::wrap_under_get_rule(kSCPropInterfaceName) };
            pairs.push((iface_key, CFString::new(tun_name).as_CFType()));
            pairs.push((
                CFString::new("ConfirmedServiceID"),
                CFString::new(SC_SERVICE_ID).as_CFType(),
            ));
        }
        let typed_dict = CFDictionary::from_CFType_pairs(&pairs);
        let dict = unsafe { CFDictionary::wrap_under_get_rule(typed_dict.as_concrete_TypeRef()) };

        anyhow::ensure!(
            store.0.set(SC_DNS_KEY, dict),
            "SCDynamicStoreSetValue failed for {SC_DNS_KEY}"
        );
        Ok(())
    }

    /// Publish the IPv6 half of our service, plus the service's rank. Only
    /// meaningful in IPv6-only mode, and only there is it written.
    ///
    /// This is what puts the AAAA flag on the resolver written above. configd
    /// asks one question of a service before it will request a family for it:
    /// does the service have a *default route* of that family (`ip_plugin.c`,
    /// `service_is_routable` over `kRouteListFlagsHasDefault`). Address,
    /// prefix and interface are not enough, and the answer turns on the
    /// presence of `Router` and nothing else. Note what is *not* asked: no part
    /// of that path inspects the address range, so our `200::/7`, which is
    /// IETF-reserved rather than global unicast or ULA, counts exactly as much
    /// as another VPN's ULA. The same flag is what admits an interface to
    /// `scutil --nwi`, which is why ours was missing from it.
    ///
    /// `Router` pointing back at our own address is the "all routes local"
    /// case: configd wants a default route to exist in its own model of the
    /// service, and gets one with no gateway. `PrimaryRank = Never` is what
    /// keeps that model from reaching the kernel: the service can never win the
    /// primary election, so it claims no `::/0` and cannot capture the host's
    /// IPv6 traffic, and it stays out of the flag set configd merges into every
    /// other resolver. In practice the routing table is unchanged, byte for
    /// byte, before and after this key is written.
    ///
    /// The rank goes first, and the ordering is load-bearing: it is the only
    /// thing keeping the `Router` below from being taken seriously. Publish the
    /// address without it and configd is free to elect us the primary IPv6
    /// service and put a real `::/0` on the utun, so a failure here has to stop
    /// us before we publish anything routable, never after.
    fn write_service_config(tun_name: &str, mesh_v6: Ipv6Addr) -> Result<()> {
        let store = get_or_init_store()?;
        let store = store.lock().unwrap();

        let rank = CFDictionary::from_CFType_pairs(&[(
            CFString::new("PrimaryRank"),
            CFString::new("Never").as_CFType(),
        )]);
        let rank = unsafe { CFDictionary::wrap_under_get_rule(rank.as_concrete_TypeRef()) };
        // Our session's keys are reclaimed by configd when the session ends, but
        // a copy left behind by anyone else is not, and a session store cannot
        // overwrite one. Drop it first so a stray key cannot wedge us for good.
        store.0.remove(SC_SERVICE_KEY);
        anyhow::ensure!(
            store.0.set(SC_SERVICE_KEY, rank),
            "SCDynamicStoreSetValue failed for {SC_SERVICE_KEY}"
        );

        let addr_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetIPv6Addresses) };
        let addr_val = CFArray::from_CFTypes(&[CFString::new(&mesh_v6.to_string())]);
        let prefix_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetIPv6PrefixLength) };
        let prefix_val = CFArray::from_CFTypes(&[CFNumber::from(128i32)]);
        let iface_key = unsafe { CFString::wrap_under_get_rule(kSCPropInterfaceName) };
        let router_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetIPv6Router) };

        let pairs: Vec<(CFString, CFType)> = vec![
            (addr_key, addr_val.as_CFType()),
            (prefix_key, prefix_val.as_CFType()),
            (iface_key, CFString::new(tun_name).as_CFType()),
            (router_key, CFString::new(&mesh_v6.to_string()).as_CFType()),
        ];
        let typed_dict = CFDictionary::from_CFType_pairs(&pairs);
        let dict = unsafe { CFDictionary::wrap_under_get_rule(typed_dict.as_concrete_TypeRef()) };

        anyhow::ensure!(
            store.0.set(SC_IPV6_KEY, dict),
            "SCDynamicStoreSetValue failed for {SC_IPV6_KEY}"
        );
        Ok(())
    }

    /// Read the system's current default-resolver upstreams from `scutil --dns`,
    /// so a full-tunnel catch-all can forward non-`.ray` queries to them. Captured
    /// once, before we install our own config, so we never capture ourselves.
    /// `resolver #1` is macOS's primary (default) resolver; skip our magic IP.
    pub(super) fn capture_system_upstreams() -> Vec<std::net::Ipv4Addr> {
        let out = std::process::Command::new("scutil")
            .arg("--dns")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let magic = crate::dns::MAGIC_DNS_V4;
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
        /// The utun the resolver is scoped to (see [`write_dns_config`]).
        tun_name: String,
        /// This node's mesh IPv6, published as the service's address in
        /// IPv6-only mode (see [`write_service_config`]).
        mesh_v6: Ipv6Addr,
    }

    impl MacosDynamicStoreDns {
        pub fn new(tun_name: String, mesh_v6: Ipv6Addr) -> Self {
            Self {
                captured: capture_system_upstreams(),
                tun_name,
                mesh_v6,
            }
        }
    }

    #[async_trait]
    impl DnsConfigurator for MacosDynamicStoreDns {
        async fn apply(&self) -> Result<()> {
            init_store()?;
            // The service first: the DNS key is only scoped to the interface if
            // configd already knows the service has one.
            if super::ipv6_only() && !self.tun_name.is_empty() {
                write_service_config(&self.tun_name, self.mesh_v6)?;
            }
            write_dns_config(&[super::SearchDomain::root()], &self.tun_name)?;
            tracing::info!(
                key = SC_DNS_KEY,
                interface = %self.tun_name,
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
                // Unconditional: the mode can have changed since the write, and
                // removing a key that was never set is a no-op.
                store.0.remove(SC_IPV6_KEY);
                store.0.remove(SC_SERVICE_KEY);
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
fn write_dns_config_macos(search_domains: &[SearchDomain], tun_name: &str) -> Result<()> {
    macos::write_dns_config(search_domains, tun_name)
}

// ---------------------------------------------------------------------------
// Linux: search domains
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
async fn set_search_domains_linux(rayfish_domains: &[SearchDomain], tun_name: &str) -> Result<()> {
    let ifindex = linux::get_ifindex(tun_name);

    // Try D-Bus first
    if let Some(idx) = ifindex
        && let Ok(conn) = Connection::system().await
    {
        // `.ray` is the only routing domain (~ray); bare network names are not
        // registered, so a network named `dev` never captures `*.dev`.
        let mut domains: Vec<(String, bool)> = vec![(DNS_DOMAIN.to_string(), true)];
        for d in rayfish_domains {
            domains.push((d.to_string(), false));
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
        args.extend(rayfish_domains.iter().map(SearchDomain::to_string));
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
        // AF_INET = 2 / AF_INET6 = 10; the address is the magic resolver IP,
        // routed into the TUN (the v6 one by the `200::/7` peer-range route).
        let dns_addrs: Vec<(i32, Vec<u8>)> = match resolver_addr() {
            IpAddr::V4(v4) => vec![(2i32, v4.octets().to_vec())],
            IpAddr::V6(v6) => vec![(10i32, v6.octets().to_vec())],
        };
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
    // This backend sets nameservers through NM's `IP4Config.Nameservers`, which
    // is typed as an array of u32 and so cannot carry the IPv6 resolver an
    // IPv6-only data plane needs. Decline the rung rather than install a v4
    // address that gets dropped on such a host; the ladder falls through to
    // resolvconf or direct resolv.conf, both of which take either family.
    if IPV6_ONLY.load(Ordering::Relaxed) {
        tracing::info!(
            "skipping the NetworkManager DNS backend: it can only carry an IPv4 \
             nameserver, and this node's data plane is IPv6-only"
        );
        return None;
    }
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
            .args(["dns", &self.tun_iface, &resolver_addr().to_string()])
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
    /// The domains our stanza carries, so a join/leave can re-register it.
    search: SearchDomains,
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
    Some(Resolvconf {
        variant,
        search: Arc::new(ArcSwap::from_pointee(vec![SearchDomain::root()])),
    })
}

#[cfg(target_os = "linux")]
impl Resolvconf {
    fn iface_name(&self) -> &str {
        match self.variant {
            ResolvconfVariant::Debian => "tun-rayfish.inet",
            ResolvconfVariant::Openresolv => "tun-rayfish",
        }
    }

    /// (Re-)register our stanza with the current search domains. resolvconf
    /// replaces an interface's whole record on `-a`, so this is also how a
    /// join or leave lands.
    async fn register(&self) -> Result<()> {
        use std::process::Stdio;

        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;
        let search = self.search.load();
        let mut config = format!("nameserver {}\n", resolver_addr());
        if !search.is_empty() {
            config.push_str(&format!("search {}\n", join_domains(&search)));
        }
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
        // Check the merge here rather than once at `apply`: the case that
        // matters is the other VPN registering its stanza after we did, which
        // is exactly the one a startup-only check cannot see. This runs on
        // every join and leave too.
        self.warn_if_outranked().await;
        Ok(())
    }

    /// resolvconf merges every registered interface into one flat
    /// `/etc/resolv.conf`, and glibc stops at the first nameserver that answers
    /// (an NXDOMAIN included). Second place therefore never sees a `.ray`
    /// query. Nothing to fix from here, since the file is resolvconf's and not
    /// ours to rewrite, so say so instead of reporting a success the host will
    /// not show.
    async fn warn_if_outranked(&self) {
        let Ok(merged) = tokio::fs::read_to_string("/etc/resolv.conf").await else {
            return;
        };
        let Some(first) = first_nameserver(&merged) else {
            return;
        };
        // A loopback stub (resolved's 127.0.0.53, an NM/dnsmasq 127.0.0.1) is
        // not a competitor: it is a forwarder we registered *with*, so it is
        // reached first by design and hands `.ray` back to us.
        if first == resolver_addr() || first.is_loopback() {
            return;
        }
        tracing::warn!(
            ahead_of_us = %first,
            other_vpn = ?foreign_mesh_resolver(&merged),
            "resolvconf put another resolver ahead of ours in /etc/resolv.conf, so `.ray` \
             queries stop there and never reach us; give our stanza priority in resolvconf's \
             interface order, or run systemd-resolved so each VPN registers its own domains"
        );
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl DnsConfigurator for Resolvconf {
    async fn apply(&self) -> Result<()> {
        self.register().await?;
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

    /// Our stanza carries the domains, so a join or leave re-registers it.
    /// `set_manager_search_domains` would be a no-op on a host that fell this
    /// far down the ladder: there is no resolved here to hand them to.
    async fn set_search_domains(&self, domains: &[SearchDomain], _tun_name: &str) -> Result<()> {
        self.search.store(Arc::new(domains.to_vec()));
        self.register().await
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
// This and the resolv.conf helpers below serve the Linux direct-write fallback
// and their own tests, and nothing else: no other platform writes resolv.conf.
#[cfg(any(target_os = "linux", test))]
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

/// The host's own DNS servers, read the way this platform stores them.
///
/// This is not the Magic DNS forwarder's upstream set (that one is captured by
/// whichever backend takes DNS over, and only when one does). It answers a
/// different question: which resolvers does the *daemon* use for its own names,
/// the relay and the pkarr server. Called once, before the endpoint binds, so
/// what it reads is the host's configuration rather than ours.
///
/// `None` on a platform where we have no way to read them (Android keeps its
/// resolvers behind JNI, Windows behind the registry); the caller leaves such a
/// host on iroh's own system-defaults reader. `Some(vec![])` is the different
/// answer "we read the host's configuration and it holds nothing we can use",
/// which is a host the daemon must still work on.
pub(crate) fn system_nameservers() -> Option<Vec<Ipv4Addr>> {
    #[cfg(target_os = "linux")]
    let found = Some(parse_resolv_nameservers(
        &std::fs::read_to_string("/etc/resolv.conf").ok()?,
    ));
    #[cfg(target_os = "macos")]
    let found = Some(macos::capture_system_upstreams());
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let found: Option<Vec<Ipv4Addr>> = None;

    // Nothing inside an overlay range is a resolver we can lean on: ours would
    // ask itself, and another VPN's answers only for as long as that VPN is up.
    // Both magic addresses live in those ranges, so this is also what keeps the
    // daemon's own lookups off its own data plane.
    Some(
        found?
            .into_iter()
            .filter(|ip| !crate::membership::is_overlay_ip(IpAddr::V4(*ip)))
            .collect(),
    )
}

/// What glibc reads: entries past `MAXNS` are ignored in silence, so the render
/// truncates deliberately rather than write a list the resolver will cut short.
#[cfg(any(target_os = "linux", test))]
const MAX_NAMESERVERS: usize = 3;

/// Render a direct-mode resolv.conf pointing at the magic resolver IP, with the
/// servers we captured listed after it.
///
/// Those servers are what keeps a box that trusts us from losing DNS outright:
/// if our resolver is dead, wedged, or the daemon is gone, the libc resolver
/// moves on to a real one instead of the machine having no DNS at all.
///
/// On a host we share with another mesh VPN they are load-bearing rather than a
/// safety net. Their resolver is among them (it is what their file named, so it
/// is what we captured), and the in-daemon resolver *declines* names outside
/// `.ray` on such a host, which means these lines are the path every other name
/// on the box takes. All of them are written, not just the first, because the
/// second and third are what the stub tries next.
#[cfg(any(target_os = "linux", test))]
fn render_direct_resolv_conf(search: &[SearchDomain], fallbacks: &[Ipv4Addr]) -> String {
    render_direct_resolv_conf_with(resolver_addr(), search, fallbacks)
}

/// The body of [`render_direct_resolv_conf`], with the resolver address passed
/// in so the rendering is testable without the process-wide mode.
#[cfg(any(target_os = "linux", test))]
fn render_direct_resolv_conf_with(
    resolver: IpAddr,
    search: &[SearchDomain],
    fallbacks: &[Ipv4Addr],
) -> String {
    let mut s = String::from(HEADER_COMMENT);
    s.push_str(&format!("nameserver {resolver}\n"));
    for ip in fallbacks.iter().take(MAX_NAMESERVERS - 1) {
        s.push_str(&format!("nameserver {ip}\n"));
    }
    if !search.is_empty() {
        s.push_str(&format!("search {}\n", join_domains(search)));
    }
    s
}

#[cfg(target_os = "linux")]
const BACKUP_SUFFIX: &str = ".before-rayfish";
#[cfg(any(target_os = "linux", test))]
const HEADER_COMMENT: &str = "# Added by rayfish - do not edit\n";

/// True iff `/etc/resolv.conf` contents are ours (carry the rayfish marker).
#[cfg(any(target_os = "linux", test))]
fn resolv_conf_is_ours(contents: &str) -> bool {
    contents.contains(HEADER_COMMENT.trim_end())
}

/// What one re-assert pass makes of the current `/etc/resolv.conf`.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
enum Reassert {
    /// The file is ours. Nothing to do.
    Held,
    /// Something overwrote it that will not fight back (NetworkManager,
    /// dhclient). Put ours back.
    Rewrite,
    /// Another overlay took the file. Rebuild ours on top of what it wrote.
    Merge(Ipv4Addr),
    /// The overlay we were merged with is gone from the file. Rebuild from what
    /// replaced it, so we stop forwarding to a resolver that left.
    Reclaim,
}

/// Decide what to do about the current contents, without touching the file.
/// Split out from [`reassert_resolv_conf`] so the decision is testable.
///
/// `merged_with` is the overlay resolver we are currently forwarding to, if any
/// (see [`run_resolv_reassert`]). It is what separates the two ways a file that
/// is no longer ours can read: another VPN arrived, or the one we merged with
/// left.
#[cfg(any(target_os = "linux", test))]
fn reassert_decision(current: &str, merged_with: Option<Ipv4Addr>) -> Reassert {
    if resolv_conf_is_ours(current) {
        return Reassert::Held;
    }
    // Another overlay took the file while we held it. Writing ours straight back
    // over theirs is the rewrite war `apply` used to refuse to start, only with
    // the roles swapped. Merging is what makes losing that race harmless: our
    // write keeps their resolver as the next nameserver and their search domains
    // beside ours, so whichever of us wrote last, the file still resolves both
    // meshes. The caller rate-limits how often we do it.
    if let Some(ip) = foreign_mesh_resolver(current) {
        return Reassert::Merge(ip);
    }
    // No overlay resolver in the file, and the last one we rendered pointed at
    // one: that VPN went down and restored the host's own servers. A plain
    // rewrite would put our file back naming a resolver that is gone, from a
    // forwarder still aimed at it, and take the host's DNS with it (#111). Go
    // back through detection so the upstreams are captured and probed afresh.
    match merged_with {
        Some(_) => Reassert::Reclaim,
        None => Reassert::Rewrite,
    }
}

#[cfg(target_os = "linux")]
async fn reassert_resolv_conf(
    search: &ArcSwap<Vec<SearchDomain>>,
    fallbacks: &[Ipv4Addr],
    merged_with: Option<Ipv4Addr>,
) -> Result<Reassert> {
    let path = Path::new("/etc/resolv.conf");
    let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let decision = reassert_decision(&current, merged_with);
    if decision == Reassert::Rewrite {
        tracing::warn!("/etc/resolv.conf was overwritten; re-asserting rayfish DNS");
        tokio::fs::write(path, render_direct_resolv_conf(&search.load(), fallbacks))
            .await
            .context("re-asserting /etc/resolv.conf")?;
    }
    Ok(decision)
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
///
/// Returns why it stopped, or `None` if it was cancelled. Both exit reasons mean
/// the same thing to the caller: rebuild the backend from the file as it stands
/// now, because the set of resolvers to forward to has changed.
#[cfg(target_os = "linux")]
pub async fn run_resolv_reassert(
    search: SearchDomains,
    fallbacks: Vec<Ipv4Addr>,
    token: tokio_util::sync::CancellationToken,
) -> Option<Recapture> {
    use futures::StreamExt;
    use std::time::Instant;

    // An overlay address among the servers we render is exactly "we are sharing
    // the file with that VPN". Derived rather than stored: what matters is which
    // address the host's DNS now depends on, not which VPN wrote the file.
    let merged_with = fallbacks
        .iter()
        .copied()
        .find(|ip| crate::membership::is_overlay_ip(IpAddr::V4(*ip)));
    // Consecutive liveness failures for `merged_with`. Two, so one lost packet
    // or a restart does not hand the file back.
    let mut shared_misses = 0u32;

    // This task is spawned immediately after the apply it belongs to, so its own
    // uptime is the time since we last wrote the file. That is what the merge
    // cooldown is measured against; see [`MERGE_COOLDOWN`].
    let start = Instant::now();

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

    // Re-assert immediately on entry: covers any trample between apply() and our
    // arrival. Thereafter a pass runs on a relevant inotify event or the tick.
    let mut check = true;
    loop {
        if check {
            match pass(&search, &fallbacks, merged_with).await {
                // Hold off rather than answer their write with ours. Sleeping
                // and re-reading (instead of exiting late) means what we finally
                // merge with is their newest file, not the one that woke us.
                Some(Recapture::Merge(ip)) if start.elapsed() < MERGE_COOLDOWN => {
                    // Saturating: the guard and this line read the clock
                    // separately, and `Duration` subtraction panics if it went
                    // past the cooldown in between.
                    let wait = MERGE_COOLDOWN.saturating_sub(start.elapsed());
                    tracing::info!(
                        resolver = %ip, ?wait,
                        "another VPN rewrote /etc/resolv.conf; waiting out the merge cooldown"
                    );
                    tokio::select! {
                        _ = token.cancelled() => return None,
                        _ = tokio::time::sleep(wait) => continue,
                    }
                }
                Some(exit) => return Some(exit),
                None => {}
            }
        }

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
                check = match ev {
                    Some(Ok(e)) => e.name.as_deref().is_none_or(|n| n == "resolv.conf"),
                    Some(Err(e)) => { tracing::warn!(error = %e, "inotify stream error"); false }
                    None => { stream = None; false } // stream ended; rely on the tick
                };
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                check = true;
                // A VPN that leaves while we hold the file changes nothing about
                // the file: it will not restore a backup over one it does not
                // own (nor will we over theirs), so its address just sits there
                // and stops answering. Nothing the watcher reads can see that,
                // which is why liveness is asked rather than inferred: on a host
                // where we decline off-mesh names, that dead address *is* the
                // host's DNS.
                if let Some(ip) = merged_with {
                    let up = SocketAddr::from((ip, 53u16));
                    if crate::dns::resolver::probe_upstream(up).await {
                        shared_misses = 0;
                    } else {
                        shared_misses += 1;
                        tracing::warn!(
                            resolver = %ip, misses = shared_misses,
                            "the resolver we share /etc/resolv.conf with is not answering"
                        );
                        if shared_misses >= 2 {
                            return Some(Recapture::SharedResolverGone(ip));
                        }
                    }
                }
            }
        }
    }
    None
}

/// Why the re-assert watcher stopped. Both reasons say the resolvers named in
/// `/etc/resolv.conf` are no longer the ones we captured, which is a thing only
/// detection can fix: it re-reads the file, probes what it finds, and applies a
/// backend built from that.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recapture {
    /// Another VPN's resolver is in the file now. Merge ours on top of it.
    Merge(Ipv4Addr),
    /// The VPN we were merged with is gone from it. Take the file back.
    Reclaim,
    /// The resolver we share the file with stopped answering, and the file
    /// still names it because neither of us will overwrite the other's. Nothing
    /// here can fix that: on this host we decline off-mesh names, so its
    /// address is where the rest of the machine's DNS was going.
    SharedResolverGone(Ipv4Addr),
}

/// How long after our own last write we refuse to write again over another
/// VPN's file.
///
/// Both daemons re-assert, so an unthrottled merge answers their write with
/// ours inside a millisecond and theirs answers back: a rewrite loop that burns
/// both CPUs and leaves the file's contents up to whoever wrote most recently.
/// The merge is what makes the *content* of that race harmless (either file
/// resolves both meshes); this is what stops the race itself. One write a
/// minute converges just as surely, and the cost of being slow here is that
/// `.ray` resolves through the stub a minute late.
#[cfg(target_os = "linux")]
const MERGE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

/// One re-assert pass, reporting only the outcomes the loop acts on. Errors are
/// logged and treated as "keep watching" (the next tick retries).
#[cfg(target_os = "linux")]
async fn pass(
    search: &ArcSwap<Vec<SearchDomain>>,
    fallbacks: &[Ipv4Addr],
    merged_with: Option<Ipv4Addr>,
) -> Option<Recapture> {
    match reassert_resolv_conf(search, fallbacks, merged_with).await {
        Ok(Reassert::Merge(ip)) => Some(Recapture::Merge(ip)),
        Ok(Reassert::Reclaim) => Some(Recapture::Reclaim),
        Ok(Reassert::Held | Reassert::Rewrite) => None,
        Err(e) => {
            tracing::warn!(error = %e, "resolv.conf re-assert failed");
            None
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
#[cfg(any(target_os = "linux", test))]
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
pub(crate) async fn nm_quiet_remove() {
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

/// Capture the host's `/etc/resolv.conf` before we overwrite it, once.
///
/// Never captures a file that is already ours, and it can be: the other VPN
/// backed the file up *while we owned it*, so when that VPN leaves it restores
/// our old rayfish file and the next detection finds that as "the host's".
/// Storing it as the baseline would mean a later `ray down` restores a
/// resolv.conf whose first nameserver is the magic IP with no daemon behind it,
/// and every lookup on the host eats a resolver timeout before falling through
/// to the second line. With no backup, `restore_file` takes its marker-based
/// in-place strip instead, which is the right answer for a file we wrote.
///
/// Kept from the *first* apply onwards, including across a merge: the file it
/// captures is the host as it was before us, and a merge revert never uses it
/// anyway (it subtracts our lines in place, see [`restore_file`]).
#[cfg(target_os = "linux")]
async fn backup_file(path: &Path) -> Result<()> {
    let backup = backup_path(path);
    if backup.exists() {
        return Ok(());
    }
    let Ok(current) = tokio::fs::read_to_string(path).await else {
        return Ok(()); // absent or unreadable: nothing to capture
    };
    if resolv_conf_is_ours(&current) {
        tracing::info!("not backing up /etc/resolv.conf: it is one we wrote");
        return Ok(());
    }
    // `copy`, not a write of `current`: it carries the original's mode across,
    // and the restore copies it straight back.
    tokio::fs::copy(path, &backup)
        .await
        .map(|_| ())
        .with_context(|| format!("backing up {}", path.display()))
}

#[cfg(target_os = "linux")]
async fn restore_file(path: &Path) -> Result<()> {
    let backup = backup_path(path);
    // Another VPN's resolver is in this file, so our write was additive and our
    // undo has to be subtractive. Restoring the backup here would put a snapshot
    // of the host from before the merge over a file that is now partly theirs,
    // taking their DNS down to undo ours. Drop our lines, keep the rest, and
    // drop the backup so nothing restores it later behind our back.
    if let Ok(current) = tokio::fs::read_to_string(path).await
        && let Some(ip) = other_overlay_resolver(&current)
    {
        let stripped = strip_our_resolv_entries(&current);
        if stripped != current {
            tokio::fs::write(path, &stripped)
                .await
                .with_context(|| format!("removing our entries from {}", path.display()))?;
        }
        if backup.exists() {
            tokio::fs::remove_file(&backup).await?;
        }
        tracing::info!(
            resolver = %ip, path = %path.display(),
            "another VPN's resolver is in this file; removed only our entries and left it to them"
        );
        return Ok(());
    }
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

/// Drop everything [`DirectResolvConf`] adds (our marker comment, the
/// `nameserver` line pointing at our resolver, and our own search domains) and
/// keep the rest, so what is left is the file without us in it.
///
/// This is the undo for a write that was additive: a merged file carries the
/// other VPN's resolver behind ours and its search domains beside ours, and
/// removing our half has to leave that half standing. It is also the
/// backup-less revert, where the alternative is deleting the file and taking
/// the host's DNS with it.
#[cfg(any(target_os = "linux", test))]
fn strip_our_resolv_entries(contents: &str) -> String {
    // Both families: a file written before a switch to (or from) IPv6-only mode
    // names the other address, and leaving it behind would point the host at a
    // resolver that is no longer listening.
    let magic_v4 = crate::dns::MAGIC_DNS_V4.to_string();
    let magic_v6 = crate::dns::MAGIC_DNS_V6.to_string();
    let mut kept: Vec<String> = Vec::new();
    for line in contents.lines() {
        let t = line.trim();
        if t == HEADER_COMMENT.trim() || t.starts_with("# Added by rayfish") {
            continue;
        }
        let fields: Vec<&str> = t.split_whitespace().collect();
        match fields.as_slice() {
            // `nameserver <our ip>` in any spacing; other nameservers stay.
            ["nameserver", ip] if *ip == magic_v4 || *ip == magic_v6 => continue,
            // A merged `search` line is part theirs. Keep their domains in the
            // order they had them; drop the line only if all of it was ours.
            [kw @ ("search" | "domain"), rest @ ..] => {
                let theirs: Vec<&str> = rest
                    .iter()
                    .copied()
                    .filter(|d| !SearchDomain::from_host(d).is_ours())
                    .collect();
                if !theirs.is_empty() {
                    kept.push(format!("{kw} {}", theirs.join(" ")));
                }
            }
            _ => kept.push(line.to_string()),
        }
    }
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
    // Same rule as [`restore_file`], and it matters more here: the file we would
    // copy over is one we merged into another VPN's, and the process is about to
    // abort, so nothing will be along to notice we took their DNS down with
    // ours. Subtract our lines instead and leave the backup alone.
    match std::fs::read_to_string(path) {
        Ok(current) if other_overlay_resolver(&current).is_some() => {
            let _ = std::fs::write(path, strip_our_resolv_entries(&current));
            let _ = std::fs::remove_file(&backup);
        }
        _ if backup.exists() => {
            let _ = std::fs::copy(&backup, path);
            let _ = std::fs::remove_file(&backup);
        }
        _ => {}
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
    /// The search domains the file already had. Kept separately from the live
    /// list so a later join/leave re-merges against the host's own domains
    /// instead of accumulating ours on top of the previous render.
    captured_search: Vec<SearchDomain>,
    /// What actually goes in the file: [`Self::captured_search`] plus the
    /// rayfish domains, swapped whole on every join/leave and shared with the
    /// re-assert task so a trample-repair writes the current list.
    search: SearchDomains,
    /// The operator named a *usable* `dns_upstreams` in the config. Their explicit
    /// choice overrides our refusal to take over with no verified upstream of our
    /// own: [`DnsService::configure`] merges theirs in after detection, so the
    /// forwarder does get somewhere to send queries.
    ///
    /// Counts only entries that survive [`crate::config::resolve_upstreams`],
    /// which narrows to IPv4. `dns_upstreams` accepts any `IpAddr` since the
    /// IPv6-only exit tunnel needed it, so a purely IPv6 setting is a real
    /// possibility and would otherwise waive this guard while contributing
    /// nothing: we would take over `/etc/resolv.conf`, install the re-assert
    /// watcher, and leave the forwarder with an empty upstream list, which is the
    /// exact black hole the `ensure!` below exists to prevent. The IPv6 entries
    /// are not ignored, they are reached by `exit_node::tunnel_upstreams`, the one
    /// caller whose transport can carry them.
    operator_upstreams: bool,
    /// Another mesh VPN's resolver, if the file we captured names one. Means
    /// this apply is a merge: it is already in [`Self::captured_upstreams`], so
    /// it is what we render behind ours and what the forwarder sends everything
    /// outside `.ray` to. See [`foreign_mesh_resolver`].
    foreign_resolver: Option<Ipv4Addr>,
}

/// The CGNAT-range resolver another mesh VPN installed in `contents`, if any.
///
/// Taking over `/etc/resolv.conf` means owning DNS for the whole host, and this
/// backend backs that up with an inotify watch that rewrites the file whenever
/// something else touches it. Against a peer VPN that does exactly the same,
/// neither can own it outright, so what this address selects is *how* we write:
/// additively, keeping it as the next nameserver and forwarding to it, on a
/// cooldown (see [`MERGE_COOLDOWN`]) rather than by return of write.
///
/// A nameserver inside `100.64.0.0/10` that is not ours is the signal: nothing
/// in that range is a real resolver, so it can only be another overlay's magic
/// DNS. Deliberately not a check for any particular vendor's marker line.
///
/// Parsing goes through [`parse_resolv_nameservers`] for the reason stated
/// there: `resolv.conf(5)` allows any run of whitespace after the keyword, and
/// a hand-rolled `"nameserver "` match misses the generators that emit a tab.
/// Missing an entry costs nothing there; here it costs us the whole check.
#[cfg(any(target_os = "linux", test))]
fn foreign_mesh_resolver(contents: &str) -> Option<Ipv4Addr> {
    if resolv_conf_is_ours(contents) {
        return None;
    }
    other_overlay_resolver(contents)
}

/// The first overlay-range nameserver in `contents` that is not ours, whether or
/// not the file itself is ours.
///
/// [`foreign_mesh_resolver`] answers "did someone else take this file", so it
/// stops at our own marker. This answers the question that outlives the
/// takeover: is another VPN's resolver *in* this file, including the merged one
/// we wrote ourselves. That is what [`restore_file`] needs, since by then the
/// file is ours by definition and their resolver is in it because we put it
/// there.
#[cfg(any(target_os = "linux", test))]
fn other_overlay_resolver(contents: &str) -> Option<Ipv4Addr> {
    // `parse_resolv_nameservers` already drops our own magic IP.
    parse_resolv_nameservers(contents)
        .into_iter()
        .find(|ip| crate::membership::is_overlay_ip(IpAddr::V4(*ip)))
}

/// The first `nameserver` in `contents`, whatever its family.
///
/// glibc queries resolvers in the order they are listed and stops at the first
/// one that answers, and an authoritative NXDOMAIN is an answer. On a file that
/// something else merged (resolvconf), first place is therefore the only place
/// from which `.ray` queries ever reach us.
#[cfg(any(target_os = "linux", test))]
fn first_nameserver(contents: &str) -> Option<IpAddr> {
    contents.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        let value = (f.next()? == "nameserver").then(|| f.next())??;
        value.parse().ok()
    })
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
        let search: Vec<SearchDomain> = contents
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("search ")
                    .or_else(|| l.trim().strip_prefix("domain "))
            })
            .flat_map(|s| s.split_whitespace().map(SearchDomain::from_host))
            // Ours are re-derived from the joined networks on every refresh;
            // keeping the ones this file already names would outlive a leave.
            .filter(|d| !d.is_ours())
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
            search: Arc::new(ArcSwap::from_pointee(search.clone())),
            captured_search: search,
            operator_upstreams: crate::config::load()
                .map(|c| crate::config::has_usable_upstream(&c.dns_upstreams))
                .unwrap_or(false),
            foreign_resolver: foreign_mesh_resolver(&contents),
        }
    }

    /// The upstream written into resolv.conf as the second nameserver, so the
    /// host keeps resolving if our resolver stops answering.
    fn fallbacks(&self) -> &[Ipv4Addr] {
        &self.captured_upstreams
    }
}

/// What the resolver actually reads: glibc's `MAXDNSRCH`. Entries past it are
/// ignored in silence, which is why the merge below truncates deliberately
/// instead of rendering a list the host will quietly cut short.
#[cfg(any(target_os = "linux", test))]
const MAX_SEARCH_DOMAINS: usize = 6;

/// The host's own search domains followed by ours, without duplicates, capped
/// at what the resolver reads.
///
/// Host first: on a box that already searched `lan`, a bare name that resolves
/// there keeps resolving there. Ours only add candidates, they never take one
/// away, and the cost of losing the race is one extra NXDOMAIN.
///
/// The cap inverts that priority for exactly one entry. `search_domains_for`
/// puts the catch-all `ray` last, so a host with its own domains and several
/// networks would overflow the list and lose precisely the entry that makes any
/// bare mesh name resolve. `ray` is kept at the cost of the last thing that
/// fits, and what got dropped is logged rather than silently cut.
#[cfg(any(target_os = "linux", test))]
fn merge_search_domains(captured: &[SearchDomain], rayfish: &[SearchDomain]) -> Vec<SearchDomain> {
    let mut out: Vec<SearchDomain> = Vec::with_capacity(captured.len() + rayfish.len());
    for d in captured.iter().chain(rayfish) {
        if !out.contains(d) {
            out.push(d.clone());
        }
    }
    if out.len() <= MAX_SEARCH_DOMAINS {
        return out;
    }
    let root = SearchDomain::root();
    let mut dropped = out.split_off(MAX_SEARCH_DOMAINS);
    if !out.contains(&root) {
        dropped.retain(|d| *d != root);
        dropped.push(out.pop().expect("cap is non-zero"));
        out.push(root);
    }
    tracing::warn!(
        dropped = ?dropped.iter().map(SearchDomain::as_str).collect::<Vec<_>>(),
        kept = ?out.iter().map(SearchDomain::as_str).collect::<Vec<_>>(),
        "more search domains than the resolver reads ({MAX_SEARCH_DOMAINS}); \
         bare names under the dropped ones need their full `.{DNS_DOMAIN}` name"
    );
    out
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
        // Another overlay already owns this file. We take it, but additively:
        // their resolver was captured above and is rendered as the nameserver
        // after ours, their search domains are merged with ours, and everything
        // we cannot answer is forwarded to them. First place is not a
        // preference, it is the only place a `.ray` query reaches us from
        // (glibc stops at the first server that answers, and their NXDOMAIN
        // answers); behind us they keep resolving exactly what they did before.
        if let Some(ip) = self.foreign_resolver {
            // Going first in the file is only worth anything if we can be
            // reached there. A v4 magic address sits inside `100.64.0.0/10`,
            // which is the range this other VPN owns and filters, so our reply
            // is dropped before the stub sees it: we would be an unanswering
            // first nameserver and every lookup on the host would eat the
            // resolver timeout before falling through to them. That is worse
            // than not taking the file, which is what the IPv6-only mode exists
            // to avoid; a host that opted out of it (`ipv6-only = off`) keeps
            // its DNS instead of Magic DNS.
            anyhow::ensure!(
                resolver_addr().is_ipv6(),
                "/etc/resolv.conf is shared with another VPN (nameserver {ip}) that filters \
                 {}, so our resolver could not answer from there; set `ipv6-only` to auto or \
                 on so Magic DNS moves to {}",
                "100.64.0.0/10",
                crate::dns::MAGIC_DNS_V6
            );
            tracing::info!(
                resolver = %ip,
                "/etc/resolv.conf names another VPN's resolver; merging ours in ahead of it \
                 and declining everything outside `.{DNS_DOMAIN}` so the stub asks it directly"
            );
        }

        let path = Path::new("/etc/resolv.conf");
        backup_file(path).await?;
        // Quiet NM first so it doesn't regenerate the file out from under the
        // write we're about to make (the inotify re-assert covers any residual).
        nm_quiet_install().await;
        let new_content = render_direct_resolv_conf(&self.search.load(), self.fallbacks());
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

    /// We own the file, so the domains go in it. Nothing else would put them
    /// there: this backend is the one the host falls to when it has no DNS
    /// manager to hand them to.
    async fn set_search_domains(&self, domains: &[SearchDomain], _tun_name: &str) -> Result<()> {
        self.search.store(Arc::new(merge_search_domains(
            &self.captured_search,
            domains,
        )));
        let path = Path::new("/etc/resolv.conf");
        // Only rewrite a file that is still ours. If something else holds it,
        // the re-assert watcher decides what to do about that, on its own
        // schedule: a join is not a reason to write over another VPN inside the
        // merge cooldown, and the domains are stored above either way, so the
        // next render carries them.
        let current = tokio::fs::read_to_string(path).await.unwrap_or_default();
        if !resolv_conf_is_ours(&current) {
            return Ok(());
        }
        tokio::fs::write(
            path,
            render_direct_resolv_conf(&self.search.load(), self.fallbacks()),
        )
        .await
        .context("writing search domains to /etc/resolv.conf")
    }

    fn search_handle(&self) -> Option<SearchDomains> {
        Some(Arc::clone(&self.search))
    }

    fn fallback_upstreams(&self) -> Vec<Ipv4Addr> {
        self.captured_upstreams.clone()
    }

    fn shared_resolver(&self) -> Option<Ipv4Addr> {
        self.foreign_resolver
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        MAX_NAMESERVERS, Reassert, SearchDomain, first_nameserver, foreign_mesh_resolver,
        join_domains, merge_search_domains, nm_dns_none_dropin, other_overlay_resolver,
        parse_resolv_nameservers, reassert_decision, render_direct_resolv_conf,
        render_direct_resolv_conf_with, resolv_conf_is_ours, search_domains_for,
        strip_our_resolv_entries,
    };

    /// Domains as the host had them, i.e. read back from its own config.
    fn host(domains: &[&str]) -> Vec<SearchDomain> {
        domains.iter().map(|d| SearchDomain::from_host(d)).collect()
    }

    fn networks(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }
    #[cfg(target_os = "linux")]
    use super::{nsswitch_uses_resolve, resolv_conf_points_at_resolved};

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
    fn foreign_mesh_resolver_spots_another_overlays_dns() {
        // Tailscale's MagicDNS: in the CGNAT range, so it can only be an overlay.
        assert_eq!(
            foreign_mesh_resolver(
                "# resolv.conf generated by a VPN\nnameserver 100.100.100.100\nsearch ts.net\n"
            ),
            Some("100.100.100.100".parse::<Ipv4Addr>().unwrap())
        );
        // An ordinary file is free to take over.
        assert_eq!(
            foreign_mesh_resolver("# Generated by NetworkManager\nnameserver 192.168.1.1\n"),
            None
        );
        // Ours is not foreign, whether we look at the marker or the address.
        assert_eq!(
            foreign_mesh_resolver(
                "# Added by rayfish - do not edit\nnameserver 100.100.100.53\nnameserver 1.1.1.1\n"
            ),
            None
        );
        assert_eq!(
            foreign_mesh_resolver("nameserver 100.100.100.53\nnameserver 1.1.1.1\n"),
            None
        );
        // resolv.conf(5) separates the keyword from its value by any run of
        // whitespace, and generators do emit a tab. Missing the entry here
        // would mean taking the file over and starting the rewrite war.
        assert_eq!(
            foreign_mesh_resolver("nameserver\t100.100.100.100\n"),
            Some("100.100.100.100".parse::<Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn reassert_merges_with_another_overlay_and_rewrites_over_anything_else() {
        let theirs: Ipv4Addr = "100.100.100.100".parse().unwrap();
        // Ours: nothing to do.
        assert_eq!(
            reassert_decision(
                "# Added by rayfish - do not edit\nnameserver 100.100.100.53\n",
                None
            ),
            Reassert::Held
        );
        // A trample by something that will not fight back: put ours back now.
        assert_eq!(
            reassert_decision(
                "# Generated by NetworkManager\nnameserver 192.168.1.1\n",
                None
            ),
            Reassert::Rewrite
        );
        // Another VPN took the file. Ours goes back on top of theirs, not
        // instead of it, and the caller waits out the cooldown first.
        assert_eq!(
            reassert_decision("nameserver 100.100.100.100\nsearch ts.net\n", None),
            Reassert::Merge(theirs)
        );
        // Same file, but this time we are the ones already merged with them:
        // still a merge, because their write dropped our nameserver.
        assert_eq!(
            reassert_decision("nameserver 100.100.100.100\n", Some(theirs)),
            Reassert::Merge(theirs)
        );
        // The overlay we were merged with is gone and the host's own servers are
        // back. Rewriting ours here would re-render `nameserver 100.100.100.100`
        // from a forwarder still pointed at it, so go recapture instead.
        assert_eq!(
            reassert_decision(
                "# Generated by NetworkManager\nnameserver 192.168.1.1\n",
                Some(theirs)
            ),
            Reassert::Reclaim
        );
    }

    /// The undo for an additive write. What is left has to be *their* file: our
    /// marker, our nameserver, and our search domains gone, theirs untouched.
    #[test]
    fn stripping_our_entries_leaves_the_other_vpn_theirs() {
        let merged = "# Added by rayfish - do not edit\nnameserver 100.100.100.53\nnameserver 100.100.100.100\nsearch tailnet.ts.net homelab.ray ray\n";
        assert_eq!(
            strip_our_resolv_entries(merged),
            "nameserver 100.100.100.100\nsearch tailnet.ts.net\n"
        );
        // The v6 magic IP is ours too (an IPv6-only host, which is exactly the
        // host that has another VPN on 100.64.0.0/10).
        let merged_v6 = "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 100.100.100.100\nsearch ray\n";
        assert_eq!(
            strip_our_resolv_entries(merged_v6),
            "nameserver 100.100.100.100\n"
        );
        // Nothing of ours in it: left exactly as found, so a revert that reads a
        // file the other VPN just rewrote does not touch it.
        let theirs = "nameserver 100.100.100.100\nsearch tailnet.ts.net\n";
        assert_eq!(strip_our_resolv_entries(theirs), theirs);
    }

    /// `foreign_mesh_resolver` stops at our marker, because it answers "did
    /// someone take this file". The revert path has to see through the marker:
    /// the file is ours precisely because we merged theirs into it.
    #[test]
    fn other_overlay_resolver_sees_through_our_own_marker() {
        let merged = "# Added by rayfish - do not edit\nnameserver 100.100.100.53\nnameserver 100.100.100.100\n";
        assert_eq!(foreign_mesh_resolver(merged), None);
        assert_eq!(
            other_overlay_resolver(merged),
            Some("100.100.100.100".parse::<Ipv4Addr>().unwrap())
        );
        // Ours alone is not another overlay, or every revert would think it was
        // merged and leave the file behind.
        let plain = "# Added by rayfish - do not edit\nnameserver 100.100.100.53\n";
        assert_eq!(other_overlay_resolver(plain), None);
    }

    #[test]
    fn first_nameserver_is_the_one_glibc_asks() {
        // A file resolvconf merged from two stanzas: only the first is queried.
        let merged = "# Dynamic resolv.conf\nnameserver 100.100.100.100\nnameserver 100.100.100.53\nsearch ts.net ray\n";
        assert_eq!(
            first_nameserver(merged),
            Some("100.100.100.100".parse().unwrap())
        );
        assert_eq!(
            first_nameserver("search ray\nnameserver\t200::53\n"),
            Some("200::53".parse().unwrap())
        );
        assert_eq!(first_nameserver("search ray\n"), None);
    }

    #[test]
    fn search_domains_keep_the_hosts_own_first() {
        let rayfish = search_domains_for(&networks(&["homelab", "work"]));
        // The suffix is applied exactly once, by the constructor: a network
        // name goes in and a search domain comes out, and they are now
        // different types, so the output cannot be fed back through.
        assert_eq!(join_domains(&rayfish), "homelab.ray work.ray ray");
        // The host's own domains still resolve, and a domain named twice is
        // listed once (glibc caps the search list, so duplicates cost real
        // candidates).
        assert_eq!(
            join_domains(&merge_search_domains(&host(&["lan", "ray"]), &rayfish)),
            "lan ray homelab.ray work.ray"
        );
        assert_eq!(merge_search_domains(&[], &rayfish), rayfish);
        // Reading back a file we wrote must not turn our own domains into the
        // host's, or a `ray leave` would never drop them.
        assert!(SearchDomain::from_host("ray").is_ours());
        assert!(SearchDomain::from_host("homelab.ray").is_ours());
        assert!(!SearchDomain::from_host("lan").is_ours());
        assert!(!SearchDomain::from_host("notray").is_ours());
    }

    #[test]
    fn search_domains_overflow_keeps_the_catch_all() {
        // Three host domains plus four networks is eight entries, and the
        // resolver reads six. `ray` is last in our list, so a plain truncation
        // drops the one entry that makes any bare mesh name resolve.
        let captured = host(&["corp.example.com", "example.com", "lan"]);
        let rayfish = search_domains_for(&networks(&["a", "b", "c", "d"]));
        let merged = merge_search_domains(&captured, &rayfish);
        assert_eq!(merged.len(), 6);
        // The host's own domains outrank ours: they resolved here before.
        assert_eq!(
            join_domains(&merged),
            "corp.example.com example.com lan a.ray b.ray ray"
        );
        // Already inside the cap: nothing is rearranged.
        let small = merge_search_domains(&host(&["lan"]), &search_domains_for(&[]));
        assert_eq!(join_domains(&small), "lan ray");
    }

    /// The re-assert loop reads the domains through a shared handle rather than
    /// the snapshot it started with, so a join or leave lands in the file the
    /// next repair writes. This is the staleness `SearchDomains` exists to fix.
    #[test]
    fn reassert_renders_the_live_search_list() {
        let handle = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(search_domains_for(&[])));
        assert!(render_direct_resolv_conf(&handle.load(), &[]).contains("search ray\n"));
        handle.store(std::sync::Arc::new(search_domains_for(&networks(&[
            "homelab",
        ]))));
        assert!(
            render_direct_resolv_conf(&handle.load(), &[]).contains("search homelab.ray ray\n")
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
        let out = render_direct_resolv_conf(&search_domains_for(&networks(&["homelab"])), &[]);
        assert!(out.starts_with("# Added by rayfish"));
        assert!(out.contains("nameserver 100.100.100.53"));
        assert!(out.contains("search homelab.ray ray"));
    }

    /// An IPv6-only host must be pointed at the v6 resolver: the v4 one sits in
    /// `100.64.0.0/10`, which on such a host belongs to another VPN that drops
    /// our reply on the way back in.
    #[test]
    fn render_direct_resolv_conf_can_point_at_the_v6_magic_ip() {
        let out = render_direct_resolv_conf_with(
            std::net::IpAddr::V6(crate::dns::MAGIC_DNS_V6),
            &search_domains_for(&[]),
            &["1.1.1.1".parse().unwrap()],
        );
        assert!(out.contains("nameserver 200::53"));
        assert!(!out.contains("100.100.100.53"));
        // The upstream fallback is still IPv4: it is a real resolver reached
        // over the underlay, not something the mesh carries.
        assert!(out.contains("nameserver 1.1.1.1"));
    }

    /// Whichever address we installed, a revert has to take it back out. A
    /// switch into or out of IPv6-only mode leaves the other one in the file.
    #[test]
    #[cfg(target_os = "linux")]
    fn strip_removes_either_magic_address() {
        let v6 = "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 9.9.9.9\n";
        assert_eq!(strip_our_resolv_entries(v6), "nameserver 9.9.9.9\n");
        let v4 =
            "# Added by rayfish - do not edit\nnameserver 100.100.100.53\nnameserver 9.9.9.9\n";
        assert_eq!(strip_our_resolv_entries(v4), "nameserver 9.9.9.9\n");
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
        let out = render_direct_resolv_conf(&[], &[]);
        assert!(out.contains("nameserver 100.100.100.53"));
        assert!(!out.contains("search "));
    }

    #[test]
    fn render_direct_resolv_conf_lists_fallback_after_magic_ip() {
        let out = render_direct_resolv_conf(&[], &["192.168.1.1".parse().unwrap()]);
        // Order is load-bearing: the resolver library tries entries top-down, so
        // ours must come first or `.ray` names go to the upstream and NXDOMAIN.
        let magic = out.find("nameserver 100.100.100.53").unwrap();
        let fallback = out.find("nameserver 192.168.1.1").unwrap();
        assert!(magic < fallback, "magic IP must be listed first:\n{out}");
    }

    /// Every captured server is written, not just the first: on a host where we
    /// decline names outside `.ray`, these lines *are* the resolution path for
    /// everything else, so dropping one drops what the stub tries next.
    #[test]
    fn render_direct_resolv_conf_carries_every_server_up_to_maxns() {
        let servers: Vec<Ipv4Addr> = ["100.100.100.100", "192.168.1.1", "9.9.9.9"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let out = render_direct_resolv_conf(&[], &servers);
        assert!(out.contains("nameserver 100.100.100.100\n"));
        assert!(out.contains("nameserver 192.168.1.1\n"));
        // Ours plus two is glibc's MAXNS; a fourth line is read by nobody, and
        // writing it would only misrepresent what the host will actually try.
        assert!(!out.contains("9.9.9.9"));
        assert_eq!(out.matches("nameserver ").count(), MAX_NAMESERVERS);
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
}
