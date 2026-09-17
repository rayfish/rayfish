//! OS-level DNS resolver configuration for Magic DNS.
//!
//! Configures the system to route `.ray` queries to our local resolver at
//! `[200::53]:53`.
//! macOS: SCDynamicStore with session keys (auto-cleanup on process exit).
//! Linux: systemd-resolved / resolvconf / direct /etc/resolv.conf.

use std::net::IpAddr;
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AtomicOrdering};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::Duration;
// Only the macOS/Linux configurators build resolver/backup file paths; Android
// does no OS-level DNS configuration.
#[cfg(any(target_os = "macos", target_os = "linux"))]
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

use crate::DNS_DOMAIN;

/// The address to hand the OS as the `.ray` nameserver. Always the v6 one: the
/// overlay carries no IPv4, and `100.64.0.0/10` belongs to whatever other VPN
/// shares the host, which would drop our reply before it reached the stub.
pub fn resolver_addr() -> IpAddr {
    IpAddr::V6(crate::dns::MAGIC_DNS_V6)
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

    /// The bare network name this was built from, for a `<network>.ray`.
    ///
    /// `None` for the `ray` root and for anything captured from the host, which
    /// name no network of ours. Windows wants both forms and is handed only
    /// this list, so the split happens here rather than by re-splitting strings
    /// at the call site, which is the confusion the type exists to prevent.
    #[cfg(any(windows, test))]
    fn network_name(&self) -> Option<&str> {
        self.0
            .strip_suffix(&format!(".{DNS_DOMAIN}"))
            .filter(|name| !name.is_empty() && !name.contains('.'))
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
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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
        // NetworkManager is deliberately not a rung: it sets nameservers through
        // `IP4Config.Nameservers`, a `u32` array that cannot carry the IPv6
        // address the mesh resolver answers on. The ladder falls through to
        // resolvconf or a direct `resolv.conf`, both of which take either family.
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
    // macOS clears by *removing* the keys, not by writing an empty search list.
    // The only caller is `DnsService::revert`, which has already run the
    // backend's own revert, and on macOS the sole way to set search domains is
    // `write_dns_config`, which rewrites `ServerAddresses` and (while the tunnel
    // flag is still up, which it is at this point in `deactivate`) the empty
    // catch-all match domain. Routing a *clear* through the *set* path therefore
    // re-armed the whole host's resolver, pointed at a `200::53` that stops
    // answering the moment the TUN goes down.
    #[cfg(target_os = "macos")]
    {
        let _ = tun_name;
        macos::remove_dns_config();
    }
    #[cfg(not(target_os = "macos"))]
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
    #[cfg(windows)]
    {
        set_search_domains_windows(rayfish_domains, tun_name).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (rayfish_domains, tun_name);
        Ok(())
    }
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::*;

// ---------------------------------------------------------------------------
// macOS: SCDynamicStore
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
use macos::MacosDynamicStoreDns;

/// The system's default resolvers *right now*, as opposed to the set captured
/// when the backend was detected.
///
/// [`DnsConfigurator::captured_upstreams`] is a snapshot taken once, before we
/// install our own configuration, and it stays frozen for the life of the
/// backend. That is wrong the moment the host's DNS moves under it: joining
/// another network, or another VPN connecting or disconnecting, replaces the
/// resolvers the snapshot names, and the forwarder keeps sending every non-`.ray`
/// name to addresses that have stopped answering. Connecting a VPN and then
/// restarting is the worst version, because the snapshot then holds *that VPN's*
/// resolvers and they become black holes the moment it disconnects.
///
/// See [`crate::daemon::dns_service::DnsService::run_upstream_refresh`], which
/// polls this and re-points the forwarder at whatever currently answers.
#[cfg(target_os = "macos")]
pub fn live_system_upstreams() -> Vec<std::net::Ipv4Addr> {
    macos::capture_system_upstreams()
}

#[cfg(target_os = "macos")]
fn write_dns_config_macos(search_domains: &[SearchDomain], tun_name: &str) -> Result<()> {
    macos::write_dns_config(search_domains, tun_name)
}

/// How often the macOS re-assert pass reads its own key back.
///
/// A plain delay, not a deadline like the Linux `REASSERT_TICK`: nothing else
/// drives that loop, so the interval is also the worst case for how long `.ray`
/// stays unresolvable after another VPN drops our key. The pass is one Mach IPC
/// round trip to configd, so it is cheap enough to ask often.
#[cfg(target_os = "macos")]
pub const SC_REASSERT_TICK: Duration = Duration::from_secs(5);

#[cfg(target_os = "macos")]
pub use macos::DnsKeyState;

/// Who holds the macOS DNS configuration right now.
///
/// There is no SCDynamicStore equivalent of the inotify watch
/// `run_resolv_reassert` uses: a notification would need its own store with a
/// callback context and a thread running a `CFRunLoop`, and the store this
/// backend holds is deliberately built without one. Asking on a timer gets the
/// same repair for one `SCDynamicStoreCopyValue` every few seconds.
#[cfg(target_os = "macos")]
pub fn dns_key_state() -> DnsKeyState {
    macos::dns_key_state()
}

/// Drop the macOS DNS keys, with or without a configurator to do it for us.
///
/// The re-assert loop uses this to undo a write that lost a race with `revert`:
/// by then the configurator has been taken and its `revert` has already run, so
/// there is nothing left holding the keys we just put back. Idempotent.
#[cfg(target_os = "macos")]
pub fn remove_dns_config() {
    macos::remove_dns_config();
}

mod linux_backend;
#[cfg(target_os = "linux")]
pub(crate) use linux_backend::nm_quiet_remove;
pub(crate) use linux_backend::system_nameservers;
#[cfg(any(target_os = "linux", test))]
use linux_backend::*;
#[cfg(target_os = "linux")]
pub use linux_backend::{Recapture, emergency_restore_resolv_conf, run_resolv_reassert};

/// No-op on non-Linux: only the direct `/etc/resolv.conf` takeover has artifacts
/// to restore.
#[cfg(not(target_os = "linux"))]
pub fn emergency_restore_resolv_conf() {}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        MAX_NAMESERVERS, NmQuietOutcome, Reassert, SearchDomain, first_nameserver,
        foreign_mesh_resolver, join_domains, merge_search_domains, nm_dns_none_dropin,
        nm_quiet_outcome, other_overlay_resolver, parse_resolv_nameservers, reassert_decision,
        render_direct_resolv_conf, render_direct_resolv_conf_with, resolv_conf_is_ours,
        search_domains_for, strip_our_resolv_entries,
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

    /// Windows is handed only the search domains and has to recover the bare
    /// network names from them, for the NRPT namespaces. The two lists must not
    /// be interchangeable: a bare `homelab` in the machine-wide
    /// `SuffixSearchList` would be appended to every unqualified lookup on the
    /// host, and it survived `ray down` and uninstall once because it was never
    /// recorded as one of ours.
    #[test]
    fn only_a_network_dot_ray_yields_a_network_name() {
        fn names(domains: &[SearchDomain]) -> Vec<String> {
            domains
                .iter()
                .filter_map(SearchDomain::network_name)
                .map(str::to_owned)
                .collect()
        }

        assert_eq!(
            names(&search_domains_for(&networks(&["homelab"]))),
            ["homelab"]
        );
        // The `ray` root is in every list and names no network.
        assert!(names(&search_domains_for(&[])).is_empty());
        // Nothing the host already had is ours to turn into a namespace, even
        // when it happens to end in our domain.
        assert!(names(&host(&["corp", "other.example.com"])).is_empty());
        // A deeper name under `.ray` is not a network either.
        assert!(names(&host(&["box.homelab.ray"])).is_empty());
    }

    #[test]
    fn resolv_conf_is_ours_detects_marker() {
        assert!(resolv_conf_is_ours(
            "# Added by rayfish - do not edit\nnameserver 200::53\n"
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
                "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 1.1.1.1\n"
            ),
            None
        );
        assert_eq!(
            foreign_mesh_resolver("nameserver 200::53\nnameserver 1.1.1.1\n"),
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
                "# Added by rayfish - do not edit\nnameserver 200::53\n",
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
        let merged = "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 100.100.100.100\nsearch tailnet.ts.net homelab.ray ray\n";
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
        let merged =
            "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 100.100.100.100\n";
        assert_eq!(foreign_mesh_resolver(merged), None);
        assert_eq!(
            other_overlay_resolver(merged),
            Some("100.100.100.100".parse::<Ipv4Addr>().unwrap())
        );
        // Ours alone is not another overlay, or every revert would think it was
        // merged and leave the file behind.
        let plain = "# Added by rayfish - do not edit\nnameserver 200::53\n";
        assert_eq!(other_overlay_resolver(plain), None);
    }

    #[test]
    fn first_nameserver_is_the_one_glibc_asks() {
        // A file resolvconf merged from two stanzas: only the first is queried.
        let merged = "# Dynamic resolv.conf\nnameserver 100.100.100.100\nnameserver 200::53\nsearch ts.net ray\n";
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

    /// NetworkManager in `dns=dnsmasq` mode is the case this exists for: it puts
    /// its own loopback forwarder in `resolv.conf`, we capture it while it is
    /// alive, and then `dns=none` stops it. The pre-quiet capture is not evidence
    /// about the post-quiet host, and taking the file over on the strength of it
    /// owns DNS for the machine with nothing behind us.
    #[test]
    fn quieting_networkmanager_can_invalidate_the_capture_that_allowed_the_takeover() {
        let nm = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
        let router = "192.168.1.1".parse::<Ipv4Addr>().unwrap();

        // The regression: NM's dnsmasq was the only thing we captured, and
        // quieting NM killed it. Refuse, rather than install the black hole.
        assert_eq!(
            nm_quiet_outcome(&[nm], &[], false),
            NmQuietOutcome::Abort,
            "the last surviving upstream died with NM's dnsmasq"
        );
        // The operator named their own servers, so there is still somewhere to
        // forward: the same waiver the `ensure!` gives. Still degraded, not
        // clean -- the dead entry is in the file we are about to write.
        assert_eq!(
            nm_quiet_outcome(&[nm], &[], true),
            NmQuietOutcome::Degraded(vec![nm])
        );
        // A real router alongside NM's forwarder: degraded, not fatal. The dead
        // entry is named so it can be seen rather than silently costing timeouts.
        assert_eq!(
            nm_quiet_outcome(&[nm, router], &[router], false),
            NmQuietOutcome::Degraded(vec![nm])
        );
        // Nothing died (NM absent, or not running a local forwarder).
        assert_eq!(
            nm_quiet_outcome(&[router], &[router], false),
            NmQuietOutcome::Proceed
        );
        assert_eq!(nm_quiet_outcome(&[], &[], true), NmQuietOutcome::Proceed);
    }

    /// A host that had no working DNS *before* the quiet is not evidence about
    /// NetworkManager, whatever it looks like afterwards.
    ///
    /// This is the shape a passing blip takes: a boot, a reassociating link, a
    /// capture minutes old. `apply` refuses it ahead of `backup_file` with an
    /// ordinary error the retry loop retries, so it must not reach the abort that
    /// latches the takeover off for the life of the daemon.
    #[test]
    fn nothing_answering_before_the_quiet_is_not_a_verdict_about_networkmanager() {
        assert_eq!(nm_quiet_outcome(&[], &[], false), NmQuietOutcome::Proceed);
        // And the abort still fires when something *was* answering and stopped,
        // which is the case it exists for.
        let nm = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
        assert_eq!(nm_quiet_outcome(&[nm], &[], false), NmQuietOutcome::Abort);
    }

    /// `Degraded` is not just a warning: the surviving set is what gets rendered
    /// into the file and seeded into the forwarder, and a dead entry in either
    /// costs a full lookup timeout on every off-mesh name.
    #[test]
    fn a_degraded_verdict_names_exactly_the_servers_that_died() {
        let nm = "127.0.0.1".parse::<Ipv4Addr>().unwrap();
        let router = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
        let public = "9.9.9.9".parse::<Ipv4Addr>().unwrap();
        // What survives is `after`, so the caller can store it directly; what is
        // reported is the complement, so the operator can see what it cost.
        assert_eq!(
            nm_quiet_outcome(&[nm, router, public], &[router, public], false),
            NmQuietOutcome::Degraded(vec![nm])
        );
        assert_eq!(
            nm_quiet_outcome(&[nm, router, public], &[public], false),
            NmQuietOutcome::Degraded(vec![nm, router])
        );
    }

    /// The scenario above is only reachable because a loopback nameserver is
    /// captured like any other. If this ever starts filtering them, the guard
    /// above becomes dead code rather than wrong.
    #[test]
    fn a_loopback_nameserver_is_captured_like_any_other() {
        let c = "# Generated by NetworkManager\nnameserver 127.0.0.1\n";
        assert_eq!(
            parse_resolv_nameservers(c),
            vec!["127.0.0.1".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn parse_resolv_nameservers_extracts_ipv4_excluding_magic() {
        // Both magic addresses are dropped, by different mechanisms: the v6 one
        // fails the `Ipv4Addr` parse, the v4 one is filtered by name. Only the
        // second is a rule this function has to carry, so it has to be present or
        // the filter could be deleted with every test still passing.
        let c = "# Generated by NetworkManager\nsearch home\nnameserver 192.168.1.1\n\
                 nameserver 100.100.100.53\nnameserver 8.8.8.8\nnameserver 200::53\n";
        assert_eq!(
            parse_resolv_nameservers(c),
            vec![
                "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
                "8.8.8.8".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn render_direct_resolv_conf_points_at_magic_ip() {
        let out = render_direct_resolv_conf(&search_domains_for(&networks(&["homelab"])), &[]);
        assert!(out.starts_with("# Added by rayfish"));
        assert!(out.contains("nameserver 200::53"));
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
    /// upgrade leaves the IPv4 one sitting in a file we are the ones to clean up.
    #[test]
    #[cfg(target_os = "linux")]
    fn strip_removes_either_magic_address() {
        let v6 = "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 9.9.9.9\n";
        assert_eq!(strip_our_resolv_entries(v6), "nameserver 9.9.9.9\n");
        // The v4 half is the whole reason `MAGIC_DNS_V4` still exists as a
        // constant, so it has to be the address an older build actually wrote.
        let v4 =
            "# Added by rayfish - do not edit\nnameserver 100.100.100.53\nnameserver 9.9.9.9\n";
        assert_eq!(strip_our_resolv_entries(v4), "nameserver 9.9.9.9\n");
        // And both at once: a file written across the upgrade names each.
        let both = "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 100.100.100.53\nnameserver 9.9.9.9\n";
        assert_eq!(strip_our_resolv_entries(both), "nameserver 9.9.9.9\n");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn backup_less_revert_keeps_the_other_nameservers() {
        // Verbatim from a host running direct mode. A revert with no backup used
        // to delete this file outright, leaving the machine with no resolver at
        // all; it must come back as the upstream it had before we prepended ours.
        let ours =
            "# Added by rayfish - do not edit\nnameserver 200::53\nnameserver 108.61.10.10\n";
        assert_eq!(strip_our_resolv_entries(ours), "nameserver 108.61.10.10\n");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn backup_less_revert_preserves_search_domains_and_options() {
        let ours = "# Added by rayfish - do not edit\nsearch home lan\nnameserver 200::53\nnameserver 1.1.1.1\noptions ndots:2\n";
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
        let ours = "# Added by rayfish - do not edit\nnameserver 200::53\n";
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
        assert!(out.contains("nameserver 200::53"));
        assert!(!out.contains("search "));
    }

    #[test]
    fn render_direct_resolv_conf_lists_fallback_after_magic_ip() {
        let out = render_direct_resolv_conf(&[], &["192.168.1.1".parse().unwrap()]);
        // Order is load-bearing: the resolver library tries entries top-down, so
        // ours must come first or `.ray` names go to the upstream and NXDOMAIN.
        let magic = out.find("nameserver 200::53").unwrap();
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
            next_managed_suffixes, ps_quote, resolver_addr, suffix_rollback_cas_matches,
            touched_rule_displays, windows_dns_reconcile_script, windows_dns_rollback_script,
            windows_dns_snapshot_script, windows_nrpt_domains,
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
        // Both spellings of the nameserver, because the script's own comment
        // promises they are rendered from one value and cannot drift apart.
        let resolver = resolver_addr();
        assert!(one.contains(&format!("@($_.NameServers)[0] -eq '{resolver}'")));
        assert!(one.contains(&format!("-NameServers '{resolver}'")));
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
