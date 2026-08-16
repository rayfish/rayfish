//! `DnsService`: Magic DNS, a leaf service in the daemon dependency graph.
//!
//! Holds the `.ray` naming tables (the single source of truth that the mesh
//! roster writes and the in-daemon resolver reads), the resolver itself, and the
//! OS-DNS configurator/re-assert handles owned while the data plane is active.
//! It depends on nothing above it and holds no back-reference to the daemon: all
//! input arrives as method arguments (a roster to publish, a name to resolve),
//! all output is the return value. Shared as `Arc<DnsService>` into its
//! consumers (the roster writers and the packet-path resolver). The OS-DNS
//! lifecycle (`configure`/`revert`) takes the TUN name as a parameter since the
//! foundation owns it.
//!
//! Named-interface methods: `sync_network` / `clear_network` (writer side) and
//! `resolve` (reader side), on top of `configure` / `revert` (lifecycle).

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::membership::is_overlay_ip;

/// First and last backoff step for the OS-DNS configuration retry loop.
const DNS_CONFIG_RETRY_MIN: Duration = Duration::from_secs(5);
const DNS_CONFIG_RETRY_MAX: Duration = Duration::from_secs(60);

pub(crate) struct DnsService {
    /// `.ray` forward lookup table (hostname → IP). Cloned into `MeshCtx` and the
    /// resolver; the roster is the single source of truth that writes it.
    pub(crate) hostname_table: dns::HostnameTable,
    /// `.ray` reverse lookup table (IP → hostname).
    pub(crate) reverse_table: dns::ReverseLookupTable,
    /// In-daemon Magic DNS resolver (answers `.ray` queries intercepted via TUN).
    pub(crate) resolver: std::sync::Arc<crate::dns::resolver::Resolver>,
    /// The system-DNS configurator owned while active, so `revert` can undo it and
    /// `reassert_os_config` can re-apply it. `Arc` (not `Box`) so a re-apply can
    /// clone it out and run without holding the lock across the await.
    configurator: Arc<Mutex<Option<Arc<dyn dns_config::DnsConfigurator>>>>,
    /// Cancellation token for the `run_resolv_reassert` task (Linux direct mode).
    reassert_token: Mutex<Option<tokio_util::sync::CancellationToken>>,
    /// Cancellation token for the retry loop spawned when the initial OS-DNS
    /// configuration fails (see [`DnsService::configure`]).
    configure_retry: Mutex<Option<CancellationToken>>,
    /// The search domains last derived from the joined networks. Kept so a
    /// backend adopted *after* the registry last announced them (the usual
    /// order at startup, and every reconfigure after a retry or a stand-down)
    /// still gets them; it is a cache of the argument, not a back-reference to
    /// the registry that produced it.
    search_domains: Mutex<Vec<dns_config::SearchDomain>>,
    /// This node's identity-derived mesh IPv6. Handed to the OS-DNS backend,
    /// which on macOS publishes it as the address of the service our resolver
    /// belongs to; never rotates, so it is captured once at construction.
    mesh_v6: Ipv6Addr,
}

impl DnsService {
    pub(crate) fn new(
        hostname_table: dns::HostnameTable,
        reverse_table: dns::ReverseLookupTable,
        resolver: std::sync::Arc<crate::dns::resolver::Resolver>,
        mesh_v6: Ipv6Addr,
    ) -> Self {
        Self {
            hostname_table,
            reverse_table,
            resolver,
            configurator: Arc::new(Mutex::new(None)),
            reassert_token: Mutex::new(None),
            configure_retry: Mutex::new(None),
            search_domains: Mutex::new(Vec::new()),
            mesh_v6,
        }
    }

    /// Drop a network's `.ray` names entirely (on leave / nuke / kick).
    pub(crate) async fn clear_network(&self, network: &str) {
        dns::remove_network(&self.hostname_table, &self.reverse_table, network).await;
    }

    /// Resolve a fully-qualified `.ray` name against the forward table. Reader
    /// side (packet path); returns `None` for names outside the mesh.
    pub(crate) async fn resolve(&self, name: &str, suffix: &str) -> Option<dns::HostnameEntry> {
        dns::resolve_name(name, suffix, &self.hostname_table).await
    }

    /// Point system DNS at the in-daemon Magic DNS resolver: detect the OS DNS
    /// backend, merge any user-configured upstreams over the captured ones, and
    /// (Linux direct-resolv.conf mode) spawn the inotify re-assert watcher.
    /// Failures are non-fatal: pushed to `warnings` so `ray up` can surface them.
    pub(crate) async fn configure(self: &Arc<Self>, tun_name: &str, warnings: &mut Vec<String>) {
        // Configure system DNS to route .ray queries to our in-daemon resolver.
        dns_config::restore_stale_backups();
        if let Some(retry) = self.configure_retry.lock().unwrap().take() {
            retry.cancel();
        }
        match dns_config::detect_and_configure(tun_name, self.mesh_v6).await {
            Ok(c) => self.adopt_configurator(c, tun_name).await,
            Err(e) => {
                tracing::warn!(error = %e, "failed to configure system DNS, retrying in the background");
                warnings.push(format!(
                    "failed to configure system DNS, so .ray names won't resolve yet: {e}"
                ));
                self.spawn_configure_retry(tun_name.to_string(), DNS_CONFIG_RETRY_MIN);
            }
        }
    }

    /// The upstreams for everything the delegations do not claim.
    ///
    /// Without a delegation this is just what detection captured. With one, the
    /// file we captured from is the other mesh's, so what it named is their
    /// resolver, and pointing the host's general traffic there is both a detour
    /// for names neither mesh owns and the leg that loops if they are pointed
    /// back at us. Real servers we already knew are the host's own and nothing
    /// in the shared file will name them again, so they are kept when the merge
    /// would otherwise leave us with nothing but the other mesh's resolver.
    fn general_upstreams(&self, captured: Vec<Ipv4Addr>, delegating: bool) -> Vec<Ipv4Addr> {
        if !delegating || captured.iter().any(|ip| !is_overlay_ip(IpAddr::V4(*ip))) {
            return captured;
        }
        let retained: Vec<Ipv4Addr> = self
            .resolver
            .upstreams()
            .into_iter()
            .filter_map(|a| match a.ip() {
                IpAddr::V4(ip) if !is_overlay_ip(IpAddr::V4(ip)) => Some(ip),
                _ => None,
            })
            .collect();
        if retained.is_empty() {
            // Nothing but theirs, which is the ordinary case when they had the
            // file first: they hold the host's real servers, so forwarding the
            // rest to them is right and cannot loop back through us.
            captured
        } else {
            tracing::info!(
                upstreams = ?retained,
                "keeping the host's own resolvers for general traffic; the shared file names \
                 only the other mesh's"
            );
            retained
        }
    }

    /// Take ownership of a detected OS-DNS backend: seed the resolver's
    /// upstreams, keep the configurator for `revert`, install the current search
    /// domains, and (Linux direct mode) start the inotify re-assert watcher.
    async fn adopt_configurator(
        self: &Arc<Self>,
        c: Box<dyn dns_config::DnsConfigurator>,
        tun_name: &str,
    ) {
        let captured = c.captured_upstreams();
        // Merge any user-configured DNS upstreams over the system-captured
        // set (replace drops the captured ones; augment tries custom first).
        let dns_override = config::load().map(|c| c.dns_upstreams).unwrap_or_default();
        let upstreams = config::resolve_upstreams(&dns_override, captured);
        #[cfg(target_os = "linux")]
        let search_handle = c.search_handle();
        #[cfg(target_os = "linux")]
        let fallback = c.fallback_upstream();
        let delegation = c.delegated_domains();
        let upstreams = self.general_upstreams(upstreams, delegation.is_some());
        tracing::info!(backend = c.name(), resolver_ip = %dns_config::resolver_addr(), upstreams = ?upstreams, "Magic DNS active");
        self.resolver.set_upstreams(upstreams);
        self.resolver.set_delegations(
            delegation
                .into_iter()
                .flat_map(|(domains, resolver)| {
                    let addr = SocketAddr::from((resolver, 53u16));
                    domains
                        .into_iter()
                        .map(move |d| dns::resolver::Delegation::new(d.as_str(), addr))
                })
                .collect(),
        );
        let c: Arc<dyn dns_config::DnsConfigurator> = Arc::from(c);
        *self.configurator.lock().unwrap() = Some(Arc::clone(&c));

        // The registry announces the search domains when networks are restored,
        // which at startup is before any of this ran. Install what it said into
        // the backend we just adopted, or a host on a file-owning backend gets
        // `.ray` without the domains that make a bare `box` resolve.
        let domains = self.search_domains.lock().unwrap().clone();
        if !domains.is_empty()
            && let Err(e) = c.set_search_domains(&domains, tun_name).await
        {
            tracing::warn!(error = %e, "failed to install search domains");
        }

        // In direct mode, re-assert /etc/resolv.conf the instant another
        // program (NetworkManager, dhclient) overwrites it (inotify watch).
        // Only that backend hands back a search handle, and only it writes the
        // file the watcher guards.
        #[cfg(target_os = "linux")]
        if let Some(search) = search_handle {
            let rt = tokio_util::sync::CancellationToken::new();
            *self.reassert_token.lock().unwrap() = Some(rt.clone());
            // Weak: the watcher outlives nothing. A shutdown that never got to
            // `revert` should not be held open by a task waiting on a 30s tick.
            let me = Arc::downgrade(self);
            let tun_name = tun_name.to_string();
            let watcher = rt.clone();
            tokio::spawn(async move {
                // The watcher can return a verdict it decided just before
                // `revert` cancelled it: the select arm is already committed by
                // then, so the cancel is only visible here. Acting on a stale
                // verdict would re-arm DNS for a data plane that is down.
                if let Some(why) = dns_config::run_resolv_reassert(search, fallback, rt).await
                    && !watcher.is_cancelled()
                    && let Some(me) = me.upgrade()
                {
                    me.recapture(why, tun_name, &watcher);
                }
            });
        }
    }

    /// The set of resolvers in `/etc/resolv.conf` changed under us: another VPN
    /// took the file, or the one we had merged with left it. Rebuild the backend
    /// from the file as it stands now.
    ///
    /// Re-running detection rather than patching in place is what keeps the
    /// forwarder honest. The upstreams we forward to were captured and probed
    /// from this file, so when its nameservers change, ours have to be captured
    /// and probed again: merging means forwarding everything outside `.ray` to
    /// the other VPN's resolver, and reclaiming means noticing that resolver is
    /// gone before we send the host's DNS to an address that stopped answering.
    ///
    /// No `revert` first. The old configurator's undo is subtractive now, and
    /// running it here would strip the very entries `apply` is about to write.
    /// The backup and the `dns=none` drop-in both survive the swap, which is
    /// what we want: `apply` keeps the first backup it took, and re-quieting NM
    /// is idempotent.
    ///
    /// Detection runs through the retry loop with no initial delay rather than
    /// inline: the loop is already the thing that owns "keep trying until the
    /// host's DNS makes sense", and going through it keeps this off the cycle
    /// `adopt_configurator` -> watcher -> here -> `adopt_configurator`, which
    /// the compiler cannot prove `Send` when it is all one chain of awaits.
    ///
    /// `watcher` is the token of the watcher that reported this, and it is what
    /// says the verdict is still current: `revert` cancels it on the way down,
    /// and re-arming DNS after that would point a downed data plane back at us.
    #[cfg(target_os = "linux")]
    fn recapture(
        self: &Arc<Self>,
        why: dns_config::Recapture,
        tun_name: String,
        watcher: &CancellationToken,
    ) {
        match why {
            dns_config::Recapture::Merge(ip) => tracing::info!(
                resolver = %ip,
                "another VPN wrote /etc/resolv.conf; merging ours back in ahead of theirs"
            ),
            dns_config::Recapture::Reclaim => tracing::info!(
                "the VPN sharing /etc/resolv.conf is gone; recapturing the host's own resolvers"
            ),
        }
        self.reassert_token.lock().unwrap().take();
        self.configurator.lock().unwrap().take();
        if watcher.is_cancelled() {
            return;
        }
        self.spawn_configure_retry(tun_name, Duration::ZERO);
    }

    /// Install the OS search domains for the currently joined networks, through
    /// whichever backend holds DNS.
    ///
    /// Dispatching matters: only the backends that own a file can carry these
    /// on a host with no DNS manager, and they are exactly the backends a host
    /// without one ends up on. With no backend adopted yet (standby, or before
    /// the data plane comes up) it still tries the manager path, which is what
    /// it always did, and the list is remembered for whatever gets adopted next.
    pub(crate) async fn set_search_domains(&self, network_names: &[String], tun_name: &str) {
        let domains = dns_config::search_domains_for(network_names);
        *self.search_domains.lock().unwrap() = domains.clone();
        let configurator = self.configurator.lock().unwrap().clone();
        let result = match configurator.as_ref() {
            Some(c) => c.set_search_domains(&domains, tun_name).await,
            None => dns_config::set_manager_search_domains(&domains, tun_name).await,
        };
        match result {
            Ok(()) => tracing::info!(search = ?domains, "updated search domains"),
            Err(e) => tracing::warn!(error = %e, "failed to update search domains"),
        }
    }

    /// Keep trying to configure OS DNS in the background after the first attempt
    /// failed. Detection refuses to take DNS over when the host has no working
    /// upstream to forward to, which is exactly the state a machine is in when
    /// the daemon starts before the network settles after a reboot. Without a
    /// retry that verdict was permanent: `.ray` names stayed unresolvable for
    /// the daemon's lifetime even once the host's DNS came back. Cancelled by
    /// `revert` (the data plane going down) and by a later `configure`.
    ///
    /// `first_delay` is how long to wait before the first attempt. It is the
    /// backoff floor for a failure (there is no point asking again immediately)
    /// and [`Duration::ZERO`] for `recapture`, where the file has demonstrably
    /// just changed and the whole point is to act on it now.
    fn spawn_configure_retry(self: &Arc<Self>, tun_name: String, first_delay: Duration) {
        let token = CancellationToken::new();
        *self.configure_retry.lock().unwrap() = Some(token.clone());
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut delay = first_delay;
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
                match dns_config::detect_and_configure(&tun_name, me.mesh_v6).await {
                    Ok(c) => {
                        // `revert` may have run while detection was in flight; it
                        // cancelled us, so drop the configuration on the floor
                        // rather than pointing a downed data plane's DNS at us.
                        if token.is_cancelled() {
                            let _ = dns_config::revert(c.as_ref()).await;
                            return;
                        }
                        me.adopt_configurator(c, &tun_name).await;
                        me.configure_retry.lock().unwrap().take();
                        return;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, retry_in = ?delay, "system DNS still not configurable");
                    }
                }
                // `max` first so a zero first delay backs off like any other
                // failure instead of spinning on a doubled zero.
                delay = (delay.max(DNS_CONFIG_RETRY_MIN) * 2).min(DNS_CONFIG_RETRY_MAX);
            }
        });
    }

    /// Re-apply the current OS-DNS configuration in place (no re-detect, no
    /// re-capture of upstreams). Called when the exit-node full-tunnel state flips
    /// so the macOS configurator rewrites its match domains: catch-all (route all
    /// DNS through Magic DNS, forwarded upstream via the tunnel) while an exit is
    /// up, `.ray`-only split DNS otherwise. No-op if DNS was never configured.
    ///
    /// macOS-only: it is the only platform whose exit-node client rewrites match
    /// domains, so elsewhere this is dead code and `-D warnings` says so.
    #[cfg(target_os = "macos")]
    pub(crate) async fn reassert_os_config(&self) {
        // Clone the Arc out, not the guard, so the lock isn't held across await.
        let configurator = self.configurator.lock().unwrap().clone();
        if let Some(configurator) = configurator
            && let Err(e) = configurator.apply().await
        {
            tracing::warn!(error = %e, "failed to re-apply system DNS after exit-node change");
        }
    }

    /// Revert the OS-DNS changes made by [`configure`](Self::configure): stop the
    /// re-assert watcher, restore the captured configurator, and clear the TUN's
    /// search domains. Idempotent (no-op if never configured).
    pub(crate) async fn revert(&self, tun_name: &str) {
        if let Some(rt) = self.reassert_token.lock().unwrap().take() {
            rt.cancel();
        }
        if let Some(retry) = self.configure_retry.lock().unwrap().take() {
            retry.cancel();
        }

        // Revert system DNS (extract the configurator before reverting so the
        // mutex guard isn't held across the call).
        let configurator = self.configurator.lock().unwrap().take();
        if let Some(configurator) = configurator
            && let Err(e) = dns_config::revert(configurator.as_ref()).await
        {
            tracing::warn!(error = %e, "failed to revert DNS configuration");
        }
        // Un-quiet NetworkManager even with no configurator to do it for us.
        // `recapture` drops the configurator while the `dns=none` drop-in is
        // still installed, so a revert landing in that window (or after the
        // re-detect it runs failed) would otherwise leave NM muted for good:
        // `DirectResolvConf::revert` is the only other thing that removes the
        // drop-in, and nothing else regenerates the file. Marker-guarded and
        // idempotent, so this is a no-op on every backend that never had one.
        #[cfg(target_os = "linux")]
        dns_config::nm_quiet_remove().await;
        dns_config::clear_search_domains(tun_name).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Arc<DnsService> {
        Arc::new(DnsService::new(
            dns::HostnameTable::default(),
            dns::ReverseLookupTable::default(),
            std::sync::Arc::new(crate::dns::resolver::Resolver::new(
                dns::HostnameTable::default(),
                dns::ReverseLookupTable::default(),
            )),
            Ipv6Addr::LOCALHOST,
        ))
    }

    const THEIRS: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);
    const REAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    /// With nothing delegated the captured set is used as-is, whatever is in
    /// it: this must not start second-guessing an ordinary host's resolvers.
    #[test]
    fn general_upstreams_are_the_captured_ones_without_a_delegation() {
        let s = service();
        assert_eq!(s.general_upstreams(vec![THEIRS], false), vec![THEIRS]);
        assert_eq!(s.general_upstreams(vec![REAL], false), vec![REAL]);
    }

    /// The shared file named a real server too, so there is nothing to repair.
    #[test]
    fn a_real_server_in_the_shared_file_is_kept() {
        let s = service();
        assert_eq!(
            s.general_upstreams(vec![THEIRS, REAL], true),
            vec![THEIRS, REAL]
        );
    }

    /// They took the file while we held it, so it names only their resolver.
    /// The host's own servers, which we captured before they arrived, are what
    /// general traffic should keep using: their names are delegated, and
    /// sending the rest to them is the leg that can loop back through us.
    #[test]
    fn the_hosts_own_resolvers_survive_a_merge_that_hides_them() {
        let s = service();
        s.resolver.set_upstreams(vec![REAL]);
        assert_eq!(s.general_upstreams(vec![THEIRS], true), vec![REAL]);
    }

    /// They had the file first, so we never saw the host's own servers. Theirs
    /// is all there is, and forwarding to them is right: they hold the real
    /// upstreams, so nothing comes back to us.
    #[test]
    fn with_nothing_else_known_their_resolver_is_the_general_one() {
        let s = service();
        assert_eq!(s.general_upstreams(vec![THEIRS], true), vec![THEIRS]);
    }
}
