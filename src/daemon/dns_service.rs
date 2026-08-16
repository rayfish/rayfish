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
use std::net::Ipv6Addr;

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
    configurator: Arc<std::sync::Mutex<Option<Arc<dyn dns_config::DnsConfigurator>>>>,
    /// Cancellation token for the `run_resolv_reassert` task (Linux direct mode).
    reassert_token: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>>,
    /// Cancellation token for the retry loop spawned when the initial OS-DNS
    /// configuration fails (see [`DnsService::configure`]).
    configure_retry: std::sync::Mutex<Option<CancellationToken>>,
    /// The search domains last derived from the joined networks. Kept so a
    /// backend adopted *after* the registry last announced them (the usual
    /// order at startup, and every reconfigure after a retry or a stand-down)
    /// still gets them; it is a cache of the argument, not a back-reference to
    /// the registry that produced it.
    search_domains: std::sync::Mutex<Vec<String>>,
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
            configurator: Arc::new(std::sync::Mutex::new(None)),
            reassert_token: std::sync::Mutex::new(None),
            configure_retry: std::sync::Mutex::new(None),
            search_domains: std::sync::Mutex::new(Vec::new()),
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
                self.spawn_configure_retry(tun_name.to_string());
            }
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
        tracing::info!(backend = c.name(), resolver_ip = %dns_config::resolver_addr(), upstreams = ?upstreams, "Magic DNS active");
        self.resolver.set_upstreams(upstreams);
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
            tokio::spawn(async move {
                if let Some(ip) = dns_config::run_resolv_reassert(search, fallback, rt).await
                    && let Some(me) = me.upgrade()
                {
                    me.stand_down(ip, tun_name).await;
                }
            });
        }
    }

    /// Another VPN took `/etc/resolv.conf` while we held it, and the re-assert
    /// watcher stopped rather than rewrite it back at them.
    ///
    /// Let go of the file completely: no `revert`, because restoring our backup
    /// would put a capture of the host from before either VPN over their
    /// configuration. Drop that backup instead, so neither `revert` nor
    /// `restore_stale_backups` can do it later, and go back to retrying
    /// detection so we reclaim DNS if that VPN leaves.
    ///
    /// The `dns=none` NetworkManager drop-in stays: un-quieting NM here would
    /// only have NM regenerate the file and start a different fight over it.
    /// It is marker-guarded and still removed on the real revert path.
    #[cfg(target_os = "linux")]
    async fn stand_down(self: &Arc<Self>, foreign: std::net::Ipv4Addr, tun_name: String) {
        tracing::warn!(
            %foreign,
            "/etc/resolv.conf is owned by another VPN now; leaving it to them rather than \
             rewriting it against each other. `.ray` names stop resolving on this host until \
             that VPN goes away or a DNS manager both can register with is in the path"
        );
        self.reassert_token.lock().unwrap().take();
        self.configurator.lock().unwrap().take();
        dns_config::discard_resolv_backup().await;
        self.spawn_configure_retry(tun_name);
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
    fn spawn_configure_retry(self: &Arc<Self>, tun_name: String) {
        let token = CancellationToken::new();
        *self.configure_retry.lock().unwrap() = Some(token.clone());
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut delay = DNS_CONFIG_RETRY_MIN;
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
                delay = (delay * 2).min(DNS_CONFIG_RETRY_MAX);
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
        dns_config::clear_search_domains(tun_name).await;
    }
}
