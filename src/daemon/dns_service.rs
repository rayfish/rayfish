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
    configurator: Arc<Mutex<Option<Arc<dyn dns_config::DnsConfigurator>>>>,
    /// Cancellation token for the re-assert task that repairs the OS DNS
    /// configuration after another program tramples it: `run_resolv_reassert`
    /// on Linux (direct mode only), `run_sc_reassert` on macOS.
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
    /// spawn the re-assert watcher the platform's backend needs.
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

    /// Take ownership of a detected OS-DNS backend: seed the resolver's
    /// upstreams, keep the configurator for `revert`, install the current search
    /// domains, and start the re-assert watcher that repairs the configuration
    /// if something else overwrites or deletes it.
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
        let fallbacks = c.fallback_upstreams();
        // Sharing the file with another mesh means the stub has its resolver
        // listed after ours, so a name outside `.ray` can be declined and the
        // stub will ask it directly. Both halves are required: somebody to
        // share with, and a live server behind us to decline *to*.
        let defer_off_mesh = c.shared_resolver().is_some() && !fallbacks.is_empty();
        tracing::info!(backend = c.name(), resolver_ip = %dns_config::resolver_addr(), upstreams = ?upstreams, defer_off_mesh, "Magic DNS active");
        self.resolver.set_upstreams(upstreams);
        self.resolver.set_defer_off_mesh(defer_off_mesh);
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
                if let Some(why) = dns_config::run_resolv_reassert(search, fallbacks, rt).await
                    && !watcher.is_cancelled()
                    && let Some(me) = me.upgrade()
                {
                    me.recapture(why, tun_name, &watcher).await;
                }
            });
        }

        // macOS: another VPN's DNS handling walks every service in the dynamic
        // store, ours included. Mullvad writes its own resolver over
        // `State:/Network/Service/rayfish/DNS` while it is connected and
        // *removes* the key on disconnect instead of restoring what it found,
        // so `.ray` stopped resolving the moment the other VPN went away and
        // nothing brought it back before the next `ray up`. Poll the key and
        // re-apply when it is gone.
        #[cfg(target_os = "macos")]
        {
            let rt = CancellationToken::new();
            // Cancel whatever the last adopt left running: `configure` can be
            // called again without a `revert` in between (the retry loop
            // succeeding is the usual way), and two watchers on one key would
            // both answer the same removal.
            if let Some(old) = self.reassert_token.lock().unwrap().replace(rt.clone()) {
                old.cancel();
            }
            tokio::spawn(Arc::clone(self).run_sc_reassert(tun_name.to_string(), rt));
        }
    }

    /// Re-install the macOS DNS configuration after another program deletes it.
    ///
    /// Mullvad's `talpid_dns` enumerates every service in the dynamic store when
    /// it connects, ours included, writes its own resolver over each one, and on
    /// disconnect *removes* them rather than putting back what it found. Our key
    /// is a session key, so nothing reclaims it for us: `.ray` went quiet when
    /// the other VPN was switched off, not while it was up, and stayed that way
    /// until the next `ray up`.
    ///
    /// Only a key that is *gone* is repaired. One that somebody else is holding
    /// is left to them: a VPN that owns DNS for the length of its tunnel
    /// re-asserts on a notification of its own, so writing over it would be two
    /// daemons overwriting each other for as long as it stays connected, which
    /// is the fight `MERGE_COOLDOWN` avoids on Linux.
    #[cfg(target_os = "macos")]
    async fn run_sc_reassert(self: Arc<Self>, tun_name: String, token: CancellationToken) {
        use dns_config::DnsKeyState;

        // One line per takeover, not one per pass: another VPN holds DNS for as
        // long as it is connected, and the key is read every few seconds.
        let mut warned = false;
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(dns_config::SC_REASSERT_TICK) => {}
            }
            match dns_config::dns_key_state() {
                DnsKeyState::Ours => warned = false,
                DnsKeyState::Foreign => {
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            "another program has taken the macOS DNS configuration for our \
                             service; leaving it to them, so .ray names will not resolve \
                             until they release it"
                        );
                    }
                }
                DnsKeyState::Gone => {
                    tracing::warn!(
                        "the macOS DNS configuration was removed under us; \
                         re-asserting rayfish DNS"
                    );
                    warned = false;
                    self.reassert_os_config(&tun_name).await;
                    // `revert` cancels us on the way down, but it can have run
                    // while the re-apply above was in flight: it took the
                    // configurator with it, so its own `revert` removed the keys
                    // before we wrote them back. Drop them rather than leave a
                    // downed data plane's resolver in the store.
                    if token.is_cancelled() {
                        dns_config::remove_dns_config();
                        return;
                    }
                }
            }
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
    async fn recapture(
        self: &Arc<Self>,
        why: dns_config::Recapture,
        tun_name: String,
        watcher: &CancellationToken,
    ) {
        // The one verdict that is not a rebuild. Nothing on this host knows a
        // working resolver any more: the file names theirs, theirs is gone, and
        // the servers it replaced are unrecoverable (they dropped their backup
        // on the way out, and ours is a copy of *their* file). Standing all the
        // way down is what gets DNS back, because it un-quiets NetworkManager
        // and hands the file to whatever regenerates it from DHCP. The retry
        // loop then takes it over again once that has happened.
        if let dns_config::Recapture::SharedResolverGone(ip) = why {
            tracing::warn!(
                resolver = %ip,
                "the resolver we shared /etc/resolv.conf with has gone and left the host \
                 without one; releasing DNS so it can be regenerated"
            );
            self.revert(&tun_name).await;
            if watcher.is_cancelled() {
                return;
            }
            self.spawn_configure_retry(tun_name, DNS_CONFIG_RETRY_MIN);
            return;
        }
        match why {
            dns_config::Recapture::Merge(ip) => tracing::info!(
                resolver = %ip,
                "another VPN wrote /etc/resolv.conf; merging ours back in ahead of theirs"
            ),
            dns_config::Recapture::Reclaim => tracing::info!(
                "the VPN sharing /etc/resolv.conf is gone; recapturing the host's own resolvers"
            ),
            dns_config::Recapture::SharedResolverGone(_) => unreachable!("handled above"),
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
        // Cancel whatever this replaces. `configure` and `revert` already cancel
        // before they call in here, but `recapture` does not, and a token that is
        // dropped from the cell without being cancelled leaves its loop running
        // with nothing left that can ever stop it.
        if let Some(previous) = self.configure_retry.lock().unwrap().replace(token.clone()) {
            previous.cancel();
        }
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
    /// re-capture of upstreams), then put the search domains back.
    ///
    /// Called when the exit-node full-tunnel state flips, so the macOS
    /// configurator rewrites its match domains: catch-all (route all DNS through
    /// Magic DNS, forwarded upstream via the tunnel) while an exit is up,
    /// `.ray`-only split DNS otherwise. Also how [`run_sc_reassert`] repairs a
    /// deleted configuration. No-op if DNS was never configured.
    ///
    /// The second half is not optional. `apply` writes the whole key from
    /// scratch and the only search domain it knows is `.ray` itself; the
    /// per-network ones that make a bare `box` resolve arrive separately, via
    /// `set_search_domains`, and a re-apply that did not reinstall them would
    /// drop every one until the next join or leave.
    ///
    /// macOS-only: it is the only platform whose exit-node client rewrites match
    /// domains, so elsewhere this is dead code and `-D warnings` says so.
    ///
    /// [`run_sc_reassert`]: DnsService::run_sc_reassert
    #[cfg(target_os = "macos")]
    pub(crate) async fn reassert_os_config(&self, tun_name: &str) {
        // Clone the Arc out, not the guard, so the lock isn't held across await.
        let configurator = self.configurator.lock().unwrap().clone();
        let Some(configurator) = configurator else {
            return;
        };
        if let Err(e) = configurator.apply().await {
            tracing::warn!(error = %e, "failed to re-apply system DNS");
            return;
        }
        let domains = self.search_domains.lock().unwrap().clone();
        if !domains.is_empty()
            && let Err(e) = configurator.set_search_domains(&domains, tun_name).await
        {
            tracing::warn!(error = %e, "failed to reinstall search domains after re-applying system DNS");
        }
    }

    /// The active OS-DNS backend's name, or `None` before `configure` / after
    /// `revert`. Used to say whether a change that only affects the daemon's own
    /// forwarder can actually reach an application's queries: on a split-DNS
    /// backend only `.ray` is routed to us, so everything else bypasses it.
    #[cfg(target_os = "linux")]
    pub(crate) fn backend_name(&self) -> Option<&'static str> {
        self.configurator.lock().unwrap().as_ref().map(|c| c.name())
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
        // No backend held means no guarantee another nameserver sits behind
        // ours, so the resolver goes back to forwarding rather than declining.
        self.resolver.set_defer_off_mesh(false);
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

    /// Stop the background tasks (`configure` retry, re-assert watcher) without
    /// touching OS state. For a node going offline for good, where `revert`'s
    /// undo work is either already done or about to be irrelevant, but the tasks
    /// must not outlive the daemon that owns them.
    ///
    /// An embedder that rebuilds a daemon in the same process needs this: the
    /// retry loop holds an `Arc<DnsService>` and runs on a runtime that survives
    /// the node, so without a cancel here every stop/start cycle strands another
    /// copy of this service, retrying forever against a platform that already
    /// refused it. Observed on Android (where OS-DNS configuration always fails,
    /// so the loop never exits on its own): three live loops after three
    /// disable/enable cycles, between them filling most of the diagnostics log
    /// ring with retry chatter.
    pub(crate) fn shutdown_background(&self) {
        if let Some(rt) = self.reassert_token.lock().unwrap().take() {
            rt.cancel();
        }
        if let Some(retry) = self.configure_retry.lock().unwrap().take() {
            retry.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> Arc<DnsService> {
        let table = dns::HostnameTable::default();
        let reverse = dns::ReverseLookupTable::default();
        let resolver = std::sync::Arc::new(crate::dns::resolver::Resolver::new(
            table.clone(),
            reverse.clone(),
        ));
        Arc::new(DnsService::new(
            table,
            reverse,
            resolver,
            Ipv6Addr::UNSPECIFIED,
        ))
    }

    /// A second retry loop must cancel the first. `recapture` spawns without
    /// cancelling, and a token merely dropped from the cell leaves its loop with
    /// nothing that can ever stop it: on a platform that always refuses OS-DNS
    /// configuration (Android) that loop then retries for the life of the
    /// process.
    #[tokio::test]
    async fn spawning_a_retry_cancels_the_one_it_replaces() {
        let dns = service();
        dns.spawn_configure_retry("tun0".into(), Duration::from_secs(3600));
        let first = dns.configure_retry.lock().unwrap().clone().unwrap();

        dns.spawn_configure_retry("tun0".into(), Duration::from_secs(3600));
        assert!(first.is_cancelled(), "the replaced loop was left running");

        let second = dns.configure_retry.lock().unwrap().clone().unwrap();
        assert!(!second.is_cancelled(), "the new loop must still be live");
    }

    /// A node going offline has to stop the retry loop even though `revert` was
    /// never called. The loop holds an `Arc<DnsService>` on a runtime that
    /// outlives the daemon, so on an embedder that rebuilds in-process an
    /// uncancelled one strands the whole service.
    #[tokio::test]
    async fn shutdown_cancels_the_retry_loop() {
        let dns = service();
        dns.spawn_configure_retry("tun0".into(), Duration::from_secs(3600));
        let token = dns.configure_retry.lock().unwrap().clone().unwrap();

        dns.shutdown_background();
        assert!(token.is_cancelled());
        assert!(dns.configure_retry.lock().unwrap().is_none());
    }

    /// Declining is only safe with somebody to decline *to*. Both halves of
    /// that come from the backend: another mesh sharing the file, and at least
    /// one live server rendered after ours in it.
    #[test]
    fn deferring_needs_both_a_sharer_and_a_server_behind_us() {
        use std::net::Ipv4Addr;

        struct Backend {
            shared: Option<Ipv4Addr>,
            fallbacks: Vec<Ipv4Addr>,
        }
        #[async_trait::async_trait]
        impl dns_config::DnsConfigurator for Backend {
            async fn apply(&self) -> anyhow::Result<()> {
                Ok(())
            }
            async fn revert(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn name(&self) -> &'static str {
                "test"
            }
            fn shared_resolver(&self) -> Option<Ipv4Addr> {
                self.shared
            }
            fn fallback_upstreams(&self) -> Vec<Ipv4Addr> {
                self.fallbacks.clone()
            }
        }
        let theirs = Ipv4Addr::new(100, 100, 100, 100);
        let real = Ipv4Addr::new(192, 168, 1, 1);
        use dns_config::DnsConfigurator;
        let defers = |shared, fallbacks: Vec<Ipv4Addr>| {
            let b = Backend { shared, fallbacks };
            b.shared_resolver().is_some() && !b.fallback_upstreams().is_empty()
        };

        assert!(defers(Some(theirs), vec![theirs]));
        // No one to share with: ours is the only nameserver in the file, so
        // declining would take the host's DNS down.
        assert!(!defers(None, vec![real]));
        // Sharing, but nothing rendered behind us to fall through to.
        assert!(!defers(Some(theirs), vec![]));
    }
}
