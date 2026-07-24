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
}

impl DnsService {
    pub(crate) fn new(
        hostname_table: dns::HostnameTable,
        reverse_table: dns::ReverseLookupTable,
        resolver: std::sync::Arc<crate::dns::resolver::Resolver>,
    ) -> Self {
        Self {
            hostname_table,
            reverse_table,
            resolver,
            configurator: Arc::new(std::sync::Mutex::new(None)),
            reassert_token: std::sync::Mutex::new(None),
        }
    }

    /// Rebuild one network's forward + reverse `.ray` entries from its roster
    /// (the roster is the single source of truth for `*.ray`). Writer side.
    #[allow(dead_code)] // adopted by NetworkRegistry in M5
    pub(crate) async fn sync_network(
        &self,
        network: &str,
        entries: &[(String, Ipv4Addr, Ipv6Addr)],
    ) {
        dns::sync_network_hostnames(&self.hostname_table, &self.reverse_table, network, entries)
            .await;
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
    pub(crate) async fn configure(&self, tun_name: &str, warnings: &mut Vec<String>) {
        // Configure system DNS to route .ray queries to our in-daemon resolver.
        dns_config::restore_stale_backups();
        match dns_config::detect_and_configure(tun_name).await {
            Ok(c) => {
                let captured = c.captured_upstreams();
                // Merge any user-configured DNS upstreams over the system-captured
                // set (replace drops the captured ones; augment tries custom first).
                let dns_override = config::load().map(|c| c.dns_upstreams).unwrap_or_default();
                let upstreams = config::resolve_upstreams(&dns_override, captured);
                let is_direct = c.name() == "direct-resolv.conf";
                #[cfg(target_os = "linux")]
                let search = c.search_domains();
                tracing::info!(backend = c.name(), resolver_ip = %crate::dns::MAGIC_DNS_V4, upstreams = ?upstreams, "Magic DNS active");
                self.resolver.set_upstreams(upstreams);
                *self.configurator.lock().unwrap() = Some(Arc::from(c));
                // In direct mode, re-assert /etc/resolv.conf the instant another
                // program (NetworkManager, dhclient) overwrites it (inotify watch).
                #[cfg(target_os = "linux")]
                if is_direct {
                    let rt = tokio_util::sync::CancellationToken::new();
                    *self.reassert_token.lock().unwrap() = Some(rt.clone());
                    tokio::spawn(dns_config::run_resolv_reassert(search, rt));
                }
                #[cfg(not(target_os = "linux"))]
                let _ = is_direct;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to configure system DNS (Magic DNS requires manual setup)");
                warnings.push(format!(
                    "failed to configure system DNS, so .ray names won't resolve: {e}"
                ));
            }
        }
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
