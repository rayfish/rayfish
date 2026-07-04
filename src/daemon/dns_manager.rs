//! Magic DNS state and OS-DNS configuration, owned by [`MeshManager`] as one
//! cohesive unit instead of five loose fields.
//!
//! Holds the `.ray` naming tables (the single source of truth that the mesh
//! roster writes and the in-daemon resolver reads), the resolver itself, and the
//! OS-DNS configurator/re-assert handles owned while the data plane is active.
//! The mesh accept handlers and background tasks get cheap `Clone` handles of the
//! naming tables; the OS-DNS lifecycle (`configure`/`revert`) stays here and
//! takes the TUN name as a parameter since the core owns it.

use super::*;

pub(crate) struct DnsManager {
    /// `.ray` forward lookup table (hostname → IP). Cloned into `MeshCtx` and the
    /// resolver; the roster is the single source of truth that writes it.
    pub(crate) hostname_table: dns::HostnameTable,
    /// `.ray` reverse lookup table (IP → hostname).
    pub(crate) reverse_table: dns::ReverseLookupTable,
    /// In-daemon Magic DNS resolver (answers `.ray` queries intercepted via TUN).
    pub(crate) resolver: std::sync::Arc<crate::dns_resolver::Resolver>,
    /// The system-DNS configurator owned while active, so `revert` can undo it.
    configurator: Arc<std::sync::Mutex<Option<Box<dyn dns_config::DnsConfigurator>>>>,
    /// Cancellation token for the `run_resolv_reassert` task (Linux direct mode).
    reassert_token: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>>,
}

impl DnsManager {
    pub(crate) fn new(
        hostname_table: dns::HostnameTable,
        reverse_table: dns::ReverseLookupTable,
        resolver: std::sync::Arc<crate::dns_resolver::Resolver>,
    ) -> Self {
        Self {
            hostname_table,
            reverse_table,
            resolver,
            configurator: Arc::new(std::sync::Mutex::new(None)),
            reassert_token: std::sync::Mutex::new(None),
        }
    }

    /// Point system DNS at the in-daemon Magic DNS resolver: detect the OS DNS
    /// backend, merge any user-configured upstreams over the captured ones, and
    /// (Linux direct-resolv.conf mode) spawn the inotify re-assert watcher.
    /// Failures are non-fatal — pushed to `warnings` so `ray up` can surface them.
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
                *self.configurator.lock().unwrap() = Some(c);
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
