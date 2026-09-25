use super::*;

// ---------------------------------------------------------------------------
// Linux: search domains
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(super) async fn set_search_domains_linux(
    rayfish_domains: &[SearchDomain],
    tun_name: &str,
) -> Result<()> {
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
pub(super) const RESOLVED_STUB_IPS: [Ipv4Addr; 2] =
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
pub(super) async fn resolved_is_in_resolution_path() -> bool {
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
pub(super) fn resolv_conf_points_at_resolved(contents: &str) -> bool {
    parse_resolv_nameservers(contents)
        .iter()
        .any(|ip| RESOLVED_STUB_IPS.contains(ip))
}

#[cfg(target_os = "linux")]
pub(super) fn nsswitch_uses_resolve(contents: &str) -> bool {
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
pub(super) fn resolvconf_is_resolved_shim() -> bool {
    ["/sbin/resolvconf", "/usr/sbin/resolvconf"]
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .any(|p| p.file_name().is_some_and(|n| n == "resolvectl"))
}

#[cfg(target_os = "linux")]
pub(super) struct SystemdResolvedDBus {
    ifindex: i32,
}

#[cfg(target_os = "linux")]
pub(super) async fn try_systemd_resolved_dbus(tun_name: &str) -> Option<SystemdResolvedDBus> {
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

// ---------------------------------------------------------------------------
// Linux: systemd-resolved via resolvectl CLI (fallback)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(super) struct SystemdResolvedCli {
    tun_iface: String,
}

#[cfg(target_os = "linux")]
pub(super) fn try_systemd_resolved_cli(tun_name: &str) -> Option<SystemdResolvedCli> {
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
pub(super) enum ResolvconfVariant {
    Debian,
    Openresolv,
}

#[cfg(target_os = "linux")]
pub(super) struct Resolvconf {
    variant: ResolvconfVariant,
    /// The domains our stanza carries, so a join/leave can re-register it.
    search: SearchDomains,
}

#[cfg(target_os = "linux")]
pub(super) fn try_resolvconf() -> Option<Resolvconf> {
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
pub(super) fn parse_resolv_nameservers(contents: &str) -> Vec<Ipv4Addr> {
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
            .filter(|ip| !crate::membership::is_cgnat_range(*ip))
            .collect(),
    )
}

/// What glibc reads: entries past `MAXNS` are ignored in silence, so the render
/// truncates deliberately rather than write a list the resolver will cut short.
#[cfg(any(target_os = "linux", test))]
pub(super) const MAX_NAMESERVERS: usize = 3;

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
pub(super) fn render_direct_resolv_conf(search: &[SearchDomain], fallbacks: &[Ipv4Addr]) -> String {
    render_direct_resolv_conf_with(resolver_addr(), search, fallbacks)
}

/// The body of [`render_direct_resolv_conf`], with the resolver address passed
/// in so the rendering is testable without the process-wide mode.
#[cfg(any(target_os = "linux", test))]
pub(super) fn render_direct_resolv_conf_with(
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
pub(super) const BACKUP_SUFFIX: &str = ".before-rayfish";
#[cfg(any(target_os = "linux", test))]
pub(super) const HEADER_COMMENT: &str = "# Added by rayfish - do not edit\n";

/// True iff `/etc/resolv.conf` contents are ours (carry the rayfish marker).
#[cfg(any(target_os = "linux", test))]
pub(super) fn resolv_conf_is_ours(contents: &str) -> bool {
    contents.contains(HEADER_COMMENT.trim_end())
}

/// What one re-assert pass makes of the current `/etc/resolv.conf`.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reassert {
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
pub(super) fn reassert_decision(current: &str, merged_with: Option<Ipv4Addr>) -> Reassert {
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
pub(super) async fn reassert_resolv_conf(
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
        .find(|ip| crate::membership::is_cgnat_range(*ip));
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
    let mut next_tick = tokio::time::Instant::now() + REASSERT_TICK;
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
            _ = tokio::time::sleep_until(next_tick) => {
                next_tick = tokio::time::Instant::now() + REASSERT_TICK;
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
pub(super) const MERGE_COOLDOWN: Duration = Duration::from_secs(60);

/// How often the re-assert pass runs regardless of inotify.
///
/// A *deadline*, not a delay: the `/etc` watch is broad (the name filter decides
/// whether to re-assert, it does not stop the arm from completing), so a
/// per-iteration `sleep` was restarted by every unrelated write under `/etc` and
/// never elapsed on a busy host. That is the tick that probes the resolver we
/// share the file with, so losing it means `SharedResolverGone` never fires and
/// the daemon keeps declining off-mesh names while pointing the stub at an
/// address that stopped answering.
#[cfg(target_os = "linux")]
pub(super) const REASSERT_TICK: Duration = Duration::from_secs(30);

/// One re-assert pass, reporting only the outcomes the loop acts on. Errors are
/// logged and treated as "keep watching" (the next tick retries).
#[cfg(target_os = "linux")]
pub(super) async fn pass(
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
// DHCP-lease event and trampling our `nameserver 200::53`. Dropping a
// `dns=none` config snippet makes NM leave resolv.conf entirely to us
// (Tailscale takes the same "stop the fight" stance over re-asserting forever).
// Reversible: removed + reloaded on revert. The inotify re-assert remains the
// backstop for non-NM writers (dhclient).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(super) const NM_CONF_DIR: &str = "/etc/NetworkManager/conf.d";
#[cfg(target_os = "linux")]
pub(super) const NM_DROPIN: &str = "/etc/NetworkManager/conf.d/rayfish-dns.conf";

/// The `dns=none` drop-in that tells NetworkManager to stop managing resolv.conf.
#[cfg(any(target_os = "linux", test))]
pub(super) fn nm_dns_none_dropin() -> String {
    format!("{HEADER_COMMENT}[main]\ndns=none\n")
}

/// True iff NetworkManager appears installed (its conf.d dir exists). Best-effort
/// gate so we only quiet NM on hosts that actually run it.
#[cfg(target_os = "linux")]
pub(super) fn nm_present() -> bool {
    Path::new(NM_CONF_DIR).is_dir()
}

/// Ask NetworkManager to reload its configuration so a conf.d change takes effect.
#[cfg(target_os = "linux")]
pub(super) async fn nm_reload() {
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
pub(super) async fn nm_quiet_install() {
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
pub(super) fn backup_path(original: &Path) -> PathBuf {
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
pub(super) async fn backup_file(path: &Path) -> Result<()> {
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
pub(super) async fn restore_file(path: &Path) -> Result<()> {
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
pub(super) fn strip_our_resolv_entries(contents: &str) -> String {
    // Both families: a file written by a build that answered on the IPv4 magic
    // address still names it, and leaving it behind would point the host at a
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

#[cfg(target_os = "linux")]
pub(super) struct DirectResolvConf {
    /// Swapped rather than owned so [`Self::apply`] can narrow it: quieting
    /// NetworkManager can kill a server that answered at capture time, and both
    /// the file we render and the forwarder we seed read this afterwards.
    captured_upstreams: Arc<ArcSwap<Vec<Ipv4Addr>>>,
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
pub(super) fn foreign_mesh_resolver(contents: &str) -> Option<Ipv4Addr> {
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
pub(super) fn other_overlay_resolver(contents: &str) -> Option<Ipv4Addr> {
    // `parse_resolv_nameservers` already drops our own magic IP.
    parse_resolv_nameservers(contents)
        .into_iter()
        .find(|ip| crate::membership::is_cgnat_range(*ip))
}

/// The first `nameserver` in `contents`, whatever its family.
///
/// glibc queries resolvers in the order they are listed and stops at the first
/// one that answers, and an authoritative NXDOMAIN is an answer. On a file that
/// something else merged (resolvconf), first place is therefore the only place
/// from which `.ray` queries ever reach us.
#[cfg(any(target_os = "linux", test))]
pub(super) fn first_nameserver(contents: &str) -> Option<IpAddr> {
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
    pub(super) async fn new() -> Self {
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
            captured_upstreams: Arc::new(ArcSwap::from_pointee(live)),
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
    fn fallbacks(&self) -> Vec<Ipv4Addr> {
        self.captured_upstreams.load().as_ref().clone()
    }
}

/// What the resolver actually reads: glibc's `MAXDNSRCH`. Entries past it are
/// ignored in silence, which is why the merge below truncates deliberately
/// instead of rendering a list the host will quietly cut short.
#[cfg(any(target_os = "linux", test))]
pub(super) const MAX_SEARCH_DOMAINS: usize = 6;

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
pub(super) fn merge_search_domains(
    captured: &[SearchDomain],
    rayfish: &[SearchDomain],
) -> Vec<SearchDomain> {
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

/// Set once [`NmQuietOutcome::Abort`] has been reached, so the retry loop stops
/// re-running the experiment.
///
/// The verdict is about NetworkManager's *static* configuration: it runs a local
/// forwarder, and quieting it takes that forwarder away. Nothing the daemon does
/// changes that, so a retry can only reach the same answer, and reaching it costs
/// two `nmcli general reload`s and the DNS gap between them. `DnsService`'s retry
/// backs off to a 60s ceiling and never gives up, so without this the host pays
/// that twice a minute for as long as the daemon runs.
///
/// Deliberately never cleared: an operator who changes NetworkManager's DNS mode
/// in response to the message restarts the daemon, and the ladder re-runs from the
/// top when they do.
#[cfg(target_os = "linux")]
pub(super) static NM_TAKEOVER_UNSAFE: AtomicBool = AtomicBool::new(false);

/// Consecutive [`NmQuietOutcome::Abort`] verdicts. Two before [`NM_TAKEOVER_UNSAFE`]
/// is set, mirroring the two strikes `run_resolv_reassert` gives the resolver it
/// shares the file with.
///
/// The verdict is inferred from a pair of liveness probes either side of a
/// NetworkManager reload, and both halves of that pair are network measurements
/// that can be wrong once. A permanent decision deserves better evidence than a
/// single pair, and the only thing a second look costs is one retry cycle.
#[cfg(target_os = "linux")]
pub(super) static NM_ABORTS: AtomicU32 = AtomicU32::new(0);

/// What quieting NetworkManager did to the upstreams we captured before it.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NmQuietOutcome {
    /// Everything we captured still answers.
    Proceed,
    /// Some died, or all of them did while the operator's own `dns_upstreams`
    /// still give the forwarder somewhere to go. Not a black hole, so the
    /// takeover stands; the dead entries are named because they stay in the
    /// file we are about to write and cost a timeout each.
    Degraded(Vec<Ipv4Addr>),
    /// Nothing we captured answers any more and the operator named nothing.
    /// Taking the file over now would own DNS for the host with no way to
    /// resolve anything outside `.ray`.
    Abort,
}

/// Classify the upstream set after [`nm_quiet_install`], given what it was before.
///
/// Both sets are live probes taken either side of the quiet, so the difference
/// between them is attributable to the quiet and to nothing else. `apply` refuses
/// an empty `before` on its own, before it touches anything, which is why an
/// empty pair reads as [`NmQuietOutcome::Proceed`] here rather than as an abort:
/// "there was nothing to lose" is not a verdict about NetworkManager.
///
/// Split out from `apply` because the ordering it guards is not otherwise
/// observable. The operator's own `dns_upstreams` waives the abort for the same
/// reason it waives the `ensure!`: the forwarder gets somewhere to send queries
/// either way.
#[cfg(any(target_os = "linux", test))]
pub(super) fn nm_quiet_outcome(
    before: &[Ipv4Addr],
    after: &[Ipv4Addr],
    operator_upstreams: bool,
) -> NmQuietOutcome {
    if after.len() == before.len() {
        return NmQuietOutcome::Proceed;
    }
    if after.is_empty() && !operator_upstreams {
        return NmQuietOutcome::Abort;
    }
    NmQuietOutcome::Degraded(
        before
            .iter()
            .filter(|ip| !after.contains(ip))
            .copied()
            .collect(),
    )
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
            !self.captured_upstreams.load().is_empty() || self.operator_upstreams,
            "no working DNS server found in /etc/resolv.conf, so taking it over would leave \
             this host unable to resolve anything; set `dns_upstreams` in the config to \
             name one explicitly"
        );
        // Before `backup_file`, so this bails without touching anything, exactly
        // as the guard above does. See [`NM_TAKEOVER_UNSAFE`].
        anyhow::ensure!(
            !NM_TAKEOVER_UNSAFE.load(AtomicOrdering::Relaxed),
            "taking over /etc/resolv.conf on this host would stop the resolver it names \
             (NetworkManager runs it, and rayfish has to tell NetworkManager to stop \
             managing DNS); set `dns_upstreams` in the config to name a server directly, \
             or switch NetworkManager off its built-in resolver, then restart rayfish"
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
            // reached there, and we can: [`resolver_addr`] is in `200::/7`, not
            // in the `100.64.0.0/10` this other VPN owns and filters. A v4 magic
            // address there would have been an unanswering first nameserver, and
            // every lookup on the host would have eaten the resolver timeout
            // before falling through to them.
            tracing::info!(
                resolver = %ip,
                "/etc/resolv.conf names another VPN's resolver; merging ours in ahead of it \
                 and declining everything outside `.{DNS_DOMAIN}` so the stub asks it directly"
            );
        }

        // The `ensure!` above can pass on the strength of a server we are about
        // to kill. NetworkManager in `dns=dnsmasq` mode answers at a loopback
        // address of its own and writes *that* into resolv.conf, and the
        // `dns=none` drop-in below is precisely what stops it. So the capture is
        // re-probed on both sides of the kill, and the verdict is the difference
        // between them.
        //
        // Probing *before* is what makes it a verdict about NetworkManager rather
        // than about the clock. The capture in `new` may be minutes old, and a
        // host that lost its DNS in the meantime (a boot, a reassociating link)
        // presents exactly the evidence an NM forwarder does: everything answered
        // then, nothing answers now. Attributing that to the quiet is what latched
        // Magic DNS off for the daemon's lifetime on a passing blip.
        let captured = self.captured_upstreams.load().as_ref().clone();
        let before = crate::dns::resolver::live_upstreams(&captured).await;
        anyhow::ensure!(
            !before.is_empty() || self.operator_upstreams,
            "no DNS server named in /etc/resolv.conf is answering right now, so taking it \
             over would leave this host unable to resolve anything; this is a plain retry, \
             not a verdict about NetworkManager"
        );
        // Keep what the probe just learned, for the same reason the `Degraded`
        // arm below does: this set is what `fallbacks` renders into the file and
        // what `adopt_configurator` seeds the forwarder with, and a server that
        // has stopped answering costs a full lookup timeout in either.
        if before.len() != captured.len() {
            self.captured_upstreams.store(Arc::new(before.clone()));
        }

        let path = Path::new("/etc/resolv.conf");
        backup_file(path).await?;
        // Quiet NM so it doesn't regenerate the file out from under the write
        // we're about to make (the inotify re-assert covers any residual).
        nm_quiet_install().await;
        // `before`, not `captured`: comparing like with like, so a server that was
        // already dead cannot be counted against the quiet.
        let after = crate::dns::resolver::live_upstreams(&before).await;
        match nm_quiet_outcome(&before, &after, self.operator_upstreams) {
            NmQuietOutcome::Proceed => {
                NM_ABORTS.store(0, AtomicOrdering::Relaxed);
            }
            // Narrowed, not just reported: this set is what `fallbacks` renders
            // into the file and what `adopt_configurator` seeds the forwarder
            // with, and a dead server in either costs a full lookup timeout per
            // off-mesh name. The capture in `new` probed for exactly this reason;
            // quieting NM is simply a second chance to be wrong.
            NmQuietOutcome::Degraded(dead) => {
                NM_ABORTS.store(0, AtomicOrdering::Relaxed);
                tracing::warn!(
                    ?dead,
                    "some DNS servers stopped answering once NetworkManager was quieted; \
                     dropping them from the upstreams and from the file"
                );
                self.captured_upstreams.store(Arc::new(after));
            }
            NmQuietOutcome::Abort => {
                // Deliberately not `?`. This arm is the one that hands the host
                // back to NetworkManager, and every step of it has to run: a `?`
                // here left NM quieted with the `dns=none` drop-in still
                // installed and no resolver of ours in the file, so the host had
                // neither, and skipped the counter so the latch could never trip.
                // Nothing else removes that drop-in until a `ray down`.
                let restored = restore_file(path).await;
                nm_quiet_remove().await;
                if let Err(e) = &restored {
                    tracing::error!(
                        error = %e,
                        "could not put /etc/resolv.conf back after aborting the takeover"
                    );
                }
                // Two verdicts before the latch, the same two strikes
                // `run_resolv_reassert` gives the resolver it shares the file
                // with, and for the same reason: one lost packet or one
                // badly-timed reload should not decide this permanently. The
                // retry loop backs off to 60s, so the cost of a second look is
                // one cycle; the cost of latching wrongly is Magic DNS for the
                // life of the daemon.
                let aborts = NM_ABORTS.fetch_add(1, AtomicOrdering::Relaxed) + 1;
                if aborts >= 2 {
                    NM_TAKEOVER_UNSAFE.store(true, AtomicOrdering::Relaxed);
                }
                let reason = "every DNS server /etc/resolv.conf named stopped answering once \
                     NetworkManager was told to stop managing DNS (`dns=none`), which is how \
                     its built-in resolver is run; taking the file over would leave this host \
                     unable to resolve anything. Set `dns_upstreams` in the config to name a \
                     server directly.";
                match restored {
                    Ok(()) => anyhow::bail!("{reason}"),
                    Err(e) => anyhow::bail!("{reason} (and restoring the file failed: {e})"),
                }
            }
        }
        let new_content = render_direct_resolv_conf(&self.search.load(), &self.fallbacks());
        tokio::fs::write(path, new_content)
            .await
            .context("writing /etc/resolv.conf")?;
        tracing::info!(
            upstreams = ?self.captured_upstreams.load(),
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
        self.captured_upstreams.load().as_ref().clone()
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
            render_direct_resolv_conf(&self.search.load(), &self.fallbacks()),
        )
        .await
        .context("writing search domains to /etc/resolv.conf")
    }

    fn search_handle(&self) -> Option<SearchDomains> {
        Some(Arc::clone(&self.search))
    }

    fn fallback_upstreams(&self) -> Vec<Ipv4Addr> {
        self.captured_upstreams.load().as_ref().clone()
    }

    fn shared_resolver(&self) -> Option<Ipv4Addr> {
        self.foreign_resolver
    }
}
