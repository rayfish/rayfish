//! Read-only diagnostics for `Daemon`: `status`, `build_report`, `ping`,
//! `netcheck`, and connection-info helpers. Split out of `daemon/mod.rs`.

use std::io::SeekFrom;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::*;
use crate::ipc::{LOG_CHUNK_BYTES, MsgpackCodec};
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

/// The daemon's end of one IPC connection, framed.
///
/// Generic rather than [`crate::ipc::IpcFramed`], which names the *client* half
/// on Windows: the daemon serves a `NamedPipeServer` there and a `UnixStream`
/// on Unix, and `ray logs` is the one command that keeps hold of the connection
/// instead of handing back a single reply.
type ServedFramed<S> = Framed<S, MsgpackCodec<IpcMessage>>;

/// How recent a failed reach must be to render a peer `Offline` in `ray status`.
/// Older failures decay back to `Idle` (the optimistic default) so a peer that was
/// briefly unreachable doesn't stay flagged offline forever without a re-probe.
const STATUS_OFFLINE_WINDOW: Duration = Duration::from_secs(300);

impl Daemon {
    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// snapshot the daemon's status (identity, networks, peers).
    pub fn status(&self) -> IpcMessage {
        let hostname_snapshot = self.dns.hostname_table.try_read().ok();
        let my_id = self.transport.endpoint.id();
        let saved = config::load().ok();
        // Direct-connection networks are flagged in config; collect their names
        // so each NetworkStatus can be tagged `[direct]` in the CLI.
        let direct_names: HashSet<String> = saved
            .as_ref()
            .map(|c| {
                c.networks
                    .iter()
                    .filter(|n| n.direct)
                    .map(|n| n.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let statuses: Vec<NetworkStatus> = self
            .registry
            .networks
            .iter()
            .map(|h| self.network_status(&h, my_id, hostname_snapshot.as_deref(), &direct_names))
            .collect();
        // Persisted pending-join markers, minus any network that has since
        // become active (admitted while we were retrying in the background).
        let pending_networks: Vec<String> = saved
            .as_ref()
            .map(|c| {
                c.pending_joins
                    .iter()
                    .filter(|p| !self.registry.networks.contains_key(&p.network_key))
                    .map(|p| p.name.clone().unwrap_or_else(|| p.network_key.clone()))
                    .collect()
            })
            .unwrap_or_default();
        // Saved networks the daemon has not registered: a restore that has not
        // landed. Reported from here rather than read from config by the CLI,
        // which resolves the *calling user's* config directory and so finds an
        // empty one wherever the daemon's is root-owned, turning every failed
        // restore into a network that simply is not mentioned.
        let inactive_networks: Vec<InactiveNetwork> = saved
            .as_ref()
            .map(|c| {
                c.networks
                    .iter()
                    .filter(|n| !self.registry.networks.contains_key(&n.name))
                    .map(|n| InactiveNetwork {
                        name: n.name.clone(),
                        reason: self
                            .registry
                            .restore_errors
                            .get(&n.name)
                            .map(|e| e.value().clone()),
                        saved: Some(saved_network_status(n, my_id)),
                    })
                    .collect()
            })
            .unwrap_or_default();

        IpcMessage::StatusResponse {
            endpoint_id: self.transport.endpoint.id(),
            mdns_enabled: self.mdns_enabled,
            private_mode: self.private_mode,
            tor: self.tor,
            auto_update: self.auto_update,
            active: self.active.load(Ordering::SeqCst),
            contact_id: Some(self.contact_public.to_string()),
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            networks: statuses,
            packets_rx: self.stats.packets_rx.get(),
            packets_tx: self.stats.packets_tx.get(),
            bytes_rx: self.stats.bytes_rx.get(),
            bytes_tx: self.stats.bytes_tx.get(),
            pending_files: self.files.pending_files.lock().unwrap().len(),
            pending_connects: self.connect.pending_connects.len(),
            pending_networks,
            inactive_networks,
            // Only the neighbours you could still link up with: peers already on
            // one of our networks are visible in the network list, not here.
            lan_peers: self
                .lan_peer_infos()
                .into_iter()
                .filter(|p| p.shared_network.is_none())
                .collect(),
        }
    }

    /// Build one network's `NetworkStatus` for `ray status`. The peer list comes
    /// from the *roster* (every known member, not just live connections) so
    /// offline peers still show (Tailscale-style) with `connection: None`.
    fn network_status(
        &self,
        h: &NetworkHandle,
        my_id: EndpointId,
        hostname_snapshot: Option<&HashMap<String, HashMap<String, dns::HostnameEntry>>>,
        direct_names: &HashSet<String>,
    ) -> NetworkStatus {
        // Direct-connection networks are tagged `[direct]` regardless of role.
        let role = if direct_names.contains(&h.name) {
            NetworkRole::Direct
        } else {
            h.role.clone()
        };
        // Node-local aliases (display-only) come straight from config; status is
        // not a hot path, so a per-network read is fine.
        let net_cfg = config::load_network(&h.name).ok().flatten();
        let aliases = net_cfg
            .as_ref()
            .map(|n| n.aliases.clone())
            .unwrap_or_default();
        let ephemeral_ttl_secs = net_cfg.as_ref().and_then(|n| n.ephemeral_ttl_secs);
        // Resolve a mesh address back to its `.ray` hostname via the DNS snapshot,
        // matching on the address derived from the member's identity.
        let lookup_hostname = |id: EndpointId| {
            let v6 = derive_ipv6(&id);
            hostname_snapshot.and_then(|table| {
                table.get(&h.name).and_then(|hosts| {
                    hosts
                        .iter()
                        .find(|(_, v)| **v == v6)
                        .map(|(k, _)| k.clone())
                })
            })
        };

        let (members, member_count, pending_suggestions, pending_requests) = {
            let s = match h.state.read() {
                Ok(s) => s,
                Err(_) => {
                    return NetworkStatus {
                        name: h.name.clone(),
                        role,
                        my_ipv6: derive_ipv6(&my_id),
                        my_hostname: None,
                        network_key: Some(h.network_key.to_string()),
                        member_count: 0,
                        peers: vec![],
                        pending_suggestions: 0,
                        pending_requests: 0,
                        aliases,
                        ephemeral_ttl_secs,
                        my_exit_node: None,
                        exit_offering: false,
                        incompatible: h.incompatible.clone(),
                    };
                }
            };
            let count = s.members.all().len();
            (
                s.roster(),
                count,
                s.pending_suggestions.len(),
                s.pending.len(),
            )
        };
        // Index live connections by endpoint id for a fast lookup.
        let connected: HashMap<EndpointId, Connection> = self
            .registry
            .peers
            .peers_for_network_with_conn(&h.name)
            .into_iter()
            .map(|(eid, _, conn)| (eid, conn))
            .collect();
        // Our own user identity: the cert's user id on a paired device, else our
        // own endpoint id (mirrors the `try_auto_accept_file` "own device" rule).
        let own_user = self
            .device_cert
            .as_ref()
            .map(|c| c.user_identity)
            .unwrap_or(my_id);
        // The exit peer we route internet traffic through (`ray exit-node use`),
        // matched the way the roster keys members: by device id, or by the user
        // identity a paired multi-device peer is stored under.
        let exit_id = net_cfg
            .as_ref()
            .and_then(|n| n.exit_node_use.as_ref())
            .and_then(|stored| stored.parse::<EndpointId>().ok());
        let is_my_exit = |m: &Member| exit_id.is_some_and(|id| m.matches_identity(id));
        let peers = members
            .iter()
            .filter(|m| m.identity != my_id)
            .map(|m| {
                let hostname = m.hostname.clone().or_else(|| lookup_hostname(m.identity));
                let connection = connected.get(&m.identity).map(Self::gather_conn_info);
                let user_id = self.registry.device_user_map.resolve(&m.identity);
                let user_identity = (user_id != m.identity).then_some(user_id);
                PeerStatus {
                    endpoint_id: m.identity,
                    ipv6: derive_ipv6(&m.identity),
                    hostname,
                    user_identity,
                    is_own_device: user_id == own_user,
                    // Only meaningful for a peer with no live connection: a dial hit
                    // the mesh-version ALPN gate. A connected peer is same-version by
                    // definition, and `add` clears the flag on connect anyway.
                    incompatible: connection.is_none()
                        && self.registry.peers.is_incompatible(&m.identity),
                    // Three-state liveness: a live connection is Active; otherwise a
                    // recently-failed reach (or an incompatible version) is Offline;
                    // anything else is Idle (a roster member we just have no live link
                    // to). A fresh boot with no dial attempts shows every peer Idle.
                    state: if connection.is_some() {
                        PeerState::Active
                    } else if self.registry.peers.is_incompatible(&m.identity)
                        || self
                            .registry
                            .reachability
                            .is_offline(&m.identity, STATUS_OFFLINE_WINDOW)
                    {
                        PeerState::Offline
                    } else {
                        PeerState::Idle
                    },
                    connection,
                    exit_node: m.exit_node,
                    exit_in_use: is_my_exit(m),
                }
            })
            .collect();
        // The same peer as a display string for the network header: its hostname if
        // the roster knows it, else a short id, else the raw stored value (which is
        // all we have if it names nobody in the roster).
        let my_exit_node = net_cfg
            .as_ref()
            .and_then(|n| n.exit_node_use.clone())
            .map(|stored| match members.iter().find(|m| is_my_exit(m)) {
                Some(m) => m
                    .hostname
                    .clone()
                    .or_else(|| lookup_hostname(m.identity))
                    .unwrap_or_else(|| m.identity.fmt_short().to_string()),
                None => stored,
            });
        NetworkStatus {
            name: h.name.clone(),
            role,
            my_ipv6: derive_ipv6(&self.transport.identity.local_identity()),
            my_hostname: lookup_hostname(self.transport.identity.local_identity()),
            network_key: Some(h.network_key.to_string()),
            member_count,
            peers,
            pending_suggestions,
            pending_requests,
            aliases,
            ephemeral_ttl_secs,
            my_exit_node,
            // A non-empty allow-list is exactly what makes this node an exit node.
            exit_offering: net_cfg.as_ref().is_some_and(|n| !n.exit_allow.is_empty()),
            // Registered from the signed blob alone because the network's record
            // advertises a mesh version this build does not speak. Every dial on
            // it fails the ALPN gate, so the network is present but carries no
            // traffic, and status has to say so rather than render it healthy.
            incompatible: h.incompatible.clone(),
        }
    }

    /// Assemble a diagnostic `.tgz` (logs + metrics + sanitized status + system
    /// info) on disk and return its path plus a pre-filled GitHub issue. Runs
    /// daemon-side because the log files are root-owned; the resulting bundle is
    /// chowned to the calling user so an unprivileged `ray report` can attach it.
    ///
    /// Sanitization: the bundle is built only from already-public material: the
    /// `StatusResponse` (which never carries secret keys), counters, and the log
    /// files. It never touches `secret_key` or `network_secret_key`.
    pub(crate) fn build_report(&self, peer: Option<&PeerIdentity>) -> IpcMessage {
        use std::fmt::Write as _;

        let requester = peer.map(PeerIdentity::report_requester);

        // --- sysinfo.txt ---
        let version = env!("CARGO_PKG_VERSION");
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let uname = std::process::Command::new("uname")
            .arg("-a")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let uptime = self.start.elapsed().as_secs();
        let active = self.active.load(Ordering::SeqCst);
        let mut sysinfo = String::new();
        let _ = writeln!(sysinfo, "rayfish {version}");
        let _ = writeln!(sysinfo, "os: {os}  arch: {arch}");
        if !uname.is_empty() {
            let _ = writeln!(sysinfo, "uname: {uname}");
        }
        let _ = writeln!(sysinfo, "endpoint_id: {}", self.transport.endpoint.id());
        let _ = writeln!(sysinfo, "uptime_secs: {uptime}");
        let _ = writeln!(sysinfo, "active: {active}");
        let _ = writeln!(sysinfo, "networks: {}", self.registry.networks.len());

        // --- metrics.txt ---
        let snap = self.stats.snapshot(self.start);
        let total_drops: u64 = snap.drops.iter().map(|(_, c)| c).sum();
        let mut metrics = String::new();
        let _ = writeln!(metrics, "packets_rx: {}", snap.packets_rx);
        let _ = writeln!(metrics, "packets_tx: {}", snap.packets_tx);
        let _ = writeln!(metrics, "bytes_rx:   {}", snap.bytes_rx);
        let _ = writeln!(metrics, "bytes_tx:   {}", snap.bytes_tx);
        let _ = writeln!(metrics, "drops_total: {total_drops}");
        for (reason, count) in &snap.drops {
            let _ = writeln!(metrics, "  drop[{reason}]: {count}");
        }

        // --- status.txt (sanitized: StatusResponse carries no secrets) ---
        let status = format!("{:#?}", self.status());

        // --- collect files for the tarball ---
        let mut files: Vec<(String, Vec<u8>)> = vec![
            ("sysinfo.txt".to_string(), sysinfo.into_bytes()),
            ("metrics.txt".to_string(), metrics.into_bytes()),
            ("status.txt".to_string(), status.into_bytes()),
        ];
        files.extend(collect_recent_logs());
        let has_panics = files.iter().any(|(name, _)| name == "logs/panic.log");

        // --- write the gzipped tarball ---
        // The daemon is root and the temp directory is attacker-controlled, so
        // allocation, writes, permissions, and ownership all stay on one
        // exclusively-created file descriptor. A random name also prevents
        // same-second collisions.
        #[cfg(unix)]
        let dir = std::path::PathBuf::from("/tmp");
        // No fixed `/tmp` on Windows, and the service account's own temp
        // directory is where a LocalSystem process may write.
        #[cfg(windows)]
        let dir = std::env::temp_dir();
        let path = match create_report_bundle(&dir, &files, requester.as_ref()) {
            Ok(path) => path,
            Err(e) => return ipc_err(format!("failed to write report bundle: {e}")),
        };

        let issue_title = if has_panics {
            format!("[report] crash diagnostics from {os} (rayfish {version})")
        } else {
            format!("[report] diagnostics from {os} (rayfish {version})")
        };
        let mut issue_body = String::new();
        let _ = writeln!(issue_body, "**rayfish {version}** on {os}/{arch}");
        let _ = writeln!(issue_body);
        if has_panics {
            let _ = writeln!(
                issue_body,
                "⚠️ One or more panics were recorded — see `logs/panic.log` in the bundle.\n"
            );
        }
        let _ = writeln!(
            issue_body,
            "Metrics: rx {} pkts / tx {} pkts, {} drops, uptime {}s",
            snap.packets_rx, snap.packets_tx, total_drops, uptime
        );
        let _ = writeln!(issue_body);
        let _ = writeln!(
            issue_body,
            "Diagnostic bundle: `{}` — **please attach this file to the issue.**",
            path.display()
        );
        let _ = writeln!(issue_body);
        let _ = writeln!(issue_body, "<!-- Describe what went wrong below. -->");

        IpcMessage::ReportBundle {
            path: path.display().to_string(),
            issue_title,
            issue_body,
        }
    }

    pub(crate) fn gather_conn_info(conn: &iroh::endpoint::Connection) -> ipc::ConnectionInfo {
        let paths = conn.paths();
        // Classify every path, then pick which one to report. iroh only marks a
        // path `is_selected()` once its path-selector has promoted a winner;
        // during establishment, holepunch, or migration no path is selected even
        // though the connection is live and carrying traffic. Reporting only the
        // selected path then renders a working connection as `?`. `choose_path`
        // falls back to the best available (Direct > Relay > Tor) so a live
        // connection always reports a concrete path.
        let classes: Vec<(ipc::ConnType, bool)> = paths
            .iter()
            .map(|p| {
                let addr = p.remote_addr();
                let ct = if addr.is_relay() {
                    ipc::ConnType::Relay
                } else if addr.is_custom() {
                    ipc::ConnType::Tor
                } else {
                    ipc::ConnType::Direct
                };
                (ct, p.is_selected())
            })
            .collect();

        let (conn_type, remote_addr, rtt_ms) = match choose_path_index(&classes)
            .and_then(|idx| paths.iter().nth(idx).map(|p| (idx, p)))
        {
            Some((idx, path)) => {
                let rtt = path.rtt().as_secs_f64() * 1000.0;
                (
                    classes[idx].0.clone(),
                    Some(path.remote_addr().to_string()),
                    Some(rtt),
                )
            }
            None => (ipc::ConnType::Unknown, None, None),
        };

        let stats = conn.stats();
        ipc::ConnectionInfo {
            conn_type,
            remote_addr,
            rtt_ms,
            bytes_tx: stats.udp_tx.bytes,
            bytes_rx: stats.udp_rx.bytes,
            datagrams_tx: stats.udp_tx.datagrams,
            datagrams_rx: stats.udp_rx.datagrams,
            lost_packets: stats.lost_packets,
        }
    }

    // -----------------------------------------------------------------------
    // Diagnostics (ray ping / ray netcheck)
    // -----------------------------------------------------------------------

    /// Resolve a `ray ping` peer argument (hostname / mesh IPv6 / short id /
    /// `self`) to its mesh IPv6 plus a display name. Mirrors `resolve_peer_name`
    /// but returns the address (so `lookup_v6` can yield a live connection).
    pub(crate) async fn resolve_peer_ip(&self, name: &str) -> Option<(Ipv6Addr, String)> {
        let id = self.resolve_peer_name(name).await?;
        for entry in self.registry.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(m) = state.members.all().iter().find(|m| m.identity == id) {
                let display = m
                    .hostname
                    .clone()
                    .unwrap_or_else(|| id.fmt_short().to_string());
                return Some((derive_ipv6(&m.identity), display));
            }
        }
        None
    }

    /// Wake an idle peer so a caller can tell, before committing to a transfer,
    /// whether it is actually reachable. Returns true when a live mesh link
    /// exists once this returns.
    ///
    /// On an on-demand node every link self-closes after the idle timeout, so a
    /// perfectly reachable peer holds no connection and reports `Idle`. This
    /// dials it (which also stamps reachability, flipping the peer to `Offline`
    /// in `status` when the dial fails) and leaves the link up, so the file
    /// offer's own `FILES_ALPN` dial lands on an already-awake device.
    ///
    /// Part of the embedding API (used by `ray-mobile`'s share picker).
    pub async fn wake_peer(&self, peer: &str) -> bool {
        let Some(id) = self.resolve_peer_flexible(peer).await else {
            return false;
        };
        // A live link already exists (the peer table only holds connected peers).
        if self.registry.peers.ipv6_for_id(&id).is_some() {
            return true;
        }
        let Some(ip) = self.member_ipv6(&id) else {
            return false;
        };
        match self.registry.resolve_route(IpAddr::V6(ip)) {
            Some(target) => self.registry.dial_target(&target).await,
            None => false,
        }
    }

    /// The peer's mesh IPv6, for peers with no live connection (where
    /// `PeerTable::ipv6_for_id` has nothing). Derived from the identity, so the
    /// roster only has to confirm the peer is a member somewhere.
    fn member_ipv6(&self, id: &EndpointId) -> Option<Ipv6Addr> {
        for entry in self.registry.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if state.members.all().iter().any(|m| &m.identity == id) {
                return Some(derive_ipv6(id));
            }
        }
        None
    }

    /// Active liveness probe: send `count` `Ping` control messages over the
    /// peer's live mesh connection and time each `Pong` reply.
    pub(crate) async fn ping(&self, peer: &str, count: u32, interval_ms: u64) -> IpcMessage {
        let (ip, display) = match self.resolve_peer_ip(peer).await {
            Some(x) => x,
            None => {
                return ipc_err(format!("unknown peer '{peer}'"));
            }
        };
        let route = match self.registry.peers.lookup_v6(&ip) {
            Some(r) => r,
            None => {
                // No live link (an on-demand idle peer holds none): dial it on
                // demand so ping works like a reach probe, then re-look up.
                // `dial_target` stamps reachability, so a failure here also flips
                // the peer's status to offline.
                match self.registry.resolve_route(IpAddr::V6(ip)) {
                    Some(target) if self.registry.dial_target(&target).await => {
                        match self.registry.peers.lookup_v6(&ip) {
                            Some(r) => r,
                            None => {
                                return ipc_err(format!("{display}: dialed but no route to {ip}"));
                            }
                        }
                    }
                    _ => {
                        return ipc_err(format!("{display} is unreachable (no answer at {ip})"));
                    }
                }
            }
        };
        let conn = route.conn;
        let network = route.network.to_string();
        let count = count.clamp(1, 100);
        let mut probes: Vec<Option<f64>> = Vec::with_capacity(count as usize);

        for seq in 0..count {
            if seq > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
            let nonce: u64 = rand::random();
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.protocol_router.pending_pongs().insert(nonce, tx);
            let sent = Instant::now();
            let sent_ok = match conn.open_bi().await {
                Ok((mut send, _)) => {
                    control::send_msg(&mut send, None, &control::ControlMsg::Ping { nonce })
                        .await
                        .is_ok()
                }
                Err(_) => false,
            };
            let rtt = if sent_ok {
                match tokio::time::timeout(Duration::from_secs(1), rx).await {
                    Ok(Ok(())) => Some(sent.elapsed().as_secs_f64() * 1000.0),
                    _ => None,
                }
            } else {
                None
            };
            // Drop the slot whether or not the Pong arrived (timeout / send error).
            self.protocol_router.pending_pongs().remove(&nonce);
            probes.push(rtt);
        }

        let info = Self::gather_conn_info(&conn);
        IpcMessage::PingResponse {
            peer_name: display,
            conn_type: info.conn_type,
            remote_addr: info.remote_addr,
            network,
            probes,
        }
    }

    /// Local endpoint diagnostics: bound port, home relay, reachability.
    pub(crate) async fn netcheck(&self) -> IpcMessage {
        use iroh::Watcher as _;

        let bound = self.transport.endpoint.bound_sockets();
        let bound_port = bound.first().map(|a| a.port()).unwrap_or(0);
        let port_is_fixed = bound_port == transport::RAYFISH_LISTEN_PORT;

        // The endpoint runs net reports continuously; the first may still be in
        // flight, so wait briefly for an initialized report, then fall back to
        // whatever the watcher currently holds.
        let report = {
            let mut w = self.transport.endpoint.net_report();
            match tokio::time::timeout(Duration::from_secs(3), w.initialized()).await {
                Ok(r) => Some(r),
                Err(_) => w.get(),
            }
        };

        let mut home_relay = None;
        let mut relay_latency_ms = None;
        let mut public_ipv4 = None;
        let mut public_ipv6 = None;
        let mut udp = false;

        if let Some(r) = report {
            udp = r.has_udp();
            public_ipv4 = r.global_v4.map(|a| a.to_string());
            public_ipv6 = r.global_v6.map(|a| a.to_string());
            if let Some(pref) = r.preferred_relay.clone() {
                home_relay = Some(pref.to_string());
                // Lowest measured latency to the preferred relay across probes.
                relay_latency_ms = r
                    .relay_latency
                    .iter()
                    .filter(|(_, url, _)| **url == pref)
                    .map(|(_, _, d)| d.as_secs_f64() * 1000.0)
                    .fold(None, |acc: Option<f64>, v| {
                        Some(acc.map_or(v, |a| a.min(v)))
                    });
            }
        }

        // Fall back to the connection-status watcher for the relay URL if the net
        // report has not surfaced a preferred relay yet.
        if home_relay.is_none() {
            let status = self.transport.endpoint.home_relay_status().get();
            home_relay = status.first().map(|s| s.url().to_string());
        }

        IpcMessage::NetcheckResponse {
            bound_port,
            port_is_fixed,
            home_relay,
            relay_latency_ms,
            public_ipv4,
            public_ipv6,
            udp,
        }
    }
}

// ---------------------------------------------------------------------------
// `ray logs`: the streamed read of the daemon's own rolling log files
// ---------------------------------------------------------------------------

/// The appender's per-day filename prefix (`rayfish.log.2026-08-15`).
const LOG_PREFIX: &str = "rayfish.log.";

/// Width of the `YYYY-MM-DD` day a rolling file is named for, and of the day
/// half of a timestamp.
const DAY_LEN: usize = 10;

/// Width of the fixed-layout RFC3339 UTC timestamp the appender writes at the
/// head of every line: `2026-08-15T22:36:00.123456Z`.
const TS_LEN: usize = 27;

/// How often `--follow` looks for appended bytes. Polling the file the daemon
/// writes itself needs no new plumbing, shows exactly what `ray report` would
/// bundle, and picks the daily rotation up for free by re-resolving "today"
/// each tick.
const FOLLOW_POLL: Duration = Duration::from_millis(500);

/// Answer an [`IpcMessage::Logs`] request on `framed`, reading the rolling
/// files under `dir`.
///
/// The one multi-frame reply in the protocol, and it writes its own frames
/// rather than returning a message: a day of `rayfish=debug` output is well
/// over the 1 MiB frame cap, and `--follow` has no end at all. A one-shot read
/// closes with an [`IpcMessage::Ok`] sentinel; a followed one runs until the
/// client hangs up or the daemon shuts down.
pub(crate) async fn stream_logs<S: Hangup>(
    dir: &Path,
    framed: &mut ServedFramed<S>,
    since: Option<Duration>,
    follow: bool,
    token: &CancellationToken,
) -> Result<()> {
    if !dir.is_dir() {
        let _ = ipc::send(
            framed,
            ipc_err(format!("no log directory at {}", dir.display())),
        )
        .await;
        return Ok(());
    }

    let now = SystemTime::now();
    // The cutoff is rendered in the appender's own format so a line can be
    // compared against it as a string; `now - since` saturates at the epoch.
    let cutoff = since.map(|d| rfc3339_micros(now.checked_sub(d).unwrap_or(UNIX_EPOCH)));
    let today = day_of(now);

    // Oldest file first, so what the client concatenates reads chronologically.
    let mut offset = 0u64;
    let mut current = dir.join(format!("{LOG_PREFIX}{today}"));
    for path in select_log_files(dir, cutoff.as_deref(), &today) {
        let end = stream_file(framed, &path, cutoff.as_deref(), 0).await?;
        // Where `--follow` picks up, if the pass ended on the live file.
        if path == current {
            offset = end;
        }
    }

    if !follow {
        return ipc::send(
            framed,
            IpcMessage::Ok {
                message: "end of logs".to_string(),
            },
        )
        .await;
    }

    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            // `--follow` can sit idle for minutes between lines, so a hangup has
            // to be noticed on the read side: waiting for a write to fail would
            // leak the task until something happened to be logged.
            _ = client_gone(framed.get_ref()) => return Ok(()),
            _ = tokio::time::sleep(FOLLOW_POLL) => {}
        }

        // Re-resolve the day each tick: at midnight the appender opens a new
        // file and the old one stops growing.
        let today = day_of(SystemTime::now());
        let path = dir.join(format!("{LOG_PREFIX}{today}"));
        if path != current {
            current = path;
            offset = 0;
        }
        if !current.is_file() {
            continue;
        }
        // A file shorter than where we left off was replaced under us; restart
        // from its head rather than waiting forever on bytes past the end.
        if let Ok(meta) = tokio::fs::metadata(&current).await
            && meta.len() < offset
        {
            offset = 0;
        }
        // No cutoff on the tail: anything appended after the one-shot pass is
        // inside the `--since` window by construction.
        offset = stream_file(framed, &current, None, offset).await?;
    }
}

/// The rolling files that can hold lines at or after `cutoff`, oldest first.
///
/// `None` selects just `today`'s file, which is everything since the last
/// daily rotation and what a bare `ray logs` shows. `panic.log` is not in
/// either set: it carries no timestamps to filter on, and `ray report` is what
/// collects it.
fn select_log_files(dir: &Path, cutoff: Option<&str>, today: &str) -> Vec<PathBuf> {
    let Some(cutoff) = cutoff else {
        let path = dir.join(format!("{LOG_PREFIX}{today}"));
        return if path.is_file() {
            vec![path]
        } else {
            Vec::new()
        };
    };
    let Some(day) = cutoff.get(..DAY_LEN) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix(LOG_PREFIX))
                .is_some_and(|d| d >= day)
        })
        .collect();
    // Rotation appends the date, so lexical order is chronological.
    files.sort();
    files
}

/// Forward one log file's complete lines from byte `from`, dropping anything
/// older than `cutoff`. Returns the offset just past the last whole line,
/// which is where a `--follow` poll resumes.
///
/// A trailing partial line is left where it is: the daemon writes into this
/// same file, so a read can land mid-line, and forwarding half of one would
/// both garble it and make the next poll repeat it.
async fn stream_file<S: Hangup>(
    framed: &mut ServedFramed<S>,
    path: &Path,
    cutoff: Option<&str>,
    from: u64,
) -> Result<u64> {
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

    let Ok(file) = tokio::fs::File::open(path).await else {
        return Ok(from);
    };
    let mut reader = BufReader::new(file);
    if from > 0 {
        reader.seek(SeekFrom::Start(from)).await?;
    }

    let mut offset = from;
    let mut out: Vec<u8> = Vec::with_capacity(LOG_CHUNK_BYTES);
    let mut line: Vec<u8> = Vec::new();
    let mut keep = true;
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line).await?;
        if n == 0 || !line.ends_with(b"\n") {
            break;
        }
        offset += n as u64;
        if let Some(cutoff) = cutoff {
            keep = keep_line(&line, cutoff, keep);
            if !keep {
                continue;
            }
        }
        out.extend_from_slice(&line);
        if out.len() >= LOG_CHUNK_BYTES {
            send_chunks(framed, &mut out).await?;
        }
    }
    send_chunks(framed, &mut out).await?;
    Ok(offset)
}

/// Drain `buf` into `LogChunk` frames, none bigger than the frame cap allows.
async fn send_chunks<S: Hangup>(framed: &mut ServedFramed<S>, buf: &mut Vec<u8>) -> Result<()> {
    for piece in buf.chunks(LOG_CHUNK_BYTES) {
        ipc::send(
            framed,
            IpcMessage::LogChunk {
                data: piece.to_vec(),
            },
        )
        .await?;
    }
    buf.clear();
    Ok(())
}

/// Whether a log line is at or after `cutoff`. `prev` is the verdict for the
/// line before it: a line with no leading timestamp is a continuation (a panic
/// backtrace, a multi-line message) and inherits it, so a kept event keeps its
/// whole body.
fn keep_line(line: &[u8], cutoff: &str, prev: bool) -> bool {
    match line_timestamp(line) {
        Some(ts) => ts >= cutoff,
        None => prev,
    }
}

/// The leading RFC3339 UTC timestamp of a log line, if it has one.
///
/// Recognized by shape and compared as a string: the appender writes a
/// fixed-width, zero-padded `YYYY-MM-DDTHH:MM:SS.ffffffZ`, so lexical order is
/// chronological and no calendar arithmetic is needed to answer the only
/// question `--since` asks.
fn line_timestamp(line: &[u8]) -> Option<&str> {
    let head = std::str::from_utf8(line.get(..TS_LEN)?).ok()?;
    let b = head.as_bytes();
    let shaped = b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[26] == b'Z';
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let filled = digits(0..4)
        && digits(5..7)
        && digits(8..10)
        && digits(11..13)
        && digits(14..16)
        && digits(17..19)
        && digits(20..26);
    (shaped && filled).then_some(head)
}

/// `t` in the appender's timestamp format.
fn rfc3339_micros(t: SystemTime) -> String {
    humantime::format_rfc3339_micros(t).to_string()
}

/// The `YYYY-MM-DD` a rolling file is named for.
fn day_of(t: SystemTime) -> String {
    rfc3339_micros(t)[..DAY_LEN].to_string()
}

/// A served IPC transport that can be watched for the client hanging up.
///
/// `readable`/`try_read` are inherent methods on both `UnixStream` and
/// `NamedPipeServer` with the same shapes, but they belong to no shared trait,
/// and `AsyncRead` alone cannot express "tell me about EOF without consuming a
/// read the framing owns". So the two are named here, which is also what makes
/// [`stream_logs`] servable on both.
pub(crate) trait Hangup: AsyncRead + AsyncWrite + Unpin {
    fn readable(&self) -> impl Future<Output = std::io::Result<()>>;
    fn try_read(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[cfg(unix)]
impl Hangup for tokio::net::UnixStream {
    fn readable(&self) -> impl Future<Output = std::io::Result<()>> {
        Self::readable(self)
    }
    fn try_read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        Self::try_read(self, buf)
    }
}

#[cfg(windows)]
impl Hangup for tokio::net::windows::named_pipe::NamedPipeServer {
    fn readable(&self) -> impl Future<Output = std::io::Result<()>> {
        Self::readable(self)
    }
    fn try_read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        Self::try_read(self, buf)
    }
}

/// Resolves once the client's end of the connection is gone.
///
/// The client sends nothing after its request, so any readability is either
/// EOF (it hung up) or noise to discard.
async fn client_gone<S: Hangup>(stream: &S) -> std::io::Result<()> {
    let mut scratch = [0u8; 64];
    loop {
        stream.readable().await?;
        match stream.try_read(&mut scratch) {
            Ok(0) => return Ok(()),
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Project a saved but unregistered network into the `NetworkStatus` shape, so
/// `ray status` can draw the group from disk while the restore is still dialling
/// its coordinator.
///
/// Restoring a membership needs the network's signed pkarr record, and that can
/// take a minute of backoff after a reboot (`restore_member_network`). Until it
/// lands the network is not in the registry, and status used to render it as a
/// bare name over one line of apology: no address, no members, no join code,
/// even though the config on disk holds all three. The projection is the
/// `members` list as last saved, which is deliberately lossy compared with the
/// signed blob, so nothing here is presented as live: every peer carries no
/// connection and reads `Offline`, and pairing is left unresolved (the
/// device/user map is filled by applying a verified roster, which has not
/// happened yet).
pub(crate) fn saved_network_status(
    net: &config::NetworkConfig,
    my_id: EndpointId,
) -> NetworkStatus {
    // Same order the registered path decides in: a `ray connect` link is
    // `direct` whatever else it is, then holding the network secret key is what
    // makes this node the coordinator.
    let role = if net.direct {
        NetworkRole::Direct
    } else if net.network_secret_key.is_some() {
        NetworkRole::Coordinator
    } else {
        NetworkRole::Member
    };
    let peers = net
        .members
        .iter()
        .filter(|m| m.identity != my_id)
        .map(|m| PeerStatus {
            endpoint_id: m.identity,
            ipv6: derive_ipv6(&m.identity),
            hostname: m.hostname.clone(),
            user_identity: None,
            is_own_device: false,
            incompatible: false,
            connection: None,
            // Not `Idle`: idle means "no link, but nothing says it failed", which
            // is the optimistic default for a *registered* network. Nothing on
            // this one is reachable at all until the restore lands.
            state: PeerState::Offline,
            exit_node: false,
            exit_in_use: false,
        })
        .collect();
    NetworkStatus {
        name: net.name.clone(),
        role,
        my_ipv6: derive_ipv6(&my_id),
        my_hostname: net.my_hostname.clone(),
        network_key: net.network_public_key.map(|k| k.to_string()),
        member_count: net.members.len(),
        peers,
        pending_suggestions: 0,
        pending_requests: 0,
        aliases: net.aliases.clone(),
        ephemeral_ttl_secs: net.ephemeral_ttl_secs,
        my_exit_node: None,
        exit_offering: false,
        incompatible: None,
    }
}

#[cfg(test)]
mod log_tests {
    use super::*;

    const CUTOFF: &str = "2026-08-15T12:00:00.000000Z";

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"").unwrap();
    }

    #[test]
    fn no_cutoff_selects_only_todays_file() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "rayfish.log.2026-08-13");
        touch(dir.path(), "rayfish.log.2026-08-15");

        let files = select_log_files(dir.path(), None, "2026-08-15");
        assert_eq!(files, vec![dir.path().join("rayfish.log.2026-08-15")]);
    }

    #[test]
    fn no_cutoff_and_no_file_today_selects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "rayfish.log.2026-08-13");

        assert!(select_log_files(dir.path(), None, "2026-08-15").is_empty());
    }

    #[test]
    fn a_cutoff_selects_its_day_and_newer_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        for day in ["2026-08-12", "2026-08-14", "2026-08-15", "2026-08-16"] {
            touch(dir.path(), &format!("rayfish.log.{day}"));
        }
        // The daemon may have crashed mid-write, and a report bundle may sit
        // alongside; neither is a rolling log file.
        touch(dir.path(), "panic.log");
        touch(dir.path(), "rayfish-report-1.tgz");

        let files = select_log_files(
            dir.path(),
            Some("2026-08-14T09:30:00.000000Z"),
            "2026-08-16",
        );
        let names: Vec<&str> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "rayfish.log.2026-08-14",
                "rayfish.log.2026-08-15",
                "rayfish.log.2026-08-16"
            ]
        );
    }

    #[test]
    fn a_missing_directory_selects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("nope");
        assert!(select_log_files(&gone, Some(CUTOFF), "2026-08-15").is_empty());
        assert!(select_log_files(&gone, None, "2026-08-15").is_empty());
    }

    #[test]
    fn a_leading_timestamp_is_recognized_by_shape() {
        assert_eq!(
            line_timestamp(b"2026-08-15T12:00:00.000000Z  INFO rayfish: hi\n"),
            Some(CUTOFF)
        );
        // Local time, a missing `Z`, a short fraction, a bare backtrace frame:
        // none of these is the appender's format, so none is a timestamp.
        assert_eq!(line_timestamp(b"2026-08-15 12:00:00.000000Z INFO\n"), None);
        assert_eq!(line_timestamp(b"2026-08-15T12:00:00.000000+ INFO\n"), None);
        assert_eq!(line_timestamp(b"2026-08-15T12:00:00.00Z INFO\n"), None);
        assert_eq!(line_timestamp(b"   1: rayfish::forward::run\n"), None);
        assert_eq!(line_timestamp(b"short\n"), None);
    }

    #[test]
    fn the_cutoff_line_itself_is_kept() {
        let at = b"2026-08-15T12:00:00.000000Z  INFO rayfish: at the cutoff\n";
        let just_before = b"2026-08-15T11:59:59.999999Z  INFO rayfish: before\n";
        let just_after = b"2026-08-15T12:00:00.000001Z  INFO rayfish: after\n";

        assert!(keep_line(at, CUTOFF, false));
        assert!(!keep_line(just_before, CUTOFF, true));
        assert!(keep_line(just_after, CUTOFF, false));
    }

    #[test]
    fn a_continuation_line_inherits_the_line_above_it() {
        let frame = b"   1: rayfish::forward::run\n";
        assert!(keep_line(frame, CUTOFF, true));
        assert!(!keep_line(frame, CUTOFF, false));
    }
}

/// The streaming half of `ray logs`, driven over a real socket pair: the
/// filtering and file-selection units above say what *should* go out, these
/// say what actually comes back on the wire.
///
/// Unix only, for want of a `NamedPipeServer::pair()`: naming a pipe would make
/// these tests share process-wide state with anything else running.
#[cfg(all(test, unix))]
mod log_stream_tests {
    use super::*;

    /// Ample for a 500ms poll, short enough that a hang fails the run instead
    /// of stalling it.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// A log line stamped `ago` before now, in the appender's format.
    fn line(ago: Duration, msg: &str) -> String {
        let at = SystemTime::now().checked_sub(ago).unwrap();
        format!("{}  INFO rayfish: {msg}\n", rfc3339_micros(at))
    }

    fn today_log(dir: &Path) -> PathBuf {
        dir.join(format!("{LOG_PREFIX}{}", day_of(SystemTime::now())))
    }

    /// The text of one `LogChunk` frame.
    fn chunk(msg: IpcMessage) -> String {
        match msg {
            IpcMessage::LogChunk { data } => String::from_utf8(data).unwrap(),
            other => panic!("expected a LogChunk, got {other:?}"),
        }
    }

    /// Read the next frame off the client end, failing rather than hanging.
    async fn next_chunk(framed: &mut crate::ipc::IpcFramed) -> String {
        let msg = tokio::time::timeout(PATIENCE, ipc::recv(framed))
            .await
            .expect("no frame arrived")
            .unwrap();
        chunk(msg)
    }

    /// Drain the client end until the `Ok` sentinel and return what the chunks
    /// concatenate to. `None` for `Error`, which is a different answer.
    async fn drain(framed: &mut crate::ipc::IpcFramed) -> Option<String> {
        let mut out = Vec::new();
        loop {
            match ipc::recv(framed).await.unwrap() {
                IpcMessage::LogChunk { data } => out.extend_from_slice(&data),
                IpcMessage::Ok { .. } => return Some(String::from_utf8(out).unwrap()),
                IpcMessage::Error { .. } => return None,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    }

    async fn serve(
        dir: &Path,
        since: Option<Duration>,
        follow: bool,
    ) -> (crate::ipc::IpcFramed, tokio::task::JoinHandle<Result<()>>) {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let dir = dir.to_path_buf();
        let task = tokio::spawn(async move {
            let mut framed = ipc::framed(server);
            stream_logs(&dir, &mut framed, since, follow, &CancellationToken::new()).await
        });
        (ipc::framed(client), task)
    }

    #[tokio::test]
    async fn a_bare_read_returns_todays_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!(
            "{}{}",
            line(Duration::from_secs(7200), "early"),
            line(Duration::from_secs(60), "late")
        );
        std::fs::write(today_log(dir.path()), &body).unwrap();

        let (mut client, task) = serve(dir.path(), None, false).await;
        let got = tokio::time::timeout(PATIENCE, drain(&mut client))
            .await
            .unwrap();
        assert_eq!(got.unwrap(), body);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn since_drops_older_lines_and_keeps_their_continuations_out() {
        let dir = tempfile::tempdir().unwrap();
        let old = line(Duration::from_secs(7200), "early");
        let recent = line(Duration::from_secs(60), "late");
        std::fs::write(
            today_log(dir.path()),
            format!("{old}   1: an old backtrace frame\n{recent}   1: a recent one\n"),
        )
        .unwrap();

        let (mut client, task) = serve(dir.path(), Some(Duration::from_secs(3600)), false).await;
        let got = tokio::time::timeout(PATIENCE, drain(&mut client))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, format!("{recent}   1: a recent one\n"));
        task.await.unwrap().unwrap();
    }

    /// A read lands mid-write often enough that it has to be handled: the
    /// partial line stays put and arrives whole once its newline does.
    #[tokio::test]
    async fn follow_sends_appended_lines_and_holds_a_partial_one_back() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let first = line(Duration::from_secs(1), "already there");
        std::fs::write(today_log(dir.path()), &first).unwrap();

        let (mut client, task) = serve(dir.path(), None, true).await;
        assert_eq!(next_chunk(&mut client).await, first);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(today_log(dir.path()))
            .unwrap();
        let second = line(Duration::ZERO, "appended");
        write!(file, "{}", &second[..10]).unwrap();
        file.flush().unwrap();
        // Past a poll, so the half-written line really is what the follow loop
        // finds rather than something the timing happened to skip over.
        tokio::time::sleep(FOLLOW_POLL * 2).await;
        write!(file, "{}", &second[10..]).unwrap();
        file.flush().unwrap();

        assert_eq!(next_chunk(&mut client).await, second);

        // Hanging up is how a follow ends; the daemon must not be left polling
        // a file for a client that is gone.
        drop(client);
        tokio::time::timeout(PATIENCE, task)
            .await
            .expect("follow outlived its client")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_missing_log_directory_is_an_error_not_an_empty_read() {
        let dir = tempfile::tempdir().unwrap();
        let (mut client, task) = serve(&dir.path().join("nope"), None, false).await;
        assert!(
            tokio::time::timeout(PATIENCE, drain(&mut client))
                .await
                .unwrap()
                .is_none()
        );
        task.await.unwrap().unwrap();
    }
}

#[cfg(test)]
mod saved_network_tests {
    use super::*;

    fn member(id: EndpointId, host: &str, coordinator: bool) -> config::MemberEntry {
        config::MemberEntry {
            identity: id,
            is_coordinator: coordinator,
            hostname: Some(host.to_string()),
        }
    }

    /// The roster on disk is the whole point of the projection: a group the
    /// daemon has not registered yet still knows who is on it, and every one of
    /// them is unreachable until the restore lands.
    #[test]
    fn projects_the_saved_roster_with_every_peer_offline() {
        let me = iroh::SecretKey::generate().public();
        let them = iroh::SecretKey::generate().public();
        let cfg = config::NetworkConfig {
            name: "homelab".to_string(),
            my_hostname: Some("laptop".to_string()),
            members: vec![member(me, "laptop", false), member(them, "desktop", true)],
            ..Default::default()
        };

        let status = saved_network_status(&cfg, me);

        assert_eq!(status.name, "homelab");
        assert_eq!(status.my_ipv6, derive_ipv6(&me));
        // Self is not a peer of itself.
        assert_eq!(status.peers.len(), 1);
        let peer = &status.peers[0];
        assert_eq!(peer.endpoint_id, them);
        assert_eq!(peer.hostname.as_deref(), Some("desktop"));
        assert_eq!(peer.ipv6, derive_ipv6(&them));
        assert!(peer.connection.is_none());
        assert!(peer.state.is_offline());
    }

    /// Holding the network secret key is what makes this node the coordinator,
    /// and the header says so before any coordinator has been reached.
    #[test]
    fn a_key_holder_projects_as_the_coordinator() {
        let me = iroh::SecretKey::generate().public();
        let cfg = config::NetworkConfig {
            name: "homelab".to_string(),
            network_secret_key: Some(iroh::SecretKey::generate()),
            ..Default::default()
        };
        assert!(saved_network_status(&cfg, me).role.is_coordinator());
    }

    /// A `ray connect` link is tagged `direct` wherever it renders, including
    /// here, so its (non-shareable) room id stays suppressed.
    #[test]
    fn a_direct_link_projects_as_direct() {
        let me = iroh::SecretKey::generate().public();
        let cfg = config::NetworkConfig {
            name: "peer".to_string(),
            direct: true,
            network_secret_key: Some(iroh::SecretKey::generate()),
            ..Default::default()
        };
        assert!(saved_network_status(&cfg, me).role.is_direct());
    }
}
