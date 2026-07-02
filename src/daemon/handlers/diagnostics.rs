//! Read-only diagnostics for `DaemonState`: `status`, `build_report`, `ping`,
//! `netcheck`, and connection-info helpers. Split out of `daemon/mod.rs`.

use super::super::*;

impl DaemonState {
    pub(crate) fn status(&self) -> IpcMessage {
        let hostname_snapshot = self.hostname_table.try_read().ok();
        let my_id = self.endpoint.id();
        // Direct-connection networks are flagged in config; collect their names
        // so each NetworkStatus can be tagged `[direct]` in the CLI.
        let direct_names: HashSet<String> = config::load()
            .map(|c| {
                c.networks
                    .iter()
                    .filter(|n| n.direct)
                    .map(|n| n.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let statuses: Vec<NetworkStatus> = self
            .networks
            .iter()
            .map(|h| self.network_status(&h, my_id, hostname_snapshot.as_deref(), &direct_names))
            .collect();

        IpcMessage::StatusResponse {
            endpoint_id: self.endpoint.id(),
            mdns_enabled: self.mdns_enabled,
            active: self.active.load(Ordering::SeqCst),
            contact_id: Some(self.contact_public.to_string()),
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            networks: statuses,
            packets_rx: self.stats.packets_rx.get(),
            packets_tx: self.stats.packets_tx.get(),
            bytes_rx: self.stats.bytes_rx.get(),
            bytes_tx: self.stats.bytes_tx.get(),
            pending_files: self.protocol_router.pending_files.lock().unwrap().len(),
            pending_connects: self.protocol_router.pending_connects.len(),
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
        let aliases = config::load_network(&h.name)
            .ok()
            .flatten()
            .map(|n| n.aliases)
            .unwrap_or_default();
        // Resolve a mesh IPv4 back to its `.ray` hostname via the DNS snapshot.
        let lookup_hostname = |ip| {
            hostname_snapshot.and_then(|table| {
                table.get(&h.name).and_then(|hosts| {
                    hosts.iter().find(|(_, v)| v.0 == ip).map(|(k, _)| k.clone())
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
                        my_ip: h.my_ip,
                        my_ipv6: Some(derive_ipv6(&my_id)),
                        my_hostname: None,
                        network_key: Some(h.network_key.to_string()),
                        member_count: 0,
                        peers: vec![],
                        pending_suggestions: 0,
                        pending_requests: 0,
                        aliases,
                    };
                }
            };
            let count = s.members.all().len();
            (s.roster(), count, s.pending_suggestions.len(), s.pending.len())
        };
        // Index live connections by endpoint id for a fast lookup.
        let connected: HashMap<EndpointId, Connection> = self
            .peers
            .peers_for_network_with_conn(&h.name)
            .into_iter()
            .map(|(eid, _, conn)| (eid, conn))
            .collect();
        let peers = members
            .iter()
            .filter(|m| m.identity != my_id)
            .map(|m| {
                let hostname = m.hostname.clone().or_else(|| lookup_hostname(m.ip));
                let connection = connected.get(&m.identity).map(Self::gather_conn_info);
                let user_id = self.device_user_map.resolve(&m.identity);
                let user_identity = (user_id != m.identity).then_some(user_id);
                PeerStatus {
                    endpoint_id: m.identity,
                    ip: m.ip,
                    ipv6: Some(derive_ipv6(&m.identity)),
                    hostname,
                    user_identity,
                    connection,
                }
            })
            .collect();
        NetworkStatus {
            name: h.name.clone(),
            role,
            my_ip: h.my_ip,
            my_ipv6: Some(derive_ipv6(&self.identity.local_identity())),
            my_hostname: lookup_hostname(h.my_ip),
            network_key: Some(h.network_key.to_string()),
            member_count,
            peers,
            pending_suggestions,
            pending_requests,
            aliases,
        }
    }

    /// Assemble a diagnostic `.tgz` (logs + metrics + sanitized status + system
    /// info) on disk and return its path plus a pre-filled GitHub issue. Runs
    /// daemon-side because the log files are root-owned; the resulting bundle is
    /// chowned to the calling user so an unprivileged `ray report` can attach it.
    ///
    /// Sanitization: the bundle is built only from already-public material — the
    /// `StatusResponse` (which never carries secret keys), counters, and the log
    /// files. It never touches `secret_key` or `network_secret_key`.
    pub(crate) fn build_report(&self, peer_cred: Option<(u32, u32)>) -> IpcMessage {
        use std::fmt::Write as _;

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
        let _ = writeln!(sysinfo, "endpoint_id: {}", self.endpoint.id());
        let _ = writeln!(sysinfo, "uptime_secs: {uptime}");
        let _ = writeln!(sysinfo, "active: {active}");
        let _ = writeln!(sysinfo, "networks: {}", self.networks.len());

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
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = std::path::PathBuf::from("/tmp").join(format!("rayfish-report-{ts}.tgz"));
        if let Err(e) = write_bundle(&path, &files) {
            return IpcMessage::Error {
                message: format!("failed to write report bundle: {e}"),
            };
        }

        // Make it readable by, and owned by, the user who invoked `ray report`.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        if let Some((uid, gid)) = peer_cred {
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
        }

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

    /// Resolve a `ray ping` peer argument (hostname / IPv4 / short id / `self`)
    /// to its virtual IPv4 plus a display name. Mirrors `resolve_peer_name` but
    /// returns the address (so `lookup_v4` can yield a live connection).
    pub(crate) async fn resolve_peer_ip(&self, name: &str) -> Option<(Ipv4Addr, String)> {
        let id = self.resolve_peer_name(name).await?;
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(m) = state.members.all().iter().find(|m| m.identity == id) {
                let display = m
                    .hostname
                    .clone()
                    .unwrap_or_else(|| id.fmt_short().to_string());
                return Some((m.ip, display));
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
                return IpcMessage::Error {
                    message: format!("unknown peer '{peer}'"),
                };
            }
        };
        let route = match self.peers.lookup_v4(&ip) {
            Some(r) => r,
            None => {
                return IpcMessage::Error {
                    message: format!(
                        "{display} is not connected (no live mesh link to {ip})"
                    ),
                };
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
            self.protocol_router.pending_pongs.insert(nonce, tx);
            let sent = Instant::now();
            let sent_ok = match conn.open_bi().await {
                Ok((mut send, _)) => {
                    control::send_msg(&mut send, &control::ControlMsg::Ping { nonce })
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
            self.protocol_router.pending_pongs.remove(&nonce);
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

        let bound = self.endpoint.bound_sockets();
        let bound_port = bound.first().map(|a| a.port()).unwrap_or(0);
        let port_is_fixed = bound_port == transport::RAYFISH_LISTEN_PORT;

        // The endpoint runs net reports continuously; the first may still be in
        // flight, so wait briefly for an initialized report, then fall back to
        // whatever the watcher currently holds.
        let report = {
            let mut w = self.endpoint.net_report();
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
            let status = self.endpoint.home_relay_status().get();
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
