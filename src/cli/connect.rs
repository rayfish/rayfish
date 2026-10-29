//! CLI direct-connection, ping/netcheck and admin handlers.

use crate::*;

#[derive(serde::Serialize)]
struct LanPeersOutput {
    mdns_enabled: bool,
    peers: Vec<LanPeerOutput>,
}

#[derive(serde::Serialize)]
struct LanPeerOutput {
    endpoint_id: String,
    short_id: String,
    addrs: Vec<String>,
    last_seen_secs: u64,
    shared_network: Option<String>,
}

impl From<ipc::LanPeerInfo> for LanPeerOutput {
    fn from(peer: ipc::LanPeerInfo) -> Self {
        Self {
            endpoint_id: peer.endpoint_id.to_string(),
            short_id: peer.short_id,
            addrs: peer.addrs,
            last_seen_secs: peer.last_seen_secs,
            shared_network: peer.shared_network,
        }
    }
}

impl DisplayOut for LanPeersOutput {
    fn print_human(&self) {
        if !self.mdns_enabled {
            println!(
                "\n  {}\n",
                style::faint("mDNS discovery is off — turn it on with: ray mdns on")
            );
        } else if self.peers.is_empty() {
            println!(
                "\n  {}\n",
                style::faint("no rayfish nodes seen on this LAN")
            );
        } else {
            let rows = self
                .peers
                .iter()
                .map(|p| {
                    let addrs = if p.addrs.is_empty() {
                        "—".to_string()
                    } else {
                        p.addrs.join(", ")
                    };
                    let seen = format!("{}s", p.last_seen_secs);
                    let status = match &p.shared_network {
                        Some(net) => format!("shared: {net}"),
                        None => "not connected".to_string(),
                    };
                    let status_cell = match &p.shared_network {
                        Some(_) => style::green(&status),
                        None => style::faint(&status),
                    };
                    vec![
                        layout::Cell::new(p.short_id.clone(), style::rose(&p.short_id)),
                        layout::Cell::new(addrs.clone(), style::value(&addrs)),
                        layout::Cell::right(seen.clone(), style::faint(&seen)),
                        layout::Cell::new(status, status_cell),
                    ]
                })
                .collect();
            println!();
            print!(
                "{}",
                table(&["peer", "addresses", "seen", "status"], rows, 2)
            );
            println!(
                "\n  {}",
                style::faint("link up with: ray connect <peer> (they approve it)")
            );
        }
    }
}

#[derive(serde::Serialize)]
struct PingOutput {
    peer: String,
    network: String,
    conn_type: &'static str,
    remote_addr: Option<String>,
    /// Scope of the legacy path fields; per-probe evidence is below.
    summary_path_scope: &'static str,
    /// Legacy JSON name: counts probe attempts, including local send failures.
    /// It is not a count of transmitted or lost network packets.
    sent: usize,
    received: usize,
    rtts_ms: Vec<Option<f64>>,
    /// Each entry describes local path selection observations, not packet routes.
    probe_details: Vec<ipc::PingProbeDetails>,
}

fn selected_path_text(path: &Option<ipc::PingSelectedPath>) -> String {
    path.as_ref().map_or_else(
        || "unknown".to_string(),
        |path| format!("{} {}", path.conn_type, path.remote_addr),
    )
}

fn probe_path_text(detail: Option<&ipc::PingProbeDetails>) -> String {
    let Some(detail) = detail else {
        return "selected path not reported by daemon".to_string();
    };
    let before = selected_path_text(&detail.selected_path_before);
    let after = selected_path_text(&detail.selected_path_after);
    let mut parts = Vec::new();
    if detail.path_history_incomplete {
        parts.push(format!(
            "selected-path history incomplete (before={before}; after={after})"
        ));
    } else if detail.selection_changed {
        parts.push(format!(
            "selected path changed during probe (before={before}; after={after})"
        ));
    } else {
        parts.push(format!("selected={after}"));
    }
    if detail.connection_changed {
        parts.push("connection changed".to_string());
    }
    parts.join("; ")
}

impl PingOutput {
    fn probe_summary(&self) -> String {
        let unanswered = if self.sent > 0 {
            (self.sent - self.received) as f64 * 100.0 / self.sent as f64
        } else {
            0.0
        };
        format!(
            "{} probes attempted, {} answered, {unanswered:.0}% unanswered",
            self.sent, self.received
        )
    }

    fn probe_line(&self, seq: usize, probe: Option<f64>) -> String {
        let detail = self.probe_details.get(seq);
        let path = probe_path_text(detail);
        match probe {
            Some(ms) => format!(
                "  {} pong from {} seq={seq} rtt={}  {}",
                style::green("✓"),
                style::value(&self.peer),
                style::latency(ms),
                style::faint(&path),
            ),
            None => {
                let reason = match detail.map(|detail| detail.outcome) {
                    Some(ipc::PingProbeOutcome::Timeout) => "probe timed out",
                    Some(ipc::PingProbeOutcome::SendFailed) => "send failed",
                    Some(ipc::PingProbeOutcome::ReplyWaitFailed) => "reply wait failed",
                    Some(ipc::PingProbeOutcome::ConnectionClosed) => "connection closed",
                    Some(ipc::PingProbeOutcome::NoConnection) => "no live connection",
                    _ => "no reply",
                };
                format!(
                    "  {} no reply from {} seq={seq} ({reason})  {}",
                    style::red("✗"),
                    style::value(&self.peer),
                    style::faint(&path)
                )
            }
        }
    }
}

impl DisplayOut for PingOutput {
    fn print_human(&self) {
        for (seq, probe) in self.rtts_ms.iter().enumerate() {
            println!("{}", self.probe_line(seq, *probe));
        }
        println!(
            "  {}",
            style::faint("Selected paths are local observations, not per-packet route traces.")
        );

        println!();
        println!("  --- {} ping statistics ---", self.peer);
        let rtts: Vec<f64> = self.rtts_ms.iter().filter_map(|p| *p).collect();
        let summary = self.probe_summary();
        if rtts.is_empty() {
            println!("  {summary}");
            println!(
                "  {}",
                style::faint("no replies received during this run; see per-probe results above")
            );
        } else {
            let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let avg = rtts.iter().sum::<f64>() / self.received as f64;
            println!("  {summary}, rtt min/avg/max {min:.0}/{avg:.0}/{max:.0} ms");
        }
    }
}

#[derive(serde::Serialize)]
struct NetcheckOutput {
    bound_port: u16,
    port_is_fixed: bool,
    home_relay: Option<String>,
    relay_latency_ms: Option<f64>,
    public_ipv4: Option<String>,
    public_ipv6: Option<String>,
    udp: bool,
}

impl DisplayOut for NetcheckOutput {
    fn print_human(&self) {
        let na = || style::faint("—").to_string();
        let port_note = if self.port_is_fixed {
            style::faint("  (fixed, forwardable)")
        } else {
            style::faint("  (ephemeral fallback)")
        };
        println!(
            "  {:<15}{}{port_note}",
            "UDP port",
            style::value(&self.bound_port.to_string())
        );
        println!(
            "  {:<15}{}",
            "UDP working",
            if self.udp {
                style::green("yes")
            } else {
                style::red("no")
            }
        );
        println!(
            "  {:<15}{}",
            "Home relay",
            self.home_relay
                .as_ref()
                .map(|s| style::value(s))
                .unwrap_or_else(na)
        );
        println!(
            "  {:<15}{}",
            "Relay latency",
            self.relay_latency_ms.map(style::latency).unwrap_or_else(na)
        );
        println!(
            "  {:<15}{}",
            "Public IPv4",
            self.public_ipv4
                .as_ref()
                .map(|s| style::value(s))
                .unwrap_or_else(na)
        );
        println!(
            "  {:<15}{}",
            "Public IPv6",
            self.public_ipv6
                .as_ref()
                .map(|s| style::value(s))
                .unwrap_or_else(na)
        );
    }
}

#[derive(serde::Serialize)]
struct AdminsOutput(Vec<AdminOutput>);

#[derive(serde::Serialize)]
struct AdminOutput {
    id: String,
    #[serde(rename = "self")]
    self_node: bool,
}

impl DisplayOut for AdminsOutput {
    fn print_human(&self) {
        if self.0.is_empty() {
            println!("\n  {}\n", style::faint("no admins recorded"));
        } else {
            println!();
            let mut rows = Vec::new();
            for a in &self.0 {
                let (glyph, tag) = if a.self_node {
                    (style::dot_online(), style::marker("this device"))
                } else {
                    (style::dot_offline(), String::new())
                };
                rows.push(vec![
                    layout::Cell::new("●", glyph),
                    layout::Cell::new(a.id.clone(), style::value(&a.id)),
                    layout::Cell::new(if a.self_node { "this device" } else { "" }, tag),
                ]);
            }
            print!("{}", indent(&layout::columns(&rows, 2), 2));
            println!();
        }
    }
}

pub(crate) async fn ipc_connect(peer: &str, hostname: Option<String>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Connect {
            peer: peer.to_string(),
            hostname,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Joined { name, my_ipv6, .. } => {
            println!(
                "  {} connected — direct network {} ({})",
                style::green("✓"),
                style::value(&name),
                style::faint(&my_ipv6.to_string()),
            );
        }
        ipc::IpcMessage::Error { message } => fail_with("connect failed", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_connections(action: Option<ConnectAction>) -> Result<()> {
    match action.unwrap_or(ConnectAction::List) {
        ConnectAction::List => ipc_connections_list().await,
        ConnectAction::Approve { id } => ipc_connections_approve(&id).await,
        ConnectAction::Deny { id } => {
            let response = ipc_request(ipc::IpcMessage::ConnectDeny { id }).await?;
            print_ok_reply(response)
        }
    }
}

pub(crate) async fn ipc_connections_list() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Connections).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PendingRequests { requests } => print_pending_requests(
            &requests,
            "no pending connection requests",
            "approve with: ray connect approve <name>, or refuse with: ray connect deny <name>",
        )?,
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_connections_approve(id: &str) -> Result<()> {
    let response = ipc_request(ipc::IpcMessage::ApproveConnection { id: id.to_string() }).await?;
    print_ok_reply(response)
}

/// `ray mdns scan`: the rayfish nodes mDNS has seen on this LAN.
pub(crate) async fn ipc_lan_peers() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::ListLanPeers).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::LanPeersList {
            peers,
            mdns_enabled,
        } => {
            printout(&LanPeersOutput {
                mdns_enabled,
                peers: peers.into_iter().map(LanPeerOutput::from).collect(),
            })?;
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_ping(peer: &str, count: u32, interval: u64) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Ping {
            peer: peer.to_string(),
            count,
            interval_ms: interval,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PingResponse {
            peer_name,
            conn_type,
            remote_addr,
            network,
            probes,
            probe_details,
        } => {
            let conn_str = match conn_type {
                ipc::ConnType::Direct => "direct",
                ipc::ConnType::Relay => "relay",
                ipc::ConnType::Tor => "tor",
                ipc::ConnType::Unknown => "?",
            };
            let sent = probes.len();
            let received = probes.iter().filter(|probe| probe.is_some()).count();
            printout(&PingOutput {
                peer: peer_name,
                network,
                conn_type: conn_str,
                remote_addr,
                summary_path_scope: "end_of_run",
                sent,
                received,
                rtts_ms: probes,
                probe_details,
            })?;
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_netcheck() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Netcheck).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::NetcheckResponse {
            bound_port,
            port_is_fixed,
            home_relay,
            relay_latency_ms,
            public_ipv4,
            public_ipv6,
            udp,
        } => {
            printout(&NetcheckOutput {
                bound_port,
                port_is_fixed,
                home_relay,
                relay_latency_ms,
                public_ipv4,
                public_ipv6,
                udp,
            })?;
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_admin(network: &str, action: AdminAction) -> Result<()> {
    let req = match action {
        AdminAction::Add { identity } => ipc::IpcMessage::AdminAdd {
            network: network.to_string(),
            identity,
        },
        AdminAction::List => ipc::IpcMessage::AdminList {
            network: network.to_string(),
        },
    };
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::AdminListResponse { admins } => {
            printout(&AdminsOutput(
                admins
                    .into_iter()
                    .map(|admin| AdminOutput {
                        id: admin.short_id,
                        self_node: admin.self_node,
                    })
                    .collect(),
            ))?;
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

#[cfg(test)]
mod ping_tests {
    use super::*;

    fn path(conn_type: ipc::ConnType, remote_addr: &str) -> Option<ipc::PingSelectedPath> {
        Some(ipc::PingSelectedPath {
            conn_type,
            remote_addr: remote_addr.into(),
        })
    }

    fn detail(selected: Option<ipc::PingSelectedPath>) -> ipc::PingProbeDetails {
        ipc::PingProbeDetails {
            outcome: ipc::PingProbeOutcome::Reply,
            selected_path_before: selected.clone(),
            selected_path_after: selected,
            selection_changed: false,
            path_history_incomplete: false,
            connection_changed: false,
        }
    }

    fn output(details: Vec<ipc::PingProbeDetails>) -> PingOutput {
        PingOutput {
            peer: "dual-a10".into(),
            network: "net".into(),
            conn_type: "relay",
            remote_addr: Some("relay:https://final-relay.example/".into()),
            summary_path_scope: "end_of_run",
            sent: 3,
            received: 3,
            rtts_ms: vec![Some(7.0), Some(550.0), Some(78.0)],
            probe_details: details,
        }
    }

    #[test]
    fn ping_does_not_relabel_earlier_replies_with_the_final_path() {
        let output = output(vec![
            detail(path(ipc::ConnType::Direct, "ip:192.0.2.1:41383")),
            detail(path(
                ipc::ConnType::Relay,
                "relay:https://middle-relay.example/",
            )),
            detail(path(ipc::ConnType::Direct, "ip:[2001:db8::1]:41383")),
        ]);
        let first = output.probe_line(0, output.rtts_ms[0]);
        let second = output.probe_line(1, output.rtts_ms[1]);
        let third = output.probe_line(2, output.rtts_ms[2]);
        assert!(first.contains("selected=direct ip:192.0.2.1:41383"));
        assert!(second.contains("selected=relay relay:https://middle-relay.example/"));
        assert!(third.contains("selected=direct ip:[2001:db8::1]:41383"));
        for line in [&first, &second, &third] {
            assert!(!line.contains("final-relay.example"));
            assert!(!line.contains(" via "));
        }
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["summary_path_scope"], "end_of_run");
        assert_eq!(json["rtts_ms"], serde_json::json!([7.0, 550.0, 78.0]));
        assert_eq!(
            json["probe_details"][0]["selected_path_after"]["remote_addr"],
            "ip:192.0.2.1:41383"
        );
    }

    #[test]
    fn ping_with_an_old_daemon_reports_path_unknown_instead_of_reusing_final_state() {
        let output = output(vec![]);
        let line = output.probe_line(0, Some(7.0));
        assert!(line.contains("selected path not reported by daemon"));
        assert!(!line.contains("final-relay.example"));
        assert!(!line.contains("selected=relay"));
    }

    #[test]
    fn ping_marks_changes_and_incomplete_history_even_for_equal_snapshots() {
        let mut changed = detail(path(ipc::ConnType::Direct, "ip:192.0.2.1:41383"));
        changed.selection_changed = true;
        changed.connection_changed = true;
        let label = probe_path_text(Some(&changed));
        assert!(label.contains("selected path changed during probe"));
        assert!(label.contains("connection changed"));
        changed.path_history_incomplete = true;
        assert!(probe_path_text(Some(&changed)).contains("history incomplete"));
        assert_eq!(probe_path_text(Some(&detail(None))), "selected=unknown");
    }

    #[test]
    fn ping_reports_closed_missing_and_failed_sends_without_calling_them_timeouts() {
        for (outcome, expected) in [
            (ipc::PingProbeOutcome::ConnectionClosed, "connection closed"),
            (ipc::PingProbeOutcome::NoConnection, "no live connection"),
            (ipc::PingProbeOutcome::SendFailed, "send failed"),
            (ipc::PingProbeOutcome::ReplyWaitFailed, "reply wait failed"),
            (ipc::PingProbeOutcome::Timeout, "probe timed out"),
        ] {
            let mut details = detail(None);
            details.outcome = outcome;
            let line = output(vec![details]).probe_line(0, None);
            assert!(line.contains(expected), "{line}");
        }
    }

    #[test]
    fn ping_counts_unanswered_probe_attempts_without_claiming_packet_loss() {
        let mut missing = detail(None);
        missing.outcome = ipc::PingProbeOutcome::NoConnection;
        let mut output = output(vec![missing; 3]);
        output.received = 0;
        output.rtts_ms = vec![None; 3];
        let summary = output.probe_summary();
        assert!(summary.contains("3 probes attempted, 0 answered, 100% unanswered"));
        assert!(!summary.contains(" sent"));
        assert!(!summary.contains("loss"));
        output.received = 2;
        assert!(output.probe_summary().contains("33% unanswered"));
    }
}
