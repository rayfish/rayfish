//! CLI direct-connection, contact, ping/netcheck and admin handlers.

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
struct ContactIdOutput {
    contact_id: String,
    #[serde(skip)]
    rotating: bool,
}

impl DisplayOut for ContactIdOutput {
    fn print_human(&self) {
        if self.rotating {
            println!("  {} contact id rotated", style::green("✓"));
        }
        println!("{}", self.contact_id);
        println!(
            "  {}",
            style::faint("share this so others can: ray connect <contact-id>")
        );
    }
}

#[derive(serde::Serialize)]
struct PingOutput {
    peer: String,
    network: String,
    conn_type: &'static str,
    remote_addr: Option<String>,
    sent: usize,
    received: usize,
    rtts_ms: Vec<Option<f64>>,
}

impl DisplayOut for PingOutput {
    fn print_human(&self) {
        let addr = self.remote_addr.as_deref().unwrap_or("?");
        for (seq, probe) in self.rtts_ms.iter().enumerate() {
            match probe {
                Some(ms) => println!(
                    "  {} pong from {} via {} {}  seq={seq} rtt={}",
                    style::green("✓"),
                    style::value(&self.peer),
                    self.conn_type,
                    style::faint(addr),
                    style::latency(*ms),
                ),
                None => println!(
                    "  {} no reply from {}  seq={seq} {}",
                    style::red("✗"),
                    style::value(&self.peer),
                    style::faint("(timeout)"),
                ),
            }
        }

        let loss = if self.sent > 0 {
            (self.sent - self.received) as f64 * 100.0 / self.sent as f64
        } else {
            0.0
        };
        println!();
        println!("  --- {} ping statistics ---", self.peer);
        let rtts: Vec<f64> = self.rtts_ms.iter().filter_map(|p| *p).collect();
        if rtts.is_empty() {
            println!(
                "  {} sent, {} received, {loss:.0}% loss",
                self.sent, self.received
            );
            println!(
                "  {}",
                style::faint(
                    "no replies — the peer may be offline, firewalled, or on an \
                     incompatible version (run ray update)"
                )
            );
        } else {
            let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let avg = rtts.iter().sum::<f64>() / self.received as f64;
            println!(
                "  {} sent, {} received, {loss:.0}% loss, \
                 rtt min/avg/max {min:.0}/{avg:.0}/{max:.0} ms",
                self.sent, self.received
            );
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

pub(crate) async fn ipc_connect(contact_id: &str, hostname: Option<String>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Connect {
            contact_id: contact_id.to_string(),
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
    }
}

pub(crate) async fn ipc_connections_list() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Connections).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PendingRequests { requests } => print_pending_requests(
            &requests,
            "no pending connection requests",
            "approve with: ray connect approve <name>",
        )?,
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_connections_approve(id: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::ApproveConnection { id: id.to_string() },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
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

pub(crate) async fn ipc_contact(action: Option<ContactAction>) -> Result<()> {
    let req = match action.unwrap_or(ContactAction::Id) {
        ContactAction::Id => ipc::IpcMessage::ContactId,
        ContactAction::Rotate => ipc::IpcMessage::RotateContact,
    };
    let rotating = matches!(req, ipc::IpcMessage::RotateContact);
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, req).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::ContactIdResponse { contact_id } => {
            printout(&ContactIdOutput {
                contact_id,
                rotating,
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
                sent,
                received,
                rtts_ms: probes,
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
