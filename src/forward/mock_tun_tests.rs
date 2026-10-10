//! Tier 1 data-path tests: inject IP packets into the production TUN read loop
//! and observe real local QUIC datagrams or writes to an in-memory TUN. Minimal
//! endpoints have no relay or discovery service; no OS TUN or root is needed.
//! Run with `cargo -q test -p rayfish --lib forward::mock_tun_tests`.

use super::*;
use crate::config::QuicEngine;
use crate::firewall::{Action, FirewallConfig, FirewallRule, PeerFilter, Protocol, RuleOrigin};
use crate::membership::derive_ipv6;
use crate::tun::{TUN_MTU, TunRead, TunWrite};
use iroh::Endpoint;
use iroh::endpoint::{QuicTransportConfig, presets};
use smol_str::SmolStr;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(5);
const ENGINES: [QuicEngine; 2] = [QuicEngine::Standalone, QuicEngine::FqCodel];

enum Input {
    Packet(Bytes),
    Processed(oneshot::Sender<()>),
}

struct FakeTunReader(mpsc::Receiver<Input>);

impl TunRead for FakeTunReader {
    async fn read_packet(&mut self) -> Result<Bytes> {
        loop {
            match self.0.recv().await {
                Some(Input::Packet(packet)) => return Ok(packet),
                // The loop asks for its next packet only after processing the
                // preceding one. This acknowledges admission/drop decisions,
                // not asynchronous QUIC delivery, without a timing assertion.
                Some(Input::Processed(done)) => done.send(()).expect("waiting test"),
                None => anyhow::bail!("mock TUN input closed"),
            }
        }
    }
}

struct FakeTunWriter(mpsc::Sender<Bytes>);

impl TunWrite for FakeTunWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.0.send(Bytes::copy_from_slice(packet)).await?;
        Ok(())
    }
}

struct Peer {
    endpoint: Endpoint,
    local_conn: Connection,
    remote_conn: Connection,
    ipv6: Ipv6Addr,
}

struct Harness {
    endpoint: Endpoint,
    local_ipv6: Ipv6Addr,
    peers: Vec<Peer>,
    table: PeerTable,
    firewall: SharedFirewall,
    stats: Arc<ForwardMetrics>,
    input: Option<mpsc::Sender<Input>>,
    output: mpsc::Receiver<Bytes>,
    tun_tx: mpsc::Sender<Bytes>,
    token: CancellationToken,
    forwarder: Option<JoinHandle<Result<()>>>,
    readers: Vec<JoinHandle<()>>,
    writer: JoinHandle<()>,
}

impl Harness {
    async fn new(engine: QuicEngine, peer_count: usize, config: FirewallConfig) -> Self {
        let endpoint = test_endpoint(engine).await;
        let local_ipv6 = derive_ipv6(&endpoint.id());
        let table = PeerTable::new().with_engine(engine);
        table.set_local_mtu(TUN_MTU);
        let firewall = SharedFirewall::new(config);
        let stats = Arc::new(ForwardMetrics::default());
        let token = CancellationToken::new();
        let (input, packets) = mpsc::channel(16);
        let (tun_tx, tun_rx) = mpsc::channel(16);
        let (written, output) = mpsc::channel(16);
        let writer = spawn_tun_writer(
            FakeTunWriter(written),
            tun_rx,
            Arc::new(AtomicBool::new(true)),
            Arc::clone(&stats),
        );
        let mut peers = Vec::new();
        let mut readers = Vec::new();
        for _ in 0..peer_count {
            let remote = test_endpoint(engine).await;
            let alpn = crate::transport::mesh_alpn();
            let (local_conn, remote_conn) = timeout(DEADLINE, async {
                tokio::join!(endpoint.connect(remote.addr(), &alpn), async {
                    remote
                        .accept()
                        .await
                        .expect("incoming connection")
                        .await
                        .expect("QUIC handshake")
                })
            })
            .await
            .expect("local QUIC handshake deadline");
            let local_conn = local_conn.expect("connect to local peer");
            let ipv6 = derive_ipv6(&remote.id());
            table.add(ipv6, local_conn.clone(), remote.id(), "mesh");
            table.note_receive_mtu(&remote.id(), &local_conn, TUN_MTU);
            table.add_inbound_handle_by_id(&remote.id(), &local_conn, 1, SmolStr::new("mesh"));
            readers.push(spawn_peer_reader(
                local_conn.clone(),
                remote.id(),
                table.clone(),
                ForwardCtx {
                    firewall: firewall.clone(),
                    tun_tx: Arc::new(arc_swap::ArcSwap::from_pointee(tun_tx.clone())),
                    token: token.clone(),
                    stats: Arc::clone(&stats),
                    device_user_map: DeviceUserMap::new(),
                    exit: ExitContext {
                        my_v6: local_ipv6,
                        ..Default::default()
                    },
                },
            ));
            peers.push(Peer {
                endpoint: remote,
                local_conn,
                remote_conn,
                ipv6,
            });
        }
        let forwarder = tokio::spawn(
            MeshForwarder {
                tun: FakeTunReader(packets),
                local_ipv6,
                peers: table.clone(),
                firewall: firewall.clone(),
                token: token.clone(),
                stats: Arc::clone(&stats),
                resolver: Arc::new(dns::resolver::Resolver::new(
                    dns::HostnameTable::default(),
                    dns::ReverseLookupTable::default(),
                )),
                tun_tx: tun_tx.clone(),
                dialer: None,
            }
            .run(),
        );
        Self {
            endpoint,
            local_ipv6,
            peers,
            table,
            firewall,
            stats,
            input: Some(input),
            output,
            tun_tx,
            token,
            forwarder: Some(forwarder),
            readers,
            writer,
        }
    }

    async fn inject(&self, packet: Bytes) {
        let input = self.input.as_ref().expect("open mock TUN");
        input
            .send(Input::Packet(packet))
            .await
            .expect("inject packet");
        let (done, processed) = oneshot::channel();
        input
            .send(Input::Processed(done))
            .await
            .expect("queue processing acknowledgement");
        timeout(DEADLINE, processed)
            .await
            .expect("forwarder processes packet")
            .expect("processing acknowledgement");
    }

    async fn receive_peer(&self, index: usize, expected: &Bytes) -> usize {
        timeout(DEADLINE, async {
            let mut reassembly = fragment::Reassembler::default();
            let mut frames = 0;
            loop {
                let wire = self.peers[index]
                    .remote_conn
                    .read_datagram()
                    .await
                    .expect("peer datagram");
                assert_eq!(untag_datagram(&wire).expect("tagged packet").0, 1);
                frames += 1;
                if let Some(packet) = reassembly
                    .accept(wire, tokio::time::Instant::now())
                    .expect("valid mesh framing")
                {
                    assert_eq!(
                        &packet, expected,
                        "packet reaches its intended peer unchanged"
                    );
                    return frames;
                }
            }
        })
        .await
        .expect("packet reaches peer")
    }

    fn inject_peer(&self, index: usize, packet: &Bytes) {
        self.peers[index]
            .remote_conn
            .send_datagram(tag_datagram(1, packet))
            .expect("inject peer packet");
    }

    async fn receive_tun(&mut self) -> Bytes {
        timeout(DEADLINE, self.output.recv())
            .await
            .expect("packet reaches TUN writer")
            .expect("open mock writer")
    }

    async fn dropped(&self, reason: DropReason, count: u64) {
        timeout(DEADLINE, async {
            while self.stats.drop_count(reason) < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer reader records drop");
        assert_eq!(self.stats.drop_count(reason), count);
    }

    async fn shutdown(mut self) {
        self.token.cancel();
        if let Some(task) = self.forwarder.take() {
            timeout(DEADLINE, task)
                .await
                .expect("forwarder stops")
                .expect("forwarder task")
                .expect("clean cancellation");
        }
        for reader in self.readers {
            timeout(DEADLINE, reader)
                .await
                .expect("peer reader stops")
                .expect("peer reader task");
        }
        drop(self.tun_tx);
        timeout(DEADLINE, self.writer)
            .await
            .expect("TUN writer drains and stops")
            .expect("TUN writer task");
        for peer in self.peers {
            peer.endpoint.close().await;
        }
        self.endpoint.close().await;
    }
}

async fn test_endpoint(engine: QuicEngine) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .alpns(vec![crate::transport::mesh_alpn()])
        .transport_config(
            QuicTransportConfig::builder()
                .initial_mtu(1200)
                .mtu_discovery_config(None)
                .datagram_send_buffer_size(crate::transport::datagram_send_buffer_size(engine))
                .build(),
        )
        .bind()
        .await
        .expect("bind local peer")
}

fn policy(outbound: Action, rules: Vec<FirewallRule>) -> FirewallConfig {
    FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: outbound,
        rules,
        ..Default::default()
    }
}

fn rule(
    direction: Direction,
    action: Action,
    port: u16,
    peer: PeerFilter,
    network: Option<&str>,
) -> FirewallRule {
    FirewallRule {
        direction,
        action,
        protocol: Protocol::Tcp,
        port: Some(firewall::PortRange {
            start: port,
            end: port,
        }),
        peer,
        network: network.map(str::to_owned),
        origin: RuleOrigin::Local,
    }
}

fn packet(
    proto: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    len: usize,
) -> Bytes {
    let header = if proto == 6 { 20 } else { 8 };
    assert!(len >= 40 + header);
    let mut packet = vec![0xa5; len];
    packet[..40 + header].fill(0);
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    packet[6] = proto;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet[40..42].copy_from_slice(&src_port.to_be_bytes());
    packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
    let checksum_offset = if proto == 6 {
        packet[52] = 0x50;
        packet[53] = flags;
        packet[54..56].copy_from_slice(&4096u16.to_be_bytes());
        56
    } else {
        packet[44..46].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        46
    };
    let mut sum = (len - 40) as u32 + u32::from(proto);
    for bytes in packet[8..40].chunks(2).chain(packet[40..].chunks(2)) {
        sum += u32::from(u16::from_be_bytes([bytes[0], *bytes.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    packet[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
    Bytes::from(packet)
}

#[tokio::test]
async fn outbound_loop_routes_each_destination_and_counts_unknown_peers() {
    for engine in ENGINES {
        let h = Harness::new(engine, 2, policy(Action::Allow, vec![])).await;
        let unknown = derive_ipv6(&iroh::SecretKey::from([255; 32]).public());
        assert!(h.table.lookup_v6(&unknown).is_none());
        h.inject(packet(6, h.local_ipv6, unknown, 50000, 443, 2, 60))
            .await;
        assert_eq!(h.stats.drop_count(DropReason::NoPeer), 1);
        for index in [1, 0] {
            let packet = packet(6, h.local_ipv6, h.peers[index].ipv6, 50000, 443, 2, 60);
            h.inject(packet.clone()).await;
            h.receive_peer(index, &packet).await;
        }
        assert_eq!(h.stats.packets_tx.get(), 2);
        assert_eq!(h.stats.bytes_tx.get(), 120);
        assert_eq!(h.stats.total_drops(), 1);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn outbound_deny_blocks_the_matching_port_and_keeps_other_traffic() {
    for engine in ENGINES {
        let rules = vec![rule(
            Direction::Out,
            Action::Deny,
            443,
            PeerFilter::Any,
            None,
        )];
        let mut h = Harness::new(engine, 1, policy(Action::Allow, rules)).await;
        h.inject(packet(6, h.local_ipv6, h.peers[0].ipv6, 50000, 443, 2, 60))
            .await;
        assert_eq!(h.stats.drop_count(DropReason::Firewall), 1);
        assert_eq!(h.stats.packets_tx.get(), 0);
        // A refused outbound SYN must not open a return-traffic allowance.
        let reply = packet(6, h.peers[0].ipv6, h.local_ipv6, 443, 50000, 0x12, 60);
        h.inject_peer(0, &reply);
        h.dropped(DropReason::Firewall, 2).await;
        assert_eq!(h.stats.packets_rx.get(), 0);
        assert!(h.output.try_recv().is_err());
        let allowed = packet(6, h.local_ipv6, h.peers[0].ipv6, 50000, 8443, 2, 60);
        h.inject(allowed.clone()).await;
        h.receive_peer(0, &allowed).await;
        assert_eq!(h.stats.packets_tx.get(), 1);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn outbound_whitelist_checks_both_peer_identity_and_port() {
    for engine in ENGINES {
        let h = Harness::new(engine, 2, policy(Action::Deny, vec![])).await;
        h.firewall.update(policy(
            Action::Deny,
            vec![rule(
                Direction::Out,
                Action::Allow,
                443,
                PeerFilter::Identity(h.peers[0].endpoint.id()),
                None,
            )],
        ));
        h.inject(packet(6, h.local_ipv6, h.peers[1].ipv6, 50000, 443, 2, 60))
            .await;
        h.inject(packet(6, h.local_ipv6, h.peers[0].ipv6, 50000, 8443, 2, 60))
            .await;
        assert_eq!(h.stats.drop_count(DropReason::Firewall), 2);
        assert_eq!(h.stats.packets_tx.get(), 0);
        let allowed = packet(6, h.local_ipv6, h.peers[0].ipv6, 50000, 443, 2, 60);
        h.inject(allowed.clone()).await;
        h.receive_peer(0, &allowed).await;
        assert_eq!(h.stats.packets_tx.get(), 1);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn scoped_rules_follow_live_shared_membership_across_transport_handles() {
    for engine in ENGINES {
        let allow = rule(
            Direction::Out,
            Action::Allow,
            443,
            PeerFilter::Any,
            Some("z-policy"),
        );
        let h = Harness::new(engine, 1, policy(Action::Deny, vec![allow])).await;
        let peer = &h.peers[0];
        let packet = packet(6, h.local_ipv6, peer.ipv6, 50000, 443, 2, 60);
        h.inject(packet.clone()).await;
        assert_eq!(h.stats.drop_count(DropReason::Firewall), 1);
        h.table.add(
            peer.ipv6,
            peer.local_conn.clone(),
            peer.endpoint.id(),
            "z-policy",
        );
        assert_eq!(h.table.lookup_v6(&peer.ipv6).unwrap().network, "mesh");
        h.inject(packet.clone()).await;
        h.receive_peer(0, &packet).await;
        h.table.remove_peer_from_network(&peer.ipv6, "z-policy");
        h.inject(packet.clone()).await;
        assert_eq!(h.stats.drop_count(DropReason::Firewall), 2);
        assert_eq!(h.stats.packets_tx.get(), 1);

        h.firewall.update(policy(
            Action::Allow,
            vec![rule(
                Direction::Out,
                Action::Deny,
                443,
                PeerFilter::Any,
                Some("z-policy"),
            )],
        ));
        h.table.add(
            peer.ipv6,
            peer.local_conn.clone(),
            peer.endpoint.id(),
            "z-policy",
        );
        h.inject(packet.clone()).await;
        assert_eq!(h.stats.drop_count(DropReason::Firewall), 3);
        h.table.remove_peer_from_network(&peer.ipv6, "z-policy");
        assert!(h.table.shares_network_v6(&peer.ipv6, "mesh"));
        h.inject(packet.clone()).await;
        h.receive_peer(0, &packet).await;
        assert_eq!(h.stats.packets_tx.get(), 2);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn inbound_whitelist_checks_identity_port_and_live_shared_membership() {
    for engine in ENGINES {
        let mut h = Harness::new(engine, 2, policy(Action::Allow, vec![])).await;
        h.firewall.update(policy(
            Action::Allow,
            vec![rule(
                Direction::In,
                Action::Allow,
                8080,
                PeerFilter::Identity(h.peers[0].endpoint.id()),
                Some("z-policy"),
            )],
        ));
        let allowed = packet(6, h.peers[0].ipv6, h.local_ipv6, 50000, 8080, 2, 60);
        h.inject_peer(0, &allowed);
        h.dropped(DropReason::Firewall, 1).await;
        // Packets arrive under the mesh handle, while the allow rule refers to
        // another shared network. Both peers share it, so only the identity
        // selector distinguishes the whitelisted peer from the other one.
        for peer in &h.peers {
            h.table.add(
                peer.ipv6,
                peer.local_conn.clone(),
                peer.endpoint.id(),
                "z-policy",
            );
        }
        h.inject_peer(0, &allowed);
        assert_eq!(h.receive_tun().await, allowed);
        let other_peer = packet(6, h.peers[1].ipv6, h.local_ipv6, 50000, 8080, 2, 60);
        h.inject_peer(1, &other_peer);
        h.dropped(DropReason::Firewall, 2).await;
        let other_port = packet(6, h.peers[0].ipv6, h.local_ipv6, 50000, 8081, 2, 60);
        h.inject_peer(0, &other_port);
        h.dropped(DropReason::Firewall, 3).await;
        h.table
            .remove_peer_from_network(&h.peers[0].ipv6, "z-policy");
        h.inject_peer(0, &allowed);
        h.dropped(DropReason::Firewall, 4).await;
        assert_eq!(h.stats.packets_rx.get(), 1);
        assert!(h.output.try_recv().is_err());
        h.shutdown().await;
    }
}

#[tokio::test]
async fn outbound_mtu_limits_drop_oversize_and_fragment_valid_packets() {
    for engine in ENGINES {
        let mut h = Harness::new(engine, 1, policy(Action::Allow, vec![])).await;
        let destination = h.peers[0].ipv6;
        let oversize = packet(
            6,
            h.local_ipv6,
            destination,
            50000,
            443,
            2,
            usize::from(TUN_MTU) + 1,
        );
        h.inject(oversize).await;
        let ptb = h.receive_tun().await;
        assert_eq!(ptb[6], 58);
        assert_eq!(ptb[40], 2);
        assert_eq!(&ptb[44..48], &u32::from(TUN_MTU).to_be_bytes());
        assert_eq!(&ptb[24..40], &h.local_ipv6.octets());
        assert_eq!(h.stats.drop_count(DropReason::PacketTooBig), 1);
        assert_eq!(h.stats.packets_tx.get(), 0);

        let full = packet(
            6,
            h.local_ipv6,
            destination,
            50001,
            443,
            2,
            usize::from(TUN_MTU),
        );
        assert!(h.peers[0].local_conn.max_datagram_size().unwrap() < full.len() + TAG_LEN);
        h.inject(full.clone()).await;
        assert!(h.receive_peer(0, &full).await > 1);
        assert_eq!(h.stats.packets_tx.get(), 1);
        assert_eq!(h.stats.bytes_tx.get(), u64::from(TUN_MTU));

        let peer = &h.peers[0];
        h.table.note_receive_mtu(
            &peer.endpoint.id(),
            &peer.local_conn,
            crate::tun::MIN_TUN_MTU,
        );
        h.inject(full).await;
        let ptb = h.receive_tun().await;
        assert_eq!(ptb[40], 2);
        assert_eq!(&ptb[44..48], &1280u32.to_be_bytes());
        assert_eq!(h.stats.drop_count(DropReason::PacketTooBig), 2);
        assert_eq!(h.stats.packets_tx.get(), 1);
        h.shutdown().await;
    }
}

#[tokio::test]
async fn tcp_conntrack_admits_real_replies_but_honors_denies_and_flow_close() {
    for engine in ENGINES {
        for close_flag in [1, 4] {
            // FIN and RST both close a tracked flow.
            let mut h = Harness::new(engine, 1, policy(Action::Allow, vec![])).await;
            let peer = h.peers[0].ipv6;
            let reply = packet(6, peer, h.local_ipv6, 443, 50000, 0x12, 60);
            h.inject_peer(0, &reply);
            h.dropped(DropReason::Firewall, 1).await;
            assert_eq!(h.stats.packets_rx.get(), 0);

            let syn = packet(6, h.local_ipv6, peer, 50000, 443, 2, 60);
            h.inject(syn.clone()).await;
            h.receive_peer(0, &syn).await;
            h.inject_peer(0, &reply);
            assert_eq!(h.receive_tun().await, reply);
            assert_eq!(h.stats.packets_rx.get(), 1);

            h.firewall.update(policy(
                Action::Allow,
                vec![rule(
                    Direction::In,
                    Action::Deny,
                    50000,
                    PeerFilter::Any,
                    None,
                )],
            ));
            h.inject_peer(0, &reply);
            h.dropped(DropReason::Firewall, 2).await;
            assert_eq!(h.stats.packets_rx.get(), 1);

            h.firewall.update(policy(Action::Allow, vec![]));
            let close = packet(6, h.local_ipv6, peer, 50000, 443, close_flag, 60);
            h.inject(close.clone()).await;
            h.receive_peer(0, &close).await;
            h.inject_peer(0, &reply);
            h.dropped(DropReason::Firewall, 3).await;
            assert_eq!(h.stats.packets_rx.get(), 1);
            assert!(h.output.try_recv().is_err());
            h.shutdown().await;
        }
    }
}

#[tokio::test]
async fn udp_conntrack_admits_only_the_requested_return_flow() {
    for engine in ENGINES {
        let mut h = Harness::new(engine, 1, policy(Action::Allow, vec![])).await;
        let peer = h.peers[0].ipv6;
        let reply = packet(17, peer, h.local_ipv6, 5400, 50000, 0, 48);
        h.inject_peer(0, &reply);
        h.dropped(DropReason::Firewall, 1).await;
        let request = packet(17, h.local_ipv6, peer, 50000, 5400, 0, 48);
        h.inject(request.clone()).await;
        h.receive_peer(0, &request).await;
        h.inject_peer(0, &reply);
        assert_eq!(h.receive_tun().await, reply);
        let unsolicited = packet(17, peer, h.local_ipv6, 5400, 50001, 0, 48);
        h.inject_peer(0, &unsolicited);
        h.dropped(DropReason::Firewall, 2).await;
        assert_eq!(h.stats.packets_rx.get(), 1);
        assert!(h.output.try_recv().is_err());
        h.shutdown().await;
    }
}

#[tokio::test]
async fn empty_and_malformed_tun_packets_do_not_prevent_eof_termination() {
    let mut h = Harness::new(QuicEngine::Standalone, 0, policy(Action::Allow, vec![])).await;
    h.inject(Bytes::new()).await;
    assert_eq!(h.stats.total_drops(), 0);
    h.inject(Bytes::from_static(&[0x60])).await;
    assert_eq!(h.stats.drop_count(DropReason::Malformed), 1);
    drop(h.input.take());
    let error = timeout(DEADLINE, h.forwarder.take().unwrap())
        .await
        .expect("closed TUN terminates loop")
        .expect("forwarder task")
        .expect_err("EOF must be an error");
    assert_eq!(error.to_string(), "mock TUN input closed");
    h.shutdown().await;
}
