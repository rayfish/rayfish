use super::*;
use crate::AsyncMutex;
use crate::config::QuicEngine;
use crate::firewall::Action;
use crate::membership::ExitFamilies;
use iroh::SecretKey;
use smol_str::SmolStr;
use std::sync::Mutex;

#[tokio::test]
async fn self_packets_return_to_tun_without_ssh_translation_or_a_peer() {
    use std::time::Duration;
    use tokio::time::timeout;

    struct Reader(mpsc::Receiver<Bytes>);
    impl crate::tun::TunRead for Reader {
        async fn read_packet(&mut self) -> Result<Bytes> {
            self.0
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("test reader closed"))
        }
    }
    let local_ipv6 = "200::1".parse().expect("local mesh address");
    let other = "200::2".parse().expect("other mesh address");
    let packet = Bytes::from(make_tcp_packet_between(local_ipv6, local_ipv6, SSH_PORT));
    let remote = Bytes::from(make_tcp_packet_between(local_ipv6, other, SSH_PORT));
    let (input, reader) = mpsc::channel(4);
    let (tun_tx, mut output) = mpsc::channel(4);
    let token = CancellationToken::new();
    let forwarder = MeshForwarder {
        tun: Reader(reader),
        active: Arc::new(AtomicBool::new(true)),
        local_ipv6,
        peers: PeerTable::default(),
        firewall: SharedFirewall::new(firewall::FirewallConfig::default()),
        token: token.clone(),
        stats: Arc::new(ForwardMetrics::default()),
        resolver: Arc::new(dns::resolver::Resolver::new(
            dns::HostnameTable::default(),
            dns::ReverseLookupTable::default(),
        )),
        tun_tx,
        dialer: None,
    };
    let task = tokio::spawn(forwarder.run());
    input.send(remote).await.expect("send remote packet");
    input.send(packet.clone()).await.expect("send self packet");
    assert_eq!(
        timeout(Duration::from_secs(1), output.recv())
            .await
            .expect("self packet delivered"),
        Some(packet)
    );
    assert!(
        output.try_recv().is_err(),
        "remote packet must not loop back"
    );
    token.cancel();
    task.await
        .expect("forwarder task")
        .expect("forwarder stops cleanly");
}

fn evaluate_inbound(
    packet: &[u8],
    firewall: &SharedFirewall,
    exit: &ExitContext,
    identity: &EndpointId,
    ipv6: Ipv6Addr,
    network: &str,
) -> InboundDecision {
    super::evaluate_inbound(
        packet,
        firewall,
        exit,
        InboundPeer {
            identity,
            ipv6,
            network,
            shares_network: &|name| name == network,
        },
        &mut FragmentVerdicts::default(),
    )
}

#[test]
fn remote_ping_replies_are_not_android_wake_signals() {
    let mut info = firewall::PacketInfo {
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        protocol: 58,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        icmp_type: 129,
        icmp_id: 1,
        transport_offset: 40,
    };
    assert!(firewall::is_icmp_echo_reply(info.protocol, info.icmp_type));
    info.icmp_type = 128;
    assert!(!firewall::is_icmp_echo_reply(info.protocol, info.icmp_type));
    info.protocol = 1;
    info.icmp_type = 0;
    assert!(firewall::is_icmp_echo_reply(info.protocol, info.icmp_type));
    info.icmp_type = 8;
    assert!(!firewall::is_icmp_echo_reply(info.protocol, info.icmp_type));
}

#[test]
fn write_failures_log_once_per_interval_with_a_count() {
    let start = Instant::now();
    let mut budget = LogBudget::new(Duration::from_secs(10));
    assert_eq!(budget.allow(start), Some(0));
    for i in 1..=5 {
        assert_eq!(budget.allow(start + Duration::from_secs(i)), None);
    }
    assert_eq!(budget.allow(start + Duration::from_secs(10)), Some(5));
    assert_eq!(budget.allow(start + Duration::from_secs(11)), None);
}

fn test_peer(seed: u8) -> EndpointId {
    SecretKey::from([seed; 32]).public()
}

#[tokio::test]
async fn fragmented_tcp_crosses_small_quic_path_and_keeps_policy_checks() {
    check_fragmented_tcp(1280, QuicEngine::Standalone).await;
}

#[tokio::test]
async fn full_tun_mtu_crosses_small_quic_path_and_keeps_policy_checks() {
    check_fragmented_tcp(crate::tun::TUN_MTU as usize, QuicEngine::Standalone).await;
}

#[tokio::test]
async fn fq_codel_preserves_fragmentation_firewall_and_lazy_dial_flush() {
    check_fragmented_tcp(crate::tun::TUN_MTU as usize, QuicEngine::FqCodel).await;
}

#[tokio::test]
async fn v5_connection_sends_only_whole_packets() {
    use iroh::endpoint::{QuicTransportConfig, presets};
    use iroh::{Endpoint, RelayMode};
    use std::time::Duration;
    use tokio::time::timeout;

    async fn endpoint() -> Endpoint {
        Endpoint::builder(presets::N0)
            .alpns(vec![crate::transport::MESH_V5_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .transport_config(
                QuicTransportConfig::builder()
                    .initial_mtu(1200)
                    .mtu_discovery_config(None)
                    .build(),
            )
            .bind()
            .await
            .unwrap()
    }
    let a = endpoint().await;
    let b = endpoint().await;
    let (send, recv) = timeout(Duration::from_secs(5), async {
        tokio::join!(a.connect(b.addr(), crate::transport::MESH_V5_ALPN), async {
            b.accept().await.unwrap().await.unwrap()
        })
    })
    .await
    .unwrap();
    let send = send.unwrap();
    assert!(send.max_datagram_size().unwrap() < 1282);
    let a_ip = crate::membership::derive_ipv6(&a.id());
    let b_ip = crate::membership::derive_ipv6(&b.id());
    let peers = PeerTable::new();
    peers.add(b_ip, send.clone(), b.id(), "test");
    peers.note_receive_mtu(&b.id(), &send, crate::tun::TUN_MTU);
    let route = peers.lookup_v6(&b_ip).unwrap();
    let (feedback_tx, mut feedback_rx) = mpsc::channel(4);
    let fw = inbound_fw(Action::Allow, vec![]);
    let stats = Arc::new(ForwardMetrics::default());
    let ctx = SendCtx {
        active: &Arc::new(AtomicBool::new(true)),
        firewall: &fw,
        peers: &peers,
        stats: &stats,
        tun_tx: &feedback_tx,
    };
    let small = Bytes::from(make_tcp_packet_between(a_ip, b_ip, 22));
    let info = firewall::parse_packet_info(&small).unwrap();
    send_over_route(&ctx, &route, &info, small.clone()).await;
    let wire = timeout(Duration::from_secs(5), recv.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wire, tag_datagram(1, &small));

    let mut large = small.to_vec();
    large.resize(1280, 0);
    large[4..6].copy_from_slice(&1240u16.to_be_bytes());
    let info = firewall::parse_packet_info(&large).unwrap();
    send_over_route(&ctx, &route, &info, Bytes::from(large)).await;
    let reply = feedback_rx.try_recv().expect("v5 sends a local PTB");
    assert_eq!(reply[40], 2);
    assert_eq!(
        &reply[44..48],
        &((send.max_datagram_size().unwrap() - TAG_LEN) as u32).to_be_bytes()
    );
    a.close().await;
    b.close().await;
}

/// Exercise the production sender, lazy-dial batch flush and receiver over
/// real QUIC, with discovery disabled so full IP packets need fragmentation
/// even on loopback.
async fn check_fragmented_tcp(packet_len: usize, cc: QuicEngine) {
    use iroh::endpoint::{QuicTransportConfig, presets};
    use iroh::{Endpoint, RelayMode};
    use std::time::{Duration, Instant};
    use tokio::time::timeout;

    async fn endpoint(cc: QuicEngine) -> Endpoint {
        Endpoint::builder(presets::N0)
            .alpns(vec![crate::transport::mesh_alpn()])
            .relay_mode(RelayMode::Disabled)
            .transport_config(
                QuicTransportConfig::builder()
                    .initial_mtu(1200)
                    .datagram_send_buffer_size(crate::transport::datagram_send_buffer_size(cc))
                    .mtu_discovery_config(None)
                    .build(),
            )
            .bind()
            .await
            .unwrap()
    }
    let a = endpoint(cc).await;
    let b = endpoint(cc).await;
    let connect = async {
        let alpn = crate::transport::mesh_alpn();
        let (send, recv) = tokio::join!(a.connect(b.addr(), &alpn), async {
            b.accept().await.unwrap().await.unwrap()
        },);
        (send.unwrap(), recv)
    };
    let (send, recv) = timeout(Duration::from_secs(5), connect).await.unwrap();
    assert!(send.max_datagram_size().unwrap() < 1282);
    let a_ip = crate::membership::derive_ipv6(&a.id());
    let b_ip = crate::membership::derive_ipv6(&b.id());
    let sender_peers = PeerTable::new().with_engine(cc);
    sender_peers.add(b_ip, send.clone(), b.id(), "test");
    sender_peers.note_receive_mtu(&b.id(), &send, crate::tun::TUN_MTU);
    let receiver_peers = PeerTable::new();
    receiver_peers.set_local_mtu(crate::tun::TUN_MTU);
    receiver_peers.add(a_ip, recv.clone(), a.id(), "test");
    receiver_peers.add_inbound_handle_by_id(&a.id(), &recv, 1, SmolStr::new("test"));

    let (tun_tx, mut tun_rx) = mpsc::channel(16);
    let (feedback_tx, mut feedback_rx) = mpsc::channel(16);
    let stats = Arc::new(ForwardMetrics::default());
    let send_stats = Arc::new(ForwardMetrics::default());
    receiver_peers.add(a_ip, recv.clone(), a.id(), "z-allowed");
    sender_peers.add(b_ip, send.clone(), b.id(), "z-allowed");
    let rule = firewall::FirewallRule {
        direction: Direction::In,
        action: Action::Allow,
        protocol: firewall::Protocol::Any,
        port: None,
        peer: firewall::PeerFilter::Identity(a.id()),
        network: Some("z-allowed".to_string()),
        origin: firewall::RuleOrigin::Local,
    };
    let firewall = inbound_fw(Action::Deny, vec![rule.clone()]);
    let token = CancellationToken::new();
    let reader = spawn_peer_reader(
        recv.clone(),
        a.id(),
        receiver_peers.clone(),
        ForwardCtx {
            firewall: firewall.clone(),
            tun_tx: Arc::new(arc_swap::ArcSwap::from_pointee(tun_tx)),
            token: token.clone(),
            stats: Arc::clone(&stats),
            device_user_map: DeviceUserMap::new(),
            exit: no_exit(),
        },
    );
    let sender_fw = SharedFirewall::new(firewall::FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Deny,
        rules: vec![firewall::FirewallRule {
            direction: Direction::Out,
            peer: firewall::PeerFilter::Identity(b.id()),
            ..rule
        }],
        ..Default::default()
    });
    let ctx = SendCtx {
        active: &Arc::new(AtomicBool::new(true)),
        firewall: &sender_fw,
        peers: &sender_peers,
        stats: &send_stats,
        tun_tx: &feedback_tx,
    };
    let route = sender_peers.lookup_v6(&b_ip).unwrap();
    assert_eq!(
        route.network, "test",
        "transport uses a different network than the rule"
    );
    let mut packet = make_tcp_packet_between(a_ip, b_ip, 22);
    packet.resize(packet_len, 0x5a);
    packet[4..6].copy_from_slice(&((packet_len - 40) as u16).to_be_bytes());
    packet[52] = 0x50; // TCP data offset
    packet[53] = 0x18; // PSH + ACK
    let checksum = tcp_csum_v6(&packet);
    packet[56..58].copy_from_slice(&checksum.to_be_bytes());
    let packet = Bytes::from(packet);
    let info = firewall::parse_packet_info(&packet).unwrap();
    send_over_route(&ctx, &route, &info, packet.clone()).await;
    assert_eq!(
        timeout(Duration::from_secs(5), tun_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        packet
    );
    assert!(
        feedback_rx.try_recv().is_err(),
        "no sub-1280 PTB is injected"
    );

    // The on-demand backlog mixes small and fragmented packets. Counters must
    // still count IP packets, not individual fragments.
    let small = Bytes::from(make_tcp_packet_between(a_ip, b_ip, 22));
    flush_or_drop(
        &ctx,
        &ExitClient::default(),
        true,
        VecDeque::from([small.clone(), packet.clone(), small.clone()]),
    )
    .await;
    for expected in [&small, &packet, &small] {
        assert_eq!(
            &timeout(Duration::from_secs(5), tun_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            expected
        );
    }
    let sent = send_stats.snapshot(Instant::now());
    let received = stats.snapshot(Instant::now());
    assert_eq!(sent.packets_tx, 4);
    assert_eq!(received.packets_rx, 4);
    assert_eq!(sent.bytes_tx, (packet.len() * 2 + small.len() * 2) as u64);
    assert_eq!(received.bytes_rx, sent.bytes_tx);

    // A cached route must not keep an allow rule effective after membership
    // ends. The transport network still exists at both ends.
    sender_peers.remove_peer_from_network(&b_ip, "z-allowed");
    assert!(
        prepare_datagrams(&ctx, &route, &info, packet.clone(), Admission::Firewall)
            .await
            .is_none()
    );
    let reset = crate::reject::build_reject(&packet, &info).expect("denied SSH has a reset");
    assert_eq!(feedback_rx.try_recv().expect("local SSH reset"), reset);
    sender_peers.add(b_ip, send.clone(), b.id(), "z-allowed");
    receiver_peers.remove_peer_from_network(&a_ip, "z-allowed");
    send_over_route(&ctx, &route, &info, packet.clone()).await;
    timeout(Duration::from_secs(5), async {
        while stats.drop_count(DropReason::Firewall) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(tun_rx.try_recv().is_err());
    let wire = timeout(Duration::from_secs(5), send.read_datagram())
        .await
        .expect("remote SSH reset arrives")
        .expect("read remote SSH reset");
    assert_eq!(untag_datagram(&wire).expect("tagged SSH reset").1, reset);
    receiver_peers.add(a_ip, recv.clone(), a.id(), "z-allowed");

    if packet_len > usize::from(crate::tun::MIN_TUN_MTU) {
        // A smaller receive limit takes effect even on an already-cached
        // route. Feedback reaches the local host without sending the packet.
        sender_peers.note_receive_mtu(&b.id(), &send, crate::tun::MIN_TUN_MTU);
        send_over_route(&ctx, &route, &info, packet.clone()).await;
        let reply = feedback_rx
            .try_recv()
            .expect("local PTB for a smaller peer");
        assert_eq!(reply[40], 2); // ICMPv6 Packet Too Big
        assert_eq!(&reply[44..48], &1280u32.to_be_bytes());
        assert!(tun_rx.try_recv().is_err());

        // Simulate a TUN reattach while old 1500-byte packets are still in
        // flight. The receiver must return a tagged, fragmented PTB rather
        // than inject an oversized packet into the smaller TUN.
        receiver_peers.set_local_mtu(crate::tun::MIN_TUN_MTU);
        let encoded = fragment::encode(1, &packet, send.max_datagram_size().unwrap()).unwrap();
        send.send_many_datagrams(encoded.datagrams()).unwrap();
        let reply = timeout(Duration::from_secs(5), async {
            let mut reassembly = fragment::Reassembler::default();
            loop {
                let wire = send.read_datagram().await.unwrap();
                assert_eq!(untag_datagram(&wire).unwrap().0, 1);
                if let Some(reply) = reassembly
                    .accept(wire, tokio::time::Instant::now())
                    .unwrap()
                {
                    break reply;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(reply[40], 2);
        assert_eq!(&reply[44..48], &1280u32.to_be_bytes());
        assert!(tun_rx.try_recv().is_err());

        // The sender can still deliver a packet at the fallback MTU.
        let mut smaller = packet[..1280].to_vec();
        smaller[4..6].copy_from_slice(&1240u16.to_be_bytes());
        smaller[56..58].fill(0);
        let checksum = tcp_csum_v6(&smaller);
        smaller[56..58].copy_from_slice(&checksum.to_be_bytes());
        let smaller = Bytes::from(smaller);
        let info = firewall::parse_packet_info(&smaller).unwrap();
        send_over_route(&ctx, &route, &info, smaller.clone()).await;
        assert_eq!(
            timeout(Duration::from_secs(5), tun_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            smaller
        );
    }

    // Reassembled packets still face source validation and the firewall.
    let mut spoofed = packet.to_vec();
    spoofed[8..24].copy_from_slice(&OTHER_V6.octets());
    let spoofed = fragment::encode(1, &spoofed, send.max_datagram_size().unwrap()).unwrap();
    send.send_many_datagrams(spoofed.datagrams()).unwrap();
    firewall.update(firewall::FirewallConfig {
        default_inbound: Action::Deny,
        default_outbound: Action::Allow,
        ..Default::default()
    });
    // Use a new source port to avoid the earlier flow's conntrack allowance.
    let mut denied = packet.to_vec();
    denied[40..42].copy_from_slice(&54321u16.to_be_bytes());
    let denied = fragment::encode(1, &denied, send.max_datagram_size().unwrap()).unwrap();
    send.send_many_datagrams(denied.datagrams()).unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = stats.snapshot(Instant::now());
            let count = |name| snapshot.drops.iter().find(|(n, _)| n == name).unwrap().1;
            if count("Spoof") >= 1 && count("Firewall") >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(tun_rx.try_recv().is_err());

    token.cancel();
    reader.await.unwrap();
    a.close().await;
    b.close().await;
}

#[test]
fn lazy_dial_buffer_keeps_oldest_packets_and_releases_budget() {
    let peer = test_peer(1);
    let mut buffers = LazyDialBuffers::default();
    assert!(buffers.push(peer, Bytes::from_static(b"first")));
    assert!(buffers.push(peer, Bytes::from_static(b"second")));

    let packets = buffers.take(&peer);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], Bytes::from_static(b"first"));
    assert_eq!(packets[1], Bytes::from_static(b"second"));
    assert_eq!(buffers.packets, 0);
    assert_eq!(buffers.bytes, 0);
    assert!(buffers.by_peer.is_empty());
}

#[test]
fn lazy_dial_buffer_caps_each_peer_and_drops_newest() {
    let peer = test_peer(2);
    let mut buffers = LazyDialBuffers::default();
    for n in 0..LAZY_DIAL_MAX_PACKETS_PER_PEER {
        assert!(buffers.push(peer, Bytes::from(vec![n as u8])));
    }
    assert!(!buffers.push(peer, Bytes::from_static(b"newest")));

    let packets = buffers.take(&peer);
    assert_eq!(packets.len(), LAZY_DIAL_MAX_PACKETS_PER_PEER);
    assert_eq!(packets.front().unwrap().as_ref(), &[0]);
    assert_eq!(
        packets.back().unwrap().as_ref(),
        &[(LAZY_DIAL_MAX_PACKETS_PER_PEER - 1) as u8]
    );
}

#[test]
fn lazy_dial_buffer_caps_total_retention_across_peers() {
    let mut buffers = LazyDialBuffers::default();
    for n in 0..LAZY_DIAL_MAX_PACKETS_TOTAL {
        assert!(buffers.push(test_peer((n % 8) as u8 + 3), Bytes::from_static(b"x")));
    }
    assert!(!buffers.push(test_peer(42), Bytes::from_static(b"x")));
}

#[test]
fn only_a_deliberate_leave_prunes_the_member() {
    // A `ray leave` (LEAVE_CODE) is the only close a coordinator acts on by
    // pruning the member from the signed roster.
    assert!(CloseReason::Left.prunes_member());
    // A kick (the peer removed *us* from its view) must never evict the
    // closer: that is what let a flapping link's mutual prune desync the mesh.
    assert!(!CloseReason::Kicked.prunes_member());
    // A transient drop keeps the member (offline peers stay in the roster).
    assert!(!CloseReason::Transient.prunes_member());
}

#[derive(Default)]
struct FakeTunWriter {
    written: Arc<AsyncMutex<Vec<Vec<u8>>>>,
}

impl crate::tun::TunWrite for FakeTunWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        self.written.lock().await.push(packet.to_vec());
        Ok(())
    }
}

#[tokio::test]
async fn tun_writer_writes_when_active() {
    use std::sync::atomic::AtomicBool;
    let writer = FakeTunWriter::default();
    let sink = Arc::clone(&writer.written);
    let (tx, rx) = mpsc::channel::<Bytes>(8);
    let active = std::sync::Arc::new(AtomicBool::new(true));
    let handle = spawn_tun_writer(writer, rx, active, Arc::new(ForwardMetrics::default()));
    tx.send(Bytes::from_static(b"kept")).await.unwrap();
    drop(tx); // close channel so the writer task exits
    handle.await.unwrap();
    let got = sink.lock().await;
    assert_eq!(got.as_slice(), &[b"kept".to_vec()]);
}

#[tokio::test]
async fn tun_writer_counts_packets_larger_than_the_mtu() {
    use std::sync::atomic::AtomicBool;
    let writer = FakeTunWriter::default();
    let sink = Arc::clone(&writer.written);
    let (tx, rx) = mpsc::channel::<Bytes>(8);
    let active = std::sync::Arc::new(AtomicBool::new(true));
    let stats = Arc::new(ForwardMetrics::default());
    let handle = spawn_tun_writer(writer, rx, active, Arc::clone(&stats));
    let oversize = vec![0u8; usize::from(crate::tun::TUN_MTU) + 1];
    tx.send(Bytes::from(oversize)).await.unwrap();
    tx.send(Bytes::from_static(b"kept")).await.unwrap();
    drop(tx);
    handle.await.unwrap();
    assert_eq!(sink.lock().await.as_slice(), &[b"kept".to_vec()]);
    assert_eq!(stats.drop_count(DropReason::PacketTooBig), 1);
}

#[tokio::test]
async fn tun_writer_drops_when_inactive() {
    use std::sync::atomic::AtomicBool;
    let writer = FakeTunWriter::default();
    let sink = Arc::clone(&writer.written);
    let (tx, rx) = mpsc::channel::<Bytes>(8);
    let active = std::sync::Arc::new(AtomicBool::new(false));
    let handle = spawn_tun_writer(writer, rx, active, Arc::new(ForwardMetrics::default()));
    tx.send(Bytes::from_static(b"dropped")).await.unwrap();
    drop(tx);
    handle.await.unwrap();
    assert!(sink.lock().await.is_empty());
}

struct BatchingTunWriter {
    batches: Arc<AsyncMutex<Vec<Vec<Vec<u8>>>>>,
}

impl crate::tun::TunWrite for BatchingTunWriter {
    async fn write_packet(&mut self, _packet: &[u8]) -> anyhow::Result<()> {
        unreachable!("batch-capable writer must receive write_packets")
    }

    fn write_batch_size(&self) -> usize {
        8
    }

    async fn write_packets(&mut self, packets: &[Bytes]) -> anyhow::Result<()> {
        self.batches
            .lock()
            .await
            .push(packets.iter().map(|packet| packet.to_vec()).collect());
        Ok(())
    }
}

#[tokio::test]
async fn tun_writer_drains_ready_packets_into_one_batch() {
    use std::sync::atomic::AtomicBool;
    let batches = Arc::new(AsyncMutex::new(Vec::new()));
    let writer = BatchingTunWriter {
        batches: Arc::clone(&batches),
    };
    let (tx, rx) = mpsc::channel::<Bytes>(8);
    tx.send(Bytes::from_static(b"one")).await.unwrap();
    tx.send(Bytes::from_static(b"two")).await.unwrap();
    tx.send(Bytes::from_static(b"three")).await.unwrap();
    drop(tx);

    let stats = Arc::new(ForwardMetrics::default());
    spawn_tun_writer(
        writer,
        rx,
        Arc::new(AtomicBool::new(true)),
        Arc::clone(&stats),
    )
    .await
    .unwrap();

    assert_eq!(
        batches.lock().await.as_slice(),
        &[vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]]
    );
    assert_eq!(stats.tun_write_batches.get(), 1);
    assert_eq!(stats.tun_write_packets.get(), 3);
    assert_eq!(stats.tun_write_batch_limit.get(), 8);
}

#[test]
fn test_parse_packet_valid_ipv4() {
    let mut packet = vec![0u8; 24];
    packet[0] = 0x45;
    packet[9] = 6; // TCP
    packet[16] = 100;
    packet[17] = 64;
    packet[18] = 0;
    packet[19] = 3;
    let info = firewall::parse_packet_info(&packet).unwrap();
    assert_eq!(
        info.dst_ip,
        IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 3))
    );
    assert_eq!(info.protocol, 6);
}

#[test]
fn test_parse_packet_too_short() {
    assert!(firewall::parse_packet_info(&[0x45; 10]).is_none());
}

#[test]
fn test_parse_packet_ipv6() {
    // 44 bytes: enough for the fixed header plus the TCP ports. A packet that
    // names TCP and carries no TCP header has no ports to key on and is
    // refused (`firewall::parse_ipv6`).
    let mut packet = vec![0u8; 44];
    packet[0] = 0x60; // IPv6
    packet[6] = 6; // TCP next header
    // dst at bytes 24-39
    packet[24] = 0x02;
    packet[25] = 0x01;
    let info = firewall::parse_packet_info(&packet).unwrap();
    assert!(info.dst_ip.is_ipv6());
}

/// Mesh address the test packets are sourced from; passed to
/// `evaluate_inbound` as the sending peer's assigned IP so the ingress
/// anti-spoof check passes.
const TEST_V6: Ipv6Addr = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 5);
/// Another mesh address, standing in for a peer other than the sender.
const OTHER_V6: Ipv6Addr = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 3);

/// An IPv6/TCP packet from `src` to `dst`, enough for
/// `firewall::parse_packet_info` and the anti-spoof check.
fn make_tcp_packet_between(src: Ipv6Addr, dst: Ipv6Addr, dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 44];
    p[0] = 0x60; // IPv6
    p[5] = 4; // payload length: the truncated TCP header below
    p[6] = 6; // next header = TCP
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p[40] = 0;
    p[41] = 80; // src port 80
    p[42] = (dst_port >> 8) as u8;
    p[43] = dst_port as u8;
    p
}

/// The common case: from TEST_V6 to another mesh address.
fn make_tcp_packet(dst_port: u16) -> Vec<u8> {
    make_tcp_packet_between(TEST_V6, OTHER_V6, dst_port)
}

/// An IPv4 TCP packet. Nothing on the mesh produces one any more, which is
/// the reason to build one by hand: the rules that reject it have to be
/// exercised by something.
fn make_tcp_packet_v4(src: [u8; 4], dst: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut p = vec![0u8; 24];
    p[0] = 0x45; // IPv4, 5-word header
    p[2] = 0;
    p[3] = 24; // total length
    p[8] = 64; // TTL
    p[9] = 6; // protocol = TCP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[20] = 0;
    p[21] = 80; // src port 80
    p[22] = (dst_port >> 8) as u8;
    p[23] = dst_port as u8;
    p
}

/// This node's mesh address in the `evaluate_inbound` tests. Distinct from the
/// peer/packet addresses; only consulted by the exit return-traffic path.
const MY_V6: Ipv6Addr = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1);
/// A routable public IPv6 host, standing in for whatever an exit tunnel
/// reached on our behalf. Must be `is_transitable` for the return-path
/// exemption to fire.
const PUBLIC_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

/// Exit state for the firewall/anti-spoof tests: no exit offered and none
/// selected, so neither exit path fires (their destinations are overlay IPs).
fn no_exit() -> ExitContext {
    ExitContext {
        my_v6: MY_V6,
        ..Default::default()
    }
}

fn inbound_fw(default: Action, rules: Vec<firewall::FirewallRule>) -> SharedFirewall {
    SharedFirewall::new(firewall::FirewallConfig {
        default_inbound: default,
        default_outbound: Action::Allow,
        reject: false,
        disabled: false,
        rules,
    })
}

#[test]
fn inbound_oversized_datagram_dropped_as_malformed() {
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let peer = iroh::SecretKey::generate().public();
    let huge = vec![0u8; MAX_PEER_DATAGRAM + 1];
    assert!(matches!(
        evaluate_inbound(&huge, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::DropMalformed
    ));
}

#[test]
fn inbound_ipv6_evaluated_by_firewall() {
    let fw = inbound_fw(Action::Deny, vec![]);
    let peer = iroh::SecretKey::generate().public();
    // 44 bytes, so the TCP ports are present: without them the packet is
    // unclassifiable and would be dropped as malformed before the firewall.
    let mut pkt = vec![0u8; 44];
    pkt[0] = 0x60; // IPv6
    pkt[6] = 6; // TCP
    // src is the sender's own mesh address, or the anti-spoof check drops it
    // before the firewall is consulted.
    pkt[8..24].copy_from_slice(&TEST_V6.octets());
    // dst in the overlay 200::/7 range so it takes the firewall path (a
    // non-overlay dst would instead be evaluated as exit-node transit).
    pkt[24] = 0x02;
    assert!(matches!(
        evaluate_inbound(&pkt, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::DropFirewall(_)
    ));
}

#[test]
fn inbound_firewall_denied_port() {
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(
        Action::Allow,
        vec![firewall::FirewallRule {
            direction: Direction::In,
            action: Action::Deny,
            protocol: firewall::Protocol::Tcp,
            port: Some(firewall::PortRange { start: 22, end: 22 }),
            peer: firewall::PeerFilter::Any,
            network: None,
            origin: firewall::RuleOrigin::Local,
        }],
    );
    let blocked = make_tcp_packet(22);
    let allowed = make_tcp_packet(80);
    assert!(matches!(
        evaluate_inbound(&blocked, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::DropFirewall(_)
    ));
    assert!(matches!(
        evaluate_inbound(&allowed, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::Accept(_)
    ));
}

#[test]
fn inbound_clean_tcp_denied_by_secure_default() {
    // The built-in default denies unsolicited inbound TCP (no service port is
    // exposed out of the box).
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let pkt = make_tcp_packet(443);
    assert!(matches!(
        evaluate_inbound(&pkt, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::DropFirewall(_)
    ));
}

#[test]
fn inbound_icmp_accepted_by_default() {
    // Inbound ICMP is allowed-by-default so ping/reachability works out of the
    // box even under the deny-inbound default.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let mut pkt = vec![0u8; 48];
    pkt[0] = 0x60; // IPv6
    pkt[5] = 8;
    pkt[6] = 58; // next header = ICMPv6
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&TEST_V6.octets());
    pkt[24..40].copy_from_slice(&OTHER_V6.octets());
    pkt[40] = 128; // ICMPv6 echo request
    assert!(matches!(
        evaluate_inbound(&pkt, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::Accept(_)
    ));
}

/// TCP checksum over the IPv6 pseudo-header (RFC 2460 §8.1): src, dst,
/// the upper-layer length as a 32-bit big-endian, three zero bytes and the
/// next-header value, followed by the TCP segment itself.
fn tcp_csum_v6(pkt: &[u8]) -> u16 {
    tcp_csum_v6_at(pkt, 40)
}

/// [`tcp_csum_v6`] for a TCP header at `tcp_off`, past any extension headers.
fn tcp_csum_v6_at(pkt: &[u8], tcp_off: usize) -> u16 {
    let tcp = &pkt[tcp_off..];
    let mut sum: u32 = 0;
    for chunk in pkt[8..40].chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += tcp.len() as u32;
    sum += 6; // next header = TCP
    for (i, chunk) in tcp.chunks(2).enumerate() {
        if i == 8 {
            continue; // the checksum field itself
        }
        let v = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += v as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Held by tests that change or depend on the process-global SSH NAT port.
static SSH_NAT_PORT_TEST: Mutex<()> = Mutex::new(());

#[test]
fn ssh_nat_rewrites_port_and_keeps_checksum_valid() {
    let _port = SSH_NAT_PORT_TEST.lock().unwrap_or_else(|e| e.into_inner());
    // `SSH_NAT` is a process-global `OnceLock`, so another test in this binary
    // (e.g. the headless daemon build) may seed it first, making our
    // `init_ssh_nat` a no-op. Read the addresses the NAT actually holds and
    // build the packet from those, so the test is independent of run order.
    init_ssh_nat(Ipv6Addr::LOCALHOST, 41384);
    set_ssh_nat_port(2222);
    set_ssh_nat_active(true);
    let (our_v6, listen_port) = {
        let nat = ssh_nat().expect("nat active");
        (nat.v6, nat.listen_port)
    };

    // IPv6 TCP packet from a peer to our configured mesh port.
    let mut pkt = vec![0u8; 60];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload = TCP header
    pkt[6] = 6; // next header = TCP
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 9).octets());
    pkt[24..40].copy_from_slice(&our_v6.octets()); // dst (us)
    pkt[40..42].copy_from_slice(&5000u16.to_be_bytes()); // src port
    pkt[42..44].copy_from_slice(&2222u16.to_be_bytes());
    pkt[52] = 0x50; // data offset = 5 (20-byte TCP header)
    let ck = tcp_csum_v6(&pkt);
    pkt[56..58].copy_from_slice(&ck.to_be_bytes());

    let info = firewall::parse_packet_info(&pkt).unwrap();
    assert_eq!(
        rewrite_ssh_port(&mut pkt, &info, true),
        SshRewrite::Rewritten
    );
    let info2 = firewall::parse_packet_info(&pkt).unwrap();
    assert_eq!(
        info2.dst_port, listen_port,
        "dest port rewritten from the configured port to listen"
    );
    // The incrementally-updated checksum must equal a freshly computed one.
    let field = u16::from_be_bytes([pkt[56], pkt[57]]);
    assert_eq!(
        field,
        tcp_csum_v6(&pkt),
        "checksum stays valid after rewrite"
    );

    pkt[8..24].copy_from_slice(&our_v6.octets());
    pkt[24..40].copy_from_slice(&Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 9).octets());
    pkt[40..42].copy_from_slice(&listen_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&5000u16.to_be_bytes());
    let reply_ck = tcp_csum_v6(&pkt);
    pkt[56..58].copy_from_slice(&reply_ck.to_be_bytes());
    let reply = firewall::parse_packet_info(&pkt).unwrap();
    assert_eq!(
        rewrite_ssh_port(&mut pkt, &reply, false),
        SshRewrite::Rewritten
    );
    assert_eq!(firewall::parse_packet_info(&pkt).unwrap().src_port, 2222);
    assert_eq!(u16::from_be_bytes([pkt[56], pkt[57]]), tcp_csum_v6(&pkt));

    // A hop-by-hop header before TCP: the port and checksum live past it, at
    // the offset the parser found, and the extension header is left alone.
    // Kept in this test because the NAT config is process-global.
    let mut ext = vec![0u8; 68];
    ext[0] = 0x60;
    ext[4..6].copy_from_slice(&28u16.to_be_bytes()); // 8 hop-by-hop + 20 TCP
    ext[6] = 0; // next header = hop-by-hop
    ext[7] = 64;
    ext[8..24].copy_from_slice(&Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 9).octets());
    ext[24..40].copy_from_slice(&our_v6.octets());
    ext[40] = 6; // hop-by-hop next header = TCP
    ext[41] = 0; // 8 octets
    ext[42] = 1; // PadN option filling the rest
    ext[43] = 4;
    ext[48..50].copy_from_slice(&5000u16.to_be_bytes());
    ext[50..52].copy_from_slice(&2222u16.to_be_bytes());
    ext[60] = 0x50;
    let ck = tcp_csum_v6_at(&ext, 48);
    ext[64..66].copy_from_slice(&ck.to_be_bytes());
    let hop_by_hop: [u8; 8] = ext[40..48].try_into().expect("8-byte slice");

    let info = firewall::parse_packet_info(&ext).unwrap();
    assert_eq!(info.transport_offset, 48);
    assert_eq!(
        rewrite_ssh_port(&mut ext, &info, true),
        SshRewrite::Rewritten
    );
    assert_eq!(ext[40..48], hop_by_hop, "extension header untouched");
    assert_eq!(
        firewall::parse_packet_info(&ext).unwrap().dst_port,
        listen_port
    );
    assert_eq!(
        u16::from_be_bytes([ext[64], ext[65]]),
        tcp_csum_v6_at(&ext, 48),
        "checksum stays valid behind an extension header"
    );

    // A packet to the mesh port too short to hold the checksum cannot be
    // rewritten, and says so, so the caller drops it rather than handing
    // it to the host on the mesh port.
    let mut short = pkt[..40 + 16].to_vec();
    short[8..24].copy_from_slice(&Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 9).octets());
    short[24..40].copy_from_slice(&our_v6.octets());
    short[42..44].copy_from_slice(&2222u16.to_be_bytes());
    let short_info = firewall::parse_packet_info(&short).unwrap();
    assert_eq!(
        rewrite_ssh_port(&mut short, &short_info, true),
        SshRewrite::Truncated
    );
    // Another port is left alone, however short.
    short[42..44].copy_from_slice(&80u16.to_be_bytes());
    let short_info = firewall::parse_packet_info(&short).unwrap();
    assert_eq!(
        rewrite_ssh_port(&mut short, &short_info, true),
        SshRewrite::Untouched
    );

    // Inactive -> no rewrite.
    set_ssh_nat_active(false);
    let mut pkt2 = pkt.clone();
    let info3 = firewall::parse_packet_info(&pkt2).unwrap();
    assert_eq!(
        rewrite_ssh_port(&mut pkt2, &info3, true),
        SshRewrite::Untouched
    );
    set_ssh_nat_port(SSH_PORT);
}

#[test]
fn csum_replace2_round_trips() {
    // Swapping a field value and swapping it back restores the checksum.
    let c = 0x1234u16;
    assert_eq!(csum_replace2(csum_replace2(c, 22, 41384), 41384, 22), c);
}

/// IPv4 transit still requires a canonical source and an exit grant.
#[test]
fn ipv4_transit_requires_canonical_source_and_network_permission() {
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(Action::Deny, vec![]);
    let exit = no_exit();
    let packet = make_tcp_packet_v4(ipv4::CLIENT_ADDR.octets(), [8, 8, 8, 8], 443);
    assert!(matches!(
        evaluate_inbound(&packet, &fw, &exit, &peer, TEST_V6, "example"),
        InboundDecision::DropExit
    ));
    exit.server.reload([("example", &[peer.to_string()][..])]);
    assert!(matches!(
        evaluate_inbound(&packet, &fw, &exit, &peer, TEST_V6, "example"),
        InboundDecision::Accept(_)
    ));
    assert!(matches!(
        evaluate_inbound(&packet, &fw, &exit, &peer, TEST_V6, "other"),
        InboundDecision::DropExit
    ));
    for destination in [
        [127, 0, 0, 1],
        [10, 0, 0, 1],
        [169, 254, 169, 254],
        [192, 0, 0, 2],
        [198, 19, 0, 1],
    ] {
        let packet = make_tcp_packet_v4(ipv4::CLIENT_ADDR.octets(), destination, 443);
        assert!(!matches!(
            evaluate_inbound(&packet, &fw, &exit, &peer, TEST_V6, "example"),
            InboundDecision::Accept(_)
        ));
    }
    let spoof = make_tcp_packet_v4([192, 0, 0, 3], [8, 8, 8, 8], 443);
    assert!(matches!(
        evaluate_inbound(&spoof, &fw, &exit, &peer, TEST_V6, "example"),
        InboundDecision::DropSpoof
    ));
}

#[test]
fn ipv4_return_traffic_requires_selected_gateway_and_open_flow() {
    let peer = iroh::SecretKey::generate().public();
    let other = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = exit_via(peer);
    let mut reply = make_tcp_packet_v4([8, 8, 8, 8], ipv4::CLIENT_ADDR.octets(), 50000);
    reply[20..22].copy_from_slice(&443u16.to_be_bytes());
    assert!(matches!(
        evaluate_inbound(&reply, &fw, &exit, &peer, TEST_V6, "test-net"),
        InboundDecision::DropFirewall(_)
    ));
    let mut request = make_tcp_packet_v4(ipv4::CLIENT_ADDR.octets(), [8, 8, 8, 8], 443);
    request[20..22].copy_from_slice(&50000u16.to_be_bytes());
    let info = firewall::parse_packet_info(&request).unwrap();
    assert!(
        fw.evaluate_packet(Direction::Out, &info, &peer, |name| name == "test-net")
            .is_allow()
    );
    assert!(matches!(
        evaluate_inbound(&reply, &fw, &exit, &peer, TEST_V6, "test-net"),
        InboundDecision::Accept(_)
    ));
    assert!(matches!(
        evaluate_inbound(&reply, &fw, &exit, &other, OTHER_V6, "test-net"),
        InboundDecision::DropSpoof
    ));
}

#[test]
fn inbound_mesh_ipv4_is_never_accepted() {
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(Action::Allow, vec![]);
    let pkt = make_tcp_packet_v4([100, 64, 0, 5], [100, 64, 0, 9], 80);

    // Not our exit peer: plain anti-spoofing.
    assert!(matches!(
        evaluate_inbound(&pkt, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::DropSpoof
    ));

    // And with the sender as our selected exit peer, where the exemption for
    // return traffic fires for real return packets. `100.64.0.0/10` is not
    // transitable and the destination is not our mesh v6, so it still cannot
    // be mistaken for one.
    assert!(matches!(
        evaluate_inbound(&pkt, &fw, &exit_via(peer), &peer, TEST_V6, "test-net"),
        InboundDecision::DropSpoof
    ));
}

#[test]
fn inbound_spoofed_source_ip_dropped() {
    // A packet whose source IP isn't the sending peer's assigned mesh IP is
    // dropped as spoofed, before the firewall or any in-daemon listener sees
    // it, even when the firewall would otherwise allow it.
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(Action::Allow, vec![]);
    let pkt = make_tcp_packet(80); // sourced from TEST_V6
    // Same packet, but the peer is supposedly assigned a different IP.
    assert!(matches!(
        evaluate_inbound(
            &pkt,
            &fw,
            &no_exit(),
            &peer,
            Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 9),
            "test-net"
        ),
        InboundDecision::DropSpoof
    ));
    // With the matching peer IP it passes.
    assert!(matches!(
        evaluate_inbound(&pkt, &fw, &no_exit(), &peer, TEST_V6, "test-net"),
        InboundDecision::Accept(_)
    ));
}

/// A TCP packet from TEST_V4 to `dst`, a non-overlay destination.
fn make_packet_to(dst: Ipv6Addr) -> Vec<u8> {
    make_tcp_packet_between(TEST_V6, dst, 443)
}

/// A TCP packet from TEST_V6 to a public (non-overlay) destination.
fn make_public_packet() -> Vec<u8> {
    make_packet_to(PUBLIC_V6)
}

#[test]
fn internet_bound_dropped_when_not_an_exit() {
    // With no exit offered, a packet to the internet is dropped (not leaked),
    // even though the source IP is legitimate.
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(Action::Allow, vec![]);
    assert!(matches!(
        evaluate_inbound(
            &make_public_packet(),
            &fw,
            &no_exit(),
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::DropExit
    ));
}

/// A gateway does not become a way onto its own LAN. The client is allowed
/// to transit, and the destination is a perfectly ordinary global address --
/// it is a neighbour of the gateway's, which is the only thing that stops it.
#[test]
fn an_allowed_client_still_cannot_transit_onto_the_gateways_own_lan() {
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = no_exit();
    exit.server
        .reload([("test-net", vec![peer.to_string()].as_slice())]);
    exit.server.set_on_link(
        crate::exit_node::parse_host_interfaces("eth0 inet6 2001:db8:1:2::5/64 scope global")
            .on_link,
    );
    let lan_neighbour: std::net::Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
    assert!(
        matches!(
            evaluate_inbound(
                &make_packet_to(lan_neighbour),
                &fw,
                &exit,
                &peer,
                TEST_V6,
                "test-net"
            ),
            InboundDecision::DropExit
        ),
        "the gateway's /64 is global, so is_transitable cannot refuse it and \
         is_self_addr does not cover a neighbour"
    );
    // And the same gateway still forwards to the actual internet.
    assert!(matches!(
        evaluate_inbound(
            &make_public_packet(),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
}

#[test]
fn internet_bound_accepted_for_allowed_exit_user() {
    // When we offer an exit to this sender, the internet-bound packet is
    // accepted for forwarding, bypassing the (deny-all) inbound firewall.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default()); // deny inbound
    let exit = no_exit();
    exit.server
        .reload([("test-net", vec![peer.to_string()].as_slice())]);
    assert!(matches!(
        evaluate_inbound(
            &make_public_packet(),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
    // A different sender we don't allow is still dropped.
    let other = iroh::SecretKey::generate().public();
    assert!(matches!(
        evaluate_inbound(
            &make_public_packet(),
            &fw,
            &exit,
            &other,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::DropExit
    ));
}

#[test]
fn exit_transit_refuses_the_gateways_own_network() {
    // An allowed exit client gets the internet, not the inside of the gateway:
    // its LAN, its loopback, and above all the cloud metadata service (which
    // hands out the gateway's instance credentials) are all refused.
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(Action::Allow, vec![]);
    let exit = no_exit();
    exit.server
        .reload([("test-net", vec![peer.to_string()].as_slice())]);
    for dst in [
        // fe80::/10 link-local, which is where the v6 metadata address lives
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe),
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), // the gateway's LAN
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5), // fc00::/7 unique-local
        Ipv6Addr::LOCALHOST,                        // the gateway's loopback
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), // multicast
        Ipv6Addr::UNSPECIFIED,
    ] {
        assert!(
            matches!(
                evaluate_inbound(&make_packet_to(dst), &fw, &exit, &peer, TEST_V6, "test-net"),
                InboundDecision::DropExit
            ),
            "exit node transited a packet to {dst:?}, which is not on the internet"
        );
    }
    // A genuinely public destination still goes through.
    assert!(matches!(
        evaluate_inbound(
            &make_public_packet(),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
}

#[test]
fn exit_transit_refuses_the_gateways_own_public_ip() {
    // The gateway's own public address is globally routable, but a packet
    // transited to it is local-delivered by the gateway's kernel, reaching its
    // services without ever passing its rayfish inbound firewall. Refused: an
    // exit offer is a way to the internet, not into the gateway host.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default()); // deny inbound
    let exit = no_exit();
    exit.server
        .reload([("test-net", vec![peer.to_string()].as_slice())]);
    let self_addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 0x1);
    let neighbour = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 0x2);
    exit.server.set_self_addrs([IpAddr::V6(self_addr)].into());
    assert!(matches!(
        evaluate_inbound(
            &make_packet_to(self_addr),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::DropExit
    ));
    // A neighboring public destination still transits.
    assert!(matches!(
        evaluate_inbound(
            &make_packet_to(neighbour),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
}

/// A TCP packet from a public source (8.8.8.8) to `dst` (an overlay IP): the
/// shape of exit-node return traffic arriving from our exit peer.
fn make_return_packet(dst: Ipv6Addr) -> Vec<u8> {
    let mut p = vec![0u8; 44];
    p[0] = 0x60; // IPv6
    p[5] = 4; // payload length: the truncated TCP header below
    p[6] = 6; // next header = TCP
    p[7] = 64; // hop limit
    p[8..24].copy_from_slice(&PUBLIC_V6.octets()); // src: from the internet
    p[24..40].copy_from_slice(&dst.octets()); // dst = our mesh IP
    p[40] = 1;
    p[41] = 0xbb; // src port 443
    p
}

/// Exit state where `peer` is our selected exit node on `test-net`.
fn exit_via(peer: EndpointId) -> ExitContext {
    let exit = no_exit();
    exit.client.set(Some(crate::exit_node::ExitSelection {
        carries: ExitFamilies::Dual,
        peer_user: peer,
        ipv6: TEST_V6,
        network: SmolStr::new("test-net"),
    }));
    exit
}

/// The outbound half of the flow `make_return_packet` answers: our mesh IP to
/// 8.8.8.8:443. Sending it through the firewall records the conntrack entry.
fn open_flow_to_internet(fw: &SharedFirewall, peer: &EndpointId) {
    let mut p = vec![0u8; 44];
    p[0] = 0x60; // IPv6
    p[5] = 4;
    p[6] = 6; // next header = TCP
    p[7] = 64;
    p[8..24].copy_from_slice(&MY_V6.octets()); // src = us
    p[24..40].copy_from_slice(&PUBLIC_V6.octets()); // dst: the internet
    p[42] = 1;
    p[43] = 0xbb; // dst port 443
    let info = firewall::parse_packet_info(&p).unwrap();
    assert!(
        fw.evaluate_packet(Direction::Out, &info, peer, |name| name == "test-net")
            .is_allow()
    );
}

#[test]
fn exit_return_traffic_accepted_past_antispoof() {
    // A reply from our exit peer (public src, our mesh IP as dst) is accepted
    // even though its source is not the peer's mesh IP: the anti-spoof check it
    // could never satisfy is skipped. It still goes through the firewall, and
    // what lets it past the deny-inbound default is the conntrack entry our own
    // outbound packet created.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = exit_via(peer);
    open_flow_to_internet(&fw, &peer);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(MY_V6),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
}

#[test]
fn exit_peer_cannot_inject_unsolicited_traffic() {
    // The exit peer carries our internet traffic, which does NOT make it trusted
    // to reach our local ports. With no flow of ours to answer, the same packet
    // is dropped by the firewall like any other unsolicited inbound traffic.
    // Otherwise `exit-node use` would silently hand that peer the ability to
    // dial every service on this host, bypassing the firewall entirely.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default()); // deny inbound
    let exit = exit_via(peer);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(MY_V6),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::DropFirewall(_)
    ));
}

#[test]
fn an_inbound_allow_does_not_admit_unsolicited_exit_traffic() {
    // An allow-inbound default (or a rule such as mesh SSH's) speaks for mesh
    // peers. A flow started from the gateway's side of the exit must still
    // answer one of ours, or anyone routing to the gateway reaches our ports.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig {
        default_inbound: firewall::Action::Allow,
        ..Default::default()
    });
    let exit = exit_via(peer);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(MY_V6),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::DropFirewall(_)
    ));
    open_flow_to_internet(&fw, &peer);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(MY_V6),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
}

#[test]
fn exit_return_traffic_not_addressed_to_us_is_spoof() {
    // The relaxation only applies to packets addressed to our own mesh IP; a
    // public-sourced packet to some other overlay IP still fails anti-spoof.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = exit_via(peer);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 42)),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::DropSpoof
    ));
}

#[test]
fn exit_return_traffic_from_wrong_peer_is_spoof() {
    // A public-sourced packet from a peer that is NOT our exit peer gets no
    // relaxation and is dropped as spoofed. The wrong peer has its own mesh IP
    // (two peers never share one), so neither the identity nor the IP match.
    let exit_peer = iroh::SecretKey::generate().public();
    let other = iroh::SecretKey::generate().public();
    let other_ip = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 9);
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = exit_via(exit_peer);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(MY_V6),
            &fw,
            &exit,
            &other,
            other_ip,
            "test-net"
        ),
        InboundDecision::DropSpoof
    ));
}

#[test]
fn exit_return_traffic_accepted_by_ip_when_identity_differs() {
    // Regression: the exemption must admit return traffic from our exit peer
    // even when the sender's resolved user identity does not match the
    // selection's (a device-vs-user-key mismatch). The verified mesh IPv6 the
    // reader resolves for the sender is the robust match: it is derived from
    // the identity that actually dialed, so it cannot be forged. Without the
    // IP match every reply from the exit node was dropped as spoofed and
    // traffic never flowed.
    let selected_user = iroh::SecretKey::generate().public();
    let arriving_user = iroh::SecretKey::generate().public(); // resolves differently
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = no_exit();
    exit.client.set(Some(crate::exit_node::ExitSelection {
        carries: ExitFamilies::Dual,
        peer_user: selected_user,
        ipv6: TEST_V6, // the exit peer's mesh IPv6
        network: SmolStr::new("test-net"),
    }));
    open_flow_to_internet(&fw, &arriving_user);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(MY_V6),
            &fw,
            &exit,
            &arriving_user, // identity does NOT match selection.peer_user
            TEST_V6,        // but the verified mesh IP does
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
}

#[test]
fn exit_return_traffic_accepted_on_any_shared_network() {
    // The gateway tags its replies via the generic route(), which picks the
    // lexically-smallest network it shares with us, not necessarily the one we
    // selected the exit on. The exemption is scoped to the peer identity, not
    // the tag: a reply from our exit peer is accepted whichever shared
    // network's handle it arrives under.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = exit_via(peer); // selected on "test-net"
    open_flow_to_internet(&fw, &peer);
    assert!(matches!(
        evaluate_inbound(
            &make_return_packet(MY_V6),
            &fw,
            &exit,
            &peer,
            TEST_V6,
            "another-net"
        ),
        InboundDecision::Accept(_)
    ));
}

#[test]
fn exit_return_traffic_with_martian_source_is_spoof() {
    // Symmetric to the outbound is_transitable check: the exit peer cannot
    // inject packets sourced from private/loopback/link-local space (e.g.
    // forging our LAN gateway at fe80::1), conntrack entry or not.
    let peer = iroh::SecretKey::generate().public();
    let fw = SharedFirewall::new(firewall::FirewallConfig::default());
    let exit = exit_via(peer);
    open_flow_to_internet(&fw, &peer);
    let mut p = make_return_packet(MY_V6);
    p[8..24].copy_from_slice(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
    assert!(matches!(
        evaluate_inbound(&p, &fw, &exit, &peer, TEST_V6, "test-net"),
        InboundDecision::DropSpoof
    ));
}

#[test]
fn mesh_ipv4_is_no_longer_an_overlay_destination() {
    // `is_overlay_ip` is what the data path uses to tell "a mesh peer" from
    // "the internet". The CGNAT range is no longer ours, so an address in it
    // is not a mesh destination and falls through to the exit-node rules
    // like any other non-overlay address.
    let mesh_v4: IpAddr = "100.64.0.9".parse().unwrap();
    let mesh_v6: IpAddr = "200::9".parse().unwrap();
    let internet: IpAddr = "1.1.1.1".parse().unwrap();

    assert!(is_overlay_ip(mesh_v6));
    assert!(!is_overlay_ip(mesh_v4));
    assert!(!is_overlay_ip(internet));
}

#[test]
fn magic_dns_predicate_matches_only_magic_ip_port_53() {
    let mk = |ip: IpAddr, port: u16| firewall::PacketInfo {
        src_ip: "200::5".parse().unwrap(),
        dst_ip: ip,
        protocol: 17,
        src_port: 50000,
        dst_port: port,
        tcp_flags: 0,
        icmp_type: 0,
        icmp_id: 0,
        transport_offset: 40,
    };
    assert!(is_magic_dns(&mk(IpAddr::V6(crate::dns::MAGIC_DNS_V6), 53)));
    assert!(!is_magic_dns(&mk(IpAddr::V6(crate::dns::MAGIC_DNS_V6), 80)));
    assert!(!is_magic_dns(&mk("200::9".parse().unwrap(), 53)));
    // The old v4 magic address is nobody's resolver now.
    assert!(!is_magic_dns(&mk("100.100.100.53".parse().unwrap(), 53)));
}

/// A UDP fragment from `src` to [`MY_V6`]: the first (`offset` 0) carries
/// the UDP header for `dst_port`, a later one only payload.
fn udp_fragment(src: Ipv6Addr, dst_port: u16, id: u32, offset: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 64];
    pkt[0] = 0x60;
    pkt[6] = 44;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&MY_V6.octets());
    pkt[40] = 17;
    pkt[42..44].copy_from_slice(&((offset << 3) | 1).to_be_bytes());
    pkt[44..48].copy_from_slice(&id.to_be_bytes());
    if offset == 0 {
        pkt[48..50].copy_from_slice(&5353u16.to_be_bytes());
        pkt[50..52].copy_from_slice(&dst_port.to_be_bytes());
    } else {
        // Payload that would read as an open port if taken for a header.
        pkt[48..52].copy_from_slice(&[0x11, 0x94, 0x11, 0x94]);
    }
    pkt
}

/// A UDP send past the MTU arrives as fragments. The first meets the
/// firewall; the rest follow its verdict and never meet a rule on their own.
#[test]
fn inbound_fragments_follow_their_first_fragments_verdict() {
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(
        Action::Deny,
        vec![firewall::FirewallRule {
            direction: Direction::In,
            action: Action::Allow,
            protocol: firewall::Protocol::Udp,
            port: Some(firewall::PortRange {
                start: 4500,
                end: 4500,
            }),
            peer: firewall::PeerFilter::Any,
            network: None,
            origin: firewall::RuleOrigin::Local,
        }],
    );
    let mut verdicts = FragmentVerdicts::default();
    let mut eval = |pkt: &[u8]| {
        super::evaluate_inbound(
            pkt,
            &fw,
            &no_exit(),
            InboundPeer {
                identity: &peer,
                ipv6: TEST_V6,
                network: "test-net",
                shares_network: &|name| name == "test-net",
            },
            &mut verdicts,
        )
    };
    // Before its first fragment, a later one has nothing to follow.
    assert!(matches!(
        eval(&udp_fragment(TEST_V6, 0, 1, 185)),
        InboundDecision::DropFragment
    ));
    assert!(matches!(
        eval(&udp_fragment(TEST_V6, 4500, 1, 0)),
        InboundDecision::Accept(_)
    ));
    assert!(matches!(
        eval(&udp_fragment(TEST_V6, 0, 1, 185)),
        InboundDecision::Accept(_)
    ));
    // A refused first fragment refuses the rest of its packet.
    assert!(matches!(
        eval(&udp_fragment(TEST_V6, 9999, 2, 0)),
        InboundDecision::DropFirewall(_)
    ));
    assert!(matches!(
        eval(&udp_fragment(TEST_V6, 0, 2, 185)),
        InboundDecision::DropFragment
    ));
    // The source check runs on every fragment, not just the first.
    let other = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 9);
    assert!(matches!(
        eval(&udp_fragment(other, 0, 1, 185)),
        InboundDecision::DropSpoof
    ));
}

/// TCP fragments to the mesh SSH port are refused before the firewall, so
/// their later fragments find no verdict to follow either.
#[test]
fn ssh_port_fragments_are_refused() {
    let mut first = udp_fragment(TEST_V6, 2222, 7, 0);
    first[40] = 6;
    first.resize(48 + 20, 0);
    first[48 + 12] = 5 << 4;
    let f = firewall::parse_ipv6_fragment(&first).expect("a first fragment");
    assert!(is_ssh_fragment(&f.info, 2222));
    assert!(!is_ssh_fragment(&f.info, 22));
    let udp = firewall::parse_ipv6_fragment(&udp_fragment(TEST_V6, 2222, 7, 0))
        .expect("a first fragment");
    assert!(!is_ssh_fragment(&udp.info, 2222), "UDP is not SSH");

    // Through the inbound path, with the port the NAT holds right now.
    let _port = SSH_NAT_PORT_TEST.lock().unwrap_or_else(|e| e.into_inner());
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(Action::Allow, vec![]);
    let mut verdicts = FragmentVerdicts::default();
    let mut eval = |pkt: &[u8]| {
        super::evaluate_inbound(
            pkt,
            &fw,
            &no_exit(),
            InboundPeer {
                identity: &peer,
                ipv6: TEST_V6,
                network: "test-net",
                shares_network: &|name| name == "test-net",
            },
            &mut verdicts,
        )
    };
    let mut to_ssh = first.clone();
    to_ssh[50..52].copy_from_slice(&ssh_port().to_be_bytes());
    assert!(matches!(eval(&to_ssh), InboundDecision::DropFragment));
    let mut later = udp_fragment(TEST_V6, 0, 7, 185);
    later[40] = 6;
    assert!(matches!(eval(&later), InboundDecision::DropFragment));
}

#[test]
fn inbound_tcp_accepted_when_port_explicitly_opened() {
    // An explicit allow rule opens a port under the deny-inbound default.
    let peer = iroh::SecretKey::generate().public();
    let fw = inbound_fw(
        Action::Deny,
        vec![firewall::FirewallRule {
            direction: Direction::In,
            action: Action::Allow,
            protocol: firewall::Protocol::Tcp,
            port: Some(firewall::PortRange {
                start: 8080,
                end: 8080,
            }),
            peer: firewall::PeerFilter::Any,
            network: None,
            origin: firewall::RuleOrigin::Local,
        }],
    );
    assert!(matches!(
        evaluate_inbound(
            &make_tcp_packet(8080),
            &fw,
            &no_exit(),
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::Accept(_)
    ));
    // A different port stays denied.
    assert!(matches!(
        evaluate_inbound(
            &make_tcp_packet(9090),
            &fw,
            &no_exit(),
            &peer,
            TEST_V6,
            "test-net"
        ),
        InboundDecision::DropFirewall(_)
    ));
}
