//! Mesh packet forwarding between TUN device and peer QUIC connections.
//!
//! Three concurrent tasks handle the data plane:
//! - [`run_mesh`]: reads outgoing packets from TUN, routes to correct peer via [`PeerTable`]
//! - [`spawn_peer_reader`]: one per peer, reads incoming datagrams and forwards to TUN writer
//! - [`spawn_tun_writer`]: single task, writes incoming packets to the TUN device

pub(crate) mod fq_codel;
mod frag_verdicts;
mod fragment;
mod lazy_dial;
#[cfg(test)]
mod mock_tun_tests;

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use iroh::EndpointId;
use iroh::endpoint::Connection;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::daemon::NetworkRegistry;
use crate::dns;
use crate::exit_node::{ExitClient, ExitContext, is_transitable};
use crate::firewall::{self, Direction, SharedFirewall};
use crate::membership::{derive_ipv6, is_overlay_ip};
use crate::peers::{DeviceUserMap, PeerRoute, PeerTable};
use crate::stats::{DropReason, ForwardMetrics};
use frag_verdicts::FragmentVerdicts;
use lazy_dial::{LazyDialBuffers, MAX_IN_FLIGHT as LAZY_DIAL_MAX_IN_FLIGHT};
#[cfg(test)]
use lazy_dial::{
    MAX_PACKETS_PER_PEER as LAZY_DIAL_MAX_PACKETS_PER_PEER,
    MAX_PACKETS_TOTAL as LAZY_DIAL_MAX_PACKETS_TOTAL,
};

/// Maximum datagram size accepted from a peer, including the [`TAG_LEN`]-byte
/// network handle prefix. Anything larger is dropped before being parsed or
/// written to the TUN device, bounding memory use under a flood of oversized
/// datagrams from a malicious or buggy peer.
const MAX_PEER_DATAGRAM: usize = fragment::MAX_PACKET + TAG_LEN;

/// Datagrams drained from a peer connection in one `read_many_datagrams` call.
/// Sized for a burst at line rate without holding a large idle buffer: each slot
/// is an empty `Bytes` between reads, so the cost when idle is the vector itself.
const RECV_BATCH: usize = 32;

/// Bytes of the per-datagram network handle tag: a big-endian `u16` prefixed to
/// every mesh datagram. Since one connection now carries every network the two
/// peers share, the receiver can no longer infer a datagram's network from the
/// connection (ALPN) — this handle names it. `0` is reserved as invalid.
pub(crate) const TAG_LEN: usize = 2;

/// Prefix `payload` (a raw IP packet) with its outbound network `handle`,
/// producing the on-wire mesh datagram `[handle:u16 BE][ip packet…]`.
pub(crate) fn tag_datagram(handle: u16, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(TAG_LEN + payload.len());
    buf.extend_from_slice(&handle.to_be_bytes());
    buf.extend_from_slice(payload);
    buf.freeze()
}

/// Split a received mesh datagram into its network `handle` and the IP-packet
/// slice. `None` if it is too short to carry a tag.
pub(crate) fn untag_datagram(datagram: &[u8]) -> Option<(u16, &[u8])> {
    if datagram.len() < TAG_LEN {
        return None;
    }
    let handle = u16::from_be_bytes([datagram[0], datagram[1]]);
    Some((handle, &datagram[TAG_LEN..]))
}

/// Magic DNS forwarding may await an upstream resolver.  Keep enough requests
/// in flight for normal browser parallelism while bounding task and socket use
/// when a local app floods the resolver address.
const DNS_QUERIES_MAX_IN_FLIGHT: usize = 64;

/// The default port a stock `ssh` client targets (`ssh user@host.ray`). Defined here in
/// the always-compiled forward core because the userspace SSH NAT below rewrites
/// it on every platform, including Android, where the desktop-only `crate::ssh`
/// module (which re-exports this) is gated out.
pub(crate) const SSH_PORT: u16 = 22;

/// Internal port the embedded SSH server binds. The configured mesh port is translated
/// to/from this port by the userspace NAT below. Chosen below the ephemeral
/// source-port ranges so the outbound NAT (which matches `src_port == this`)
/// can't collide with a kernel-assigned ephemeral port. See `crate::ssh`.
pub(crate) const SSH_LISTEN_PORT: u16 = 30022;

/// Userspace NAT that maps this node's configured mesh SSH port to/from the embedded SSH
/// server's internal listen port ([`SSH_LISTEN_PORT`]). The kernel
/// won't let us bind `<mesh-ip>:22` alongside a host sshd on `0.0.0.0:22`, so
/// instead of an OS-firewall redirect (which would be Linux-only) we translate
/// the port inside our own forwarding path, portable across every platform the
/// TUN runs on. Inbound (peer -> us) rewrites dest `22 -> listen`; outbound
/// (us -> peer) rewrites source `listen -> 22`. Active only while `ray firewall
/// ssh` is on.
struct SshNat {
    active: AtomicBool,
    v6: Ipv6Addr,
    listen_port: u16,
    mesh_port: AtomicU16,
}

static SSH_NAT: OnceLock<SshNat> = OnceLock::new();

/// Register this node's mesh addresses + SSH listen port. Called once at daemon
/// start; the NAT stays inactive until [`set_ssh_nat_active`].
pub fn init_ssh_nat(v6: Ipv6Addr, listen_port: u16) {
    let _ = SSH_NAT.set(SshNat {
        active: AtomicBool::new(false),
        v6,
        listen_port,
        mesh_port: AtomicU16::new(SSH_PORT),
    });
}

/// Toggle the SSH port NAT (on when the mesh SSH server is running).
pub fn set_ssh_nat_active(on: bool) {
    if let Some(nat) = SSH_NAT.get() {
        nat.active.store(on, Ordering::Relaxed);
    }
}

pub fn set_ssh_nat_port(port: u16) {
    if let Some(nat) = SSH_NAT.get() {
        nat.mesh_port.store(port, Ordering::Relaxed);
    }
}

pub fn ssh_port() -> u16 {
    SSH_NAT
        .get()
        .map_or(SSH_PORT, |nat| nat.mesh_port.load(Ordering::Relaxed))
}

/// The NAT config, or `None` when unset or inactive.
fn ssh_nat() -> Option<&'static SshNat> {
    SSH_NAT.get().filter(|n| n.active.load(Ordering::Relaxed))
}

impl SshNat {
    fn is_ours(&self, ip: IpAddr) -> bool {
        matches!(ip, IpAddr::V6(v) if v == self.v6)
    }
}

/// RFC 1624 incremental checksum update for a single changed 16-bit word:
/// `HC' = ~(~HC + ~m + m')`. Used so a port rewrite doesn't require recomputing
/// the whole TCP checksum.
fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    let mut sum = (!check as u32) + (!old as u32 & 0xffff) + new as u32;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// What [`rewrite_ssh_port`] did with a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SshRewrite {
    /// Not an SSH NAT packet (or the NAT is off): forward it as it is.
    Untouched,
    Rewritten,
    /// An SSH NAT packet too short to hold the TCP checksum. It must be
    /// dropped: forwarded unrewritten, an inbound one would reach whatever
    /// listens on the mesh port on the host itself, such as its own sshd.
    Truncated,
}

/// Rewrite a TCP port in place for the SSH NAT, fixing the TCP checksum. When
/// `inbound`, maps the configured mesh port to `listen_port`;
/// otherwise maps source `listen_port` to the mesh port. `info` is the
/// already-parsed header, so the common case (no match) costs nothing.
fn rewrite_ssh_port(pkt: &mut [u8], info: &firewall::PacketInfo, inbound: bool) -> SshRewrite {
    let Some(nat) = ssh_nat() else {
        return SshRewrite::Untouched;
    };
    if info.protocol != 6 {
        return SshRewrite::Untouched; // TCP only
    }
    // The parser already walked any IPv6 extension headers, so this is where
    // the TCP header really starts.
    let ihl = info.transport_offset;
    let mesh_port = nat.mesh_port.load(Ordering::Relaxed);
    let (port_off, old, new) = if inbound {
        if !nat.is_ours(info.dst_ip) || info.dst_port != mesh_port {
            return SshRewrite::Untouched;
        }
        (ihl + 2, mesh_port, nat.listen_port)
    } else {
        if !nat.is_ours(info.src_ip) || info.src_port != nat.listen_port {
            return SshRewrite::Untouched;
        }
        (ihl, nat.listen_port, mesh_port)
    };
    if pkt.len() < ihl + 18 {
        return SshRewrite::Truncated;
    }
    pkt[port_off..port_off + 2].copy_from_slice(&new.to_be_bytes());
    let ck_off = ihl + 16;
    let old_ck = u16::from_be_bytes([pkt[ck_off], pkt[ck_off + 1]]);
    let new_ck = csum_replace2(old_ck, old, new);
    pkt[ck_off..ck_off + 2].copy_from_slice(&new_ck.to_be_bytes());
    SshRewrite::Rewritten
}

/// Whether a first IPv6 fragment is TCP to the mesh SSH port. Such fragments
/// are refused, and with them the rest of their packet: SSH segments are sized
/// to the path and never fragmented in practice, and a fragmented one is the
/// shape an attempt to slip past the port rewrite would take.
fn is_ssh_fragment(info: &firewall::PacketInfo, mesh_port: u16) -> bool {
    info.protocol == 6 && info.dst_port == mesh_port
}

/// Decision returned by [`evaluate_inbound`] for a datagram received from a peer.
pub(crate) enum InboundDecision {
    /// Packet passed the firewall check and may be written to the TUN. Carries
    /// the parsed packet so the accept path does not parse it again.
    Accept(firewall::PacketInfo),
    /// Dropped by the local firewall. Carries the parsed packet so a fail-fast
    /// REJECT reply can be built without re-parsing.
    DropFirewall(firewall::PacketInfo),
    /// Dropped: too large or not a parseable IP packet.
    DropMalformed,
    /// Dropped: a later IPv6 fragment whose first fragment was not let through
    /// (refused, or not seen yet). Counted as a firewall drop, never answered:
    /// the first fragment already got any reject there was to send.
    DropFragment,
    /// Dropped: the packet's source IP is not the sending peer's assigned mesh
    /// address. A peer may only source packets from its own mesh IP, so this
    /// blocks one peer from impersonating another's IP (ingress anti-spoofing).
    DropSpoof,
    /// Dropped: the datagram is bound for a non-overlay (internet) destination but
    /// this node does not offer the sender an exit node on this network. Prevents
    /// a non-exit node from silently transiting a peer's internet traffic.
    DropExit,
}

struct InboundPeer<'a> {
    identity: &'a EndpointId,
    ipv6: Ipv6Addr,
    network: &'a str,
    shares_network: &'a dyn Fn(&str) -> bool,
}

/// Pure evaluation of an inbound peer datagram against the firewall and basic
/// packet validity. Extracted from [`spawn_peer_reader`] so it can be unit-tested.
///
/// Non-IP / truncated / oversized packets are rejected (`DropMalformed`) rather
/// than passed through: previously such packets bypassed the firewall entirely.
///
/// An IPv6 fragment is classified by its first fragment: that one meets every
/// check a whole packet does, and the later ones of the same packet pass the
/// firewall only if it did (see [`frag_verdicts`]). The address checks still
/// run on every fragment.
fn evaluate_inbound(
    packet: &[u8],
    firewall: &SharedFirewall,
    exit: &ExitContext,
    peer: InboundPeer<'_>,
    fragments: &mut FragmentVerdicts,
) -> InboundDecision {
    let InboundPeer {
        identity: peer_id,
        ipv6: peer_ipv6,
        network,
        shares_network,
    } = peer;
    if packet.len() > fragment::MAX_PACKET {
        return InboundDecision::DropMalformed;
    }
    let (info, ip_fragment) = match firewall::parse_packet_info(packet) {
        Some(info) => (info, None),
        None => match firewall::parse_ipv6_fragment(packet) {
            Some(f) => (f.info, Some(f)),
            None => return InboundDecision::DropMalformed,
        },
    };
    // Ingress anti-spoofing: a peer may only inject packets sourced from its own
    // assigned mesh address. Anything else (e.g. one peer forging another's mesh
    // IP) is dropped before the firewall or any in-daemon listener sees it, so
    // identity-from-source-IP (used by mesh SSH) stays trustworthy.
    //
    // The mesh address is the peer's derived IPv6, so an IPv4 source is never a
    // legitimate mesh source. It still reaches the exit-node exemption below,
    // which is where a routable public IPv4 return packet belongs.
    let src_ok = matches!(info.src_ip, IpAddr::V6(v6) if v6 == peer_ipv6);
    if !src_ok {
        // Exit-node client return traffic: replies to our internet-bound flows come
        // back from our chosen exit peer sourced from the *host we reached*, not
        // from the peer's mesh IP, so they can never satisfy the anti-spoof check.
        // Exempt them (only when the sender is our exit peer, whichever shared
        // network's handle the reply arrives under; the source is a routable public
        // address, symmetric to the outbound is_transitable check so the exit peer
        // cannot forge our LAN or loopback; and the packet is addressed to us) and
        // let them face the firewall like any other inbound packet.
        //
        // They are not waved through: the conntrack entry our own outbound packet
        // created is what admits the reply. So the exit peer can deliver traffic for
        // flows we opened, but cannot inject unsolicited packets at our local ports.
        // (It is on-path for our real flows and can forge within them, as any
        // gateway or ISP can; that is what TLS is for. Reaching a service we never
        // dialed is a different matter, and it can't.)
        let dst_is_me = matches!(info.dst_ip, IpAddr::V6(v6) if v6 == exit.my_v6);
        let exit_return = exit.client.is_return_from(peer_id, peer_ipv6)
            && is_transitable(info.src_ip)
            && dst_is_me;
        if !exit_return {
            // A non-overlay source is a would-be exit-node reply: log why the
            // exemption did not fire so a broken return path is diagnosable.
            if !is_overlay_ip(info.src_ip) {
                tracing::debug!(
                    src = %info.src_ip,
                    dst = %info.dst_ip,
                    is_return = exit.client.is_return_from(peer_id, peer_ipv6),
                    transitable = is_transitable(info.src_ip),
                    dst_is_me,
                    peer_ip = %peer_ipv6,
                    my_v6 = %exit.my_v6,
                    "exit-return exemption did not fire; dropping as spoofed"
                );
            }
            return InboundDecision::DropSpoof;
        }
    }
    // Exit-node transit: a datagram bound for a non-overlay (internet) destination
    // is not for a mesh host at all. Forward it to the TUN (where the kernel NATs
    // it out) only if we offer this sender an exit node on this network *and* the
    // destination is one the internet could reach anyway ([`is_transitable`]:
    // loopback, link-local/metadata, ULA, private v4) *and* not on a network this
    // gateway is directly attached to ([`ExitServer::is_on_link`]: an IPv6 LAN is
    // normally a global /64, which `is_transitable` cannot recognise the way the
    // v4 arm recognises `is_private`) *and* not one of this host's own addresses
    // (the kernel would local-deliver those, skipping this firewall).
    // Otherwise drop it, so a non-exit node never leaks a peer's traffic and an
    // exit offer never doubles as a way into the gateway's own network or the
    // gateway host itself. `peer_id` is already the sender's user
    // identity, matching the allow-list. The normal inbound firewall is bypassed:
    // this is transit, not traffic addressed to us.
    if !is_overlay_ip(info.dst_ip) {
        let permitted = exit.server.allows(network, peer_id)
            && is_transitable(info.dst_ip)
            && !exit.server.is_on_link(info.dst_ip)
            && !exit.server.is_self_addr(info.dst_ip);
        return if permitted {
            InboundDecision::Accept(info)
        } else {
            InboundDecision::DropExit
        };
    }
    match ip_fragment {
        // A later fragment has no ports to judge; its first fragment decided.
        Some(f) if !f.first => {
            if fragments.admits(&f.key, tokio::time::Instant::now()) {
                InboundDecision::Accept(info)
            } else {
                InboundDecision::DropFragment
            }
        }
        Some(f) if is_ssh_fragment(&f.info, ssh_port()) => InboundDecision::DropFragment,
        whole_or_first => {
            if firewall
                .evaluate_packet(Direction::In, &info, peer_id, shares_network)
                .is_deny()
            {
                return InboundDecision::DropFirewall(info);
            }
            if let Some(f) = whole_or_first {
                fragments.allow(f.key, tokio::time::Instant::now());
            }
            InboundDecision::Accept(info)
        }
    }
}

/// Application close code a peer sends when it deliberately leaves a network
/// (`ray leave`). Distinguishes an intentional departure from a transient drop
/// (timeout/reset), so only deliberate leaves prune the canonical member list.
pub const LEAVE_CODE: u32 = 0x1ea5e;

/// Application close code used to drop a peer that floods the control plane with
/// messages (see [`crate::ratelimit::ControlGate`]). Distinct from
/// [`LEAVE_CODE`]: a flooded-out peer did not depart the network, so it is
/// treated as a non-intentional disconnect (the peer may reconnect; no quarantine).
pub const ABUSE_CODE: u32 = 0xab05e;

/// Application close code that tears down a link to a peer our verified roster no
/// longer lists (a nullified device, or a `prune_departed_peers` cleanup after
/// reconverge). It is transport teardown, never authority: membership is decided
/// only by the network-key-signed blob, and the authoritative per-network kick is
/// the in-band `ControlMsg::KickedFromNetwork`, not this close. On the receiving
/// side it is classified as [`CloseReason::Kicked`] and only affects reconnection:
/// we never evict the peer or leave a network on it. A coordinator reconnects (a
/// member cannot evict the coordinator, e.g. a flapping link's mutual prune); a
/// plain member does not (avoiding churn) and lets the in-band kick plus reconverge
/// settle its membership. The closing side does not observe its own close code
/// (that read is a local close), so it relies on the shared `pruned_peers` set to
/// suppress its reconnect loop.
pub const KICK_CODE: u32 = 0x14ced;

/// Application close code an on-demand node sends when it closes a peer connection
/// that has seen no traffic for the idle timeout. The remote peer classifies it as
/// [`CloseReason::Idle`] and does **not** reconnect (the link is re-established
/// lazily on the next packet either side sends). Distinct from a transient drop so
/// an eager peer doesn't immediately re-dial the link we deliberately let go idle.
pub const IDLE_CODE: u32 = 0x1d1e;

/// Application close code sent when a peer has selected another live QUIC
/// connection for this identity. The replacement is already in flight, so the
/// receiver must not immediately create yet another competing connection.
pub const REPLACED_CONNECTION_CODE: u32 = 0x2e91aced;

/// How a peer's connection ended, from the perspective of the side that observed
/// the close. Membership is decided solely by the network-key-signed roster, so a
/// close code is a hint about intent, never authority over who is a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Idle timeout, reset, control-flood close, or any non-graceful drop. The
    /// peer may reconnect.
    Transient,
    /// The peer closed with [`LEAVE_CODE`] (`ray leave`): it deliberately departed
    /// the last network we shared. A coordinator prunes it from the roster, and it
    /// is not reconnected.
    Left,
    /// The peer closed with [`KICK_CODE`]: it removed *us* from *its* view (a
    /// coordinator kicking us, or a member pruning what it believes is a stale
    /// roster entry). We never treat this as the peer leaving: doing so would let a
    /// member that wrongly kicks the coordinator during a flapping link evict a
    /// valid member and desync the mesh. A network-key holder keeps the peer and
    /// reconnects; the signed roster remains the sole authority.
    Kicked,
    /// The peer closed with [`IDLE_CODE`]: it deliberately let an idle connection
    /// go (on-demand teardown). Never reconnect; the link comes back lazily on the
    /// next packet either side sends.
    Idle,
    /// The peer selected another connection for this identity. Preserve an
    /// already registered successor; otherwise retry in case its handshake fails.
    Replaced,
}

impl CloseReason {
    /// Whether a coordinator should prune the peer from the signed roster on this
    /// close. Only a deliberate `ray leave` does; a kick never evicts the closer.
    pub fn prunes_member(self) -> bool {
        matches!(self, CloseReason::Left)
    }
}

/// Sent by [`spawn_peer_reader`] when a peer connection drops,
/// consumed by the reconnect loop (joiner) or cleanup task (coordinator).
///
/// Since a peer now has a single connection carrying every shared network, a
/// drop tears down the peer across **all** its networks at once (there is no
/// per-network connection). A graceful per-network departure (`ray leave` of one
/// of several shared networks) does not close the connection — it rides an
/// in-band control message and is handled by the control dispatcher, not here.
pub struct DisconnectEvent {
    pub endpoint_id: EndpointId,
    pub ipv6: Ipv6Addr,
    /// How the connection closed: a deliberate leave, a kick (the peer removed us
    /// from its view), or a transient drop. Only [`CloseReason::Left`] prunes the
    /// peer from a coordinated roster.
    pub reason: CloseReason,
    /// [`Connection::stable_id`] of the connection that dropped, so a consumer
    /// can tell whether the connection currently stored for this peer is still
    /// the one that died. `None` for a synthetic kick that is not tied to a live
    /// connection (the cold-restore reconnect seed), which always proceeds.
    ///
    /// Guards an ABA race: when a peer's process is killed and it re-dials with
    /// the same identity, the coordinator registers the fresh connection before
    /// the old one's idle timeout fires. Without this id, the stale connection's
    /// delayed disconnect would evict the fresh connection and drop the peer.
    pub conn_stable_id: Option<usize>,
}

/// Shared data-plane handles threaded into every per-peer reader. All fields are
/// cheap `Clone` (channels and Arc-backed handles), so a reader is spawned with a
/// single bundle instead of six separate arguments. Built per spawn by
/// `NetworkRegistry::forward_ctx`.
pub struct ForwardCtx {
    pub firewall: SharedFirewall,
    /// Swappable sender cell for the TUN writer. Peer readers outlive TUN
    /// attach/detach cycles (the control plane stays up across a VPN toggle), so
    /// they resolve the current writer per packet through an `arc_swap` `Cache`
    /// over this cell rather than capturing one sender. After a detach +
    /// re-attach the cell points at the new writer, so a reader spawned during
    /// the first `up()` keeps forwarding after the next one. See
    /// [`DaemonState::attach_tun`].
    pub tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
    pub token: CancellationToken,
    pub stats: Arc<ForwardMetrics>,
    pub device_user_map: DeviceUserMap,
    /// Exit-node state for the inbound path: the gateway allow policy (consulted
    /// for any datagram bound for a non-overlay destination), our own exit
    /// selection (whose return traffic bypasses the anti-spoof check), and our mesh
    /// addresses.
    pub exit: ExitContext,
}

/// True when a parsed packet is a DNS query addressed to the magic resolver IP
/// ([`dns::MAGIC_DNS_V6`]), the only address the resolver answers on and the one
/// handed to the OS.
pub(crate) fn is_magic_dns(info: &firewall::PacketInfo) -> bool {
    info.dst_port == 53 && info.dst_ip == IpAddr::V6(dns::MAGIC_DNS_V6)
}

/// The inputs and shared handles for one TUN forwarding loop.
pub(crate) struct MeshForwarder<R> {
    pub tun: R,
    pub local_ipv6: Ipv6Addr,
    pub peers: PeerTable,
    pub firewall: SharedFirewall,
    pub token: CancellationToken,
    pub stats: Arc<ForwardMetrics>,
    pub resolver: Arc<dns::resolver::Resolver>,
    pub tun_tx: mpsc::Sender<Bytes>,
    pub dialer: Option<Arc<NetworkRegistry>>,
}

/// Main TUN read loop. Reads outgoing packets from the TUN device and sends each
/// to its peer over QUIC. When there is no live connection to the destination, an
/// on-demand node buffers the packet and dials the peer (see below); with no dialer
/// the packet is dropped.
///
/// On-demand lazy dial: the loop owns two maps, `buffered` (packets waiting for a
/// peer's connection to come up, per peer) and `in_flight` (peers currently being
/// dialed), plus an internal `done` channel. A packet to an unconnected roster
/// member is buffered and, if no dial is in flight for that peer, a dial is spawned
/// that reports back on `done`. When a dial completes the loop flushes that peer's
/// buffered packets over the now-live route (or drops them if the dial failed). The
/// dial itself runs off-loop, so a slow handshake never blocks forwarding.
impl<R: crate::tun::TunRead> MeshForwarder<R> {
    pub(crate) async fn run(self) -> Result<()> {
        let Self {
            mut tun,
            local_ipv6,
            peers,
            firewall,
            token,
            stats,
            resolver,
            tun_tx,
            dialer,
        } = self;
        // On-demand lazy-dial state, owned by this loop (no shared/locked buffer).
        // `LazyDialBuffers` bounds retained bytes and packets both per peer and for
        // the whole daemon, so an offline route cannot make the forwarding task grow
        // without limit during a dial timeout.
        let mut buffered = LazyDialBuffers::default();
        let mut in_flight: HashSet<EndpointId> = HashSet::new();
        let (done_tx, mut done_rx) = mpsc::channel::<(EndpointId, bool)>(64);
        let dns_queries = Arc::new(Semaphore::new(DNS_QUERIES_MAX_IN_FLIGHT));
        // Client-side exit-node selection (cheap Arc-backed clone), consulted for
        // internet-bound packets. Default (no selection) when there is no registry.
        let exit_client = dialer
            .as_ref()
            .map(|r| r.exit_client.clone())
            .unwrap_or_default();
        let ctx = SendCtx {
            firewall: &firewall,
            peers: &peers,
            stats: &stats,
            tun_tx: &tun_tx,
        };
        let mut ip_fragments = FragmentVerdicts::default();
        loop {
            let pkt = tokio::select! {
                _ = token.cancelled() => return Ok(()),
                result = tun.read_packet() => match result {
                    Ok(pkt) => pkt,
                    // The reader lost one packet and can still read. Ending the
                    // loop here would stop all outbound traffic while the daemon
                    // and its links still looked healthy (#237).
                    Err(error) if error.is::<crate::tun::UnreadablePacket>() => {
                        tracing::debug!(%error, "dropping unreadable TUN packet");
                        stats.record_drop(DropReason::TunRead);
                        continue;
                    }
                    Err(error) => return Err(error),
                },
                Some((peer, connected)) = done_rx.recv() => {
                    in_flight.remove(&peer);
                    let pkts = buffered.take(&peer);
                    flush_or_drop(&ctx, &exit_client, connected, pkts).await;
                    continue;
                }
            };
            let n = pkt.len();
            if n == 0 {
                continue;
            }
            tracing::trace!(len = n, first_byte = pkt[0], "TUN read");
            // Router solicitations and MLD reports from the kernel's own IPv6
            // stack. Not traffic, and not a drop worth counting.
            if firewall::is_link_scoped_v6(&pkt) {
                continue;
            }
            let Some(info) = firewall::parse_packet_info(&pkt) else {
                // A UDP send past the TUN MTU arrives as kernel-made fragments.
                if let Some(f) = firewall::parse_ipv6_fragment(&pkt) {
                    send_fragment(&ctx, &exit_client, &mut ip_fragments, f, pkt).await;
                    continue;
                }
                // Not IP, truncated, or IPv6 with an extension-header chain the
                // parser refuses to walk. Counted rather than merely logged: a
                // silent drop reads as the link going quiet.
                tracing::debug!(len = n, "outbound packet not classifiable, dropping");
                stats.record_drop(DropReason::Malformed);
                continue;
            };
            // OS-owned tunnels can route self-traffic through their packet flow.
            // Deliver it unchanged so the local SSH listener can identify the
            // client socket. It has no remote peer or mesh SSH port translation.
            if info.src_ip == IpAddr::V6(local_ipv6) && info.dst_ip == IpAddr::V6(local_ipv6) {
                tokio::select! {
                    _ = token.cancelled() => return Ok(()),
                    result = tun_tx.send(pkt) => {
                        result.map_err(|_| anyhow::anyhow!("TUN writer stopped"))?;
                    }
                }
                continue;
            }
            // Android keeps the TUN, DNS, and file relay alive while mesh links
            // are idle. A kernel echo reply to a remote ping is not local demand.
            #[cfg(any(target_os = "android", target_os = "ios"))]
            if let Some(reg) = dialer.as_ref() {
                if firewall::is_icmp_echo_reply(info.protocol, info.icmp_type) {
                    if reg.transport.is_suspended() {
                        continue;
                    }
                } else {
                    reg.transport.record_outgoing_activity();
                    reg.wake_transport().await;
                }
            }
            if is_magic_dns(&info) {
                let Ok(permit) = Arc::clone(&dns_queries).try_acquire_owned() else {
                    stats.record_drop(DropReason::DnsConcurrency);
                    continue;
                };
                let resolver = Arc::clone(&resolver);
                let tun_tx = tun_tx.clone();
                let pkt = pkt.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    resolver.handle_tun_query(&pkt, &info, &tun_tx).await;
                });
                continue; // do not fall through to peer routing
            }
            let Some(route) = resolve_send_route(&peers, &exit_client, info.dst_ip) else {
                // No live connection to this destination (direct or via the exit peer).
                // Dial the destination member itself for overlay traffic, or the
                // configured exit peer for internet-bound traffic. Only known roster
                // members are dialable.
                let target = dialer.as_ref().and_then(|reg| {
                    let dst = dial_dst(&exit_client, info.dst_ip)?;
                    reg.resolve_route(dst)
                });
                let (Some(reg), Some(target)) = (dialer.as_ref(), target) else {
                    tracing::debug!(dst = %info.dst_ip, "no peer for dst");
                    stats.record_drop(DropReason::NoPeer);
                    continue;
                };

                let peer = target.endpoint_id;
                if !in_flight.contains(&peer) && in_flight.len() >= LAZY_DIAL_MAX_IN_FLIGHT {
                    stats.record_drop(DropReason::LazyDialConcurrency);
                    continue;
                }
                // Buffer a bounded beginning of the flow so its first packets aren't
                // lost once connected. A single dial per peer runs at a time
                // (in_flight dedup) and is bounded by LAZY_DIAL_TIMEOUT; on completion
                // `done` flushes the retained packets (success) or drops them
                // (timeout/failure). Once either retention budget is full, drop newest
                // rather than allowing an unreachable peer to accumulate unbounded
                // memory.
                if !buffered.push(peer, pkt) {
                    stats.record_drop(DropReason::LazyDialBufferFull);
                }

                if in_flight.insert(peer) {
                    let reg = Arc::clone(reg);
                    let done = done_tx.clone();
                    tokio::spawn(async move {
                        let connected = reg.dial_target(&target).await;
                        let _ = done.send((peer, connected)).await;
                    });
                }

                continue;
            };
            send_over_route(&ctx, &route, &info, pkt).await;
        }
    }
}

/// The mesh peer an outbound packet is sent to: the destination itself for overlay
/// traffic, the selected exit peer for internet-bound traffic. `None` when a packet
/// is internet-bound and no exit node is selected (it has nowhere to go).
fn dial_dst(exit: &ExitClient, dst: IpAddr) -> Option<IpAddr> {
    if is_overlay_ip(dst) {
        return Some(dst);
    }
    Some(IpAddr::V6(exit.selection()?.ipv6))
}

/// Resolve the live route to send an outbound packet over: the destination's own
/// mesh route for overlay traffic, or the configured exit peer's route for
/// internet-bound traffic. `None` when the packet can't be routed (no live
/// connection, or nothing to route it through).
fn resolve_send_route(peers: &PeerTable, exit: &ExitClient, dst: IpAddr) -> Option<PeerRoute> {
    if is_overlay_ip(dst) {
        // Only the IPv6 half of the overlay carries traffic. An overlay IPv4
        // destination has no peer to route to and falls through to `None`, the
        // same as an unknown address.
        return match dst {
            IpAddr::V6(v6) => peers.lookup_v6(&v6),
            IpAddr::V4(_) => None,
        };
    }
    // Internet-bound: route it through the selected exit peer, pinned to the exit
    // network's handle (the network whose allow-list permits us).
    let sel = exit.selection()?;
    peers.route_on_network(&sel.ipv6, &sel.network)
}

/// Flush packets buffered while a peer's on-demand connection came up. On success
/// each is re-routed and sent over the now-live connection (its route may differ
/// per packet, so look it up fresh); on failure they are dropped. Called by
/// [`run_mesh`] when a dial completes.
async fn flush_or_drop(
    ctx: &SendCtx<'_>,
    exit: &ExitClient,
    connected: bool,
    pkts: VecDeque<Bytes>,
) {
    if !connected {
        for _ in &pkts {
            ctx.stats.record_drop(DropReason::NoPeer);
        }
        return;
    }

    for pkt in pkts {
        let Some(info) = firewall::parse_packet_info(&pkt) else {
            ctx.stats.record_drop(DropReason::Malformed);
            continue;
        };

        let Some(route) = resolve_send_route(ctx.peers, exit, info.dst_ip) else {
            // The connection vanished between dialing and flushing (a racing
            // teardown); the flow's retransmit will re-drive it.
            ctx.stats.record_drop(DropReason::NoPeer);
            continue;
        };
        send_over_route(ctx, &route, &info, pkt).await;
    }
}

/// Sends one outbound IPv6 fragment. The first is judged like a whole packet
/// and decides for the rest of its packet (see [`frag_verdicts`]). Fragments
/// need a live route: they are not buffered behind an on-demand dial, since
/// the first packets of a flow are not fragments in practice.
async fn send_fragment(
    ctx: &SendCtx<'_>,
    exit: &ExitClient,
    verdicts: &mut FragmentVerdicts,
    fragment: firewall::Ipv6Fragment,
    pkt: Bytes,
) {
    let Some(route) = resolve_send_route(ctx.peers, exit, fragment.info.dst_ip) else {
        ctx.stats.record_drop(DropReason::NoPeer);
        return;
    };
    let now = tokio::time::Instant::now();
    if fragment.first {
        if send_routed(ctx, &route, &fragment.info, pkt, Admission::Firewall).await {
            verdicts.allow(fragment.key, now);
        }
    } else if verdicts.admits(&fragment.key, now) {
        send_routed(ctx, &route, &fragment.info, pkt, Admission::Admitted).await;
    } else {
        ctx.stats.record_drop(DropReason::Firewall);
    }
}

/// Whether an outbound packet still has to pass the firewall.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admission {
    Firewall,
    /// A later IPv6 fragment whose first fragment already passed.
    Admitted,
}

/// Forwarding state for outbound admission, membership checks, counters, and
/// injecting reject or PMTU replies into the TUN.
pub(crate) struct SendCtx<'a> {
    pub firewall: &'a SharedFirewall,
    pub peers: &'a PeerTable,
    pub stats: &'a Arc<ForwardMetrics>,
    pub tun_tx: &'a mpsc::Sender<Bytes>,
}

/// Firewall-check an outbound packet routed to `route` and turn it into tagged
/// datagrams to put on the wire, or `None` if it must not be sent (the reason is
/// counted, and any reject or PMTU reply already injected). Applies reject
/// injection and SSH source-port NAT.
async fn prepare_datagrams(
    ctx: &SendCtx<'_>,
    route: &PeerRoute,
    info: &firewall::PacketInfo,
    pkt: Bytes,
    admission: Admission,
) -> Option<fragment::Encoded> {
    let n = pkt.len();
    // Reachability is "we share a network", enforced by connection existence. The
    // per-host firewall is the fine-grained gate.
    if admission == Admission::Firewall
        && ctx
            .firewall
            .evaluate_packet(Direction::Out, info, &route.endpoint_id, |network| {
                ctx.peers.shares_network_v6(&route.ipv6, network)
            })
            .is_deny()
    {
        tracing::debug!(dst = %info.dst_ip, port = info.dst_port, "firewall denied outbound");
        ctx.stats.record_drop(DropReason::Firewall);
        // Denied SSH always fails fast; other traffic follows REJECT mode.
        // Inject a RST / ICMP-unreachable back into our own TUN
        // so the local app's socket fails immediately instead of hanging.
        if ctx.firewall.rejects_denied(info)
            && let Some(reply) = crate::reject::build_reject(&pkt, info)
        {
            ctx.stats.record_reject();
            let _ = ctx.tun_tx.send(reply).await;
        }
        return None;
    }
    // The IP-facing limit stays valid for IPv6. A smaller QUIC path is
    // handled below IP by mesh fragmentation, never by a sub-1280 ICMP PTB
    // (IPv6 hosts must ignore those, leaving full-sized packets blackholed).
    let receive_mtu = route.receive_mtu();
    if n > usize::from(receive_mtu) {
        if let Some(reply) = crate::reject::build_packet_too_big(&pkt, info, receive_mtu) {
            let _ = ctx.tun_tx.send(reply).await;
        }
        ctx.stats.record_drop(DropReason::PacketTooBig);
        return None;
    }
    let Some(max) = route.conn.max_datagram_size() else {
        ctx.stats.record_drop(DropReason::SendFailure);
        return None;
    };
    let legacy = route.conn.alpn() == crate::transport::MESH_V5_ALPN;
    if legacy && n + TAG_LEN > max {
        let inner_mtu = max.saturating_sub(TAG_LEN) as u16;
        if let Some(reply) = crate::reject::build_packet_too_big(&pkt, info, inner_mtu) {
            let _ = ctx.tun_tx.send(reply).await;
        }
        ctx.stats.record_drop(DropReason::PacketTooBig);
        return None;
    }
    if fragment::wire_size(n, max).is_none() {
        ctx.stats.record_drop(DropReason::PacketTooBig);
        return None;
    }
    // SSH NAT: rewrite our reply's source port to the configured mesh port.
    // The cheap pre-check (TCP + source port == listen port)
    // gates the copy; `rewrite_ssh_port` still confirms the source IP is ours and
    // no-ops otherwise, so ordinary traffic is untouched.
    let pkt = if ssh_nat().is_some_and(|s| info.protocol == 6 && info.src_port == s.listen_port) {
        let mut v = pkt.to_vec();
        if rewrite_ssh_port(&mut v, info, false) == SshRewrite::Truncated {
            ctx.stats.record_drop(DropReason::Malformed);
            return None;
        }
        Bytes::from(v)
    } else {
        pkt
    };
    // Prefix the network handle so the receiver, which shares one connection for all
    // our networks, can recover which network this datagram belongs to for
    // reachability and exit routing. `handle == 0` means we have no handle for the routed
    // network yet (the peer hasn't been announced) — drop rather than send an
    // undecodable datagram.
    if route.handle == 0 {
        ctx.stats.record_drop(DropReason::NoPeer);
        return None;
    }
    if legacy {
        Some(fragment::Encoded::Whole(tag_datagram(route.handle, &pkt)))
    } else {
        fragment::encode(route.handle, &pkt, max)
    }
}

/// Firewall-check an outbound packet already routed to `route`, then send it as a
/// whole packet or fragments. Shared by [`run_mesh`] and the on-demand flush of packets
/// buffered while a peer connection was established.
pub(crate) async fn send_over_route(
    ctx: &SendCtx<'_>,
    route: &PeerRoute,
    info: &firewall::PacketInfo,
    pkt: Bytes,
) {
    send_routed(ctx, route, info, pkt, Admission::Firewall).await;
}

/// [`send_over_route`] with the admission spelled out. True when the packet
/// was handed on (sent or queued), false when it was refused or did not fit.
async fn send_routed(
    ctx: &SendCtx<'_>,
    route: &PeerRoute,
    info: &firewall::PacketInfo,
    pkt: Bytes,
    admission: Admission,
) -> bool {
    let n = pkt.len();
    let Some(encoded) = prepare_datagrams(ctx, route, info, pkt, admission).await else {
        return false;
    };
    if let Some(slot) = &route.scheduler {
        let sender = slot.get_or_init(|| fq_codel::Sender::spawn(route, Arc::clone(ctx.stats)));
        sender.enqueue(info, route.handle, encoded, n);
    } else {
        let datagrams = encoded.datagrams();
        send_batch(ctx, route, datagrams, &[(datagrams.len(), n)]);
    }
    true
}

/// Hands an ordered run of datagrams to noq. `packets` records the end index and
/// original IP length of each packet, so fragmentation does not inflate traffic
/// counters. noQ may discard older queued datagrams when its bounded send buffer
/// is full; QUIC datagrams are intentionally unreliable and the forwarding path
/// never waits for capacity.
fn send_batch(ctx: &SendCtx<'_>, route: &PeerRoute, batch: &[Bytes], packets: &[(usize, usize)]) {
    if batch.is_empty() {
        return;
    }
    match route.conn.send_many_datagrams(batch) {
        Ok(queued) => {
            for &(end, len) in packets {
                if end <= queued {
                    ctx.stats.record_tx(len);
                } else {
                    ctx.stats.record_drop(DropReason::SendFailure);
                }
            }
            if queued > 0 {
                route.note_activity();
            }
        }
        Err(error) => {
            tracing::debug!(
                peer = %route.endpoint_id.fmt_short(),
                %error,
                "datagram send failed"
            );
            for _ in packets {
                ctx.stats.record_drop(DropReason::SendFailure);
            }
        }
    }
}

/// Spawns a task that reads QUIC datagrams from a single peer connection and
/// forwards them to the TUN writer via `tun_tx`. On connection loss (or
/// cancellation) it just exits; the owning [`MeshConnection`] observes the same
/// close and reports the [`DisconnectEvent`] to the supervisor.
///
/// [`MeshConnection`]: crate::daemon::MeshConnection
pub fn spawn_peer_reader(
    conn: Connection,
    peer_id: EndpointId,
    peers: PeerTable,
    ctx: ForwardCtx,
) -> JoinHandle<()> {
    let legacy = conn.alpn() == crate::transport::MESH_V5_ALPN;
    let ForwardCtx {
        firewall,
        tun_tx,
        token,
        stats,
        device_user_map,
        exit,
    } = ctx;
    // A peer's mesh address is a pure function of its identity, so it is derived
    // once here rather than per datagram. The arrival network is still resolved
    // per datagram (see `PeerTable::resolve_inbound`): the reader starts when the
    // connection opens, and the networks it may carry change while it runs.
    let peer_ipv6 = derive_ipv6(&peer_id);
    use tracing::Instrument as _;
    // Tag every event from this reader (drops, connection-lost) with the peer so
    // the report bundle's logs are correlatable per peer. The connection carries
    // all the peer's shared networks, so the reader is per-identity, not per-net.
    let span = tracing::info_span!("peer", peer = %peer_id.fmt_short());
    let reader = async move {
        // Per-reader view of the swappable TUN sender. `Cache::load` revalidates
        // against the cell and hands back the already-held `Arc` without touching
        // its refcount, re-cloning only when `attach_tun` actually stored a new
        // sender. The steady state (sender unchanged) is then refcount-free on the
        // hottest path we have, while a re-attach still redirects this reader.
        let mut tun_tx = arc_swap::cache::Cache::new(tun_tx);
        // Reused across reads: `read_many_datagrams` drains what is buffered into
        // this slice under a single lock hold, so a burst costs one wake and one
        // lock instead of one of each per packet. Taking each entry out leaves an
        // empty `Bytes` behind, so the batch holds no packet memory between reads.
        let mut batch = vec![Bytes::new(); RECV_BATCH];
        let mut reassembly = fragment::Reassembler::default();
        let mut ip_fragments = FragmentVerdicts::default();
        loop {
            let deadline = reassembly.deadline();
            // Wait for the next batch, exiting on cancellation or connection loss.
            // Keeping the `select!` to "yield datagrams or return" leaves the
            // actual forwarding below at loop-body depth.
            let count = tokio::select! {
                _ = token.cancelled() => return,
                _ = async {
                    match deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => {
                    for _ in 0..reassembly.expire(tokio::time::Instant::now()) {
                        stats.record_drop(DropReason::ReassemblyTimeout);
                    }
                    continue;
                }
                result = conn.read_many_datagrams(&mut batch) => match result {
                    Ok(n) => n,
                    Err(e) => {
                        // Connection closed. The owning `MeshConnection` observes
                        // the same close and reports the disconnect to the
                        // supervisor; the reader just stops forwarding.
                        tracing::debug!(peer = %peer_id.fmt_short(), error = %e, "peer datagram reader stopped");
                        return;
                    }
                },
            };
            for datagram in batch.iter_mut().take(count).map(std::mem::take) {
                if datagram.len() > MAX_PEER_DATAGRAM {
                    stats.record_drop(DropReason::Malformed);
                    continue;
                }
                if legacy && datagram.get(TAG_LEN) == Some(&0) {
                    stats.record_drop(DropReason::Malformed);
                    continue;
                }
                // Strip the network handle tag and resolve which network it names.
                let Some((handle, _)) = untag_datagram(&datagram) else {
                    stats.record_drop(DropReason::Malformed);
                    continue;
                };
                // Resolve the arrival network from the handle in one lookup,
                // which also enforces the in-band reachability wall: it returns
                // `None` unless the handle maps to a network *we* currently share with
                // this peer per our own roster. So the peer's handle table alone can't
                // smuggle a datagram into a network we don't agree it belongs to.
                let Some(network) = peers.resolve_inbound(&peer_ipv6, &conn, handle) else {
                    stats.record_drop(DropReason::Spoof);
                    continue;
                };
                // Reassemble only after validating membership, then run the same
                // source-IP, firewall and SSH NAT checks as for whole packets.
                let datagram = match reassembly.accept(datagram, tokio::time::Instant::now()) {
                    Ok(Some(packet)) => packet,
                    Ok(None) => continue,
                    Err(reason) => {
                        stats.record_drop(reason);
                        continue;
                    }
                };

                let peer_user = device_user_map.resolve(&peer_id);
                let peer = InboundPeer {
                    identity: &peer_user,
                    ipv6: peer_ipv6,
                    network: &network,
                    shares_network: &|name| peers.shares_network_v6(&peer_ipv6, name),
                };
                match evaluate_inbound(&datagram, &firewall, &exit, peer, &mut ip_fragments) {
                    InboundDecision::Accept(info) => {
                        // The TUN can be replaced with a smaller one while this
                        // connection stays open. Guard in-flight packets too,
                        // before peers have received the new MTU announcement.
                        let mtu = peers.local_mtu();
                        if datagram.len() > usize::from(mtu) {
                            stats.record_drop(DropReason::PacketTooBig);
                            if let Some(reply) =
                                crate::reject::build_packet_too_big(&datagram, &info, mtu)
                                && let Some(handle) = peers.out_handle(&peer_ipv6, &network)
                            {
                                send_peer_reply(&conn, handle, &reply);
                            }
                            continue;
                        }
                        stats.record_rx(datagram.len());
                        // SSH NAT: a packet to our configured mesh SSH port is rewritten to the
                        // SSH server's internal listen port before injection. The
                        // anti-spoof + firewall checks above already ran on the
                        // original packet. Cheap pre-check avoids a copy on
                        // ordinary traffic.
                        let datagram = match ssh_nat() {
                            Some(s)
                                if info.protocol == 6
                                    && info.dst_port == s.mesh_port.load(Ordering::Relaxed) =>
                            {
                                let mut v = datagram.to_vec();
                                if rewrite_ssh_port(&mut v, &info, true) == SshRewrite::Truncated {
                                    stats.record_drop(DropReason::Malformed);
                                    continue;
                                }
                                Bytes::from(v)
                            }
                            _ => datagram,
                        };
                        // Resolve the live writer for each packet: the sender is
                        // swapped on every TUN re-attach (VPN toggle). A send error
                        // means the writer is currently down (standby between a
                        // detach and the next attach); drop the packet and keep the
                        // reader alive so it forwards again once a new TUN attaches.
                        let _ = tun_tx.load().send(datagram).await;
                    }
                    InboundDecision::DropFirewall(info) => {
                        stats.record_drop(DropReason::Firewall);
                        // Denied SSH always fails fast; other traffic follows REJECT mode.
                        // Send a RST / ICMP-unreachable back over
                        // this connection so the initiator on the other host fails
                        // immediately. Its conntrack admits the reply (a RST matches
                        // its outbound flow; the seeded `allow in icmp` rule admits an
                        // ICMP error), so the initiator's app sees "connection refused".
                        if firewall.rejects_denied(&info)
                            && let Some(reply) = crate::reject::build_reject(&datagram, &info)
                        {
                            stats.record_reject();
                            if let Some(handle) = peers.out_handle(&peer_ipv6, &network) {
                                send_peer_reply(&conn, handle, &reply);
                            }
                        }
                    }
                    InboundDecision::DropMalformed => stats.record_drop(DropReason::Malformed),
                    InboundDecision::DropFragment => stats.record_drop(DropReason::Firewall),
                    InboundDecision::DropSpoof => {
                        stats.record_drop(DropReason::Spoof);
                        tracing::debug!(
                            peer = %peer_id.fmt_short(),
                            "dropped inbound packet with spoofed source IP"
                        );
                    }
                    InboundDecision::DropExit => {
                        stats.record_drop(DropReason::ExitDenied);
                        tracing::debug!(
                            peer = %peer_id.fmt_short(),
                            "dropped internet-bound packet: not an exit node for this sender"
                        );
                    }
                }
            }
            for _ in 0..reassembly.take_evicted() {
                stats.record_drop(DropReason::ReassemblyLimit);
            }
        }
    };
    tokio::spawn(reader.instrument(span))
}

/// Feedback uses our handle namespace and the same framing as ordinary packets.
/// Even a 1280-byte ICMP error may need fragmentation on a small QUIC path.
fn send_peer_reply(conn: &Connection, handle: u16, reply: &[u8]) {
    if let Some(max) = conn.max_datagram_size()
        && let Some(encoded) = fragment::encode(handle, reply, max)
    {
        let _ = conn.send_many_datagrams(encoded.datagrams());
    }
}

/// Minimum gap between two TUN write failure or oversize-drop warnings.
const WRITE_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Lets one log line through per `interval` and counts the rest, so a failure
/// that repeats at packet rate still shows up, once, with how often it happened.
struct LogBudget {
    interval: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl LogBudget {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
            suppressed: 0,
        }
    }

    /// `Some(n)` when a line may be logged now, `n` being how many were
    /// swallowed since the last one.
    fn allow(&mut self, now: Instant) -> Option<u64> {
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < self.interval)
        {
            self.suppressed += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// Spawns a task that consumes packets from `tun_rx` and writes them to the TUN
/// device. Single instance per session, serializes writes without a Mutex.
/// `active` is the data-plane gate: while it is false (standby, after `ray
/// down`) inbound datagrams are dropped instead of written, so a node that
/// stays connected to peers still carries no traffic.
pub fn spawn_tun_writer<W: crate::tun::TunWrite>(
    mut tun: W,
    mut tun_rx: mpsc::Receiver<Bytes>,
    active: Arc<AtomicBool>,
    stats: Arc<ForwardMetrics>,
) -> JoinHandle<()> {
    use std::sync::atomic::Ordering;
    tokio::spawn(async move {
        let batch_size = tun.write_batch_size().max(1);
        stats.tun_write_batch_limit.set(batch_size as i64);
        stats
            .tun_tcp_gso_enabled
            .set(i64::from(tun.tcp_gso_enabled()));
        stats
            .tun_udp_gso_enabled
            .set(i64::from(tun.udp_gso_enabled()));
        let mut batch = Vec::with_capacity(batch_size);
        let mut write_error_log = LogBudget::new(WRITE_ERROR_LOG_INTERVAL);
        let mut oversize_log = LogBudget::new(WRITE_ERROR_LOG_INTERVAL);
        while let Some(packet) = tun_rx.recv().await {
            batch.clear();
            for packet in std::iter::once(packet)
                .chain(std::iter::from_fn(|| tun_rx.try_recv().ok()))
                .take(batch_size)
            {
                if !active.load(Ordering::Relaxed) {
                    // Data plane is down (standby). Drain and drop so the channel
                    // never backs up while we keep the control plane connected.
                    continue;
                }
                // A peer reader may have queued this just before a TUN reattach
                // lowered the MTU. Never pass an oversized packet to the device.
                // Nothing answers it with a Packet Too Big, so count and warn.
                if packet.len() > usize::from(tun.mtu()) {
                    stats.record_drop(DropReason::PacketTooBig);
                    if let Some(suppressed) = oversize_log.allow(Instant::now()) {
                        tracing::warn!(
                            len = packet.len(),
                            mtu = tun.mtu(),
                            suppressed,
                            "dropped packet larger than the TUN MTU"
                        );
                    }
                    continue;
                }
                batch.push(packet);
            }
            if !batch.is_empty()
                && let Err(e) = tun.write_packets(&batch).await
            {
                stats.tun_write_errors.inc();
                // A device that has gone away fails every batch; one line per
                // batch would flood the journal at packet rate.
                if let Some(suppressed) = write_error_log.allow(Instant::now()) {
                    tracing::warn!(error = %e, packets = batch.len(), suppressed, "TUN batch write failed");
                }
            } else if !batch.is_empty() {
                stats.tun_write_batches.inc();
                stats.tun_write_packets.inc_by(batch.len() as u64);
            }
        }
    })
}

#[cfg(test)]
mod tests;
