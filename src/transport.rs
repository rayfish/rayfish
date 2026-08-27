//! iroh endpoint setup and peer connection management.
//!
//! Each network gets its own ALPN (`rayfish/net/<version>/<prefix>`) for isolation
//! and mesh-protocol version gating (see `MESH_PROTOCOL_VERSION`).
//! A single shared iroh [`Endpoint`] handles all networks, filtering by ALPN on accept.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey,
    address_lookup::{PkarrPublisher, PkarrResolver},
    dns::{DnsProtocol, DnsResolver},
    endpoint::Connection,
    endpoint::presets,
    endpoint::{BindOpts, Builder, DirectAddrFilter, QuicTransportConfig},
};

use crate::config::ServerOverride;
#[cfg(feature = "tor")]
use std::sync::Arc;

/// ALPN for the file-transfer protocol. The trailing `/1` is its protocol
/// version, **bump it (`/2`, …) on any breaking change to the file wire
/// protocol** (`FileOffer`/blob handshake). iroh negotiates the ALPN at the QUIC
/// handshake, so a peer on a different version shares no common ALPN and the
/// transfer simply can't connect: the version gate needs no in-band check.
pub const FILES_ALPN: &[u8] = b"rayfish/files/2";

/// Identity-level ALPN for the `ray connect` friend-request handshake. Unlike
/// `network_alpn`, this is not per-network: it accepts connection requests
/// addressed to this node's contact key. The trailing `/1` is its protocol
/// version, **bump it on any breaking change to the `ConnectMsg` handshake**;
/// peers on different versions can't negotiate a connection (transport-enforced).
pub const CONNECT_ALPN: &[u8] = b"rayfish/connect/2";

/// Fixed UDP port the endpoint binds so users can port-forward a stable, known
/// port for guaranteed direct reachability (Tailscale-style). Unlike an ephemeral
/// port, this stays the same across daemon restarts, so a manual router forward
/// keeps working and the external NAT mapping doesn't churn. iroh still does
/// automatic NAT traversal (UPnP/NAT-PMP/PCP), discovery, and relay fallback on
/// top of this. If the port is already taken, the endpoint falls back to an
/// ephemeral port (see `create_endpoint_with_alpns`).
pub const RAYFISH_LISTEN_PORT: u16 = 41383;

/// Mesh wire-protocol version, embedded in the single mesh ALPN. Bump this on any
/// breaking change to the mesh control/forwarding protocol. Because iroh negotiates
/// the ALPN during the QUIC handshake, two peers on different mesh versions share no
/// common ALPN and simply cannot connect: the version gate is enforced by the
/// transport, with no in-band handshake.
///
/// Bumped to 2 for the single-connection-per-identity change: one mesh ALPN carries
/// every shared network (network selection is now in-band, a `ControlFrame.net`
/// per control message and a `u16` handle tag per datagram, not encoded in the
/// ALPN as it was in v1's `rayfish/net/<v>/<prefix>`). Version 2 is an unreleased,
/// in-flight breaking batch (the last released version is 1), so later breaking
/// wire changes on this branch fold into 2 rather than bumping again: e.g.
/// `ControlMsg::SignedRecord`, by which a coordinator hands a (re)connecting member
/// its current network-key-signed pkarr record over the mesh so the member
/// converges to the live roster in ~1s instead of waiting out a stale DHT lookup
/// plus the group poll; and `Welcome.direct_key`, which folds a direct
/// (`ray connect`) network's co-coordinator key grant into the join handshake's
/// Welcome (deterministic) instead of a separate best-effort `AdminGrant` stream.
///
/// A new *variant* does not bump this version: the frame reader skips any frame
/// it cannot decode (so an unknown `ControlMsg` variant is dropped, not fatal)
/// and nacks it with `ControlMsg::NotSupported` so the mismatch shows in the
/// sender's log (builds before the nack existed skip silently). A new *field*
/// does. Every frame and blob is msgpack array-encoded (`to_vec`), so a struct's
/// slot count is part of the wire: a new build reads an older peer's shorter
/// array and defaults the tail (`serde(default)`), but the older peer reads the
/// longer one and rejects it whole. Both ends of a connection share this ALPN,
/// so an un-bumped field addition leaves the old side dropping and nacking every
/// frame that carries it, on a connection that stays up and no longer works.
/// Under the map encoding this was free, and exit nodes are what that bought: a
/// v2 peer predating `ControlMsg::ExitNodeOffer` and `Member.exit_node` stayed
/// connected and simply could not offer or discover exit nodes until updated.
/// Compact gave that up. Bump for anything that changes a struct's shape, and
/// for anything an old peer would *misinterpret* (removed or repurposed fields
/// and variants, changed semantics of existing ones).
pub const MESH_PROTOCOL_VERSION: u32 = 5;

/// Capability bits a peer advertises in its `MeshHello.features`. These are
/// negotiated *inside* the single mesh ALPN, so adding one needs no version bump:
/// a peer acts on a bit only if the other side set it, and an absent `features`
/// field decodes to `0` (a peer on a build that predates the bit). This is how
/// idle-close coexists with v0.2.0 peers, which speak mesh v2 but do not
/// understand [`forward::IDLE_CODE`](crate::forward::IDLE_CODE): we simply never
/// idle-close a connection whose peer did not advertise `FEATURE_IDLE_CLOSE`.
pub const FEATURE_IDLE_CLOSE: u64 = 1 << 0;

/// The single mesh ALPN. Unlike the old per-network `rayfish/net/<v>/<prefix>`,
/// every mesh connection now negotiates this one ALPN regardless of network — a
/// peer holds exactly one QUIC connection to us, carrying all networks we share.
/// The accept loop dispatches every mesh connection to one connection handler,
/// which routes each control message to the right network by its `ControlFrame.net`.
pub fn mesh_alpn() -> Vec<u8> {
    format!("rayfish/mesh/{MESH_PROTOCOL_VERSION}").into_bytes()
}

/// Public resolvers appended to the endpoint's nameserver list so the daemon can
/// still find the relay and the pkarr server when the host's own DNS is down.
///
/// This is not a second resolver for the user's traffic: the endpoint's resolver
/// is only ever asked for iroh's public infrastructure names, so nothing about
/// the mesh or the names on it goes here. An operator who names their own
/// upstreams with `replace` gets exactly those instead (see
/// [`control_plane_nameservers`]).
const PUBLIC_FALLBACK_DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];

/// At most this many nameservers are handed to the endpoint, so a host with a
/// long resolv.conf doesn't turn every lookup into a fan-out.
const MAX_CONTROL_PLANE_NAMESERVERS: usize = 4;

/// The nameservers the daemon uses for its *own* lookups: the operator's
/// configured upstreams, then the host's, then a public fallback.
///
/// The fallback is the point. Without it the daemon inherits whatever the host's
/// resolv.conf claims, and a machine whose only nameserver stopped answering
/// takes rayfish down with it: no relay, no pkarr, `ray join` reporting a DNS
/// failure the user cannot act on (#111). `replace` suppresses it, because an
/// operator who said "only these servers" means it.
///
/// `system` has already had overlay addresses filtered out
/// ([`dns::config::system_nameservers`](crate::dns::config::system_nameservers)),
/// which is what keeps our own magic IP out of this list: pointing the daemon at
/// its own Magic DNS makes the control plane depend on the data plane it is
/// there to bring up. `None` means the platform keeps its resolvers somewhere we
/// cannot read (Android, Windows), which is a different thing from a host that
/// has none: with nothing configured either, the answer is an empty list and the
/// caller leaves iroh's own reader in place. Naming a public server there would
/// step over Android's Private DNS and downgrade those lookups to cleartext.
fn control_plane_nameservers(o: &ServerOverride, system: Option<Vec<Ipv4Addr>>) -> Vec<Ipv4Addr> {
    if system.is_none() && o.servers.is_empty() {
        return Vec::new();
    }
    let mut out = crate::config::resolve_upstreams(o, system.unwrap_or_default());
    if !o.replace {
        out.extend(PUBLIC_FALLBACK_DNS);
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|ip| !crate::membership::is_cgnat_range(*ip) && seen.insert(*ip));
    out.truncate(MAX_CONTROL_PLANE_NAMESERVERS);
    out
}

/// How this node reaches the network, from the two settings that decide it:
/// `private` (whose servers) and `tor` (how they are reached).
///
/// The two are orthogonal on purpose. `private` says nothing but the operator's
/// own relay and discovery server is contacted; `tor` says every connection goes
/// over Tor and no UDP socket is opened at all. They compose rather than nest.
///
/// The Tor arms are the only ones that publish nothing. A Tor v3 onion address
/// *is* an ed25519 public key, and so is an [`EndpointId`], so
/// `iroh_tor_transport` derives a peer's onion address from its id with no
/// lookup at all. There is no address to gather and none to advertise: a peer
/// that knows who we are already knows where we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodePosture {
    /// The default: direct UDP plus n0's relays, addresses published to n0.
    Open,
    /// Tor only. No UDP socket, no relay, nothing published.
    Tor,
    /// Direct UDP plus the operator's own relay, addresses published only to
    /// their own discovery server.
    Private,
    /// Tor only, with the network-record plane pointed at the operator's own
    /// discovery server (and reached through Tor's SOCKS proxy).
    PrivateTor,
}

impl NodePosture {
    /// Derive the posture from the two settings.
    pub fn new(private: bool, tor: bool) -> Self {
        match (private, tor) {
            (false, false) => Self::Open,
            (false, true) => Self::Tor,
            (true, false) => Self::Private,
            (true, true) => Self::PrivateTor,
        }
    }

    /// Whether Tor is the only transport: no UDP bind, no relay, no address
    /// gathering, and nothing published.
    pub fn is_tor_only(self) -> bool {
        matches!(self, Self::Tor | Self::PrivateTor)
    }

    /// Whether this node refuses infrastructure it was not explicitly given.
    pub fn is_private(self) -> bool {
        matches!(self, Self::Private | Self::PrivateTor)
    }
}

/// A handle that must outlive the endpoint.
///
/// Today this holds exactly one thing, and it is easy to delete by accident.
/// `iroh_tor_transport::TorCustomTransport` registers an *ephemeral* onion
/// service over a Tor control connection (`ADD_ONION` without `Detach`), and
/// that service lives only as long as the control connection. The connection is
/// owned by the `TorCustomTransport`, and `TorCustomTransport::bind` does **not**
/// pass it to the `TorCustomEndpoint` it returns, despite the field's own doc
/// comment saying it is shared (it is `#[allow(dead_code)]`, which is the tell).
///
/// So if the last `Arc` drops, tor tears the service down and the failure is
/// silent and total: the endpoint stays bound and looks healthy, this node still
/// believes it is reachable, and every peer that dials it gets "descriptor not
/// found" for as long as the daemon runs. Measured, not deduced: a spike that
/// dropped the `Arc` timed out on every dial while tor logged `No more HSDir
/// available to query`; holding it, the same dial connected in ~9s.
///
/// Not `#[cfg]`-gated at the field level so call sites need no `cfg` of their
/// own; a build without the `tor` feature simply has nothing to keep.
#[derive(Clone, Default)]
pub struct TransportGuard {
    #[cfg(feature = "tor")]
    _tor: Option<Arc<iroh_tor_transport::TorCustomTransport>>,
}

impl std::fmt::Debug for TransportGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportGuard").finish_non_exhaustive()
    }
}

/// A bound endpoint plus whatever must stay alive alongside it.
///
/// A plain `Endpoint` would compile and then not work: see [`TransportGuard`].
#[derive(Debug)]
pub struct BoundEndpoint {
    pub endpoint: Endpoint,
    pub guard: TransportGuard,
}

/// Creates an iroh endpoint with the N0 preset (NAT traversal + relay fallback),
/// or, in a Tor posture, one carrying the Tor transport and nothing else.
///
/// **Keep the returned [`TransportGuard`] for as long as the endpoint lives.**
pub async fn create_endpoint_with_alpns(
    secret_key: SecretKey,
    alpns: Vec<Vec<u8>>,
    posture: NodePosture,
    relay: &ServerOverride,
    discovery: &ServerOverride,
    dns_upstreams: &ServerOverride,
) -> Result<BoundEndpoint> {
    // Bind the fixed port so the daemon is reachable on a known, forwardable UDP
    // port across restarts. The builder is consumed by `.bind()`, so we rebuild
    // it for the ephemeral fallback. Falling back to port 0 keeps the guarantee
    // that the daemon always starts even if the fixed port is already in use.
    // Read the host's resolvers once, here, rather than per bind attempt: the
    // second attempt runs after the first failed, and this must be the host's
    // configuration as it stood before anything of ours touched it.
    // A Tor-only node resolves no hostname of ours: there is no relay to find and
    // the pkarr server is reached through the SOCKS proxy, which does its own
    // remote DNS. Handing the endpoint an empty list means the public fallback in
    // `control_plane_nameservers` cannot fire, so no query for our infrastructure
    // ever leaves this machine in the clear.
    let nameservers = if posture.is_tor_only() {
        Vec::new()
    } else {
        control_plane_nameservers(dns_upstreams, crate::dns::config::system_nameservers())
    };
    tracing::debug!(?nameservers, ?posture, "control-plane DNS");

    // The fixed-port retry only means anything when there is a UDP socket to
    // collide over. A Tor posture binds none, so it gets one attempt.
    let bound = match bind_endpoint(
        &secret_key,
        &alpns,
        posture,
        RAYFISH_LISTEN_PORT,
        relay,
        discovery,
        &nameservers,
    )
    .await
    {
        Ok(bound) => bound,
        Err(e) if posture.is_tor_only() => {
            return Err(e).context("failed to bind iroh endpoint over Tor");
        }
        Err(e) => {
            tracing::warn!(
                port = RAYFISH_LISTEN_PORT,
                error = %e,
                "fixed UDP port unavailable; falling back to an ephemeral port"
            );
            bind_endpoint(
                &secret_key,
                &alpns,
                posture,
                0,
                relay,
                discovery,
                &nameservers,
            )
            .await
            .context("failed to bind iroh endpoint")?
        }
    };

    tracing::info!(
        id = %bound.endpoint.id().fmt_short(),
        ?posture,
        "iroh endpoint ready"
    );

    Ok(bound)
}

/// Builds and binds an iroh endpoint on `port` with the N0 preset and (when
/// requested + compiled in) the Tor custom transport. Factored out so the caller
/// can retry with a different port after a collision. Port `0` means ephemeral.
///
/// Both families are bound, on the unspecified address of each: `0.0.0.0:port`
/// and `[::]:port`. Clearing the preset's IP transports to pin the port drops
/// *both* of the sockets it pre-configures, so re-adding only the v4 one would
/// leave the node without a v6 underlay: no direct v6 path, no v6 candidate
/// published, and a peer on an IPv6-only network reachable through a relay only.
/// The v6 bind is best-effort (`set_is_required(false)`), matching the preset,
/// since a host with IPv6 disabled must still start.
async fn bind_endpoint(
    secret_key: &SecretKey,
    alpns: &[Vec<u8>],
    posture: NodePosture,
    port: u16,
    relay: &ServerOverride,
    discovery: &ServerOverride,
    nameservers: &[Ipv4Addr],
) -> Result<BoundEndpoint> {
    #[allow(unused_mut)]
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .alpns(alpns.to_vec())
        .clear_ip_transports()
        // Rayfish's data plane is a single stream of QUIC datagrams per peer
        // (TUN packets → `send_datagram`), with a few reliable control streams per
        // connection. Tune the transport config for that shape:
        //   - `send_fairness(false)`: no competing data streams of equal priority
        //     to round-robin, so fairness scheduling is pure overhead. (Affects
        //     stream scheduling only, not datagrams, but is the correct setting and
        //     removes a small amount of per-packet work.)
        //   - GSO on (default): confirmed explicit so a future change can't silently
        //     regress it. GSO coalesces same-destination segments into one sendmsg,
        //     cutting syscalls under burst.
        //   - Datagrams enabled (iroh/noq default `Some` receive buffer); the send
        //     buffer stays at the 1 MiB default, sized via `datagram_send_buffer_space`
        //     on the hot path (see `forward::run_mesh`).
        // The congestion controller stays at the noq default (Cubic). Switching to
        // BBR3 would help on lossy/shallow-buffer consumer uplinks but requires a
        // `noq-proto` dependency to reach the config type, deferred to a measured
        // follow-up (see iroh-audit BASELINE.md, cross-parameter sweep).
        .transport_config(quic_transport_config())
        // Drop overlay addresses from the gathered direct-address candidates, so a
        // mesh IP bound on the TUN is never stored, published, or offered as a
        // holepunch / NAT-traversal candidate (and so never dialed by a peer, which
        // would loop the underlay back through the tunnel). Stays bound to `0.0.0.0`,
        // so multi-homing / roaming is unaffected.
        .direct_addr_filter(OverlayAddrFilter);

    // A Tor posture binds no UDP socket at all. Skipping these two is what makes
    // the node unpublishable rather than merely unpublished: with no socket there
    // are no direct addresses to gather, so there is nothing for an address-lookup
    // service to advertise even if one were installed.
    if !posture.is_tor_only() {
        builder = builder
            .bind_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .context("invalid IPv4 bind address")?
            .bind_addr_with_opts(
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
                BindOpts::default().set_is_required(false),
            )
            .context("invalid IPv6 bind address")?;
    }

    // Resolve our own names (the relay, the pkarr server) against an explicit
    // list instead of iroh's default, which reads the host's resolv.conf at bind
    // and keeps it for the endpoint's life. Two things follow from that default:
    // a host whose nameserver stopped answering takes the daemon's control plane
    // with it, and a resolv.conf that already points at our magic IP (a restart
    // before the revert, a crash) makes the control plane wait on the data plane
    // it exists to bring up. Not setting `with_system_defaults` is deliberate:
    // hickory then never reads the file, so neither can come back.
    //
    // Empty means we had no way to read the host's resolvers (Android reads them
    // over JNI, and its own resolver honours the device's Private DNS), so leave
    // iroh's default in place there.
    if !nameservers.is_empty() {
        builder = builder.dns_resolver(
            DnsResolver::builder()
                .with_nameservers(
                    nameservers
                        .iter()
                        .map(|ip| (SocketAddr::from((*ip, 53u16)), DnsProtocol::Udp)),
                )
                .build(),
        );
    }

    // Loop prevention for the exit-node client full-tunnel: keep iroh's own sockets
    // (the underlay UDP sockets and the relay connection) off the default route that
    // `ray up` points into the TUN, instead of looping the transport back through the
    // tunnel it is carrying. See `exit_node::LoopPrevention`.
    builder = builder.configure_socket(crate::exit_node::LoopPrevention);

    if posture.is_tor_only() {
        // Everything that could reach the network in the clear, removed:
        //   - `clear_relay_transports`: a relay is a clearnet TCP connection to a
        //     server that would see this node's address, and onion routing needs
        //     no fallback path anyway.
        //   - `clear_address_lookup`: this is the one that finally drops the N0
        //     preset's `PkarrPublisher`. Until now there was no way to stop
        //     publishing at all, because `apply_discovery` only ever swapped one
        //     publisher for another.
        // The Tor transport's own lookup is added below, and it resolves a peer's
        // address from its id arithmetically, without touching the network.
        builder = builder.clear_relay_transports().clear_address_lookup();
    } else {
        // Override the N0 preset's relay / discovery defaults when configured.
        if let Some(mode) = build_relay_mode(relay)? {
            builder = builder.relay_mode(mode);
        }
        builder = apply_discovery(builder, discovery)?;
    }

    #[allow(unused_mut)]
    let mut guard = TransportGuard::default();

    #[cfg(feature = "tor")]
    if posture.is_tor_only() {
        let tor_transport = iroh_tor_transport::TorCustomTransport::builder()
            .build(secret_key.clone())
            .await
            .context("failed to create Tor transport — is Tor running with ControlPort 9051?")?;
        builder = builder
            .add_custom_transport(
                tor_transport.clone() as Arc<dyn iroh::endpoint::transports::CustomTransport>
            )
            .address_lookup(tor_transport.discovery());
        // Keeping this is not bookkeeping: dropping it makes tor delete the onion
        // service, silently and permanently. See `TransportGuard`.
        guard._tor = Some(tor_transport);
        tracing::info!("Tor transport enabled (Tor only)");
    }

    #[cfg(not(feature = "tor"))]
    if posture.is_tor_only() {
        anyhow::bail!(
            "Tor mode requires a build with --features tor\n    \
             turn it off with: ray up --no-tor"
        );
    }

    let endpoint = builder
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;
    Ok(BoundEndpoint { endpoint, guard })
}

/// Tailscale's IPv6 ULA range. Its IPv4 half is inside `100.64.0.0/10`, which
/// [`crate::membership::is_overlay_ip`] already covers, but the v6 half looks
/// like an ordinary private address to iroh. Named here rather than in
/// `membership` because it is not *our* overlay: this is only about what we
/// publish, not about what counts as a mesh address.
const TAILSCALE_ULA: (u16, u16, u16) = (0xfd7a, 0x115c, 0xa1e0);

/// True for an address belonging to another VPN's overlay, which we must not
/// advertise as a way to reach this node.
fn is_foreign_overlay_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0], s[1], s[2]) == TAILSCALE_ULA
        }
        std::net::IpAddr::V4(_) => false,
    }
}

/// A [`DirectAddrFilter`] that drops rayfish overlay addresses (`100.64.0.0/10`,
/// `200::/7`) from iroh's gathered direct-address candidates. The mesh IP is bound
/// on the TUN device; without this iroh would discover it, advertise it (pkarr/DNS
/// and in-band NAT-traversal), and peers would dial it, looping the underlay back
/// through the tunnel we carry.
///
/// Another VPN's overlay is dropped too. A host running rayfish alongside
/// Tailscale would otherwise publish its tailnet address in a public pkarr
/// record: it names a network no rayfish peer can route to, and it leaks the
/// fact (and address) of that tailnet to anyone who reads the record.
#[derive(Debug)]
struct OverlayAddrFilter;

impl DirectAddrFilter for OverlayAddrFilter {
    fn keeps(&self, ip: std::net::IpAddr) -> bool {
        !crate::membership::is_overlay_ip(ip)
            && !matches!(ip, IpAddr::V4(v4) if crate::membership::is_cgnat_range(v4))
            && !is_foreign_overlay_ip(ip)
    }
}

/// Builds the [`QuicTransportConfig`] for rayfish's data-plane shape (one stream
/// of QUIC datagrams per peer, plus a few reliable control streams).
///
/// Starts from iroh's builder defaults (which carry the multipath / NAT-traversal
/// / heartbeat settings required for holepunching) and only overrides the
/// datagram-relevant knobs. See `bind_endpoint` for the rationale.
fn quic_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        // No competing data streams of equal priority → disable round-robin
        // fairness scheduling (removes overhead; correct for a single datagram
        // stream per peer).
        .send_fairness(false)
        // Keep GSO on (default) explicitly so a future change can't silently
        // regress it.
        .enable_segmentation_offload(true)
        .build()
}

/// Build a custom [`RelayMode`] from a relay override, or `None` when unset (in
/// which case the N0 preset's default relays are kept). Replace mode uses only
/// the configured relays; augment mode appends n0's default relay URLs so the
/// node keeps the n0 fallback.
pub fn build_relay_mode(o: &ServerOverride) -> Result<Option<RelayMode>> {
    let urls = crate::config::relay_urls(o)?;
    if urls.is_empty() {
        return Ok(None);
    }
    let mut parsed: Vec<RelayUrl> = urls
        .iter()
        .map(|u| u.parse().with_context(|| format!("invalid relay URL: {u}")))
        .collect::<Result<_>>()?;
    if !o.replace {
        parsed.extend(RelayMode::Default.relay_map().urls::<Vec<RelayUrl>>());
    }
    Ok(Some(RelayMode::custom(parsed)))
}

/// Apply a discovery-DNS override to the endpoint builder. Each configured URL
/// is registered as a pkarr publisher + resolver. Replace mode first clears the
/// preset's address-lookup services (n0 pkarr/DNS); augment mode stacks on top.
fn apply_discovery(mut builder: Builder, o: &ServerOverride) -> Result<Builder> {
    let urls = crate::config::discovery_urls(o)?;
    if urls.is_empty() {
        return Ok(builder);
    }
    if o.replace {
        builder = builder.clear_address_lookup();
    }
    for u in urls {
        let url: url::Url = u
            .parse()
            .with_context(|| format!("invalid discovery URL: {u}"))?;
        builder = builder
            .address_lookup(PkarrPublisher::builder(url.clone()))
            .address_lookup(PkarrResolver::builder(url));
    }
    Ok(builder)
}

pub async fn accept_connection_with_alpn(ep: &Endpoint) -> Result<(Connection, Vec<u8>)> {
    let incoming = ep.accept().await.context("no incoming connection")?;
    let conn = incoming.await.context("failed to accept connection")?;
    let alpn = conn.alpn().to_vec();
    tracing::info!(
        peer = %conn.remote_id().fmt_short(),
        alpn = %String::from_utf8_lossy(&alpn),
        "peer connected"
    );
    Ok((conn, alpn))
}

/// Connects to a peer by EndpointId with a specific ALPN. iroh handles
/// NAT traversal and falls back to relay if direct connection fails.
pub async fn connect_to_peer_with_alpn(
    ep: &Endpoint,
    id: EndpointId,
    alpn: &[u8],
) -> Result<Connection> {
    let addr: EndpointAddr = id.into();
    let conn = match ep.connect(addr, alpn).await {
        Ok(conn) => conn,
        // An ALPN mismatch fails the QUIC/TLS handshake opaquely. Map that one
        // case to an actionable hint (it's a heuristic: a peer that isn't
        // running rayfish at all looks similar, hence "may be").
        Err(e) if is_alpn_mismatch(&e.to_string()) => {
            return Err(e).context(
                "no shared protocol with peer — it may be running an incompatible \
                 rayfish version (run `ray update`)",
            );
        }
        Err(e) => return Err(e).context("failed to connect to peer"),
    };
    tracing::info!(
        peer = %conn.remote_id().fmt_short(),
        alpn = %String::from_utf8_lossy(alpn),
        "connected to peer"
    );
    Ok(conn)
}

/// Heuristic: does a connect error look like an ALPN mismatch (no protocol the
/// two peers share)? iroh/quinn surfaces this as "peer doesn't support any known
/// protocol" / a TLS `no_application_protocol` alert. Matching the message keeps
/// us robust across iroh patch releases without depending on exact error enums.
pub(crate) fn is_alpn_mismatch(err: &str) -> bool {
    let e = err.to_lowercase();
    e.contains("known protocol") || e.contains("application protocol")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real composition, against a live Tor daemon. Ignored by default: it
    /// needs `tor` running with `ControlPort 9051`, takes ~10s for the descriptor
    /// to publish, and talks to the public Tor network.
    ///
    /// Run with: `cargo test --features tor -- --ignored tor_posture_binds`
    ///
    /// What it pins is the pair of claims the design rests on: a Tor node gathers
    /// no address at all (so it can publish none), and the guard that keeps its
    /// onion service alive is actually populated. The second matters more than it
    /// looks: dropping it leaves a node that binds, reports healthy, and is
    /// unreachable forever (see [`TransportGuard`]).
    #[tokio::test]
    #[ignore = "needs a Tor daemon with ControlPort 9051"]
    #[cfg(feature = "tor")]
    async fn tor_posture_binds_nothing_and_keeps_its_service() {
        let bound = create_endpoint_with_alpns(
            SecretKey::generate(),
            vec![b"test/1".to_vec()],
            NodePosture::Tor,
            &ServerOverride::default(),
            &ServerOverride::default(),
            &ServerOverride::default(),
        )
        .await
        .expect("a Tor endpoint binds");

        assert!(
            bound.endpoint.bound_sockets().is_empty(),
            "a Tor posture must bind no UDP socket: {:?}",
            bound.endpoint.bound_sockets()
        );
        assert!(
            bound.guard._tor.is_some(),
            "the onion service's control connection must be held, or tor deletes it"
        );
        bound.endpoint.close().await;
    }

    /// The two settings are orthogonal, and every combination is a real state a
    /// node can be in. Pinned because the whole design rests on them composing
    /// rather than one implying the other.
    #[test]
    fn posture_is_the_product_of_the_two_settings() {
        use NodePosture::*;
        assert_eq!(NodePosture::new(false, false), Open);
        assert_eq!(NodePosture::new(false, true), Tor);
        assert_eq!(NodePosture::new(true, false), Private);
        assert_eq!(NodePosture::new(true, true), PrivateTor);

        // Tor-only is what decides whether a UDP socket is bound at all, and it
        // is exactly the two Tor arms: `Private` alone still binds and publishes.
        assert!(!Open.is_tor_only());
        assert!(Tor.is_tor_only());
        assert!(!Private.is_tor_only());
        assert!(PrivateTor.is_tor_only());

        assert!(!Open.is_private());
        assert!(!Tor.is_private());
        assert!(Private.is_private());
        assert!(PrivateTor.is_private());
    }

    /// A Tor posture must bind no UDP socket, so the port it would have used is
    /// irrelevant. Guards against someone "fixing" the skipped bind by making it
    /// conditional on the port instead of the posture.
    #[tokio::test]
    async fn a_tor_posture_binds_no_socket_and_publishes_nothing() {
        // Without the `tor` feature the composition is unreachable by design and
        // `bind_endpoint` says so rather than silently binding in the clear.
        #[cfg(not(feature = "tor"))]
        {
            let err = bind_endpoint(
                &SecretKey::generate(),
                &[b"test/1".to_vec()],
                NodePosture::Tor,
                0,
                &ServerOverride::default(),
                &ServerOverride::default(),
                &[],
            )
            .await
            .expect_err("a Tor posture cannot bind without the feature");
            assert!(
                err.to_string().contains("--features tor"),
                "the error must name what is missing: {err}"
            );
        }

        // With the feature, binding needs a live Tor daemon, so this asserts the
        // half that holds without one: an Open posture still binds normally, and
        // the Tor branch is not silently taken for it.
        let bound = bind_endpoint(
            &SecretKey::generate(),
            &[b"test/1".to_vec()],
            NodePosture::Open,
            0,
            &ServerOverride::default(),
            &ServerOverride::default(),
            &[],
        )
        .await
        .expect("an open posture binds");
        assert!(
            !bound.endpoint.bound_sockets().is_empty(),
            "an open posture binds at least one socket"
        );
        bound.endpoint.close().await;
    }

    #[test]
    fn overlay_addr_filter_keeps_only_non_overlay() {
        use std::net::IpAddr;
        let keeps = |s: &str| OverlayAddrFilter.keeps(s.parse::<IpAddr>().unwrap());
        // Real underlay / LAN addresses are kept.
        assert!(keeps("51.15.139.151"));
        assert!(keeps("192.168.1.104"));
        // An ordinary ULA is a real (if private) underlay path, so it stays.
        assert!(keeps("fd00:1234:5678::1"));
        // Overlay v4 (100.64.0.0/10) and v6 (200::/7) are dropped.
        assert!(!keeps("100.124.253.88"));
        assert!(!keeps("200::1"));
        // So is another VPN's overlay: a tailnet address names a network no
        // rayfish peer can route to, and publishing it leaks the tailnet.
        assert!(!keeps("fd7a:115c:a1e0::1"));
        assert!(!keeps("fd7a:115c:a1e0:ab12:4843:cd96:1234:5678"));
    }

    /// The one property that must hold whatever the host's file says: the
    /// daemon never asks our own resolver for the names it needs to reach the
    /// network. Anything else and a restart that finds our own resolv.conf still
    /// in place waits on the data plane it is trying to bring up.
    #[test]
    fn control_plane_never_points_at_an_overlay_resolver() {
        let magic = crate::dns::MAGIC_DNS_V4;
        let tailnet: Ipv4Addr = "100.100.100.100".parse().unwrap();
        let got = control_plane_nameservers(&ServerOverride::default(), Some(vec![magic, tailnet]));
        assert!(!got.contains(&magic));
        assert!(!got.contains(&tailnet));
        // And it still has somewhere to ask.
        assert!(!got.is_empty());
    }

    #[test]
    fn control_plane_falls_back_to_public_when_the_host_has_no_resolver() {
        let got = control_plane_nameservers(&ServerOverride::default(), Some(vec![]));
        assert_eq!(got, PUBLIC_FALLBACK_DNS.to_vec());
    }

    /// A platform whose resolvers we cannot read is not a host without any: it
    /// keeps iroh's own reader, which on Android goes through JNI and honours
    /// the device's Private DNS. Naming a public server there would downgrade
    /// those lookups to cleartext.
    #[test]
    fn control_plane_defers_where_the_host_config_is_unreadable() {
        assert!(control_plane_nameservers(&ServerOverride::default(), None).is_empty());

        // Unless the operator named servers, which is an explicit instruction
        // and applies on every platform.
        let custom: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let o = ServerOverride {
            servers: vec![custom.to_string()],
            replace: false,
        };
        assert_eq!(control_plane_nameservers(&o, None)[0], custom);
    }

    #[test]
    fn control_plane_prefers_the_host_then_the_fallback() {
        let lan: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let got = control_plane_nameservers(&ServerOverride::default(), Some(vec![lan]));
        assert_eq!(got[0], lan, "the host's own resolver is asked first");
        assert_eq!(got[1..], PUBLIC_FALLBACK_DNS);
    }

    #[test]
    fn control_plane_honors_the_operator() {
        let lan: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let custom: Ipv4Addr = "9.9.9.9".parse().unwrap();

        // Augment: the operator's server first, then the host's, then public.
        let aug = ServerOverride {
            servers: vec![custom.to_string()],
            replace: false,
        };
        let got = control_plane_nameservers(&aug, Some(vec![lan]));
        assert_eq!(
            got,
            vec![custom, lan, PUBLIC_FALLBACK_DNS[0], PUBLIC_FALLBACK_DNS[1]]
        );

        // Replace means only these: no host resolver, and no public fallback
        // added behind the operator's back.
        let rep = ServerOverride {
            servers: vec![custom.to_string()],
            replace: true,
        };
        assert_eq!(
            control_plane_nameservers(&rep, Some(vec![lan])),
            vec![custom]
        );
    }

    #[test]
    fn control_plane_dedupes_and_caps() {
        let lan: Ipv4Addr = "192.168.1.1".parse().unwrap();
        // A host that already lists a public resolver must not get it twice.
        let got = control_plane_nameservers(
            &ServerOverride::default(),
            Some(vec![lan, PUBLIC_FALLBACK_DNS[0], lan]),
        );
        assert_eq!(
            got,
            vec![lan, PUBLIC_FALLBACK_DNS[0], PUBLIC_FALLBACK_DNS[1]]
        );

        // A long resolv.conf is truncated rather than fanned out over.
        let many: Vec<Ipv4Addr> = (1..=8).map(|i| Ipv4Addr::new(192, 168, 1, i)).collect();
        let got = control_plane_nameservers(&ServerOverride::default(), Some(many.clone()));
        assert_eq!(got.len(), MAX_CONTROL_PLANE_NAMESERVERS);
        assert_eq!(got, many[..MAX_CONTROL_PLANE_NAMESERVERS]);
    }

    #[test]
    fn test_mesh_alpn() {
        // The mesh ALPN is a single node-wide protocol id, no per-network suffix.
        let expected = format!("rayfish/mesh/{MESH_PROTOCOL_VERSION}");
        assert_eq!(mesh_alpn(), expected.as_bytes());
    }

    #[test]
    fn relay_mode_augment_vs_replace() {
        // Unset: keep the preset default (None).
        assert!(
            build_relay_mode(&ServerOverride::default())
                .unwrap()
                .is_none()
        );

        // A parseable relay URL (iroh RelayUrl requires a host).
        let custom = "https://relay.example.com".to_string();

        // Replace: only the custom relay.
        let rep = ServerOverride {
            servers: vec![custom.clone()],
            replace: true,
        };
        let mode = build_relay_mode(&rep).unwrap().expect("some mode");
        assert_eq!(mode.relay_map().urls::<Vec<RelayUrl>>().len(), 1);

        // Augment: custom + n0 defaults (more than one).
        let aug = ServerOverride {
            servers: vec![custom],
            replace: false,
        };
        let mode = build_relay_mode(&aug).unwrap().expect("some mode");
        assert!(mode.relay_map().urls::<Vec<RelayUrl>>().len() > 1);
    }

    #[test]
    fn alpn_mismatch_classifier() {
        // iroh/quinn phrasings for "no shared ALPN".
        assert!(is_alpn_mismatch(
            "connection closed: peer doesn't support any known protocol"
        ));
        assert!(is_alpn_mismatch(
            "the cryptographic handshake failed: no application protocol"
        ));
        // Unrelated failures must not be misclassified as version mismatches.
        assert!(!is_alpn_mismatch("connection timed out"));
        assert!(!is_alpn_mismatch("connection refused"));
    }
}
