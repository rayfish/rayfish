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
pub const CONNECT_ALPN: &[u8] = b"rayfish/connect/3";

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

/// Creates an iroh endpoint with the N0 preset (NAT traversal + relay fallback).
/// When `tor` is true and the `tor` feature is enabled, adds the Tor custom transport
/// alongside the default relay transport.
pub async fn create_endpoint_with_alpns(
    secret_key: SecretKey,
    alpns: Vec<Vec<u8>>,
    tor: bool,
    relay: &ServerOverride,
    discovery: &ServerOverride,
    dns_upstreams: &ServerOverride,
) -> Result<Endpoint> {
    // Bind the fixed port so the daemon is reachable on a known, forwardable UDP
    // port across restarts. The builder is consumed by `.bind()`, so we rebuild
    // it for the ephemeral fallback. Falling back to port 0 keeps the guarantee
    // that the daemon always starts even if the fixed port is already in use.
    // Read the host's resolvers once, here, rather than per bind attempt: the
    // second attempt runs after the first failed, and this must be the host's
    // configuration as it stood before anything of ours touched it.
    let nameservers =
        control_plane_nameservers(dns_upstreams, crate::dns::config::system_nameservers());
    tracing::debug!(?nameservers, "control-plane DNS");

    let ep = match bind_endpoint(
        &secret_key,
        &alpns,
        tor,
        RAYFISH_LISTEN_PORT,
        relay,
        discovery,
        &nameservers,
    )
    .await
    {
        Ok(ep) => ep,
        Err(e) => {
            tracing::warn!(
                port = RAYFISH_LISTEN_PORT,
                error = %e,
                "fixed UDP port unavailable; falling back to an ephemeral port"
            );
            bind_endpoint(&secret_key, &alpns, tor, 0, relay, discovery, &nameservers)
                .await
                .context("failed to bind iroh endpoint")?
        }
    };

    tracing::info!(id = %ep.id().fmt_short(), "iroh endpoint ready");

    Ok(ep)
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
    tor: bool,
    port: u16,
    relay: &ServerOverride,
    discovery: &ServerOverride,
    nameservers: &[Ipv4Addr],
) -> Result<Endpoint> {
    #[allow(unused_mut)]
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .alpns(alpns.to_vec())
        .clear_ip_transports()
        .bind_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
        .context("invalid IPv4 bind address")?
        .bind_addr_with_opts(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
            BindOpts::default().set_is_required(false),
        )
        .context("invalid IPv6 bind address")?
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

    // Override the N0 preset's relay / discovery defaults when configured.
    if let Some(mode) = build_relay_mode(relay)? {
        builder = builder.relay_mode(mode);
    }
    builder = apply_discovery(builder, discovery)?;

    #[cfg(feature = "tor")]
    if tor {
        let tor_transport = iroh_tor_transport::TorCustomTransport::builder()
            .build(secret_key.clone())
            .await
            .context("failed to create Tor transport — is Tor running with ControlPort 9051?")?;
        builder = builder
            .add_custom_transport(
                tor_transport.clone() as Arc<dyn iroh::endpoint::transports::CustomTransport>
            )
            .address_lookup(tor_transport.discovery());
        tracing::info!("Tor transport enabled");
    }

    #[cfg(not(feature = "tor"))]
    if tor {
        anyhow::bail!("Tor support requires building with --features tor");
    }

    builder.bind().await.context("failed to bind iroh endpoint")
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
