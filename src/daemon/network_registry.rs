//! `NetworkRegistry`: the service that owns the set of active networks.
//!
//! This is the seam that the `Daemon` network methods (create / join /
//! leave / coordinator / reconverge / …) migrate onto over the course of the
//! decomposition. It owns the per-network runtime handles keyed by name; during
//! the transition it shares the same `Arc<DashMap>` the daemon still holds, so
//! methods can move here one at a time while the tree stays green.
//!
//! It is a control-plane service: never on the packet path. Membership queries
//! (like the file auto-accept gate) and the coordinator/member operations live
//! here so leaf tasks and other services can call them directly instead of
//! signalling the daemon through a channel.

use super::*;
use arc_swap::{ArcSwap, ArcSwapOption};
use futures::future::BoxFuture;
use iroh_dns::pkarr::SignedPacket;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Notify;

/// Upper bound on a single on-demand dial. The first packets of a flow wait at
/// most this long for the connection; past it the buffered packets are dropped and
/// the peer is marked unreachable until a later packet retries the dial.
const LAZY_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on delivering a `ray leave` before the network is torn down: a
/// dial ([`LAZY_DIAL_TIMEOUT`]) plus its acknowledgement, with room to spare. A
/// leave is attempted once, so this is how long an unreachable coordinator can
/// hold up `ray leave`.
const LEAVE_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `ray rename` waits for a coordinator network to come back under its
/// new name before replying. Restoring one is local, so this is only a bound;
/// past it the restore carries on in the background.
const RENAME_RESTORE_WAIT: Duration = Duration::from_secs(10);

/// How long re-authorizing a device that pairs again waits for the records
/// that no longer nullify it to be published, before the pairing is refused
/// ([`NetworkRegistry::reauth_device_locked`]). A failed publish is retried
/// after five seconds, so this leaves room for a second attempt.
const REAUTHORIZATION_PUBLISH_WAIT: Duration = Duration::from_secs(10);

/// Finish a `ray rename` that a crash interrupted, from the intent it saved
/// before anything moved ([`config::rename_network`]): move the network's file
/// and the name inside it if either is left, and point the firewall rules that
/// name the network at its new name. Runs at startup before anything reads the
/// saved networks or the firewall, so no network is restored under a name its
/// file no longer has. The rest of what a rename moves is runtime state, built
/// from the config afterwards.
pub(crate) fn finish_interrupted_rename() {
    let intent = match config::rename_intent() {
        Ok(Some(intent)) => intent,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "could not read an unfinished network rename");
            return;
        }
    };
    let finished = config::finish_rename(&intent).and_then(|net| {
        if net.is_some() {
            let mut rules = firewall::load_firewall()?;
            if rules.rename_network(&intent.from, &intent.to) {
                firewall::save_firewall(&rules)?;
            }
        }
        config::clear_rename_intent().map(|()| net.is_some())
    });
    let (from, to) = (intent.from.as_str(), intent.to.as_str());
    match finished {
        Ok(true) => tracing::info!(from, to, "finished an interrupted network rename"),
        Ok(false) => tracing::warn!(
            from,
            to,
            "dropped an interrupted network rename: the network is gone, or another one is saved under the new name"
        ),
        Err(e) => {
            tracing::warn!(from, to, error = %format!("{e:#}"), "could not finish an interrupted network rename")
        }
    }
}

fn network_key_from_selector(selector: &str) -> Option<EndpointId> {
    selector.parse().ok().or_else(|| {
        crate::invite::decode_invite_code(selector)
            .ok()
            .map(|decoded| decoded.network_key)
    })
}

/// What holds a local network name on this node. The name is also the file name
/// of the network's config (`networks/<name>.toml`), so it stays held while only
/// that file is left, as for a network whose restore has not landed: saving
/// another network under it would replace that network's config, keys included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameOwner {
    Free,
    /// The network with this key, active or only saved.
    Network(EndpointId),
    /// A saved config that records no network key, so it is no network's own.
    Unknown,
}

/// `base` with `-{suffix}` appended, cut short so the result is still a valid
/// name (`hostname::is_valid_hostname`): at most 63 characters, and no hyphen left
/// at the cut to run into the suffix's own.
fn suffixed_name(base: &str, suffix: u32) -> String {
    const MAX_LEN: usize = 63;
    let tail = format!("-{suffix}");
    let stem: String = base
        .chars()
        .take(MAX_LEN.saturating_sub(tail.len()))
        .collect();
    format!("{}{tail}", stem.trim_end_matches('-'))
}

/// One network to (re)handshake when dialing a peer: its name and the per-network
/// public key that signs the `MeshHello`. A peer's single connection carries every
/// shared network, so a dial takes a slice of these.
#[derive(Clone)]
pub(crate) struct DialTarget {
    pub network: String,
    pub network_key: EndpointId,
}

pub(crate) struct CurrentSignedNetworkState {
    pub(crate) hash: blake3::Hash,
    pub(crate) packet: Vec<u8>,
    pub(crate) published: bool,
    pub(crate) members: Vec<Member>,
    pub(crate) approved: Vec<ApprovedEntry>,
    pub(crate) key: SecretKey,
}

/// What the rosters held here say about one endpoint.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RosterStanding {
    /// The user identity a roster binds this device to. Rosters are
    /// coordinator-signed, so this is not the dialer's own claim.
    pub(crate) user_identity: Option<EndpointId>,
    /// A member (device or user identity) or approved entry somewhere, or this
    /// device's paired primary.
    pub(crate) known: bool,
}

pub(crate) struct NetworkRegistry {
    /// Per-network runtime handles, keyed by network name. Shared with
    /// `Daemon` during the transition (same `Arc`), so a method can move to
    /// the registry without splitting the map.
    // Fields are `pub(crate)` because the network methods migrating onto the
    // registry live in their existing `daemon/mesh/*.rs` files (as `impl
    // NetworkRegistry` blocks), which are sibling modules and so cannot see
    // module-private fields. Mirrors how `Daemon`'s fields are reached.
    pub(crate) networks: Arc<DashMap<String, NetworkHandle>>,
    /// Foundation handles (endpoint + blob store) for reseal/publish.
    pub(crate) transport: Arc<Transport>,
    /// Live peer routing table, for severing / notifying peers on roster change.
    pub(crate) peers: PeerTable,
    /// Shares outbound mesh dials per peer. Pairing joins several networks at
    /// once; checking the peer table alone would let every join dial before any
    /// of them has installed the shared connection.
    mesh_dialer: MeshDialer,
    /// The per-peer connection driver, so the registry can (re-)register a
    /// network's accept handler (coordinator promotion) or unregister it on
    /// teardown directly.
    pub(crate) conn: Arc<ConnectionManager>,
    /// Magic-DNS service, to clear a torn-down network's `.ray` entries.
    pub(crate) dns: Arc<DnsService>,
    /// The TUN interface name, shared with the daemon (which sets it once the TUN
    /// is up), for refreshing DNS search domains after a network is torn down.
    pub(crate) tun_name: Arc<ArcSwap<String>>,
    /// This device's cert loaded at boot, the in-memory fallback for the paired
    /// check when the on-disk cert read errors (see [`Self::current_device_cert`]).
    pub(crate) device_cert: Option<control::DeviceCert>,
    /// Daemon-wide shutdown token; each network's cancel is a child of it.
    pub(crate) shutdown_token: CancellationToken,
    /// Per-device firewall, threaded into the [`MeshCtx`] handler bundle.
    pub(crate) firewall: SharedFirewall,
    /// Transport-key -> user-identity map, threaded into the [`MeshCtx`] bundle.
    pub(crate) device_user_map: peers::DeviceUserMap,
    /// Sender to the single TUN writer, threaded into peer readers via [`MeshCtx`].
    pub(crate) tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
    /// Roster-pruned peers to skip on reconnect (see [`MeshCtx::pruned_peers`]).
    pub(crate) pruned_peers: Arc<DashSet<(String, EndpointId)>>,
    /// IP -> roster member map (no connection required), so the on-demand data
    /// path can turn a destination IP into the peer to lazily dial. Populated
    /// wherever the roster is applied; queried by the forwarding loop + dialer.
    pub(crate) route_map: peers::RosterRouteMap,
    /// Per-peer dial outcome history: drives the on-demand dialer cooldown and the
    /// idle/offline distinction in `ray status`.
    pub(crate) reachability: peers::Reachability,
    /// Daemon-wide disconnect channel drained by the connection supervisor.
    pub(crate) disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
    /// The inbound QUIC router, needed to drive a freshly (re)dialed connection's
    /// control demux. Built after the registry (it depends on FileService /
    /// ConnectService, which depend on the registry), so it is set once at boot
    /// via [`Self::set_protocol_router`] rather than passed to `new`.
    protocol_router: OnceLock<Arc<ProtocolRouter>>,
    /// On-demand mode: run the per-connection idle timer that closes a link idle
    /// past [`idle_timeout`](Self::idle_timeout), and never auto-reconnect an
    /// idle-closed peer (re-dialing is lazy). See [`Daemon::on_demand`](crate::daemon::Daemon).
    pub(crate) on_demand: bool,
    /// How long a connection may sit with no traffic (either direction) before an
    /// on-demand node idle-closes it. Read by each [`MeshConnection`]'s idle timer.
    pub(crate) idle_timeout: Duration,
    /// Per-network exit-node allow policy, threaded into peer readers via the
    /// [`MeshCtx`] forward context and populated on `activate()` from config.
    pub(crate) exit_server: crate::exit_node::ExitServer,
    /// Client-side exit-node selection: the peer this node routes its non-mesh
    /// traffic through. Read by the forwarding loop (outbound) and peer readers
    /// (return traffic); populated on `activate()` from config.
    pub(crate) exit_client: crate::exit_node::ExitClient,
    /// Set while the config selects an exit peer that the roster cannot resolve
    /// yet (boot before reconverge, or the peer temporarily absent). A reconverge
    /// that lands a roster then nudges [`Self::exit_reapply`] so the daemon
    /// re-runs the exit reconcile instead of leaking traffic until the next
    /// `ray up`.
    pub(crate) exit_selection_pending: AtomicBool,
    /// The last failure from installing the client full tunnel, or `None` when
    /// the last attempt succeeded (or there was nothing to install).
    ///
    /// A failed install rolls its own rules back and leaves the *selection* in
    /// place, which is right (the next re-apply retries it) but makes the
    /// selection a poor answer to "is traffic being tunnelled". `ray exit-node
    /// status` reads this so the answer comes from what the kernel accepted
    /// rather than from what the config asked for.
    pub(crate) exit_install_error: ArcSwapOption<String>,
    /// Nudged by reconverge via [`NetworkRegistry::nudge_exit_reapply`]; the
    /// daemon listens and re-runs `apply_exit_node`. A channel rather than a
    /// direct call because the kernel plumbing lives on `Daemon`, above the
    /// registry in the service graph.
    pub(crate) exit_reapply: Arc<Notify>,
    /// Whether exit-offer advertisements may be synced to the roster right now:
    /// true only between `activate()` and `deactivate()`. Keeps a reconverge that
    /// fires while the data plane is down (boot, standby) from withdrawing an
    /// offer that `activate()` is about to re-advertise.
    pub(crate) exit_sync_enabled: AtomicBool,
    /// Networks that a create or restore is bringing up right now, each held by
    /// a [`RegistrationClaim`]. A sweep skips them: a create saves the config
    /// before its handle is registered, and a restore started in that gap would
    /// run a second coordinator state for the same network. See
    /// [`NetworkRegistry::claim_registration`].
    pub(crate) restoring: Arc<DashSet<String>>,
    /// Why each saved-but-unregistered network's last restore attempt failed,
    /// keyed by network name. `ray status` reports it beside the network so a
    /// failed restore says what went wrong instead of sending the reader to the
    /// daemon log. Cleared when the restore lands or gives up.
    pub(crate) restore_errors: Arc<DashMap<String, String>>,
    /// Nudges [`Self::run_restore_supervisor`] to sweep now instead of at its
    /// next tick. Fired when a peer sends a control frame for a network we have
    /// saved but not live: their traffic is proof the network is reachable
    /// again, so recovery shouldn't wait out the tick.
    pub(crate) restore_nudge: Arc<Notify>,
    /// Nudges every network's group poller to resolve now instead of at its next
    /// tick. Fired when the data plane comes up and when the host reports a
    /// network change: a battery-powered node polls on a long interval, so
    /// without this a phone whose VPN was just switched on could work from a
    /// roster up to that interval stale.
    ///
    /// `notify_waiters` (not `notify_one`): there is a poller per network and
    /// they all want it. That also makes it a hint rather than a guarantee, since
    /// a poller already mid-resolve is not parked on it and misses the wakeup.
    /// The cost of a missed nudge is one tick of staleness, which is what the
    /// poll was for anyway.
    pub(crate) poll_nudge: Arc<Notify>,
    /// Wakes [`Self::run_unpair_requests`] when this device saves an unpair, or
    /// finds the primary of one reachable.
    pub(crate) unpair_nudge: Arc<Notify>,
    /// Held while this device pairs or unpairs itself, and across each attempt
    /// at its saved unpairs, so none of them sees another half done: a request
    /// sent while a pairing with its primary completes would revoke that
    /// pairing, and a pairing must not start before an unpair's cleanup ends.
    pub(crate) unpair_lock: AsyncMutex<()>,
    /// Wakes [`Self::run_unpair_notices`] when `ray unpair` saves a device to
    /// tell.
    pub(crate) notice_nudge: Arc<Notify>,
    /// Held across each revocation of a device and each re-authorization of a
    /// device that paired again, so neither runs in the middle of the other: a
    /// revocation still under way when the device pairs again would put back
    /// the nullifiers the re-authorization clears. Creating, renaming, leaving
    /// and destroying a network hold it too, until the network is saved, saved
    /// under its new name, or gone. A re-authorization checks that every
    /// network this node coordinates runs, then clears the device from each
    /// and waits for their records, and a network that stopped or appeared in
    /// between would keep a record that still nullifies the device.
    pub(crate) revocation_lock: AsyncMutex<()>,
    /// Signalled each time a network's record is confirmed published here, for
    /// a caller waiting until one is ([`Self::reauth_device_locked`]).
    pub(crate) records_published: tokio::sync::watch::Sender<()>,
}

/// One saved network the restore supervisor found missing from the live map,
/// and how it has to be restored. The two paths differ: a coordinator holds the
/// network key and restores locally, a member has to reconverge from the signed
/// record.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MissingNetwork {
    pub name: String,
    /// `None` for a member network (restore needs the pkarr lookup), `Some` for
    /// a coordinator network (we hold the key, so the restore is local).
    pub coordinator_mode: Option<GroupMode>,
}

fn peer_selector_for_network<'a>(network: &str, selector: &'a str) -> Option<&'a str> {
    match selector.strip_suffix(&format!(".{network}.{}", crate::DNS_DOMAIN)) {
        Some(hostname) => Some(hostname),
        None => match selector.strip_suffix(&format!(".{}", crate::DNS_DOMAIN)) {
            Some(name) if !name.contains('.') => Some(name),
            Some(_) => None,
            None => Some(selector),
        },
    }
}

/// Decide which saved networks the supervisor should restore: everything in
/// config that is neither live nor already being restored.
///
/// Split out as a pure function over the three inputs so the decision is
/// testable without a running daemon, which is the part worth pinning down: the
/// sweep runs on a timer and on peer traffic, so starting a duplicate restore
/// (or skipping a genuinely dead network) is the failure mode that matters.
/// A network name held in [`NetworkRegistry::restoring`] while one path brings
/// that network up. Dropping it releases the name, however that path ends.
pub(crate) struct RegistrationClaim {
    claims: Arc<DashSet<String>>,
    name: String,
}

impl Drop for RegistrationClaim {
    fn drop(&mut self) {
        self.claims.remove(&self.name);
    }
}

pub(crate) fn missing_networks(
    saved: &[config::NetworkConfig],
    is_live: impl Fn(&str) -> bool,
    is_restoring: impl Fn(&str) -> bool,
) -> Vec<MissingNetwork> {
    saved
        .iter()
        .filter(|n| !is_live(&n.name) && !is_restoring(&n.name))
        .map(|n| MissingNetwork {
            name: n.name.clone(),
            coordinator_mode: n.network_secret_key.as_ref().map(|_| n.group_mode),
        })
        .collect()
}

pub(crate) fn networks_joined_with_certificate(
    saved: &[config::NetworkConfig],
    primary: EndpointId,
) -> Vec<String> {
    saved
        .iter()
        .filter(|net| net.join_certificate_issuer == Some(primary))
        .map(|net| net.name.clone())
        .collect()
}

impl NetworkRegistry {
    #[allow(clippy::too_many_arguments)] // one clone per shared daemon handle
    pub(crate) fn new(
        networks: Arc<DashMap<String, NetworkHandle>>,
        transport: Arc<Transport>,
        peers: PeerTable,
        conn: Arc<ConnectionManager>,
        dns: Arc<DnsService>,
        tun_name: Arc<ArcSwap<String>>,
        device_cert: Option<control::DeviceCert>,
        shutdown_token: CancellationToken,
        firewall: SharedFirewall,
        device_user_map: peers::DeviceUserMap,
        tun_tx: Arc<arc_swap::ArcSwap<mpsc::Sender<Bytes>>>,
        pruned_peers: Arc<DashSet<(String, EndpointId)>>,
        disconnect_tx: mpsc::Sender<forward::DisconnectEvent>,
        on_demand: bool,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            networks,
            transport,
            peers,
            mesh_dialer: MeshDialer::default(),
            conn,
            dns,
            tun_name,
            device_cert,
            shutdown_token,
            firewall,
            device_user_map,
            tun_tx,
            pruned_peers,
            route_map: peers::RosterRouteMap::new(),
            reachability: peers::Reachability::new(),
            disconnect_tx,
            protocol_router: OnceLock::new(),
            on_demand,
            idle_timeout,
            exit_server: crate::exit_node::ExitServer::new(),
            exit_client: crate::exit_node::ExitClient::new(),
            exit_selection_pending: AtomicBool::new(false),
            exit_install_error: ArcSwapOption::empty(),
            exit_reapply: Arc::new(Notify::new()),
            exit_sync_enabled: AtomicBool::new(false),
            restoring: Arc::new(DashSet::new()),
            restore_errors: Arc::new(DashMap::new()),
            restore_nudge: Arc::new(Notify::new()),
            poll_nudge: Arc::new(Notify::new()),
            unpair_nudge: Arc::new(Notify::new()),
            unpair_lock: AsyncMutex::new(()),
            notice_nudge: Arc::new(Notify::new()),
            revocation_lock: AsyncMutex::new(()),
            records_published: tokio::sync::watch::Sender::default(),
        }
    }

    /// Claim `name` for the one create or restore that may register it, or
    /// `None` while another holds it.
    pub(crate) fn claim_registration(&self, name: &str) -> Option<RegistrationClaim> {
        self.restoring
            .insert(name.to_string())
            .then(|| RegistrationClaim {
                claims: Arc::clone(&self.restoring),
                name: name.to_string(),
            })
    }

    /// A live mesh connection to `peer`, registered or freshly dialed, sharing
    /// any dial to it already in flight. See [`MeshDialer`].
    pub(crate) async fn connect_mesh_peer(&self, peer: EndpointId) -> Result<DialedPeer> {
        self.mesh_dialer
            .connect(&self.transport.endpoint, &self.peers, peer)
            .await
    }

    /// Resolve a destination mesh IP to a roster member the on-demand forwarding
    /// loop can dial, if we know one. Just a route-map lookup; the loop owns the
    /// packet buffering and dedup.
    pub(crate) fn resolve_route(&self, dst: IpAddr) -> Option<peers::RouteTarget> {
        // Only the IPv6 half of the overlay is routed, so an IPv4 destination
        // never names a roster member to dial.
        match dst {
            IpAddr::V6(v6) => self.route_map.resolve_v6(&v6),
            IpAddr::V4(_) => None,
        }
    }

    /// Resume mesh activity without touching the TUN/DNS plane. The relay stays
    /// connected in idle mode so file offers can still arrive.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) async fn wake_transport(&self) {
        // Avoid an atomic read-modify-write for every packet while mesh links
        // are already active.
        if !self.transport.is_suspended() {
            return;
        }
        if self.transport.mark_awake() {
            tracing::info!("resuming idle mesh links");
            self.transport.sync_relays().await;
            self.transport.endpoint.network_change().await;
            self.poll_nudge.notify_waiters();
            tracing::info!("mesh links resumed after idle");
        }
    }

    /// Go outgoing-only: close mesh connections and drop the relay, keeping
    /// the endpoint, TUN and DNS alive. Every unsolicited packet wakes a
    /// sleeping phone, and the relay alone pings every 15-20 seconds, so an
    /// idle phone is unreachable until it sends something itself.
    /// Disconnect handling sees the suspended flag and must not start retries.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub(crate) async fn suspend_mesh_links(&self) {
        if !self.transport.mark_suspended() {
            return;
        }
        tracing::info!("suspending idle mesh links");
        for (ip, conn) in self.peers.all_connections() {
            conn.close(VarInt::from_u32(forward::IDLE_CODE), b"idle");
            self.peers.remove(&ip);
        }
        self.transport.sync_relays().await;
        tracing::info!("mesh links and relay suspended after idle timeout");
    }

    /// The raw on-demand dial mechanism: connect to `target` across every shared
    /// network (bounded by [`LAZY_DIAL_TIMEOUT`]) and register its route, recording
    /// the outcome for status + cooldown. Returns whether a connection was
    /// established (the caller then flushes any buffered packets). The forwarding
    /// loop owns the buffering/dedup and calls this from a spawned task.
    pub(crate) async fn dial_target(self: &Arc<Self>, target: &peers::RouteTarget) -> bool {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        self.wake_transport().await;
        let targets: Vec<DialTarget> = target
            .networks
            .iter()
            .filter_map(|net| {
                self.networks.get(net.as_str()).map(|h| DialTarget {
                    network: net.to_string(),
                    network_key: h.network_key,
                })
            })
            .collect();
        let id = target.endpoint_id;
        // `dial_peer_once` stamps reachability (ok/fail) itself, so the timeout arm
        // is the only failure this path must record separately.
        let ok = !targets.is_empty()
            && match tokio::time::timeout(LAZY_DIAL_TIMEOUT, self.dial_peer_once(id, &targets))
                .await
            {
                Ok(established) => established,
                Err(_elapsed) => {
                    self.reachability.note_fail(id);
                    false
                }
            };
        self.transport.stats.record_lazy_dial(ok);
        ok
    }

    /// Seed the route map from a restored roster so the on-demand data path can
    /// lazily dial members before the first reconverge (self excluded by the
    /// caller-provided list, which should already omit us).
    pub(crate) fn seed_route_map(&self, network: &str, members: &[Member]) {
        let my_id = self.transport.identity.local_identity();
        let routes: Vec<peers::RouteMember> = members
            .iter()
            .filter(|m| m.identity != my_id)
            .map(|m| peers::RouteMember {
                endpoint_id: m.identity,
                ipv6: derive_ipv6(&m.identity),
            })
            .collect();
        self.route_map.sync_network(network, &routes);
    }

    /// Install the inbound QUIC router. Called once at boot after the router is
    /// built; the network (re)connect paths use it to drive a dialed connection's
    /// control demux.
    pub(crate) fn set_protocol_router(&self, router: Arc<ProtocolRouter>) {
        let _ = self.protocol_router.set(router);
    }

    /// The inbound QUIC router (panics if used before [`Self::set_protocol_router`]).
    pub(crate) fn protocol_router(&self) -> &Arc<ProtocolRouter> {
        self.protocol_router
            .get()
            .expect("protocol_router set at boot")
    }

    /// Build the [`MeshCtx`] handler bundle from the registry's own handles. This
    /// is the same bundle `Daemon::mesh_ctx` produces; relocating the builder
    /// here lets the network methods (create/join/coordinator spawn) assemble it
    /// themselves instead of taking it as a threaded-in argument.
    pub(crate) fn mesh_ctx(self: &Arc<Self>) -> MeshCtx {
        MeshCtx {
            identity: self.transport.identity.clone(),
            peers: self.peers.clone(),
            tun_tx: Arc::clone(&self.tun_tx),
            stats: Arc::clone(&self.transport.stats),
            blob_store: self.transport.blob_store.clone(),
            firewall: self.firewall.clone(),
            hostname_table: Arc::clone(&self.dns.hostname_table),
            reverse_table: Arc::clone(&self.dns.reverse_table),
            device_user_map: self.device_user_map.clone(),
            pruned_peers: Arc::clone(&self.pruned_peers),
            route_map: self.route_map.clone(),
            disconnect_tx: self.disconnect_tx.clone(),
            registry: Arc::clone(self),
        }
    }

    /// Remember a path that a peer has just completed an authenticated QUIC
    /// handshake over.  The in-memory lookup makes it available immediately;
    /// the compact on-disk cache survives the next daemon restart.  Neither is
    /// authoritative: stale hints fall through to iroh discovery, and TLS pins
    /// the endpoint id before a connection can be accepted.
    fn remember_endpoint_hint(&self, peer: EndpointId, addr: iroh::TransportAddr) {
        if peer == self.transport.identity.local_identity()
            || !matches!(
                addr,
                iroh::TransportAddr::Ip(_) | iroh::TransportAddr::Relay(_)
            )
        {
            return;
        }
        if let Err(e) = self
            .transport
            .warm_lookup
            .remember_verified(iroh::EndpointAddr::from_parts(peer, [addr]))
        {
            tracing::debug!(peer = %peer.fmt_short(), error = %e, "failed to persist warm endpoint hint");
        }
    }

    /// Capture live authenticated paths and subsequent upgrades. Periodically
    /// refresh live paths so a long-lived connection does not lose its warm
    /// hints merely because it needed no new handshake. Closed paths are not
    /// refreshed; lookups do not renew timestamps.
    pub(crate) fn remember_connection_hints(self: &Arc<Self>, conn: &Connection) {
        let peer = conn.remote_id();
        let mut events = conn.path_events();
        for path in conn.paths().iter() {
            self.remember_endpoint_hint(peer, path.remote_addr().clone());
        }
        let this = Arc::clone(self);
        let conn = conn.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            let interval = Duration::from_secs(crate::endpoint_hints::REFRESH_INTERVAL_SECS);
            let mut refresh =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    event = events.next() => match event {
                        Some(iroh::endpoint::PathEvent::Opened { remote_addr, .. }) => {
                            this.remember_endpoint_hint(peer, remote_addr);
                        }
                        Some(_) => {}
                        None => break,
                    },
                    _ = refresh.tick() => {
                        let addrs = conn.paths().iter().map(|path| path.remote_addr().clone()).collect::<Vec<_>>();
                        if peer != this.transport.identity.local_identity()
                            && let Err(error) = this.transport.warm_lookup.remember_verified(
                                iroh::EndpointAddr::from_parts(peer, addrs),
                            )
                        {
                            tracing::debug!(peer = %peer.fmt_short(), %error, "failed to refresh warm endpoint hint");
                        }
                    }
                }
            }
        });
    }

    /// This device's pairing cert. The on-disk cert is authoritative: a cleanly
    /// absent file (`Ok(None)`, e.g. after `unpair_self` deletes it) means
    /// unpaired, so only a genuine read error falls back to the in-memory copy.
    pub(crate) fn current_device_cert(&self) -> Option<control::DeviceCert> {
        match identity::load_device_cert() {
            Ok(cert) => cert,
            Err(_) => self.device_cert.clone(),
        }
    }

    /// What the rosters held here say about `remote`, in one pass with one lock
    /// per network. A poisoned roster lock counts as saying nothing.
    pub(crate) fn roster_standing(&self, remote: EndpointId) -> RosterStanding {
        let mut standing = RosterStanding::default();
        for network in self.networks.iter() {
            let Ok(state) = network.state.read() else {
                continue;
            };
            if let Some(member) = state.members.get(&remote) {
                standing.known = true;
                standing.user_identity = standing.user_identity.or(member.user_identity);
            }
            standing.known = standing.known
                || state
                    .members
                    .all()
                    .iter()
                    .any(|m| m.user_identity == Some(remote))
                || state
                    .approved
                    .all()
                    .iter()
                    .any(|e| e.identity == remote || e.user_identity == Some(remote));
        }
        // The paired primary need not share a roster with this device yet.
        standing.known = standing.known
            || self
                .current_device_cert()
                .is_some_and(|cert| cert.user_identity == remote);
        standing
    }

    /// What a person shares to reach this user: the paired user identity, or
    /// this endpoint when unpaired. Also the target of `ray connect`.
    pub(crate) fn own_identity(&self) -> EndpointId {
        self.current_device_cert()
            .map(|cert| cert.user_identity)
            .unwrap_or_else(|| self.transport.endpoint.id())
    }

    /// Record memberships a device held before receiving our certificate.
    /// A later certificate revocation must not turn those into paired joins.
    pub(crate) fn remember_independent_paired_device(&self, device: EndpointId) -> Result<()> {
        let mut names = Vec::new();
        for entry in self.networks.iter() {
            let state = entry.state.read().unwrap();
            if state.network_secret_key.is_none() {
                continue;
            }
            let Some(member) = state.members.get(&device) else {
                continue;
            };
            if member.user_identity.is_none() {
                names.push(entry.key().clone());
            }
        }
        for name in names {
            config::update_network(&name, |net| {
                if !net.independent_paired_devices.contains(&device) {
                    net.independent_paired_devices.push(device);
                }
                Ok(())
            })?
            .with_context(|| format!("network '{name}' has no saved config"))?;
        }
        Ok(())
    }

    /// The local cleanup of an unpair from `cert`'s primary: leave only networks
    /// whose first join used that primary's certificate, then delete the stored
    /// cert. Part of [`Self::unpair_self`], which saves the unpair first and
    /// makes this cleanup durable before it asks the primary to record it.
    pub(crate) async fn leave_certificate_networks(
        self: &Arc<Self>,
        cert: &control::DeviceCert,
    ) -> IpcMessage {
        let cfg = match config::load() {
            Ok(cfg) => cfg,
            Err(error) => return ipc_err(format!("could not read saved networks: {error}")),
        };
        let networks = networks_joined_with_certificate(&cfg.networks, cert.user_identity);
        for name in &networks {
            if self.networks.contains_key(name) {
                self.leave_network(name).await;
            }
            if let Err(error) = config::delete_network(name) {
                return ipc_err(format!("could not remove network '{name}': {error}"));
            }
        }
        match crate::identity::delete_device_cert() {
            Ok(()) => tracing::info!(left = networks.len(), "unpaired this device"),
            Err(e) => {
                tracing::warn!(error = %e, "unpair: failed to delete device cert");
                return ipc_err(format!(
                    "left certificate-joined networks but failed to delete device cert: {e}"
                ));
            }
        }
        IpcMessage::Ok {
            message: format!("unpaired this device (left {} network(s))", networks.len()),
        }
    }

    /// Tear down a network's runtime: cancel its tasks, drop its peers + `.ray`
    /// entries, unregister its accept handler, and refresh DNS search domains.
    /// Returns whether the network was actually active. The mesh ALPN set is
    /// static, so (unlike the old `refresh_alpns`) only the search domains need
    /// updating here. A caller that stops a network this node coordinates holds
    /// [`Self::revocation_lock`] until the network is gone or saved under its
    /// new name.
    pub(crate) async fn teardown_network_runtime(&self, name: &str) -> bool {
        self.teardown_network_runtime_closing(name, forward::LEAVE_CODE, b"leave")
            .await
    }

    /// [`Self::teardown_network_runtime`], closing the links it leaves unused with
    /// `code`. The leave code tells a coordinator we left; a network restarted
    /// under a new name ([`Self::rename_network`]) has not.
    async fn teardown_network_runtime_closing(&self, name: &str, code: u32, reason: &[u8]) -> bool {
        let Some(handle) = self.networks.remove(name).map(|(_, v)| v) else {
            return false;
        };
        handle.cancel.cancel();
        for task in handle.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }

        // Drop this network from every peer's routing. A peer left sharing no
        // network at all is fully disconnected, so close its now-unused link with
        // `code` (on the leave code the peer treats it as intentional and stops
        // reconnecting); a peer we still share another network with keeps its
        // connection.
        for (_ip, conn) in self.peers.remove_by_network(name) {
            conn.close(VarInt::from_u32(code), reason);
        }
        self.dns.clear_network(name).await;
        self.route_map.remove_network(name);
        self.conn.unregister(&handle.network_key);
        self.refresh_search_domains().await;
        true
    }

    /// Re-derive the OS DNS search domains from the currently-joined networks.
    /// Split out of the daemon's `refresh_alpns` (whose ALPN half is a no-op now
    /// the mesh ALPN is static) for the teardown path.
    pub(crate) async fn refresh_search_domains(&self) {
        let network_names: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        let tun_name = self.tun_name.load().as_str().to_owned();
        self.dns.set_search_domains(&network_names, &tun_name).await;
    }

    /// Leave a network: announce our departure to its peers, tear down the runtime,
    /// and remove it from config.
    ///
    /// The departure is sent in-band and network-scoped (`ControlMsg::LeaveNetwork`)
    /// rather than by closing the QUIC connection, because one connection now
    /// carries every network two peers share: closing it would sever the peer on
    /// networks we are *not* leaving (and, on a peer that coordinates one of them,
    /// get us pruned from a network we never left). A coordinator that receives the
    /// message prunes us from that one network's roster and republishes, so
    /// [`Self::announce_leave`] dials any coordinator no live link reaches.
    /// `teardown_network_runtime` then closes only the links left sharing no
    /// network at all.
    pub(crate) async fn leave_network(self: &Arc<Self>, name: &str) -> IpcMessage {
        // Announce the leave while the peer entries still list this network
        // (before teardown drops them), and let it land before tearing down.
        if let Some(net_pubkey) = self.networks.get(name).map(|h| h.network_key) {
            self.announce_leave(name, net_pubkey).await;
        }

        if self.remove_network_locally(name).await {
            tracing::info!(network = %name, "left network");
            IpcMessage::Ok {
                message: format!("left network '{}'", name),
            }
        } else {
            ipc_err(format!("network '{}' not found", name))
        }
    }

    /// Deliver `ControlMsg::LeaveNetwork` to every peer sharing `name` over a live
    /// link, and to every coordinator without one, dialing it first. Waits, at most
    /// [`LEAVE_DELIVERY_TIMEOUT`], until each has acknowledged the message.
    ///
    /// Only a coordinator prunes the roster, and nothing ages out a member that
    /// left without being heard: the roster keeps it, holding its hostname, until
    /// a `ray kick`. An on-demand node's link to its coordinator is usually
    /// idle-closed by the time it leaves, so the live links alone are not enough.
    /// Ordinary members need no dial: the coordinator's republish and `MemberSync`
    /// reach them, dialing idle ones in turn.
    async fn announce_leave(self: &Arc<Self>, name: &str, net_pubkey: EndpointId) {
        let live = self.peers.peers_for_network_with_conn(name);
        let reached: HashSet<EndpointId> = live.iter().map(|(id, _, _)| *id).collect();
        let absent = leave_recipients(
            &self.roster(name),
            self.transport.identity.local_identity(),
            &reached,
        );
        let deliveries = live
            .into_iter()
            .map(|(_, ip, _)| ip)
            .chain(absent)
            .map(|ip| async move { (ip, self.deliver_leave(ip, net_pubkey).await) });
        match tokio::time::timeout(
            LEAVE_DELIVERY_TIMEOUT,
            futures::future::join_all(deliveries),
        )
        .await
        {
            Ok(results) => {
                for (ip, result) in results {
                    if let Err(e) = result {
                        tracing::warn!(network = %name, peer_ip = %ip, error = %format!("{e:#}"), "failed to deliver leave");
                    }
                }
            }
            Err(_) => tracing::warn!(network = %name, "timed out delivering leave"),
        }
    }

    /// Send `LeaveNetwork` to the peer at `ip`, dialing it first when no link is up.
    ///
    /// A named, boxed future rather than an `async fn`: the dial spawns the new
    /// link's control loop, and an unpair notice arriving on that loop leaves
    /// networks through here again (`unpair_self`), so the loop's future type
    /// would otherwise contain itself.
    fn deliver_leave(
        self: &Arc<Self>,
        ip: Ipv6Addr,
        net_pubkey: EndpointId,
    ) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if self.peers.conn_for_ip(&ip).is_none() {
                let target = self
                    .resolve_route(IpAddr::V6(ip))
                    .context("no route to the peer")?;
                anyhow::ensure!(self.dial_target(&target).await, "could not dial the peer");
            }
            let conn = self
                .peers
                .conn_for_ip(&ip)
                .context("the link closed before the leave was sent")?;
            send_confirmed(&conn, Some(net_pubkey), &ControlMsg::LeaveNetwork).await
        })
    }

    /// Tear down and forget a network after its signed roster confirms that this
    /// node was removed. Unlike [`Self::leave_network`], this does not announce a
    /// departure to a coordinator that has already removed us.
    pub(crate) async fn remove_kicked_network(&self, name: &str) {
        if self.remove_network_locally(name).await {
            tracing::info!(network = %name, "removed kicked network");
        }
    }

    async fn remove_network_locally(&self, name: &str) -> bool {
        // Stopped and deleted under [`Self::revocation_lock`]: a pairing that
        // lifts a revocation meanwhile would skip the network, yet share it with
        // the device until it is deleted.
        let _revoking = self.revocation_lock.lock().await;
        let was_active = self.teardown_network_runtime(name).await;
        let removed_from_config = match config::delete_network(name) {
            Ok(removed) => removed,
            Err(error) => {
                tracing::warn!(network = %name, %error, "failed to remove network from config");
                false
            }
        };
        was_active || removed_from_config
    }

    /// Rename a network on this node only (`ray rename`). The name is local: it
    /// is the config's file name, the Magic DNS zone (`<host>.<name>.ray`) and
    /// the key every runtime structure files the network under. Peers know the
    /// network by its key, and the signed blob carries its own name
    /// (`group_name`), so neither notices.
    ///
    /// A live network is restarted under the new name, as a daemon restart
    /// would bring it back, rather than rekeyed in place, which would mean
    /// finding every structure and task that holds the name. Its links close with
    /// the idle code: a peer lets an idle link go without reconnecting, and a
    /// coordinator does not take it for a departure the way it takes the leave
    /// code, so nobody prunes us. What the restart does not rebuild is moved to
    /// the new name instead ([`Self::follow_rename`]); the daemon rebuilds its
    /// SSH allow-lists itself.
    ///
    /// The config and the invite ledger move under a saved intent
    /// ([`config::rename_network`]), which is cleared only once the firewall
    /// rules are saved under the new name as well, so a rename a crash
    /// interrupts is finished at the next start ([`finish_interrupted_rename`]).
    pub(crate) async fn rename_network(self: &Arc<Self>, from: &str, to: &str) -> IpcMessage {
        if !crate::hostname::is_valid_hostname(to) {
            return ipc_err(format!(
                "invalid network name '{to}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
            ));
        }
        if from == to {
            return ipc_err(format!("network '{from}' already has that name"));
        }
        match config::load_network(from) {
            Ok(Some(_)) => {}
            Ok(None) => return ipc_err(format!("network '{from}' not found")),
            Err(e) => return ipc_err(format!("{e:#}")),
        }
        match self.name_owner(to) {
            Ok(NameOwner::Free) => {}
            Ok(_) => {
                return ipc_err(format!(
                    "network name '{to}' belongs to another network on this node; choose another name"
                ));
            }
            Err(e) => return ipc_err(format!("{e:#}")),
        }
        // `config::rename_network` refuses this too, but only after the network
        // has been taken down for it.
        match config::rename_intent() {
            Ok(None) => {}
            Ok(Some(pending)) => {
                return ipc_err(format!(
                    "renaming network '{}' to '{}' has not finished; restart the daemon to finish it",
                    pending.from, pending.to
                ));
            }
            Err(e) => return ipc_err(format!("{e:#}")),
        }
        // Holding the restore guard keeps the supervisor from restoring the old
        // name while the network moves. A restore already under way would bring
        // the network up under the old name after the move, so wait for it.
        let Some(claim) = self.claim_registration(from) else {
            return ipc_err(format!(
                "network '{from}' is still being restored; try again once it is up"
            ));
        };
        // Stopped and moved under [`Self::revocation_lock`]: a pairing that
        // lifts a revocation meanwhile would skip the network, which then comes
        // back under the new name from a record that still nullifies the device.
        // Once moved, the network is saved and not running, which such a
        // pairing refuses.
        let revoking = self.revocation_lock.lock().await;
        // The network's invite ledger moves with the name. Its invites are
        // redeemed and delivered under its invite lock, so hold that across the
        // move: a write already under way would otherwise land under the old
        // name, where nothing reads it.
        let invite_lock = self
            .networks
            .get(from)
            .map(|handle| Arc::clone(&handle.invite_lock));
        self.teardown_network_runtime_closing(from, forward::IDLE_CODE, b"rename")
            .await;
        let renamed = {
            let _invites = match &invite_lock {
                Some(lock) => Some(lock.lock().await),
                None => None,
            };
            config::rename_network(from, to)
        };
        drop(revoking);
        drop(claim);
        let net = match renamed {
            Ok(Some(net)) => net,
            // Left meanwhile, so there is nothing to bring back.
            Ok(None) => return ipc_err(format!("network '{from}' not found")),
            Err(e) => {
                // Restore what is saved now rather than at the supervisor's next
                // tick. Before the intent was saved nothing moved, so that is the
                // network under its old name. After, the rename is committed and
                // the next start finishes it; until then a file the move left
                // holding its old name loads under neither name, so no restore
                // brings the network back half-renamed.
                self.nudge_restore();
                let committed = config::rename_intent()
                    .ok()
                    .flatten()
                    .is_some_and(|pending| pending.from == from && pending.to == to);
                return ipc_err(if committed {
                    format!(
                        "renaming network '{from}' to '{to}' did not finish ({e:#}); it finishes when the daemon next starts"
                    )
                } else {
                    format!("{e:#}")
                });
            }
        };
        let warning = self.follow_rename(from, to);
        self.restore_errors.remove(from);
        let coordinator = net.network_secret_key.is_some();
        let restore = if coordinator {
            self.spawn_coordinator_restore(&net)
        } else {
            self.spawn_member_restore(&net)
        };
        if let Some(restore) = restore {
            // The exit-node state moved with the name. Once the network is back,
            // rerun the daemon's exit reconcile too, which resolves an exit
            // selection against the restored roster; a member's restore carries
            // on after this replies.
            let exit_configured = !net.exit_allow.is_empty() || net.exit_node_use.is_some();
            let reapply = exit_configured.then(|| Arc::clone(&self.exit_reapply));
            let restored = tokio::spawn(async move {
                let _ = restore.await;
                if let Some(reapply) = reapply {
                    reapply.notify_one();
                }
            });
            if coordinator {
                // Local and quick, so `ray status` right after shows the new name.
                let _ = tokio::time::timeout(RENAME_RESTORE_WAIT, restored).await;
            }
        }
        tracing::info!(from, to, "renamed network");
        let mut message = format!("renamed network '{from}' to '{to}'");
        if let Some(warning) = warning {
            message.push_str(&format!("\nwarning: {warning}"));
        }
        IpcMessage::Ok { message }
    }

    /// Carry over to a network's new name what this node keeps under its name
    /// across the network's restart: the firewall rules scoped to it or installed
    /// from its suggestions, the exit-node policy and selection a gateway or full
    /// tunnel runs on, and the peers pruned from it. Then save the firewall rules
    /// and clear the rename's intent. Returns a warning when either could not be
    /// saved; the intent then stays, so the next start finishes saving the rules
    /// ([`finish_interrupted_rename`]).
    fn follow_rename(&self, from: &str, to: &str) -> Option<String> {
        let rules = self.firewall.rename_network(from, to);
        self.exit_server.rename_network(from, to);
        self.exit_client.rename_network(from, to);
        let pruned: Vec<EndpointId> = self
            .pruned_peers
            .iter()
            .filter(|entry| entry.0 == from)
            .map(|entry| entry.1)
            .collect();
        for peer in pruned {
            self.pruned_peers.remove(&(from.to_string(), peer));
            self.pruned_peers.insert((to.to_string(), peer));
        }
        let saved = rules
            .map_or(Ok(()), |rules| firewall::save_firewall(&rules))
            .and_then(|()| config::clear_rename_intent());
        saved.err().map(|e| {
            tracing::warn!(from, to, error = %format!("{e:#}"), "failed to save renamed network");
            format!(
                "could not save the rename in full ({e:#}); it finishes when the daemon next starts"
            )
        })
    }

    /// Look up an active network we coordinate, returning its public key and
    /// invite lock, or an error response if it's absent or we're only a member.
    #[allow(clippy::result_large_err)]
    pub(crate) fn coordinator_handle(
        &self,
        network: &str,
    ) -> std::result::Result<(EndpointId, Arc<AsyncMutex<()>>), IpcMessage> {
        let Some(handle) = self.networks.get(network) else {
            return Err(ipc_err(format!("network '{network}' not active")));
        };
        if !handle.role.is_coordinator() {
            return Err(ipc_err(format!(
                "only the coordinator of '{network}' can manage invites/requests"
            )));
        }
        Ok((handle.network_key, Arc::clone(&handle.invite_lock)))
    }

    /// Resolve an active network by its local name, public key, or invite code.
    pub(crate) fn active_network_name(&self, selector: &str) -> Option<String> {
        if self.networks.contains_key(selector) {
            return Some(selector.to_string());
        }
        let network_key = network_key_from_selector(selector)?;
        self.networks
            .iter()
            .find_map(|handle| (handle.network_key == network_key).then(|| handle.key().clone()))
    }

    /// The name of any network whose roster already holds `peer`, if any. Used
    /// by `ray mdns scan` to mark which LAN neighbours are already reachable;
    /// unlike `existing_direct_network_with` this looks at every network, not
    /// just the direct ones.
    pub(crate) fn network_shared_with(&self, peer: &EndpointId) -> Option<String> {
        self.networks.iter().find_map(|h| {
            let s = h.state.read().ok()?;
            s.members.is_member(peer).then(|| h.key().clone())
        })
    }

    /// The name of an existing direct (`ray connect`) network already linking us
    /// to `peer` (as a member or approved), if any. Used to keep `approve` /
    /// re-connect idempotent.
    pub(crate) fn existing_direct_network_with(&self, peer: &EndpointId) -> Option<String> {
        let direct: HashSet<String> = config::load()
            .map(|c| {
                c.networks
                    .iter()
                    .filter(|n| n.direct)
                    .map(|n| n.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.networks.iter().find_map(|h| {
            if !direct.contains(h.key()) {
                return None;
            }
            let s = h.state.read().ok()?;
            let has = s.members.is_member(peer) || s.approved.is_approved(peer);
            has.then(|| h.key().clone())
        })
    }

    /// Pick a collision-free `<me>-<peer>` name for a direct network.
    pub(crate) fn direct_network_name(
        &self,
        my_host: &str,
        peer_hostname: Option<&str>,
    ) -> Result<String> {
        let peer = peer_hostname.unwrap_or("peer");
        let mut base = format!("{my_host}-{peer}");
        if base.len() > 63 {
            base.truncate(63);
            base = base.trim_end_matches('-').to_string();
        }
        if !crate::hostname::is_valid_hostname(&base) {
            base = crate::network_name::generate_name();
        }
        self.unclaimed_network_name(&base, None)
    }

    /// What holds the local network name `name` (see [`NameOwner`]).
    pub(crate) fn name_owner(&self, name: &str) -> Result<NameOwner> {
        if let Some(handle) = self.networks.get(name) {
            return Ok(NameOwner::Network(handle.network_key));
        }
        Ok(match config::load_network(name)? {
            None => NameOwner::Free,
            Some(net) => net
                .network_public_key
                .or_else(|| net.network_secret_key.as_ref().map(SecretKey::public))
                .map_or(NameOwner::Unknown, NameOwner::Network),
        })
    }

    /// A local name for a network this node names itself (a generated one, the
    /// name a coordinator gave a joined network, a `ray connect` link): `base` if no
    /// other network holds it, else the first free `base-1`, `base-2`, ..., the way
    /// hostname collisions resolve. A name that network `key` already holds counts
    /// as free, so rejoining a saved network keeps its name and its config.
    pub(crate) fn unclaimed_network_name(
        &self,
        base: &str,
        key: Option<EndpointId>,
    ) -> Result<String> {
        let mut candidate = base.to_string();
        for suffix in 1u32.. {
            match self.name_owner(&candidate)? {
                NameOwner::Free => return Ok(candidate),
                NameOwner::Network(owner) if Some(owner) == key => return Ok(candidate),
                NameOwner::Network(_) | NameOwner::Unknown => {
                    candidate = suffixed_name(base, suffix);
                }
            }
        }
        unreachable!()
    }

    /// Mint a new network: generate its keypair, build the initial roster, seal +
    /// publish the blob, persist config, spawn coordinator tasks, and register the
    /// coordinator accept handler. `direct`/`pre_approve` back the `ray connect`
    /// 2-peer path. Takes a `&MeshCtx` for the task spawn + handler registration.
    pub(crate) async fn create_network_inner(
        self: &Arc<Self>,
        mode: GroupMode,
        custom_name: Option<String>,
        hostname: Option<String>,
        direct: bool,
        pre_approve: Option<(EndpointId, Option<String>)>,
    ) -> Result<IpcMessage> {
        let ctx = self.mesh_ctx();
        let name = match custom_name {
            Some(n) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&n),
                    "invalid network name '{n}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                if self.networks.contains_key(&n) {
                    return Ok(ipc_err(format!("network '{n}' already active")));
                }
                if self.name_owner(&n)? != NameOwner::Free {
                    return Ok(ipc_err(format!(
                        "network name '{n}' belongs to a saved network that is not active \
                         (see `ray status`); choose another name"
                    )));
                }
                n
            }
            None => self.unclaimed_network_name(&network_name::generate_name(), None)?,
        };
        // Held until the handle is registered. The config is saved first and the
        // record publish in between can take seconds; a restore sweep in that
        // gap would see a saved network that is not live and restore a second
        // coordinator state for it, whose publisher then republishes its stale
        // roster over every admission this one makes.
        let Some(_registration) = self.claim_registration(&name) else {
            return Ok(ipc_err(format!("network '{name}' is already being set up")));
        };

        let net_secret_key = SecretKey::generate();
        let net_public_key = net_secret_key.public();

        let my_ip = self.transport.identity.local_ipv6();

        let my_hostname = match hostname {
            Some(h) => {
                anyhow::ensure!(
                    crate::hostname::is_valid_hostname(&h),
                    "invalid hostname '{h}': use 1-63 lowercase ASCII letters, digits, or hyphens (no leading/trailing hyphen)"
                );
                h
            }
            // Founding the network, so there is no roster to clash with yet.
            None => crate::hostname::default_hostname(
                config::load().ok().and_then(|c| c.default_hostname),
                &[],
            ),
        };

        // Captured before `pre_approve` is consumed below: on a direct network
        // this is the one peer the co-coordinator key grant is pinned to.
        let pre_approved_peer = pre_approve.as_ref().map(|(id, _)| *id);

        let mut net_state =
            self.build_initial_roster(&name, &my_hostname, mode, &net_secret_key, pre_approve)?;

        // Sealed and saved under [`Self::revocation_lock`]: the seal copies the
        // device revocations saved here into the network, and a pairing that
        // lifts one in between would find the network neither saved nor running,
        // and leave it nullifying the device.
        let revoking = self.revocation_lock.lock().await;
        let last_group_hash = self.seal_group_snapshot(&mut net_state).await?;

        let member_entries = to_member_entries(net_state.members.all());
        let approved_entries = to_approved_entries(net_state.approved.all());
        config::save_network(&config::NetworkConfig {
            name: name.clone(),
            group_mode: mode,
            my_hostname: Some(my_hostname.clone()),
            pending_hostname: None,
            members: member_entries,
            approved: approved_entries,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: Some(net_public_key),
            join_certificate_issuer: None,
            independent_paired_devices: vec![],
            last_group_hash: Some(last_group_hash),
            last_group_hash_published: false,
            transport: None,
            auto_accept_firewall: false,
            // Own-device file offers are auto-accepted by default (identity-checked).
            auto_accept_files: true,
            admins: vec![],
            direct,
            // The peer this direct link was minted for. Pins the co-coordinator
            // key grant in `admit_peer` to that one peer instead of to whoever
            // happens to be approved on the network later.
            direct_peer: direct.then_some(pre_approved_peer).flatten(),
            ssh_allow: vec![],
            managed_ssh_allow: vec![],
            aliases: BTreeMap::new(),
            ephemeral_ttl_secs: None,
            exit_allow: vec![],
            exit_node_use: None,
        })?;
        drop(revoking);
        dns::update_hostname(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            &name,
            &my_hostname,
            derive_ipv6(&self.transport.identity.local_identity()),
        )
        .await;
        let initial_record = self
            .publish_group_hash(
                &name,
                &net_secret_key,
                last_group_hash,
                &net_state.snapshot_commit,
            )
            .await;

        let cancel = self.shutdown_token.child_token();
        let state = Arc::new(std::sync::RwLock::new(net_state));
        let invite_lock = Arc::new(AsyncMutex::new(()));
        let dht_notify = Arc::new(tokio::sync::Notify::new());
        let tasks = self.spawn_coordinator_background_tasks(
            &ctx,
            &name,
            &net_secret_key,
            &state,
            &dht_notify,
            &cancel,
            initial_record.as_ref().map(|_| last_group_hash),
        );

        // Insert the handle first so register_coordinator_handler can update the role.
        let handle = NetworkHandle {
            name: name.clone(),
            network_key: net_public_key,
            role: NetworkRole::Coordinator,
            state: Arc::clone(&state),
            dht_notify: Some(Arc::clone(&dht_notify)),
            cancel: cancel.clone(),
            tasks,
            invite_lock: Arc::clone(&invite_lock),
            // A coordinator holds the network key and publishes the record, so
            // the version it advertises is this build's by construction.
            incompatible: None,
        };
        self.networks.insert(name.clone(), handle);

        self.register_coordinator_handler(
            &ctx,
            &name,
            state,
            invite_lock,
            Some(dht_notify),
            net_public_key,
        );
        self.refresh_search_domains().await;

        tracing::info!(name = %name, key = %net_public_key, ip = %my_ip, "network created");

        Ok(IpcMessage::Created {
            name,
            network_key: net_public_key,
            my_ipv6: derive_ipv6(&self.transport.identity.local_identity()),
        })
    }

    /// Build the initial [`NetworkState`] for a network we're minting: a member
    /// list holding just us (as coordinator), plus an optional pre-approved peer
    /// (used by `ray connect` to admit the requester without a live prompt).
    pub(crate) fn build_initial_roster(
        &self,
        name: &str,
        my_hostname: &str,
        mode: GroupMode,
        net_secret_key: &SecretKey,
        pre_approve: Option<(EndpointId, Option<String>)>,
    ) -> Result<NetworkState> {
        let mut member_list = MemberList::new();
        member_list.add(Member {
            identity: self.transport.identity.local_identity(),
            is_coordinator: true,
            hostname: Some(my_hostname.to_string()),
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            // `Unknown` until the data plane probes the uplink: an offer we have
            // not verified is not a claim to publish.
            exit_families: ExitFamilies::Unknown,
        });

        let mut approved = ApprovedList::new();
        if let Some((peer_id, peer_hostname)) = pre_approve {
            approved.approve(ApprovedEntry {
                identity: peer_id,
                hostname: peer_hostname,
                user_identity: None,
                device_cert: None,
            });
        }

        Ok(NetworkState {
            members: member_list,
            approved,
            snapshot: None,
            snapshot_commit: Arc::new(AsyncMutex::new(())),
            destroyed: false,
            converged_hash: None,
            unconfirmed_durable_hash: None,
            network_secret_key: Some(net_secret_key.clone()),
            network_public_key: net_secret_key.public(),
            network_name: Some(name.to_string()),
            group_name: Some(name.to_string()),
            mode,
            suggested_firewall: SuggestedFirewall::default(),
            reusable_keys: BTreeMap::new(),
            // Seeded from persisted `revoked_devices` by `seal_and_publish`.
            nullifiers: BTreeSet::new(),
            pending_suggestions: Vec::new(),
            pending: HashMap::new(),
            // We author this network's records; there is nothing to replay to us.
            last_record_timestamp: None,
        })
    }

    /// Seed a coordinated network's nullifiers from our durable
    /// `revoked_devices`, refresh its blob snapshot, and durably store the bytes.
    /// The caller persists the returned hash before publishing it, so a crash can
    /// never leave the DHT newer than the recovery pointer on disk.
    pub(crate) async fn seal_group_snapshot(
        &self,
        net_state: &mut NetworkState,
    ) -> Result<blake3::Hash> {
        {
            let cfg = config::load().unwrap_or_default();
            net_state
                .nullifiers
                .extend(config::revoked_device_ids(&cfg));
        }
        net_state.refresh_snapshot();
        let snap = net_state
            .snapshot
            .as_ref()
            .context("group snapshot missing")?;
        self.transport
            .blob_store
            .blobs()
            .add_slice(&snap.msgpack_bytes)
            .await
            .context("store complete group snapshot")?;
        Ok(snap.hash)
    }

    /// Sign and publish the record for `blob_hash`, then mark it published.
    /// Returns the record's bytes once both happened.
    pub(crate) async fn publish_group_hash(
        &self,
        network: &str,
        net_secret_key: &SecretKey,
        blob_hash: blake3::Hash,
        commit: &AsyncMutex<()>,
    ) -> Option<Vec<u8>> {
        let packet = match dht::encode_network_record(
            net_secret_key,
            &blob_hash,
            &[self.transport.endpoint.id()],
        ) {
            Ok(packet) => packet,
            Err(e) => {
                tracing::warn!(error = %e, "failed to build network record");
                return None;
            }
        };
        self.publish_signed_group_record(network, blob_hash, &packet, commit)
            .await
            .then(|| packet.as_bytes().to_vec())
    }

    /// Publish a record already signed under `commit` and mark it published.
    /// Returns whether both happened; failures are logged here.
    pub(crate) async fn publish_signed_group_record(
        &self,
        network: &str,
        hash: blake3::Hash,
        packet: &SignedPacket,
        commit: &AsyncMutex<()>,
    ) -> bool {
        let client = match dht::create_pkarr_client(
            &self.transport.endpoint,
            &self.transport.pkarr_relay_url,
        ) {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(error = %e, "failed to build pkarr client for network record");
                return false;
            }
        };
        match publish_signed_record(&client, commit, network, hash, packet).await {
            Ok(marked) => {
                if marked {
                    self.records_published.send_replace(());
                }
                marked
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to publish network record");
                false
            }
        }
    }

    /// Spawn a coordinated network's background tasks: the pkarr network publisher
    /// and the ephemeral stale-member pruner. Dead-peer cleanup/reconnect is
    /// daemon-wide (the connection supervisor), so no per-network disconnect task.
    /// Returns the task handles plus the daemon-wide disconnect sender (taken from
    /// the supplied `ctx`) the caller uses to build peer readers.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_coordinator_background_tasks(
        &self,
        ctx: &MeshCtx,
        name: &str,
        net_secret_key: &SecretKey,
        state: &SharedNetworkState,
        dht_notify: &Arc<tokio::sync::Notify>,
        cancel: &CancellationToken,
        initially_published: Option<blake3::Hash>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut tasks = Vec::new();

        if let Ok(pkarr_client) =
            dht::create_pkarr_client(&self.transport.endpoint, &self.transport.pkarr_relay_url)
        {
            tasks.push(spawn_network_publisher(
                pkarr_client,
                net_secret_key.clone(),
                Arc::clone(state),
                Arc::clone(&ctx.registry),
                name.to_string(),
                initially_published,
                Arc::clone(dht_notify),
                cancel.clone(),
            ));
        }

        tasks.push(spawn_stale_member_pruner(
            ctx.clone(),
            name.to_string(),
            Arc::clone(state),
            Some(Arc::clone(dht_notify)),
            cancel.clone(),
        ));

        tasks
    }

    /// Store a network's current blob snapshot, persist its recovery pointer,
    /// and wake its single publisher. Publication stays serialized in that task,
    /// so an older async write can never complete after a newer one.
    pub(crate) async fn store_and_publish_group(&self, network: &str) {
        let (state, notify) = {
            let Some(handle) = self.networks.get(network) else {
                return;
            };
            (Arc::clone(&handle.state), handle.dht_notify.clone())
        };
        update_snapshot_and_publish(&state, &self.transport.blob_store, &notify).await;
    }

    /// This coordinator's current network record, serialized as a signed pkarr
    /// packet, for handing to a (re)connecting member over the mesh so it converges
    /// to the live roster without waiting on a fresh (possibly stale) DHT lookup.
    /// `None` when we are not a coordinator of `network` (no secret key) or have no
    /// snapshot yet. Mirrors the record built by [`Self::store_and_publish_group`];
    /// the receiver verifies it against the network key before trusting it.
    pub(crate) async fn current_signed_record(
        &self,
        network: &str,
    ) -> Option<CurrentSignedNetworkState> {
        let state = Arc::clone(&self.networks.get(network)?.state);
        let hash = state.read().unwrap().converged_hash?;
        if !persist_group_hash_if_needed(&state, &self.transport.blob_store, network, hash, false)
            .await
        {
            return None;
        }
        let commit = Arc::clone(&state.read().unwrap().snapshot_commit);
        let _commit = commit.lock().await;
        let net = config::load_network(network).ok().flatten()?;
        let hash = net.last_group_hash?;
        if !snapshot_is_publishable(&self.transport.blob_store, &state, network, hash).await {
            return None;
        }
        let (key, members, approved) = {
            let state = state.read().unwrap();
            (
                state.network_secret_key.clone()?,
                state.roster(),
                state.approved_snapshot(),
            )
        };
        let mut seed_peers: Vec<EndpointId> = self
            .peers
            .peers_for_network(network)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        seed_peers.push(self.transport.endpoint.id());
        seed_peers.sort_by_key(|id| id.to_string());
        seed_peers.dedup();
        let packet = dht::encode_network_record(&key, &hash, &seed_peers).ok()?;
        Some(CurrentSignedNetworkState {
            hash,
            packet: packet.as_bytes().to_vec(),
            published: net.last_group_hash == Some(hash) && net.last_group_hash_published,
            members,
            approved,
            key,
        })
    }

    /// Resolve a peer name (hostname, `host.net.ray`, or mesh address) to its
    /// endpoint id: Magic DNS + connected-peer route first, then the member
    /// roster (offline peers / self), then a short-id / endpoint-id prefix scan.
    pub(crate) async fn resolve_peer_name(&self, name: &str) -> Option<EndpointId> {
        let suffix = format!(".{}", crate::DNS_DOMAIN);
        let qualified = if name.ends_with(&suffix) {
            name.to_string()
        } else {
            format!("{name}{suffix}")
        };
        if let Some(v6) = self.dns.resolve(&qualified, &suffix).await {
            if let Some(route) = self.peers.lookup_v6(&v6) {
                return Some(route.endpoint_id);
            }
            for entry in self.networks.iter() {
                let state = entry.value().state.read().unwrap();
                if let Some(m) = state
                    .members
                    .all()
                    .iter()
                    .find(|m| derive_ipv6(&m.identity) == v6)
                {
                    return Some(m.identity);
                }
            }
        }
        self.resolve_short_id_any_network(name)
    }

    /// Resolve a firewall `--peer` argument to a peer's **device** endpoint id,
    /// accepting more forms than [`Self::resolve_peer_name`]: hostname, mesh address
    /// (incl. offline members, since it derives from the roster's identities),
    /// short / full endpoint id, or a paired user identity.
    pub(crate) async fn resolve_peer_flexible(&self, name: &str) -> Option<EndpointId> {
        if let Some(id) = self.resolve_peer_name(name).await {
            return Some(id);
        }
        if let Ok(v6) = name.parse::<std::net::Ipv6Addr>()
            && let Some(route) = self.peers.lookup_v6(&v6)
        {
            return Some(route.endpoint_id);
        }
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(id) = state.members.resolve_peer_literal(name) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve a peer selector against one network's roster. Network-scoped
    /// commands use this so a repeated hostname on another network cannot pick
    /// the wrong member. Accepts a hostname, qualified `.ray` name, mesh
    /// address, short id, full device identity, or paired user identity.
    pub(crate) fn resolve_peer_in_network(
        &self,
        network: &str,
        selector: &str,
    ) -> Option<EndpointId> {
        let selector = peer_selector_for_network(network, selector)?;
        let handle = self.networks.get(network)?;
        if selector == "self" {
            return Some(self.transport.endpoint.id());
        }
        handle
            .state
            .read()
            .unwrap()
            .members
            .resolve_peer_selector(selector)
    }

    /// Resolve `"self"` or a short / prefix endpoint id against every network's
    /// roster to a full endpoint id.
    pub(crate) fn resolve_short_id_any_network(&self, short: &str) -> Option<EndpointId> {
        if short == "self" {
            return Some(self.transport.endpoint.id());
        }
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(m) = state
                .members
                .all()
                .iter()
                .find(|m| m.identity.to_string().starts_with(short))
            {
                return Some(m.identity);
            }
        }
        None
    }

    /// Verified memberships for authorization, independent of transport handles.
    #[cfg(any(test, all(feature = "desktop", unix)))]
    pub(crate) fn authorization_networks(&self, peer: EndpointId) -> Vec<SmolStr> {
        let user = self.device_user_map.resolve(&peer);
        self.networks
            .iter()
            .filter_map(|entry| {
                if self.pruned_peers.contains(&(entry.key().clone(), peer)) {
                    return None;
                }
                let state = entry.state.read().unwrap();
                let independent_member = state.members.get(&peer).is_some_and(|member| {
                    member.user_identity.is_none() && member.device_cert.is_none()
                });
                if state.nullifiers.contains(&peer) && !independent_member {
                    return None;
                }
                (state.members.is_member(&peer) || state.members.is_member(&user))
                    .then(|| SmolStr::new(entry.key()))
            })
            .collect()
    }

    /// Whether `identity` is a current member of at least one network that has
    /// file auto-accept enabled. Backs the own-device file auto-accept gate.
    pub(crate) fn member_on_autoaccept_network(&self, identity: EndpointId) -> bool {
        for entry in self.networks.iter() {
            let enabled = config::load_network(entry.key())
                .ok()
                .flatten()
                .map(|nc| nc.auto_accept_files)
                .unwrap_or(false);
            if !enabled {
                continue;
            }
            let is_member = entry
                .value()
                .state
                .read()
                .map(|s| s.members.is_member(&identity))
                .unwrap_or(false);
            if is_member {
                return true;
            }
        }
        false
    }

    /// Register (or replace) `network`'s accept handler with a
    /// [`CoordinatorAcceptState`], so any node holding the network key admits
    /// fresh joiners instead of dropping their `JoinRequest`s. The daemon-wide
    /// `ctx` (identical for every network) is supplied by the caller: the daemon
    /// passes `self.mesh_ctx()`, a promoting control reader passes its own `ctx`.
    /// Also flips the stored role so `ray status` reports Coordinator at once.
    #[allow(clippy::too_many_arguments)] // the params are the handler's own fields
    pub(crate) fn register_coordinator_handler(
        &self,
        ctx: &MeshCtx,
        network: &str,
        state: SharedNetworkState,
        invite_lock: Arc<AsyncMutex<()>>,
        dht_notify: Option<Arc<Notify>>,
        network_key: EndpointId,
    ) {
        self.conn.register(
            network_key,
            AcceptHandler::Coordinator(Arc::new(CoordinatorAcceptState {
                ctx: ctx.clone(),
                network_name: network.to_string(),
                state,
                dht_notify,
                invite_lock,
            })),
        );
        if let Some(mut handle) = self.networks.get_mut(network) {
            handle.role = NetworkRole::Coordinator;
        }
    }

    /// Swap a live member to a coordinator accept handler after it is granted the
    /// per-network key (via `AdminGrant`), so it can admit fresh joiners. Called
    /// directly by the granted member's control reader (was the `promote_tx`
    /// hand-off to the daemon loop). Idempotent: a network already coordinating is
    /// left untouched ([`should_promote`]). No `refresh_alpns` is needed: the mesh
    /// ALPN is static and promotion adds no network, so the advertised set and the
    /// DNS search domains are unchanged.
    pub(crate) fn promote_to_coordinator(
        &self,
        ctx: &MeshCtx,
        network: &str,
        key: SecretKey,
        pkarr_client: PkarrRelayClient,
    ) -> bool {
        let state;
        let invite_lock;
        let notify;
        let network_key;
        {
            let Some(mut handle) = self.networks.get_mut(network) else {
                return false;
            };
            if !should_promote(handle.role.clone()) {
                return false;
            }
            notify = Arc::new(Notify::new());
            let publisher = spawn_network_publisher(
                pkarr_client,
                key,
                Arc::clone(&handle.state),
                Arc::clone(&ctx.registry),
                network.to_string(),
                None,
                Arc::clone(&notify),
                handle.cancel.clone(),
            );
            handle.tasks.push(publisher);
            handle.dht_notify = Some(Arc::clone(&notify));
            handle.role = NetworkRole::Coordinator;
            state = Arc::clone(&handle.state);
            invite_lock = Arc::clone(&handle.invite_lock);
            network_key = handle.network_key;
        } // DashMap ref dropped before connection-handler registration.
        self.register_coordinator_handler(
            ctx,
            network,
            state,
            invite_lock,
            Some(notify),
            network_key,
        );
        tracing::info!(
            network,
            "promoted to coordinator accept handler and publisher"
        );
        true
    }

    /// Clear the nullifier of a device that pairs again, before it gets the new
    /// certificate (the inverse of `unpair`): drop it from the durable
    /// `revoked_devices` seed and from every coordinated network's blob
    /// nullifier set, wait, at most [`REAUTHORIZATION_PUBLISH_WAIT`], until each
    /// network that changed has its new record published, and only then tell
    /// the members. The device joins the networks shared with it as soon as it
    /// has the certificate, reading the record first, and the earlier record
    /// still nullifies its key. A nullifier names no pairing, so the device
    /// would take that for a revocation of the new one. Non-coordinated
    /// networks clear on their own coordinator's next reseal.
    ///
    /// Returns whether a revocation was lifted. If a record is not published in
    /// time, the revocation is put back, so that the next attempt lifts it and
    /// waits again, and an error is returned. A coordinated network that is not
    /// running, while its restore is in progress or after one failed, publishes
    /// nothing, and the device is told of every saved network, so a revoked
    /// device gets an error then, before anything changes. The caller holds
    /// [`Self::revocation_lock`], which keeps the networks this node
    /// coordinates from stopping or appearing until this returns.
    pub(crate) async fn reauth_device_locked(
        self: &Arc<Self>,
        device: EndpointId,
    ) -> Result<bool, String> {
        // Before anything changes, so that no publication after it is missed.
        let mut published = self.records_published.subscribe();
        let hex = device.to_string();
        let settings =
            config::load().map_err(|e| format!("could not read the nullifier seed: {e:#}"))?;
        if settings.revoked_devices.contains(&hex) {
            let stopped: Vec<&str> = settings
                .networks
                .iter()
                .filter(|net| {
                    net.network_secret_key.is_some() && !self.networks.contains_key(&net.name)
                })
                .map(|net| net.name.as_str())
                .collect();
            if !stopped.is_empty() {
                return Err(format!(
                    "networks this node coordinates are not running, and their records still nullify the device: {}",
                    stopped.join(", ")
                ));
            }
        }
        // Drop from the durable nullifier seed so a later reseal won't re-add it.
        let mut lifted = false;
        // No-op when the device was not in the seed: `update_settings` skips the
        // write when the callback changes nothing.
        config::update_settings(|cfg| {
            if let Some(pos) = cfg.revoked_devices.iter().position(|d| *d == hex) {
                cfg.revoked_devices.remove(pos);
                lifted = true;
            }
            Ok(())
        })
        .map_err(|e| format!("could not clear the device from the nullifier seed: {e:#}"))?;
        // Collect coordinated networks (clone the handles) before awaiting.
        let mut nets: Vec<(String, SharedNetworkState, Option<Arc<Notify>>)> = Vec::new();
        for entry in self.networks.iter() {
            if entry
                .value()
                .state
                .read()
                .unwrap()
                .network_secret_key
                .is_some()
            {
                nets.push((
                    entry.key().clone(),
                    Arc::clone(&entry.value().state),
                    entry.value().dht_notify.clone(),
                ));
            }
        }
        let mut changed = Vec::new();
        let mut failure = None;
        for (net, state, dht_notify) in nets {
            let removed = {
                let mut s = state.write().unwrap();
                s.nullifiers.remove(&device)
            };
            if !removed {
                continue;
            }
            lifted = true;
            // A network destroyed meanwhile leaves no record to wait for.
            if !update_snapshot_and_publish(&state, &self.transport.blob_store, &dht_notify).await
                && !state.read().unwrap().destroyed
            {
                failure = Some(format!(
                    "could not save network '{net}' without the device's nullifier"
                ));
                break;
            }
            changed.push((net, state));
        }
        // Each network's own publisher publishes its record.
        let deadline = tokio::time::Instant::now() + REAUTHORIZATION_PUBLISH_WAIT;
        while failure.is_none() && !changed.iter().all(|(net, _)| record_is_published(net)) {
            if !matches!(
                tokio::time::timeout_at(deadline, published.changed()).await,
                Ok(Ok(()))
            ) {
                failure = Some("the networks' records were not published in time".to_string());
            }
        }
        if let Some(message) = failure {
            if let Err(error) = self.revoke_device_locked(device, |_| {}).await {
                tracing::warn!(device = %device.fmt_short(), %error, "could not put back the revocation a failed re-authorization lifted");
            }
            return Err(message);
        }
        for (net, state) in changed {
            let net_pubkey = state.read().unwrap().network_public_key;
            broadcast_member_sync(self, net_pubkey, &net, None).await;
        }
        if lifted {
            tracing::info!(device = %device.fmt_short(), "re-authorized device (cleared nullifier)");
        }
        Ok(lifted)
    }
}

/// Whether `network`'s current record is published, which its publisher marks
/// once the relay took it. A network no longer saved here is not waited for.
fn record_is_published(network: &str) -> bool {
    config::load_network(network)
        .is_ok_and(|net| net.is_none_or(|net| net.last_group_hash_published))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the production observation path, not a hand-built cache. This
    /// regression also runs on the parent commit, where all 32 addresses stay
    /// in settings indefinitely for a single continuously active peer.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn verified_path_observations_bound_warm_cache_addresses() {
        let _env_lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    match &self.0 {
                        Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                        None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
                    }
                }
            }
        }
        let _restore = Restore(std::env::var_os("RAYFISH_CONFIG_DIR"));
        unsafe {
            std::env::set_var("RAYFISH_CONFIG_DIR", dir.path());
        }
        let endpoint = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let registry = super::super::accept_handler_tests::sample_registry(
            endpoint.clone(),
            IrohIdentityProvider::new(endpoint.id()),
            FsStore::load(dir.path().join("blobs")).await.unwrap(),
        );
        let peer = SecretKey::from([71; 32]).public();
        for port in 10000..10032 {
            registry.remember_endpoint_hint(
                peer,
                iroh::TransportAddr::Ip(format!("192.0.2.1:{port}").parse().unwrap()),
            );
        }
        let cfg = config::load().unwrap();
        assert_eq!(cfg.endpoint_hints.len(), 1);
        assert!(
            cfg.endpoint_hints[0].addrs.len() <= 8,
            "a peer's old paths must not accumulate indefinitely: {} retained",
            cfg.endpoint_hints[0].addrs.len()
        );
        let info = registry
            .transport
            .warm_lookup
            .get_endpoint_info(peer)
            .unwrap();
        let addr = info.into_endpoint_addr();
        assert!(addr.addrs.len() <= 8);
        endpoint.close().await;
    }

    #[test]
    fn network_selector_accepts_public_key_and_invite_code() {
        let network_key = SecretKey::generate().public();
        let coordinator = SecretKey::generate().public();
        let invite = crate::invite::encode_invite_code(
            &network_key,
            &coordinator,
            &crate::invite::generate_secret(),
        );

        assert_eq!(
            network_key_from_selector(&network_key.to_string()),
            Some(network_key)
        );
        assert_eq!(network_key_from_selector(&invite), Some(network_key));
        assert_eq!(network_key_from_selector("field"), None);
    }

    #[test]
    fn peer_selector_accepts_names_for_the_named_network_only() {
        assert_eq!(peer_selector_for_network("box", "alice"), Some("alice"));
        assert_eq!(peer_selector_for_network("box", "alice.ray"), Some("alice"));
        assert_eq!(
            peer_selector_for_network("box", "alice.box.ray"),
            Some("alice")
        );
        assert_eq!(peer_selector_for_network("box", "alice.lab.ray"), None);
    }

    fn net(name: &str) -> config::NetworkConfig {
        config::NetworkConfig {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn coordinator_net(name: &str) -> config::NetworkConfig {
        config::NetworkConfig {
            name: name.to_string(),
            group_mode: GroupMode::Restricted,
            network_secret_key: Some(SecretKey::generate()),
            ..Default::default()
        }
    }

    #[test]
    fn unpair_keeps_independent_and_coordinated_networks() {
        let primary = SecretKey::generate().public();
        let other_primary = SecretKey::generate().public();
        let mut paired = net("paired");
        paired.join_certificate_issuer = Some(primary);
        let mut other_pairing = net("other-pairing");
        other_pairing.join_certificate_issuer = Some(other_primary);
        let saved = vec![
            net("independent"),
            coordinator_net("coordinated"),
            paired,
            other_pairing,
        ];

        assert_eq!(
            networks_joined_with_certificate(&saved, primary),
            vec!["paired"]
        );
    }

    #[test]
    fn restores_only_saved_networks_that_are_not_live() {
        let saved = vec![net("homelab"), net("trade")];
        let missing = missing_networks(&saved, |n| n == "trade", |_| false);
        assert_eq!(
            missing,
            vec![MissingNetwork {
                name: "homelab".to_string(),
                coordinator_mode: None,
            }]
        );
    }

    /// The sweep runs on a timer *and* on peer traffic, so the same network can
    /// be swept twice while its restore is still in flight. Without this guard
    /// each inbound frame for a dead network would start another restore.
    #[test]
    fn skips_a_network_whose_restore_is_already_running() {
        let saved = vec![net("homelab")];
        assert!(missing_networks(&saved, |_| false, |n| n == "homelab").is_empty());
    }

    /// Holding the network key means the restore is local (no pkarr lookup), so
    /// the two are dispatched to different restore paths.
    #[test]
    fn tags_a_key_holding_network_as_a_coordinator_restore() {
        let saved = vec![coordinator_net("field")];
        let missing = missing_networks(&saved, |_| false, |_| false);
        assert_eq!(
            missing,
            vec![MissingNetwork {
                name: "field".to_string(),
                coordinator_mode: Some(GroupMode::Restricted),
            }]
        );
    }

    #[test]
    fn nothing_to_do_when_every_saved_network_is_live() {
        let saved = vec![net("homelab"), coordinator_net("field")];
        assert!(missing_networks(&saved, |_| true, |_| false).is_empty());
    }

    /// A suffix must not push a name past the 63-character limit: the candidate
    /// is looked up by its config file name, which rejects a longer one, so the
    /// search would fail instead of finding a free name.
    #[test]
    fn a_suffixed_name_stays_a_valid_name() {
        assert_eq!(suffixed_name("gaming", 1), "gaming-1");
        let longest = "a".repeat(63);
        for (suffix, want) in [
            (1, format!("{}-1", "a".repeat(61))),
            (10, format!("{}-10", "a".repeat(60))),
        ] {
            let name = suffixed_name(&longest, suffix);
            assert_eq!(name, want);
            assert!(crate::hostname::is_valid_hostname(&name), "{name}");
        }
        // A cut that ends on a hyphen drops it rather than doubling it.
        let hyphen_at_cut = format!("{}-bb", "a".repeat(60));
        assert_eq!(
            suffixed_name(&hyphen_at_cut, 1),
            format!("{}-1", "a".repeat(60))
        );
    }
}
