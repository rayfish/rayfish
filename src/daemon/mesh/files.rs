//! File-sharing and device-pairing handlers for `MeshManager`: `send_file`,
//! `list_files`, `accept_file`, pairing. Split out of `daemon/mod.rs`.

use std::ffi::CString;
use std::path::Path;

use super::super::*;

/// Upper bound on the pairing dial to a primary device. `Endpoint::connect`
/// retries discovery/relay with no timeout of its own, so without this an
/// unreachable primary hangs the pairing call forever.
const PAIR_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

impl MeshManager {
    pub(crate) async fn resolve_peer_name(&self, name: &str) -> Option<EndpointId> {
        let suffix = format!(".{}", crate::DNS_DOMAIN);
        let qualified = if name.ends_with(&suffix) {
            name.to_string()
        } else {
            format!("{name}{suffix}")
        };
        if let Some((ip, _)) =
            dns::resolve_name(&qualified, &suffix, &self.dns.hostname_table).await
        {
            // Try connected peers first
            if let Some(route) = self.peers.lookup_v4(&ip) {
                return Some(route.endpoint_id);
            }
            // Fall back to member list (peer may be offline or it's us)
            for entry in self.networks.iter() {
                let state = entry.value().state.read().unwrap();
                if let Some(m) = state.members.all().iter().find(|m| m.ip == ip) {
                    return Some(m.identity);
                }
            }
        }
        self.resolve_short_id_any_network(name)
    }

    /// Resolve a firewall `--peer` argument to a peer's **device** endpoint id,
    /// accepting far more forms than [`resolve_peer_name`]: hostname (bare or
    /// `host.net.ray`), mesh IPv4 (also for offline members, since the roster
    /// stores v4), mesh IPv6 (connected peers only — the roster carries no v6),
    /// short id / full endpoint id, or a paired **user identity** (resolved to
    /// that user's joined device). Returns the device id `D`; `firewall_add`
    /// normalizes it to the user identity for inbound rules. Kept separate from
    /// `resolve_peer_name` so `ping`/`send` behaviour is unchanged; the extra
    /// cases could later back those commands too.
    pub(crate) async fn resolve_peer_flexible(&self, name: &str) -> Option<EndpointId> {
        // Hostname (Magic DNS) + short-id / endpoint-id-prefix fallback.
        if let Some(id) = self.resolve_peer_name(name).await {
            return Some(id);
        }
        // Mesh IP literal of a *connected* peer (fast path; also the only way to
        // reach a peer by IPv6, since the roster carries no v6 address).
        if let Ok(v4) = name.parse::<Ipv4Addr>()
            && let Some(route) = self.peers.lookup_v4(&v4)
        {
            return Some(route.endpoint_id);
        }
        if let Ok(v6) = name.parse::<std::net::Ipv6Addr>()
            && let Some(route) = self.peers.lookup_v6(&v6)
        {
            return Some(route.endpoint_id);
        }
        // Roster scan: an offline peer's mesh IPv4, or a paired user identity.
        for entry in self.networks.iter() {
            let state = entry.value().state.read().unwrap();
            if let Some(id) = state.members.resolve_peer_literal(name) {
                return Some(id);
            }
        }
        None
    }

    /// Resolve whether a pending offer's sender is one of *our own* paired
    /// devices: the sender's resolved user identity must equal ours (our device
    /// cert's `user_identity`, or on the primary — which holds no cert — our own
    /// endpoint id). A non-paired peer resolves to its own transport id and so
    /// can never match. Shared by `try_auto_accept_file` and `list_files` (which
    /// surfaces it as `PendingFileInfo.own_device` for the mobile UI).
    pub(crate) fn is_own_device_sender(&self, from: EndpointId) -> bool {
        let own_user = self
            .device_cert
            .as_ref()
            .map(|c| c.user_identity)
            .unwrap_or_else(|| self.endpoint.id());
        self.device_user_map.resolve(&from) == own_user
    }

    pub async fn send_file(&self, path: &str, peer: &str) -> IpcMessage {
        let peer_id = match self.resolve_peer_flexible(peer).await {
            Some(id) => id,
            None => {
                return IpcMessage::Error {
                    message: format!("unknown peer '{peer}'"),
                };
            }
        };

        let file_path = Path::new(path);
        let file_bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot read '{}': {e}", file_path.display()),
                };
            }
        };

        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let size = file_bytes.len() as u64;
        let mime_type = guess_mime_type(&filename);
        let hash = blake3::hash(&file_bytes);

        if let Err(e) = self.blob_store.blobs().add_slice(&file_bytes).await {
            return IpcMessage::Error {
                message: format!("blob store error: {e}"),
            };
        }

        let msg = control::ControlMsg::FileOffer {
            from: self.endpoint.id(),
            filename: filename.clone(),
            size,
            mime_type: mime_type.clone(),
            blob_hash: hash,
        };

        match transport::connect_to_peer_with_alpn(&self.endpoint, peer_id, transport::FILES_ALPN)
            .await
        {
            Ok(conn) => match conn.open_bi().await {
                Ok((mut send, _)) => {
                    if let Err(e) = control::send_msg(&mut send, &msg).await {
                        return IpcMessage::Error {
                            message: format!("failed to send offer: {e}"),
                        };
                    }
                    // send_msg already finished the stream; wait for the peer to
                    // read the offer so it flushes before this `conn` is dropped.
                    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
                }
                Err(e) => {
                    return IpcMessage::Error {
                        message: format!("failed to open stream: {e}"),
                    };
                }
            },
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot reach peer '{peer}': {e}"),
                };
            }
        }

        IpcMessage::Ok {
            message: format!("offered {} ({}) to {}", filename, format_size(size), peer),
        }
    }

    pub fn list_files(&self) -> IpcMessage {
        let pending = self.files.pending_files.lock().unwrap();
        let files = pending
            .iter()
            .map(|f| ipc::PendingFileInfo {
                id: f.id,
                from: f.from.fmt_short().to_string(),
                filename: f.filename.clone(),
                size: f.size,
                mime_type: f.mime_type.clone(),
                own_device: self.is_own_device_sender(f.from),
            })
            .collect();
        IpcMessage::FileList { files }
    }

    /// Decline a pending file offer: drop it from the queue without fetching the
    /// blob. In-memory only, mirroring how `accept_file` consumes the entry.
    pub fn reject_file(&self, id: u64) -> IpcMessage {
        let mut pending = self.files.pending_files.lock().unwrap();
        match pending.iter().position(|f| f.id == id) {
            Some(i) => {
                pending.remove(i);
                IpcMessage::Ok {
                    message: format!("declined file {id}"),
                }
            }
            None => IpcMessage::Error {
                message: format!("no pending file with id {id}"),
            },
        }
    }

    pub async fn accept_file(
        &self,
        id: u64,
        output: Option<String>,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        let pending_file = {
            let mut pending = self.files.pending_files.lock().unwrap();
            let idx = pending.iter().position(|f| f.id == id);
            match idx {
                Some(i) => pending.remove(i),
                None => {
                    return IpcMessage::Error {
                        message: format!("no pending file with id {id}"),
                    };
                }
            }
        };

        let blob_hash = iroh_blobs::Hash::from_bytes(*pending_file.blob_hash.as_bytes());

        let conn = match transport::connect_to_peer_with_alpn(
            &self.endpoint,
            pending_file.from,
            iroh_blobs::protocol::ALPN,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("cannot reach sender: {e}"),
                };
            }
        };

        if let Err(e) = self
            .blob_store
            .remote()
            .fetch(conn, iroh_blobs::HashAndFormat::raw(blob_hash))
            .await
        {
            return IpcMessage::Error {
                message: format!("blob fetch failed: {e}"),
            };
        }

        let bytes = match self.blob_store.blobs().get_bytes(blob_hash).await {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("blob read failed: {e}"),
                };
            }
        };

        let dir = match output {
            Some(ref p) => PathBuf::from(p),
            None => dirs::download_dir().unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("Downloads")
            }),
        };

        if let Err(e) = std::fs::create_dir_all(&dir) {
            return IpcMessage::Error {
                message: format!("cannot create directory '{}': {e}", dir.display()),
            };
        }

        let dest = dir.join(&pending_file.filename);
        if let Err(e) = std::fs::write(&dest, &bytes) {
            return IpcMessage::Error {
                message: format!("write failed: {e}"),
            };
        }

        if let Some((uid, gid)) = peer_cred {
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = CString::new(dest.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
            if let Ok(c) = CString::new(dir.as_os_str().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
        }

        IpcMessage::Ok {
            message: format!("saved to {}", dest.display()),
        }
    }

    /// Evaluate a newly-queued (or already-pending) file offer against the
    /// own-devices auto-accept policy and, if it qualifies, accept it without
    /// user action. A no-op (offer stays queued) unless: the sender resolves to
    /// *our own* user identity (a paired device) **and** it is a member of at
    /// least one network with `auto_accept_files` enabled. Never removes the
    /// pending entry unless it actually accepts (via `accept_file`).
    pub(crate) async fn try_auto_accept_file(&self, id: u64) {
        // Peek the offer's sender without consuming the queue entry.
        let from = {
            let pending = self.files.pending_files.lock().unwrap();
            match pending.iter().find(|f| f.id == id) {
                Some(f) => f.from,
                None => return,
            }
        };

        // Own-device gate: the sender must resolve to one of our own paired
        // devices (see `is_own_device_sender`).
        if !self.is_own_device_sender(from) {
            return;
        }

        // Network gate: the sender must be a member of a network we've enabled.
        let mut on_enabled_network = false;
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
                .map(|s| s.members.all().iter().any(|m| m.identity == from))
                .unwrap_or(false);
            if is_member {
                on_enabled_network = true;
                break;
            }
        }
        if !on_enabled_network {
            return;
        }

        // Placement must be explicitly resolvable (download-dir / download-user /
        // operator). With none configured we do not write as root: leave the
        // offer queued for manual `ray files accept`.
        let (dir, cred) = match resolve_download_target() {
            Some((dir, cred)) => (dir, cred),
            None => {
                tracing::warn!(
                    from = %from.fmt_short(),
                    "auto-accept: no download target configured (set `ray files download-dir` or `download-user`); leaving offer queued"
                );
                return;
            }
        };
        let output = Some(dir.to_string_lossy().into_owned());

        match self.accept_file(id, output, cred).await {
            IpcMessage::Ok { message } => {
                tracing::info!(from = %from.fmt_short(), %message, "file auto-accepted from own device");
            }
            IpcMessage::Error { message } => {
                tracing::warn!(from = %from.fmt_short(), %message, "file auto-accept failed");
            }
            _ => {}
        }
    }

    /// Toggle this node's per-network auto-accept of file offers from our own
    /// paired devices (persisted in config). Turning it on also drains any
    /// already-queued offers that now qualify.
    pub(crate) async fn files_auto_accept(&self, network: &str, enabled: bool) -> IpcMessage {
        if !self.networks.contains_key(network) {
            return IpcMessage::Error {
                message: format!("network '{network}' not found"),
            };
        }
        match config::load_network(network) {
            Ok(Some(mut nc)) => {
                nc.auto_accept_files = enabled;
                if let Err(e) = config::save_network(&nc) {
                    return IpcMessage::Error {
                        message: format!("failed to persist auto-accept setting: {e}"),
                    };
                }
            }
            Ok(None) => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not found in config"),
                };
            }
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to load config: {e}"),
                };
            }
        }
        // On enable, sweep any already-queued offers so a file that arrived
        // before the toggle still lands.
        if enabled {
            let ids: Vec<u64> = self
                .files
                .pending_files
                .lock()
                .unwrap()
                .iter()
                .map(|f| f.id)
                .collect();
            for id in ids {
                self.try_auto_accept_file(id).await;
            }
        }
        IpcMessage::Ok {
            message: format!(
                "auto-accept files from your own devices {} for '{network}'",
                if enabled { "enabled" } else { "disabled" }
            ),
        }
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// mint a pairing ticket for this device.
    pub fn start_pairing(&self) -> IpcMessage {
        // Only a primary (a device that holds no cert of its own) may mint device
        // certs. A device that already carries a cert is a secondary: its key is
        // not the user identity, so any cert it signed would bind the new device
        // to the wrong identity and fork the device group. Refuse to hand out a
        // pairing ticket in that case; new devices must pair from the primary.
        if self.current_device_cert().is_some() {
            return IpcMessage::Error {
                message: "this device is already paired; add new devices from your primary device"
                    .to_string(),
            };
        }

        let secret: [u8; 32] = rand::random();

        let endpoint_id = self.endpoint.id();
        let mut ticket_bytes = Vec::with_capacity(64);
        ticket_bytes.extend_from_slice(endpoint_id.as_bytes());
        ticket_bytes.extend_from_slice(&secret);
        let ticket = bs58::encode(&ticket_bytes).into_string();

        *self.files.pairing_secret.lock().unwrap() = Some(secret);

        tracing::info!("pairing session opened; awaiting a secondary to scan the ticket");
        IpcMessage::PairingTicket { ticket }
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// pair this device with a primary device using a scanned ticket.
    #[tracing::instrument(skip_all, fields(primary = %endpoint_id.fmt_short()))]
    pub async fn pair_with_device(
        self: &Arc<Self>,
        endpoint_id: EndpointId,
        secret: Vec<u8>,
    ) -> IpcMessage {
        let addr: iroh::EndpointAddr = endpoint_id.into();
        tracing::info!(primary = %endpoint_id.fmt_short(), "dialing primary device for pairing");
        // `Endpoint::connect` has no built-in timeout: if a path to the primary
        // never establishes (primary offline, no open pairing session, or an
        // unreachable relay/NAT path) it keeps retrying discovery and the caller
        // hangs indefinitely. Bound it so pairing fails fast with a clear message.
        let conn = match tokio::time::timeout(
            PAIR_CONNECT_TIMEOUT,
            self.endpoint.connect(addr, PAIR_ALPN),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "pairing: could not connect to primary device");
                return IpcMessage::Error {
                    message: format!("failed to connect to primary device: {e}"),
                };
            }
            Err(_) => {
                tracing::warn!(
                    timeout_secs = PAIR_CONNECT_TIMEOUT.as_secs(),
                    "pairing: timed out connecting to primary device"
                );
                return IpcMessage::Error {
                    message: "timed out reaching the primary device. Make sure it is online and \
                              that you opened pairing on it (run `ray pair` there)."
                        .to_string(),
                };
            }
        };
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to open stream: {e}"),
                };
            }
        };

        let secret_arr: [u8; 32] = match secret.try_into() {
            Ok(a) => a,
            Err(_) => {
                return IpcMessage::Error {
                    message: "invalid secret length".to_string(),
                };
            }
        };

        let request = control::PairMsg::Request {
            secret: secret_arr,
            device_pubkey: self.endpoint.id(),
        };
        let request_bytes = match rmp_serde::to_vec_named(&request) {
            Ok(b) => b,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to encode pair request: {e}"),
                };
            }
        };
        let len = (request_bytes.len() as u32).to_be_bytes();
        if let Err(e) = send.write_all(&len).await {
            return IpcMessage::Error {
                message: format!("failed to send pair request: {e}"),
            };
        }
        if let Err(e) = send.write_all(&request_bytes).await {
            return IpcMessage::Error {
                message: format!("failed to send pair request: {e}"),
            };
        }

        // Read PairResponse
        let mut len_buf = [0u8; 4];
        if let Err(e) = recv.read_exact(&mut len_buf).await {
            return IpcMessage::Error {
                message: format!("failed to read pair response: {e}"),
            };
        }
        let body_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; body_len];
        if let Err(e) = recv.read_exact(&mut body).await {
            return IpcMessage::Error {
                message: format!("failed to read pair response body: {e}"),
            };
        }
        let response: control::PairMsg = match rmp_serde::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to decode pair response: {e}"),
                };
            }
        };

        match response {
            control::PairMsg::Response { cert, networks } => {
                if !cert.verify() {
                    return IpcMessage::Error {
                        message: "received invalid device certificate".to_string(),
                    };
                }
                if let Err(e) = identity::store_device_cert(&cert) {
                    return IpcMessage::Error {
                        message: format!("failed to store device certificate: {e}"),
                    };
                }
                // Auto-join every network the primary shared. Each join attaches the
                // freshly stored cert (see current_device_cert) so the coordinator,
                // which owns this device, admits it without manual approval.
                for net in networks {
                    if self.networks.contains_key(&net.network_key) {
                        continue;
                    }
                    let me = Arc::clone(self);
                    let net_name = net.name.clone();
                    let net_key = net.network_key.clone();
                    tokio::spawn(async move {
                        match me
                            .join_network(&net_key, Some(&net_name), None, None, None, false, false)
                            .await
                        {
                            IpcMessage::Joined { .. } | IpcMessage::Ok { .. } => {
                                tracing::info!(network = %net_name, "pairing auto-join ok");
                            }
                            IpcMessage::Error { message } => {
                                tracing::warn!(network = %net_name, error = %message, "pairing auto-join failed");
                            }
                            other => {
                                tracing::warn!(network = %net_name, response = ?other, "pairing auto-join: unexpected response");
                            }
                        }
                    });
                }
                tracing::info!("pairing complete; device certificate stored");
                IpcMessage::PairingComplete {
                    user_identity: cert.user_identity,
                }
            }
            _ => IpcMessage::Error {
                message: "unexpected pairing response".to_string(),
            },
        }
    }

    /// This node's "user identity": our device cert's `user_identity` if we are a
    /// paired secondary, else our own endpoint id (we are the primary). Matches
    /// the own-device gate used by file auto-accept.
    fn own_user_identity(&self) -> EndpointId {
        self.current_device_cert()
            .map(|c| c.user_identity)
            .unwrap_or_else(|| self.endpoint.id())
    }

    /// Enumerate this user's paired secondary devices from the network rosters
    /// (`ray pair list`). A paired device is any roster member whose
    /// `user_identity` is ours but whose device id is neither ours nor the user
    /// identity itself.
    pub(crate) fn list_paired_devices(&self) -> IpcMessage {
        let own_user = self.own_user_identity();
        let own_device = self.endpoint.id();
        let mut by_device: HashMap<EndpointId, (Option<String>, Vec<String>)> = HashMap::new();
        for entry in self.networks.iter() {
            let net_name = entry.key().clone();
            let roster = entry.value().state.read().unwrap().roster();
            for m in roster {
                if m.user_identity == Some(own_user)
                    && m.identity != own_user
                    && m.identity != own_device
                {
                    let e = by_device
                        .entry(m.identity)
                        .or_insert_with(|| (m.hostname.clone(), Vec::new()));
                    if e.0.is_none() {
                        e.0 = m.hostname.clone();
                    }
                    e.1.push(net_name.clone());
                }
            }
        }
        let devices = by_device
            .into_iter()
            .map(|(device_id, (hostname, mut networks))| {
                networks.sort();
                networks.dedup();
                ipc::PairedDeviceInfo {
                    device_id,
                    short_id: device_id.fmt_short().to_string(),
                    hostname,
                    networks,
                }
            })
            .collect();
        IpcMessage::PairedDevices { devices }
    }

    /// Revoke one of this user's paired devices (`ray unpair`). Primary-only.
    ///
    /// Persists + publishes a signed revocation record for the device key,
    /// enforces it locally right away, best-effort tells the device to wipe its
    /// own cert, and — on every network this node coordinates — removes the
    /// device from the roster and republishes so the blob stops carrying its
    /// cert. Live links to the device are severed everywhere; other nodes drop it
    /// when they reconverge (or resolve the revocation record).
    pub(crate) async fn unpair(self: &Arc<Self>, device: &str) -> IpcMessage {
        // Only the primary holds the user identity secret that signs both the
        // certs and their revocation. A secondary carries a device cert.
        if self.current_device_cert().is_some() {
            return IpcMessage::Error {
                message: "only your primary device can unpair a device".to_string(),
            };
        }
        let own_user = self.endpoint.id();

        let target = match self.resolve_peer_flexible(device).await {
            Some(id) => id,
            None => {
                return IpcMessage::Error {
                    message: format!("could not resolve device '{device}'"),
                };
            }
        };
        if target == own_user {
            return IpcMessage::Error {
                message: "that is your primary device, not a paired secondary".to_string(),
            };
        }

        // Confirm the target is actually one of our paired devices, and grab a
        // display name. Collect the coordinated-network handles at the same time
        // (cloning the Arc state) so we drop the DashMap guards before awaiting.
        let mut display = target.fmt_short().to_string();
        let mut is_paired = false;
        let mut nets: Vec<(String, SharedNetworkState, Option<Arc<Notify>>, bool)> = Vec::new();
        for entry in self.networks.iter() {
            let s = entry.value().state.read().unwrap();
            if let Some(m) = s.members.all().iter().find(|m| m.identity == target)
                && m.user_identity == Some(own_user)
            {
                is_paired = true;
                if let Some(h) = &m.hostname {
                    display = h.clone();
                }
            }
            let has_key = s.network_secret_key.is_some();
            drop(s);
            nets.push((
                entry.key().clone(),
                entry.value().state.clone(),
                entry.value().dht_notify.clone(),
                has_key,
            ));
        }
        if !is_paired {
            return IpcMessage::Error {
                message: format!(
                    "'{device}' is not one of your paired devices (see `ray pair list`)"
                ),
            };
        }

        // 1. Add the device to our revoked set and bump the revocation version.
        //    Per-cert: only this device is revoked; every other device we keep is
        //    left untouched (no generation bump, no re-issue).
        let mut cfg = config::load().unwrap_or_default();
        let hex = target.to_string();
        if !cfg.revoked_devices.contains(&hex) {
            cfg.revoked_devices.push(hex);
        }
        cfg.revocation_version += 1;
        let version = cfg.revocation_version;
        let revoked_set: std::collections::HashSet<EndpointId> =
            config::revoked_device_ids(&cfg).into_iter().collect();
        if let Err(e) = config::save_settings(&cfg) {
            return IpcMessage::Error {
                message: format!("failed to persist revocation: {e}"),
            };
        }
        self.revocation
            .set_local(own_user, version, revoked_set.clone());
        self.device_user_map.remove(&target);

        // 2. Publish the updated revoked set, so every peer rejects the revoked
        //    device's cert (verifiers adopt it on its strictly-newer version).
        let devices: Vec<EndpointId> = revoked_set.into_iter().collect();
        if let Ok(client) = dht::create_pkarr_client(&self.endpoint)
            && let Ok(secret) = crate::identity::load_or_create()
            && let Err(e) = dht::publish_revoked(&client, &secret, version, &devices).await
        {
            tracing::warn!(error = %e, "failed to publish revoked-device record");
        }

        // 3. Best-effort: ask the revoked device to wipe its own cert if online.
        self.send_unpaired_notice(target).await;

        // 4. Drop the device from every network we coordinate, and sever links.
        for (net, state, dht_notify, has_key) in nets {
            if has_key {
                let member_ip = {
                    let mut s = state.write().unwrap();
                    let ip = s
                        .members
                        .all()
                        .iter()
                        .find(|m| m.identity == target)
                        .map(|m| m.ip);
                    s.members.remove(&target);
                    s.approved.remove(&target);
                    ip
                };
                if let Some(ip) = member_ip {
                    dns::remove_hostname_by_ip(
                        &self.dns.hostname_table,
                        &self.dns.reverse_table,
                        &net,
                        ip,
                    )
                    .await;
                }
                update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
            }
            for (pid, ip, conn) in self.peers.peers_for_network_with_conn(&net) {
                if pid == target {
                    self.pruned_peers.insert((net.clone(), pid));
                    conn.close(VarInt::from_u32(forward::KICK_CODE), b"unpaired");
                    self.peers
                        .remove_peer_from_network(&ip, &derive_ipv6(&pid), &net);
                }
            }
        }
        // Nudge other members to reconverge from the freshly republished records.
        broadcast_member_sync(&self.peers, None).await;

        tracing::info!(device = %target.fmt_short(), "unpaired device");
        IpcMessage::Ok {
            message: format!("unpaired '{display}' and revoked its device certificate"),
        }
    }

    /// Best-effort `ControlMsg::Unpaired` to a device over any shared live mesh
    /// connection, asking it to wipe its own cert. Never blocks unpair on success
    /// — the authoritative revocation is the signed pkarr record.
    async fn send_unpaired_notice(&self, target: EndpointId) {
        for entry in self.networks.iter() {
            let net = entry.key().clone();
            for (pid, _ip, conn) in self.peers.peers_for_network_with_conn(&net) {
                if pid != target {
                    continue;
                }
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let _ = control::send_msg(&mut send, &ControlMsg::Unpaired).await;
                    let _ = send.finish();
                }
                return;
            }
        }
    }

    /// Unpair *this* device from its primary, locally. Deletes the stored device
    /// cert and leaves every network this device joined under the shared identity,
    /// closing each connection with the leave code so coordinators prune us and
    /// every peer drops us right away (rather than waiting on the revocation
    /// floor). Used by the phone's "unpair this device" control and by the
    /// device-side handler when its primary sends `ControlMsg::Unpaired`. A device
    /// with no cert (a primary) has nothing to unpair.
    pub async fn unpair_self(self: &Arc<Self>) -> IpcMessage {
        if self.current_device_cert().is_none() {
            return IpcMessage::Error {
                message: "this device is not paired to a primary".to_string(),
            };
        }
        // Leave every network first (graceful LEAVE_CODE close + config removal),
        // so peers see an intentional departure and prune us immediately.
        let networks: Vec<String> = self.networks.iter().map(|e| e.key().clone()).collect();
        for net in &networks {
            self.leave_network(net).await;
        }
        // Then wipe the cert so this device is no longer one of its user's devices.
        match crate::identity::delete_device_cert() {
            Ok(()) => tracing::warn!("unpaired this device: deleted device certificate and left all networks"),
            Err(e) => {
                tracing::warn!(error = %e, "unpair: failed to delete device cert");
                return IpcMessage::Error {
                    message: format!("left all networks but failed to delete device cert: {e}"),
                };
            }
        }
        IpcMessage::Ok {
            message: format!("unpaired this device (left {} network(s))", networks.len()),
        }
    }
}

/// Device-side handler for an inbound `ControlMsg::Unpaired` from `sender`. Acts
/// only when this device holds a cert signed by `sender` (so a stranger can't
/// trigger a wipe): deletes the stored device cert best-effort. The authoritative
/// revocation is the signed pkarr record; this just completes a cooperative wipe.
/// The in-memory cert copy clears on the next daemon restart.
/// This node's cert-issuing authority for [`revocation::cert_decision`]:
/// `(issuing_identity, revoked_set)`. The issuing identity is `Some(my_identity)`
/// only on the **primary** (holds the user secret + the authoritative revoked
/// set); on a secondary it is `None`, so every cert is judged by the published
/// set instead. Reads config fresh so a revoke/re-auth takes effect without a
/// restart.
pub(crate) fn cert_authority(
    my_identity: EndpointId,
) -> (Option<EndpointId>, std::collections::HashSet<EndpointId>) {
    let is_primary = crate::identity::load_device_cert().ok().flatten().is_none();
    if is_primary {
        let cfg = config::load().unwrap_or_default();
        (
            Some(my_identity),
            config::revoked_device_ids(&cfg).into_iter().collect(),
        )
    } else {
        (None, std::collections::HashSet::new())
    }
}

/// Device-side handler for an inbound `ControlMsg::CertRefresh`. Retained for
/// wire-compat with older peers that may still send it (the per-cert revocation
/// model no longer re-issues certs, so nothing sends `CertRefresh` now). Stores
/// the new cert only when it is signed by our own user identity, binds our own
/// device key, verifies, and is at a generation no lower than the one we already
/// hold (so a replayed old cert can't downgrade us).
pub(crate) fn store_refreshed_cert(cert: &control::DeviceCert) {
    let Ok(Some(current)) = crate::identity::load_device_cert() else {
        return;
    };
    if cert.verify()
        && cert.user_identity == current.user_identity
        && cert.device_key == current.device_key
        && cert.generation >= current.generation
    {
        match crate::identity::store_device_cert(cert) {
            Ok(()) => tracing::info!(
                generation = cert.generation,
                "stored refreshed device certificate (rotation)"
            ),
            Err(e) => tracing::warn!(error = %e, "failed to store refreshed device cert"),
        }
    }
}

/// Returns true when `sender` is this device's primary (it signed our cert), so
/// the caller can also tear the device out of the mesh. The cert deletion itself
/// is deferred to [`MeshManager::unpair_self`] (called by the caller) so the
/// leave-all runs first while the cert still identifies our networks.
pub(crate) fn is_unpaired_by(sender: EndpointId) -> bool {
    matches!(
        crate::identity::load_device_cert(),
        Ok(Some(cert)) if cert.user_identity == sender
    )
}

/// (gid, home) for a uid via the passwd db, or None if it can't be resolved.
fn pw_gid_home(uid: u32) -> Option<(u32, PathBuf)> {
    // SAFETY: getpwuid returns a pointer into a static buffer; copy fields out
    // immediately before any other libc call can clobber it.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return None;
        }
        let gid = (*pw).pw_gid;
        let home = std::ffi::CStr::from_ptr((*pw).pw_dir)
            .to_string_lossy()
            .into_owned();
        Some((gid, PathBuf::from(home)))
    }
}

/// A uid's ~/Downloads plus its (uid, gid) owner, if the uid resolves.
fn user_downloads(uid: u32) -> Option<(PathBuf, (u32, u32))> {
    let (gid, home) = pw_gid_home(uid)?;
    Some((home.join("Downloads"), (uid, gid)))
}

/// (uid, gid) that currently owns `path`, if it exists.
fn dir_owner(path: &std::path::Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.uid(), m.gid()))
}

/// Resolve the auto-accept target from live config, applying the precedence in
/// [`pick_download_target`]. `None` means "no configured target": the caller
/// must leave the offer queued rather than writing as root. The daemon runs as
/// root, so its own `~/Downloads` is never a valid fallback.
fn resolve_download_target() -> Option<(PathBuf, Option<(u32, u32)>)> {
    let cfg = config::load().ok()?;
    let dir = cfg.download_dir.map(PathBuf::from);
    let dir_owned = dir.as_deref().and_then(dir_owner);
    let user = cfg.download_user.and_then(user_downloads);
    let operator = cfg.operator_uid.and_then(user_downloads);
    pick_download_target(dir, dir_owned, user, operator)
}

/// Decide the auto-accept target `(dir, owner)` from resolved inputs. Pure so
/// the precedence is unit-tested without touching the filesystem. First match:
/// 1. `dir` set -> that dir; owner = `user`'s cred if set, else the dir's owner.
/// 2. `user` set -> that user's ~/Downloads, owned by them.
/// 3. `operator` set -> operator's ~/Downloads, owned by them.
/// 4. otherwise None (caller must not write).
fn pick_download_target(
    dir: Option<PathBuf>,
    dir_owner: Option<(u32, u32)>,
    user: Option<(PathBuf, (u32, u32))>,
    operator: Option<(PathBuf, (u32, u32))>,
) -> Option<(PathBuf, Option<(u32, u32)>)> {
    if let Some(d) = dir {
        let owner = user.map(|(_, cred)| cred).or(dir_owner);
        return Some((d, owner));
    }
    if let Some((home, cred)) = user {
        return Some((home, Some(cred)));
    }
    if let Some((home, cred)) = operator {
        return Some((home, Some(cred)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::pick_download_target;
    use std::path::PathBuf;

    fn dl(p: &str) -> PathBuf {
        PathBuf::from(p)
    }

    #[test]
    fn dir_with_user_owns_as_user() {
        let got = pick_download_target(
            Some(dl("/srv/in")),
            Some((5, 5)),
            Some((dl("/home/bob/Downloads"), (1000, 1000))),
            Some((dl("/home/op/Downloads"), (1001, 1001))),
        );
        assert_eq!(got, Some((dl("/srv/in"), Some((1000, 1000)))));
    }

    #[test]
    fn dir_without_user_inherits_dir_owner() {
        let got = pick_download_target(
            Some(dl("/srv/in")),
            Some((5, 5)),
            None,
            Some((dl("/home/op/Downloads"), (1001, 1001))),
        );
        assert_eq!(got, Some((dl("/srv/in"), Some((5, 5)))));
    }

    #[test]
    fn user_downloads_when_no_dir() {
        let got = pick_download_target(
            None,
            None,
            Some((dl("/home/bob/Downloads"), (1000, 1000))),
            Some((dl("/home/op/Downloads"), (1001, 1001))),
        );
        assert_eq!(got, Some((dl("/home/bob/Downloads"), Some((1000, 1000)))));
    }

    #[test]
    fn operator_fallback_when_no_dir_or_user() {
        let got = pick_download_target(
            None,
            None,
            None,
            Some((dl("/home/op/Downloads"), (1001, 1001))),
        );
        assert_eq!(got, Some((dl("/home/op/Downloads"), Some((1001, 1001)))));
    }

    #[test]
    fn none_when_nothing_resolves() {
        assert_eq!(pick_download_target(None, None, None, None), None);
    }
}
