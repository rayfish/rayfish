//! File-sharing and device-pairing handlers for `Daemon`: `send_file`,
//! `list_files`, `accept_file`, pairing. Split out of `daemon/mod.rs`.

use super::super::*;

/// Upper bound on the pairing dial to a primary device. `Endpoint::connect`
/// retries discovery/relay with no timeout of its own, so without this an
/// unreachable primary hangs the pairing call forever.
const PAIR_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a device spends telling its primary the new certificate is saved,
/// and then waiting for the primary to close the pairing connection.
const PAIR_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

impl Daemon {
    pub(crate) async fn resolve_peer_name(&self, name: &str) -> Option<EndpointId> {
        self.registry.resolve_peer_name(name).await
    }

    /// Resolve a peer argument to its **device** endpoint id, accepting more
    /// forms than [`Self::resolve_peer_name`] (delegates to [`NetworkRegistry`]).
    pub(crate) async fn resolve_peer_flexible(&self, name: &str) -> Option<EndpointId> {
        self.registry.resolve_peer_flexible(name).await
    }

    pub async fn send_file(&self, path: &str, peer: &str) -> IpcMessage {
        self.files.send_file(path, peer).await
    }

    pub fn list_files(&self) -> IpcMessage {
        self.files.list_files()
    }

    /// Decline a pending file offer (delegates to [`FileService`]).
    pub fn reject_file(&self, id: u64) -> IpcMessage {
        self.files.reject_file(id)
    }

    /// Drop a queued outbound send before it is delivered (delegates to
    /// [`FileService`]). Public for the `ray-mobile` FFI, matching how the CLI
    /// reaches it via `IpcMessage::CancelSend`.
    pub fn cancel_send(&self, id: u64) -> IpcMessage {
        self.files.cancel_send(id)
    }

    pub fn cancel_transfer(&self, id: u64) -> IpcMessage {
        self.files.cancel_transfer(id)
    }

    /// Accept a queued file offer (delegates to [`FileService`]). Kept as a
    /// public Daemon method for the `ray-mobile` FFI.
    pub async fn accept_file(
        &self,
        id: u64,
        output: Option<String>,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        self.files.accept_file(id, output, peer_cred).await
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// mint a pairing ticket for this device (delegates to [`FileService`]).
    pub fn start_pairing(&self) -> IpcMessage {
        self.files.start_pairing()
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// pair this device with a primary device using a scanned ticket.
    #[tracing::instrument(skip_all, fields(primary = %endpoint_id.fmt_short()))]
    pub async fn pair_with_device(
        self: &Arc<Self>,
        endpoint_id: EndpointId,
        secret: Vec<u8>,
    ) -> IpcMessage {
        // A request this device saved when it last unpaired would revoke the
        // pairing made here: the lock keeps an attempt at it from running
        // while the pairing completes, which then cancels it.
        let _guard = self.registry.unpair_lock.lock().await;
        if let Err(message) = self.registry.finish_cleanups_locked().await {
            return ipc_err(format!("an earlier unpair has not finished: {message}"));
        }
        let addr: iroh::EndpointAddr = endpoint_id.into();
        tracing::info!(primary = %endpoint_id.fmt_short(), "dialing primary device for pairing");
        // `Endpoint::connect` has no built-in timeout: if a path to the primary
        // never establishes (primary offline, no open pairing session, or an
        // unreachable relay/NAT path) it keeps retrying discovery and the caller
        // hangs indefinitely. Bound it so pairing fails fast with a clear message.
        let conn = match tokio::time::timeout(
            PAIR_CONNECT_TIMEOUT,
            connect_pair(&self.transport.endpoint, addr),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "pairing: could not connect to primary device");
                return ipc_err(format!("failed to connect to primary device: {e}"));
            }
            Err(_) => {
                tracing::warn!(
                    timeout_secs = PAIR_CONNECT_TIMEOUT.as_secs(),
                    "pairing: timed out connecting to primary device"
                );
                return ipc_err(
                    "timed out reaching the primary device. Make sure it is online and \
                              that you opened pairing on it (run `ray pair` there)."
                        .to_string(),
                );
            }
        };
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                return ipc_err(format!("failed to open stream: {e}"));
            }
        };

        let secret_arr: [u8; 32] = match secret.try_into() {
            Ok(a) => a,
            Err(_) => {
                return ipc_err("invalid secret length".to_string());
            }
        };

        let request = control::PairMsg::Request {
            secret: secret_arr,
            device_pubkey: self.transport.endpoint.id(),
        };
        if let Err(e) = control::send_framed(&mut send, &request).await {
            return ipc_err(format!("failed to send pair request: {e}"));
        }

        let response: control::PairMsg = match control::recv_framed(&mut recv).await {
            Ok(response) => response,
            Err(e) => {
                return ipc_err(format!("failed to read pair response: {e:#}"));
            }
        };

        match response {
            control::PairMsg::Response { cert, networks } => {
                if !cert.verify()
                    || cert.device_key != self.transport.endpoint.id()
                    || cert.user_identity != endpoint_id
                {
                    return ipc_err("received invalid device certificate".to_string());
                }
                if let Err(e) = identity::store_device_cert(&cert) {
                    return ipc_err(format!("failed to store device certificate: {e}"));
                }
                self.registry.paired_again(cert.user_identity);
                // Until the primary hears the cert is saved, an unpair request
                // about the earlier pairing still revokes. A primary on version
                // 2 does not ask.
                if conn.alpn() == PAIR_ALPN {
                    confirm_certificate_saved(&conn, cert.generation).await;
                }
                // Auto-join every network the primary shared. Each join attaches the
                // freshly stored cert (see current_device_cert) so the coordinator,
                // which owns this device, admits it without manual approval. Dial
                // the primary itself as the coordinator: it just shared these
                // networks (so it is online and either coordinates them or knows a
                // coordinator), and this does not depend on the fetched blob's
                // roster flagging it `is_coordinator`. Falls back to the blob's
                // coordinators if the primary does not admit.
                self.queue_shared_networks(networks, endpoint_id);
                self.registry.poll_nudge.notify_waiters();
                tracing::info!("pairing complete; device certificate stored");
                IpcMessage::PairingComplete {
                    user_identity: cert.user_identity,
                }
            }
            _ => ipc_err("unexpected pairing response".to_string()),
        }
    }

    fn queue_shared_networks(
        self: &Arc<Self>,
        networks: Vec<control::PairNetwork>,
        primary: EndpointId,
    ) {
        for net in networks {
            let Ok(key) = net.network_key.parse::<EndpointId>() else {
                tracing::warn!(network = %net.name, "primary sent invalid network key");
                continue;
            };
            if self
                .registry
                .networks
                .iter()
                .any(|entry| entry.network_key == key)
            {
                continue;
            }
            if let Ok(cfg) = config::load()
                && (cfg
                    .networks
                    .iter()
                    .any(|saved| saved.network_public_key == Some(key))
                    || cfg
                        .pending_joins
                        .iter()
                        .any(|pending| pending.network_key == net.network_key))
            {
                continue;
            }
            if !self.paired_network_joins.insert(key) {
                continue;
            }
            let me = Arc::clone(self);
            let joining = Arc::clone(&self.paired_network_joins);
            let net_name = net.name.clone();
            let net_key = net.network_key.clone();
            tokio::spawn(async move {
                let result = me
                    .join_network(
                        &net_key,
                        Some(&net_name),
                        None,
                        None,
                        Some(primary),
                        false,
                        false,
                    )
                    .await;
                joining.remove(&key);
                match result {
                    IpcMessage::Joined { .. } | IpcMessage::Ok { .. } => {
                        tracing::info!(network = %net_name, "paired network join queued or complete");
                    }
                    IpcMessage::Error { message } => {
                        tracing::warn!(network = %net_name, error = %message, "paired network join failed");
                    }
                    other => {
                        tracing::warn!(network = %net_name, response = ?other, "paired network join: unexpected response");
                    }
                }
            });
        }
    }

    async fn sync_networks_from_primary(self: &Arc<Self>) {
        let Some(cert) = self.registry.current_device_cert() else {
            return;
        };
        let primary = cert.user_identity;
        let request_cert = cert.clone();
        let addr: iroh::EndpointAddr = primary.into();
        let sync = async {
            let conn = connect_pair(&self.transport.endpoint, addr).await?;
            if conn.remote_id() != primary {
                anyhow::bail!("connected to an unexpected primary");
            }
            let (mut send, mut recv) = conn.open_bi().await?;
            let request = control::PairMsg::NetworkListRequest { cert: request_cert };
            control::send_framed(&mut send, &request).await?;
            let response: control::PairMsg = control::recv_framed(&mut recv).await?;
            match response {
                control::PairMsg::NetworkListResponse { networks } => Ok(networks),
                _ => anyhow::bail!("unexpected paired network response"),
            }
        };
        match tokio::time::timeout(PAIR_CONNECT_TIMEOUT, sync).await {
            Ok(Ok(networks)) if self.registry.current_device_cert() == Some(cert) => {
                self.queue_shared_networks(networks, primary);
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::debug!(%error, "paired network sync failed"),
            Err(_) => tracing::debug!("paired network sync timed out"),
        }
    }

    pub(crate) async fn run_paired_network_sync(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(15 * 60));
        let nudge = Arc::clone(&self.registry.poll_nudge);
        loop {
            tokio::select! {
                _ = self.shutdown_token.cancelled() => return,
                _ = tick.tick() => {},
                _ = nudge.notified() => tick.reset(),
            }
            self.sync_networks_from_primary().await;
        }
    }

    /// `ray pair list`: enumerate this user's other paired devices.
    pub(crate) fn list_paired_devices(&self) -> IpcMessage {
        self.files.list_paired_devices()
    }

    /// Revoke one of this user's paired devices (`ray unpair`). Primary-only.
    ///
    /// Records the device key as a durable nullifier (`revoked_devices`), and in
    /// the same write that the device has yet to be told
    /// (`pending_unpair_notices`). Then, on every network this node coordinates,
    /// adds it to the signed blob's nullifier set, removes certificate-joined
    /// memberships, and republishes. Independent memberships remain. Other nodes
    /// reject the revoked cert when they receive the signed blob. The device is
    /// told to wipe its own cert until it confirms, after a restart too (see
    /// `mesh::unpair`). Networks this node does not coordinate rely on that
    /// local unpair.
    pub(crate) async fn unpair(self: &Arc<Self>, device: &str) -> IpcMessage {
        // Only the primary holds the user identity secret that signs both the
        // certs and their revocation. A secondary carries a device cert.
        if self.current_device_cert().is_some() {
            return ipc_err("only your primary device can unpair a device".to_string());
        }
        let own_user = self.transport.endpoint.id();

        let target = match self.resolve_peer_flexible(device).await {
            Some(id) => id,
            None => {
                return ipc_err(format!("could not resolve device '{device}'"));
            }
        };
        if target == own_user {
            return ipc_err("that is your primary device, not a paired secondary".to_string());
        }

        // Save the revocation and the notice, then write the authoritative
        // nullifier across every network we coordinate. The notice loop tells
        // the device from there.
        match self.registry.nullify_device(target, true).await {
            Ok(display) => {
                self.registry.notice_nudge.notify_one();
                IpcMessage::Ok {
                    message: format!("unpaired '{display}' and nullified its device certificate"),
                }
            }
            Err(message) => ipc_err(message),
        }
    }

    /// Unpair *this* device from its primary ([`NetworkRegistry::unpair_self`]):
    /// leave the networks first joined with the primary's certificate, closing
    /// each link with the leave code so coordinators prune us and every peer
    /// drops us right away, delete the certificate, and ask the primary to
    /// record the revocation until it confirms. Each step is saved first, so a
    /// restart finishes it. Used by the phone's "unpair this device" control. A
    /// device with no cert (a primary) has nothing to unpair.
    pub async fn unpair_self(&self) -> IpcMessage {
        self.registry.unpair_self().await
    }
}

/// Tell the primary, over the pairing connection, that the certificate it just
/// sent, at `generation`, is saved (`PairMsg::CertificateSaved`), then wait for
/// the primary to close the connection, so closing first does not reset the
/// message. The pairing is complete either way: a primary that does not hear
/// it only keeps revoking on an unpair request about the earlier pairing.
async fn confirm_certificate_saved(conn: &Connection, generation: u64) {
    let sent = async {
        let (mut send, _recv) = conn.open_bi().await?;
        let saved = control::PairMsg::CertificateSaved { generation };
        control::send_framed(&mut send, &saved).await
    };
    match tokio::time::timeout(PAIR_CONFIRM_TIMEOUT, sent).await {
        Ok(Ok(())) => {
            let _ = tokio::time::timeout(PAIR_CONFIRM_TIMEOUT, conn.closed()).await;
        }
        Ok(Err(error)) => {
            tracing::debug!(error = %format!("{error:#}"), "could not tell the primary the certificate is saved");
        }
        Err(_) => tracing::debug!("timed out telling the primary the certificate is saved"),
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

/// (gid, home) for a uid via the passwd db, or None if it can't be resolved.
#[cfg(unix)]
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
#[cfg(unix)]
fn user_downloads(uid: u32) -> Option<(PathBuf, (u32, u32))> {
    let (gid, home) = pw_gid_home(uid)?;
    Some((home.join("Downloads"), (uid, gid)))
}

#[cfg(not(unix))]
fn user_downloads(_uid: u32) -> Option<(PathBuf, (u32, u32))> {
    None
}

/// (uid, gid) that currently owns `path`, if it exists.
#[cfg(unix)]
fn dir_owner(path: &std::path::Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.uid(), m.gid()))
}

#[cfg(not(unix))]
fn dir_owner(_path: &std::path::Path) -> Option<(u32, u32)> {
    None
}

/// Resolve the auto-accept target from live config, applying the precedence in
/// [`pick_download_target`]. `None` means "no configured target": the caller
/// must leave the offer queued rather than writing as root. The daemon runs as
/// root, so its own `~/Downloads` is never a valid fallback.
pub(crate) fn resolve_download_target() -> Option<(PathBuf, Option<(u32, u32)>)> {
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
