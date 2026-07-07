//! File-sharing and device-pairing handlers for `Daemon`: `send_file`,
//! `list_files`, `accept_file`, pairing. Split out of `daemon/mod.rs`.

use super::super::*;

/// Upper bound on the pairing dial to a primary device. `Endpoint::connect`
/// retries discovery/relay with no timeout of its own, so without this an
/// unreachable primary hangs the pairing call forever.
const PAIR_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

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

    /// Toggle per-network own-device file auto-accept (delegates to
    /// [`FileService`]).
    pub(crate) async fn files_auto_accept(&self, network: &str, enabled: bool) -> IpcMessage {
        self.files.files_auto_accept(network, enabled).await
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
        let addr: iroh::EndpointAddr = endpoint_id.into();
        tracing::info!(primary = %endpoint_id.fmt_short(), "dialing primary device for pairing");
        // `Endpoint::connect` has no built-in timeout: if a path to the primary
        // never establishes (primary offline, no open pairing session, or an
        // unreachable relay/NAT path) it keeps retrying discovery and the caller
        // hangs indefinitely. Bound it so pairing fails fast with a clear message.
        let conn = match tokio::time::timeout(
            PAIR_CONNECT_TIMEOUT,
            self.transport.endpoint.connect(addr, PAIR_ALPN),
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
                return ipc_err("timed out reaching the primary device. Make sure it is online and \
                              that you opened pairing on it (run `ray pair` there)."
                        .to_string());
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
        let request_bytes = match rmp_serde::to_vec_named(&request) {
            Ok(b) => b,
            Err(e) => {
                return ipc_err(format!("failed to encode pair request: {e}"));
            }
        };
        let len = (request_bytes.len() as u32).to_be_bytes();
        if let Err(e) = send.write_all(&len).await {
            return ipc_err(format!("failed to send pair request: {e}"));
        }
        if let Err(e) = send.write_all(&request_bytes).await {
            return ipc_err(format!("failed to send pair request: {e}"));
        }

        // Read PairResponse
        let mut len_buf = [0u8; 4];
        if let Err(e) = recv.read_exact(&mut len_buf).await {
            return ipc_err(format!("failed to read pair response: {e}"));
        }
        let body_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; body_len];
        if let Err(e) = recv.read_exact(&mut body).await {
            return ipc_err(format!("failed to read pair response body: {e}"));
        }
        let response: control::PairMsg = match rmp_serde::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return ipc_err(format!("failed to decode pair response: {e}"));
            }
        };

        match response {
            control::PairMsg::Response { cert, networks } => {
                if !cert.verify() {
                    return ipc_err("received invalid device certificate".to_string());
                }
                if let Err(e) = identity::store_device_cert(&cert) {
                    return ipc_err(format!("failed to store device certificate: {e}"));
                }
                // Auto-join every network the primary shared. Each join attaches the
                // freshly stored cert (see current_device_cert) so the coordinator,
                // which owns this device, admits it without manual approval. Dial
                // the primary itself as the coordinator: it just shared these
                // networks (so it is online and either coordinates them or knows a
                // coordinator), and this does not depend on the fetched blob's
                // roster flagging it `is_coordinator`. Falls back to the blob's
                // coordinators if the primary does not admit.
                for net in networks {
                    if self.registry.networks.contains_key(&net.network_key) {
                        continue;
                    }
                    let me = Arc::clone(self);
                    let net_name = net.name.clone();
                    let net_key = net.network_key.clone();
                    tokio::spawn(async move {
                        match me
                            .join_network(
                                &net_key,
                                Some(&net_name),
                                None,
                                None,
                                Some(endpoint_id),
                                false,
                                false,
                            )
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
            _ => ipc_err("unexpected pairing response".to_string()),
        }
    }

    /// `ray pair list`: enumerate this user's other paired devices.
    pub(crate) fn list_paired_devices(&self) -> IpcMessage {
        self.files.list_paired_devices()
    }

    /// Revoke one of this user's paired devices (`ray unpair`). Primary-only.
    ///
    /// Records the device key as a durable nullifier (`revoked_devices`), then, on
    /// every network this node coordinates, adds it to the signed blob's nullifier
    /// set, removes it from the roster, and republishes, so the blob stops
    /// honoring its cert. Best-effort tells the device to wipe its own cert. Live
    /// links to the device are severed everywhere; other nodes reject its cert and
    /// prune it when they reconverge from the republished blob. Networks this node
    /// does not coordinate are unaffected in Phase 1 (see the amendments design).
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

        // Best-effort: ask the device to wipe its own cert while the link is still
        // up (nullifying below severs it). A spurious notice to a non-secondary is
        // a no-op on the receiver (`is_unpaired_by`), so it is safe to send before
        // the paired-device check inside `nullify_device`.
        self.send_unpaired_notice(target).await;

        // Write the authoritative nullifier across every network we coordinate.
        match self.registry.nullify_device(target).await {
            Ok(display) => IpcMessage::Ok {
                message: format!("unpaired '{display}' and nullified its device certificate"),
            },
            Err(message) => ipc_err(message),
        }
    }

    /// Best-effort `ControlMsg::Unpaired` to a device over any shared live mesh
    /// connection, asking it to wipe its own cert. Never blocks unpair on success
    /// the authoritative revocation is the signed pkarr record.
    async fn send_unpaired_notice(&self, target: EndpointId) {
        for entry in self.registry.networks.iter() {
            let net = entry.key().clone();
            for (pid, _ip, conn) in self.registry.peers.peers_for_network_with_conn(&net) {
                if pid != target {
                    continue;
                }
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let _ = control::send_msg(&mut send, None, &ControlMsg::Unpaired).await;
                    let _ = send.finish();
                }
                return;
            }
        }
    }

    /// Best-effort `ControlMsg::RequestUnpair` to our primary over a shared live
    /// mesh connection, asking it to write the authoritative nullifier for this
    /// device. Sent while the link is up, before we tear ourselves down. If it is
    /// not delivered (we are offline from the primary) the primary keeps a stale
    /// roster entry until someone runs `ray unpair` on it; the local teardown still
    /// happens either way. A device with no cert (a primary) has no primary to ask.
    async fn request_primary_nullify(&self) {
        let Some(cert) = self.registry.current_device_cert() else {
            return;
        };
        let primary = cert.user_identity;
        for entry in self.registry.networks.iter() {
            let net = entry.key().clone();
            for (pid, _ip, conn) in self.registry.peers.peers_for_network_with_conn(&net) {
                if pid != primary {
                    continue;
                }
                if let Ok((mut send, _recv)) = conn.open_bi().await {
                    let _ = control::send_msg(&mut send, None, &ControlMsg::RequestUnpair).await;
                    let _ = send.finish();
                }
                return;
            }
        }
    }

    /// Unpair *this* device from its primary. First asks the primary to write the
    /// authoritative nullifier (`request_primary_nullify`, best-effort while the
    /// link is up), then locally deletes the stored device cert and leaves every
    /// network this device joined under the shared identity, closing each
    /// connection with the leave code so coordinators prune us and every peer drops
    /// us right away (rather than waiting on the revocation floor). Used by the
    /// phone's "unpair this device" control. A device with no cert (a primary) has
    /// nothing to unpair.
    pub async fn unpair_self(&self) -> IpcMessage {
        self.request_primary_nullify().await;
        self.registry.unpair_self().await
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
/// is deferred to [`Daemon::unpair_self`] (called by the caller) so the
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
