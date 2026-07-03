//! File-sharing and device-pairing handlers for `DaemonState`: `send_file`,
//! `list_files`, `accept_file`, pairing. Split out of `daemon/mod.rs`.

use std::ffi::CString;
use std::path::Path;

use super::super::*;

impl DaemonState {
    pub(crate) async fn resolve_peer_name(&self, name: &str) -> Option<EndpointId> {
        let suffix = format!(".{}", crate::DNS_DOMAIN);
        let qualified = if name.ends_with(&suffix) {
            name.to_string()
        } else {
            format!("{name}{suffix}")
        };
        if let Some((ip, _)) = dns::resolve_name(&qualified, &suffix, &self.hostname_table).await {
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

    pub(crate) async fn send_file(&self, path: &str, peer: &str) -> IpcMessage {
        let peer_id = match self.resolve_peer_name(peer).await {
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

    pub(crate) fn list_files(&self) -> IpcMessage {
        let pending = self.protocol_router.pending_files.lock().unwrap();
        let files = pending
            .iter()
            .map(|f| ipc::PendingFileInfo {
                id: f.id,
                from: f.from.fmt_short().to_string(),
                filename: f.filename.clone(),
                size: f.size,
                mime_type: f.mime_type.clone(),
            })
            .collect();
        IpcMessage::FileList { files }
    }

    pub(crate) async fn accept_file(
        &self,
        id: u64,
        output: Option<String>,
        peer_cred: Option<(u32, u32)>,
    ) -> IpcMessage {
        let pending_file = {
            let mut pending = self.protocol_router.pending_files.lock().unwrap();
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
            let pending = self.protocol_router.pending_files.lock().unwrap();
            match pending.iter().find(|f| f.id == id) {
                Some(f) => f.from,
                None => return,
            }
        };

        // Own-device gate: the sender's resolved user identity must match ours.
        // Our identity is our device cert's user_identity, or (on the primary,
        // which has no cert) our own endpoint id. A non-paired peer resolves to
        // its own transport id and so can never match.
        let own_user = self
            .device_cert
            .as_ref()
            .map(|c| c.user_identity)
            .unwrap_or_else(|| self.endpoint.id());
        let sender_user = self.device_user_map.resolve(&from);
        if sender_user != own_user {
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
                .protocol_router
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
        let secret: [u8; 32] = rand::random();

        let endpoint_id = self.endpoint.id();
        let mut ticket_bytes = Vec::with_capacity(64);
        ticket_bytes.extend_from_slice(endpoint_id.as_bytes());
        ticket_bytes.extend_from_slice(&secret);
        let ticket = bs58::encode(&ticket_bytes).into_string();

        *self.pairing_secret.lock().unwrap() = Some(secret);

        IpcMessage::PairingTicket { ticket }
    }

    /// Part of the embedding API (used by `ray-mobile` and future embedders):
    /// pair this device with a primary device using a scanned ticket.
    pub async fn pair_with_device(&self, endpoint_id: EndpointId, secret: Vec<u8>) -> IpcMessage {
        let addr: iroh::EndpointAddr = endpoint_id.into();
        let conn = match self.endpoint.connect(addr, PAIR_ALPN).await {
            Ok(c) => c,
            Err(e) => {
                return IpcMessage::Error {
                    message: format!("failed to connect to primary device: {e}"),
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
            control::PairMsg::Response { cert } => {
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
                IpcMessage::PairingComplete {
                    user_identity: cert.user_identity,
                }
            }
            _ => IpcMessage::Error {
                message: "unexpected pairing response".to_string(),
            },
        }
    }
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
