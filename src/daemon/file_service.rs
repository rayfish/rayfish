//! File-transfer and device-pairing state, owned as one unit instead of being
//! split across `ProtocolRouter` (pending offers, id counter, pairing secret,
//! signing key) and `MeshManager`.
//!
//! The two ALPN accept arms (`FILES_ALPN` file offers, `PAIR_ALPN` pairing) live
//! here; the `ProtocolRouter` accept loop holds an `Arc<FileService>` and
//! delegates to them. The IPC handlers (`send_file`/`accept_file`/`start_pairing`
//! /…) stay on `MeshManager` since they orchestrate over core handles (endpoint,
//! peers, the shared blob store) and read this service's state.

use super::*;

/// A received file offer awaiting `ray files accept`.
pub(crate) struct PendingFile {
    pub(crate) id: u64,
    pub(crate) from: EndpointId,
    pub(crate) filename: String,
    pub(crate) size: u64,
    pub(crate) mime_type: String,
    pub(crate) blob_hash: blake3::Hash,
}

pub(crate) struct FileService {
    /// Received file offers awaiting `ray files accept`.
    pub(crate) pending_files: Arc<std::sync::Mutex<Vec<PendingFile>>>,
    /// Monotonic id source for pending offers.
    pub(crate) file_id_counter: Arc<AtomicU64>,
    /// Active pairing secret (set by `start_pairing`, consumed by a pair request).
    pub(crate) pairing_secret: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    /// This node's transport secret key, used to sign device certs on pairing.
    secret_key: SecretKey,
    /// Auto-accept nudge: each newly-queued offer's id is sent here so the
    /// daemon-wide worker (`spawn_file_auto_accept`) can evaluate it for
    /// own-device auto-accept without waiting for a manual `ray files accept`.
    new_file_tx: mpsc::UnboundedSender<u64>,
}

impl FileService {
    pub(crate) fn new(secret_key: SecretKey, new_file_tx: mpsc::UnboundedSender<u64>) -> Self {
        Self {
            pending_files: Arc::new(std::sync::Mutex::new(Vec::new())),
            file_id_counter: Arc::new(AtomicU64::new(1)),
            pairing_secret: Arc::new(std::sync::Mutex::new(None)),
            secret_key,
            new_file_tx,
        }
    }

    /// `FILES_ALPN`: read a single `FileOffer` and queue it for `ray files`.
    /// Rejects offers whose claimed sender doesn't match the dialing identity.
    pub(crate) async fn accept_file_offer(&self, conn: Connection) {
        let pending = self.pending_files.clone();
        let counter = self.file_id_counter.clone();
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((_send, mut recv)) => {
                match control::recv_msg(&mut recv).await {
                    Ok(control::ControlMsg::FileOffer {
                        from,
                        filename,
                        size,
                        mime_type,
                        blob_hash,
                    }) => {
                        if from == remote_id {
                            let id = counter.fetch_add(1, Ordering::Relaxed);
                            tracing::info!(from = %from.fmt_short(), filename = %filename, size, "file offer received");
                            pending.lock().unwrap().push(PendingFile {
                                id,
                                from,
                                filename,
                                size,
                                mime_type,
                                blob_hash,
                            });
                            // Nudge the auto-accept worker: it accepts only offers
                            // from our own paired devices on an opted-in network,
                            // and no-ops otherwise, so the offer stays queued for
                            // `ray files accept` unless it qualifies.
                            let _ = self.new_file_tx.send(id);
                        } else {
                            tracing::warn!(claimed = %from.fmt_short(), actual = %remote_id.fmt_short(), "file offer identity mismatch");
                        }
                    }
                    Ok(other) => {
                        tracing::warn!(msg = ?other, "unexpected control message on FILES_ALPN");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read file offer");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for file offer");
            }
        }
    }

    /// `PAIR_ALPN`: complete a device-pairing handshake. Verifies the dialer's
    /// secret against the active pairing session and, on match, signs and returns
    /// a `DeviceCert` binding the new device key to our identity.
    pub(crate) async fn accept_pair_request(&self, conn: Connection) {
        let pairing_secret = self.pairing_secret.clone();
        let secret_key = self.secret_key.clone();
        let remote_id = conn.remote_id();
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                // Read length-prefixed PairMsg::Request
                let mut len_buf = [0u8; 4];
                if let Err(e) = recv.read_exact(&mut len_buf).await {
                    tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read pair request length");
                    return;
                }
                let body_len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; body_len];
                if let Err(e) = recv.read_exact(&mut body).await {
                    tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to read pair request body");
                    return;
                }
                let request: control::PairMsg = match rmp_serde::from_slice(&body) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to decode pair request");
                        return;
                    }
                };
                match request {
                    control::PairMsg::Request {
                        secret,
                        device_pubkey,
                    } => {
                        // Verify the secret matches the stored pairing secret
                        let stored = pairing_secret.lock().unwrap().take();
                        match stored {
                            Some(expected) if expected == secret => {
                                // Sign the device's public key
                                // Share our saved networks so the new device can auto-join them. Only
                                // networks with a known public key (skips freshly created, unsynced ones).
                                let networks: Vec<control::PairNetwork> = match config::load() {
                                    Ok(cfg) => cfg
                                        .networks
                                        .into_iter()
                                        .filter_map(|n| {
                                            n.network_public_key.map(|k| control::PairNetwork {
                                                name: n.name,
                                                network_key: k.to_string(),
                                            })
                                        })
                                        .collect(),
                                    Err(_) => Vec::new(),
                                };
                                let cert = control::DeviceCert::create(&secret_key, &device_pubkey);
                                let response = control::PairMsg::Response { cert, networks };
                                let response_bytes = match rmp_serde::to_vec_named(&response) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        tracing::warn!(error = %e, "failed to encode pair response");
                                        return;
                                    }
                                };
                                let len = (response_bytes.len() as u32).to_be_bytes();
                                if let Err(e) = send.write_all(&len).await {
                                    tracing::warn!(error = %e, "failed to send pair response length");
                                    return;
                                }
                                if let Err(e) = send.write_all(&response_bytes).await {
                                    tracing::warn!(error = %e, "failed to send pair response body");
                                    return;
                                }
                                // Flush before the connection drops: finish the stream and wait
                                // (briefly) for the joiner to close. Returning here drops `conn`,
                                // which RSTs the stream — without this the joiner often sees
                                // "connection lost" and never receives the cert even though we
                                // logged success below.
                                let _ = send.finish();
                                let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed())
                                    .await;
                                tracing::info!(device = %device_pubkey.fmt_short(), "device paired successfully");
                            }
                            Some(_) => {
                                tracing::warn!(peer = %remote_id.fmt_short(), "pairing secret mismatch");
                            }
                            None => {
                                tracing::warn!(peer = %remote_id.fmt_short(), "no pairing session active");
                            }
                        }
                    }
                    _ => {
                        tracing::warn!(peer = %remote_id.fmt_short(), "unexpected pair message type");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, peer = %remote_id.fmt_short(), "failed to accept bi stream for pairing");
            }
        }
    }
}
