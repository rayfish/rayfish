//! Invite + join-request handlers for `DaemonState`: mint/list/revoke invites and
//! reusable keys, list/accept/deny pending join requests. Split out of `daemon/mod.rs`.

use super::super::*;

impl DaemonState {
    pub(crate) async fn invite_create(
        &self,
        network: &str,
        expires_secs: u64,
        hostname: Option<String>,
        reusable: bool,
    ) -> IpcMessage {
        if reusable {
            return self
                .reusable_key_create(network, expires_secs, hostname)
                .await;
        }
        let (net_pubkey, lock) = match self.coordinator_handle(network) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let minted = {
            let _guard = lock.lock().await;
            match crate::invite::InviteStore::load(network) {
                Ok(mut store) => store.mint(Duration::from_secs(expires_secs), hostname),
                Err(e) => Err(e),
            }
        };
        match minted {
            Ok((secret, id)) => {
                let code =
                    crate::invite::encode_invite_code(&net_pubkey, &self.endpoint.id(), &secret);
                // Gossip the new invite (hash only, never the secret) to other
                // coordinators so any of them can later redeem it. The wire field
                // carries the hex hash's UTF-8 bytes; receivers decode back to the
                // ledger's hex `String`.
                let secret_hash = crate::invite::hash_secret(&secret);
                let expires = now_secs().saturating_add(expires_secs);
                if let Some(handle) = self.networks.get(network) {
                    let members: Vec<crate::membership::Member> = handle
                        .state
                        .read()
                        .unwrap()
                        .members
                        .all()
                        .into_iter()
                        .cloned()
                        .collect();
                    let me = self.endpoint.id();
                    drop(handle);
                    gossip_to_coordinators(
                        &self.peers,
                        network,
                        &members,
                        me,
                        &ControlMsg::InviteShare {
                            id: id.clone(),
                            secret_hash: secret_hash.into_bytes(),
                            expires,
                        },
                    )
                    .await;
                }
                IpcMessage::InviteCreated {
                    code,
                    id,
                    expires_secs,
                }
            }
            Err(e) => IpcMessage::Error {
                message: format!("failed to mint invite: {e:#}"),
            },
        }
    }

    /// Mint a reusable join key: insert its hash into the signed blob and
    /// republish, so any network-key holder can admit. Authority is holding the
    /// network secret key (like firewall suggestions), not the `is_coordinator`
    /// flag. A reusable key cannot bind an authoritative hostname.
    pub(crate) async fn reusable_key_create(
        &self,
        network: &str,
        expires_secs: u64,
        hostname: Option<String>,
    ) -> IpcMessage {
        if hostname.is_some() {
            return IpcMessage::Error {
                message: "a reusable key cannot bind a hostname (a multi-use key admits many \
                          machines); drop --hostname or omit --reusable"
                    .to_string(),
            };
        }
        let (state, dht_notify, net_pubkey, has_key) = match self.networks.get(network) {
            Some(h) => {
                let has_key = h.state.read().unwrap().network_secret_key.is_some();
                (
                    h.state.clone(),
                    h.dht_notify.clone(),
                    h.network_key,
                    has_key,
                )
            }
            None => {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            }
        };
        if !has_key {
            return IpcMessage::Error {
                message: "only a coordinator (network key holder) can mint a reusable key"
                    .to_string(),
            };
        }
        let secret = crate::invite::generate_secret();
        let (hash, key) =
            crate::membership::ReusableKey::from_secret(&secret, now_secs(), expires_secs);
        let id = key.id.clone();
        {
            let mut s = state.write().unwrap();
            s.reusable_keys.insert(hash, key);
        }
        update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
        let code = crate::invite::encode_invite_code(&net_pubkey, &self.endpoint.id(), &secret);
        IpcMessage::InviteCreated {
            code,
            id,
            expires_secs,
        }
    }

    pub(crate) async fn invite_list(&self, network: &str) -> IpcMessage {
        // Extract owned handles before any await (DashMap refs must not be held
        // across `.await`).
        let (lock, has_key, reusable) = {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let s = handle.state.read().unwrap();
            (
                handle.invite_lock.clone(),
                s.network_secret_key.is_some(),
                s.reusable_keys.clone(),
            )
        };
        if !has_key {
            return IpcMessage::Error {
                message: format!(
                    "only a coordinator (network key holder) can list invites for '{network}'"
                ),
            };
        }
        let mut invites: Vec<ipc::InviteInfo> = Vec::new();
        // Single-use invites from the local ledger (present on the minting node;
        // a co-coordinator's ledger is simply empty).
        {
            let _guard = lock.lock().await;
            if let Ok(store) = crate::invite::InviteStore::load(network) {
                for v in store.list() {
                    invites.push(ipc::InviteInfo {
                        id: v.id,
                        status: v.status,
                        created: v.created,
                        expires: v.expires,
                        redeemer: v.redeemer,
                        hostname: v.hostname,
                        reusable: false,
                    });
                }
            }
        }
        // Reusable keys from the signed blob — known to every network-key holder.
        let now = now_secs();
        for k in reusable.values() {
            let status = if k.revoked {
                "revoked"
            } else if now >= k.expires {
                "expired"
            } else {
                "active"
            };
            invites.push(ipc::InviteInfo {
                id: k.id.clone(),
                status: status.to_string(),
                created: k.created,
                expires: k.expires,
                redeemer: None,
                hostname: None,
                reusable: true,
            });
        }
        IpcMessage::InviteListResponse { invites }
    }

    pub(crate) async fn invite_revoke(&self, network: &str, id: &str) -> IpcMessage {
        let (state, dht_notify, lock, has_key) = {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let has_key = handle.state.read().unwrap().network_secret_key.is_some();
            (
                handle.state.clone(),
                handle.dht_notify.clone(),
                handle.invite_lock.clone(),
                has_key,
            )
        };
        if !has_key {
            return IpcMessage::Error {
                message: format!(
                    "only a coordinator (network key holder) can revoke invites for '{network}'"
                ),
            };
        }
        // A reusable key lives in the signed blob: revoke it there and republish
        // so the revocation propagates to every admin.
        let revoked_reusable = {
            let mut s = state.write().unwrap();
            crate::membership::revoke_reusable(&mut s.reusable_keys, id).is_ok()
        };
        if revoked_reusable {
            update_snapshot_and_publish(&state, &self.blob_store, &dht_notify).await;
            return IpcMessage::Ok {
                message: format!("revoked reusable key '{id}' (propagating to all admins)"),
            };
        }
        // Fall back to the local single-use invite ledger.
        let result = {
            let _guard = lock.lock().await;
            match crate::invite::InviteStore::load(network) {
                Ok(mut store) => store.revoke(id),
                Err(e) => Err(e),
            }
        };
        match result {
            Ok(()) => IpcMessage::Ok {
                message: format!("revoked invite '{id}'"),
            },
            Err(e) => IpcMessage::Error {
                message: format!("{e:#}"),
            },
        }
    }

    pub(crate) fn list_requests(&self, network: &str) -> IpcMessage {
        let Some(handle) = self.networks.get(network) else {
            return IpcMessage::Error {
                message: format!("network '{network}' not active"),
            };
        };
        if !handle.role.is_coordinator() {
            return IpcMessage::Error {
                message: format!("only the coordinator of '{network}' has join requests"),
            };
        }
        let s = handle.state.read().unwrap();
        let requests = s
            .pending
            .iter()
            .map(|(id, pj)| ipc::PendingRequestInfo {
                short_id: id.fmt_short().to_string(),
                hostname: pj.hostname.clone(),
                waiting_secs: pj.requested_at.elapsed().as_secs(),
            })
            .collect();
        IpcMessage::PendingRequests { requests }
    }

    pub(crate) async fn accept_request(&self, network: &str, id_prefix: &str) -> IpcMessage {
        if let Err(e) = self.coordinator_handle(network) {
            return e;
        }
        // Find and remove the pending request matching the short id prefix.
        let pending = {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut s = handle.state.write().unwrap();
            let found = s
                .pending
                .keys()
                .find(|k| {
                    k.fmt_short().to_string().starts_with(id_prefix)
                        || k.to_string().starts_with(id_prefix)
                })
                .copied();
            found.and_then(|id| s.pending.remove(&id).map(|pj| (id, pj)))
        };
        let Some((identity, pj)) = pending else {
            return IpcMessage::Error {
                message: format!("no pending request matching '{id_prefix}'"),
            };
        };

        let user_id = pj.device_cert.as_ref().map(|c| c.user_identity);
        let ip = {
            let Some(handle) = self.networks.get(network) else {
                return IpcMessage::Error {
                    message: format!("network '{network}' not active"),
                };
            };
            let mut s = handle.state.write().unwrap();
            // Assign authoritatively from the current roster so two coordinators
            // accepting concurrently can be reconciled by the reconverge tiebreak.
            let (ip, collision_index) = crate::membership::assign_ip(&s.members, &identity);
            let members = s.members.clone();
            let _ = s.approved.approve(
                ApprovedEntry {
                    identity,
                    ip,
                    hostname: pj.hostname.clone(),
                    user_identity: user_id,
                    device_cert: pj.device_cert.clone(),
                    collision_index,
                },
                &members,
            );
            s.refresh_snapshot();
            ip
        };
        self.store_and_publish_group(network).await;
        broadcast_control_msg(
            &self.peers,
            &ControlMsg::MemberApproved {
                identity,
                ip,
                hostname: pj.hostname.clone(),
                device_cert: pj.device_cert.clone(),
            },
        )
        .await;
        IpcMessage::Ok {
            message: format!("accepted {} — they'll join shortly", identity.fmt_short()),
        }
    }

    pub(crate) fn deny_request(&self, network: &str, id_prefix: &str) -> IpcMessage {
        if let Err(e) = self.coordinator_handle(network) {
            return e;
        }
        let Some(handle) = self.networks.get(network) else {
            return IpcMessage::Error {
                message: format!("network '{network}' not active"),
            };
        };
        let mut s = handle.state.write().unwrap();
        let found = s
            .pending
            .keys()
            .find(|k| {
                k.fmt_short().to_string().starts_with(id_prefix)
                    || k.to_string().starts_with(id_prefix)
            })
            .copied();
        match found {
            Some(id) => {
                s.pending.remove(&id);
                IpcMessage::Ok {
                    message: format!("denied {}", id.fmt_short()),
                }
            }
            None => IpcMessage::Error {
                message: format!("no pending request matching '{id_prefix}'"),
            },
        }
    }
}
