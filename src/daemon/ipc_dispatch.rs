//! Local IPC authorization and request dispatch.

use super::*;

impl Daemon {
    /// Tailscale-style access control. Read-only queries are open to any local
    /// user; mutating commands require the caller to be root or the configured
    /// operator UID; setting the operator itself is root-only. Returns `None`
    /// when the request is permitted, or `Some(error)` to short-circuit it.
    ///
    /// Identity is taken from the connecting socket's `SO_PEERCRED` (the kernel
    /// vouches for it, it can't be forged by the client), so the socket file
    /// mode only has to permit the connection, not gate authority.
    pub(crate) fn check_authorized(
        req: &IpcMessage,
        peer: Option<&PeerIdentity>,
    ) -> Option<IpcMessage> {
        // Reads are available to everyone.
        if matches!(
            req,
            IpcMessage::Status
                | IpcMessage::Report
                | IpcMessage::Logs { .. }
                | IpcMessage::FirewallShow
                | IpcMessage::FirewallSuggestions { .. }
                | IpcMessage::FirewallPending { .. }
                | IpcMessage::FirewallSshShow
                | IpcMessage::ExitNodeStatus { .. }
                | IpcMessage::ListFiles
                | IpcMessage::Connections
                // The queue `ray requests <net> accept` reads its id out of,
                // and the same shape as `Connections` right above it.
                | IpcMessage::Requests { .. }
                | IpcMessage::ContactId
                | IpcMessage::Ping { .. }
                | IpcMessage::Netcheck
                | IpcMessage::AliasList { .. }
                | IpcMessage::ListPairedDevices
                | IpcMessage::ListLanPeers
                | IpcMessage::ConfigGet { .. }
                | IpcMessage::NetConfigGet { .. }
        ) {
            return None;
        }

        #[cfg(unix)]
        let uid = peer.map(|p| match p {
            PeerIdentity::Unix { uid, .. } => *uid,
        });
        // Root may do anything.
        #[cfg(unix)]
        if uid == Some(0) {
            return None;
        }

        // Granting operator access is reserved for root.
        if matches!(req, IpcMessage::SetOperator { .. }) {
            #[cfg(unix)]
            return Some(ipc_err(
                "permission denied: granting operator access requires root \
                          (re-run with sudo)"
                    .to_string(),
            ));
            // There is no root here to be, and `ray set-operator` does not use
            // this path on Windows: it writes the SID itself from an elevated
            // process (see `cmd_set_operator`). A frame arriving here is either
            // an older CLI or something hand-rolled, so say which command works
            // rather than naming a privilege that does not exist.
            #[cfg(windows)]
            return Some(ipc_err(
                "permission denied: set the operator from an Administrator \
                 terminal with: ray set-operator <user>"
                    .to_string(),
            ));
        }

        #[cfg(windows)]
        if windows_peer_authorized(peer, config::operator_sid().ok().flatten().as_deref()) {
            return None;
        }

        // Otherwise the caller must be the configured operator.
        #[cfg(unix)]
        {
            let operator = config::load().ok().and_then(|c| c.operator_uid);
            if uid.is_some() && uid == operator {
                return None;
            }
        }

        // The one error a non-operator is most likely to see, so it has to name a
        // command that exists on the platform reading it. Windows has no sudo,
        // and its `set-operator` needs an elevated terminal rather than a prefix.
        #[cfg(unix)]
        return Some(ipc_err(
            "permission denied: this user is not authorized to control rayfish.\n\
                      Grant access with: sudo ray set-operator <user>"
                .to_string(),
        ));
        #[cfg(windows)]
        Some(ipc_err(
            "permission denied: this user is not authorized to control rayfish.\n\
             Grant access from an Administrator terminal with: ray set-operator <user>"
                .to_string(),
        ))
    }

    /// Persist the operator UID so that user can run mutating `ray` commands
    /// without root. Authorization (root-only) is enforced in `check_authorized`.
    pub(crate) fn set_operator(&self, uid: u32) -> IpcMessage {
        if let Err(e) = config::update_settings(|cfg| {
            cfg.operator_uid = Some(uid);
            Ok(())
        }) {
            return ipc_err(format!("failed to save config: {e}"));
        }
        IpcMessage::Ok {
            message: format!("operator set to uid {uid}; that user can now run ray without sudo"),
        }
    }

    /// The nodes mDNS has seen on this LAN, newest sighting first, each marked
    /// with a network already shared with it (if any). Shared by `ray mdns scan`
    /// and the nearby block in `ray status`, so the two never disagree.
    pub(crate) fn lan_peer_infos(&self) -> Vec<LanPeerInfo> {
        let me = self.transport.endpoint.id();
        let mut peers: Vec<LanPeerInfo> = self
            .transport
            .lan_peers
            .snapshot()
            .into_iter()
            .filter(|(id, _)| *id != me)
            .map(|(id, peer)| LanPeerInfo {
                endpoint_id: id,
                short_id: id.fmt_short().to_string(),
                addrs: peer.addrs.iter().map(|a| a.to_string()).collect(),
                last_seen_secs: peer.last_seen.elapsed().as_secs(),
                shared_network: self.registry.network_shared_with(&id),
            })
            .collect();
        peers.sort_by_key(|p| p.last_seen_secs);
        peers
    }

    /// `ray mdns scan`: every LAN sighting, connected or not.
    pub(crate) fn list_lan_peers(&self) -> IpcMessage {
        IpcMessage::LanPeersList {
            peers: self.lan_peer_infos(),
            mdns_enabled: self.mdns_enabled,
        }
    }

    /// Apply one settings key and persist it. Serves `ray config set|unset` and
    /// every single-value command that used to carry its own IPC variant
    /// (`ray mdns`, `ray firewall on|off|reject|default`, `ray firewall ssh
    /// on|off`, `ray files download-dir|download-user`, and the hidden
    /// `ray auto-update`, whose only spelling is now the key itself).
    ///
    /// Dispatch is on the key's store, because the two a [`NodeKey`] can name
    /// are not interchangeable: a firewall key writes the live `ArcSwap` the
    /// packet path reads (a load/mutate/save there would silently turn `ray
    /// firewall off` into "restart required"), and `ssh` carries listener +
    /// passthrough side effects. Only a plain global key takes the
    /// load/mutate/save below. A per-network key cannot reach here: `ConfigSet`
    /// carries a `NodeKey`, which has no variant for one.
    fn config_apply(
        self: &Arc<Self>,
        key: NodeKey,
        value: &str,
        replace: bool,
        reset: bool,
    ) -> IpcMessage {
        let key = match key {
            NodeKey::Firewall(k) => return self.registry.firewall_config_set(k, value),
            // Not a plain config write: see `Daemon::ssh_config_set`.
            NodeKey::Global(GlobalKey::Ssh) => return self.ssh_config_set(value),
            // Likewise: the bridge's listeners follow the setting live.
            NodeKey::Global(GlobalKey::V4Bridge) => return self.v4_bridge_config_set(value),
            // Likewise: the pf anchor follows the setting live, and on this key
            // a write that waits for a restart leaves the mesh dead meanwhile.
            NodeKey::Global(GlobalKey::PfPassthrough) => {
                return self.pf_passthrough_config_set(value);
            }
            // Spelled out rather than caught by `_`, so a new global key cannot
            // land here by default. Falling through silently is precisely the
            // `ssh` bug: a key whose write needs a live side effect, getting
            // none, with nothing to notice it. Adding a variant breaks this
            // match and forces the choice.
            NodeKey::Global(
                k @ (GlobalKey::Mdns
                | GlobalKey::Relay
                | GlobalKey::DiscoveryDns
                | GlobalKey::DnsUpstreams
                | GlobalKey::AutoUpdate
                | GlobalKey::OnDemand
                | GlobalKey::DownloadDir
                | GlobalKey::DownloadUser),
            ) => k,
        };
        let mut set_err = None;
        let saved = config::update_settings(|cfg| {
            if let Err(e) = config::config_set(cfg, key, value, replace) {
                set_err = Some(e.to_string());
                anyhow::bail!("rejected");
            }
            Ok(())
        });
        if let Some(e) = set_err {
            return ipc_err(e);
        }
        let app_config = match saved {
            Ok(cfg) => cfg,
            Err(e) => return ipc_err(format!("failed to save config: {e}")),
        };
        IpcMessage::Ok {
            message: global_set_message(&app_config, key, reset),
        }
    }

    /// Read node config rows for `ray config get` from the daemon's own config.
    /// Firewall-scoped keys are read from the live config, not from disk, so a
    /// get always agrees with what the packet path is enforcing.
    ///
    /// Without a key this lists both stores, globals first: the two live in
    /// different files behind different handlers, but the user typed one
    /// command and expects every node setting back.
    fn config_get(&self, key: Option<NodeKey>) -> IpcMessage {
        let key = match key {
            Some(NodeKey::Firewall(k)) => return self.registry.firewall_config_get(k),
            Some(NodeKey::Global(k)) => Some(k),
            None => None,
        };
        let app_config = match config::load() {
            Ok(c) => c,
            Err(e) => return ipc_err(format!("failed to load config: {e}")),
        };
        let mut rows = config::config_get(&app_config, key);
        if key.is_none() {
            rows.extend(self.registry.firewall_config_rows(None));
        }
        IpcMessage::ConfigValues { rows }
    }

    /// Apply one per-network setting and persist just that network's file, then
    /// run whatever live re-materialization the key implies (the registry's
    /// `apply_network` is pure and deliberately does none of it).
    pub(super) async fn net_config_apply(
        self: &Arc<Self>,
        network: &str,
        key: NetworkKey,
        value: &str,
    ) -> IpcMessage {
        let mut validation_error = None;
        let updated = config::update_network(network, |net| {
            settings::apply_network(net, key, value).inspect_err(|e| {
                validation_error = Some(e.to_string());
            })
        });
        let net = match updated {
            Ok(Some(net)) => net,
            Ok(None) => return ipc_err(format!("network '{network}' not found")),
            Err(_) if validation_error.is_some() => {
                return ipc_err(validation_error.unwrap());
            }
            Err(e) => return ipc_err(format!("failed to save config: {e}")),
        };
        // Run the live re-materialization the key implies, then confirm.
        match key {
            NetworkKey::AutoAcceptFirewall => self.registry.reapply_suggested_firewall(network),
            NetworkKey::AutoAcceptFiles if net.auto_accept_files => {
                self.files.drain_auto_acceptable().await
            }
            // The pruner re-reads the TTL each tick, so there is nothing to do
            // beyond the write.
            NetworkKey::AutoAcceptFiles | NetworkKey::EphemeralTtl => {}
        }
        IpcMessage::Ok {
            message: net_set_message(&net, network, key),
        }
    }

    /// Read one or every per-network setting.
    fn net_config_get(&self, network: &str, key: Option<NetworkKey>) -> IpcMessage {
        let net = match config::load_network(network) {
            Ok(Some(n)) => n,
            Ok(None) => return ipc_err(format!("network '{network}' not found")),
            Err(e) => return ipc_err(format!("failed to load network: {e}")),
        };
        let keys: Vec<NetworkKey> = match key {
            Some(k) => vec![k],
            None => NetworkKey::ALL.to_vec(),
        };
        let rows = keys
            .into_iter()
            .map(|k| (k.name().to_string(), settings::render_network(&net, k)))
            .collect();
        IpcMessage::ConfigValues { rows }
    }

    pub(crate) async fn handle_request(
        self: &Arc<Self>,
        req: IpcMessage,
        peer: Option<PeerIdentity>,
        fds: Vec<IpcOwnedFd>,
    ) -> IpcMessage {
        if let Some(denied) = Self::check_authorized(&req, peer.as_ref()) {
            return denied;
        }
        let peer_cred = peer.as_ref().and_then(PeerIdentity::unix_cred);
        match req {
            IpcMessage::Create {
                mode,
                name,
                hostname,
                transport: _,
            } => self.create_network(mode, name, hostname).await,
            IpcMessage::Join {
                network_key,
                name,
                hostname,
                transport: _,
                invite,
                coordinator,
                auto_accept_firewall,
                auto_accept_files,
            } => {
                self.join_network(
                    &network_key,
                    name.as_deref(),
                    hostname,
                    invite,
                    coordinator,
                    auto_accept_firewall,
                    auto_accept_files,
                )
                .await
            }
            IpcMessage::Leave { name } => self.leave_network(&name).await,
            IpcMessage::Nuke { name, force } => self.registry.nuke_network(&name, force).await,
            IpcMessage::Kick {
                network,
                peer,
                confirm,
            } => self.registry.kick_member(&network, &peer, confirm).await,
            IpcMessage::Status => self.status(),
            IpcMessage::Report => self.build_report(peer.as_ref()),
            IpcMessage::Up { hostname } => self.activate(hostname).await,
            IpcMessage::Down => self.deactivate().await,
            IpcMessage::Shutdown => {
                self.shutdown_token.cancel();
                IpcMessage::Ok {
                    message: "shutting down".to_string(),
                }
            }
            IpcMessage::FirewallAdd {
                direction,
                action,
                protocol,
                port,
                peer,
                network,
            } => {
                self.registry
                    .firewall_add(
                        direction,
                        action,
                        protocol,
                        port.as_deref(),
                        peer.as_deref(),
                        network.as_deref(),
                    )
                    .await
            }
            IpcMessage::FirewallRemove { index } => self.registry.firewall_remove(index),
            IpcMessage::FirewallShow => self.registry.firewall_show(),
            IpcMessage::FirewallSuggest {
                network,
                suggestions,
            } => self.registry.firewall_suggest(&network, suggestions).await,
            IpcMessage::FirewallSuggestions { network } => {
                self.registry.firewall_suggestions(&network)
            }
            IpcMessage::FirewallPending { network } => self.registry.firewall_pending(&network),
            IpcMessage::FirewallAccept { network } => self.registry.firewall_accept(&network),
            IpcMessage::FirewallDeny { network } => self.registry.firewall_deny(&network),
            IpcMessage::FirewallResolveSuggestions {
                network,
                accept,
                deny,
            } => self
                .registry
                .firewall_resolve_suggestions(&network, &accept, &deny),
            IpcMessage::FirewallSshAllow {
                network,
                peer,
                users,
                allow,
            } => self.firewall_ssh_allow(&network, &peer, users, allow).await,
            IpcMessage::FirewallSshShow => self.firewall_ssh_show(),
            IpcMessage::ExitNodeAllow {
                network,
                peer,
                allow,
            } => {
                let resp = self.registry.exit_node_allow(&network, &peer, allow).await;
                // If the data plane is up, reconcile the runtime state and kernel
                // plumbing now; otherwise `activate()` picks it up on `ray up`.
                self.reconcile_exit_node(resp).await
            }
            IpcMessage::ExitNodeUse { network, peer } => {
                let resp = self.registry.exit_node_use(&network, peer).await;
                self.reconcile_exit_node(resp).await
            }
            IpcMessage::ExitNodeStatus { network } => self.registry.exit_node_status(network),
            IpcMessage::SetHostname { network, hostname } => {
                self.set_hostname(&network, &hostname).await
            }
            IpcMessage::AliasSet {
                network,
                identity,
                alias,
            } => self.registry.set_alias(&network, &identity, &alias),
            IpcMessage::AliasRemove { network, alias } => {
                self.registry.remove_alias(&network, &alias)
            }
            IpcMessage::AliasList { network } => self.registry.list_aliases(&network),
            IpcMessage::SendFile { path, peer } => self.send_file(&path, &peer).await,
            IpcMessage::SendFileStaged {
                path,
                filename,
                peer,
            } => {
                self.files
                    .send_file_named(&path, Some(&filename), &peer)
                    .await
            }
            IpcMessage::SendFileFd { filename, peer } => {
                #[cfg(unix)]
                {
                    let mut fds = fds;
                    match fds.pop() {
                        Some(fd) => self.files.send_file_fd(fd, &filename, &peer).await,
                        None => ipc_err("SendFileFd request carried no file descriptor"),
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = (filename, peer, fds);
                    ipc_err("SendFileFd is unavailable on this platform")
                }
            }
            IpcMessage::CancelSend { id } => self.files.cancel_send(id),
            IpcMessage::CancelTransfer { id } => self.files.cancel_transfer(id),
            IpcMessage::ListFiles => self.list_files(),
            IpcMessage::AcceptFile { id, output } => {
                self.files.accept_file(id, output, peer_cred).await
            }
            IpcMessage::RejectFile { id } => self.files.reject_file(id),
            IpcMessage::StartPairing => self.start_pairing(),
            IpcMessage::PairWithDevice {
                endpoint_id,
                secret,
            } => self.pair_with_device(endpoint_id, secret).await,
            IpcMessage::ListPairedDevices => self.list_paired_devices(),
            IpcMessage::Unpair { device } => self.unpair(&device).await,
            IpcMessage::SetOperator { uid } => self.set_operator(uid),
            IpcMessage::ListLanPeers => self.list_lan_peers(),
            IpcMessage::ConfigSet {
                key,
                value,
                replace,
            } => self.config_apply(key, &value, replace, false),
            IpcMessage::ConfigUnset { key } => self.config_apply(key, "", false, true),
            IpcMessage::ConfigGet { key } => self.config_get(key),
            IpcMessage::NetConfigSet {
                network,
                key,
                value,
            } => self.net_config_apply(&network, key, &value).await,
            IpcMessage::NetConfigGet { network, key } => self.net_config_get(&network, key),
            IpcMessage::InviteCreate {
                network,
                expires_secs,
                hostname,
                reusable,
            } => {
                self.registry
                    .invite_create(&network, expires_secs, hostname, reusable)
                    .await
            }
            IpcMessage::InviteList { network } => self.registry.invite_list(&network).await,
            IpcMessage::InviteRevoke { network, id } => {
                self.registry.invite_revoke(&network, &id).await
            }
            IpcMessage::Requests { network } => self.registry.list_requests(&network),
            IpcMessage::AcceptRequest { network, id } => {
                self.registry.accept_request(&network, &id).await
            }
            IpcMessage::DenyRequest { network, id } => self.registry.deny_request(&network, &id),
            IpcMessage::AdminAdd { network, identity } => {
                self.registry.admin_add(&network, &identity).await
            }
            IpcMessage::AdminList { network } => self.registry.admin_list(&network),
            IpcMessage::Connect {
                contact_id,
                hostname,
            } => self.connect(&contact_id, hostname).await,
            IpcMessage::Connections => self.list_connections(),
            IpcMessage::ApproveConnection { id } => self.approve_connection(&id).await,
            IpcMessage::ContactId => IpcMessage::ContactIdResponse {
                contact_id: self.contact_public.to_string(),
            },
            IpcMessage::RotateContact => self.rotate_contact().await,
            IpcMessage::Ping {
                peer,
                count,
                interval_ms,
            } => self.ping(&peer, count, interval_ms).await,
            IpcMessage::Netcheck => self.netcheck().await,
            other => ipc_err(format!("unexpected message: {:?}", other)),
        }
    }
}
