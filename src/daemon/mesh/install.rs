//! Registering a live network. Creating, restoring, joining and warm-resuming
//! a network all end the same way: spawn the network's tasks, insert its
//! handle, expose its accept handler, then publish its names and dial its
//! members. [`NetworkRegistry::install_network`] is that one step.

use super::super::network_registry::coordinator_tasks;
use super::super::*;
use dashmap::mapref::entry::Entry;

/// The network key of a node that signs the network's record.
pub(crate) struct RecordAuthority {
    pub(crate) key: SecretKey,
    /// The hash the record already points at, so the publisher does not sign
    /// it a second time.
    pub(crate) initially_published: Option<blake3::Hash>,
}

/// Everything [`NetworkRegistry::install_network`] needs to make a network live.
pub(crate) struct NetworkInstall<'a> {
    pub(crate) name: &'a str,
    pub(crate) network_key: EndpointId,
    pub(crate) state: SharedNetworkState,
    /// Child of the daemon's shutdown token; stops every task below.
    pub(crate) cancel: CancellationToken,
    pub(crate) invite_lock: Arc<AsyncMutex<()>>,
    pub(crate) incompatible: Option<MeshVersionMismatch>,
    /// `Some` makes this node a coordinator: it gets the publisher, the
    /// stale-member pruner and the coordinator accept handler.
    pub(crate) authority: Option<RecordAuthority>,
    /// The reconverge worker a member handshake already started. The
    /// handshake registers the member accept handler before it drives the
    /// coordinator's connection, so the worker exists before the network
    /// does. A member without one gets a fresh worker and handler here.
    pub(crate) reconverge_worker: Option<JoinHandle<()>>,
    /// This node's name on the network when the roster may not carry it yet
    /// (a rename still pending). Registered in DNS before the roster's names.
    pub(crate) my_hostname: Option<&'a str>,
    /// Seed routes to every roster member and dial them in the background,
    /// announcing this hostname.
    pub(crate) dial: Option<MemberDial>,
}

pub(crate) struct MemberDial {
    pub(crate) my_hostname: Option<String>,
}

impl NetworkRegistry {
    /// Make a network live. `false` when another path registered `name` first:
    /// that handle owns the network, so nothing is spawned, `cancel` is
    /// cancelled, a handshake's worker is aborted, and nothing else is touched.
    ///
    /// The handle is inserted before any peer is dialed, so `ray status` sees
    /// the network the moment it exists, and the coordinator handler is only
    /// exposed once its key, publisher and handle are all in place.
    #[must_use]
    pub(crate) async fn install_network(self: &Arc<Self>, install: NetworkInstall<'_>) -> bool {
        let NetworkInstall {
            name,
            network_key,
            state,
            cancel,
            invite_lock,
            incompatible,
            authority,
            reconverge_worker,
            my_hostname,
            dial,
        } = install;
        // Read before the slot is held: it is a file read.
        let device_cert = self.current_device_cert();
        // Claim the name before spawning anything. A task started for an
        // install that then loses runs on a state no network owns: the poller's
        // first tick is an immediate apply, and an apply can persist its hash
        // into the saved network, or tear the network down by name, which is
        // the winner's by then. The spawns are synchronous, so holding the
        // slot across them is brief.
        let (dht_notify, fresh_member_notify) = match self.networks.entry(name.to_string()) {
            Entry::Occupied(_) => {
                cancel.cancel();
                // The handshake started this one before the network existed.
                // Cancelling is not enough: an apply already in flight would
                // finish on the losing state.
                if let Some(task) = reconverge_worker {
                    task.abort();
                }
                return false;
            }
            Entry::Vacant(slot) => {
                let mut tasks = Vec::new();
                let dht_notify = authority.as_ref().map(|authority| {
                    let notify = Arc::new(Notify::new());
                    tasks.extend(coordinator_tasks(
                        self,
                        name,
                        &authority.key,
                        &state,
                        &notify,
                        &cancel,
                        authority.initially_published,
                    ));
                    notify
                });
                // Every node watches the signed record, coordinators included:
                // with more than one coordinator, another one can publish an
                // edit that no trigger delivers here. A coordinator's own
                // records do not undo themselves: publishing raises its replay
                // floor, and an unconfirmed authored snapshot is kept until its
                // record lands.
                tasks.push(spawn_group_poller(
                    network_key,
                    Arc::clone(&state),
                    self.transport.endpoint.clone(),
                    Arc::clone(self),
                    name.to_string(),
                    cancel.clone(),
                ));
                // A member registered without a handshake (warm resume, or a
                // restore whose coordinator did not answer) has no worker or
                // accept handler yet.
                let fresh_member_notify = match reconverge_worker {
                    Some(task) => {
                        tasks.push(task);
                        None
                    }
                    None if authority.is_none() => {
                        let notify = Arc::new(Notify::new());
                        tasks.push(spawn_reconverge_worker(
                            Arc::clone(&notify),
                            cancel.clone(),
                            Arc::clone(&state),
                            name.to_string(),
                            Arc::clone(self),
                            self.transport.endpoint.clone(),
                            network_key,
                            device_cert,
                        ));
                        Some(notify)
                    }
                    None => None,
                };
                slot.insert(NetworkHandle {
                    name: name.to_string(),
                    network_key,
                    role: role_for_key_holder(authority.is_some()),
                    state: Arc::clone(&state),
                    dht_notify: dht_notify.clone(),
                    cancel: cancel.clone(),
                    tasks,
                    invite_lock: Arc::clone(&invite_lock),
                    incompatible,
                });
                (dht_notify, fresh_member_notify)
            }
        };

        if authority.is_some() {
            self.register_coordinator_handler(
                name,
                Arc::clone(&state),
                Arc::clone(&invite_lock),
                dht_notify,
                network_key,
            );
        } else if let Some(reconverge_notify) = fresh_member_notify {
            self.conn.register(
                network_key,
                AcceptHandler::Member(Arc::new(MemberAcceptState {
                    network_name: name.to_string(),
                    state: Arc::clone(&state),
                    net_pubkey: network_key,
                    my_identity: self.transport.identity.local_identity(),
                    endpoint: self.transport.endpoint.clone(),
                    registry: Arc::clone(self),
                    invite_lock,
                    reconverge_notify,
                })),
            );
        }

        let members = state.read().unwrap().roster();
        let my_ipv6 = derive_ipv6(&self.transport.identity.local_identity());
        let hostnames: Vec<(String, Ipv6Addr)> = my_hostname
            .map(|h| (h.to_string(), my_ipv6))
            .into_iter()
            .chain(members.iter().filter_map(|member| {
                Some((member.hostname.clone()?, derive_ipv6(&member.identity)))
            }))
            .collect();
        dns::sync_network_hostnames(
            &self.dns.hostname_table,
            &self.dns.reverse_table,
            name,
            &hostnames,
        )
        .await;
        self.refresh_search_domains().await;

        if let Some(MemberDial { my_hostname }) = dial {
            // Lets the data path re-dial a member that has since been
            // idle-closed, before the first reconverge.
            self.seed_route_map(name, &members);
            let me = Arc::clone(self);
            let network_name = name.to_string();
            let my_identity = self.transport.identity.local_identity();
            let dial_task = tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = me.dial_all_members(
                        &members,
                        network_key,
                        &network_name,
                        my_identity,
                        my_hostname,
                    ) => {}
                }
            });
            // Tracked on the handle so leave or nuke stops it before it can
            // recreate routes after teardown.
            if let Some(mut handle) = self.networks.get_mut(name) {
                handle.tasks.push(dial_task);
            } else {
                dial_task.abort();
            }
        }
        true
    }
}
