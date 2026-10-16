//! Durable contact delivery and a recipient-owned inbox. The connect transport
//! only stores offers; joining requires a separate authorized IPC request.
//! Outbox credentials live in the invite ledger under its existing network lock.
//! Delivery and inbox locks serialize metadata, never an I/O resource.

use super::*;
use crate::invite::{InviteSecret, InviteStore};
use crate::membership::now_secs;
use ray_proto::ipc::{InvitationInfo, InvitationStatus, MachineHostname, NetworkName};
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_INTERVAL: Duration = Duration::from_secs(60);
const MAX_INBOX: usize = 256;
/// Pending offers one sender may hold, so a single peer cannot fill the inbox.
const MAX_PENDING_PER_SENDER: usize = 8;

/// A queued delivery is not a failure: the sweep retries it until expiry.
enum DeliveryOutcome {
    Done(String),
    Queued(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ReceivedInvitation {
    id: String,
    network: NetworkName,
    network_key: EndpointId,
    coordinator: EndpointId,
    secret: InviteSecret,
    expires: u64,
    status: InvitationStatus,
}

impl ReceivedInvitation {
    pub(super) fn new(
        network: NetworkName,
        network_key: EndpointId,
        coordinator: EndpointId,
        secret: InviteSecret,
        expires: u64,
    ) -> Self {
        // Scope deduplication to both the authenticated sender and the secret.
        let mut hash = blake3::Hasher::new();
        hash.update(coordinator.as_bytes());
        hash.update(network_key.as_bytes());
        hash.update(&secret.0);
        Self {
            id: hash.finalize().to_hex()[..16].to_string(),
            network,
            network_key,
            coordinator,
            secret,
            expires,
            status: InvitationStatus::Pending,
        }
    }

    fn info(&self) -> InvitationInfo {
        InvitationInfo {
            id: self.id.clone(),
            network: self.network.clone(),
            coordinator: self.coordinator,
            expires: self.expires,
            status: if self.expires <= now_secs() {
                InvitationStatus::Expired
            } else {
                self.status.clone()
            },
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Inbox {
    #[serde(default)]
    invitations: Vec<ReceivedInvitation>,
}

impl Inbox {
    fn path() -> Result<PathBuf> {
        Ok(config::config_dir()?.join("invitations.toml"))
    }

    fn load() -> Result<Self> {
        Self::from_path(&Self::path()?)
    }

    fn from_path(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                toml::from_str(&contents).map_err(|_| anyhow::anyhow!("invalid invitation inbox"))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => anyhow::bail!("could not read invitation inbox"),
        }
    }

    fn save(&self) -> Result<()> {
        self.save_to(&Self::path()?)
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string(self).context("serialize invitation inbox")?;
        config::write_file(path, contents.as_bytes(), true)
    }

    fn receive(&mut self, offer: ReceivedInvitation) -> Result<bool> {
        anyhow::ensure!(offer.expires > now_secs(), "invitation expired");
        anyhow::ensure!(
            offer.expires <= now_secs().saturating_add(8 * 86400),
            "invitation expiry too distant"
        );
        anyhow::ensure!(
            crate::hostname::is_valid_hostname(offer.network.as_ref()),
            "invalid invitation network name"
        );
        // A retry never overwrites acceptance or decline, including after restart.
        if self.invitations.iter().any(|i| i.id == offer.id) {
            return Ok(false);
        }
        self.invitations.retain(|i| i.expires > now_secs());
        let pending = || {
            self.invitations
                .iter()
                .filter(|i| i.status == InvitationStatus::Pending)
        };
        anyhow::ensure!(
            pending()
                .filter(|i| i.coordinator == offer.coordinator)
                .count()
                < MAX_PENDING_PER_SENDER,
            "too many pending invitations from this sender"
        );
        anyhow::ensure!(pending().count() < MAX_INBOX, "invitation inbox full");
        // Answered entries only stop a retry from resurfacing; they never take
        // pending slots, and the soonest to expire goes first when space runs out.
        if self.invitations.len() >= 2 * MAX_INBOX
            && let Some(oldest) = self
                .invitations
                .iter()
                .enumerate()
                .filter(|(_, i)| i.status != InvitationStatus::Pending)
                .min_by_key(|(_, i)| i.expires)
                .map(|(index, _)| index)
        {
            self.invitations.remove(oldest);
        }
        self.invitations.push(offer);
        Ok(true)
    }

    fn find_mut(&mut self, id: &str) -> Result<&mut ReceivedInvitation> {
        let mut matches = self.invitations.iter_mut().filter(|i| i.id.starts_with(id));
        let found = matches.next().context("invitation not found")?;
        anyhow::ensure!(
            !id.is_empty() && matches.next().is_none(),
            "ambiguous invitation id"
        );
        Ok(found)
    }
}

impl ConnectService {
    pub(super) async fn resolve_invite_contact(&self, contact: EndpointId) -> Result<EndpointId> {
        if contact == self.transport.contact_public {
            return Ok(self.transport.endpoint.id());
        }
        let client =
            dht::create_pkarr_client(&self.transport.endpoint, &self.transport.pkarr_relay_url)?;
        tokio::time::timeout(DELIVERY_TIMEOUT, dht::resolve_contact(&client, contact)).await?
    }

    /// A previous successful delivery supplies a fallback when the contact's
    /// signed record is temporarily unavailable. Never reinterpret a contact key
    /// itself as a device identity.
    pub(super) fn known_contact_endpoint(&self, contact: EndpointId) -> Option<EndpointId> {
        self.registry.networks.iter().find_map(|network| {
            InviteStore::load(network.key())
                .ok()?
                .contact_endpoint(contact)
        })
    }

    fn contact_joined(&self, network: &str, identity: EndpointId) -> Result<bool> {
        let Some(handle) = self.registry.networks.get(network) else {
            return Ok(false);
        };
        let state = handle
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("could not read network membership"))?;
        Ok(state
            .members
            .all()
            .iter()
            .any(|member| member.matches_identity(identity)))
    }

    pub(super) async fn deliver_contact_invite(
        &self,
        network: &str,
        contact: EndpointId,
        identity: Option<EndpointId>,
    ) -> IpcMessage {
        match self
            .deliver_contact_invite_locked(network, contact, identity, true)
            .await
        {
            Ok(DeliveryOutcome::Done(message) | DeliveryOutcome::Queued(message)) => {
                IpcMessage::Ok { message }
            }
            Err(error) => ipc_err(error.to_string()),
        }
    }

    async fn deliver_contact_invite_locked(
        &self,
        network: &str,
        contact: EndpointId,
        identity: Option<EndpointId>,
        mint: bool,
    ) -> Result<DeliveryOutcome> {
        let lock = Arc::clone(
            &self
                .invite_delivery_locks
                .entry(contact)
                .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        );
        let _guard = lock.lock().await;
        self.deliver_contact_invite_inner(network, contact, identity, mint)
            .await
    }

    async fn deliver_contact_invite_inner(
        &self,
        network: &str,
        contact: EndpointId,
        identity: Option<EndpointId>,
        mint: bool,
    ) -> Result<DeliveryOutcome> {
        let done = |message: String| Ok(DeliveryOutcome::Done(message));
        let (network_key, lock) = self.registry.coordinator_handle(network).map_err(|_| {
            anyhow::anyhow!("contact invitation requires an active coordinator network")
        })?;
        if let Some(identity) = identity
            && self.contact_joined(network, identity)?
        {
            return done("contact already has joined devices".to_string());
        }
        // A retry sweep never mints: redemption, revocation or expiry may have
        // changed the ledger since the sweep selected this contact.
        let existing = {
            let _guard = lock.lock().await;
            InviteStore::load(network)?.live_contact_invite(contact)
        };
        let identity = identity.or_else(|| {
            existing
                .as_ref()
                .and_then(|invite| invite.delivery.as_ref())
                .and_then(|delivery| delivery.identity)
        });
        if let Some(identity) = identity
            && self.contact_joined(network, identity)?
        {
            return done("contact already has joined devices".to_string());
        }
        if !mint && existing.is_none() {
            return done("no pending contact delivery".to_string());
        }
        if let Some(invite) = &existing
            && invite
                .delivery
                .as_ref()
                .is_some_and(|delivery| delivery.delivered)
        {
            return done(format!("invite {} already delivered", invite.id));
        }
        let endpoint = self.resolve_invite_contact(contact).await.ok();
        if let Some(endpoint) = endpoint.or_else(|| self.known_contact_endpoint(contact))
            && self.contact_joined(network, endpoint)?
        {
            return done("contact already has a joined device".to_string());
        }
        let invite = {
            let _guard = lock.lock().await;
            let mut store = InviteStore::load(network)?;
            if mint {
                store.for_contact(contact, identity)?
            } else {
                match store.live_contact_invite(contact) {
                    Some(invite) => invite,
                    None => return done("no pending contact delivery".to_string()),
                }
            }
        };
        let delivery = invite.delivery.context("contact delivery record missing")?;
        if delivery.delivered {
            return done(format!("invite {} already delivered", invite.id));
        }
        let Some(endpoint) = endpoint else {
            return Ok(DeliveryOutcome::Queued(format!(
                "contact offline or unknown; invite {} queued, daemon will retry until expiry",
                invite.id
            )));
        };
        {
            let _guard = lock.lock().await;
            InviteStore::load(network)?.record_contact_endpoint(&invite.id, endpoint)?;
        }
        let result = tokio::time::timeout(DELIVERY_TIMEOUT, async {
            let conn = transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
                endpoint,
                transport::CONNECT_ALPN,
            )
            .await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            control::send_framed(
                &mut send,
                &control::ConnectMsg::InviteOffer {
                    network: NetworkName::new(network.to_string()),
                    network_key,
                    recipient_contact: contact,
                    secret: delivery.secret,
                    expires: invite.expires,
                },
            )
            .await?;
            match control::recv_framed::<control::ConnectMsg>(&mut recv).await? {
                control::ConnectMsg::InviteReceived => Ok(()),
                // Never echo a peer-supplied reason: it could contain a credential.
                _ => anyhow::bail!("recipient did not acknowledge invitation"),
            }
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            return Ok(DeliveryOutcome::Queued(format!(
                "private delivery failed (contact unreachable, inbox rejected, or incompatible protocol); invite {} queued, daemon will retry until expiry",
                invite.id
            )));
        }
        {
            let _guard = lock.lock().await;
            InviteStore::load(network)?.mark_delivered(&invite.id, endpoint)?;
        }
        done(format!(
            "invite {} delivered privately; awaiting recipient acceptance",
            invite.id
        ))
    }

    pub(super) fn start_invite_delivery(self: &Arc<Self>, token: CancellationToken) {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let networks: Vec<String> = service
                    .registry
                    .networks
                    .iter()
                    .map(|n| n.key().clone())
                    .collect();
                for network in networks {
                    let contacts = match InviteStore::load(&network) {
                        Ok(store) => store.pending_deliveries(),
                        Err(_) => {
                            tracing::warn!("could not read contact invite outbox");
                            continue;
                        }
                    };
                    for contact in contacts {
                        tokio::select! {
                            _ = token.cancelled() => return,
                            reply = service.deliver_contact_invite_locked(&network, contact, None, false) => {
                                if !matches!(reply, Ok(DeliveryOutcome::Done(_))) {
                                    tracing::debug!("contact invitation still queued for retry");
                                }
                            }
                        }
                    }
                }
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(RETRY_INTERVAL) => {}
                }
            }
        });
    }

    pub(super) async fn receive_invitation(
        &self,
        recipient: EndpointId,
        offer: ReceivedInvitation,
    ) -> control::ConnectMsg {
        let current_contact = config::load()
            .ok()
            .and_then(|c| c.contact_secret_key)
            .map(|key| key.public())
            .unwrap_or(self.transport.contact_public);
        if recipient != current_contact {
            return control::ConnectMsg::Denied {
                reason: "contact key changed".to_string(),
            };
        }
        let _guard = self.inbox_lock.lock().await;
        let result = (|| -> Result<()> {
            let mut inbox = Inbox::load()?;
            if inbox.receive(offer)? {
                inbox.save()?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => control::ConnectMsg::InviteReceived,
            Err(_) => control::ConnectMsg::Denied {
                reason: "invitation could not be stored".to_string(),
            },
        }
    }

    pub(super) async fn list_invitations(&self) -> IpcMessage {
        let _guard = self.inbox_lock.lock().await;
        match Inbox::load() {
            Ok(inbox) => IpcMessage::InvitationsResponse {
                invitations: inbox
                    .invitations
                    .iter()
                    .map(ReceivedInvitation::info)
                    .collect(),
            },
            Err(_) => ipc_err("could not read invitation inbox".to_string()),
        }
    }

    pub(super) async fn accept_invitation(
        &self,
        id: &str,
        hostname: Option<MachineHostname>,
    ) -> IpcMessage {
        // Joining can take longer than a sender's delivery timeout, so only the
        // answer lock spans it; offers keep landing in the inbox meanwhile.
        let _answer = self.answer_lock.lock().await;
        let result = async {
            let invite = {
                let _guard = self.inbox_lock.lock().await;
                let mut inbox = Inbox::load()?;
                let invite = inbox.find_mut(id)?;
                anyhow::ensure!(invite.expires > now_secs(), "invitation expired");
                anyhow::ensure!(
                    invite.status == InvitationStatus::Pending,
                    "invitation already answered"
                );
                invite.clone()
            };
            // Pin the join to the authenticated offer sender. Receipt never calls this.
            let reply = self
                .registry
                .join_network(
                    &invite.network_key.to_string(),
                    None,
                    hostname.map(|h| h.to_string()),
                    Some(invite.secret.0.to_vec()),
                    Some(invite.coordinator),
                    false,
                    false,
                )
                .await;
            // `Ok` means a closed network queued the join; its retry loop now
            // owns the secret, so a second accept must not start another.
            if matches!(reply, IpcMessage::Joined { .. } | IpcMessage::Ok { .. }) {
                let _guard = self.inbox_lock.lock().await;
                let mut inbox = Inbox::load()?;
                inbox.find_mut(&invite.id)?.status = InvitationStatus::Accepted;
                inbox.save()?;
            }
            Ok::<_, anyhow::Error>(reply)
        }
        .await;
        match result {
            Ok(reply) => reply,
            Err(error) => ipc_err(error.to_string()),
        }
    }

    pub(super) async fn decline_invitation(&self, id: &str) -> IpcMessage {
        let _answer = self.answer_lock.lock().await;
        let _guard = self.inbox_lock.lock().await;
        let result = (|| -> Result<()> {
            let mut inbox = Inbox::load()?;
            let invite = inbox.find_mut(id)?;
            anyhow::ensure!(
                invite.status == InvitationStatus::Pending,
                "invitation already answered"
            );
            invite.status = InvitationStatus::Declined;
            inbox.save()
        })();
        match result {
            Ok(()) => IpcMessage::Ok {
                message: "invitation declined".to_string(),
            },
            Err(error) => ipc_err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::accept_handler_tests::{make_network_state, sample_registry};
    use super::*;
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::presets;
    use std::ffi::OsString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct ConfigEnv(Option<OsString>);
    impl Drop for ConfigEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.0 {
                    Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                    None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
                }
            }
        }
    }

    fn offer() -> ReceivedInvitation {
        ReceivedInvitation::new(
            NetworkName::new("sample-net".into()),
            SecretKey::from([1; 32]).public(),
            SecretKey::from([2; 32]).public(),
            InviteSecret([3; 16]),
            now_secs() + 3600,
        )
    }

    #[test]
    fn inbox_retries_preserve_review_and_decline_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inbox.toml");
        let offer = offer();
        let mut inbox = Inbox::default();
        assert!(inbox.receive(offer.clone()).unwrap());
        assert_eq!(inbox.invitations[0].status, InvitationStatus::Pending);
        assert!(!inbox.receive(offer.clone()).unwrap());
        inbox.find_mut(&offer.id).unwrap().status = InvitationStatus::Declined;
        inbox.save_to(&path).unwrap();
        let mut inbox = Inbox::from_path(&path).unwrap();
        assert!(!inbox.receive(offer.clone()).unwrap());
        assert_eq!(inbox.invitations.len(), 1);
        assert_eq!(inbox.invitations[0].status, InvitationStatus::Declined);
        let metadata = serde_json::to_string(&inbox.invitations[0].info()).unwrap();
        assert!(!metadata.contains("secret"));
        assert!(format!("{offer:?}").contains("[redacted]"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn inbox_limits_pending_offers_per_sender_and_answered_offers_free_slots() {
        let offer_from = |sender: u8, n: u8| {
            ReceivedInvitation::new(
                NetworkName::new("sample-net".into()),
                SecretKey::from([1; 32]).public(),
                SecretKey::from([sender; 32]).public(),
                InviteSecret([n; 16]),
                now_secs() + 3600,
            )
        };
        let mut inbox = Inbox::default();
        for n in 0..MAX_PENDING_PER_SENDER as u8 {
            assert!(inbox.receive(offer_from(2, n)).unwrap());
        }
        assert!(inbox.receive(offer_from(2, 100)).is_err());
        // Another sender is unaffected by the first one's backlog.
        assert!(inbox.receive(offer_from(3, 0)).unwrap());
        // Declining frees the sender's pending slot without forgetting the decline.
        inbox.invitations[0].status = InvitationStatus::Declined;
        assert!(inbox.receive(offer_from(2, 100)).unwrap());
        let declined = inbox.invitations[0].clone();
        assert!(!inbox.receive(declined).unwrap());
    }

    #[test]
    fn inbox_rejects_expired_offers_and_does_not_echo_corrupt_credentials() {
        let mut expired = offer();
        expired.expires = now_secs();
        let mut inbox = Inbox::default();
        assert!(inbox.receive(expired).is_err());
        assert!(inbox.invitations.is_empty());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inbox.toml");
        std::fs::write(&path, "secret = 'private-credential'\ninvalid").unwrap();
        let error = Inbox::from_path(&path).err().unwrap().to_string();
        assert!(!error.contains("private-credential"));
    }

    async fn local_endpoint(lookup: MemoryLookup) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .alpns(vec![transport::CONNECT_ALPN.to_vec()])
            .address_lookup(lookup)
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    // The process-wide environment lock isolates both ledgers and the inbox.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn offline_delivery_lost_ack_and_repeated_applies_reuse_one_live_invite() {
        let _env_lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let _env = ConfigEnv(std::env::var_os("RAYFISH_CONFIG_DIR"));
        unsafe {
            std::env::set_var("RAYFISH_CONFIG_DIR", dir.path());
        }
        let contact = SecretKey::from([11; 32]);
        let lookup = MemoryLookup::new();
        let sender_endpoint = local_endpoint(lookup.clone()).await;
        let receiver_endpoint = local_endpoint(MemoryLookup::new()).await;
        lookup.add_endpoint_info(receiver_endpoint.addr());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = format!("http://{}/pkarr", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let packet = dht::encode_contact_record(&contact, receiver_endpoint.id())
            .unwrap()
            .to_relay_payload();
        let discovery = tokio::spawn(async move {
            for payload in [Vec::new(), packet.clone(), packet] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut buf = [0; 1024];
                    let len = stream.read(&mut buf).await.unwrap();
                    assert!(len > 0 && request.len() < 16384);
                    request.extend_from_slice(&buf[..len]);
                }
                let status = if payload.is_empty() {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(&payload).await.unwrap();
            }
        });
        let store = FsStore::load(dir.path().join("blobs")).await.unwrap();
        let mut registry = sample_registry(
            sender_endpoint.clone(),
            IrohIdentityProvider::new(sender_endpoint.id()),
            store.clone(),
            sender_endpoint.id(),
        );
        let mut transport = (*registry.transport).clone();
        transport.pkarr_relay_url = url;
        Arc::get_mut(&mut registry).unwrap().transport = Arc::new(transport);
        let state = make_network_state();
        registry.networks.insert(
            "sample-net".into(),
            NetworkHandle {
                name: "sample-net".into(),
                network_key: state.read().unwrap().network_public_key,
                role: NetworkRole::Coordinator,
                state: Arc::clone(&state),
                dht_notify: None,
                cancel: CancellationToken::new(),
                tasks: vec![],
                invite_lock: Arc::new(AsyncMutex::new(())),
                incompatible: None,
            },
        );
        let sender = Arc::new(ConnectService::new(
            Arc::clone(&registry.transport),
            Arc::new(AtomicBool::new(true)),
            registry,
        ));
        let receiver_registry = sample_registry(
            receiver_endpoint.clone(),
            IrohIdentityProvider::new(receiver_endpoint.id()),
            store,
            contact.public(),
        );
        let receiver = Arc::new(ConnectService::new(
            Arc::clone(&receiver_registry.transport),
            Arc::new(AtomicBool::new(true)),
            receiver_registry,
        ));

        // Offline resolution persists the outbox, without creating an inbox entry.
        let reply = sender
            .deliver_contact_invite("sample-net", contact.public(), None)
            .await;
        assert!(matches!(reply, IpcMessage::Ok { message } if message.contains("queued")));
        let first = InviteStore::load("sample-net")
            .unwrap()
            .live_contact_invite(contact.public())
            .unwrap();
        assert_eq!(InviteStore::load("sample-net").unwrap().list().len(), 1);
        assert!(Inbox::load().unwrap().invitations.is_empty());
        // Membership is checked before dialing or minting, even while offline.
        let joined = SecretKey::from([40; 32]).public();
        state.write().unwrap().members.add(Member {
            identity: joined,
            is_coordinator: false,
            hostname: Some("laptop".into()),
            user_identity: None,
            device_cert: None,
            last_seen: None,
            exit_node: false,
            exit_families: ExitFamilies::default(),
        });
        assert!(
            matches!(sender.deliver_contact_invite("sample-net", contact.public(), Some(joined)).await,
            IpcMessage::Ok { message } if message.contains("already has joined"))
        );
        assert_eq!(InviteStore::load("sample-net").unwrap().list().len(), 1);
        state.write().unwrap().members.remove(&joined);

        let receiver_task = tokio::spawn({
            let receiver = Arc::clone(&receiver);
            let receiver_endpoint = receiver_endpoint.clone();
            async move {
                // Store the first offer, then lose its acknowledgement.
                let conn = receiver_endpoint.accept().await.unwrap().await.unwrap();
                let remote = conn.remote_id();
                let (_send, mut recv) = conn.accept_bi().await.unwrap();
                let request: control::ConnectMsg = control::recv_framed(&mut recv).await.unwrap();
                if let control::ConnectMsg::InviteOffer {
                    network,
                    network_key,
                    recipient_contact,
                    secret,
                    expires,
                } = request
                {
                    let reply = receiver
                        .receive_invitation(
                            recipient_contact,
                            ReceivedInvitation::new(network, network_key, remote, secret, expires),
                        )
                        .await;
                    assert_eq!(reply, control::ConnectMsg::InviteReceived);
                } else {
                    panic!("expected invitation");
                }
                conn.close(0u32.into(), b"lost acknowledgement");
                let conn = receiver_endpoint.accept().await.unwrap().await.unwrap();
                receiver.accept_connect_request(conn).await;
            }
        });
        let failed = sender
            .deliver_contact_invite("sample-net", contact.public(), None)
            .await;
        assert!(matches!(failed, IpcMessage::Ok { message } if message.contains("queued")));
        assert_eq!(Inbox::load().unwrap().invitations.len(), 1);
        assert!(
            receiver.registry.networks.is_empty(),
            "receiving must not join"
        );
        // A sweep uses the saved credential, rather than minting a replacement.
        assert!(matches!(
            sender
                .deliver_contact_invite_inner("sample-net", contact.public(), None, false)
                .await
                .unwrap(),
            DeliveryOutcome::Done(_)
        ));
        receiver_task.await.unwrap();
        discovery.await.unwrap();
        let saved = InviteStore::load("sample-net").unwrap();
        assert!(saved.pending_deliveries().is_empty());
        assert_eq!(saved.list().len(), 1);
        assert_eq!(
            saved
                .live_contact_invite(contact.public())
                .unwrap()
                .secret_hash,
            first.secret_hash
        );
        assert_eq!(
            Inbox::load().unwrap().invitations[0].status,
            InvitationStatus::Pending
        );
        let (one, two) = tokio::join!(
            sender.deliver_contact_invite("sample-net", contact.public(), None),
            sender.deliver_contact_invite("sample-net", contact.public(), None)
        );
        assert!(matches!(one, IpcMessage::Ok { message } if message.contains("already delivered")));
        assert!(matches!(two, IpcMessage::Ok { message } if message.contains("already delivered")));
        assert_eq!(Inbox::load().unwrap().invitations.len(), 1);
        // The recipient controls whether an offer remains pending.
        let id = Inbox::load().unwrap().invitations[0].id.clone();
        assert!(matches!(
            receiver.decline_invitation(&id).await,
            IpcMessage::Ok { .. }
        ));
        assert!(matches!(
            receiver.accept_invitation(&id, None).await,
            IpcMessage::Error { .. }
        ));
        sender_endpoint.close().await;
        receiver_endpoint.close().await;
    }
}
