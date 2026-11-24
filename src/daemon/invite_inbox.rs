//! Private invitations this node has received (`ray invitations`).
//!
//! An offer arrives on the connect channel from a network's coordinator and is
//! only stored: joining needs the recipient's explicit accept. The inbox file
//! holds invite codes, so it is owner-only, its errors never quote it, and IPC
//! sees metadata only.
//!
//! Two locks, both over metadata, never an I/O resource: `inbox_lock` covers
//! one load-modify-save of the file, `answer_lock` spans a whole accept or
//! decline. A join can outlast a sender's delivery timeout, so it runs under
//! the answer lock only and offers keep landing meanwhile.

use std::io::ErrorKind;

use serde::{Deserialize, Serialize};

use super::inbound::Inbound;
use super::*;
use crate::invite::InviteCode;
use crate::membership::now_secs;
use ray_proto::ipc::{InvitationInfo, InvitationStatus, MachineHostname, NetworkName};

/// An entry ages out this long after it arrived, answered or not: as long as
/// a delivered invite lives.
const INBOX_TTL_SECS: u64 = crate::invite::DELIVERY_TTL.as_secs();
/// Pending offers one known sender may hold: more networks than anyone runs,
/// so it only stops one member of a shared network from flooding the inbox.
const MAX_PENDING_KNOWN: usize = 64;
/// Pending offers one stranger may hold. One is enough to make contact; the
/// rest arrive on the sender's retries once the first is accepted.
const MAX_PENDING_STRANGER: usize = 1;
/// Pending offers all strangers may hold together. A stranger beyond it
/// evicts the oldest pending stranger offer, never a known sender's.
const MAX_PENDING_STRANGERS: usize = 16;
/// Pending offers the inbox holds in all. A known sender beyond it evicts the
/// oldest stranger offer; with none left, the offer waits for room.
const MAX_PENDING: usize = 256;

/// Why an offer was not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OfferRefusal {
    /// Not now: no room for this sender, or the inbox could not be saved.
    /// The sender keeps retrying, so the offer lands once the recipient has
    /// room or knows the sender.
    Later(String),
    /// Bad or unwanted. The sender stops offering it.
    Denied(String),
}

impl std::fmt::Display for OfferRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Later(reason) | Self::Denied(reason) => f.write_str(reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct ReceivedInvitation {
    id: String,
    network: NetworkName,
    coordinator: EndpointId,
    code: InviteCode,
    received: u64,
    stranger: bool,
    status: InvitationStatus,
}

impl ReceivedInvitation {
    fn new(
        network: NetworkName,
        coordinator: EndpointId,
        code: InviteCode,
        received: u64,
        stranger: bool,
    ) -> Self {
        let mut hash = blake3::Hasher::new();
        hash.update(coordinator.as_bytes());
        hash.update(code.as_str().as_bytes());
        Self {
            id: hash.finalize().to_hex()[..16].to_string(),
            network,
            coordinator,
            code,
            received,
            stranger,
            status: InvitationStatus::Pending,
        }
    }

    fn info(&self) -> InvitationInfo {
        InvitationInfo {
            id: self.id.clone(),
            network: self.network.clone(),
            coordinator: self.coordinator,
            received: self.received,
            status: self.status,
        }
    }

    fn is_pending(&self) -> bool {
        self.status == InvitationStatus::Pending
    }
}

#[derive(Default, Clone, PartialEq, Serialize, Deserialize)]
struct Inbox {
    #[serde(default)]
    invitations: Vec<ReceivedInvitation>,
}

impl Inbox {
    fn path() -> Result<PathBuf> {
        Ok(config::config_dir()?.join("invitations.toml"))
    }

    fn load() -> Result<Self> {
        Self::load_from(&Self::path()?)
    }

    /// Errors name the problem, never the contents: the file holds codes.
    fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents)
                .map_err(|_| anyhow::anyhow!("invitation inbox is corrupt")),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => anyhow::bail!("could not read the invitation inbox"),
        }
    }

    fn save(&self) -> Result<()> {
        self.save_to(&Self::path()?)
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string(self).context("serialize invitation inbox")?;
        config::write_file(path, contents.as_bytes(), true)
    }

    fn prune(&mut self, now: u64) {
        self.invitations
            .retain(|i| i.received.saturating_add(INBOX_TTL_SECS) > now);
    }

    /// Store an offer. `Ok(true)` stored, `Ok(false)` already held (a retry
    /// after a lost ack).
    fn receive(&mut self, offer: ReceivedInvitation, now: u64) -> Result<bool, OfferRefusal> {
        if !crate::hostname::is_valid_hostname(offer.network.as_ref()) {
            return Err(OfferRefusal::Denied("invalid network label".to_string()));
        }
        self.prune(now);
        if self.invitations.iter().any(|i| i.id == offer.id) {
            return Ok(false);
        }
        let from_sender = self
            .invitations
            .iter()
            .filter(|i| i.is_pending() && i.coordinator == offer.coordinator)
            .count();
        let cap = if offer.stranger {
            MAX_PENDING_STRANGER
        } else {
            MAX_PENDING_KNOWN
        };
        if from_sender >= cap {
            return Err(OfferRefusal::Later(
                "too many pending invitations from this sender".to_string(),
            ));
        }
        let pending = |inbox: &Self, strangers_only: bool| {
            inbox
                .invitations
                .iter()
                .filter(|i| i.is_pending() && (i.stranger || !strangers_only))
                .count()
        };
        if (offer.stranger && pending(self, true) >= MAX_PENDING_STRANGERS)
            || pending(self, false) >= MAX_PENDING
        {
            // Make room by dropping the oldest stranger offer. Only strangers
            // are evicted, so a full inbox of known offers turns the newcomer
            // away instead.
            let oldest = self
                .invitations
                .iter()
                .enumerate()
                .filter(|(_, i)| i.is_pending() && i.stranger)
                .min_by_key(|(_, i)| i.received)
                .map(|(index, _)| index);
            match oldest {
                Some(index) => {
                    self.invitations.remove(index);
                }
                None => return Err(OfferRefusal::Later("invitation inbox is full".to_string())),
            }
        }
        self.invitations.push(offer);
        Ok(true)
    }

    /// The entry named by `id`, an exact id or an unambiguous prefix.
    fn find(&mut self, id: &str) -> Result<&mut ReceivedInvitation> {
        anyhow::ensure!(!id.is_empty(), "an invitation id is required");
        let mut matches = self.invitations.iter_mut().filter(|i| i.id.starts_with(id));
        let found = matches.next().context("no such invitation")?;
        anyhow::ensure!(matches.next().is_none(), "invitation id is ambiguous");
        Ok(found)
    }

    /// Forget pending offers from blocked senders. Answered entries stay so a
    /// retry cannot resurface a decline.
    fn drop_from(&mut self, blocked: impl Fn(EndpointId) -> bool) -> bool {
        let before = self.invitations.len();
        self.invitations
            .retain(|i| !(i.is_pending() && blocked(i.coordinator)));
        self.invitations.len() != before
    }
}

impl ConnectService {
    /// Read the inbox under `inbox_lock`, aged-out entries dropped.
    async fn read_inbox<T>(&self, read: impl FnOnce(&mut Inbox) -> Result<T>) -> Result<T> {
        let _guard = self.inbox_lock.lock().await;
        let mut inbox = Inbox::load()?;
        inbox.prune(now_secs());
        read(&mut inbox)
    }

    /// Like [`Self::read_inbox`], then save if anything changed. An error
    /// from `edit` saves nothing. Skipping the unchanged save keeps a peer
    /// repeating an offer from forcing a disk sync each time.
    async fn edit_inbox<T>(&self, edit: impl FnOnce(&mut Inbox) -> Result<T>) -> Result<T> {
        let _guard = self.inbox_lock.lock().await;
        let loaded = Inbox::load()?;
        let mut inbox = loaded.clone();
        inbox.prune(now_secs());
        let out = edit(&mut inbox)?;
        if inbox != loaded {
            inbox.save()?;
        }
        Ok(out)
    }

    /// Whether an offer can be acknowledged, used by the local callers.
    #[cfg(test)]
    pub(super) async fn receive_offer(
        &self,
        remote: EndpointId,
        class: Inbound,
        network: NetworkName,
        code: InviteCode,
    ) -> bool {
        self.receive_offer_result(remote, class, network, code)
            .await
            .is_ok()
    }

    /// Store an offer, or say why not and whether the sender should retry.
    pub(super) async fn receive_offer_result(
        &self,
        remote: EndpointId,
        class: Inbound,
        network: NetworkName,
        code: InviteCode,
    ) -> Result<(), OfferRefusal> {
        match code.decode() {
            Ok(decoded) if decoded.coordinator == remote => {}
            _ => {
                return Err(OfferRefusal::Denied(
                    "invalid invitation or coordinator".to_string(),
                ));
            }
        }
        let offer = ReceivedInvitation::new(
            network,
            remote,
            code,
            now_secs(),
            class == Inbound::Stranger,
        );
        let mut refusal = None;
        let edited = self
            .edit_inbox(|inbox| {
                let declined = inbox.invitations.iter().any(|entry| {
                    entry.id == offer.id && entry.status == InvitationStatus::Declined
                });
                let received = if declined {
                    Err(OfferRefusal::Denied(
                        "recipient declined the invitation".to_string(),
                    ))
                } else {
                    inbox.receive(offer, now_secs())
                };
                // The refusal still lets the prune be saved.
                refusal = received.err();
                Ok(())
            })
            .await;
        if let Err(error) = edited {
            return Err(OfferRefusal::Later(error.to_string()));
        }
        refusal.map_or(Ok(()), Err)
    }

    pub(super) async fn list_invitations(&self) -> OpResult<Vec<InvitationInfo>> {
        self.read_inbox(|inbox| {
            Ok(inbox
                .invitations
                .iter()
                .map(ReceivedInvitation::info)
                .collect())
        })
        .await
        .map_err(|e| OpError::msg(e.to_string()))
    }

    /// Join the invitation's network, pinned to the coordinator that sent it.
    /// A failed join leaves the entry pending so it can be retried or declined.
    pub(super) async fn accept_invitation(
        &self,
        id: &str,
        hostname: Option<MachineHostname>,
    ) -> OpResult<JoinOutcome> {
        let _answer = self.answer_lock.lock().await;
        let found = self
            .read_inbox(|inbox| {
                let entry = inbox.find(id)?;
                anyhow::ensure!(entry.is_pending(), "invitation already answered");
                Ok(entry.clone())
            })
            .await;
        let invitation = found.map_err(|e| OpError::msg(e.to_string()))?;
        let Ok(decoded) = invitation.code.decode() else {
            return op_err("invitation code is invalid");
        };
        let reply = self
            .registry
            .join_network(
                &decoded.network_key.to_string(),
                None,
                hostname.map(|h| h.to_string()),
                Some(decoded.secret),
                Some(JoinCoordinator::Preferred(invitation.coordinator)),
                false,
                false,
                None,
            )
            .await;
        self.settle_accept(&invitation, reply).await
    }

    /// Record what the join did to an accepted invitation.
    pub(super) async fn settle_accept(
        &self,
        invitation: &ReceivedInvitation,
        joined: OpResult<JoinOutcome>,
    ) -> OpResult<JoinOutcome> {
        // A queued join's retry loop now holds the secret, so a second accept
        // must not start another.
        if joined.is_ok() {
            let saved = self
                .edit_inbox(|inbox| {
                    // An entry that aged out during the join is gone; the join stands.
                    if let Ok(entry) = inbox.find(&invitation.id) {
                        entry.status = InvitationStatus::Accepted;
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = saved {
                tracing::warn!(error = %e, "joined, but could not mark the invitation accepted");
            }
        }
        match joined {
            Err(e) if crate::invite::is_dead_invite(e.message()) => {
                Err(self.drop_dead_invitation(invitation).await)
            }
            joined => joined,
        }
    }

    /// The coordinator refused the invitation's code: it was revoked, used or
    /// has expired. Nothing can redeem it, so it leaves the inbox.
    async fn drop_dead_invitation(&self, invitation: &ReceivedInvitation) -> OpError {
        let dropped = self
            .edit_inbox(|inbox| {
                inbox.invitations.retain(|i| i.id != invitation.id);
                Ok(())
            })
            .await;
        if let Err(e) = dropped {
            tracing::warn!(error = %e, "could not drop a revoked invitation");
        }
        OpError::msg(format!(
            "the invitation to {} was revoked or has expired; ask {} for a new one",
            invitation.network,
            invitation.coordinator.fmt_short()
        ))
    }

    #[cfg(test)]
    pub(super) async fn invitation_entry(&self, id: &str) -> ReceivedInvitation {
        self.read_inbox(|inbox| Ok(inbox.find(id)?.clone()))
            .await
            .expect("the invitation is in the inbox")
    }

    /// Refuse an invitation and block its sender on the connect channel.
    pub(super) async fn decline_invitation(&self, id: &str) -> OpResult<Done> {
        let _answer = self.answer_lock.lock().await;
        let declined = self
            .edit_inbox(|inbox| {
                let entry = inbox.find(id)?;
                anyhow::ensure!(entry.is_pending(), "invitation already answered");
                entry.status = InvitationStatus::Declined;
                Ok(entry.coordinator)
            })
            .await;
        let coordinator = declined.map_err(|e| OpError::msg(e.to_string()))?;
        if let Err(e) = self.block(coordinator).await {
            return op_err(format!("declined, but blocking the sender failed: {e:#}"));
        }
        Ok(Done(format!(
            "declined and blocked {} (undo with: ray unblock {coordinator})",
            coordinator.fmt_short()
        )))
    }

    /// Drop pending offers from blocked senders.
    pub(super) async fn drop_blocked_invitations(&self, blocked: impl Fn(EndpointId) -> bool) {
        let dropped = self
            .edit_inbox(|inbox| {
                inbox.drop_from(blocked);
                Ok(())
            })
            .await;
        if let Err(e) = dropped {
            tracing::warn!(error = %e, "could not drop blocked invitations");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        SecretKey::from([seed; 32]).public()
    }

    fn offer_from(sender: u8, n: u8, stranger: bool, received: u64) -> ReceivedInvitation {
        ReceivedInvitation::new(
            NetworkName::new("sample-net".into()),
            id(sender),
            InviteCode::encode(&id(100), &id(sender), &[n; 16]),
            received,
            stranger,
        )
    }

    #[test]
    fn duplicate_offer_is_acked_once() {
        let mut inbox = Inbox::default();
        assert!(inbox.receive(offer_from(1, 1, false, 1000), 1000).unwrap());
        assert!(!inbox.receive(offer_from(1, 1, false, 1001), 1001).unwrap());
        assert_eq!(inbox.invitations.len(), 1);
    }

    #[test]
    fn pending_caps_per_known_sender_per_stranger_and_for_all_strangers() {
        let mut inbox = Inbox::default();
        for n in 0..MAX_PENDING_KNOWN as u8 {
            assert!(inbox.receive(offer_from(1, n, false, 1000), 1000).unwrap());
        }
        assert!(matches!(
            inbox.receive(offer_from(1, 99, false, 1000), 1000),
            Err(OfferRefusal::Later(_))
        ));
        for n in 0..MAX_PENDING_STRANGER as u8 {
            assert!(inbox.receive(offer_from(2, n, true, 1000), 1000).unwrap());
        }
        assert!(matches!(
            inbox.receive(offer_from(2, 99, true, 1000), 1000),
            Err(OfferRefusal::Later(_))
        ));
        // Fill the shared stranger slots, oldest first.
        for sender in 3..(3 + MAX_PENDING_STRANGERS as u8) {
            let received = 1000 + u64::from(sender);
            assert!(
                inbox
                    .receive(offer_from(sender, 0, true, received), received)
                    .unwrap()
            );
        }
        let strangers = |inbox: &Inbox| inbox.invitations.iter().filter(|i| i.stranger).count();
        assert_eq!(strangers(&inbox), MAX_PENDING_STRANGERS);
        // Known senders kept every slot.
        assert_eq!(
            inbox.invitations.iter().filter(|i| !i.stranger).count(),
            MAX_PENDING_KNOWN
        );
    }

    /// The stranger cap counts the sender, not the flag on each entry: once
    /// the sender is known, its next offer lands beside the stranger one.
    #[test]
    fn a_stranger_who_becomes_known_gets_the_known_cap() {
        let mut inbox = Inbox::default();
        assert!(inbox.receive(offer_from(1, 0, true, 1000), 1000).unwrap());
        assert!(inbox.receive(offer_from(1, 1, true, 1000), 1000).is_err());
        assert!(inbox.receive(offer_from(1, 1, false, 1001), 1001).unwrap());
    }

    /// A full inbox evicts strangers for a known sender, and turns the known
    /// sender away for later only when no stranger is left.
    #[test]
    fn a_full_inbox_evicts_strangers_then_defers() {
        let mut inbox = Inbox::default();
        inbox.receive(offer_from(200, 0, true, 999), 999).unwrap();
        let mut sender = 1u8;
        while inbox.invitations.len() < MAX_PENDING {
            for n in 0..MAX_PENDING_KNOWN as u8 {
                if inbox.invitations.len() == MAX_PENDING {
                    break;
                }
                inbox
                    .receive(offer_from(sender, n, false, 1000), 1000)
                    .unwrap();
            }
            sender += 1;
        }
        assert!(
            inbox
                .receive(offer_from(sender, 0, false, 1001), 1001)
                .unwrap()
        );
        assert!(inbox.invitations.iter().all(|i| !i.stranger));
        assert_eq!(
            inbox.receive(offer_from(sender, 1, false, 1001), 1001),
            Err(OfferRefusal::Later("invitation inbox is full".to_string()))
        );
        assert!(matches!(
            inbox.receive(offer_from(201, 0, true, 1001), 1001),
            Err(OfferRefusal::Later(_))
        ));
    }

    #[test]
    fn answered_offers_do_not_count_and_survive_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invitations.toml");
        let mut inbox = Inbox::default();
        for n in 0..MAX_PENDING_STRANGER as u8 {
            inbox.receive(offer_from(2, n, true, 1000), 1000).unwrap();
        }
        inbox.invitations[0].status = InvitationStatus::Declined;
        let declined = inbox.invitations[0].clone();
        assert!(inbox.receive(offer_from(2, 50, true, 1000), 1000).unwrap());
        inbox.save_to(&path).unwrap();
        let mut inbox = Inbox::load_from(&path).unwrap();
        assert!(!inbox.receive(declined, 1001).unwrap());
        assert_eq!(inbox.invitations[0].status, InvitationStatus::Declined);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn entries_age_out_after_seven_days() {
        let mut inbox = Inbox::default();
        inbox.receive(offer_from(1, 1, false, 1000), 1000).unwrap();
        inbox.prune(1000 + INBOX_TTL_SECS - 1);
        assert_eq!(inbox.invitations.len(), 1);
        inbox.prune(1000 + INBOX_TTL_SECS);
        assert!(inbox.invitations.is_empty());
    }

    #[test]
    fn corrupt_inbox_error_does_not_contain_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invitations.toml");
        std::fs::write(&path, "code = 'private-credential'\nbroken").unwrap();
        let error = Inbox::load_from(&path).err().unwrap().to_string();
        assert!(!error.contains("private-credential"));
    }

    #[test]
    fn invalid_network_label_is_refused() {
        let mut inbox = Inbox::default();
        let mut offer = offer_from(1, 1, false, 1000);
        offer.network = NetworkName::new("not a label!".into());
        assert!(matches!(
            inbox.receive(offer, 1000),
            Err(OfferRefusal::Denied(_))
        ));
    }

    #[test]
    fn blocking_drops_pending_offers_but_keeps_answers() {
        let mut inbox = Inbox::default();
        inbox.receive(offer_from(1, 1, false, 1000), 1000).unwrap();
        inbox.receive(offer_from(1, 2, false, 1000), 1000).unwrap();
        inbox.invitations[0].status = InvitationStatus::Declined;
        assert!(inbox.drop_from(|remote| remote == id(1)));
        assert_eq!(inbox.invitations.len(), 1);
        assert_eq!(inbox.invitations[0].status, InvitationStatus::Declined);
    }
}
