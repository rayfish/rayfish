//! Sending private invitations (`ray apply --invite-missing`).
//!
//! The outbox is the invite ledger: a delivery invite keeps its code so every
//! retry offers the same credential. A delivery is dialed to the recipient's
//! identity and counts as delivered only when the recipient's daemon acks it.
//! An unreachable recipient is not an error: the sweep retries until the
//! invite expires, is redeemed, or is revoked, and never mints a new one.
//! Offers ride their own ALPN, so a recipient too old to read one fails the
//! handshake: that is recorded and the sweep leaves it alone.

use super::*;
use crate::invite::{Invite, InviteStore};

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// What a delivery attempt did. Both are success for the caller: a queued
/// delivery is retried by the sweep.
pub(super) enum DeliveryOutcome {
    Done(String),
    Queued(String),
}

impl DeliveryOutcome {
    pub(super) fn into_message(self) -> String {
        match self {
            Self::Done(message) | Self::Queued(message) => message,
        }
    }
}

/// What the recipient's node did with a dial.
enum Reply {
    /// Stored the offer and acked it.
    Stored,
    /// Shares no ALPN with us: it predates invite delivery.
    TooOld,
}

/// Whether a delivery may mint a new invite. The sweep never does: if the
/// invite was redeemed, revoked or expired since it was picked, there is
/// nothing to resend.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mint {
    Allow,
    Never,
}

impl ConnectService {
    /// `InviteDeliver`: deliver (or reuse and redeliver) an invite to
    /// `recipient` for `network`.
    pub(super) async fn deliver_invite(&self, network: &str, recipient: EndpointId) -> IpcMessage {
        match self.deliver_locked(network, recipient, Mint::Allow).await {
            Ok(outcome) => IpcMessage::Ok {
                message: outcome.into_message(),
            },
            Err(e) => ipc_err(e.to_string()),
        }
    }

    /// One delivery per recipient at a time, so a slow dial to one recipient
    /// never holds up another.
    pub(super) async fn deliver_locked(
        &self,
        network: &str,
        recipient: EndpointId,
        mint: Mint,
    ) -> Result<DeliveryOutcome> {
        let lock = Arc::clone(
            &self
                .delivery_locks
                .entry(recipient)
                .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        );
        let _guard = lock.lock().await;
        self.deliver_inner(network, recipient, mint).await
    }

    async fn deliver_inner(
        &self,
        network: &str,
        recipient: EndpointId,
        mint: Mint,
    ) -> Result<DeliveryOutcome> {
        let (network_key, invite_lock) =
            self.registry.coordinator_handle(network).map_err(|_| {
                anyhow::anyhow!("invite delivery requires a network this node coordinates")
            })?;
        if self.recipient_joined(network, recipient) {
            return Ok(DeliveryOutcome::Done(format!(
                "{} already has a device in {network}",
                recipient.fmt_short()
            )));
        }
        let invite: Invite = {
            let _guard = invite_lock.lock().await;
            let mut store = InviteStore::load(network)?;
            if mint == Mint::Allow {
                store.delivery_for(recipient, network_key, self.transport.endpoint.id())?
            } else {
                match store.live_delivery(recipient) {
                    Some(invite) => invite,
                    None => return Ok(DeliveryOutcome::Done("no pending delivery".to_string())),
                }
            }
        };
        let delivery = invite.delivery.context("delivery invite missing")?;
        if delivery.delivered {
            return Ok(DeliveryOutcome::Done(format!(
                "invite {} already delivered; awaiting the recipient",
                invite.id
            )));
        }
        let offer = control::ConnectMsg::InviteOffer {
            network: ipc::NetworkName::new(network.to_string()),
            code: delivery.code.clone(),
        };
        let reply = tokio::time::timeout(DELIVERY_TIMEOUT, async {
            let conn = match transport::connect_to_peer_with_alpn(
                &self.transport.endpoint,
                recipient,
                transport::INVITE_ALPN,
            )
            .await
            {
                Ok(conn) => conn,
                Err(e) if transport::is_alpn_mismatch(&format!("{e:#}")) => {
                    return Ok(Reply::TooOld);
                }
                Err(e) => return Err(e),
            };
            let (mut send, mut recv) = conn.open_bi().await?;
            control::send_framed(&mut send, &offer).await?;
            // Never echo a peer reply: only the ack shape matters.
            match control::recv_framed::<control::ConnectMsg>(&mut recv).await? {
                control::ConnectMsg::Pending => Ok(Reply::Stored),
                _ => anyhow::bail!("recipient did not acknowledge"),
            }
        })
        .await;
        match reply {
            Ok(Ok(Reply::Stored)) => {}
            Ok(Ok(Reply::TooOld)) => {
                {
                    let _guard = invite_lock.lock().await;
                    InviteStore::load(network)?.mark_unsupported(&invite.id)?;
                }
                // The sweep finds this on its own, with nobody to read the
                // reply, so it goes to the log too. Never the code itself.
                tracing::warn!(
                    %network,
                    peer = %recipient.fmt_short(),
                    invite = %invite.id,
                    "recipient runs an older Rayfish and cannot receive invites; no longer retrying, send the invite again to get its code"
                );
                // The coordinator's own credential, shown only to its operator.
                return Ok(DeliveryOutcome::Done(format!(
                    "{} runs an older Rayfish that cannot receive invites; send them this code instead: {}",
                    recipient.fmt_short(),
                    delivery.code.as_str()
                )));
            }
            _ => {
                return Ok(DeliveryOutcome::Queued(format!(
                    "{} is unreachable; invite {} queued and retried until it expires",
                    recipient.fmt_short(),
                    invite.id
                )));
            }
        }
        {
            let _guard = invite_lock.lock().await;
            InviteStore::load(network)?.mark_delivered(&invite.id)?;
        }
        Ok(DeliveryOutcome::Done(format!(
            "invite {} delivered; awaiting the recipient",
            invite.id
        )))
    }

    /// Whether any device of `recipient` (device or user identity) is already a
    /// member of `network`.
    fn recipient_joined(&self, network: &str, recipient: EndpointId) -> bool {
        self.registry.networks.get(network).is_some_and(|handle| {
            handle.state.read().is_ok_and(|state| {
                state
                    .members
                    .all()
                    .iter()
                    .any(|member| member.matches_identity(recipient))
            })
        })
    }

    /// Retry undelivered invites every minute until the daemon stops.
    pub(crate) fn start_invite_delivery(self: &Arc<Self>, token: CancellationToken) {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(RETRY_INTERVAL) => {}
                }
                service.sweep_deliveries(&token).await;
            }
        });
    }

    /// Retry every undelivered invite at once: each attempt can wait out a
    /// dial timeout, and the per-recipient locks keep them apart.
    pub(super) async fn sweep_deliveries(&self, token: &CancellationToken) {
        let networks: Vec<String> = self
            .registry
            .networks
            .iter()
            .filter(|n| n.role.is_coordinator())
            .map(|n| n.key().clone())
            .collect();
        let mut queued = Vec::new();
        for network in networks {
            match InviteStore::load(&network) {
                Ok(store) => queued.extend(
                    store
                        .pending_deliveries()
                        .into_iter()
                        .map(|recipient| (network.clone(), recipient)),
                ),
                Err(_) => tracing::warn!(%network, "could not read the invite ledger for delivery"),
            }
        }
        let attempts = queued.iter().map(|(network, recipient)| async move {
            if !matches!(
                self.deliver_locked(network, *recipient, Mint::Never).await,
                Ok(DeliveryOutcome::Done(_))
            ) {
                tracing::debug!(%network, peer = %recipient.fmt_short(), "invite still queued");
            }
        });
        tokio::select! {
            _ = token.cancelled() => {}
            _ = futures::future::join_all(attempts) => {}
        }
    }
}
