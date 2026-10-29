//! Unpairing a device from its primary, saved at each step so that a crash, a
//! restart or an unreachable peer leaves it to be finished rather than lost.
//!
//! Only the primary revokes a device network-wide: the nullifier rides the
//! signed blob, which only a network-key holder writes. Each side therefore
//! saves what is left to do before doing it, and keeps it until the other side
//! confirms:
//!
//! - A device that unpairs, by itself or when its primary tells it to, first
//!   saves a [`PendingUnpair`] holding the certificate it gives up. It then
//!   leaves the networks first joined with that certificate and deletes it, and
//!   only once those deletions are durable does the entry move on to
//!   [`UnpairPhase::Request`]. A start that finds an entry still in
//!   [`UnpairPhase::Cleanup`] finishes the cleanup before anything reads the
//!   certificate or restores a network ([`finish_interrupted_unpair`]).
//! - In the request phase the device asks its primary, over the pairing
//!   protocol, to record the revocation (`PairMsg::UnpairRequest`, carrying the
//!   certificate as the evidence of the pairing). The primary answers
//!   `PairMsg::UnpairRecorded` once the revocation is saved, also when it
//!   already was, and only that answer removes the entry. Until then the
//!   request is retried, at once after a start and then with a growing pause:
//!   once the device has left, neither side has another reason to dial the
//!   other.
//! - A primary too old for version 3 of the pairing protocol is sent the
//!   earlier `ControlMsg::RequestUnpair` instead, which revokes the device if
//!   its rosters still list it. Nothing confirms that, so the entry stays.
//! - Saving a new pairing with the same primary cancels the entry, which would
//!   otherwise revoke it. A pairing with another primary leaves it be.
//! - On the primary, `ray unpair <device>` saves the revocation, and the device
//!   in `pending_unpair_notices`, before telling the device
//!   (`ControlMsg::PairingRevoked`). The notice is repeated, after a restart
//!   too, until the device confirms with the same request, which it sends only
//!   once its cleanup is saved, or until the device pairs here again.
//!
//! A notice or a request can be acted on long after it was sent, and the
//! device can pair again in between: a notice can wait on the link behind
//! another stream, and a request can still be under way on the primary when
//! the device gives up on it. So each pairing gets a generation, one above the
//! last the primary gave that device, saved there before the device gets its
//! certificate, which is signed at it. The device confirms on the pairing
//! connection once it has saved the certificate (`PairMsg::CertificateSaved`).
//! The notice names the latest generation issued, and the request carries the
//! certificate. Each is judged against the pairing current when it is acted
//! on: a device ignores a notice older than its certificate, and a primary
//! revokes nothing for a certificate older than the latest one the device
//! confirmed. An unconfirmed replacement does not count, since the reply
//! carrying it can be lost and leave the device on its earlier certificate,
//! whose unpair must still revoke it. Over mesh version 6 or 5 the notice is
//! the bare `ControlMsg::Unpaired`, which names no pairing: an older device
//! knows no other, and an older primary signs every pairing of a device alike.
//!
//! A nullifier names no pairing either: the signed blob lists the device's
//! key, and a device that finds itself there unpairs. So the primary lifts the
//! revocation of a device that pairs again before it signs the certificate,
//! and waits until the records without it are published, since the device
//! joins the networks shared with it at once and reads the record first. A
//! pairing whose records are not published in time is refused, and the
//! revocation put back. While a network the primary coordinates is not
//! running, it publishes nothing and its last record still nullifies the
//! device, so the pairing of a revoked device is refused before anything
//! changes. Creating, renaming, leaving or destroying a network waits for a
//! pairing under way, so that none stops or appears after that check.

use super::super::network_registry::networks_joined_with_certificate;
use super::super::*;
use crate::config::{DeviceGeneration, PendingUnpair, PendingUnpairNotice, UnpairPhase};

#[cfg(test)]
mod tests;

/// How long one unpair request may take: the dial, then the primary saving the
/// revocation and republishing its networks. Past it the attempt has failed.
const UNPAIR_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long telling a device it is unpaired may take, the dial included.
const UNPAIR_NOTICE_TIMEOUT: Duration = Duration::from_secs(10);

/// The first pause before trying again, doubled after each miss up to
/// [`UNPAIR_RETRY_MAX`]. A peer can stay offline for days, and the device on
/// one end of it is usually a phone.
const UNPAIR_RETRY_MIN: Duration = Duration::from_secs(60);
const UNPAIR_RETRY_MAX: Duration = Duration::from_secs(30 * 60);

/// What an unpair request got from the primary.
#[derive(Debug, PartialEq, Eq)]
enum RequestOutcome {
    /// The primary saved the revocation.
    Recorded,
    /// The primary predates the request and was sent the earlier
    /// `ControlMsg::RequestUnpair`, which nothing confirms.
    Legacy,
}

/// Finish the cleanup of each unpair that a restart interrupted, before
/// anything reads the device certificate or restores a network: the saved
/// networks first joined with the certificate are deleted, and so is the
/// certificate, as the interrupted unpair would have done. No network is live
/// yet, so none is told the device left; the primary's revocation removes it
/// from the networks the primary coordinates.
pub(crate) fn finish_interrupted_unpair() {
    let pending = match config::load() {
        Ok(cfg) => cfg.pending_unpairs,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not read saved unpairs");
            return;
        }
    };
    for entry in pending
        .iter()
        .filter(|entry| entry.phase == UnpairPhase::Cleanup)
    {
        let primary = entry.cert.user_identity;
        match finish_cleanup_offline(&entry.cert) {
            Ok(left) => tracing::info!(
                primary = %primary.fmt_short(),
                left,
                "finished an interrupted unpair"
            ),
            Err(error) => tracing::warn!(
                primary = %primary.fmt_short(),
                error = %format!("{error:#}"),
                "could not finish an interrupted unpair; it is retried"
            ),
        }
    }
}

/// The cleanup of an unpair from `cert` with no network live: delete the saved
/// networks first joined with it and, unless another pairing's certificate is
/// stored, the certificate, then [`complete_cleanup`]. Returns how many
/// networks were removed.
fn finish_cleanup_offline(cert: &control::DeviceCert) -> Result<usize> {
    let cfg = config::load()?;
    let names = networks_joined_with_certificate(&cfg.networks, cert.user_identity);
    for name in &names {
        config::delete_network(name)?;
    }
    match identity::load_device_cert() {
        Ok(Some(stored)) if stored != *cert => {}
        _ => identity::delete_device_cert()?,
    }
    complete_cleanup(cert)?;
    Ok(names.len())
}

/// Make the cleanup of the unpair from `cert` durable, then move its entry on
/// to the request, which is also the device's confirmation that the cleanup is
/// done.
fn complete_cleanup(cert: &control::DeviceCert) -> Result<()> {
    config::sync_deletions()?;
    config::update_settings(|cfg| {
        for entry in &mut cfg.pending_unpairs {
            if entry.cert == *cert {
                entry.phase = UnpairPhase::Request;
            }
        }
        Ok(())
    })?;
    Ok(())
}

/// Remove the saved unpair from `cert`, confirmed or cancelled. Returns whether
/// it is gone.
fn remove_pending_unpair(cert: &control::DeviceCert) -> bool {
    match config::update_settings(|cfg| {
        cfg.pending_unpairs.retain(|entry| entry.cert != *cert);
        Ok(())
    }) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "could not remove a saved unpair");
            false
        }
    }
}

/// What this primary saved about its pairings with `device`, if it numbered any.
fn device_generation(cfg: &config::AppConfig, device: EndpointId) -> Option<&DeviceGeneration> {
    cfg.device_generations
        .iter()
        .find(|known| known.device == device)
}

/// The generation of the latest certificate this primary signed for
/// `device`: the one saved in `device_generations`, or, for a device paired
/// before pairings were numbered, the legacy `cert_generation` its
/// certificate carries.
fn issued_generation(cfg: &config::AppConfig, device: EndpointId) -> u64 {
    device_generation(cfg, device).map_or(cfg.cert_generation, |known| known.issued)
}

/// Save the generation of a new pairing of `device` before it gets its
/// certificate: one above the last issued, and, in the same write, the end of
/// its notices, which are about earlier pairings. What it confirmed saving so
/// far stays: this pairing counts only once the device confirms it too.
/// Returns the generation to sign.
fn save_pairing_generation(device: EndpointId) -> Result<u64> {
    let mut generation = 0;
    config::update_settings(|cfg| {
        generation = issued_generation(cfg, device) + 1;
        let confirmed = device_generation(cfg, device).and_then(|known| known.confirmed);
        cfg.device_generations
            .retain(|known| known.device != device);
        cfg.device_generations.push(DeviceGeneration {
            device,
            issued: generation,
            confirmed,
        });
        cfg.pending_unpair_notices
            .retain(|notice| notice.device != device);
        Ok(())
    })?;
    Ok(generation)
}

/// Save that `device` confirmed it saved the certificate this primary signed
/// for it at `generation`, which a request about an earlier pairing then
/// cannot revoke.
pub(crate) fn save_certificate_saved(device: EndpointId, generation: u64) -> Result<()> {
    config::update_settings(|cfg| {
        if let Some(known) = cfg
            .device_generations
            .iter_mut()
            .find(|known| known.device == device)
        {
            known.confirmed = known.confirmed.max(Some(generation));
        }
        Ok(())
    })?;
    Ok(())
}

/// Save in `cfg` that `device` has yet to be told it is unpaired, naming its
/// latest pairing.
pub(crate) fn save_unpair_notice(cfg: &mut config::AppConfig, device: EndpointId) {
    let generation = issued_generation(cfg, device);
    cfg.pending_unpair_notices
        .retain(|notice| notice.device != device);
    cfg.pending_unpair_notices
        .push(PendingUnpairNotice { device, generation });
}

/// Whether a mesh link speaks version 6 or 5, which predate
/// `ControlMsg::PairingRevoked`: a device is told over it with the bare
/// `ControlMsg::Unpaired`.
pub(crate) fn predates_pairing_generations(alpn: &[u8]) -> bool {
    alpn == transport::MESH_V6_ALPN || alpn == transport::MESH_V5_ALPN
}

/// The notice that a device's pairing up to `generation` is revoked, in the
/// form `link` speaks.
fn unpair_notice(link: &Connection, generation: u64) -> ControlMsg {
    if predates_pairing_generations(link.alpn()) {
        ControlMsg::Unpaired
    } else {
        ControlMsg::PairingRevoked { generation }
    }
}

/// Run `attempt` at once, whenever `nudge` fires, and, while it reports work
/// left, again after a pause that starts at [`UNPAIR_RETRY_MIN`] and doubles up
/// to [`UNPAIR_RETRY_MAX`]. A nudge also resets the pause. With nothing left it
/// waits for a nudge alone, so it costs no wakeups.
async fn retry_until_done<F, Fut>(shutdown: &CancellationToken, nudge: &Notify, mut attempt: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let mut wait = UNPAIR_RETRY_MIN;
    loop {
        let left = attempt().await;
        let pause = async {
            if left {
                tokio::time::sleep(wait).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = nudge.notified() => wait = UNPAIR_RETRY_MIN,
            _ = pause => wait = (wait * 2).min(UNPAIR_RETRY_MAX),
        }
    }
}

impl NetworkRegistry {
    /// Unpair this device from its primary: save the unpair, leave the networks
    /// first joined with the primary's certificate and delete it, then, once
    /// that is durable, ask the primary to record the revocation (see the
    /// module docs). Used by the phone's unpair control, and, through
    /// [`Self::on_unpaired_notice`] and [`Self::unpair_nullified`], by the
    /// primary's notice and a signed blob that nullifies this device. A device
    /// with no cert (a primary) has nothing to unpair.
    pub(crate) async fn unpair_self(self: &Arc<Self>) -> IpcMessage {
        let _guard = self.unpair_lock.lock().await;
        self.unpair_self_locked().await
    }

    /// [`Self::unpair_self`], for a caller holding the unpair lock.
    async fn unpair_self_locked(self: &Arc<Self>) -> IpcMessage {
        let Some(cert) = self.current_device_cert() else {
            return ipc_err("this device is not paired to a primary".to_string());
        };
        // Saved before any of the work, so a restart finishes it.
        if let Err(error) = config::update_settings(|cfg| {
            cfg.pending_unpairs
                .retain(|entry| entry.cert.user_identity != cert.user_identity);
            cfg.pending_unpairs.push(PendingUnpair {
                cert: cert.clone(),
                phase: UnpairPhase::Cleanup,
            });
            Ok(())
        }) {
            return ipc_err(format!("could not save the unpair: {error:#}"));
        }
        let left = self.finish_cleanup_locked(&cert).await;
        self.unpair_nudge.notify_one();
        left
    }

    /// The cleanup of the saved unpair from `cert`, made durable and moved on to
    /// its request. Caller holds the unpair lock.
    async fn finish_cleanup_locked(self: &Arc<Self>, cert: &control::DeviceCert) -> IpcMessage {
        let left = self.leave_certificate_networks(cert).await;
        if !matches!(left, IpcMessage::Ok { .. }) {
            return left;
        }
        if let Err(error) = complete_cleanup(cert) {
            return ipc_err(format!(
                "left the primary's networks and deleted its certificate, but could not \
                 save that ({error:#}); it is retried"
            ));
        }
        left
    }

    /// The primary's notice that this device is unpaired, from `sender`:
    /// `ControlMsg::PairingRevoked`, whose generation is `revoked`, or, over
    /// mesh version 6 or 5, the bare `Unpaired`, which names none. Judged here,
    /// under the unpair lock, against the certificate stored now rather than
    /// when the notice was read: it may have waited on the link behind another
    /// stream while this device paired again, which signs the new certificate
    /// at a higher generation. Unpairs this device when `sender` signed its
    /// certificate and the certificate is no newer than the notice. A device
    /// that already unpaired from `sender` and still waits for it to confirm
    /// asks again at once, since the primary is reachable now.
    pub(crate) async fn on_unpaired_notice(
        self: &Arc<Self>,
        sender: EndpointId,
        revoked: Option<u64>,
    ) {
        let _guard = self.unpair_lock.lock().await;
        if let Some(cert) = self
            .current_device_cert()
            .filter(|cert| cert.user_identity == sender)
        {
            if revoked.is_some_and(|generation| cert.generation > generation) {
                tracing::info!(primary = %sender.fmt_short(), "ignoring an unpair notice about an earlier pairing");
                return;
            }
            tracing::warn!(primary = %sender.fmt_short(), "primary unpaired this device");
            let _ = self.unpair_self_locked().await;
            return;
        }
        let waiting = config::load().is_ok_and(|cfg| {
            cfg.pending_unpairs
                .iter()
                .any(|entry| entry.cert.user_identity == sender)
        });
        if waiting {
            self.unpair_nudge.notify_one();
        }
    }

    /// Unpair this device because its own primary nullified `cert` in a
    /// network's verified blob. The blob was checked before this took the
    /// unpair lock, which a pairing holds until it completes, so a certificate
    /// stored since is a new pairing, signed at a higher generation, and stays.
    /// A blob read after the pairing completed revokes the new one: the primary
    /// publishes the records that lift the earlier revocation before it signs
    /// ([`Self::save_new_pairing`]).
    pub(crate) async fn unpair_nullified(self: &Arc<Self>, cert: control::DeviceCert) {
        let _guard = self.unpair_lock.lock().await;
        match self.current_device_cert() {
            Some(stored) if stored == cert => {
                let _ = self.unpair_self_locked().await;
            }
            Some(_) => {
                tracing::info!(primary = %cert.user_identity.fmt_short(), "paired again since the primary nullified this device; keeping the new pairing");
            }
            None => {}
        }
    }

    /// A new pairing with `primary` is saved: cancel this device's request to be
    /// unpaired from it, which would otherwise revoke the new pairing. Caller
    /// holds the unpair lock. If the cancel cannot be saved, the next attempt at
    /// the request finds the new certificate and cancels it then.
    pub(crate) fn paired_again(&self, primary: EndpointId) {
        if let Err(error) = config::update_settings(|cfg| {
            cfg.pending_unpairs
                .retain(|entry| entry.cert.user_identity != primary);
            Ok(())
        }) {
            tracing::warn!(error = %format!("{error:#}"), "could not cancel the unpair request to this primary");
        }
    }

    /// Finish the cleanup of any saved unpair still in that phase, which only a
    /// start that failed to finish it leaves, so that a pairing never starts
    /// under one. Caller holds the unpair lock.
    pub(crate) async fn finish_cleanups_locked(self: &Arc<Self>) -> Result<(), String> {
        let pending = config::load()
            .map_err(|error| format!("could not read saved unpairs: {error:#}"))?
            .pending_unpairs;
        for entry in pending {
            if entry.phase != UnpairPhase::Cleanup {
                continue;
            }
            if let IpcMessage::Error { message } = self.finish_cleanup_locked(&entry.cert).await {
                return Err(message);
            }
        }
        Ok(())
    }

    /// Drive this device's saved unpairs to completion: at once when the daemon
    /// starts or [`Self::unpair_nudge`] fires, and while any is left, again
    /// after a pause growing from [`UNPAIR_RETRY_MIN`] to [`UNPAIR_RETRY_MAX`].
    /// Spawned on every build, so the mobile embedder gets it: a phone is what
    /// unpairs itself.
    pub(crate) async fn run_unpair_requests(self: Arc<Self>) {
        let nudge = Arc::clone(&self.unpair_nudge);
        retry_until_done(&self.shutdown_token, &nudge, || {
            self.attempt_unpair_requests()
        })
        .await;
    }

    /// One attempt at each of this device's saved unpairs: finish a cleanup the
    /// start could not, and send each request. Returns whether any is left.
    pub(crate) async fn attempt_unpair_requests(self: &Arc<Self>) -> bool {
        let _guard = self.unpair_lock.lock().await;
        let pending = match config::load() {
            Ok(cfg) => cfg.pending_unpairs,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "could not read saved unpairs");
                return true;
            }
        };
        let stored = self.current_device_cert();
        let mut left = false;
        for entry in pending {
            let primary = entry.cert.user_identity;
            if entry.phase == UnpairPhase::Cleanup {
                if let IpcMessage::Error { message } = self.finish_cleanup_locked(&entry.cert).await
                {
                    tracing::warn!(primary = %primary.fmt_short(), %message, "could not finish an unpair");
                } else {
                    // Its request is next, without waiting for the pause.
                    self.unpair_nudge.notify_one();
                }
                left = true;
                continue;
            }
            // Pairing again saves the new certificate before it cancels the
            // request, and in this phase the old one is already deleted, so a
            // stored certificate from this primary is a new pairing that a
            // restart kept from cancelling it.
            if stored
                .as_ref()
                .is_some_and(|cert| cert.user_identity == primary)
            {
                tracing::info!(primary = %primary.fmt_short(), "paired with this primary again; cancelling the unpair request");
                left |= !remove_pending_unpair(&entry.cert);
                continue;
            }
            match tokio::time::timeout(
                UNPAIR_REQUEST_TIMEOUT,
                self.send_unpair_request(&entry.cert),
            )
            .await
            {
                Ok(Ok(RequestOutcome::Recorded)) => {
                    tracing::info!(primary = %primary.fmt_short(), "primary recorded this device's unpair");
                    left |= !remove_pending_unpair(&entry.cert);
                }
                Ok(Ok(RequestOutcome::Legacy)) => {
                    tracing::debug!(primary = %primary.fmt_short(), "primary predates unpair requests; sent it the earlier one");
                    left = true;
                }
                Ok(Err(error)) => {
                    tracing::debug!(primary = %primary.fmt_short(), error = %format!("{error:#}"), "unpair request failed");
                    left = true;
                }
                Err(_) => {
                    tracing::debug!(primary = %primary.fmt_short(), "unpair request timed out");
                    left = true;
                }
            }
        }
        left
    }

    /// Ask the primary that signed `cert` to record this device's revocation.
    /// A primary on version 2 of the pairing protocol cannot, so it is sent the
    /// earlier `ControlMsg::RequestUnpair` instead.
    async fn send_unpair_request(&self, cert: &control::DeviceCert) -> Result<RequestOutcome> {
        #[cfg(target_os = "android")]
        self.wake_transport().await;
        let primary = cert.user_identity;
        let conn = connect_pair(&self.transport.endpoint, primary.into()).await?;
        if conn.alpn() != PAIR_ALPN {
            conn.close(VarInt::from_u32(0), b"older pairing protocol");
            self.deliver_control(primary, |_| ControlMsg::RequestUnpair)
                .await?;
            return Ok(RequestOutcome::Legacy);
        }
        let (mut send, mut recv) = conn.open_bi().await.context("open unpair stream")?;
        let request = control::PairMsg::UnpairRequest { cert: cert.clone() };
        control::send_framed(&mut send, &request).await?;
        let reply: control::PairMsg = control::recv_framed(&mut recv)
            .await
            .context("read unpair reply")?;
        conn.close(VarInt::from_u32(0), b"done");
        match reply {
            control::PairMsg::UnpairRecorded => Ok(RequestOutcome::Recorded),
            _ => anyhow::bail!("unexpected reply to an unpair request"),
        }
    }

    /// Send `peer` the connection-level control message `msg` builds for the
    /// link, and wait until the peer's transport acknowledges it, which does not
    /// mean the peer has read it. Uses the live link when there is one.
    /// Otherwise a link is dialed for the message alone, since an unpaired
    /// device and its primary may share no network any more.
    async fn deliver_control(
        &self,
        peer: EndpointId,
        msg: impl FnOnce(&Connection) -> ControlMsg,
    ) -> Result<()> {
        #[cfg(target_os = "android")]
        self.wake_transport().await;
        let live = self
            .peers
            .conn_for_ip(&derive_ipv6(&peer))
            .filter(|conn| conn.close_reason().is_none());
        let dialed = live.is_none();
        let conn = match live {
            Some(conn) => conn,
            None => {
                transport::connect_to_peer_with_alpn(
                    &self.transport.endpoint,
                    peer,
                    &transport::mesh_alpn(),
                )
                .await?
            }
        };
        send_confirmed(&conn, None, &msg(&conn)).await?;
        if dialed {
            // Acknowledged, but closing at once can still reset it before the
            // peer's reader is done with it. Leave it a moment, as `nuke` does
            // for its one-off deliveries.
            let _ = tokio::time::timeout(Duration::from_secs(1), conn.closed()).await;
        }
        Ok(())
    }

    /// Tell each device in `pending_unpair_notices` that its pairing is revoked:
    /// at once when the daemon starts or [`Self::notice_nudge`] fires, and while
    /// any is left, again after the same growing pause as the requests.
    pub(crate) async fn run_unpair_notices(self: Arc<Self>) {
        let nudge = Arc::clone(&self.notice_nudge);
        retry_until_done(&self.shutdown_token, &nudge, || {
            self.attempt_unpair_notices()
        })
        .await;
    }

    /// One notice to each device still to be told. Returns whether any is
    /// left: told or not, a device stays until it confirms
    /// ([`Self::record_unpair`]) or pairs here again
    /// ([`Self::save_new_pairing`]). A notice that reaches the device after it
    /// paired again names the earlier pairing, which the device ignores.
    pub(crate) async fn attempt_unpair_notices(&self) -> bool {
        let notices = match config::load() {
            Ok(cfg) => cfg.pending_unpair_notices,
            Err(error) => {
                tracing::debug!(error = %format!("{error:#}"), "could not read devices to tell they are unpaired");
                return true;
            }
        };
        for &PendingUnpairNotice { device, generation } in &notices {
            match tokio::time::timeout(
                UNPAIR_NOTICE_TIMEOUT,
                self.deliver_control(device, |link| unpair_notice(link, generation)),
            )
            .await
            {
                Ok(Ok(())) => {
                    tracing::debug!(device = %device.fmt_short(), "told device it is unpaired; waiting for it to confirm")
                }
                Ok(Err(error)) => {
                    tracing::debug!(device = %device.fmt_short(), error = %format!("{error:#}"), "could not tell device it is unpaired")
                }
                Err(_) => {
                    tracing::debug!(device = %device.fmt_short(), "timed out telling device it is unpaired")
                }
            }
        }
        !notices.is_empty()
    }

    /// Record the unpair a paired device asked for with the certificate this
    /// node signed for it at `generation`, which the caller checked: revoke the
    /// device ([`Self::revoke_device_locked`]) and, in the same write, stop
    /// telling it to unpair, since a device asks only once its cleanup is saved.
    /// A certificate older than the latest one the device confirmed it saved is
    /// from a pairing the device has since replaced, and revokes nothing: the
    /// request can be read late, or still be under way, when the device pairs
    /// again. A replacement it never confirmed does not count. Returns whether
    /// the pairing was current.
    pub(crate) async fn record_unpair(
        self: &Arc<Self>,
        device: EndpointId,
        generation: u64,
    ) -> Result<bool, String> {
        // A pairing of the device takes this lock too, so it lifts this
        // revocation only once it is done.
        let _revoking = self.revocation_lock.lock().await;
        let cfg = config::load().map_err(|error| format!("could not read settings: {error:#}"))?;
        if device_generation(&cfg, device)
            .and_then(|known| known.confirmed)
            .is_some_and(|confirmed| confirmed > generation)
        {
            return Ok(false);
        }
        self.revoke_device_locked(device, |cfg| {
            cfg.pending_unpair_notices
                .retain(|notice| notice.device != device);
        })
        .await?;
        Ok(true)
    }

    /// Save a new pairing of `device` before it gets its certificate, and
    /// return the generation to sign it at. A revocation of the device here is
    /// lifted first, with the records that no longer nullify it published
    /// ([`Self::reauth_device_locked`]), since the device joins the networks
    /// shared with it as soon as it has the certificate. Both run under
    /// [`Self::revocation_lock`], so no revocation lands between them. On an
    /// error the revocation stands and nothing about this pairing is saved, so
    /// the notices about the earlier one stay as well.
    pub(crate) async fn save_new_pairing(
        self: &Arc<Self>,
        device: EndpointId,
    ) -> Result<u64, String> {
        let _revoking = self.revocation_lock.lock().await;
        let lifted = self.reauth_device_locked(device).await?;
        match save_pairing_generation(device) {
            Ok(generation) => Ok(generation),
            Err(error) => {
                if lifted && let Err(message) = self.revoke_device_locked(device, |_| {}).await {
                    tracing::warn!(device = %device.fmt_short(), %message, "could not put back the revocation of a pairing that failed");
                }
                Err(format!("could not save the pairing: {error:#}"))
            }
        }
    }
}
