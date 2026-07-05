//! Device-cert generation floors (`ray unpair` / rotation).
//!
//! A `DeviceCert` carries a `generation`. Revocation is a *fleet rotation*: the
//! owning user bumps its generation and publishes the new value as a signed
//! "floor" to pkarr under its own key (`dht::encode_cert_floor_record`). Every
//! peer that would honor a cert first checks whether the cert's generation is at
//! or above the signer's floor; a cert below the floor is rejected. The devices
//! the user keeps are re-issued fresh certs at the new generation, so only the
//! revoked (not-re-issued) device stays below the floor.
//!
//! This cache holds the last-known floor per user identity so the check is a
//! lock-free map read on the hot admission path. It is populated by:
//!   - `record` — a background poller (and on-demand fetches) refresh floors from
//!     each seen user's pkarr record, and
//!   - `set_local` — a node sets its own floor instantly on rotation, no round trip.
//!
//! **Fail-open when unseen, monotonic once seen.** A user we have never resolved a
//! floor for is treated as floor 0 (`floor` returns 0), so a relay outage can't
//! lock an offline mesh out. A refresh only ever *raises* a cached floor (pkarr
//! timestamps make the record monotonic; we never lower it), so a failed or stale
//! fetch can't un-revoke a device.

use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::EndpointId;

use crate::control::DeviceCert;
use crate::peers::FastDashMap;

/// How long a cached floor is considered fresh before the poller refetches it.
/// Matches the pkarr record TTL/2 republish cadence.
pub const REVOCATION_TTL: Duration = Duration::from_secs(150);

/// What to do with a presented `DeviceCert` given the current generation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertDecision {
    /// Honor the cert as-is.
    Admit,
    /// Reject it: it is below the floor (another user's stale cert) or the device
    /// is in our local do-not-reissue set (our own revoked device).
    Reject,
    /// Our own device presenting a stale-but-not-revoked cert: admit it, but
    /// push it a fresh cert at our current generation (offline-keeper refresh).
    Reissue,
}

struct Entry {
    floor: u64,
    fetched_at: Instant,
}

/// Daemon-wide, cheap-`Clone` cache mapping a user identity to its published
/// cert-generation floor.
#[derive(Clone, Default)]
pub struct RevocationCache {
    inner: Arc<FastDashMap<EndpointId, Entry>>,
}

impl RevocationCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FastDashMap::default()),
        }
    }

    /// The cached floor for `user`, or 0 if unseen (fail-open).
    pub fn floor(&self, user: &EndpointId) -> u64 {
        self.inner.get(user).map(|e| e.floor).unwrap_or(0)
    }

    /// Record a floor observed from a user's pkarr record. Monotonic: only ever
    /// raises the cached value, so a stale fetch can't un-revoke.
    pub fn record(&self, user: EndpointId, floor: u64) {
        let mut e = self.inner.entry(user).or_insert(Entry {
            floor: 0,
            fetched_at: Instant::now(),
        });
        if floor > e.floor {
            e.floor = floor;
        }
        e.fetched_at = Instant::now();
    }

    /// Set our own floor instantly on rotation, without a round trip. Also
    /// monotonic (a rotation only increases it).
    pub fn set_local(&self, user: EndpointId, floor: u64) {
        self.record(user, floor);
    }

    /// Whether `user`'s entry is missing or older than [`REVOCATION_TTL`], i.e.
    /// the poller should refetch it.
    pub fn needs_refresh(&self, user: &EndpointId) -> bool {
        self.inner
            .get(user)
            .map(|e| e.fetched_at.elapsed() >= REVOCATION_TTL)
            .unwrap_or(true)
    }
}

/// Decide what to do with a presented `DeviceCert`. Pure, so the matrix is
/// unit-tested without any daemon state.
///
/// `my_issuing_identity` is `Some(id)` only on the **primary** — the node that
/// holds the user secret, so it can re-issue its own devices and knows the
/// authoritative generation. A secondary node passes `None`, so *every* cert
/// (including its siblings') is judged by the published floor instead.
///
/// - **Our own device** (`cert.user_identity == Some(my id)`): in `revoked_local`
///   -> `Reject`; else generation below ours -> `Reissue` (refresh it); else
///   `Admit`. We are the authority here, so we never consult the cache.
/// - **Any other cert**: below the signer's cached floor -> `Reject`; else
///   `Admit`. An unseen signer has floor 0, so nothing is rejected (fail-open).
pub fn cert_decision(
    cert: &DeviceCert,
    my_issuing_identity: Option<EndpointId>,
    my_generation: u64,
    revoked_local: &dyn Fn(&EndpointId) -> bool,
    floor: &RevocationCache,
) -> CertDecision {
    if my_issuing_identity == Some(cert.user_identity) {
        if revoked_local(&cert.device_key) {
            CertDecision::Reject
        } else if cert.generation < my_generation {
            CertDecision::Reissue
        } else {
            CertDecision::Admit
        }
    } else if cert.generation < floor.floor(&cert.user_identity) {
        CertDecision::Reject
    } else {
        CertDecision::Admit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn id() -> EndpointId {
        SecretKey::generate().public()
    }

    #[test]
    fn unseen_user_floor_is_zero() {
        let cache = RevocationCache::new();
        assert_eq!(cache.floor(&id()), 0);
    }

    #[test]
    fn record_is_monotonic() {
        let cache = RevocationCache::new();
        let user = id();
        cache.record(user, 5);
        assert_eq!(cache.floor(&user), 5);
        // A stale/lower fetch never lowers the floor.
        cache.record(user, 3);
        assert_eq!(cache.floor(&user), 5);
        cache.record(user, 8);
        assert_eq!(cache.floor(&user), 8);
    }

    #[test]
    fn needs_refresh_when_unseen() {
        let cache = RevocationCache::new();
        assert!(cache.needs_refresh(&id()));
    }

    #[test]
    fn fresh_entry_does_not_need_refresh() {
        let cache = RevocationCache::new();
        let user = id();
        cache.record(user, 0);
        assert!(!cache.needs_refresh(&user));
    }

    fn cert(user: &SecretKey, device: EndpointId, generation: u64) -> DeviceCert {
        DeviceCert::create(user, &device, generation)
    }

    #[test]
    fn own_device_admitted_at_current_generation() {
        let me = SecretKey::generate();
        let cache = RevocationCache::new();
        let c = cert(&me, id(), 3);
        let never = |_: &EndpointId| false;
        assert_eq!(
            cert_decision(&c, Some(me.public()), 3, &never, &cache),
            CertDecision::Admit
        );
    }

    #[test]
    fn own_stale_device_is_reissued() {
        let me = SecretKey::generate();
        let cache = RevocationCache::new();
        let c = cert(&me, id(), 2);
        let never = |_: &EndpointId| false;
        assert_eq!(
            cert_decision(&c, Some(me.public()), 5, &never, &cache),
            CertDecision::Reissue
        );
    }

    #[test]
    fn own_revoked_device_is_rejected_even_if_current() {
        let me = SecretKey::generate();
        let cache = RevocationCache::new();
        let device = id();
        let c = cert(&me, device, 5);
        // In the local do-not-reissue set -> reject regardless of generation.
        let revoked = move |d: &EndpointId| *d == device;
        assert_eq!(
            cert_decision(&c, Some(me.public()), 5, &revoked, &cache),
            CertDecision::Reject
        );
    }

    #[test]
    fn other_user_below_floor_rejected() {
        let other = SecretKey::generate();
        let cache = RevocationCache::new();
        cache.record(other.public(), 4);
        let c = cert(&other, id(), 2);
        let never = |_: &EndpointId| false;
        assert_eq!(
            cert_decision(&c, None, 0, &never, &cache),
            CertDecision::Reject
        );
    }

    #[test]
    fn other_user_at_or_above_floor_admitted() {
        let other = SecretKey::generate();
        let cache = RevocationCache::new();
        cache.record(other.public(), 4);
        let c = cert(&other, id(), 4);
        let never = |_: &EndpointId| false;
        assert_eq!(cert_decision(&c, None, 0, &never, &cache), CertDecision::Admit);
    }

    #[test]
    fn other_user_unseen_floor_fails_open() {
        let other = SecretKey::generate();
        let cache = RevocationCache::new();
        let c = cert(&other, id(), 0);
        let never = |_: &EndpointId| false;
        assert_eq!(cert_decision(&c, None, 0, &never, &cache), CertDecision::Admit);
    }
}
