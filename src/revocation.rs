//! Per-device certificate revocation (`ray unpair`).
//!
//! A `DeviceCert` binds a device key to a user identity and verifies forever — it
//! can't be un-signed. Revocation is therefore a **published deny-list**: the
//! owning user publishes, under its own key, a signed record naming the specific
//! device keys it has revoked (`dht::encode_revoked_record`). Every peer that
//! would honor a cert first checks whether the cert's `device_key` is in the
//! signer's revoked set; a listed device is rejected. Unlike a user-wide
//! generation floor, revoking one device leaves every other device of that user
//! untouched (no fleet rotation, no re-issue). A revoked device re-authorizes by
//! re-pairing, which removes it from the set (see `MeshManager::unpair` and the
//! pairing accept arm).
//!
//! The record carries a monotonic `version` so the deny-list can both grow (a
//! revoke) and shrink (a re-auth) without a stale/replayed copy winning: a fetch
//! only replaces the cached set when its version is strictly newer.
//!
//! This cache holds the last-known (version, revoked-set) per user identity so the
//! check is a lock-free map read on the hot admission path. It is populated by:
//!   - `record` — a background poller (and on-demand fetches) refresh each seen
//!     user's set from its pkarr record, and
//!   - `set_local` — a node sets its own set instantly on revoke/re-auth, no round
//!     trip.
//!
//! **Fail-open when unseen, monotonic by version.** A user we have never resolved
//! a record for has an empty set (nothing rejected), so a relay outage can't lock
//! an offline mesh out. A refresh replaces the set only on a strictly newer
//! version, so a failed or stale fetch can't resurrect or drop a revocation.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::EndpointId;

use crate::control::DeviceCert;
use crate::peers::FastDashMap;

/// How long a cached set is considered fresh before the poller refetches it.
/// Matches the pkarr record TTL/2 republish cadence.
pub const REVOCATION_TTL: Duration = Duration::from_secs(150);

/// What to do with a presented `DeviceCert` given the current revocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertDecision {
    /// Honor the cert.
    Admit,
    /// Reject it: the device key is in its signer's revoked set (`ray unpair`).
    Reject,
}

struct Entry {
    version: u64,
    revoked: HashSet<EndpointId>,
    fetched_at: Instant,
}

/// Daemon-wide, cheap-`Clone` cache mapping a user identity to its published set
/// of revoked device keys (plus the record version that set came from).
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

    /// Whether `device_key` is in `user`'s cached revoked set. An unseen user has
    /// an empty set, so this is `false` (fail-open).
    pub fn is_revoked(&self, user: &EndpointId, device_key: &EndpointId) -> bool {
        self.inner
            .get(user)
            .map(|e| e.revoked.contains(device_key))
            .unwrap_or(false)
    }

    /// Record the revoked set observed from a user's pkarr record at `version`.
    /// Monotonic by version: a set is only replaced by a strictly-newer version,
    /// so a stale/replayed record can't win. Returns true when this call adopted a
    /// newer version (the set may have changed), so the caller can prune peers that
    /// just became revoked.
    pub fn record(&self, user: EndpointId, version: u64, revoked: HashSet<EndpointId>) -> bool {
        use dashmap::mapref::entry::Entry as MapEntry;
        match self.inner.entry(user) {
            MapEntry::Occupied(mut o) => {
                if version > o.get().version {
                    o.insert(Entry {
                        version,
                        revoked,
                        fetched_at: Instant::now(),
                    });
                    true
                } else {
                    o.get_mut().fetched_at = Instant::now();
                    false
                }
            }
            MapEntry::Vacant(v) => {
                v.insert(Entry {
                    version,
                    revoked,
                    fetched_at: Instant::now(),
                });
                true
            }
        }
    }

    /// Set our own revoked set instantly on revoke/re-auth, without a round trip.
    pub fn set_local(&self, user: EndpointId, version: u64, revoked: HashSet<EndpointId>) {
        self.record(user, version, revoked);
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
/// holds the user secret and thus the authoritative revoked set for its own
/// devices. For our own devices we consult `revoked_local` (the live config set);
/// for every other cert we consult the signer's cached published set.
///
/// - **Our own device** (`cert.user_identity == Some(my id)`): in `revoked_local`
///   -> `Reject`; else `Admit`.
/// - **Any other cert**: device key in the signer's cached revoked set -> `Reject`;
///   else `Admit`. An unseen signer has an empty set, so nothing is rejected.
pub fn cert_decision(
    cert: &DeviceCert,
    my_issuing_identity: Option<EndpointId>,
    revoked_local: &dyn Fn(&EndpointId) -> bool,
    cache: &RevocationCache,
) -> CertDecision {
    let revoked = if my_issuing_identity == Some(cert.user_identity) {
        revoked_local(&cert.device_key)
    } else {
        cache.is_revoked(&cert.user_identity, &cert.device_key)
    };
    if revoked {
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

    fn set(keys: &[EndpointId]) -> HashSet<EndpointId> {
        keys.iter().copied().collect()
    }

    #[test]
    fn unseen_user_has_nothing_revoked() {
        let cache = RevocationCache::new();
        assert!(!cache.is_revoked(&id(), &id()));
    }

    #[test]
    fn record_is_monotonic_by_version() {
        let cache = RevocationCache::new();
        let user = id();
        let dev = id();
        cache.record(user, 5, set(&[dev]));
        assert!(cache.is_revoked(&user, &dev));
        // A stale/lower version never overwrites the current set.
        cache.record(user, 3, set(&[]));
        assert!(cache.is_revoked(&user, &dev));
        // A newer version can shrink the set (a re-auth).
        cache.record(user, 8, set(&[]));
        assert!(!cache.is_revoked(&user, &dev));
    }

    #[test]
    fn record_reports_version_adoption() {
        let cache = RevocationCache::new();
        let user = id();
        assert!(cache.record(user, 2, set(&[])));
        assert!(!cache.record(user, 2, set(&[])));
        assert!(cache.record(user, 3, set(&[])));
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
        cache.record(user, 0, set(&[]));
        assert!(!cache.needs_refresh(&user));
    }

    fn cert(user: &SecretKey, device: EndpointId) -> DeviceCert {
        DeviceCert::create(user, &device, 0)
    }

    #[test]
    fn own_device_admitted_when_not_revoked() {
        let me = SecretKey::generate();
        let cache = RevocationCache::new();
        let c = cert(&me, id());
        let never = |_: &EndpointId| false;
        assert_eq!(
            cert_decision(&c, Some(me.public()), &never, &cache),
            CertDecision::Admit
        );
    }

    #[test]
    fn own_revoked_device_is_rejected() {
        let me = SecretKey::generate();
        let cache = RevocationCache::new();
        let device = id();
        let c = cert(&me, device);
        let revoked = move |d: &EndpointId| *d == device;
        assert_eq!(
            cert_decision(&c, Some(me.public()), &revoked, &cache),
            CertDecision::Reject
        );
    }

    #[test]
    fn other_user_revoked_device_rejected() {
        let other = SecretKey::generate();
        let cache = RevocationCache::new();
        let device = id();
        cache.record(other.public(), 1, set(&[device]));
        let c = cert(&other, device);
        let never = |_: &EndpointId| false;
        assert_eq!(
            cert_decision(&c, None, &never, &cache),
            CertDecision::Reject
        );
    }

    #[test]
    fn other_user_unrevoked_device_admitted() {
        let other = SecretKey::generate();
        let cache = RevocationCache::new();
        cache.record(other.public(), 1, set(&[id()]));
        let c = cert(&other, id());
        let never = |_: &EndpointId| false;
        assert_eq!(cert_decision(&c, None, &never, &cache), CertDecision::Admit);
    }

    #[test]
    fn other_user_unseen_fails_open() {
        let other = SecretKey::generate();
        let cache = RevocationCache::new();
        let c = cert(&other, id());
        let never = |_: &EndpointId| false;
        assert_eq!(cert_decision(&c, None, &never, &cache), CertDecision::Admit);
    }
}
