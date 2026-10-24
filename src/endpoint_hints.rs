//! Bounded, expiring bootstrap hints from authenticated transport paths.
//!
//! These are fallbacks, not authoritative discovery records or a relay policy.
//! Keep the old `endpoint_hints` representation readable by older binaries and
//! store per-address Unix timestamps alongside it. An un-timestamped legacy
//! address is not evidence of a recent successful connection, so it is ignored
//! until a live connection confirms it again. Reads never renew a hint's age.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use futures::StreamExt;
use futures::stream::{self, BoxStream};
use iroh::address_lookup::{AddressLookup, EndpointData, EndpointInfo, Error, Item};
use iroh::{EndpointAddr, EndpointId, TransportAddr};

use crate::config::AppConfig;

/// Last authenticated observation, keyed by endpoint identity then address.
/// Address strings are the canonical `TransportAddr` display form, not DNS
/// answers. Keeping this separate preserves the old settings-file address list.
pub type HintTimestamps = BTreeMap<String, BTreeMap<String, u64>>;

pub const MAX_PEERS: usize = 64;
pub const MAX_ADDRS_PER_PEER: usize = 8;
pub const MAX_AGE_SECS: u64 = 24 * 60 * 60;
pub(crate) const REFRESH_INTERVAL_SECS: u64 = 10 * 60;

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn kind(addr: &TransportAddr) -> Option<usize> {
    match addr {
        TransportAddr::Relay(_) => Some(0),
        TransportAddr::Ip(SocketAddr::V4(_)) => Some(1),
        TransportAddr::Ip(SocketAddr::V6(_)) => Some(2),
        _ => None,
    }
}

/// Normalize untrusted persisted cache bookkeeping. Unknown-age, expired and
/// future-dated addresses are not re-aged during migration or after clock skew.
/// Bound both peer and address counts; preserve the freshest relay/IPv4/IPv6
/// candidate, when present, before filling the remaining slots by recency.
pub fn prune(hints: &mut Vec<EndpointAddr>, timestamps: &mut HintTimestamps, now: u64) {
    prune_observed(hints, timestamps, now, None);
}

fn prune_observed(
    hints: &mut Vec<EndpointAddr>,
    timestamps: &mut HintTimestamps,
    now: u64,
    observed: Option<&EndpointAddr>,
) {
    let mut peers: BTreeMap<EndpointId, BTreeMap<TransportAddr, u64>> = BTreeMap::new();
    for hint in hints.iter() {
        let Some(seen) = timestamps.get(&hint.id.to_string()) else {
            continue;
        };
        for addr in &hint.addrs {
            let Some(&at) = seen.get(&addr.to_string()) else {
                continue;
            };
            if kind(addr).is_none() || at == 0 || at > now || now - at >= MAX_AGE_SECS {
                continue;
            }
            peers
                .entry(hint.id)
                .or_default()
                .entry(addr.clone())
                .and_modify(|old| *old = (*old).max(at))
                .or_insert(at);
        }
    }
    let mut normalized = Vec::new();
    for (id, addrs) in peers {
        let mut recent: Vec<_> = addrs.into_iter().collect();
        let just_observed = |addr: &TransportAddr| {
            observed.is_some_and(|hint| hint.id == id && hint.addrs.contains(addr))
        };
        recent.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| just_observed(&b.0).cmp(&just_observed(&a.0)))
                .then_with(|| a.0.cmp(&b.0))
        });
        let mut kept = BTreeSet::new();
        for family in 0..3 {
            if let Some((addr, _)) = recent.iter().find(|(addr, _)| kind(addr) == Some(family)) {
                kept.insert(addr.clone());
            }
        }
        for (addr, _) in &recent {
            if kept.len() == MAX_ADDRS_PER_PEER {
                break;
            }
            kept.insert(addr.clone());
        }
        let seen: BTreeMap<_, _> = recent
            .into_iter()
            .filter(|(addr, _)| kept.contains(addr))
            .map(|(addr, at)| (addr.to_string(), at))
            .collect();
        let latest = seen.values().copied().max().unwrap_or_default();
        normalized.push((latest, EndpointAddr::from_parts(id, kept), seen));
    }
    let just_observed = |id| observed.is_some_and(|hint| hint.id == id);
    normalized.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| just_observed(b.1.id).cmp(&just_observed(a.1.id)))
            .then_with(|| a.1.id.cmp(&b.1.id))
    });
    normalized.truncate(MAX_PEERS);
    normalized.reverse();
    hints.clear();
    timestamps.clear();
    for (_, hint, seen) in normalized {
        timestamps.insert(hint.id.to_string(), seen);
        hints.push(hint);
    }
}

/// Record only a just-confirmed path, without refreshing unrelated addresses.
pub(crate) fn remember(
    hints: &mut Vec<EndpointAddr>,
    timestamps: &mut HintTimestamps,
    peer: EndpointId,
    addrs: impl IntoIterator<Item = TransportAddr>,
    now: u64,
) {
    let addrs: BTreeSet<_> = addrs
        .into_iter()
        .filter(|addr| kind(addr).is_some())
        .collect();
    let observed = EndpointAddr::from_parts(peer, addrs);
    if !observed.addrs.is_empty() {
        let seen = timestamps.entry(peer.to_string()).or_default();
        for addr in &observed.addrs {
            seen.insert(addr.to_string(), now);
        }
        hints.push(observed.clone());
    }
    // Several path changes can land in one timestamp second. Prefer this
    // actual observation over older candidates with the same timestamp, so a
    // full cache never discards the path we have just learned by address order.
    prune_observed(
        hints,
        timestamps,
        now,
        (!observed.addrs.is_empty()).then_some(&observed),
    );
}

#[derive(Debug, Default, Clone)]
struct State {
    hints: Vec<EndpointAddr>,
    timestamps: HintTimestamps,
}

impl State {
    fn prune(&mut self, now: u64) {
        prune(&mut self.hints, &mut self.timestamps, now);
    }

    fn remember(&mut self, addr: EndpointAddr, now: u64) {
        remember(
            &mut self.hints,
            &mut self.timestamps,
            addr.id,
            addr.addrs,
            now,
        );
    }

    fn copy_to(&self, cfg: &mut AppConfig) {
        cfg.endpoint_hints = self.hints.clone();
        cfg.endpoint_hint_timestamps = self.timestamps.clone();
    }
}

/// The daemon's bootstrap lookup. Expiry applies to the running lookup as well
/// as settings loaded after a restart. The lock protects cache data, never a
/// socket or stream. Cache mutations serialize memory/disk changes with each
/// other; settings' own transaction still preserves unrelated configuration.
#[derive(Debug, Clone, Default)]
pub struct WarmLookup {
    state: Arc<RwLock<State>>,
}

impl WarmLookup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(cfg: &AppConfig) -> Self {
        let mut state = State {
            hints: cfg.endpoint_hints.clone(),
            timestamps: cfg.endpoint_hint_timestamps.clone(),
        };
        state.prune(now_secs());
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Add an explicitly trusted address in memory (e.g. an embedder's peer
    /// address). Production connection observations use `remember_verified`.
    pub fn add_endpoint_info(&self, addr: EndpointAddr) {
        self.state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remember(addr, now_secs());
    }

    pub fn get_endpoint_info(&self, peer: EndpointId) -> Option<EndpointInfo> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.prune(now_secs());
        state
            .hints
            .iter()
            .find(|hint| hint.id == peer)
            .cloned()
            .map(Into::into)
    }

    pub fn remove_endpoint_info(&self, peer: EndpointId) -> Option<EndpointInfo> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let index = state.hints.iter().position(|hint| hint.id == peer)?;
        state.timestamps.remove(&peer.to_string());
        Some(state.hints.remove(index).into())
    }

    pub(crate) fn copy_to(&self, cfg: &mut AppConfig) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.prune(now_secs());
        state.copy_to(cfg);
    }

    pub(crate) fn remember_verified(&self, addr: EndpointAddr) -> Result<()> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.remember(addr, now_secs());
        // A failed save does not discard useful in-memory observations.
        crate::config::update_settings(|cfg| {
            state.copy_to(cfg);
            Ok(())
        })?;
        Ok(())
    }

    pub(crate) fn clear_config(&self, value: &str, replace: bool) -> Result<AppConfig> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let mut next = state.clone();
        next.prune(now_secs());
        let cfg = crate::config::update_settings(|cfg| {
            next.copy_to(cfg);
            crate::config::settings::apply_global(
                cfg,
                crate::config::settings::GlobalKey::EndpointHints,
                value,
                replace,
            )
        })?;
        *state = State {
            hints: cfg.endpoint_hints.clone(),
            timestamps: cfg.endpoint_hint_timestamps.clone(),
        };
        Ok(cfg)
    }
}

impl AddressLookup for WarmLookup {
    fn publish(&self, _data: &EndpointData) {}

    fn resolve(&self, peer: EndpointId) -> Option<BoxStream<'static, Result<Item, Error>>> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.prune(now_secs());
        let addr = state.hints.iter().find(|hint| hint.id == peer)?.clone();
        let at = state
            .timestamps
            .get(&peer.to_string())?
            .values()
            .max()?
            .saturating_mul(1_000_000);
        // Report the observation time, not the time this cache was read.
        let item = Item::new(addr.into(), "rayfish_warm_hints", Some(at));
        Some(stream::iter([Ok(item)]).boxed())
    }
}

pub(crate) fn render(cfg: &AppConfig) -> String {
    let mut hints = cfg.endpoint_hints.clone();
    let mut timestamps = cfg.endpoint_hint_timestamps.clone();
    let now = now_secs();
    prune(&mut hints, &mut timestamps, now);
    let rows: Vec<_> = hints
        .iter()
        .flat_map(|hint| {
            hint.addrs.iter().map(|addr| {
                let at = timestamps[&hint.id.to_string()][&addr.to_string()];
                serde_json::json!({"peer": hint.id.to_string(), "address": addr.to_string(),
                           "last_verified": at, "age_secs": now - at})
            })
        })
        .collect();
    serde_json::to_string(&rows).expect("endpoint hint rows contain only JSON values")
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    const NOW: u64 = 1_800_000_000;
    fn peer() -> EndpointId {
        SecretKey::generate().public()
    }
    fn ip(n: usize) -> TransportAddr {
        TransportAddr::Ip(format!("192.0.2.1:{}", 1000 + n).parse().unwrap())
    }
    fn relay() -> TransportAddr {
        TransportAddr::Relay("https://relay.example/".parse().unwrap())
    }

    #[test]
    fn refreshing_one_address_does_not_renew_the_rest() {
        // Only explicit authenticated observations refresh an address; reading
        // a snapshot or learning an unrelated address cannot extend its TTL.
        let id = peer();
        let mut hints = vec![];
        let mut times = HintTimestamps::new();
        remember(&mut hints, &mut times, id, [ip(1)], NOW);
        remember(
            &mut hints,
            &mut times,
            id,
            [relay()],
            NOW + MAX_AGE_SECS - 1,
        );
        prune(&mut hints, &mut times, NOW + MAX_AGE_SECS);
        assert_eq!(hints, vec![EndpointAddr::from_parts(id, [relay()])]);
        assert!(!times[&id.to_string()].contains_key(&ip(1).to_string()));
    }

    #[test]
    fn legacy_and_future_metadata_does_not_become_fresh_on_restart() {
        let id = peer();
        let mut hints = vec![EndpointAddr::from_parts(id, [ip(1), ip(2)])];
        let mut times = HintTimestamps::from([(
            id.to_string(),
            BTreeMap::from([(ip(2).to_string(), NOW + 1)]),
        )]);
        prune(&mut hints, &mut times, NOW);
        assert!(hints.is_empty());
        assert!(times.is_empty());
    }

    #[test]
    fn bounds_keep_relay_and_both_ip_families() {
        let id = peer();
        let v6 = TransportAddr::Ip("[2001:db8::1]:41383".parse().unwrap());
        let mut hints = vec![];
        let mut times = HintTimestamps::new();
        remember(&mut hints, &mut times, id, [relay(), v6.clone()], NOW);
        for n in 0..30 {
            remember(&mut hints, &mut times, id, [ip(n)], NOW + 1 + n as u64);
        }
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].addrs.len(), MAX_ADDRS_PER_PEER);
        assert!(hints[0].addrs.contains(&relay()));
        assert!(hints[0].addrs.contains(&v6));
        assert!(hints[0].addrs.contains(&ip(29)));
        assert!(!hints[0].addrs.contains(&ip(0)));
        assert_eq!(times[&id.to_string()].len(), MAX_ADDRS_PER_PEER);
    }

    #[test]
    fn peer_lru_is_bounded_and_ignores_unreferenced_metadata() {
        let oldest = peer();
        let mut hints = vec![];
        let mut times = HintTimestamps::new();
        remember(&mut hints, &mut times, oldest, [ip(0)], NOW);
        for n in 1..=MAX_PEERS {
            remember(&mut hints, &mut times, peer(), [ip(n)], NOW + n as u64);
        }
        times.insert(
            "unreferenced".into(),
            BTreeMap::from([("fake".into(), NOW)]),
        );
        prune(&mut hints, &mut times, NOW + 100);
        assert_eq!(hints.len(), MAX_PEERS);
        assert_eq!(times.len(), MAX_PEERS);
        assert!(!hints.iter().any(|hint| hint.id == oldest));
        assert!(!times.contains_key("unreferenced"));
    }

    #[test]
    fn a_full_cache_keeps_new_observations_in_the_same_timestamp_second() {
        let id = peer();
        let mut hints = vec![];
        let mut times = HintTimestamps::new();
        for n in 0..30 {
            remember(&mut hints, &mut times, id, [ip(n)], NOW);
            assert!(
                hints[0].addrs.contains(&ip(n)),
                "just observed path lost at {n}"
            );
        }
        for _ in 0..MAX_PEERS + 5 {
            let id = peer();
            remember(&mut hints, &mut times, id, [ip(0)], NOW);
            assert!(
                hints.iter().any(|hint| hint.id == id),
                "just observed peer evicted"
            );
        }
        assert_eq!(hints.len(), MAX_PEERS);
    }

    #[test]
    fn in_memory_lookup_enforces_expiry_without_a_restart() {
        let id = peer();
        let lookup = WarmLookup::new();
        lookup.add_endpoint_info(EndpointAddr::from_parts(id, [ip(1)]));
        assert!(lookup.resolve(id).is_some());
        {
            let mut state = lookup.state.write().unwrap();
            state
                .timestamps
                .get_mut(&id.to_string())
                .unwrap()
                .insert(ip(1).to_string(), now_secs() - MAX_AGE_SECS);
        }
        assert!(lookup.resolve(id).is_none());
        assert!(lookup.get_endpoint_info(id).is_none());
    }

    #[test]
    fn lookups_report_observation_time_and_do_not_refresh_it() {
        let id = peer();
        let at = now_secs() - 60;
        let mut cfg = AppConfig::default();
        remember(
            &mut cfg.endpoint_hints,
            &mut cfg.endpoint_hint_timestamps,
            id,
            [relay()],
            at,
        );
        let lookup = WarmLookup::from_config(&cfg);
        for _ in 0..2 {
            let item = futures::executor::block_on(lookup.resolve(id).unwrap().next())
                .unwrap()
                .unwrap();
            assert_eq!(item.last_updated(), Some(at * 1_000_000));
            assert!(lookup.get_endpoint_info(id).is_some());
        }
        lookup.copy_to(&mut cfg);
        assert_eq!(
            cfg.endpoint_hint_timestamps[&id.to_string()][&relay().to_string()],
            at
        );
    }

    #[test]
    fn warm_lookup_bounds_memory_and_roundtrips_without_reaging() {
        let lookup = WarmLookup::new();
        for _ in 0..MAX_PEERS + 5 {
            lookup.add_endpoint_info(EndpointAddr::from_parts(peer(), (0..20).map(ip)));
        }
        let mut cfg = AppConfig::default();
        lookup.copy_to(&mut cfg);
        assert_eq!(cfg.endpoint_hints.len(), MAX_PEERS);
        assert!(
            cfg.endpoint_hints
                .iter()
                .all(|hint| hint.addrs.len() == MAX_ADDRS_PER_PEER)
        );
        let before = cfg.endpoint_hint_timestamps.clone();
        WarmLookup::from_config(&cfg).copy_to(&mut cfg);
        assert_eq!(cfg.endpoint_hint_timestamps, before);
    }

    #[test]
    fn resetting_a_peer_updates_disk_and_memory_and_preserves_other_settings() {
        // The override belongs to this short-lived thread, not the process or
        // a reusable test-runtime worker. No system configuration is touched.
        std::thread::spawn(|| {
            let dir = tempfile::tempdir().unwrap();
            crate::config::set_thread_config_dir(dir.path().to_owned());
            let first = peer();
            let second = peer();
            crate::config::update_settings(|cfg| {
                cfg.mdns_enabled = false;
                cfg.relay = crate::config::ServerOverride {
                    servers: vec!["https://relay.example/".into()],
                    replace: true,
                };
                Ok(())
            })
            .unwrap();
            let lookup = WarmLookup::new();
            lookup
                .remember_verified(EndpointAddr::from_parts(first, [ip(1), relay()]))
                .unwrap();
            lookup
                .remember_verified(EndpointAddr::from_parts(second, [ip(2)]))
                .unwrap();
            let before = crate::config::load().unwrap();
            assert!(
                lookup
                    .clear_config(&format!("{first},invalid-id"), false)
                    .is_err()
            );
            assert!(lookup.get_endpoint_info(first).is_some());
            assert_eq!(
                crate::config::load().unwrap().endpoint_hints,
                before.endpoint_hints
            );

            let cfg = lookup.clear_config(&first.to_string(), false).unwrap();
            assert!(lookup.get_endpoint_info(first).is_none());
            assert!(lookup.get_endpoint_info(second).is_some());
            assert!(!cfg.mdns_enabled);
            assert_eq!(cfg.relay, before.relay);
            assert_eq!(cfg.endpoint_hints.len(), 1);
            assert_eq!(cfg.endpoint_hints[0].id, second);
            assert!(
                !cfg.endpoint_hint_timestamps
                    .contains_key(&first.to_string())
            );
            let reloaded = WarmLookup::from_config(&crate::config::load().unwrap());
            assert!(reloaded.resolve(first).is_none());
            assert!(reloaded.resolve(second).is_some());

            lookup.clear_config("", false).unwrap();
            let cfg = crate::config::load().unwrap();
            assert!(cfg.endpoint_hints.is_empty());
            assert!(cfg.endpoint_hint_timestamps.is_empty());
            assert!(lookup.resolve(second).is_none());
            // A later real observation may repopulate a reset cache.
            lookup
                .remember_verified(EndpointAddr::from_parts(first, [ip(3)]))
                .unwrap();
            assert!(lookup.resolve(first).is_some());
            assert!(lookup.resolve(second).is_none());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_failed_reset_does_not_clear_the_live_lookup() {
        std::thread::spawn(|| {
            let dir = tempfile::tempdir().unwrap();
            crate::config::set_thread_config_dir(dir.path().to_owned());
            let id = peer();
            let lookup = WarmLookup::new();
            lookup
                .remember_verified(EndpointAddr::from_parts(id, [relay()]))
                .unwrap();
            let path = dir.path().join("settings.toml");
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            assert!(lookup.clear_config("", false).is_err());
            assert!(lookup.resolve(id).is_some());
        })
        .join()
        .unwrap();
    }
}
