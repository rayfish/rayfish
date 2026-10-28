//! How a network comes to be live and who owns what runs for it: pending-join
//! retries, the restore sweep racing a fresh join, warm resume, promotion.

use std::ffi::OsString;

use super::*;

/// Points the daemon's config directory at a fresh temporary one, holding the
/// process-wide config lock, until dropped.
struct ConfigDir {
    _lock: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    previous: Option<OsString>,
}

impl ConfigDir {
    fn new() -> Self {
        let lock = config::CONFIG_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("RAYFISH_CONFIG_DIR");
        unsafe { std::env::set_var("RAYFISH_CONFIG_DIR", dir.path()) };
        Self {
            _lock: lock,
            _dir: dir,
            previous,
        }
    }
}

impl Drop for ConfigDir {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var("RAYFISH_CONFIG_DIR", value),
                None => std::env::remove_var("RAYFISH_CONFIG_DIR"),
            }
        }
    }
}

fn empty_state(net_pubkey: EndpointId, name: &str) -> SharedNetworkState {
    let mut state = NetworkState {
        members: MemberList::new(),
        approved: ApprovedList::new(),
        snapshot: None,
        snapshot_commit: Arc::new(AsyncMutex::new(())),
        destroyed: false,
        converged_hash: None,
        unconfirmed_durable_hash: None,
        network_secret_key: None,
        network_public_key: net_pubkey,
        network_name: Some(name.to_string()),
        group_name: Some(name.to_string()),
        mode: GroupMode::Restricted,
        suggested_firewall: SuggestedFirewall::default(),
        reusable_keys: BTreeMap::new(),
        nullifiers: BTreeSet::new(),
        pending_suggestions: Vec::new(),
        pending: HashMap::new(),
        last_record_timestamp: None,
    };
    state.refresh_snapshot();
    Arc::new(std::sync::RwLock::new(state))
}

/// Install a live member handle for `name`, as a finished join leaves one.
fn hold_live(registry: &NetworkRegistry, name: &str, net_pubkey: EndpointId) -> CancellationToken {
    let cancel = CancellationToken::new();
    registry.networks.insert(
        name.to_string(),
        NetworkHandle {
            name: name.to_string(),
            network_key: net_pubkey,
            role: NetworkRole::Member,
            state: empty_state(net_pubkey, name),
            dht_notify: None,
            cancel: cancel.clone(),
            tasks: vec![],
            invite_lock: Arc::new(AsyncMutex::new(())),
            incompatible: None,
        },
    );
    cancel
}

/// A pending join for a network that is already live, under a local name that
/// is not its key, is stale. Startup used to look the key up in the
/// name-keyed map, miss, and queue a join that could only fail.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn startup_drops_a_pending_join_for_a_live_network() {
    let _config = ConfigDir::new();
    let daemon = build_headless(false).await.unwrap();
    let key = SecretKey::generate().public();
    config::add_pending_join(config::PendingJoinEntry {
        network_key: key.to_string(),
        name: Some("home".into()),
    })
    .unwrap();
    hold_live(&daemon.registry, "home", key);

    daemon.registry.connect_all_networks().await;

    assert!(config::load().unwrap().pending_joins.is_empty());
    daemon.shutdown_and_close().await;
}
