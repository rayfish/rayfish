//! Windows v1 SSH surface.
//!
//! The existing embedded shell depends on Unix account and PTY APIs. Keep the
//! public daemon seam available on Windows while returning an explicit
//! unsupported status instead of pulling Unix-only crates into the MSVC build.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_util::sync::CancellationToken;

use crate::peers::{DeviceUserMap, PeerTable};

pub(crate) use crate::forward::SSH_LISTEN_PORT;

pub type SshAuthz = Arc<ArcSwap<HashMap<String, Vec<crate::config::SshRule>>>>;

pub fn new_authz() -> SshAuthz {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

pub struct SshServer {
    _peers: PeerTable,
    _device_user_map: DeviceUserMap,
    _authz: SshAuthz,
}

impl SshServer {
    pub fn new(peers: PeerTable, device_user_map: DeviceUserMap, authz: SshAuthz) -> Self {
        Self {
            _peers: peers,
            _device_user_map: device_user_map,
            _authz: authz,
        }
    }

    pub fn spawn(self, _addrs: Vec<IpAddr>, _token: CancellationToken) {
        tracing::warn!("embedded SSH/PTY is not supported on Windows yet");
    }
}
