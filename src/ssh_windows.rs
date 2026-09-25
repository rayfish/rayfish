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

use crate::daemon::NetworkRegistry;

pub(crate) use crate::forward::SSH_LISTEN_PORT;

pub type SshAuthz = Arc<ArcSwap<HashMap<String, Vec<crate::config::SshRule>>>>;

pub fn new_authz() -> SshAuthz {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

pub struct SshServer {
    _registry: Arc<NetworkRegistry>,
    _authz: SshAuthz,
}

impl SshServer {
    pub(crate) fn new(registry: Arc<NetworkRegistry>, authz: SshAuthz) -> Self {
        Self {
            _registry: registry,
            _authz: authz,
        }
    }

    pub fn spawn(self, _addrs: Vec<IpAddr>, _token: CancellationToken) {
        tracing::warn!("embedded SSH/PTY is not supported on Windows yet");
    }
}
