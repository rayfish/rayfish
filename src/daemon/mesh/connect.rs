//! Direct-connection (`ray connect`) handlers for `MeshManager`, plus the shared
//! `store_and_publish_group` helper. Split out of `daemon/mod.rs`.

use super::super::*;

impl MeshManager {
    /// `ray connect <contact-id>`: request a direct connection by contact id.
    pub(crate) async fn connect(&self, contact_id: &str, hostname: Option<String>) -> IpcMessage {
        self.connect.connect(contact_id, hostname).await
    }

    /// `ray connections`: list pending incoming connect requests.
    pub fn list_connections(&self) -> IpcMessage {
        self.connect.list_connections()
    }

    /// Decline a pending connect request: drop it without minting a network. The
    /// requester's retry loop eventually times out.
    pub fn reject_connect(&self, id_prefix: &str) -> IpcMessage {
        self.connect.reject_connect(id_prefix)
    }

    /// `ray connections approve <id>`: approve a pending connect request, minting
    /// a 2-peer network with the requester pre-approved.
    pub async fn approve_connection(&self, id_prefix: &str) -> IpcMessage {
        self.connect.approve_connection(id_prefix).await
    }

    /// `ray contact rotate`: replace this node's contact key. The old contact id
    /// stops resolving once its pkarr record expires (~5 min).
    pub(crate) async fn rotate_contact(&self) -> IpcMessage {
        self.connect.rotate_contact().await
    }

    // -----------------------------------------------------------------------
    // File sharing
    // -----------------------------------------------------------------------
}
