//! `ray block`, `ray unblock` and `ray blocked`: the connect-channel block
//! list, kept in the `blocked` setting so it rides the generic settings path.

use crate::*;
use ipc::GlobalKey;

#[derive(serde::Serialize)]
#[serde(transparent)]
struct BlockedOutput(Vec<String>);

impl DisplayOut for BlockedOutput {
    fn print_human(&self) {
        if self.0.is_empty() {
            println!("no blocked peers");
        }
        for peer in &self.0 {
            println!("{peer}");
        }
    }
}

/// Refuse a peer's connect requests and invitations.
pub(crate) async fn ipc_block(peer: &str) -> Result<()> {
    edit_peer_list(GlobalKey::Blocked, peer, false).await
}

/// Let a blocked peer reach this node again.
pub(crate) async fn ipc_unblock(peer: &str) -> Result<()> {
    edit_peer_list(GlobalKey::Blocked, peer, true).await
}

pub(crate) async fn ipc_blocked() -> Result<()> {
    printout(&BlockedOutput(peer_list(GlobalKey::Blocked).await?))
}
