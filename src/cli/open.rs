//! CLI handler for `ray open <uri>`: dispatches a `rayfish://` deep link to
//! the same join/pair paths the plain `ray join`/`ray pair` subcommands use.

use crate::*;
use rayfish::deeplink::{RayfishLink, parse_rayfish_uri};

pub(crate) async fn cmd_open(uri: &str) -> Result<()> {
    match parse_rayfish_uri(uri)? {
        RayfishLink::Join(code) => ipc_join(&code, None, None, false, false, false).await,
        RayfishLink::Pair(ticket) => ipc_pair_accept(&ticket).await,
    }
}
