//! CLI handler for `ray open <uri>`: dispatches a `rayfish://` deep link to
//! the same join/pair paths the plain `ray join`/`ray pair` subcommands use.

use crate::*;
use rayfish::deeplink::{RayfishLink, parse_rayfish_uri};

/// A link carries no flags, so it joins the way a bare `ray join <code>` does.
const JOIN_AUTO_ACCEPT_FIREWALL: bool = false;
const JOIN_AUTO_ACCEPT_FILES: bool = true;

pub(crate) async fn cmd_open(uri: &str) -> Result<()> {
    match parse_rayfish_uri(uri)? {
        RayfishLink::Join(code) => {
            ipc_join(
                &code,
                None,
                None,
                false,
                JOIN_AUTO_ACCEPT_FIREWALL,
                JOIN_AUTO_ACCEPT_FILES,
            )
            .await
        }
        RayfishLink::Pair(ticket) => ipc_pair_accept(&ticket).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_links_use_the_plain_join_defaults() {
        let cli = Cli::try_parse_from(["ray", "join", "code"]).unwrap();
        match cli.command {
            Command::Join {
                auto_accept_firewall,
                no_auto_accept_files,
                tor,
                ..
            } => {
                assert_eq!(auto_accept_firewall, JOIN_AUTO_ACCEPT_FIREWALL);
                assert_eq!(!no_auto_accept_files, JOIN_AUTO_ACCEPT_FILES);
                assert!(!tor);
            }
            _ => panic!("wrong command"),
        }
    }
}
