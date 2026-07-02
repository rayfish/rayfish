//! `ray alias` handlers: bind/list/remove node-local, per-network aliases for a
//! user identity. Aliases are display-only (shown inline in `ray status`) and
//! seed `ray apply`'s `aliases:` map; they never reach the signed blob.

use crate::*;

pub(crate) async fn cmd_alias(network: &str, action: AliasAction, json: bool) -> Result<()> {
    match action {
        AliasAction::Set { key, alias } => alias_set(network, &key, &alias).await,
        AliasAction::List => alias_list(network, json).await,
        AliasAction::Remove { alias } => alias_remove(network, &alias).await,
    }
}

/// Bind `alias` to the identity named by `key`. `key` is either an identity
/// string (from `ray identityof`) or a currently-joined hostname resolved to its
/// identity locally.
async fn alias_set(network: &str, key: &str, alias: &str) -> Result<()> {
    if !hostname::is_valid_hostname(alias) {
        anyhow::bail!(
            "invalid alias '{alias}' (lowercase ASCII letters, digits, and '-', 1-63 chars)"
        );
    }

    // An identity string is used verbatim (canonicalized); anything else is
    // treated as a joined hostname and resolved against live status.
    let identity = match key.parse::<iroh::EndpointId>() {
        Ok(id) => id.to_string(),
        Err(_) => {
            let (self_id, networks) = ipc_status_full().await?;
            let net = networks
                .iter()
                .find(|n| n.name == network)
                .ok_or_else(|| anyhow::anyhow!("network '{network}' not found (is it active?)"))?;
            let (identity, _paired) =
                resolve_host_identity(net, &self_id, key).ok_or_else(|| {
                    anyhow::anyhow!(
                        "'{key}' is neither a valid identity nor a joined hostname on '{network}' \
                         (copy an identity from `ray identityof <net> <host>`)"
                    )
                })?;
            identity
        }
    };

    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::AliasSet {
            network: network.to_string(),
            identity,
            alias: alias.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn alias_remove(network: &str, alias: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::AliasRemove {
            network: network.to_string(),
            alias: alias.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

async fn alias_list(network: &str, json: bool) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::AliasList {
            network: network.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::AliasListResponse { aliases } => {
            if json {
                print_json(&serde_json::json!(aliases));
            } else if aliases.is_empty() {
                println!("\n  {}\n", style::faint("no aliases set"));
            } else {
                println!();
                let rows: Vec<Vec<layout::Cell>> = aliases
                    .iter()
                    .map(|(alias, identity)| {
                        vec![
                            layout::Cell::new(alias.clone(), style::value(alias)),
                            layout::Cell::new(identity.clone(), style::faint(identity)),
                        ]
                    })
                    .collect();
                print!("{}", indent(&layout::columns(&rows, 2), 2));
                println!();
            }
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}
