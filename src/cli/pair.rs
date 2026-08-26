//! CLI device-pairing handlers: pair, accept, backup/restore.

use crate::*;

pub(crate) async fn cmd_pair(action: Option<PairAction>, ticket: Option<String>) -> Result<()> {
    match (action, ticket) {
        // `rayfish pair <ticket>` shorthand
        (None, Some(ticket)) | (Some(PairAction::Accept { ticket }), _) => {
            ipc_pair_accept(&ticket).await
        }
        // `rayfish pair list`
        (Some(PairAction::List), _) => ipc_pair_list().await,
        // `rayfish pair`: start pairing on primary device
        (None, None) => ipc_pair_start().await,
        // `rayfish pair backup`
        (
            Some(PairAction::Backup {
                onepassword,
                vault,
                item,
            }),
            _,
        ) => cmd_pair_backup(onepassword, vault.as_deref(), &item),
        // `rayfish pair restore <backup>`
        (
            Some(PairAction::Restore {
                backup,
                onepassword,
                vault,
                item,
            }),
            _,
        ) => cmd_pair_restore(backup.as_deref(), onepassword, vault.as_deref(), &item),
    }
}

pub(crate) async fn ipc_pair_start() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::StartPairing).await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::PairingTicket { ticket } => {
            println!("Pairing ticket: {}", ticket);
            println!();
            qr2term::print_qr(&ticket).ok();
            println!();
            println!("On the other device, run:");
            println!("  rayfish pair {}", ticket);
            println!();
            println!("Waiting for device to connect (this ticket expires in 5 minutes)...");
            // The daemon handles the pairing asynchronously via the accept loop.
            // We could poll for completion, but the daemon logs when it happens.
            // For now, just tell the user it's ready.
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_pair_accept(ticket: &str) -> Result<()> {
    let (endpoint_id, secret) = rayfish::control::decode_pairing_ticket(ticket)?;
    let secret = secret.to_vec();

    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::PairWithDevice {
            endpoint_id,
            secret,
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::PairingComplete { user_identity } => {
            println!("Paired successfully!");
            println!("  User identity: {}", user_identity);
            println!("  Device certificate stored.");
            println!();
            println!("This device will present its certificate when joining networks.");
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_pair_list() -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::ListPairedDevices).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::PairedDevices { devices } => {
            if json_enabled() {
                print_json(&serde_json::json!(
                    devices
                        .iter()
                        .map(|d| serde_json::json!({
                            "device_id": d.device_id.to_string(),
                            "short_id": d.short_id,
                            "hostname": d.hostname,
                            "networks": d.networks,
                        }))
                        .collect::<Vec<_>>()
                ));
            } else if devices.is_empty() {
                println!("\n  {}\n", style::faint("no paired devices"));
            } else {
                let rows = devices
                    .iter()
                    .map(|d| {
                        let host = d.hostname.clone().unwrap_or_else(|| "—".to_string());
                        let nets = if d.networks.is_empty() {
                            "—".to_string()
                        } else {
                            d.networks.join(", ")
                        };
                        vec![
                            layout::Cell::new(host.clone(), style::value(&host)),
                            layout::Cell::new(d.short_id.clone(), style::rose(&d.short_id)),
                            layout::Cell::new(nets.clone(), style::faint(&nets)),
                        ]
                    })
                    .collect();
                println!();
                print!("{}", table(&["device", "id", "networks"], rows, 2));
                println!(
                    "\n  {}",
                    style::faint("revoke one with: ray unpair <device>")
                );
            }
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_unpair(device: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::Unpair {
            device: device.to_string(),
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

/// Produce the encrypted `enc1…` backup blob for the local identity, prompting
/// for (and confirming) a backup password. The blob format lives in
/// [`keybackup`]; this only handles the terminal side of it.
pub(crate) fn make_backup_blob() -> Result<keybackup::Backup> {
    let password = rpassword::prompt_password("Enter backup password: ")?;
    if password.is_empty() {
        anyhow::bail!("password cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("passwords do not match");
    }
    keybackup::backup_current_identity(&password)
}

pub(crate) fn cmd_pair_backup(onepassword: bool, vault: Option<&str>, item: &str) -> Result<()> {
    // Fail fast if `op` is missing before prompting for a password.
    if onepassword {
        onepassword::op_available()?;
    }

    let keybackup::Backup { code, public_key } = make_backup_blob()?;

    if onepassword {
        onepassword::store(vault, item, &code, &public_key)?;
        println!("Stored encrypted backup in 1Password item \"{}\".", item);
        println!();
        println!("To restore on a new device:");
        println!("  rayfish pair restore --1password");
        return Ok(());
    }

    println!("Backup code: {}", code);
    println!();
    println!("Store this safely. To restore on a new device:");
    println!("  rayfish pair restore {}", code);
    Ok(())
}

pub(crate) fn cmd_pair_restore(
    backup: Option<&str>,
    onepassword: bool,
    vault: Option<&str>,
    item: &str,
) -> Result<()> {
    let backup = if onepassword {
        if backup.is_some() {
            anyhow::bail!("provide either a backup code or --1password, not both");
        }
        onepassword::op_available()?;
        onepassword::read(vault, item)?
    } else {
        backup
            .map(|b| b.to_string())
            .context("provide a backup code, or use --1password to read it from 1Password")?
    };

    let password = rpassword::prompt_password("Enter backup password: ")?;
    let key = keybackup::decrypt(&backup, &password)?;

    // Check if a key already exists
    let existing = identity::load_or_create()?;
    if existing.public() == key.public() {
        println!("This device already has this identity.");
        return Ok(());
    }

    // Writes into the shared config tree (Linux: /etc/rayfish, root-owned, so
    // this command may need sudo there).
    identity::store_secret_key(&key)?;

    println!("Restored user identity: {}", key.public());
    println!("Restart the daemon for changes to take effect.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Service install/uninstall
// ---------------------------------------------------------------------------
