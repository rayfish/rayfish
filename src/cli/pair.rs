//! CLI device-pairing handlers: pair, accept, backup/restore.

use crate::*;

pub(crate) async fn cmd_pair(action: Option<PairAction>, ticket: Option<String>) -> Result<()> {
    match (action, ticket) {
        // `rayfish pair <ticket>` shorthand
        (None, Some(ticket)) | (Some(PairAction::Accept { ticket }), _) => {
            ipc_pair_accept(&ticket).await
        }
        // `rayfish pair` — start pairing on primary device
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
            println!("Waiting for device to connect...");
            // The daemon handles the pairing asynchronously via the accept loop.
            // We could poll for completion, but the daemon logs when it happens.
            // For now, just tell the user it's ready.
        }
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

/// Produce the encrypted `enc1…` backup blob for the local identity, prompting
/// for (and confirming) a backup password. Returns the blob and the identity's
/// public key string.
pub(crate) fn make_backup_blob() -> Result<(String, String)> {
    use argon2::Argon2;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

    let key = identity::load_or_create()?;
    let password = rpassword::prompt_password("Enter backup password: ")?;
    if password.is_empty() {
        anyhow::bail!("password cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("passwords do not match");
    }

    let salt: [u8; 16] = rand::random();
    let mut derived_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;

    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let nonce_bytes: [u8; 24] = rand::random();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, key.to_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    // Format: "enc1" (4) || salt (16) || nonce (24) || ciphertext (32 + 16 tag)
    let mut backup_bytes = Vec::with_capacity(4 + 16 + 24 + ciphertext.len());
    backup_bytes.extend_from_slice(b"enc1");
    backup_bytes.extend_from_slice(&salt);
    backup_bytes.extend_from_slice(&nonce_bytes);
    backup_bytes.extend_from_slice(&ciphertext);

    let backup = bs58::encode(&backup_bytes).into_string();
    Ok((backup, key.public().to_string()))
}

pub(crate) fn cmd_pair_backup(onepassword: bool, vault: Option<&str>, item: &str) -> Result<()> {
    // Fail fast if `op` is missing before prompting for a password.
    if onepassword {
        onepassword::op_available()?;
    }

    let (backup, public_key) = make_backup_blob()?;

    if onepassword {
        onepassword::store(vault, item, &backup, &public_key)?;
        println!("Stored encrypted backup in 1Password item \"{}\".", item);
        println!();
        println!("To restore on a new device:");
        println!("  rayfish pair restore --1password");
        return Ok(());
    }

    println!("Backup code: {}", backup);
    println!();
    println!("Store this safely. To restore on a new device:");
    println!("  rayfish pair restore {}", backup);
    Ok(())
}

pub(crate) fn cmd_pair_restore(
    backup: Option<&str>,
    onepassword: bool,
    vault: Option<&str>,
    item: &str,
) -> Result<()> {
    use argon2::Argon2;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

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

    let backup_bytes = bs58::decode(&backup)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid backup code: {e}"))?;
    if backup_bytes.len() < 4 + 16 + 24 + 32 {
        anyhow::bail!("invalid backup code: too short");
    }
    if &backup_bytes[..4] != b"enc1" {
        anyhow::bail!("invalid backup code: unknown format");
    }
    let salt = &backup_bytes[4..20];
    let nonce_bytes = &backup_bytes[20..44];
    let ciphertext = &backup_bytes[44..];

    let password = rpassword::prompt_password("Enter backup password: ")?;
    let mut derived_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;

    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed: wrong password or corrupted backup"))?;

    let key_bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid key data"))?;
    let key = iroh::SecretKey::from_bytes(&key_bytes);

    // Check if a key already exists
    let existing = identity::load_or_create()?;
    if existing.public() == key.public() {
        println!("This device already has this identity.");
        return Ok(());
    }

    // Write the restored key into the shared config tree (Linux: /etc/rayfish,
    // root-owned — this command may need sudo there).
    let key_path = config::config_dir()?.join("secret_key");
    config::write_file(&key_path, &key.to_bytes(), true)?;

    println!("Restored user identity: {}", key.public());
    println!("Restart the daemon for changes to take effect.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Service install/uninstall
// ---------------------------------------------------------------------------
