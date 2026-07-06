//! Thin wrapper over the 1Password CLI (`op`) for storing/reading the encrypted
//! identity backup blob produced by `ray pair backup`.
//!
//! The blob stored here is the same `enc1…` base58 string the bare backup
//! prints: the secret key encrypted with Argon2 + XChaCha20Poly1305 under a
//! user-chosen password. 1Password is only a transport: a 1Password
//! compromise alone still can't unlock the key without the backup password.
//!
//! All calls shell out to `op` synchronously (matching the codebase's
//! `std::process::Command` pattern) and run CLI-side in the user's context,
//! never from the root daemon. The secret blob is passed via stdin (an item
//! template), never on the argv, so it doesn't leak into `ps`.

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::process::{Command, Stdio};

/// Field label/id under which the backup blob is stored (the item's canonical
/// password field).
const FIELD: &str = "password";

/// Verify the `op` CLI is available, returning a friendly error otherwise.
pub fn op_available() -> Result<()> {
    let status = Command::new("op")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => bail!(
            "1Password CLI `op` not found or not working. Install it from \
             https://developer.1password.com/docs/cli/ and run `op signin` first."
        ),
    }
}

/// Run `op item <args>`, feeding `stdin_body` (if any) to stdin, returning stdout.
fn run_op(args: &[&str], stdin_body: Option<&str>) -> Result<std::process::Output> {
    let mut cmd = Command::new("op");
    cmd.args(args)
        .stdin(if stdin_body.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("failed to spawn `op`")?;
    if let Some(body) = stdin_body {
        child
            .stdin
            .take()
            .context("failed to open `op` stdin")?
            .write_all(body.as_bytes())
            .context("failed to write to `op` stdin")?;
    }
    child.wait_with_output().context("failed to run `op`")
}

/// Create-or-update a 1Password item holding the backup blob.
///
/// Tries `op item edit` first; if the item doesn't exist yet, falls back to
/// `op item create`. The blob is passed via stdin as a JSON template so it
/// never appears in the process argument list.
pub fn store(vault: Option<&str>, title: &str, blob: &str, public_key: &str) -> Result<()> {
    // Try to edit an existing item first (idempotent re-runs update in place).
    let mut edit_args = vec!["item", "edit", title];
    if let Some(v) = vault {
        edit_args.push("--vault");
        edit_args.push(v);
    }
    let assignment = format!("{FIELD}={blob}");
    edit_args.push(&assignment);
    edit_args.push("--format");
    edit_args.push("json");

    let edit = run_op(&edit_args, None)?;
    if edit.status.success() {
        return Ok(());
    }

    // Item likely doesn't exist, create it from a JSON template via stdin so
    // the secret is not exposed on argv.
    let template = serde_json::json!({
        "title": title,
        "category": "PASSWORD",
        "fields": [
            { "id": "password", "label": "password", "type": "CONCEALED",
              "purpose": "PASSWORD", "value": blob },
            { "label": "public_key", "type": "STRING", "value": public_key },
            { "id": "notesPlain", "label": "notesPlain", "type": "STRING", "purpose": "NOTES",
              "value": "Rayfish encrypted identity backup. Restore with `ray pair restore --1password`." }
        ]
    })
    .to_string();

    let mut create_args = vec!["item", "create", "--format", "json"];
    if let Some(v) = vault {
        create_args.push("--vault");
        create_args.push(v);
    }
    create_args.push("-");

    let create = run_op(&create_args, Some(&template))?;
    if !create.status.success() {
        let edit_err = String::from_utf8_lossy(&edit.stderr);
        let create_err = String::from_utf8_lossy(&create.stderr);
        bail!(
            "failed to store backup in 1Password.\n  edit: {}\n  create: {}",
            edit_err.trim(),
            create_err.trim()
        );
    }
    Ok(())
}

/// Read the backup blob back from a 1Password item.
pub fn read(vault: Option<&str>, title: &str) -> Result<String> {
    let fields = format!("label={FIELD}");
    let mut args = vec!["item", "get", title];
    if let Some(v) = vault {
        args.push("--vault");
        args.push(v);
    }
    args.push("--fields");
    args.push(&fields);
    args.push("--reveal");
    args.push("--format");
    args.push("json");

    let out = run_op(&args, None)?;
    if !out.status.success() {
        bail!(
            "failed to read backup from 1Password: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // `op item get --fields label=credential --format json` returns either a
    // single field object or an array of them, each with a `value` key.
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("failed to parse `op` output")?;
    let value = match &json {
        serde_json::Value::Array(arr) => arr
            .iter()
            .find_map(|f| f.get("value").and_then(|v| v.as_str())),
        other => other.get("value").and_then(|v| v.as_str()),
    };
    let blob = value
        .context("1Password item has no `credential` field")?
        .trim()
        .to_string();
    if blob.is_empty() {
        bail!("1Password item `credential` field is empty");
    }
    Ok(blob)
}
