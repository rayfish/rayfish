//! Thin wrapper over the 1Password CLI (`op`) for storing/reading an identity
//! backup in a Secure Note.
//!
//! 1Password's encrypted vault is the protection for this copy. The printed
//! backup format remains separately password-encrypted.
//!
//! All calls shell out to `op` synchronously (matching the codebase's
//! `std::process::Command` pattern) and run CLI-side in the user's context,
//! never from the root daemon. The secret blob is passed via stdin in an item
//! template, never on the argv, so it doesn't leak into `ps`.

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::process::{Command, Stdio};

/// Field label/id under which the backup blob is stored.
const FIELD: &str = "backup";
const LEGACY_FIELD: &str = "password";

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
/// The update first reads the item as JSON, changes the two fields we own, and
/// writes the full template back through stdin. `op` documents assignment
/// statements as visible to other processes, so do not replace this with
/// `password=<blob>` on the command line.
pub fn store(vault: Option<&str>, title: &str, blob: &str, public_key: &str) -> Result<()> {
    let mut get_args = vec!["item", "get", title, "--format", "json"];
    if let Some(v) = vault {
        get_args.push("--vault");
        get_args.push(v);
    }
    let get = run_op(&get_args, None)?;
    if get.status.success() {
        let mut template: serde_json::Value = serde_json::from_slice(&get.stdout)
            .context("failed to parse existing 1Password item")?;
        update_template(&mut template, blob, public_key)?;
        let template =
            serde_json::to_string(&template).context("failed to encode 1Password item")?;

        let mut edit_args = vec!["item", "edit", title, "--format", "json"];
        if let Some(v) = vault {
            edit_args.push("--vault");
            edit_args.push(v);
        }
        let edit = run_op(&edit_args, Some(&template))?;
        if edit.status.success() {
            return Ok(());
        }
        bail!(
            "failed to update backup in 1Password: {}",
            String::from_utf8_lossy(&edit.stderr).trim()
        );
    }

    // Item likely doesn't exist, create it from a JSON template via stdin.
    let template = serde_json::json!({
        "title": title,
        "category": "SECURE_NOTE",
        "fields": [
            { "id": "backup", "label": "backup", "type": "CONCEALED", "value": blob },
            { "label": "public_key", "type": "STRING", "value": public_key },
            { "id": "notesPlain", "label": "notesPlain", "type": "STRING", "purpose": "NOTES",
              "value": "Rayfish identity backup. Restore with `ray pair restore --1p`." }
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
        let create_err = String::from_utf8_lossy(&create.stderr);
        bail!("failed to store backup in 1Password: {}", create_err.trim());
    }
    Ok(())
}

fn update_template(template: &mut serde_json::Value, blob: &str, public_key: &str) -> Result<()> {
    let fields = template
        .get_mut("fields")
        .and_then(serde_json::Value::as_array_mut)
        .context("existing 1Password item has no fields")?;
    update_field(fields, FIELD, blob, "CONCEALED", None);
    update_field(fields, "public_key", public_key, "STRING", None);
    Ok(())
}

fn update_field(
    fields: &mut Vec<serde_json::Value>,
    label: &str,
    value: &str,
    field_type: &str,
    purpose: Option<&str>,
) {
    if let Some(field) = fields.iter_mut().find(|field| {
        field.get("id").and_then(serde_json::Value::as_str) == Some(label)
            || field.get("label").and_then(serde_json::Value::as_str) == Some(label)
    }) {
        field["value"] = serde_json::Value::String(value.to_string());
        return;
    }

    let mut field = serde_json::json!({
        "label": label,
        "type": field_type,
        "value": value,
    });
    if let Some(purpose) = purpose {
        field["id"] = serde_json::Value::String(label.to_string());
        field["purpose"] = serde_json::Value::String(purpose.to_string());
    }
    fields.push(field);
}

/// Read the backup blob back from a 1Password item.
pub fn read(vault: Option<&str>, title: &str) -> Result<String> {
    let fields = format!("label={FIELD},label={LEGACY_FIELD}");
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

    // `op item get --fields label=backup --format json` returns either a
    // single field object or an array of them, each with a `value` key.
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("failed to parse `op` output")?;
    let value = match &json {
        serde_json::Value::Array(arr) => arr
            .iter()
            .find(|field| field.get("label").and_then(serde_json::Value::as_str) == Some(FIELD))
            .or_else(|| {
                arr.iter().find(|field| {
                    field.get("label").and_then(serde_json::Value::as_str) == Some(LEGACY_FIELD)
                })
            })
            .and_then(|field| field.get("value").and_then(serde_json::Value::as_str)),
        other => other.get("value").and_then(|v| v.as_str()),
    };
    let blob = value
        .context("1Password item has no `backup` field")?
        .trim()
        .to_string();
    if blob.is_empty() {
        bail!("1Password item `backup` field is empty");
    }
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_template_replaces_our_fields_without_dropping_others() {
        let mut template = serde_json::json!({
            "title": "Rayfish Identity",
            "fields": [
                { "id": "backup", "label": "backup", "value": "old" },
                { "label": "public_key", "value": "old-key" },
                { "label": "unrelated", "value": "keep" },
            ],
        });

        update_template(&mut template, "new-backup", "new-key").unwrap();

        let fields = template["fields"].as_array().unwrap();
        assert_eq!(fields[0]["value"], "new-backup");
        assert_eq!(fields[1]["value"], "new-key");
        assert_eq!(fields[2]["value"], "keep");
    }

    #[test]
    fn update_template_adds_missing_fields() {
        let mut template = serde_json::json!({ "fields": [] });

        update_template(&mut template, "backup", "key").unwrap();

        let fields = template["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0]["value"], "backup");
        assert_eq!(fields[1]["value"], "key");
    }
}
