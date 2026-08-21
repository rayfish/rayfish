//! CLI file-sharing handlers: send / list / accept.

use crate::*;
use ipc::{GlobalKey, NetworkKey, NodeKey};

/// `ray send <peer> <files...>`: one `SendFileFd` request per file. Each file
/// gets its own IPC connection (the protocol is one request per connection);
/// a failure on one file still sends the rest.
pub(crate) async fn ipc_send_files(files: &[String], peer: &str) -> Result<()> {
    let mut failed = false;
    for file in files {
        if let Err(e) = ipc_send_file(file, peer).await {
            print_error("error", &format!("{file}: {e:#}"), None);
            failed = true;
        }
    }
    if failed {
        anyhow::bail!("some files were not sent");
    }
    Ok(())
}

async fn ipc_send_file(file: &str, peer: &str) -> Result<()> {
    use std::fs::File;
    use std::os::fd::AsFd;

    let path = std::path::absolute(file).with_context(|| format!("cannot resolve '{file}'"))?;
    // Open here, in the caller's privilege domain, and pass the descriptor:
    // the daemon never touches the path, so files the daemon can't read (TCC
    // folders on macOS, user-only files) work as long as *we* can open them.
    let opened = File::open(&path).with_context(|| format!("cannot read '{}'", path.display()))?;
    if !opened.metadata()?.is_file() {
        anyhow::bail!("cannot send '{}': not a regular file", path.display());
    }
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());

    let mut stream = ipc::connect().await?;
    ipc::send_with_fd(
        stream.get_ref(),
        &ipc::IpcMessage::SendFileFd {
            filename,
            peer: peer.to_string(),
        },
        opened.as_fd(),
    )
    .await?;
    let resp = match ipc::recv(&mut stream).await {
        Ok(resp) => resp,
        // A daemon predating `SendFileFd` fails to decode the request and
        // drops the connection without a reply (never with an `Error`
        // response). Retry once the old way, path over IPC, so an updated CLI
        // keeps working until the daemon restarts onto the new binary.
        Err(_) => {
            let mut stream = ipc::connect().await?;
            ipc::send(
                &mut stream,
                ipc::IpcMessage::SendFile {
                    path: path.to_string_lossy().to_string(),
                    peer: peer.to_string(),
                },
            )
            .await?;
            ipc::recv(&mut stream).await?
        }
    };
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        // Returned, not exited: [`ipc_send_files`] calls this once per file and
        // is written to keep going, so ending the process here would drop every
        // file after the first rejected one. The caller prints this with the
        // file's name and still exits non-zero at the end.
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        // Returned, not exited, for the same reason as the arm above.
        other => anyhow::bail!(unexpected_detail(&other)),
    }
    Ok(())
}

/// Read one global settings key from the daemon. Returns the rendered value; a
/// daemon-side error ends the command.
async fn config_row(key: NodeKey) -> Result<Option<String>> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::ConfigGet { key: Some(key) }).await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::ConfigValues { rows } => Ok(Some(
            rows.into_iter().next().map(|(_, v)| v).unwrap_or_default(),
        )),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
}

pub(crate) async fn ipc_files(action: Option<FilesAction>) -> Result<()> {
    // These subcommands change (or read) global settings the daemon owns. They
    // route through the daemon so the write lands in the config dir the daemon
    // reads (see the config-writing commands note in main.rs / rayfish#94).
    match &action {
        Some(FilesAction::DownloadDir { path, clear }) => {
            if *clear {
                return crate::ipc_mutate(ipc::IpcMessage::ConfigUnset {
                    key: NodeKey::Global(GlobalKey::DownloadDir),
                })
                .await;
            } else if let Some(p) = path {
                // The registry enforces this too, so it binds every writer and
                // not just this arm. Kept here as well because the daemon's
                // error surfaces through `print_error`, which prints a different
                // prefix than the bail this command has always produced.
                if !std::path::Path::new(p).is_absolute() {
                    anyhow::bail!("download-dir must be an absolute path: {p}");
                }
                return crate::ipc_mutate(ipc::IpcMessage::ConfigSet {
                    key: NodeKey::Global(GlobalKey::DownloadDir),
                    value: p.clone(),
                    replace: false,
                })
                .await;
            }
            if let Some(dir) = config_row(NodeKey::Global(GlobalKey::DownloadDir)).await? {
                println!(
                    "download-dir = {}",
                    if dir.is_empty() { "<unset>" } else { &dir }
                );
            }
            return Ok(());
        }
        Some(FilesAction::DownloadUser { user, clear }) => {
            if *clear {
                return crate::ipc_mutate(ipc::IpcMessage::ConfigUnset {
                    key: NodeKey::Global(GlobalKey::DownloadUser),
                })
                .await;
            } else if let Some(u) = user {
                // Resolve the username here: the daemon's key takes a numeric uid
                // only, so it never has to read the local passwd database.
                let uid = crate::uid_for_user(u).ok_or_else(|| {
                    anyhow::anyhow!("unknown user '{u}' (pass a valid username or uid)")
                })?;
                return crate::ipc_mutate(ipc::IpcMessage::ConfigSet {
                    key: NodeKey::Global(GlobalKey::DownloadUser),
                    value: uid.to_string(),
                    replace: false,
                })
                .await;
            }
            if let Some(uid) = config_row(NodeKey::Global(GlobalKey::DownloadUser)).await? {
                if uid.is_empty() {
                    println!("download-user = <unset>");
                } else {
                    println!("download-user = uid {uid}");
                }
            }
            return Ok(());
        }
        _ => {}
    }

    let mut stream = ipc::connect().await?;
    match action {
        None => {
            ipc::send(&mut stream, ipc::IpcMessage::ListFiles).await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::FileList { files, outbox } => {
                    if json_enabled() {
                        let inbound: Vec<_> = files
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "id": f.id, "from": f.from, "filename": f.filename,
                                    "size": f.size, "mime_type": f.mime_type,
                                })
                            })
                            .collect();
                        let queued: Vec<_> = outbox
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "id": f.id, "to": f.peer, "filename": f.filename,
                                    "size": f.size,
                                })
                            })
                            .collect();
                        print_json(&serde_json::json!({"pending": inbound, "queued": queued}));
                    } else if files.is_empty() && outbox.is_empty() {
                        println!("\n  {}\n", style::faint("no pending file transfers"));
                    } else {
                        if !files.is_empty() {
                            let rows = files
                                .iter()
                                .map(|f| {
                                    let accept = format!("ray files accept {}", f.id);
                                    vec![
                                        layout::Cell::new(
                                            f.id.to_string(),
                                            style::rose(&f.id.to_string()),
                                        ),
                                        layout::Cell::new(f.from.clone(), style::value(&f.from)),
                                        layout::Cell::right(
                                            format_size(f.size),
                                            style::faint(&format_size(f.size)),
                                        ),
                                        layout::Cell::new(
                                            f.filename.clone(),
                                            style::value(&f.filename),
                                        ),
                                        layout::Cell::new(accept.clone(), style::faint(&accept)),
                                    ]
                                })
                                .collect();
                            println!();
                            print!("{}", table(&["id", "from", "size", "file", ""], rows, 2));
                        }
                        if !outbox.is_empty() {
                            let rows = outbox
                                .iter()
                                .map(|f| {
                                    let cancel = format!("ray files cancel {}", f.id);
                                    vec![
                                        layout::Cell::new(
                                            f.id.to_string(),
                                            style::rose(&f.id.to_string()),
                                        ),
                                        layout::Cell::new(f.peer.clone(), style::value(&f.peer)),
                                        layout::Cell::right(
                                            format_size(f.size),
                                            style::faint(&format_size(f.size)),
                                        ),
                                        layout::Cell::new(
                                            f.filename.clone(),
                                            style::value(&f.filename),
                                        ),
                                        layout::Cell::new(cancel.clone(), style::faint(&cancel)),
                                    ]
                                })
                                .collect();
                            println!();
                            println!(
                                "  {}",
                                style::faint("queued sends (deliver when the peer comes online)")
                            );
                            print!("{}", table(&["id", "to", "size", "file", ""], rows, 2));
                        }
                        println!();
                    }
                }
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::Accept { id, output }) => {
            let output = output.or_else(|| {
                dirs::download_dir()
                    .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
                    .map(|p| p.to_string_lossy().to_string())
            });
            ipc::send(&mut stream, ipc::IpcMessage::AcceptFile { id, output }).await?;
            // The blob is fetched daemon-side without progress events, so show an
            // indeterminate spinner rather than a determinate bar.
            let spinner = progress::spinner("downloading…");
            let resp = ipc::recv(&mut stream).await?;
            spinner.finish_and_clear();
            match resp {
                ipc::IpcMessage::Ok { message } => {
                    println!("  {} {}", style::check(), style::value(&message));
                }
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::Cancel { id }) => {
            ipc::send(&mut stream, ipc::IpcMessage::CancelSend { id }).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => {
                    println!("  {} {}", style::check(), style::value(&message));
                }
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::AutoAccept { network, state }) => {
            parse_on_off(&state)?;
            ipc::send(
                &mut stream,
                ipc::IpcMessage::NetConfigSet {
                    network,
                    key: NetworkKey::AutoAcceptFiles,
                    value: state,
                },
            )
            .await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::Ok { message } => {
                    println!("  {} {}", style::check(), style::value(&message));
                }
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        // Config-only subcommands are handled above and return early.
        Some(FilesAction::DownloadDir { .. }) | Some(FilesAction::DownloadUser { .. }) => {
            unreachable!("download-dir/download-user handled before daemon connect")
        }
    }
    Ok(())
}

pub(crate) fn format_size(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}

// ---------------------------------------------------------------------------
// Device pairing
// ---------------------------------------------------------------------------
