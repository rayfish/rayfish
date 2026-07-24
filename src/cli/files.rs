//! CLI file-sharing handlers: send / list / accept.

use crate::*;

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
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_files(action: Option<FilesAction>) -> Result<()> {
    // These subcommands change (or read) global settings the daemon owns. They
    // route through the daemon so the write lands in the config dir the daemon
    // reads (see the config-writing commands note in main.rs / rayfish#94).
    match &action {
        Some(FilesAction::DownloadDir { path, clear }) => {
            if *clear {
                return crate::ipc_mutate(ipc::IpcMessage::SetDownloadDir { path: None }).await;
            } else if let Some(p) = path {
                if !std::path::Path::new(p).is_absolute() {
                    anyhow::bail!("download-dir must be an absolute path: {p}");
                }
                return crate::ipc_mutate(ipc::IpcMessage::SetDownloadDir {
                    path: Some(p.clone()),
                })
                .await;
            }
            let mut stream = ipc::connect().await?;
            ipc::send(&mut stream, ipc::IpcMessage::GetDownloadSettings).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::DownloadSettings { dir, .. } => {
                    println!("download-dir = {}", dir.as_deref().unwrap_or("<unset>"));
                }
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {other:?}"),
            }
            return Ok(());
        }
        Some(FilesAction::DownloadUser { user, clear }) => {
            if *clear {
                return crate::ipc_mutate(ipc::IpcMessage::SetDownloadUser { uid: None }).await;
            } else if let Some(u) = user {
                let uid = crate::uid_for_user(u).ok_or_else(|| {
                    anyhow::anyhow!("unknown user '{u}' (pass a valid username or uid)")
                })?;
                return crate::ipc_mutate(ipc::IpcMessage::SetDownloadUser { uid: Some(uid) })
                    .await;
            }
            let mut stream = ipc::connect().await?;
            ipc::send(&mut stream, ipc::IpcMessage::GetDownloadSettings).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::DownloadSettings { uid, .. } => match uid {
                    Some(uid) => println!("download-user = uid {uid}"),
                    None => println!("download-user = <unset>"),
                },
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {other:?}"),
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
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {:?}", other),
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
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {:?}", other),
            }
        }
        Some(FilesAction::Cancel { id }) => {
            ipc::send(&mut stream, ipc::IpcMessage::CancelSend { id }).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => {
                    println!("  {} {}", style::check(), style::value(&message));
                }
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {:?}", other),
            }
        }
        Some(FilesAction::AutoAccept { network, state }) => {
            let enabled = match state.to_ascii_lowercase().as_str() {
                "on" | "true" | "yes" => true,
                "off" | "false" | "no" => false,
                other => anyhow::bail!("expected `on` or `off`, got '{other}'"),
            };
            ipc::send(
                &mut stream,
                ipc::IpcMessage::FilesAutoAccept { network, enabled },
            )
            .await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::Ok { message } => {
                    println!("  {} {}", style::check(), style::value(&message));
                }
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {:?}", other),
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
