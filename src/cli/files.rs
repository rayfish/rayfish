//! CLI file-sharing handlers: send / list / accept.

use crate::*;

pub(crate) async fn ipc_send_file(file: &str, peer: &str) -> Result<()> {
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::SendFile {
            path: file.to_string(),
            peer: peer.to_string(),
        },
    )
    .await?;
    let resp = ipc::recv(&mut stream).await?;
    match resp {
        ipc::IpcMessage::Ok { message } => println!("{}", message),
        ipc::IpcMessage::Error { message } => print_error("error", &message, None),
        other => eprintln!("Unexpected response: {:?}", other),
    }
    Ok(())
}

pub(crate) async fn ipc_files(action: Option<FilesAction>) -> Result<()> {
    let mut stream = ipc::connect().await?;
    match action {
        None => {
            ipc::send(&mut stream, ipc::IpcMessage::ListFiles).await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::FileList { files } => {
                    if json_enabled() {
                        let arr: Vec<_> = files
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "id": f.id, "from": f.from, "filename": f.filename,
                                    "size": f.size, "mime_type": f.mime_type,
                                })
                            })
                            .collect();
                        print_json(&serde_json::json!(arr));
                    } else if files.is_empty() {
                        println!("\n  {}\n", style::faint("no pending file transfers"));
                    } else {
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
        Some(FilesAction::AutoAccept { network, state }) => {
            let enabled = match state.to_ascii_lowercase().as_str() {
                "on" | "true" | "yes" => true,
                "off" | "false" | "no" => false,
                other => anyhow::bail!("expected `on` or `off`, got '{other}'"),
            };
            ipc::send(&mut stream, ipc::IpcMessage::FilesAutoAccept { network, enabled }).await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::Ok { message } => {
                    println!("  {} {}", style::check(), style::value(&message));
                }
                ipc::IpcMessage::Error { message } => print_error("error", &message, None),
                other => eprintln!("Unexpected response: {:?}", other),
            }
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

