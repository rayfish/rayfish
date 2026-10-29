//! CLI file-sharing handlers: send / list / accept.

use crate::*;
use ipc::{GlobalKey, NetworkKey, NodeKey};

#[derive(serde::Serialize)]
struct FilesOutput<'a> {
    pending: Vec<PendingFileRow<'a>>,
    queued: Vec<QueuedFileRow<'a>>,
    transfers: &'a [ipc::TransferFileInfo],
}

#[derive(serde::Serialize)]
struct PendingFileRow<'a> {
    id: u64,
    from: &'a str,
    filename: &'a str,
    size: u64,
    mime_type: &'a str,
}

#[derive(serde::Serialize)]
struct QueuedFileRow<'a> {
    id: u64,
    to: &'a str,
    filename: &'a str,
    size: u64,
}

impl<'a> FilesOutput<'a> {
    fn new(
        files: &'a [ipc::PendingFileInfo],
        outbox: &'a [ipc::OutboxFileInfo],
        transfers: &'a [ipc::TransferFileInfo],
    ) -> Self {
        Self {
            pending: files
                .iter()
                .map(|f| PendingFileRow {
                    id: f.id,
                    from: &f.from,
                    filename: &f.filename,
                    size: f.size,
                    mime_type: &f.mime_type,
                })
                .collect(),
            queued: outbox
                .iter()
                .map(|f| QueuedFileRow {
                    id: f.id,
                    to: &f.peer,
                    filename: &f.filename,
                    size: f.size,
                })
                .collect(),
            transfers,
        }
    }
}

impl DisplayOut for FilesOutput<'_> {
    fn print_human(&self) {
        if self.pending.is_empty() && self.queued.is_empty() && self.transfers.is_empty() {
            println!("\n  {}\n", style::faint("no pending file transfers"));
            return;
        }
        if !self.pending.is_empty() {
            let rows = self
                .pending
                .iter()
                .map(|f| {
                    let accept = format!("ray files accept {}", f.id);
                    vec![
                        layout::Cell::new(f.id.to_string(), style::rose(&f.id.to_string())),
                        layout::Cell::new(f.from.to_string(), style::value(f.from)),
                        layout::Cell::right(
                            format_size(f.size),
                            style::faint(&format_size(f.size)),
                        ),
                        layout::Cell::new(f.filename.to_string(), style::value(f.filename)),
                        layout::Cell::new(accept.clone(), style::faint(&accept)),
                    ]
                })
                .collect();
            println!();
            print!("{}", table(&["id", "from", "size", "file", ""], rows, 2));
        }
        if !self.queued.is_empty() {
            let rows = self
                .queued
                .iter()
                .map(|f| {
                    let cancel = format!("ray files cancel {}", f.id);
                    vec![
                        layout::Cell::new(f.id.to_string(), style::rose(&f.id.to_string())),
                        layout::Cell::new(f.to.to_string(), style::value(f.to)),
                        layout::Cell::right(
                            format_size(f.size),
                            style::faint(&format_size(f.size)),
                        ),
                        layout::Cell::new(f.filename.to_string(), style::value(f.filename)),
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
        if !self.transfers.is_empty() {
            println!();
            println!("  {}", style::faint("transfers"));
            print!("{}", transfers_table(self.transfers));
        }
        println!();
    }
}

/// Active transfers as a table: progress is `transferred / total` and the file
/// cell carries the transfer state.
fn transfers_table(transfers: &[ipc::TransferFileInfo]) -> String {
    let rows = transfers
        .iter()
        .map(|t| {
            let state = format!("{:?}", t.state).to_lowercase();
            let action = if t.outgoing
                && matches!(
                    t.state,
                    ipc::TransferFileState::Offered | ipc::TransferFileState::Transferring
                ) {
                format!("ray files cancel-transfer {}", t.id)
            } else {
                String::new()
            };
            let progress = format!("{} / {}", format_size(t.transferred), format_size(t.size));
            let state = match &t.error {
                Some(error) => format!("({state}: {error})"),
                None => format!("({state})"),
            };
            vec![
                layout::Cell::new(t.id.to_string(), style::rose(&t.id.to_string())),
                layout::Cell::new(t.peer.clone(), style::value(&t.peer)),
                layout::Cell::right(progress.clone(), style::faint(&progress)),
                layout::Cell::new(
                    format!("{} {state}", t.filename),
                    format!("{} {}", style::value(&t.filename), style::faint(&state)),
                ),
                layout::Cell::new(action.clone(), style::faint(&action)),
            ]
        })
        .collect();
    table(&["id", "peer", "progress", "file", ""], rows, 2)
}

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

#[cfg(unix)]
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
        // keeps working until the daemon restarts onto the new binary. The new
        // daemon refuses path sends from anyone but root, so this only helps
        // across the upgrade.
        Err(_) => {
            ipc_request(ipc::IpcMessage::SendFile {
                path: path.to_string_lossy().to_string(),
                peer: peer.to_string(),
            })
            .await?
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

#[cfg(windows)]
async fn ipc_send_file(file: &str, peer: &str) -> Result<()> {
    use tokio::io::AsyncReadExt;

    const CHUNK: usize = 256 * 1024;
    let path = std::path::absolute(file).with_context(|| format!("cannot resolve '{file}'"))?;
    let opened = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("cannot read '{}'", path.display()))?;
    let metadata = opened.metadata().await?;
    if !metadata.is_file() {
        anyhow::bail!("cannot send '{}': not a regular file", path.display());
    }
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_owned());
    let size = metadata.len();
    let mut stream = ipc::connect().await?;
    ipc::send(
        &mut stream,
        ipc::IpcMessage::SendFileBegin {
            filename,
            peer: peer.to_owned(),
            size,
        },
    )
    .await?;
    let mut opened = opened;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = opened.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        ipc::send(
            &mut stream,
            ipc::IpcMessage::SendFileChunk {
                data: buffer[..read].to_vec(),
                done: false,
            },
        )
        .await?;
    }
    ipc::send(
        &mut stream,
        ipc::IpcMessage::SendFileChunk {
            data: Vec::new(),
            done: true,
        },
    )
    .await?;
    match ipc::recv(&mut stream).await? {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        // Returned, not exited, for the same reason as the Unix path.
        ipc::IpcMessage::Error { message } => anyhow::bail!("{message}"),
        other => anyhow::bail!(unexpected_detail(&other)),
    }
    Ok(())
}

/// Read one global settings key from the daemon. A daemon-side error ends the
/// command, so there is no "no value" case left for the caller to handle: an
/// absent row renders as the empty string, which is how every settings key
/// spells unset.
async fn config_row(key: NodeKey) -> Result<String> {
    match ipc_request(ipc::IpcMessage::ConfigGet { key: Some(key) }).await? {
        ipc::IpcMessage::ConfigValues { rows } => {
            Ok(rows.into_iter().next().map(|(_, v)| v).unwrap_or_default())
        }
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
}

/// Add or remove one peer in a peer-list setting (`file-auto-accept-peers`,
/// `blocked`). The daemon resolves a hostname to its identity.
pub(crate) async fn edit_peer_list(key: GlobalKey, peer: &str, remove: bool) -> Result<()> {
    crate::ipc_mutate(ipc::IpcMessage::ConfigSet {
        key: NodeKey::Global(key),
        value: crate::config::settings::peer_list_edit(peer, remove)?,
        replace: false,
    })
    .await
}

/// The identities in a peer-list setting.
pub(crate) async fn peer_list(key: GlobalKey) -> Result<Vec<String>> {
    let row = config_row(NodeKey::Global(key)).await?;
    Ok(row
        .split(',')
        .filter(|peer| !peer.is_empty())
        .map(str::to_string)
        .collect())
}

/// `ray files auto-accept list`: a JSON array, or one peer per line.
#[derive(serde::Serialize)]
#[serde(transparent)]
struct PeerListOutput(Vec<String>);

impl DisplayOut for PeerListOutput {
    fn print_human(&self) {
        for peer in &self.0 {
            println!("{peer}");
        }
    }
}

/// `ray files download-dir`: `null` in JSON when unset.
#[derive(serde::Serialize)]
struct DownloadDirOutput<'a> {
    download_dir: Option<&'a str>,
}

impl DisplayOut for DownloadDirOutput<'_> {
    fn print_human(&self) {
        println!("download-dir = {}", self.download_dir.unwrap_or("<unset>"));
    }
}

/// `ray files download-user`: the uid, `null` in JSON when unset.
#[derive(serde::Serialize)]
struct DownloadUserOutput {
    download_user: Option<u32>,
}

impl DownloadUserOutput {
    /// The settings row renders the uid as text, empty when unset.
    fn parse(row: &str) -> Result<Self> {
        let download_user = match row {
            "" => None,
            uid => Some(
                uid.parse()
                    .with_context(|| format!("daemon reported an invalid download-user '{uid}'"))?,
            ),
        };
        Ok(Self { download_user })
    }
}

impl DisplayOut for DownloadUserOutput {
    fn print_human(&self) {
        match self.download_user {
            Some(uid) => println!("download-user = uid {uid}"),
            None => println!("download-user = <unset>"),
        }
    }
}

pub(crate) async fn ipc_files(action: Option<FilesAction>) -> Result<()> {
    // These subcommands change (or read) global settings the daemon owns. They
    // route through the daemon so the write lands in the config dir the daemon
    // reads (see the config-writing commands note in main.rs / rayfish#94).
    if let Some(FilesAction::AutoAccept {
        action: Some(action),
        ..
    }) = &action
    {
        let key = GlobalKey::FileAutoAcceptPeers;
        return match action {
            crate::FilesAutoAcceptAction::Add { peer } => edit_peer_list(key, peer, false).await,
            crate::FilesAutoAcceptAction::Remove { peer } => edit_peer_list(key, peer, true).await,
            crate::FilesAutoAcceptAction::List => printout(&PeerListOutput(peer_list(key).await?)),
        };
    }
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
            let dir = config_row(NodeKey::Global(GlobalKey::DownloadDir)).await?;
            return printout(&DownloadDirOutput {
                download_dir: (!dir.is_empty()).then_some(dir.as_str()),
            });
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
            let uid = config_row(NodeKey::Global(GlobalKey::DownloadUser)).await?;
            return printout(&DownloadUserOutput::parse(&uid)?);
        }
        _ => {}
    }

    let mut stream = ipc::connect().await?;
    match action {
        None => {
            ipc::send(&mut stream, ipc::IpcMessage::ListFiles).await?;
            let resp = ipc::recv(&mut stream).await?;
            match resp {
                ipc::IpcMessage::FileList {
                    files,
                    outbox,
                    transfers,
                } => {
                    printout(&FilesOutput::new(&files, &outbox, &transfers))?;
                }
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::Accept { id, output }) => {
            // The daemon resolves a relative path against its own working
            // directory, not the caller's, so send it absolute.
            let output = output
                .map(|dir| std::path::absolute(&dir).map(|p| p.to_string_lossy().to_string()))
                .transpose()
                .context("resolve the output directory")?;
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
                ipc::IpcMessage::Ok { message } => print_checked_message(&message)?,
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::Reject { id }) => {
            // No spinner, unlike `Accept`: nothing is fetched, the daemon just
            // drops the entry and answers.
            ipc::send(&mut stream, ipc::IpcMessage::RejectFile { id }).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => print_checked_message(&message)?,
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::Cancel { id }) => {
            ipc::send(&mut stream, ipc::IpcMessage::CancelSend { id }).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => print_checked_message(&message)?,
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::CancelTransfer { id }) => {
            ipc::send(&mut stream, ipc::IpcMessage::CancelTransfer { id }).await?;
            match ipc::recv(&mut stream).await? {
                ipc::IpcMessage::Ok { message } => print_checked_message(&message)?,
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
        }
        Some(FilesAction::AutoAccept { network, state, .. }) => {
            let network = network.context("network is required")?;
            let state = state.context("state is required")?;
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
                ipc::IpcMessage::Ok { message } => print_checked_message(&message)?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_settings_reads_serialize_for_json() {
        let peers = PeerListOutput(vec!["laptop".into()]);
        assert_eq!(
            serde_json::to_value(&peers).unwrap(),
            serde_json::json!(["laptop"])
        );
        let dir = DownloadDirOutput { download_dir: None };
        assert_eq!(
            serde_json::to_value(&dir).unwrap(),
            serde_json::json!({ "download_dir": null })
        );
        let user = DownloadUserOutput::parse("1000").unwrap();
        assert_eq!(
            serde_json::to_value(&user).unwrap(),
            serde_json::json!({ "download_user": 1000 })
        );
        assert_eq!(DownloadUserOutput::parse("").unwrap().download_user, None);
        assert!(DownloadUserOutput::parse("bob").is_err());
    }

    #[test]
    fn transfers_table_shows_progress_and_state() {
        style::set_plain(true);
        let transfers = [ipc::TransferFileInfo {
            error: None,
            id: 7,
            outgoing: true,
            peer: "laptop".to_string(),
            filename: "notes.txt".to_string(),
            size: 2048,
            transferred: 1024,
            state: ipc::TransferFileState::Transferring,
            destination: None,
        }];
        let out = transfers_table(&transfers);
        let row = out.lines().nth(1).expect("table has a header and one row");
        assert!(row.contains("1 KiB / 2 KiB"), "{out}");
        assert!(row.contains("notes.txt (transferring)"), "{out}");
        assert!(row.contains("ray files cancel-transfer 7"), "{out}");
    }
    #[test]
    fn declined_transfer_displays_the_reason() {
        style::set_plain(true);
        let transfers = [ipc::TransferFileInfo {
            error: Some("recipient declined the file".into()),
            id: 8,
            outgoing: true,
            peer: "receiver".into(),
            filename: "notes.txt".into(),
            size: 12,
            transferred: 0,
            state: ipc::TransferFileState::Failed,
            destination: None,
        }];
        let output = transfers_table(&transfers);
        assert!(output.contains("failed: recipient declined the file"));
        assert!(!output.contains("cancel-transfer"));
        let json = serde_json::to_value(FilesOutput::new(&[], &[], &transfers)).unwrap();
        assert_eq!(json["transfers"][0]["error"], "recipient declined the file");
    }
}
