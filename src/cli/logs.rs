//! `ray logs`: read the daemon's rolling log files without root.
//!
//! The files are `0644 root:root` under `logdir::log_dir()`, so the read goes
//! through the daemon over IPC, the same way `ray report` gets at them. The
//! reply is the protocol's one multi-frame response: a run of `LogChunk`s
//! ended by an `Ok` sentinel, or never ended at all under `--follow`.

use std::io::{ErrorKind, IsTerminal, Write};
use std::process::{Child, Command, Stdio};

use crate::*;

pub(crate) async fn ipc_logs(since: Option<String>, follow: bool) -> Result<()> {
    let since = match since {
        Some(s) => Some(
            humantime::parse_duration(&s)
                .with_context(|| format!("invalid --since '{s}': use e.g. 10m, 1h, 2h30m"))?,
        ),
        None => None,
    };

    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, ipc::IpcMessage::Logs { since, follow }).await?;

    // Following writes straight through, like `tail -f`. A one-shot read goes
    // to the pager, unless stdout is a pipe (`ray logs | grep`), where `git
    // log`'s convention is to stay out of the way.
    let mut sink = Sink::new(!follow && std::io::stdout().is_terminal());
    loop {
        match ipc::recv(&mut stream).await {
            Ok(ipc::IpcMessage::LogChunk { data }) => {
                if !sink.write(&data) {
                    break;
                }
            }
            Ok(ipc::IpcMessage::Ok { .. }) => break,
            Ok(ipc::IpcMessage::Error { message }) => {
                sink.finish();
                fail_with("error", &message);
            }
            // `finish` first, as the error arm does: it waits on the pager, and
            // exiting out from under it leaves the terminal to the pager's mercy.
            Ok(other) => {
                sink.finish();
                fail_unexpected(&other);
            }
            // The daemon went away mid-stream (a restart, a shutdown). What
            // arrived is still worth showing, so this is an end, not a failure.
            Err(_) => break,
        }
    }
    sink.finish();
    Ok(())
}

/// Where the log stream lands: the user's pager for a one-shot read on a
/// terminal, plain stdout for everything else.
enum Sink {
    Pager(Child),
    Stdout,
}

impl Sink {
    fn new(paged: bool) -> Self {
        match paged.then(spawn_pager).flatten() {
            Some(child) => Sink::Pager(child),
            None => Sink::Stdout,
        }
    }

    /// Write one chunk. `false` means the far end is gone (the pager was quit,
    /// stdout is a closed pipe), which ends the output normally rather than
    /// as an error.
    fn write(&mut self, data: &[u8]) -> bool {
        let written = match self {
            Sink::Pager(child) => match child.stdin.as_mut() {
                Some(w) => w.write_all(data).and_then(|()| w.flush()),
                None => Ok(()),
            },
            Sink::Stdout => {
                let mut out = std::io::stdout().lock();
                out.write_all(data).and_then(|()| out.flush())
            }
        };
        match written {
            Ok(()) => true,
            Err(e) if e.kind() == ErrorKind::BrokenPipe => false,
            Err(e) => {
                eprintln!("write failed: {e}");
                false
            }
        }
    }

    /// Close the pager's stdin so it sees EOF, then wait for the user to quit
    /// it. Dropping without this would leave `less` reading a pipe nobody is
    /// going to close.
    fn finish(&mut self) {
        if let Sink::Pager(child) = self {
            drop(child.stdin.take());
            let _ = child.wait();
        }
    }
}

/// `$PAGER`, else `less`. `None` when there is no usable pager, or when the
/// user asked for none by setting `PAGER` to empty or `cat`.
///
/// `LESS` follows git's convention when the user has not set it: `-F` quits
/// straight away when the output fits one screen, `-R` passes colour through,
/// `-X` leaves the log on the terminal instead of wiping it on exit.
fn spawn_pager() -> Option<Child> {
    let pager = std::env::var("PAGER").unwrap_or_else(|_| "less".to_string());
    let mut parts = pager.split_whitespace();
    let program = parts.next()?;
    if program == "cat" {
        return None;
    }
    let mut cmd = Command::new(program);
    cmd.args(parts).stdin(Stdio::piped());
    if std::env::var_os("LESS").is_none() {
        cmd.env("LESS", "FRX");
    }
    cmd.spawn().ok()
}
