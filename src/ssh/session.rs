//! Shared session input for PTY and pipe execution.

use std::future::Future;
use std::os::fd::AsFd;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use bytes::Bytes;
use pty_process::Size;
use russh::Sig;
use russh::server::{Handle, Msg};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::login::LoginInfo;
use super::session_env::{drop_privs, login_env, login_program, tty_name};
use super::{ChildProc, Origin, PtyReq};

/// Everything a session runner needs beyond its SSH channel.
pub(super) struct SessionSpec {
    pub(super) info: Arc<LoginInfo>,
    pub(super) command: Option<String>,
    pub(super) env: Vec<(String, String)>,
    pub(super) child_proc: ChildProc,
    pub(super) origin: Origin,
}

/// How a session process ended. SSH reports a signal differently from an exit
/// status, so callers need the distinction rather than a single integer.
pub(super) enum Exit {
    Code(u32),
    Signal(Sig),
}

impl Exit {
    pub(super) fn from_status(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;

        match (status.code(), status.signal()) {
            (Some(code), _) => Self::Code(code as u32),
            (None, Some(signal)) => Self::Signal(signal_name(signal)),
            (None, None) => Self::Code(0),
        }
    }
}

fn signal_name(signal: i32) -> Sig {
    match signal {
        libc::SIGABRT => Sig::ABRT,
        libc::SIGALRM => Sig::ALRM,
        libc::SIGFPE => Sig::FPE,
        libc::SIGHUP => Sig::HUP,
        libc::SIGILL => Sig::ILL,
        libc::SIGINT => Sig::INT,
        libc::SIGKILL => Sig::KILL,
        libc::SIGPIPE => Sig::PIPE,
        libc::SIGQUIT => Sig::QUIT,
        libc::SIGSEGV => Sig::SEGV,
        libc::SIGTERM => Sig::TERM,
        libc::SIGUSR1 => Sig::USR1,
        other => Sig::Custom(other.to_string()),
    }
}

/// Maps a client's SSH signal request to its local unix signal number.
pub(super) fn signal_number(signal: &Sig) -> Option<i32> {
    Some(match signal {
        Sig::ABRT => libc::SIGABRT,
        Sig::ALRM => libc::SIGALRM,
        Sig::FPE => libc::SIGFPE,
        Sig::HUP => libc::SIGHUP,
        Sig::ILL => libc::SIGILL,
        Sig::INT => libc::SIGINT,
        Sig::KILL => libc::SIGKILL,
        Sig::PIPE => libc::SIGPIPE,
        Sig::QUIT => libc::SIGQUIT,
        Sig::SEGV => libc::SIGSEGV,
        Sig::TERM => libc::SIGTERM,
        Sig::USR1 => libc::SIGUSR1,
        Sig::Custom(name) => match name.as_str() {
            "USR2" => libc::SIGUSR2,
            "TSTP" => libc::SIGTSTP,
            "CONT" => libc::SIGCONT,
            "WINCH" => libc::SIGWINCH,
            _ => return None,
        },
    })
}

/// Allocate a PTY, spawn the login shell (or `exec` command), and transfer
/// bytes between the SSH channel and PTY until the child exits.
pub(super) async fn run_pty_session(
    channel: Channel<Msg>,
    spec: SessionSpec,
    pty_req: PtyReq,
    mut resize_rx: mpsc::UnboundedReceiver<Size>,
) -> Result<Exit> {
    let SessionSpec {
        info,
        command,
        env,
        child_proc,
        origin,
    } = spec;
    let (pty, pts) = pty_process::open().context("opening pty")?;
    let _ = pty.resize(Size::new(pty_req.row, pty_req.col));
    let tty = tty_name(&pts);
    // Keep a slave fd open until the child exits. `login` briefly reopens its
    // terminal while starting, which would otherwise make the PTY reader see
    // EIO and end the SSH stream early.
    let keep_open = pts.as_fd().try_clone_to_owned().ok();

    // An interactive non-root shell goes through `login(1)` for PAM and
    // session accounting. Root and command sessions spawn the shell directly.
    let handoff = (command.is_none() && info.uid != 0)
        .then(login_program)
        .flatten();
    let mut cmd = match &handoff {
        Some(login) => pty_process::Command::new(login)
            .arg("-p")
            .arg("-h")
            .arg(origin.client.ip().to_string())
            .arg("-f")
            .arg(&info.name),
        None => match &command {
            Some(command) => pty_process::Command::new(&info.shell)
                .arg("-c")
                .arg(command),
            None => pty_process::Command::new(&info.shell).arg("-l"),
        },
    };
    cmd = cmd
        .env_clear()
        .envs(login_env(&info.home, &info.shell, &info.name))
        .env("TERM", &pty_req.term)
        .envs(tty.map(|tty| ("SSH_TTY".to_string(), tty)))
        .envs(env);
    if handoff.is_none() {
        cmd = cmd.current_dir(&info.home);
        let drop = drop_privs(info.uid, info.gid, &info.name)?;
        // SAFETY: drops supplementary groups, group, and user before exec.
        cmd = unsafe { cmd.pre_exec(drop) };
    }
    let mut child = cmd.spawn(pts).context("spawning login shell")?;
    child_proc
        .pid
        .store(child.id().unwrap_or(0), Ordering::Relaxed);

    let stream = channel.into_stream();
    let (mut chan_read, mut chan_write) = tokio::io::split(stream);
    let (mut pty_read, mut pty_write) = pty.into_split();
    // Client input and resize requests both write to the PTY.
    let c2p = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            tokio::select! {
                result = chan_read.read(&mut buf) => match result {
                    Ok(0) | Err(_) => break,
                    Ok(length) if pty_write.write_all(&buf[..length]).await.is_err() => break,
                    Ok(_) => {}
                },
                Some(size) = resize_rx.recv() => {
                    let _ = pty_write.resize(size);
                }
            }
        }
    });
    let p2c = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut pty_read, &mut chan_write).await;
        let _ = chan_write.shutdown().await;
    });

    let status = child.wait().await.context("waiting on child")?;
    child_proc.pid.store(0, Ordering::Relaxed);
    drop(keep_open);
    let _ = p2c.await;
    c2p.abort();
    Ok(Exit::from_status(status))
}

/// Run a command without a PTY, preserving stdout and stderr as separate SSH
/// streams.
pub(super) async fn run_pipe_session(
    channel: Channel<Msg>,
    handle: Handle,
    channel_id: ChannelId,
    spec: SessionSpec,
) -> Result<Exit> {
    let SessionSpec {
        info,
        command,
        env,
        child_proc,
        ..
    } = spec;
    let drop = drop_privs(info.uid, info.gid, &info.name)?;
    let mut cmd = tokio::process::Command::new(&info.shell);
    match &command {
        Some(command) => cmd.arg("-c").arg(command),
        None => cmd.arg("-l"),
    };
    cmd.current_dir(&info.home)
        .env_clear()
        .envs(login_env(&info.home, &info.shell, &info.name))
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: drops supplementary groups, group, and user before exec.
    unsafe {
        cmd.pre_exec(drop);
    }
    let mut child = cmd.spawn().context("spawning command")?;
    child_proc
        .pid
        .store(child.id().unwrap_or(0), Ordering::Relaxed);
    let mut stdin = child.stdin.take().context("child stdin")?;
    let mut stdout = child.stdout.take().context("child stdout")?;
    let mut stderr = child.stderr.take().context("child stderr")?;

    let stream = channel.into_stream();
    let (mut chan_read, _chan_write) = tokio::io::split(stream);
    // The channel stream only carries stdin. SSH output uses the handle so
    // stderr remains extended data instead of mixing with stdout.
    let stdin_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut chan_read, &mut stdin).await;
    });
    let stdout_handle = handle.clone();
    let out_task = tokio::spawn(async move {
        copy_output(&mut stdout, |bytes| stdout_handle.data(channel_id, bytes)).await;
    });
    let stderr_handle = handle.clone();
    let err_task = tokio::spawn(async move {
        copy_output(&mut stderr, |bytes| {
            stderr_handle.extended_data(channel_id, 1, bytes)
        })
        .await;
    });

    let status = child.wait().await.context("waiting on child")?;
    child_proc.pid.store(0, Ordering::Relaxed);
    let _ = out_task.await;
    let _ = err_task.await;
    stdin_task.abort();
    Ok(Exit::from_status(status))
}

async fn copy_output<F, Fut, E>(reader: &mut (impl AsyncRead + Unpin), mut send: F)
where
    F: FnMut(Bytes) -> Fut,
    Fut: Future<Output = std::result::Result<(), E>>,
{
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(length) if send(Bytes::copy_from_slice(&buf[..length])).await.is_err() => break,
            Ok(_) => {}
        }
    }
}
