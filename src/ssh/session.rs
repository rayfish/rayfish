//! Shared session input for PTY and pipe execution.

use std::sync::Arc;

use russh::Sig;

use super::login::LoginInfo;
use super::{ChildProc, Origin};

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
