//! Waiting on a blocking child process without letting it hang the caller.

use std::io::{Error, ErrorKind, Result};
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

/// Wait up to `timeout` for `child` to exit. One that has not by then, or whose
/// wait fails, is killed and reaped, and the result is the error (`TimedOut`
/// for the first).
pub(crate) fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let started = Instant::now();
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(20)),
            Ok(None) => break Error::from(ErrorKind::TimedOut),
            Err(error) => break error,
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    Err(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn an_exit_is_returned_and_a_hang_is_killed() {
        let mut quick = Command::new("true").spawn().expect("spawn true");
        assert!(
            wait_bounded(&mut quick, Duration::from_secs(5))
                .expect("true exits")
                .success()
        );

        let mut slow = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let error = wait_bounded(&mut slow, Duration::from_millis(50)).expect_err("times out");
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(slow.try_wait().expect("reaped").is_some());
    }
}
