//! Hidden, bounded subprocess execution for Windows platform adapters.

use std::ffi::OsStr;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub(crate) struct WindowsProcessOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(crate) struct WindowsProcessRunner {
    timeout: Duration,
}

impl Default for WindowsProcessRunner {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl WindowsProcessRunner {
    #[cfg(test)]
    pub(crate) fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub(crate) async fn output<I, S>(
        &self,
        program: impl AsRef<OsStr>,
        args: I,
    ) -> Result<WindowsProcessOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let program = program.as_ref();
        let mut command = Command::new(program);
        command
            .creation_flags(CREATE_NO_WINDOW)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args);

        let mut child = command
            .spawn()
            .with_context(|| format!("spawn hidden Windows process {program:?}"))?;
        let mut stdout = child.stdout.take().context("capture child stdout")?;
        let mut stderr = child.stderr.take().context("capture child stderr")?;
        let stdout_task = tokio::spawn(async move {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await.map(|_| bytes)
        });
        let stderr_task = tokio::spawn(async move {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).await.map(|_| bytes)
        });

        let status = match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(status) => status.context("wait for Windows process")?,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                anyhow::bail!(
                    "Windows process {program:?} timed out after {:?}",
                    self.timeout
                );
            }
        };
        let stdout = stdout_task
            .await
            .context("join child stdout reader")?
            .context("read child stdout")?;
        let stderr = stderr_task
            .await
            .context("join child stderr reader")?
            .context("read child stderr")?;
        Ok(WindowsProcessOutput {
            status,
            stdout,
            stderr,
        })
    }

    pub(crate) async fn powershell(&self, script: &str, operation: &str) -> Result<String> {
        let output = self
            .output(
                "powershell.exe",
                [
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
            )
            .await
            .with_context(|| operation.to_owned())?;
        anyhow::ensure!(
            output.status.success(),
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::WindowsProcessRunner;
    use std::time::Duration;

    #[tokio::test]
    async fn zombie_runner_covers_success_failure_and_timeout() {
        let runner = WindowsProcessRunner::with_timeout(Duration::from_secs(2));
        let ok = runner
            .output("cmd.exe", ["/C", "echo", "rayfish"])
            .await
            .unwrap();
        assert!(ok.status.success());
        assert!(String::from_utf8_lossy(&ok.stdout).contains("rayfish"));

        let failed = runner.output("cmd.exe", ["/C", "exit", "7"]).await.unwrap();
        assert_eq!(failed.status.code(), Some(7));

        let timeout = WindowsProcessRunner::with_timeout(Duration::from_millis(20))
            .output(
                "powershell.exe",
                ["-NoProfile", "-Command", "Start-Sleep -Seconds 2"],
            )
            .await
            .unwrap_err();
        assert!(timeout.to_string().contains("timed out"));
    }
}
