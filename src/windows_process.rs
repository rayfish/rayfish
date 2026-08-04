//! Hidden, bounded subprocess execution for Windows platform adapters.

use std::ffi::OsStr;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::task::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const WINDOWS_CREATION_FLAGS: u32 = CREATE_NO_WINDOW | CREATE_SUSPENDED;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

struct KillOnCloseJob(HANDLE);

// Kernel handles may be transferred between threads; this wrapper owns the
// handle and closes it exactly once.
unsafe impl Send for KillOnCloseJob {}

impl KillOnCloseJob {
    fn new() -> Result<Self> {
        // SAFETY: null security/name creates an unnamed job; the returned handle
        // is owned by this wrapper and closed in Drop.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error()).context("create Windows Job Object");
        }
        // SAFETY: the zeroed structure is a valid baseline and the API reads
        // exactly the size supplied below.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        };
        if configured == 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                CloseHandle(handle);
            }
            return Err(error).context("configure kill-on-close Windows Job Object");
        }
        Ok(Self(handle))
    }

    fn assign(&self, child: &tokio::process::Child) -> Result<()> {
        let process = child
            .raw_handle()
            .context("Windows child has no process handle")? as HANDLE;
        // SAFETY: both handles are live for this call and ownership is retained.
        if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("assign Windows process to kill-on-close Job Object");
        }
        Ok(())
    }
}

impl Drop for KillOnCloseJob {
    fn drop(&mut self) {
        // Closing the last job handle terminates the full assigned process tree.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn resume_suspended_process(process_id: u32) -> Result<()> {
    // CREATE_SUSPENDED creates exactly one thread. Enumerate it while still
    // suspended, then resume only after the process has joined our Job Object.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("snapshot suspended Windows threads");
    }
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut found = None;
    let mut has_entry = unsafe { Thread32First(snapshot, &mut entry) } != 0;
    while has_entry {
        if entry.th32OwnerProcessID == process_id {
            found = Some(entry.th32ThreadID);
            break;
        }
        has_entry = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
    }
    unsafe {
        CloseHandle(snapshot);
    }
    let thread_id = found.context("find primary thread of suspended Windows process")?;
    let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
    if thread.is_null() {
        return Err(std::io::Error::last_os_error()).context("open suspended Windows thread");
    }
    let resumed = unsafe { ResumeThread(thread) };
    unsafe {
        CloseHandle(thread);
    }
    if resumed == u32::MAX {
        return Err(std::io::Error::last_os_error()).context("resume suspended Windows process");
    }
    anyhow::ensure!(
        resumed == 1,
        "unexpected Windows primary-thread suspend count {resumed}; child terminated"
    );
    Ok(())
}

async fn bounded_reader_join(mut task: JoinHandle<std::io::Result<Vec<u8>>>) -> Result<Vec<u8>> {
    match tokio::time::timeout(CLEANUP_TIMEOUT, &mut task).await {
        Ok(result) => result
            .context("join Windows process pipe reader")?
            .context("read Windows process pipe"),
        Err(_) => {
            task.abort();
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, task).await;
            anyhow::bail!("Windows process pipe reader did not close after {CLEANUP_TIMEOUT:?}")
        }
    }
}

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
            .creation_flags(WINDOWS_CREATION_FLAGS)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args);

        let job = KillOnCloseJob::new()?;
        let mut child = command
            .spawn()
            .with_context(|| format!("spawn hidden Windows process {program:?}"))?;
        if let Err(error) = job.assign(&child) {
            let _ = child.start_kill();
            return Err(error);
        }
        let process_id = child
            .id()
            .context("suspended Windows child has no process id")?;
        if let Err(error) = resume_suspended_process(process_id) {
            drop(job);
            let _ = child.start_kill();
            return Err(error);
        }
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
            Ok(status) => {
                let status = status.context("wait for Windows process");
                drop(job);
                status?
            }
            Err(_) => {
                drop(job);
                if tokio::time::timeout(CLEANUP_TIMEOUT, child.wait())
                    .await
                    .is_err()
                {
                    let _ = tokio::time::timeout(CLEANUP_TIMEOUT, child.kill()).await;
                }
                let _ = tokio::join!(
                    bounded_reader_join(stdout_task),
                    bounded_reader_join(stderr_task)
                );
                anyhow::bail!(
                    "Windows process {program:?} timed out after {:?}",
                    self.timeout
                );
            }
        };
        let (stdout, stderr) = tokio::join!(
            bounded_reader_join(stdout_task),
            bounded_reader_join(stderr_task)
        );
        Ok(WindowsProcessOutput {
            status,
            stdout: stdout?,
            stderr: stderr?,
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
    use super::{CREATE_NO_WINDOW, CREATE_SUSPENDED, WINDOWS_CREATION_FLAGS, WindowsProcessRunner};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    #[tokio::test]
    async fn zombie_runner_covers_success_failure_and_timeout() {
        assert_eq!(WINDOWS_CREATION_FLAGS & CREATE_NO_WINDOW, CREATE_NO_WINDOW);
        assert_eq!(WINDOWS_CREATION_FLAGS & CREATE_SUSPENDED, CREATE_SUSPENDED);
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

    #[tokio::test]
    async fn ddd_job_close_kills_descendants_and_releases_inherited_pipes() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("descendant.pid");
        let quoted_path = pid_file.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$child=Start-Process powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -WindowStyle Hidden -PassThru; Set-Content -LiteralPath '{quoted_path}' -Value $child.Id; Start-Sleep -Seconds 30"
        );
        let error = WindowsProcessRunner::with_timeout(Duration::from_secs(3))
            .powershell(&script, "spawn descendant tree")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("spawn descendant tree"));
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string().contains("timed out"))
        );

        let pid: u32 = std::fs::read_to_string(&pid_file)
            .expect("parent must publish descendant pid before timeout")
            .trim()
            .parse()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // SAFETY: the handle is query-only, checked for null, and closed once.
        let alive = unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                false
            } else {
                let mut exit_code = 0;
                let queried = GetExitCodeProcess(process, &mut exit_code) != 0;
                CloseHandle(process);
                queried && exit_code == 259 // STILL_ACTIVE
            }
        };
        assert!(!alive, "kill-on-close job leaked descendant pid {pid}");
    }
}
