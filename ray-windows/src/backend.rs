use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;

use crate::model::{Files, PendingItem, PendingKind, Request, Snapshot, Status, words};

const MAX_OUTPUT: u64 = 512 * 1024;
const STARTUP_TASK: &str = "Rayfish Desktop App";

#[derive(Debug)]
pub(crate) enum Work {
    Refresh,
    Run(Vec<String>),
    Startup(bool),
    Quit,
}

#[derive(Debug)]
pub(crate) struct Update {
    pub snapshot: Result<Box<Snapshot>, String>,
    pub output: Option<Result<String, String>>,
    pub quit: bool,
}

pub(crate) struct Worker {
    sender: Option<SyncSender<Work>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(
        ray: PathBuf,
        app: PathBuf,
        notify: impl Fn(Update) -> bool + Send + 'static,
    ) -> Result<Self> {
        let (sender, receiver) = sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let cancelled = stopping.clone();
        let thread = thread::Builder::new()
            .name("rayfish-ui".into())
            .spawn(move || {
                while let Ok(work) = receiver.recv() {
                    if cancelled.load(Ordering::Acquire) {
                        break;
                    }
                    let quit = matches!(work, Work::Quit);
                    let output = match work {
                        Work::Refresh => None,
                        Work::Run(args) => Some(run_ray(&ray, &args, &cancelled)),
                        Work::Startup(enabled) => Some(set_startup(&app, enabled, &cancelled)),
                        Work::Quit => Some(run_ray(&ray, &words(&["down"]), &cancelled)),
                    }
                    .map(|result| result.map_err(|error| format!("{error:#}")));
                    let quit = quit && output.as_ref().is_some_and(Result::is_ok);
                    let snapshot = if quit {
                        Err("Rayfish is closing.".into())
                    } else {
                        snapshot(&ray, &cancelled)
                            .map(Box::new)
                            .map_err(|error| format!("{error:#}"))
                    };
                    if cancelled.load(Ordering::Acquire)
                        || !notify(Update {
                            snapshot,
                            output,
                            quit,
                        })
                    {
                        break;
                    }
                }
            })
            .context("starting the desktop command worker")?;
        Ok(Self {
            sender: Some(sender),
            stopping,
            thread: Some(thread),
        })
    }

    pub fn submit(&self, work: Work) -> Result<()> {
        self.sender
            .as_ref()
            .context("the command worker has stopped")?
            .try_send(work)
            .context("the command worker is busy or has stopped")
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            if thread.join().is_err() {
                eprintln!("the desktop command worker panicked");
            }
        }
    }
}

fn snapshot(ray: &Path, cancelled: &AtomicBool) -> Result<Snapshot> {
    let status: Status = json(ray, &["status", "--json"], cancelled)?;
    let config = json(ray, &["config", "--json"], cancelled).map_err(|error| format!("{error:#}"));
    let firewall =
        json(ray, &["firewall", "show", "--json"], cancelled).map_err(|error| format!("{error:#}"));
    let mut pending = Vec::new();
    let mut warnings = Vec::new();
    for network in &status.networks {
        if network.pending_requests > 0 {
            match json::<Vec<Request>>(ray, &["requests", &network.name, "--json"], cancelled) {
                Ok(requests) => {
                    for request in requests {
                        pending.push(PendingItem {
                            description: format!(
                                "{} asks to join {} (waiting {}s)",
                                request.hostname.as_deref().unwrap_or(&request.id),
                                network.name,
                                request.waiting_secs
                            ),
                            kind: PendingKind::Join {
                                network: network.name.clone(),
                                id: request.id,
                            },
                        });
                    }
                }
                Err(error) => warnings.push(format!("Could not read join requests: {error:#}")),
            }
        }
        if network.pending_suggestions > 0 {
            pending.push(PendingItem {
                description: format!(
                    "Firewall rules suggested for {}. Review before accepting.",
                    network.name
                ),
                kind: PendingKind::Firewall {
                    network: network.name.clone(),
                },
            });
        }
    }
    if status.pending.connects > 0 {
        match json::<Vec<Request>>(ray, &["connect", "--json"], cancelled) {
            Ok(requests) => {
                for request in requests {
                    pending.push(PendingItem {
                        description: format!(
                            "{} wants a direct connection (waiting {}s)",
                            request.hostname.as_deref().unwrap_or(&request.id),
                            request.waiting_secs
                        ),
                        kind: PendingKind::Connect { id: request.id },
                    });
                }
            }
            Err(error) => warnings.push(format!("Could not read connection requests: {error:#}")),
        }
    }
    if status.pending.files > 0 {
        match json::<Files>(ray, &["files", "--json"], cancelled) {
            Ok(files) => {
                for file in files.pending {
                    pending.push(PendingItem {
                        description: format!(
                            "{} sends {} ({} bytes)",
                            file.from, file.filename, file.size
                        ),
                        kind: PendingKind::File { id: file.id },
                    });
                }
            }
            Err(error) => warnings.push(format!("Could not read file offers: {error:#}")),
        }
    }
    let launch_at_login = match process(
        Path::new("schtasks.exe"),
        &words(&["/Query", "/TN", STARTUP_TASK]),
        cancelled,
    ) {
        Ok(output) => output.success,
        Err(error) => {
            warnings.push(format!("Could not read Start at login: {error:#}"));
            false
        }
    };
    Ok(Snapshot {
        status,
        config,
        firewall,
        pending,
        warnings,
        launch_at_login,
    })
}

fn json<T: DeserializeOwned>(ray: &Path, args: &[&str], cancelled: &AtomicBool) -> Result<T> {
    serde_json::from_str(&run_ray(ray, &words(args), cancelled)?)
        .context("reading the ray command's JSON response")
}

fn run_ray(ray: &Path, args: &[String], cancelled: &AtomicBool) -> Result<String> {
    process(ray, args, cancelled)?.into_result()
}

fn set_startup(app: &Path, enabled: bool, cancelled: &AtomicBool) -> Result<String> {
    let args = if enabled {
        words(&[
            "/Create",
            "/TN",
            STARTUP_TASK,
            "/SC",
            "ONLOGON",
            "/TR",
            &format!("\"{}\"", app.display()),
            "/RL",
            "HIGHEST",
            "/IT",
            "/DELAY",
            "0000:05",
            "/F",
        ])
    } else {
        words(&["/Delete", "/TN", STARTUP_TASK, "/F"])
    };
    process(Path::new("schtasks.exe"), &args, cancelled)?.into_result()
}

#[derive(Debug)]
struct ProcessOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

impl ProcessOutput {
    fn into_result(self) -> Result<String> {
        let text = [self.stdout.trim(), self.stderr.trim()]
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if !self.success {
            bail!(
                "{}",
                if text.is_empty() {
                    "The command failed."
                } else {
                    &text
                }
            );
        }
        Ok(text)
    }
}

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        // Error paths must reap the child too. Drop cannot report cleanup errors.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn process(program: &Path, args: &[String], cancelled: &AtomicBool) -> Result<ProcessOutput> {
    process_with_timeout(program, args, cancelled, Duration::from_secs(60))
}

fn process_with_timeout(
    program: &Path,
    args: &[String],
    cancelled: &AtomicBool,
    timeout: Duration,
) -> Result<ProcessOutput> {
    if cancelled.load(Ordering::Acquire) || timeout.is_zero() {
        bail!("The command was cancelled.");
    }
    // Files avoid blocking the child on a full stdout/stderr pipe.
    let mut stdout = tempfile::tempfile().context("creating the command output file")?;
    let mut stderr = tempfile::tempfile().context("creating the command error file")?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

        command.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = RunningChild(command.spawn().context("starting the ray command")?);
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.0.try_wait().context("waiting for the command")? {
            break status;
        }
        if cancelled.load(Ordering::Acquire) {
            bail!("The command was cancelled.");
        }
        if Instant::now() >= deadline {
            bail!("The command timed out. Check the Rayfish service and try again.");
        }
        thread::park_timeout(Duration::from_millis(25));
    };
    Ok(ProcessOutput {
        success: status.success(),
        stdout: read_output(&mut stdout)?,
        stderr: read_output(&mut stderr)?,
    })
}

fn read_output(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_OUTPUT + 1).read_to_end(&mut bytes)?;
    let truncated = bytes.len() as u64 > MAX_OUTPUT;
    bytes.truncate(MAX_OUTPUT as usize);
    let mut output = String::from_utf8_lossy(&bytes).into_owned();
    if truncated {
        output.push_str("\n[Output truncated]");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn output_is_bounded() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![b'x'; MAX_OUTPUT as usize + 1])
            .unwrap();
        let output = read_output(&mut file).unwrap();
        assert!(output.ends_with("[Output truncated]"));
        assert!(output.len() < MAX_OUTPUT as usize + 100);
    }

    #[test]
    fn failed_commands_preserve_the_error() {
        let output = ProcessOutput {
            success: false,
            stdout: String::new(),
            stderr: "example failure".into(),
        };
        assert_eq!(
            output.into_result().unwrap_err().to_string(),
            "example failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn commands_can_write_more_than_a_pipe_buffer_without_hanging() {
        let output = process(
            Path::new("/bin/sh"),
            &words(&["-c", "head -c 262144 /dev/zero; printf error >&2"]),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.len(), 262144);
        assert_eq!(output.stderr, "error");
    }

    #[test]
    fn cancellation_does_not_start_a_process() {
        assert!(
            process(
                Path::new("nonexistent-command"),
                &[],
                &AtomicBool::new(true)
            )
            .unwrap_err()
            .to_string()
            .contains("cancelled")
        );
    }

    #[test]
    fn worker_delivers_failures_and_shuts_down_without_a_daemon() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = Worker::start(
            PathBuf::from("nonexistent-ray-command"),
            PathBuf::new(),
            move |update| sender.send(update).is_ok(),
        )
        .unwrap();
        worker.submit(Work::Refresh).unwrap();
        let update = receiver.recv().unwrap();
        assert!(update.snapshot.is_err());
        assert!(update.output.is_none());
        assert!(!update.quit);
        drop(worker);
    }

    #[cfg(windows)]
    #[test]
    fn windows_process_preserves_stdout_stderr_and_exit_status() {
        let output = process(
            Path::new("cmd.exe"),
            &words(&[
                "/D",
                "/C",
                "echo example output & echo example error 1>&2 & exit /b 7",
            ]),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(!output.success);
        assert!(output.stdout.contains("example output"));
        assert!(output.stderr.contains("example error"));
    }
}
