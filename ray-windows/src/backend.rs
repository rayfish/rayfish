use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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
    Disconnect,
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkId(u64);

#[derive(Debug)]
pub(crate) struct Update {
    pub id: WorkId,
    pub snapshot: Result<Box<Snapshot>, String>,
    pub output: Option<Result<String, String>>,
    pub quit: bool,
}

struct Job {
    id: WorkId,
    work: Work,
    cancelled: Arc<AtomicBool>,
}

#[derive(Default)]
struct Queue {
    pending: Option<Job>,
    running: Option<Arc<AtomicBool>>,
    closing: bool,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    update: Mutex<Option<Update>>,
}

pub(crate) struct Worker {
    shared: Arc<Shared>,
    next_id: u64,
    thread: Option<JoinHandle<Result<()>>>,
}

impl Worker {
    pub fn start(ray: PathBuf, app: PathBuf, notify: impl Fn() + Send + 'static) -> Result<Self> {
        Self::start_with(
            move |id, work, cancelled| {
                let quit = matches!(work, Work::Quit);
                let output = match work {
                    Work::Refresh => None,
                    Work::Run(args) => Some(run_ray(&ray, &args, cancelled)),
                    Work::Startup(enabled) => Some(set_startup(&app, enabled, cancelled)),
                    Work::Disconnect | Work::Quit => Some(
                        process_with_timeout(
                            &ray,
                            &words(&["down"]),
                            cancelled,
                            Duration::from_secs(10),
                        )
                        .and_then(ProcessOutput::into_result),
                    ),
                }
                .map(|result| result.map_err(|error| format!("{error:#}")));
                let snapshot = if quit {
                    // Quit must not wait on unrelated status and settings reads,
                    // including when disconnect failed and the UI needs its error.
                    Err("Could not disconnect Rayfish.".into())
                } else {
                    snapshot(&ray, cancelled)
                        .map(Box::new)
                        .map_err(|error| format!("{error:#}"))
                };
                let quit = quit && output.as_ref().is_some_and(Result::is_ok);
                Update {
                    id,
                    snapshot,
                    output,
                    quit,
                }
            },
            notify,
        )
    }

    fn start_with(
        execute: impl Fn(WorkId, Work, &AtomicBool) -> Update + Send + 'static,
        notify: impl Fn() + Send + 'static,
    ) -> Result<Self> {
        let shared = Arc::new(Shared::default());
        let owner = shared.clone();
        let thread = thread::Builder::new()
            .name("rayfish-ui".into())
            .spawn(move || {
                loop {
                    let job = {
                        let queue = owner
                            .queue
                            .lock()
                            .map_err(|_| anyhow::anyhow!("The command queue was poisoned."))?;
                        let mut queue = owner
                            .ready
                            .wait_while(queue, |queue| queue.pending.is_none() && !queue.closing)
                            .map_err(|_| anyhow::anyhow!("The command queue was poisoned."))?;
                        if queue.closing {
                            return Ok(());
                        }
                        let job = queue
                            .pending
                            .take()
                            .context("the ready command queue is empty")?;
                        queue.running = Some(job.cancelled.clone());
                        job
                    };
                    let update = execute(job.id, job.work, &job.cancelled);
                    let mut queue = owner
                        .queue
                        .lock()
                        .map_err(|_| anyhow::anyhow!("The command queue was poisoned."))?;
                    queue.running = None;
                    if queue.closing {
                        return Ok(());
                    }
                    if !job.cancelled.load(Ordering::Acquire) {
                        // A single result slot keeps delivery bounded. A newer completion
                        // supersedes a result the UI has not consumed yet.
                        *owner
                            .update
                            .lock()
                            .map_err(|_| anyhow::anyhow!("The command result was poisoned."))? =
                            Some(update);
                        drop(queue);
                        notify();
                    }
                }
            })
            .context("starting the desktop command worker")?;
        Ok(Self {
            shared,
            next_id: 0,
            thread: Some(thread),
        })
    }

    pub fn submit(&mut self, work: Work) -> Result<WorkId> {
        self.enqueue(work, false)
    }

    pub fn interrupt(&mut self, work: Work) -> Result<WorkId> {
        self.enqueue(work, true)
    }

    fn enqueue(&mut self, work: Work, interrupt: bool) -> Result<WorkId> {
        let id = WorkId(
            self.next_id
                .checked_add(1)
                .context("the command identifier overflowed")?,
        );
        let mut queue = self
            .shared
            .queue
            .lock()
            .map_err(|_| anyhow::anyhow!("The command queue was poisoned."))?;
        if queue.closing
            || self
                .thread
                .as_ref()
                .is_none_or(|thread| thread.is_finished())
        {
            bail!("The command worker has stopped.");
        }
        if interrupt {
            if let Some(running) = &queue.running {
                running.store(true, Ordering::Release);
            }
            if let Some(pending) = queue.pending.take() {
                pending.cancelled.store(true, Ordering::Release);
            }
        } else if queue.pending.is_some() {
            bail!("The command queue is full.");
        }
        queue.pending = Some(Job {
            id,
            work,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        self.next_id = id.0;
        self.shared.ready.notify_one();
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
        Ok(id)
    }

    pub fn take_update(&self) -> Result<Option<Update>> {
        Ok(self
            .shared
            .update
            .lock()
            .map_err(|_| anyhow::anyhow!("The command result was poisoned."))?
            .take())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // A poisoned queue still needs to cancel and reap its child on shutdown.
        let mut queue = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        queue.closing = true;
        if let Some(running) = &queue.running {
            running.store(true, Ordering::Release);
        }
        queue.pending = None;
        self.shared.ready.notify_one();
        drop(queue);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("The command worker failed: {error:#}"),
                Err(_) => eprintln!("The command worker panicked."),
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
    let launch_at_login = match process_with_timeout(
        Path::new("schtasks.exe"),
        &words(&["/Query", "/TN", STARTUP_TASK]),
        cancelled,
        Duration::from_secs(5),
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
    let output = process_with_timeout(ray, &words(args), cancelled, Duration::from_secs(8))?
        .into_result()?;
    serde_json::from_str(&output).context("reading the ray command's JSON response")
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
    use std::sync::mpsc::{TryRecvError, sync_channel};

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
        let (sender, receiver) = sync_channel(1);
        let mut worker = Worker::start(
            PathBuf::from("nonexistent-ray-command"),
            PathBuf::new(),
            move || {
                sender.send(()).unwrap();
            },
        )
        .unwrap();
        let id = worker.submit(Work::Refresh).unwrap();
        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        let update = worker.take_update().unwrap().unwrap();
        assert_eq!(update.id, id);
        assert!(update.snapshot.is_err());
        assert!(update.output.is_none());
        assert!(!update.quit);
        drop(worker);
    }

    #[test]
    fn disconnect_and_quit_preempt_a_running_command_and_discard_its_result() {
        for priority in [Work::Disconnect, Work::Quit] {
            let (started, waiting) = sync_channel(1);
            let (done, completed) = sync_channel(1);
            let mut worker = Worker::start_with(
                move |id, work, cancelled| match work {
                    Work::Run(_) => {
                        started.send(()).unwrap();
                        while !cancelled.load(Ordering::Acquire) {
                            thread::park();
                        }
                        Update {
                            id,
                            snapshot: Err("cancelled".into()),
                            output: Some(Err("cancelled".into())),
                            quit: false,
                        }
                    }
                    Work::Disconnect | Work::Quit => Update {
                        id,
                        snapshot: Ok(Box::new(crate::preview::fixture(false))),
                        output: Some(Ok("Disconnected.".into())),
                        quit: matches!(work, Work::Quit),
                    },
                    _ => panic!("unexpected work"),
                },
                move || {
                    done.send(()).unwrap();
                },
            )
            .unwrap();
            worker
                .submit(Work::Run(words(&["join", "example-invite"])))
                .unwrap();
            waiting.recv_timeout(Duration::from_secs(5)).unwrap();
            let quitting = matches!(priority, Work::Quit);
            let id = worker.interrupt(priority).unwrap();
            completed.recv_timeout(Duration::from_secs(5)).unwrap();
            let update = worker.take_update().unwrap().unwrap();
            assert_eq!(update.id, id);
            assert_eq!(update.quit, quitting);
            assert_eq!(update.output.unwrap().unwrap(), "Disconnected.");
            assert_eq!(completed.try_recv(), Err(TryRecvError::Empty));
        }
    }

    #[test]
    fn dropping_a_busy_worker_cancels_and_joins_its_thread() {
        let (started, waiting) = sync_channel(1);
        let worker = Worker::start_with(
            move |id, _, cancelled| {
                started.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    thread::park();
                }
                Update {
                    id,
                    snapshot: Err("cancelled".into()),
                    output: None,
                    quit: false,
                }
            },
            || panic!("a cancelled result must not reach the UI"),
        )
        .unwrap();
        let mut worker = worker;
        worker.submit(Work::Refresh).unwrap();
        waiting.recv_timeout(Duration::from_secs(5)).unwrap();
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
