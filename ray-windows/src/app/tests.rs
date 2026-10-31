use std::mem::zeroed;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, IsWindowVisible, MSG, PM_REMOVE, PeekMessageW, SW_SHOW,
    ShowWindowAsync, WM_CLOSE,
};
use winit::platform::windows::EventLoopBuilderExtWindows;

use super::*;

const CLOSE_TEST_TITLE: &str = "Rayfish hidden quit regression";
const CLOSE_DEADLINE: Duration = Duration::from_secs(30);

#[test]
fn tray_and_worker_updates_wake_a_hidden_window() {
    let class = wide("STATIC");
    let title = wide("Rayfish");
    // SAFETY: STATIC is a system window class. The strings and message
    // buffer outlive these calls, and the test destroys the window it owns.
    unsafe {
        let window = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            100,
            100,
            null_mut(),
            null_mut(),
            null_mut(),
            null(),
        );
        assert!(!window.is_null());
        assert_eq!(IsWindowVisible(window), 0);
        wake_ui(&UiContext::default());
        let mut message: MSG = zeroed();
        assert_ne!(
            PeekMessageW(&mut message, window, WM_PAINT, WM_PAINT, PM_REMOVE),
            0
        );
        assert_eq!(IsWindowVisible(window), 0);
        assert_ne!(DestroyWindow(window), 0);
    }
}

#[derive(Default)]
struct CloseObservations {
    hidden: AtomicBool,
    close_event: AtomicBool,
    timed_out: AtomicBool,
    thread_panicked: AtomicBool,
}

enum ClosePhase {
    Hide,
    Hidden,
    Waiting,
    Closing,
}

struct CloseProbe {
    phase: ClosePhase,
    observations: Arc<CloseObservations>,
    hidden: Option<SyncSender<()>>,
    quit: Receiver<()>,
    finished: Option<SyncSender<()>>,
    worker: Option<JoinHandle<()>>,
    watchdog: Option<JoinHandle<()>>,
}

impl eframe::App for CloseProbe {
    fn update(&mut self, ctx: &UiContext, _frame: &mut eframe::Frame) {
        match self.phase {
            ClosePhase::Hide => {
                ctx.send_viewport_cmd(ViewportCommand::Visible(false));
                self.phase = ClosePhase::Hidden;
                wake_ui(ctx);
            }
            ClosePhase::Hidden => {
                let window = close_test_window();
                assert!(!window.is_null(), "the eframe root window must exist");
                // SAFETY: The lookup returned the live window owned by this test.
                assert_eq!(
                    unsafe { IsWindowVisible(window) },
                    0,
                    "the test must exercise a hidden root"
                );
                self.observations.hidden.store(true, Ordering::Release);
                self.hidden.take().unwrap().send(()).unwrap();
                self.phase = ClosePhase::Waiting;
            }
            ClosePhase::Waiting => {
                if self.quit.try_recv().is_ok() {
                    self.phase = ClosePhase::Closing;
                    request_close(ctx);
                    return;
                }
            }
            ClosePhase::Closing => {
                if ctx.input(|input| input.viewport().close_requested()) {
                    self.observations.close_event.store(true, Ordering::Release);
                }
                return;
            }
        }
        eframe::egui::CentralPanel::default().show(ctx, |ui| {
            ui.label("Hidden root quit regression");
        });
    }
}

impl Drop for CloseProbe {
    fn drop(&mut self) {
        // Dropping these senders also releases the threads if eframe exits early.
        drop(self.hidden.take());
        drop(self.finished.take());
        for handle in [self.worker.take(), self.watchdog.take()]
            .into_iter()
            .flatten()
        {
            if handle.join().is_err() {
                self.observations
                    .thread_panicked
                    .store(true, Ordering::Release);
            }
        }
    }
}

fn close_test_window() -> HWND {
    let title = wide(CLOSE_TEST_TITLE);
    // SAFETY: The title is terminated and the returned handle is only used with
    // APIs that validate it. The unique name cannot target the installed app.
    unsafe { FindWindowW(null(), title.as_ptr()) }
}

#[test]
fn hidden_root_consumes_the_background_quit_close_event_and_exits() {
    let observations = Arc::new(CloseObservations::default());
    let observed = Arc::clone(&observations);
    let mut options = crate::window::options().unwrap();
    options.viewport = options
        .viewport
        .with_title(CLOSE_TEST_TITLE)
        .with_inner_size([240.0, 120.0]);
    options.run_and_return = true;
    options.event_loop_builder = Some(Box::new(|builder| {
        builder.with_any_thread(true);
    }));
    let result = eframe::run_native(
        CLOSE_TEST_TITLE,
        options,
        Box::new(move |cc| {
            let (hidden, hidden_ready) = sync_channel(1);
            let (quit_sender, quit) = sync_channel(1);
            let ctx = cc.egui_ctx.clone();
            let worker = thread::spawn(move || {
                if hidden_ready.recv_timeout(CLOSE_DEADLINE).is_ok() && quit_sender.send(()).is_ok()
                {
                    wake_ui(&ctx);
                }
            });
            let (finished, done) = sync_channel(1);
            let watchdog_observed = Arc::clone(&observed);
            let watchdog = thread::spawn(move || {
                if matches!(
                    done.recv_timeout(CLOSE_DEADLINE),
                    Err(RecvTimeoutError::Timeout)
                ) {
                    watchdog_observed.timed_out.store(true, Ordering::Release);
                    // A broken close sequence must fail the test, not leave its GUI
                    // running. Show and close only the uniquely named test window.
                    let window = close_test_window();
                    if !window.is_null() {
                        // SAFETY: These asynchronous APIs validate the window handle.
                        unsafe {
                            ShowWindowAsync(window, SW_SHOW);
                            PostMessageW(window, WM_CLOSE, 0, 0);
                        }
                    }
                }
            });
            Ok(Box::new(CloseProbe {
                phase: ClosePhase::Hide,
                observations: Arc::clone(&observed),
                hidden: Some(hidden),
                quit,
                finished: Some(finished),
                worker: Some(worker),
                watchdog: Some(watchdog),
            }))
        }),
    );
    result.unwrap();
    assert!(
        !observations.timed_out.load(Ordering::Acquire),
        "the hidden eframe root did not exit before its watchdog"
    );
    assert!(!observations.thread_panicked.load(Ordering::Acquire));
    assert!(
        observations.hidden.load(Ordering::Acquire),
        "the root never entered the hidden state"
    );
    assert!(
        observations.close_event.load(Ordering::Acquire),
        "eframe did not consume the quit Close event"
    );
}
