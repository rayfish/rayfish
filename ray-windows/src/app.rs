use std::io::Error as IoError;
use std::mem::size_of_val;
use std::ptr::{null, null_mut};
use std::sync::mpsc::{Receiver, sync_channel};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use eframe::egui::{Context as UiContext, ViewportCommand};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, MB_ICONERROR, MB_OK, MessageBoxW, PostMessageW, SW_RESTORE, SetForegroundWindow,
    ShowWindow, WM_PAINT,
};

use crate::backend::{Update, Work, WorkId, Worker};
use crate::model::words;
use crate::ui::{Action, Dashboard, OutputKind};

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

struct AppInstance(HANDLE);

impl AppInstance {
    fn acquire() -> Result<Option<Self>> {
        let name = wide("Local\\RayfishDesktopApp");
        // SAFETY: name is terminated and no security attributes are supplied.
        let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(IoError::last_os_error()).context("creating the app mutex");
        }
        // SAFETY: GetLastError is read immediately after CreateMutexW.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: This is the handle just returned by CreateMutexW.
            unsafe {
                CloseHandle(handle);
            }
            show_existing_window();
            return Ok(None);
        }
        Ok(Some(Self(handle)))
    }
}

impl Drop for AppInstance {
    fn drop(&mut self) {
        // SAFETY: This instance owns the mutex handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Clone, Copy)]
enum MenuAction {
    Show,
    Toggle,
    Quit,
}

struct WindowsApp {
    dashboard: Dashboard,
    worker: Worker,
    active_work: Option<WorkId>,
    events: Receiver<MenuAction>,
    state_item: MenuItem,
    connection_item: MenuItem,
    _tray: TrayIcon,
    _instance: AppInstance,
    next_refresh: Instant,
    result_kind: Option<OutputKind>,
    quitting: bool,
}

pub(crate) fn run() -> Result<()> {
    let Some(instance) = AppInstance::acquire()? else {
        return Ok(());
    };
    let executable = std::env::current_exe().context("finding the desktop executable")?;
    let ray = executable.with_file_name("ray.exe");
    if !ray.is_file() {
        anyhow::bail!("The bundled ray.exe was not found. Reinstall Rayfish.");
    }
    let options = crate::window::options()?;
    eframe::run_native(
        "Rayfish",
        options,
        Box::new(move |cc| {
            let dashboard = Dashboard::new(&cc.egui_ctx)?;
            dark_caption();
            let (event_sender, events) = sync_channel(16);
            let state_item =
                MenuItem::with_id(MenuId::new("state"), "Rayfish: Checking...", false, None);
            let connection_id = MenuId::new("connection");
            let open_id = MenuId::new("open");
            let quit_id = MenuId::new("quit");
            let connection_item = MenuItem::with_id(connection_id.clone(), "Connect", false, None);
            let open = MenuItem::with_id(open_id.clone(), "Open Rayfish", true, None);
            let quit = MenuItem::with_id(quit_id.clone(), "Disconnect and Quit", true, None);
            let menu = Menu::new();
            menu.append_items(&[
                &state_item,
                &connection_item,
                &PredefinedMenuItem::separator(),
                &open,
                &PredefinedMenuItem::separator(),
                &quit,
            ])?;
            let image = image::load_from_memory(include_bytes!(
                "../../macos/Rayfish/Assets.xcassets/AppIcon.appiconset/icon-64.png"
            ))?
            .into_rgba8();
            let (width, height) = image.dimensions();
            let tray = TrayIconBuilder::new()
                .with_tooltip("Rayfish")
                .with_icon(Icon::from_rgba(image.into_raw(), width, height)?)
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(true)
                .build()?;
            let ctx = cc.egui_ctx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let action = if event.id == open_id {
                    MenuAction::Show
                } else if event.id == connection_id {
                    MenuAction::Toggle
                } else if event.id == quit_id {
                    MenuAction::Quit
                } else {
                    return;
                };
                if matches!(action, MenuAction::Show) {
                    show_existing_window();
                    ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                }
                // Repeated tray clicks beyond the bounded queue are deliberately ignored.
                let _ = event_sender.try_send(action);
                wake_ui(&ctx);
            }));
            let ctx = cc.egui_ctx.clone();
            let worker = Worker::start(ray, executable, move || wake_ui(&ctx))?;
            let mut app = WindowsApp {
                dashboard,
                worker,
                active_work: None,
                events,
                state_item,
                connection_item,
                _tray: tray,
                _instance: instance,
                next_refresh: Instant::now(),
                result_kind: None,
                quitting: false,
            };
            app.submit(Work::Refresh)?;
            Ok(Box::new(app))
        }),
    )
    .map_err(|error| anyhow::anyhow!("starting the Rayfish desktop window: {error}"))
}

impl WindowsApp {
    fn submit(&mut self, work: Work) -> Result<()> {
        if self.dashboard.busy {
            anyhow::bail!("Wait for the current operation to finish.");
        }
        let refreshing = matches!(work, Work::Refresh);
        self.active_work = Some(if self.active_work.is_some() {
            self.worker.interrupt(work)?
        } else {
            self.worker.submit(work)?
        });
        self.dashboard.busy = !refreshing;
        if !refreshing {
            self.dashboard.error = None;
            self.dashboard.notice = None;
        }
        Ok(())
    }

    fn toggle(&mut self) -> Result<()> {
        if let Some(snapshot) = &self.dashboard.snapshot {
            if snapshot.status.active {
                self.interrupt(Work::Disconnect)?;
            } else {
                self.submit(Work::Run(words(&["up"])))?;
            }
        }
        Ok(())
    }

    fn interrupt(&mut self, work: Work) -> Result<()> {
        self.active_work = Some(self.worker.interrupt(work)?);
        self.dashboard.operation_interrupted();
        self.dashboard.busy = true;
        self.result_kind = None;
        Ok(())
    }

    fn updated(&mut self, update: Update, ctx: &UiContext) {
        if self.active_work != Some(update.id) {
            return;
        }
        self.active_work = None;
        self.dashboard.busy = false;
        self.next_refresh = Instant::now() + REFRESH_INTERVAL;
        if update.quit {
            self.quitting = true;
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return;
        }
        match update.snapshot {
            Ok(snapshot) => self.dashboard.snapshot = Some(snapshot),
            Err(error) => {
                self.dashboard.snapshot = None;
                self.dashboard.error = Some(error);
            }
        }
        if let Some(output) = update.output {
            if output.is_err() {
                show_existing_window();
                ctx.send_viewport_cmd(ViewportCommand::Visible(true));
            }
            let kind = self.result_kind.take();
            self.dashboard.command_finished(output, kind);
        }
    }
}

impl eframe::App for WindowsApp {
    fn update(&mut self, ctx: &UiContext, _frame: &mut eframe::Frame) {
        if ctx.input(|input| input.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(ViewportCommand::Visible(false));
        }
        match self.worker.take_update() {
            Ok(Some(update)) => self.updated(update, ctx),
            Ok(None) => {}
            Err(error) => self.dashboard.error = Some(format!("{error:#}")),
        }
        while let Ok(event) = self.events.try_recv() {
            let result = match event {
                MenuAction::Show => {
                    ctx.send_viewport_cmd(ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(ViewportCommand::Focus);
                    Ok(())
                }
                MenuAction::Toggle => self.toggle(),
                MenuAction::Quit => self.interrupt(Work::Quit),
            };
            if let Err(error) = result {
                self.dashboard.error = Some(format!("{error:#}"));
            }
        }
        for action in self.dashboard.draw(ctx) {
            let result = match action {
                Action::Refresh => self.submit(Work::Refresh),
                Action::Toggle => self.toggle(),
                Action::Run(args) => self.submit(Work::Run(args)),
                Action::Join { args, hostname } => self.submit(Work::Run(args)).map(|()| {
                    self.dashboard.begin_join(hostname);
                    ctx.request_repaint();
                }),
                Action::ShowResult { kind, args } => self
                    .submit(Work::Run(args))
                    .map(|()| self.result_kind = Some(kind)),
                Action::Startup(enabled) => self.submit(Work::Startup(enabled)),
            };
            if let Err(error) = result {
                self.dashboard.error = Some(format!("{error:#}"));
            }
        }
        if Instant::now() >= self.next_refresh && self.active_work.is_none() {
            self.next_refresh = Instant::now() + REFRESH_INTERVAL;
            if let Err(error) = self.submit(Work::Refresh) {
                self.dashboard.error = Some(format!("{error:#}"));
            }
        }
        let state = self
            .dashboard
            .snapshot
            .as_ref()
            .map_or("Service unreachable", |snapshot| {
                if snapshot.status.active {
                    "Connected"
                } else {
                    "Standby"
                }
            });
        self.state_item.set_text(format!("Rayfish: {state}"));
        self.connection_item.set_text(
            if self
                .dashboard
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.status.active)
            {
                "Disconnect"
            } else {
                "Connect"
            },
        );
        self.connection_item.set_enabled(
            self.dashboard
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.status.active || !self.dashboard.busy),
        );
        ctx.request_repaint_after(REFRESH_INTERVAL);
    }
}

fn wake_ui(ctx: &UiContext) {
    ctx.request_repaint();
    let title = wide("Rayfish");
    // SAFETY: The title is terminated, and PostMessage validates the handle.
    // Hidden windows do not receive the normal repaint used by eframe to
    // deliver updates. An explicit paint also processes tray commands and
    // worker completions while the window is hidden.
    unsafe {
        let window = FindWindowW(null(), title.as_ptr());
        if !window.is_null() && PostMessageW(window, WM_PAINT, 0, 0) == 0 {
            eprintln!(
                "Could not wake the desktop window: {}",
                IoError::last_os_error()
            );
        }
    }
}

fn show_existing_window() {
    let title = wide("Rayfish");
    // SAFETY: The title is terminated and these APIs validate the window handle.
    unsafe {
        let window = FindWindowW(null(), title.as_ptr());
        if !window.is_null() {
            ShowWindow(window, SW_RESTORE);
            SetForegroundWindow(window);
        }
    }
}

fn dark_caption() {
    let title = wide("Rayfish");
    let dark = 1_i32;
    // SAFETY: Both buffers outlive the synchronous calls, and the caption
    // belongs to this app's window. Older Windows versions may reject the
    // optional dark-caption attribute; that does not prevent startup.
    unsafe {
        let window = FindWindowW(null(), title.as_ptr());
        if !window.is_null() {
            let _ = DwmSetWindowAttribute(
                window,
                DWMWA_USE_IMMERSIVE_DARK_MODE as u32,
                (&dark as *const i32).cast(),
                size_of_val(&dark) as u32,
            );
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

pub(crate) fn show_error(message: &str) {
    let message = wide(message);
    let title = wide("Rayfish");
    // SAFETY: Both strings are terminated, and a null owner is allowed during startup.
    unsafe {
        MessageBoxW(
            null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::mem::zeroed;

    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, IsWindowVisible, MSG, PM_REMOVE, PeekMessageW,
    };

    use super::*;

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
}
