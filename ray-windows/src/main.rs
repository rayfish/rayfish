#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("rayfish-app is only available on Windows");
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_app::run() {
        windows_app::show_error(&format!("Rayfish could not start.\n\n{error:#}"));
    }
}

#[cfg(windows)]
mod windows_app {
    use std::ffi::OsStr;
    use std::io::{BufRead, BufReader};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::thread;

    use anyhow::{Context, Result};
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::window::{Icon as WindowIcon, Theme, Window, WindowBuilder};
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon as TrayIconImage, TrayIconBuilder};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CreateMutexW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, MB_ICONERROR, MB_OK, MessageBoxW, SW_RESTORE, SetForegroundWindow, ShowWindow,
    };
    use wry::WebViewBuilder;

    const ICON_PNG: &[u8] =
        include_bytes!("../../macos/Rayfish/Assets.xcassets/AppIcon.appiconset/icon-64.png");
    const GUI_PREFIX: &str = "rayfish GUI listening on ";

    #[derive(Debug)]
    enum UserEvent {
        Show,
        ConnectionState(bool),
        ToggleConnection,
        ConnectionChanged { active: bool, error: Option<String> },
        Quit,
        QuitFinished(Option<String>),
    }

    struct GuiServer {
        child: Child,
    }

    struct AppInstance(HANDLE);

    impl AppInstance {
        fn acquire() -> Result<Option<Self>> {
            let name = wide("Local\\RayfishDesktopApp");
            let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
            if handle.is_null() {
                return Err(std::io::Error::last_os_error()).context("creating the app mutex");
            }
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
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
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    impl GuiServer {
        fn start() -> Result<(Self, String)> {
            let ray = ray_executable()?;
            let mut child = Command::new(&ray)
                .args(["gui", "--port", "0", "--no-open"])
                .creation_flags(CREATE_NO_WINDOW)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("starting {}", ray.display()))?;

            let stdout = child
                .stdout
                .take()
                .context("reading the dashboard address")?;
            let mut line = String::new();
            BufReader::new(stdout)
                .read_line(&mut line)
                .context("reading the dashboard address")?;
            let url = line
                .trim()
                .strip_prefix(GUI_PREFIX)
                .context("ray did not report a dashboard address")?
                .to_owned();

            Ok((Self { child }, url))
        }
    }

    impl Drop for GuiServer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    pub(super) fn run() -> Result<()> {
        let Some(instance) = AppInstance::acquire()? else {
            return Ok(());
        };
        let (server, url) = GuiServer::start()?;
        let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        let window_icon = load_window_icon()?;
        let window = WindowBuilder::new()
            .with_title("Rayfish")
            .with_inner_size(LogicalSize::new(1080.0, 720.0))
            .with_min_inner_size(LogicalSize::new(820.0, 560.0))
            .with_theme(Some(Theme::Dark))
            .with_window_icon(Some(window_icon))
            .build(&event_loop)
            .context("creating the Rayfish window")?;
        let proxy = event_loop.create_proxy();
        let webview = WebViewBuilder::new()
            .with_url(url)
            .with_ipc_handler(move |request| {
                let active = match request.body().as_str() {
                    "active" => Some(true),
                    "standby" => Some(false),
                    _ => None,
                };
                if let Some(active) = active {
                    let _ = proxy.send_event(UserEvent::ConnectionState(active));
                }
            })
            .build(&window)
            .context("creating the Rayfish dashboard")?;

        let state_id = MenuId::new("state");
        let connection_id = MenuId::new("connection");
        let open_id = MenuId::new("open");
        let quit_id = MenuId::new("quit");
        let state_item = MenuItem::with_id(state_id, "Rayfish: Checking...", false, None);
        let connection_item = MenuItem::with_id(connection_id.clone(), "Connect", false, None);
        let open_item = MenuItem::with_id(open_id.clone(), "Open Rayfish", true, None);
        let separator = PredefinedMenuItem::separator();
        let footer_separator = PredefinedMenuItem::separator();
        let quit_item = MenuItem::with_id(quit_id.clone(), "Disconnect and Quit", true, None);
        let tray_menu = Menu::new();
        tray_menu.append_items(&[
            &state_item,
            &connection_item,
            &separator,
            &open_item,
            &footer_separator,
            &quit_item,
        ])?;

        let tray_icon = TrayIconBuilder::new()
            .with_tooltip("Rayfish")
            .with_icon(load_tray_icon()?)
            .with_menu(Box::new(tray_menu))
            .with_menu_on_left_click(true)
            .build()
            .context("creating the Rayfish tray icon")?;

        let proxy = event_loop.create_proxy();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if event.id == open_id {
                let _ = proxy.send_event(UserEvent::Show);
            } else if event.id == connection_id {
                let _ = proxy.send_event(UserEvent::ToggleConnection);
            } else if event.id == quit_id {
                let _ = proxy.send_event(UserEvent::Quit);
            }
        }));

        let ray = ray_executable()?;
        let command_proxy = event_loop.create_proxy();
        let mut active = false;
        let mut command_pending = false;
        event_loop.run(move |event, _, control_flow| {
            let _keep_alive = (&instance, &server, &webview, &tray_icon);
            *control_flow = ControlFlow::Wait;
            match event {
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    window_id,
                    ..
                } if window_id == window.id() => window.set_visible(false),
                Event::UserEvent(UserEvent::Show) => show_window(&window),
                Event::UserEvent(UserEvent::ConnectionState(next)) if !command_pending => {
                    active = next;
                    update_connection_menu(&state_item, &connection_item, active, false);
                }
                Event::UserEvent(UserEvent::ToggleConnection) if !command_pending => {
                    command_pending = true;
                    update_connection_menu(&state_item, &connection_item, active, true);
                    change_connection(ray.clone(), !active, command_proxy.clone());
                }
                Event::UserEvent(UserEvent::ConnectionChanged {
                    active: next,
                    error,
                }) => {
                    command_pending = false;
                    if let Some(error) = error {
                        show_error(&error);
                    } else {
                        active = next;
                        let _ = webview.evaluate_script("refresh()");
                    }
                    update_connection_menu(&state_item, &connection_item, active, false);
                }
                Event::UserEvent(UserEvent::Quit) if !command_pending => {
                    command_pending = true;
                    update_connection_menu(&state_item, &connection_item, active, true);
                    disconnect_and_quit(ray.clone(), command_proxy.clone());
                }
                Event::UserEvent(UserEvent::QuitFinished(error)) => {
                    if let Some(error) = error {
                        command_pending = false;
                        update_connection_menu(&state_item, &connection_item, active, false);
                        show_error(&error);
                    } else {
                        *control_flow = ControlFlow::Exit;
                    }
                }
                _ => {}
            }
        });
    }

    fn ray_executable() -> Result<PathBuf> {
        let app = std::env::current_exe().context("finding the Rayfish app executable")?;
        let ray = app.with_file_name("ray.exe");
        if !ray.is_file() {
            anyhow::bail!("{} was not found", ray.display());
        }
        Ok(ray)
    }

    fn show_window(window: &Window) {
        window.set_visible(true);
        window.set_minimized(false);
        window.set_focus();
    }

    fn show_existing_window() {
        let title = wide("Rayfish");
        let window = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
        if !window.is_null() {
            unsafe {
                ShowWindow(window, SW_RESTORE);
                SetForegroundWindow(window);
            }
        }
    }

    fn update_connection_menu(
        state_item: &MenuItem,
        connection_item: &MenuItem,
        active: bool,
        pending: bool,
    ) {
        state_item.set_text(if pending {
            "Rayfish: Updating..."
        } else if active {
            "Rayfish: Connected"
        } else {
            "Rayfish: Standby"
        });
        connection_item.set_text(if active { "Disconnect" } else { "Connect" });
        connection_item.set_enabled(!pending);
    }

    fn change_connection(
        ray: PathBuf,
        active: bool,
        proxy: tao::event_loop::EventLoopProxy<UserEvent>,
    ) {
        thread::spawn(move || {
            let error = set_connection(&ray, active)
                .err()
                .map(|error| error.to_string());
            let _ = proxy.send_event(UserEvent::ConnectionChanged { active, error });
        });
    }

    fn disconnect_and_quit(ray: PathBuf, proxy: tao::event_loop::EventLoopProxy<UserEvent>) {
        thread::spawn(move || {
            let error = set_connection(&ray, false)
                .err()
                .map(|error| error.to_string());
            let _ = proxy.send_event(UserEvent::QuitFinished(error));
        });
    }

    fn set_connection(ray: &Path, active: bool) -> Result<()> {
        let action = if active { "up" } else { "down" };
        let output = Command::new(ray)
            .arg(action)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .with_context(|| format!("running ray {action}"))?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            anyhow::bail!(
                "Rayfish could not {}.{}{}",
                if active { "connect" } else { "disconnect" },
                if message.is_empty() { "" } else { "\n\n" },
                message
            );
        }
        Ok(())
    }

    fn icon_rgba() -> Result<(Vec<u8>, u32, u32)> {
        let image = image::load_from_memory(ICON_PNG)
            .context("decoding the Rayfish icon")?
            .into_rgba8();
        let (width, height) = image.dimensions();
        Ok((image.into_raw(), width, height))
    }

    fn load_window_icon() -> Result<WindowIcon> {
        let (rgba, width, height) = icon_rgba()?;
        WindowIcon::from_rgba(rgba, width, height).context("creating the window icon")
    }

    fn load_tray_icon() -> Result<TrayIconImage> {
        let (rgba, width, height) = icon_rgba()?;
        TrayIconImage::from_rgba(rgba, width, height).context("creating the tray icon")
    }

    pub(super) fn show_error(message: &str) {
        let message = wide(message);
        let title = wide("Rayfish");
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }
}
