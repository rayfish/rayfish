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
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use anyhow::{Context, Result};
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tao::window::{Icon as WindowIcon, Theme, Window, WindowBuilder};
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
    use tray_icon::{
        Icon as TrayIconImage, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent,
    };
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
        Quit,
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
        let webview = WebViewBuilder::new()
            .with_url(url)
            .build(&window)
            .context("creating the Rayfish dashboard")?;

        let open_id = MenuId::new("open");
        let quit_id = MenuId::new("quit");
        let open_item = MenuItem::with_id(open_id.clone(), "Open Rayfish", true, None);
        let separator = PredefinedMenuItem::separator();
        let quit_item = MenuItem::with_id(quit_id.clone(), "Quit", true, None);
        let tray_menu = Menu::new();
        tray_menu.append_items(&[&open_item, &separator, &quit_item])?;

        let tray_icon = TrayIconBuilder::new()
            .with_tooltip("Rayfish")
            .with_icon(load_tray_icon()?)
            .with_menu(Box::new(tray_menu))
            .with_menu_on_left_click(false)
            .build()
            .context("creating the Rayfish tray icon")?;

        let proxy = event_loop.create_proxy();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let should_show = matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } | TrayIconEvent::DoubleClick {
                    button: MouseButton::Left,
                    ..
                }
            );
            if should_show {
                let _ = proxy.send_event(UserEvent::Show);
            }
        }));

        let proxy = event_loop.create_proxy();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if event.id == open_id {
                let _ = proxy.send_event(UserEvent::Show);
            } else if event.id == quit_id {
                let _ = proxy.send_event(UserEvent::Quit);
            }
        }));

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
                Event::UserEvent(UserEvent::Quit) => *control_flow = ControlFlow::Exit,
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
