use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::io::Error as IoError;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ray_proto::Action;
use ray_proto::ipc::{FirewallRuleView, NetworkRole, NetworkStatus};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::run_return::EventLoopExtRunReturn;
use tao::platform::windows::{EventLoopBuilderExtWindows, WindowExtWindows};
use tao::window::{Icon as WindowIcon, Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon as TrayIconImage, TrayIconBuilder};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, IDOK, IsDialogMessageW, MB_ICONERROR, MB_OK, MB_OKCANCEL, MSG, MessageBoxW,
    SW_RESTORE, SetForegroundWindow, ShowWindow,
};

use crate::backend::{Update, Work, Worker};
use crate::controls::{Id, NativeUi, Page, wide};
use crate::forms::{FormKind, console_args};
use crate::model::{PendingKind, Snapshot, words};

const ICON_PNG: &[u8] =
    include_bytes!("../../macos/Rayfish/Assets.xcassets/AppIcon.appiconset/icon-64.png");
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum UserEvent {
    Show,
    Control(Id),
    Updated(Update),
    Toggle,
    Quit,
}

struct AppInstance(HANDLE);

impl AppInstance {
    fn acquire() -> Result<Option<Self>> {
        let name = wide("Local\\RayfishDesktopApp");
        // SAFETY: name is terminated and no security attributes are supplied.
        let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(IoError::last_os_error()).context("creating the app mutex");
        }
        // SAFETY: GetLastError is read immediately after successful CreateMutexW.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: This is the handle just returned by CreateMutexW.
            unsafe {
                CloseHandle(handle);
            }
            let title = wide("Rayfish");
            // SAFETY: FindWindowW receives a terminated title. The found window
            // is used only through APIs that validate its handle.
            unsafe {
                let window = FindWindowW(null(), title.as_ptr());
                if !window.is_null() {
                    ShowWindow(window, SW_RESTORE);
                    SetForegroundWindow(window);
                }
            }
            return Ok(None);
        }
        Ok(Some(Self(handle)))
    }
}

impl Drop for AppInstance {
    fn drop(&mut self) {
        // SAFETY: This instance owns the live mutex handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct App {
    ui: NativeUi,
    worker: Worker,
    snapshot: Option<Box<Snapshot>>,
    busy: bool,
    network: Option<String>,
    device: Option<String>,
    pending: Option<PendingKind>,
    rule: Option<FirewallRuleView>,
    form_network: Option<String>,
    submitted_form: bool,
    next_refresh: Instant,
    state_item: MenuItem,
    connection_item: MenuItem,
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
    let panel = Rc::new(Cell::new(null_mut::<c_void>()));
    let keyboard_panel = panel.clone();
    let mut builder = EventLoopBuilder::<UserEvent>::with_user_event();
    builder.with_msg_hook(move |message| {
        let panel = keyboard_panel.get();
        // SAFETY: tao supplies a valid MSG for this call. panel is either null
        // or the live native panel on this thread. Dialog navigation supplies
        // native Tab, Shift+Tab, Enter, Escape and keyboard mnemonics.
        !panel.is_null() && unsafe { IsDialogMessageW(panel, message.cast::<MSG>()) != 0 }
    });
    let mut event_loop = builder.build();
    let image = image::load_from_memory(ICON_PNG)
        .context("decoding the app icon")?
        .into_rgba8();
    let (width, height) = image.dimensions();
    let rgba = image.into_raw();
    let window = WindowBuilder::new()
        .with_title("Rayfish")
        .with_inner_size(LogicalSize::new(1040.0, 720.0))
        .with_min_inner_size(LogicalSize::new(860.0, 640.0))
        .with_window_icon(Some(WindowIcon::from_rgba(rgba.clone(), width, height)?))
        .build(&event_loop)
        .context("creating the Rayfish window")?;
    let proxy = event_loop.create_proxy();
    let mut ui = NativeUi::new(window.hwnd() as HWND, move |id| {
        // A closed event loop means the app is already shutting down.
        let _ = proxy.send_event(UserEvent::Control(id));
    })?;
    panel.set(ui.panel());
    let size = window.inner_size();
    ui.layout(size.width, size.height, window.scale_factor())?;
    ui.set_text(
        Id::OUTPUT,
        "Enter a ray command above. Output appears here.\nSelect text and press Ctrl+C to copy it.",
    );

    let state_item = MenuItem::with_id(MenuId::new("state"), "Rayfish: Checking...", false, None);
    let connection_id = MenuId::new("connection");
    let open_id = MenuId::new("open");
    let quit_id = MenuId::new("quit");
    let connection_item = MenuItem::with_id(connection_id.clone(), "Connect", false, None);
    let open_item = MenuItem::with_id(open_id.clone(), "Open Rayfish", true, None);
    let quit_item = MenuItem::with_id(quit_id.clone(), "Disconnect and Quit", true, None);
    let tray_menu = Menu::new();
    tray_menu.append_items(&[
        &state_item,
        &connection_item,
        &PredefinedMenuItem::separator(),
        &open_item,
        &PredefinedMenuItem::separator(),
        &quit_item,
    ])?;
    let tray = TrayIconBuilder::new()
        .with_tooltip("Rayfish")
        .with_icon(TrayIconImage::from_rgba(rgba, width, height)?)
        .with_menu(Box::new(tray_menu))
        .with_menu_on_left_click(true)
        .build()?;
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let event = if event.id == open_id {
            UserEvent::Show
        } else if event.id == connection_id {
            UserEvent::Toggle
        } else if event.id == quit_id {
            UserEvent::Quit
        } else {
            return;
        };
        // A closed event loop means the app is already shutting down.
        let _ = proxy.send_event(event);
    }));
    let proxy = event_loop.create_proxy();
    let worker = Worker::start(ray, executable, move |update| {
        proxy.send_event(UserEvent::Updated(update)).is_ok()
    })?;
    let mut app = App {
        ui,
        worker,
        snapshot: None,
        busy: false,
        network: None,
        device: None,
        pending: None,
        rule: None,
        form_network: None,
        submitted_form: false,
        next_refresh: Instant::now(),
        state_item,
        connection_item,
    };
    app.start(Work::Refresh)?;
    event_loop.run_return(|event, _, flow| {
        let _keep_alive = (&instance, &tray);
        *flow = ControlFlow::WaitUntil(app.next_refresh);
        let result = match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                window.set_visible(false);
                Ok(())
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(size),
                ..
            } => app
                .ui
                .layout(size.width, size.height, window.scale_factor()),
            Event::WindowEvent {
                event:
                    WindowEvent::ScaleFactorChanged {
                        new_inner_size,
                        scale_factor,
                    },
                ..
            } => app
                .ui
                .layout(new_inner_size.width, new_inner_size.height, scale_factor),
            Event::UserEvent(UserEvent::Show) => {
                show_window(&window);
                Ok(())
            }
            Event::UserEvent(UserEvent::Control(id)) => app.control(id),
            Event::UserEvent(UserEvent::Toggle) => app.toggle(),
            Event::UserEvent(UserEvent::Quit) if !app.busy => app.start(Work::Quit),
            Event::UserEvent(UserEvent::Updated(update)) => {
                if update.quit {
                    *flow = ControlFlow::Exit;
                } else {
                    app.updated(update);
                }
                Ok(())
            }
            Event::MainEventsCleared if Instant::now() >= app.next_refresh => {
                app.next_refresh = Instant::now() + REFRESH_INTERVAL;
                if !app.busy {
                    app.start(Work::Refresh)
                } else {
                    Ok(())
                }
            }
            Event::LoopDestroyed => {
                panel.set(null_mut());
                Ok(())
            }
            _ => Ok(()),
        };
        if let Err(error) = result {
            app.ui.set_text(Id::NOTICE, &format!("{error:#}"));
        }
    });
    panel.set(null_mut());
    drop(app);
    Ok(())
}

impl App {
    fn start(&mut self, work: Work) -> Result<()> {
        if self.busy {
            return Ok(());
        }
        self.worker.submit(work)?;
        self.busy = true;
        self.ui.set_text(Id::NOTICE, "Working...");
        self.enable_actions();
        Ok(())
    }

    fn toggle(&mut self) -> Result<()> {
        let Some(snapshot) = &self.snapshot else {
            return Ok(());
        };
        self.start(Work::Run(words(&[if snapshot.status.active {
            "down"
        } else {
            "up"
        }])))
    }

    fn control(&mut self, id: Id) -> Result<()> {
        if let Some(page) = Page::ALL.into_iter().find(|page| page.navigation() == id) {
            self.ui.show_page(page);
            self.render();
            return Ok(());
        }
        match id {
            Id::NETWORK_LIST => {
                self.network = self.snapshot.as_ref().and_then(|snapshot| {
                    self.ui
                        .selection(id)
                        .and_then(|index| networks(snapshot).nth(index))
                        .map(|network| network.name.clone())
                });
                self.render_network_detail();
            }
            Id::DEVICE_LIST => {
                self.device = self.snapshot.as_ref().and_then(|snapshot| {
                    self.ui.selection(id).and_then(|index| {
                        device_rows(snapshot).get(index).map(|row| row.key.clone())
                    })
                });
                self.render_device_detail();
            }
            Id::REQUEST_LIST => {
                self.pending = self.snapshot.as_ref().and_then(|snapshot| {
                    self.ui
                        .selection(id)
                        .and_then(|index| snapshot.pending.get(index))
                        .map(|request| request.kind.clone())
                })
            }
            Id::FIREWALL_LIST => {
                self.rule = self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.firewall.as_ref().ok())
                    .and_then(|firewall| {
                        self.ui
                            .selection(id)
                            .and_then(|index| firewall.rules.get(index))
                    })
                    .cloned()
            }
            _ if self.busy => return Ok(()),
            Id::POWER => return self.toggle(),
            Id::REFRESH => return self.start(Work::Refresh),
            Id::CREATE => self.ui.show_form(FormKind::Create, ""),
            Id::JOIN => self.ui.show_form(FormKind::Join, ""),
            Id::CONNECT => self.ui.show_form(FormKind::Connect, ""),
            Id::RENAME => {
                if let Some(network) = self.selected_network() {
                    let initial = network.my_hostname.clone().unwrap_or_default();
                    self.form_network = Some(network.name.clone());
                    self.ui.show_form(FormKind::Rename, &initial);
                }
            }
            Id::ADD_RULE => self.ui.show_form(FormKind::Firewall, ""),
            Id::CANCEL => {
                self.ui.show_page(self.ui.page);
                self.render();
            }
            Id::SAVE => {
                if let Some(kind) = self.ui.form {
                    let args =
                        kind.command(&self.ui.form_values(kind), self.form_network.as_deref())?;
                    self.start(Work::Run(args))?;
                    self.submitted_form = true;
                } else if self.ui.page == Page::Console {
                    return self.run_console();
                }
            }
            Id::INVITE => {
                if let Some(network) = self.network.clone() {
                    self.ui.show_page(Page::Console);
                    return self.start(Work::Run(words(&["invite", &network])));
                }
            }
            Id::LEAVE => {
                if let Some(network) = self.network.clone()
                    && confirm(self.ui.panel(), &format!("Leave {network} on this PC?"))
                {
                    return self.start(Work::Run(words(&["leave", &network])));
                }
            }
            Id::ACCEPT | Id::DENY | Id::REVIEW => {
                if let Some(request) = self.snapshot.as_ref().and_then(|snapshot| {
                    snapshot
                        .pending
                        .iter()
                        .find(|request| Some(&request.kind) == self.pending.as_ref())
                }) {
                    let command = if id == Id::REVIEW {
                        request.review_command()
                    } else {
                        Some(request.command(id == Id::ACCEPT))
                    };
                    if let Some(args) = command {
                        if id == Id::REVIEW {
                            self.ui.show_page(Page::Console);
                        } else if id == Id::ACCEPT
                            && matches!(request.kind, PendingKind::Firewall { .. })
                            && !confirm(
                                self.ui.panel(),
                                "Accept these suggested firewall rules? They can open ports to peers.",
                            )
                        {
                            return Ok(());
                        }
                        return self.start(Work::Run(args));
                    }
                }
            }
            Id::REMOVE_RULE => {
                if let Some(index) = self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.firewall.as_ref().ok())
                    .and_then(|firewall| {
                        firewall
                            .rules
                            .iter()
                            .position(|rule| Some(rule) == self.rule.as_ref())
                    })
                {
                    return self.start(Work::Run(words(&[
                        "firewall",
                        "remove",
                        &index.to_string(),
                    ])));
                }
            }
            Id::FIREWALL_DEFAULT => {
                if let Some(firewall) = self
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.firewall.as_ref().ok())
                {
                    let next = if firewall.default_inbound == Action::Deny {
                        "allow"
                    } else {
                        "deny"
                    };
                    if confirm(
                        self.ui.panel(),
                        &format!("Change the default inbound firewall policy to {next}?"),
                    ) {
                        return self.start(Work::Run(words(&["firewall", "default", next])));
                    }
                }
            }
            Id::DNS | Id::MDNS | Id::AUTO_UPDATE => {
                let command = match id {
                    Id::DNS => "dns",
                    Id::MDNS => "mdns",
                    _ => "auto-update",
                };
                let value = if self.ui.checked(id) {
                    if id == Id::DNS { "partial" } else { "on" }
                } else {
                    "off"
                };
                return self.start(Work::Run(words(&[command, value])));
            }
            Id::STARTUP => return self.start(Work::Startup(self.ui.checked(id))),
            Id::RUN => return self.run_console(),
            _ => {}
        }
        self.enable_actions();
        Ok(())
    }

    fn run_console(&mut self) -> Result<()> {
        self.start(Work::Run(console_args(&self.ui.text(Id::COMMAND))?))
    }

    fn updated(&mut self, update: Update) {
        self.busy = false;
        self.next_refresh = Instant::now() + REFRESH_INTERVAL;
        let output = update.output;
        if self.submitted_form && output.as_ref().is_some_and(Result::is_ok) {
            self.ui.show_page(self.ui.page);
        }
        self.submitted_form = false;
        match update.snapshot {
            Ok(snapshot) => {
                self.snapshot = Some(snapshot);
                self.render();
            }
            Err(error) => {
                self.snapshot = None;
                self.network = None;
                self.device = None;
                self.pending = None;
                self.rule = None;
                self.ui.set_text(Id::HEADER, "Rayfish: Service unreachable");
                self.state_item.set_text("Rayfish: Service unreachable");
                self.ui.set_text(Id::NOTICE, &error);
                self.ui.list(Id::NETWORK_LIST, &[], None);
                self.ui.list(Id::DEVICE_LIST, &[], None);
                self.ui.list(Id::REQUEST_LIST, &[], None);
                self.ui.list(Id::FIREWALL_LIST, &[], None);
                self.ui.set_text(Id::IDENTITY, "Identity unavailable");
                for id in [
                    Id::NETWORK_DETAIL,
                    Id::DEVICE_DETAIL,
                    Id::SETTINGS_DETAIL,
                    Id::FIREWALL_SUMMARY,
                ] {
                    self.ui.set_text(id, &error);
                }
            }
        }
        if let Some(output) = output {
            let text = match output {
                Ok(text) => {
                    if text.is_empty() {
                        "Done.".into()
                    } else {
                        text
                    }
                }
                Err(error) => error,
            };
            self.ui.set_text(Id::OUTPUT, &text);
            self.ui
                .set_text(Id::NOTICE, text.lines().next().unwrap_or("Done."));
        }
        self.enable_actions();
    }

    fn selected_network(&self) -> Option<&NetworkStatus> {
        self.snapshot.as_ref().and_then(|snapshot| {
            networks(snapshot).find(|network| Some(&network.name) == self.network.as_ref())
        })
    }

    fn render(&mut self) {
        let Some(snapshot) = &self.snapshot else {
            self.enable_actions();
            return;
        };
        let state = if snapshot.status.active {
            "Connected"
        } else {
            "Standby"
        };
        self.ui.set_text(Id::HEADER, &format!("Rayfish: {state}"));
        self.state_item.set_text(format!("Rayfish: {state}"));
        let action = if snapshot.status.active {
            "Disconnect"
        } else {
            "Connect"
        };
        self.ui.set_text(Id::POWER, action);
        self.connection_item.set_text(action);
        let network_list: Vec<_> = networks(snapshot)
            .map(|network| format!("{} ({})", network.name, network.role))
            .collect();
        let selected = networks(snapshot)
            .position(|network| Some(&network.name) == self.network.as_ref())
            .or_else(|| (!network_list.is_empty()).then_some(0));
        self.network = selected
            .and_then(|index| networks(snapshot).nth(index))
            .map(|network| network.name.clone());
        self.ui.list(Id::NETWORK_LIST, &network_list, selected);
        self.render_network_detail();
        let devices = device_rows(snapshot);
        let selected = devices
            .iter()
            .position(|row| Some(&row.key) == self.device.as_ref())
            .or_else(|| (!devices.is_empty()).then_some(0));
        self.ui.list(
            Id::DEVICE_LIST,
            &devices
                .iter()
                .map(|row| row.label.clone())
                .collect::<Vec<_>>(),
            selected,
        );
        self.render_device_detail();
        self.ui.set_text(
            Id::IDENTITY,
            snapshot
                .status
                .identity
                .as_deref()
                .unwrap_or("Identity unavailable"),
        );
        let selected = snapshot
            .pending
            .iter()
            .position(|request| Some(&request.kind) == self.pending.as_ref());
        let mut requests = snapshot
            .pending
            .iter()
            .map(|request| request.description.clone())
            .collect::<Vec<_>>();
        if requests.is_empty() {
            requests.push("No pending requests.".into());
        }
        self.ui.list(Id::REQUEST_LIST, &requests, selected);
        if selected.is_none() {
            self.pending = None;
        }
        match &snapshot.firewall {
            Ok(firewall) => {
                self.ui.set_text(
                    Id::FIREWALL_SUMMARY,
                    &format!(
                        "Default inbound: {}    Default outbound: {}",
                        firewall.default_inbound, firewall.default_outbound
                    ),
                );
                let mut rows = firewall
                    .rules
                    .iter()
                    .map(|rule| {
                        format!(
                            "{} {} {} {}    peer: {}    network: {}",
                            rule.direction,
                            rule.action,
                            rule.protocol,
                            rule.port,
                            rule.peer,
                            rule.network
                        )
                    })
                    .collect::<Vec<_>>();
                if rows.is_empty() {
                    rows.push(
                        "No firewall rules. Use Add rule to allow or deny mesh traffic.".into(),
                    );
                }
                let selected = firewall
                    .rules
                    .iter()
                    .position(|rule| Some(rule) == self.rule.as_ref());
                self.ui.list(Id::FIREWALL_LIST, &rows, selected);
                if selected.is_none() {
                    self.rule = None;
                }
            }
            Err(error) => {
                self.ui.set_text(Id::FIREWALL_SUMMARY, error);
                self.ui.list(Id::FIREWALL_LIST, &[], None);
            }
        }
        for (id, key) in [
            (Id::DNS, "dns"),
            (Id::MDNS, "mdns"),
            (Id::AUTO_UPDATE, "auto-update"),
        ] {
            self.ui.check(id, snapshot.enabled(key));
        }
        self.ui.check(Id::STARTUP, snapshot.launch_at_login);
        let mut settings = String::from(
            "The Windows service manages your VPN connection. Closing the window keeps Rayfish in the tray.\n\nMagic DNS\nResolve .ray names without changing your other DNS lookups.\n\nmDNS discovery\nFind Rayfish peers on the local network.\n\nAutomatic updates\nKeep Rayfish up to date.\n\nStart at login\nOpen the desktop app when you sign in to Windows.",
        );
        if let Err(error) = &snapshot.config {
            settings.push_str(&format!("\n\nCould not read settings: {error}"));
        }
        self.ui.set_text(Id::SETTINGS_DETAIL, &settings);
        let notice = if snapshot.warnings.is_empty() {
            format!(
                "{} networks, {} pending requests. Select an item to manage it.",
                network_list.len(),
                snapshot.pending.len()
            )
        } else {
            snapshot.warnings.join(" ")
        };
        self.ui.set_text(Id::NOTICE, &notice);
        self.enable_actions();
    }

    fn render_network_detail(&self) {
        let text = if let Some(network) = self.selected_network() {
            let mut text = format!(
                "{}\nRole: {}\nThis PC: {}\nIPv6: {}\n\n",
                network.name,
                network.role,
                network.my_hostname.as_deref().unwrap_or("Unnamed"),
                network.my_ipv6
            );
            if network.peers.is_empty() {
                text.push_str("Waiting for peers. Use Invite to add a device.\n");
            }
            for peer in &network.peers {
                text.push_str(&format!(
                    "{}    {}\n{}\n",
                    peer.hostname.as_deref().unwrap_or("Unnamed peer"),
                    peer.state,
                    peer.ipv6
                ));
                if let Some(connection) = &peer.connection {
                    let latency = connection
                        .rtt_ms
                        .map_or_else(|| "Unknown".into(), |rtt| format!("{rtt:.0} ms"));
                    text.push_str(&format!("{}    RTT: {latency}\n", connection.conn_type));
                }
                text.push('\n');
            }
            text
        } else {
            "No networks yet. Create a private network or join with an invite code.".into()
        };
        let mut text = text;
        if let Some(snapshot) = &self.snapshot {
            for network in &snapshot.status.inactive_networks {
                text.push_str(&format!(
                    "\n{} is inactive: {}\n",
                    network.name,
                    network.reason.as_deref().unwrap_or("Restoring network")
                ));
            }
            for error in &snapshot.status.connection_errors {
                text.push_str(&format!("\n{}: {}\n", error.peer, error.message));
            }
        }
        self.ui.set_text(Id::NETWORK_DETAIL, &text);
    }

    fn render_device_detail(&self) {
        let rows = self
            .snapshot
            .as_ref()
            .map(|snapshot| device_rows(snapshot))
            .unwrap_or_default();
        let detail = self
            .ui
            .selection(Id::DEVICE_LIST)
            .and_then(|index| rows.get(index));
        self.ui.set_text(
            Id::DEVICE_DETAIL,
            detail.map_or(
                "No devices yet. Devices appear when this PC joins a network.",
                |row| &row.detail,
            ),
        );
    }

    fn enable_actions(&self) {
        let ready = !self.busy;
        let connected = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.status.active);
        let selected = self.selected_network();
        for id in [
            Id::REFRESH,
            Id::CREATE,
            Id::JOIN,
            Id::RUN,
            Id::SAVE,
            Id::CANCEL,
            Id::STARTUP,
        ] {
            self.ui.enable(id, ready);
        }
        self.ui.enable(Id::POWER, ready && self.snapshot.is_some());
        self.connection_item
            .set_enabled(ready && self.snapshot.is_some());
        self.ui.enable(Id::CONNECT, ready && connected);
        self.ui.enable(
            Id::INVITE,
            ready && selected.is_some_and(|network| network.role == NetworkRole::Coordinator),
        );
        for id in [Id::RENAME, Id::LEAVE] {
            self.ui.enable(id, ready && selected.is_some());
        }
        for id in [Id::ACCEPT, Id::DENY] {
            self.ui.enable(id, ready && self.pending.is_some());
        }
        self.ui.enable(
            Id::REVIEW,
            ready && matches!(self.pending, Some(PendingKind::Firewall { .. })),
        );
        let firewall = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.firewall.is_ok());
        for id in [Id::ADD_RULE, Id::FIREWALL_DEFAULT] {
            self.ui.enable(id, ready && firewall);
        }
        self.ui
            .enable(Id::REMOVE_RULE, ready && firewall && self.rule.is_some());
        let config = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.config.is_ok());
        for id in [Id::DNS, Id::MDNS, Id::AUTO_UPDATE] {
            self.ui.enable(id, ready && config);
        }
    }
}

fn networks(snapshot: &Snapshot) -> impl Iterator<Item = &NetworkStatus> {
    snapshot.status.networks.iter().chain(
        snapshot
            .status
            .inactive_networks
            .iter()
            .filter_map(|network| network.saved.as_ref()),
    )
}

struct DeviceRow {
    key: String,
    label: String,
    detail: String,
}

fn device_rows(snapshot: &Snapshot) -> Vec<DeviceRow> {
    let mut rows = BTreeMap::new();
    for machine in snapshot.status.managed_machines.iter().flatten() {
        let state: &str = machine.state.into();
        let key = machine.identity.to_string();
        rows.insert(
            key.clone(),
            DeviceRow {
                key,
                label: format!("{} ({state})", machine.hostname),
                detail: format!(
                    "{}\nState: {state}\nIdentity: {}\nNetworks: {}",
                    machine.hostname,
                    machine.identity,
                    machine
                        .networks
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            },
        );
    }
    for network in networks(snapshot) {
        for peer in &network.peers {
            let key = peer.endpoint_id.to_string();
            rows.entry(key.clone()).or_insert_with(|| DeviceRow {
                key,
                label: format!(
                    "{} ({})",
                    peer.hostname.as_deref().unwrap_or("Unnamed peer"),
                    peer.state
                ),
                detail: format!(
                    "{}\nNetwork: {}\nIPv6: {}\nIdentity: {}\nState: {}\n{}",
                    peer.hostname.as_deref().unwrap_or("Unnamed peer"),
                    network.name,
                    peer.ipv6,
                    peer.endpoint_id,
                    peer.state,
                    if peer.is_own_device {
                        "Your paired device"
                    } else {
                        ""
                    }
                ),
            });
        }
    }
    rows.into_values().collect()
}

fn show_window(window: &Window) {
    window.set_visible(true);
    window.set_minimized(false);
    window.set_focus();
}

fn confirm(parent: HWND, message: &str) -> bool {
    let title = wide("Rayfish");
    let message = wide(message);
    // SAFETY: parent is live on this thread and both strings are terminated.
    unsafe { MessageBoxW(parent, message.as_ptr(), title.as_ptr(), MB_OKCANCEL) == IDOK }
}

pub(crate) fn show_error(message: &str) {
    let message = wide(message);
    let title = wide("Rayfish");
    // SAFETY: The strings are terminated and a null owner is allowed at startup.
    unsafe {
        MessageBoxW(
            null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
