//! Win32 controls owned by one child panel, on the window's UI thread.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Error as IoError;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{CreateFontIndirectW, DeleteObject, HFONT, InvalidateRect};
use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, SystemParametersInfoForDpi};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

use crate::forms::FormKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Id(u16);

impl Id {
    pub const SAVE: Self = Self(1);
    pub const CANCEL: Self = Self(2);
    pub const HEADER: Self = Self(10);
    pub const POWER: Self = Self(11);
    pub const REFRESH: Self = Self(12);
    pub const NOTICE: Self = Self(13);
    pub const NETWORKS: Self = Self(20);
    pub const DEVICES: Self = Self(21);
    pub const REQUESTS: Self = Self(22);
    pub const FIREWALL: Self = Self(23);
    pub const SETTINGS: Self = Self(24);
    pub const CONSOLE: Self = Self(25);
    pub const NETWORK_LIST: Self = Self(30);
    pub const NETWORK_DETAIL: Self = Self(31);
    pub const CREATE: Self = Self(32);
    pub const JOIN: Self = Self(33);
    pub const INVITE: Self = Self(34);
    pub const RENAME: Self = Self(35);
    pub const LEAVE: Self = Self(36);
    pub const DEVICE_LIST: Self = Self(40);
    pub const DEVICE_DETAIL: Self = Self(41);
    pub const CONNECT: Self = Self(42);
    pub const IDENTITY: Self = Self(43);
    pub const REQUEST_LIST: Self = Self(50);
    pub const ACCEPT: Self = Self(51);
    pub const DENY: Self = Self(52);
    pub const REVIEW: Self = Self(53);
    pub const FIREWALL_LIST: Self = Self(60);
    pub const FIREWALL_DEFAULT: Self = Self(61);
    pub const ADD_RULE: Self = Self(62);
    pub const REMOVE_RULE: Self = Self(63);
    pub const FIREWALL_SUMMARY: Self = Self(64);
    pub const DNS: Self = Self(70);
    pub const MDNS: Self = Self(71);
    pub const AUTO_UPDATE: Self = Self(72);
    pub const STARTUP: Self = Self(73);
    pub const SETTINGS_DETAIL: Self = Self(74);
    pub const COMMAND: Self = Self(80);
    pub const RUN: Self = Self(81);
    pub const OUTPUT: Self = Self(82);
    pub const FORM_TITLE: Self = Self(90);

    const fn form_label(index: u16) -> Self {
        Self(100 + index)
    }
    const fn form_input(index: u16) -> Self {
        Self(110 + index)
    }
    const fn form_choice(index: u16) -> Self {
        Self(120 + index)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Page {
    Networks,
    Devices,
    Requests,
    Firewall,
    Settings,
    Console,
}

impl Page {
    pub const ALL: [Self; 6] = [
        Self::Networks,
        Self::Devices,
        Self::Requests,
        Self::Firewall,
        Self::Settings,
        Self::Console,
    ];

    pub fn navigation(self) -> Id {
        match self {
            Self::Networks => Id::NETWORKS,
            Self::Devices => Id::DEVICES,
            Self::Requests => Id::REQUESTS,
            Self::Firewall => Id::FIREWALL,
            Self::Settings => Id::SETTINGS,
            Self::Console => Id::CONSOLE,
        }
    }

    fn controls(self) -> &'static [Id] {
        match self {
            Self::Networks => &[
                Id::NETWORK_LIST,
                Id::NETWORK_DETAIL,
                Id::CREATE,
                Id::JOIN,
                Id::INVITE,
                Id::RENAME,
                Id::LEAVE,
            ],
            Self::Devices => &[
                Id::DEVICE_LIST,
                Id::DEVICE_DETAIL,
                Id::CONNECT,
                Id::IDENTITY,
            ],
            Self::Requests => &[Id::REQUEST_LIST, Id::ACCEPT, Id::DENY, Id::REVIEW],
            Self::Firewall => &[
                Id::FIREWALL_LIST,
                Id::FIREWALL_DEFAULT,
                Id::ADD_RULE,
                Id::REMOVE_RULE,
                Id::FIREWALL_SUMMARY,
            ],
            Self::Settings => &[
                Id::DNS,
                Id::MDNS,
                Id::AUTO_UPDATE,
                Id::STARTUP,
                Id::SETTINGS_DETAIL,
            ],
            Self::Console => &[Id::COMMAND, Id::RUN, Id::OUTPUT],
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Networks => "Networks",
            Self::Devices => "Devices",
            Self::Requests => "Requests",
            Self::Firewall => "Firewall",
            Self::Settings => "Settings",
            Self::Console => "Console",
        }
    }
}

struct Events {
    notify: Box<dyn Fn(Id)>,
}

pub(crate) struct NativeUi {
    panel: HWND,
    controls: BTreeMap<Id, HWND>,
    events: Box<Events>,
    font: HFONT,
    font_dpi: u32,
    pub page: Page,
    pub form: Option<FormKind>,
    scale: f64,
}

impl NativeUi {
    pub fn new(parent: HWND, notify: impl Fn(Id) + 'static) -> Result<Self> {
        let class = wide("STATIC");
        // SAFETY: The class is a system class, strings are terminated, and parent
        // belongs to this thread. The returned panel is owned by NativeUi.
        let panel = unsafe {
            CreateWindowExW(
                WS_EX_CONTROLPARENT,
                class.as_ptr(),
                null(),
                WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
                0,
                0,
                0,
                0,
                parent,
                null_mut(),
                null_mut(),
                null(),
            )
        };
        if panel.is_null() {
            return Err(IoError::last_os_error()).context("creating the native panel");
        }
        let mut ui = Self {
            panel,
            controls: BTreeMap::new(),
            events: Box::new(Events {
                notify: Box::new(notify),
            }),
            font: null_mut(),
            font_dpi: 0,
            page: Page::Networks,
            form: None,
            scale: 1.0,
        };
        // SAFETY: The boxed callback stays at this address until the subclass is
        // removed in Drop, and all callback invocations stay on this thread.
        if unsafe {
            SetWindowSubclass(
                panel,
                Some(panel_proc),
                1,
                (&*ui.events as *const Events) as usize,
            )
        } == 0
        {
            return Err(IoError::last_os_error()).context("connecting native control events");
        }
        ui.add(Id::HEADER, "STATIC", "Rayfish: Checking...", 0)?;
        ui.button(Id::POWER, "Connect")?;
        ui.button(Id::REFRESH, "Refresh")?;
        for page in Page::ALL {
            ui.button(page.navigation(), page.title())?;
        }
        ui.add(Id::NOTICE, "STATIC", "Reading the Rayfish service...", 0)?;
        for id in [
            Id::NETWORK_LIST,
            Id::DEVICE_LIST,
            Id::REQUEST_LIST,
            Id::FIREWALL_LIST,
        ] {
            ui.add(
                id,
                "LISTBOX",
                "",
                WS_TABSTOP
                    | WS_VSCROLL
                    | WS_HSCROLL
                    | WS_BORDER
                    | LBS_NOTIFY as u32
                    | LBS_NOINTEGRALHEIGHT as u32,
            )?;
        }
        for id in [
            Id::NETWORK_DETAIL,
            Id::DEVICE_DETAIL,
            Id::SETTINGS_DETAIL,
            Id::OUTPUT,
        ] {
            ui.add(
                id,
                "EDIT",
                "",
                WS_TABSTOP
                    | WS_BORDER
                    | WS_VSCROLL
                    | ES_MULTILINE as u32
                    | ES_AUTOVSCROLL as u32
                    | ES_READONLY as u32,
            )?;
        }
        for (id, text) in [
            (Id::CREATE, "Create network"),
            (Id::JOIN, "Join with a code"),
            (Id::INVITE, "Invite"),
            (Id::RENAME, "Rename this PC"),
            (Id::LEAVE, "Leave network"),
            (Id::CONNECT, "Connect to a peer"),
            (Id::ACCEPT, "Accept"),
            (Id::DENY, "Decline"),
            (Id::REVIEW, "Review rules"),
            (Id::FIREWALL_DEFAULT, "Change inbound default"),
            (Id::ADD_RULE, "Add rule"),
            (Id::REMOVE_RULE, "Remove selected rule"),
            (Id::RUN, "Run"),
            (Id::SAVE, "Save"),
            (Id::CANCEL, "Cancel"),
        ] {
            ui.button(id, text)?;
        }
        ui.add(
            Id::IDENTITY,
            "EDIT",
            "",
            WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32 | ES_READONLY as u32,
        )?;
        ui.add(Id::FIREWALL_SUMMARY, "STATIC", "", 0)?;
        for (id, text) in [
            (Id::DNS, "Magic DNS"),
            (Id::MDNS, "mDNS discovery"),
            (Id::AUTO_UPDATE, "Automatic updates"),
            (Id::STARTUP, "Start at login"),
        ] {
            ui.add(id, "BUTTON", text, WS_TABSTOP | BS_AUTOCHECKBOX as u32)?;
        }
        ui.add(
            Id::COMMAND,
            "EDIT",
            "",
            WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32,
        )?;
        ui.add(Id::FORM_TITLE, "STATIC", "", 0)?;
        for index in 0..6 {
            ui.add(Id::form_label(index), "STATIC", "", 0)?;
            ui.add(
                Id::form_input(index),
                "EDIT",
                "",
                WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32,
            )?;
            ui.add(
                Id::form_choice(index),
                "COMBOBOX",
                "",
                WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32,
            )?;
        }
        ui.show_page(Page::Networks);
        Ok(ui)
    }

    pub fn panel(&self) -> HWND {
        self.panel
    }

    fn button(&mut self, id: Id, text: &str) -> Result<()> {
        self.add(id, "BUTTON", text, WS_TABSTOP | BS_PUSHBUTTON as u32)
    }

    fn add(&mut self, id: Id, class: &str, text: &str, style: u32) -> Result<()> {
        let class = wide(class);
        let text = wide(text);
        // SAFETY: The panel is live on this thread and the strings outlive the
        // synchronous call. Child windows are destroyed with the panel.
        let control = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                text.as_ptr(),
                WS_CHILD | style,
                0,
                0,
                0,
                0,
                self.panel,
                usize::from(id.0) as _,
                null_mut(),
                null(),
            )
        };
        if control.is_null() {
            return Err(IoError::last_os_error()).context("creating a native control");
        }
        self.controls.insert(id, control);
        Ok(())
    }

    fn handle(&self, id: Id) -> HWND {
        self.controls[&id]
    }

    fn send(&self, id: Id, message: u32, wparam: usize, lparam: isize) -> isize {
        // SAFETY: Controls are owned by this panel on the calling thread. Each
        // caller supplies the parameters specified for its synchronous message.
        unsafe { SendMessageW(self.handle(id), message, wparam, lparam) }
    }

    pub fn set_text(&self, id: Id, text: &str) {
        let text = text.replace('\n', "\r\n").replace("\r\r\n", "\r\n");
        if self.text(id) == text {
            return;
        }
        let text = wide(&text);
        // SAFETY: The control and terminated buffer are valid during this call.
        unsafe {
            SetWindowTextW(self.handle(id), text.as_ptr());
        }
    }

    pub fn text(&self, id: Id) -> String {
        // SAFETY: The control is live and GetWindowTextW receives a buffer with
        // room for the advertised length plus its terminator.
        unsafe {
            let size = GetWindowTextLengthW(self.handle(id)).saturating_add(1);
            let mut text = vec![0u16; size as usize];
            let length = GetWindowTextW(self.handle(id), text.as_mut_ptr(), size);
            String::from_utf16_lossy(&text[..length as usize])
        }
    }

    pub fn enable(&self, id: Id, enabled: bool) {
        // SAFETY: The control is owned by this panel on this thread.
        unsafe {
            EnableWindow(self.handle(id), i32::from(enabled));
        }
    }

    fn visible(&self, id: Id, visible: bool) {
        // SAFETY: The control is owned by this panel on this thread.
        unsafe {
            ShowWindow(self.handle(id), if visible { SW_SHOW } else { SW_HIDE });
        }
    }

    pub fn checked(&self, id: Id) -> bool {
        self.send(id, BM_GETCHECK, 0, 0) == 1
    }
    pub fn check(&self, id: Id, checked: bool) {
        self.send(id, BM_SETCHECK, usize::from(checked), 0);
    }

    pub fn selection(&self, id: Id) -> Option<usize> {
        usize::try_from(self.send(id, LB_GETCURSEL, 0, 0)).ok()
    }

    pub fn list(&self, id: Id, items: &[String], selected: Option<usize>) {
        self.send(id, WM_SETREDRAW, 0, 0);
        self.send(id, LB_RESETCONTENT, 0, 0);
        for item in items {
            let item = wide(item);
            self.send(id, LB_ADDSTRING, 0, item.as_ptr() as isize);
        }
        if let Some(index) = selected.filter(|index| *index < items.len()) {
            self.send(id, LB_SETCURSEL, index, 0);
        }
        self.send(id, WM_SETREDRAW, 1, 0);
        // SAFETY: A null rectangle invalidates the entire live control.
        unsafe {
            InvalidateRect(self.handle(id), null(), 1);
        }
    }

    pub fn show_page(&mut self, page: Page) {
        self.page = page;
        self.form = None;
        for id in self.controls.keys().copied() {
            let permanent = matches!(id, Id::HEADER | Id::POWER | Id::REFRESH | Id::NOTICE)
                || Page::ALL.iter().any(|page| page.navigation() == id);
            self.visible(id, permanent || page.controls().contains(&id));
        }
        for item in Page::ALL {
            self.enable(item.navigation(), item != page);
        }
        self.focus(page.controls()[0]);
    }

    pub fn show_form(&mut self, kind: FormKind, initial: &str) {
        self.show_page(self.page);
        for id in self.page.controls() {
            self.visible(*id, false);
        }
        self.form = Some(kind);
        self.set_text(Id::FORM_TITLE, kind.title());
        for id in [Id::FORM_TITLE, Id::SAVE, Id::CANCEL] {
            self.visible(id, true);
        }
        self.set_text(
            Id::SAVE,
            if kind == FormKind::Firewall {
                "Add rule"
            } else {
                "Save"
            },
        );
        for index in 0..6 {
            if let Some(field) = kind.fields().get(usize::from(index)) {
                self.set_text(Id::form_label(index), field.label);
                self.visible(Id::form_label(index), true);
                if field.choices.is_empty() {
                    self.set_text(Id::form_input(index), if index == 0 { initial } else { "" });
                    self.visible(Id::form_input(index), true);
                } else {
                    let id = Id::form_choice(index);
                    self.send(id, CB_RESETCONTENT, 0, 0);
                    for choice in field.choices {
                        let text = wide(choice);
                        self.send(id, CB_ADDSTRING, 0, text.as_ptr() as isize);
                    }
                    self.send(id, CB_SETCURSEL, 0, 0);
                    self.visible(id, true);
                }
            }
        }
        self.focus(Id::form_input(0));
        if kind == FormKind::Firewall {
            self.focus(Id::form_choice(0));
        }
    }

    pub fn form_values(&self, kind: FormKind) -> Vec<String> {
        (0..6)
            .zip(kind.fields())
            .map(|(index, field)| {
                self.text(if field.choices.is_empty() {
                    Id::form_input(index)
                } else {
                    Id::form_choice(index)
                })
            })
            .collect()
    }

    pub fn focus(&self, id: Id) {
        // SAFETY: The target is a live child of this thread's panel.
        unsafe {
            SetFocus(self.handle(id));
        }
    }

    pub fn layout(&mut self, width: u32, height: u32, scale: f64) -> Result<()> {
        self.scale = scale;
        self.update_font()?;
        let width = (f64::from(width) / scale) as i32;
        let height = (f64::from(height) / scale) as i32;
        // SAFETY: The panel is owned here, and dimensions came from its parent.
        unsafe {
            MoveWindow(
                self.panel,
                0,
                0,
                (f64::from(width) * scale) as i32,
                (f64::from(height) * scale) as i32,
                1,
            );
        }
        self.place(Id::HEADER, 16, 16, width - 280, 32);
        self.place(Id::POWER, width - 248, 12, 112, 32);
        self.place(Id::REFRESH, width - 128, 12, 112, 32);
        for (index, page) in (0..6).zip(Page::ALL) {
            self.place(page.navigation(), 16 + index * 112, 56, 104, 32);
        }
        self.place(Id::NOTICE, 16, height - 48, width - 32, 40);
        let bottom = height - 96;
        let split = width * 2 / 5;
        for id in [Id::NETWORK_LIST, Id::DEVICE_LIST] {
            self.place(id, 16, 104, split - 24, bottom - 116);
        }
        for id in [Id::NETWORK_DETAIL, Id::DEVICE_DETAIL] {
            self.place(id, split, 104, width - split - 16, bottom - 116);
        }
        for (index, id) in (0..5).zip([Id::CREATE, Id::JOIN, Id::INVITE, Id::RENAME, Id::LEAVE]) {
            self.place(id, 16 + index * 152, bottom, 144, 32);
        }
        self.place(Id::CONNECT, 16, bottom, 176, 32);
        self.place(Id::IDENTITY, 208, bottom, width - 224, 32);
        self.place(Id::REQUEST_LIST, 16, 104, width - 32, bottom - 116);
        for (index, id) in (0..3).zip([Id::ACCEPT, Id::DENY, Id::REVIEW]) {
            self.place(id, 16 + index * 152, bottom, 144, 32);
        }
        self.place(Id::FIREWALL_SUMMARY, 16, 104, width - 32, 32);
        self.place(Id::FIREWALL_LIST, 16, 144, width - 32, bottom - 156);
        for (index, id) in (0..3).zip([Id::ADD_RULE, Id::REMOVE_RULE, Id::FIREWALL_DEFAULT]) {
            self.place(id, 16 + index * 224, bottom, 216, 32);
        }
        for (index, id) in (0..4).zip([Id::DNS, Id::MDNS, Id::AUTO_UPDATE, Id::STARTUP]) {
            self.place(id, 24, 112 + index * 48, 320, 32);
        }
        self.place(Id::SETTINGS_DETAIL, 368, 104, width - 384, bottom - 72);
        self.place(Id::COMMAND, 16, 104, width - 144, 32);
        self.place(Id::RUN, width - 112, 104, 96, 32);
        self.place(Id::OUTPUT, 16, 152, width - 32, bottom - 104);
        self.place(Id::FORM_TITLE, 24, 104, width - 48, 32);
        for index in 0..6 {
            self.place(
                Id::form_label(index),
                24,
                160 + i32::from(index) * 48,
                248,
                24,
            );
            self.place(
                Id::form_input(index),
                280,
                152 + i32::from(index) * 48,
                width - 304,
                32,
            );
            self.place(
                Id::form_choice(index),
                280,
                152 + i32::from(index) * 48,
                width - 304,
                240,
            );
        }
        self.place(Id::SAVE, 280, bottom, 144, 32);
        self.place(Id::CANCEL, 440, bottom, 144, 32);
        Ok(())
    }

    fn place(&self, id: Id, x: i32, y: i32, width: i32, height: i32) {
        let scaled = |value| (f64::from(value) * self.scale) as i32;
        // SAFETY: The control is live; all coordinates are scaled parent-client coordinates.
        unsafe {
            MoveWindow(
                self.handle(id),
                scaled(x),
                scaled(y),
                scaled(width.max(0)),
                scaled(height.max(0)),
                1,
            );
        }
    }

    fn update_font(&mut self) -> Result<()> {
        // SAFETY: The panel is a live window on this thread.
        let dpi = unsafe { GetDpiForWindow(self.panel) };
        if self.font_dpi == dpi && !self.font.is_null() {
            return Ok(());
        }
        let mut metrics = NONCLIENTMETRICSW {
            cbSize: size_of::<NONCLIENTMETRICSW>() as u32,
            ..Default::default()
        };
        // SAFETY: metrics is writable, its size matches cbSize, and the panel is live.
        let font = unsafe {
            if SystemParametersInfoForDpi(
                SPI_GETNONCLIENTMETRICS,
                metrics.cbSize,
                (&mut metrics as *mut NONCLIENTMETRICSW).cast(),
                0,
                dpi,
            ) == 0
            {
                return Err(IoError::last_os_error()).context("reading the Windows UI font");
            }
            CreateFontIndirectW(&metrics.lfMessageFont)
        };
        if font.is_null() {
            return Err(IoError::last_os_error()).context("creating the Windows UI font");
        }
        for id in self.controls.keys().copied() {
            self.send(id, WM_SETFONT, font as usize, 1);
        }
        if !self.font.is_null() {
            // SAFETY: Every control has switched to the new font, so none uses the old font.
            unsafe {
                DeleteObject(self.font);
            }
        }
        self.font = font;
        self.font_dpi = dpi;
        Ok(())
    }
}

impl Drop for NativeUi {
    fn drop(&mut self) {
        // SAFETY: The subclass is removed before its boxed callback is dropped.
        // Destroying the owned panel destroys its controls before their font.
        // Cleanup cannot return errors from Drop.
        unsafe {
            RemoveWindowSubclass(self.panel, Some(panel_proc), 1);
            DestroyWindow(self.panel);
            if !self.font.is_null() {
                DeleteObject(self.font);
            }
        }
    }
}

unsafe extern "system" fn panel_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    data: usize,
) -> LRESULT {
    if message == WM_COMMAND {
        let notification = ((wparam >> 16) & 0xffff) as u32;
        if matches!(notification, BN_CLICKED | LBN_SELCHANGE) {
            // SAFETY: SetWindowSubclass receives this pointer from NativeUi;
            // the box outlives registration and messages run on its owning thread.
            let events = unsafe { &*(data as *const Events) };
            (events.notify)(Id((wparam & 0xffff) as u16));
            return 0;
        }
    }
    // SAFETY: Forward unchanged arguments from the registered subclass callback.
    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}

pub(crate) fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    #[test]
    fn native_controls_work_without_a_browser_runtime() {
        let class = wide("STATIC");
        // SAFETY: This is an owned hidden test window on this test's thread.
        let parent = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                null(),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                960,
                680,
                null_mut(),
                null_mut(),
                null_mut(),
                null(),
            )
        };
        assert!(!parent.is_null());
        let clicked = Rc::new(Cell::new(None));
        let received = clicked.clone();
        let mut ui = NativeUi::new(parent, move |id| received.set(Some(id))).unwrap();
        ui.layout(960, 680, 1.0).unwrap();
        ui.send(Id::CREATE, BM_CLICK, 0, 0);
        assert_eq!(clicked.get(), Some(Id::CREATE));
        ui.show_form(FormKind::Join, "example-invite");
        assert_eq!(ui.form_values(FormKind::Join), ["example-invite", ""]);
        ui.show_form(FormKind::Firewall, "");
        assert_eq!(
            ui.form_values(FormKind::Firewall),
            ["in", "allow", "tcp", "", "", ""]
        );
        ui.show_page(Page::Networks);
        ui.list(Id::NETWORK_LIST, &words_for_test(), Some(1));
        assert_eq!(ui.selection(Id::NETWORK_LIST), Some(1));
        ui.check(Id::DNS, true);
        assert!(ui.checked(Id::DNS));
        drop(ui);
        // SAFETY: Child controls have been destroyed and this test owns parent.
        unsafe {
            DestroyWindow(parent);
        }
    }

    fn words_for_test() -> Vec<String> {
        vec!["Example one".into(), "Example two".into()]
    }
}
