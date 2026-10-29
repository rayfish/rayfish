//! Rayfish's macOS design expressed as a desktop egui view.

use std::collections::HashSet;
use std::sync::Arc;

use eframe::egui::{
    self, Align, Color32, Context, FontData, FontDefinitions, FontFamily, FontId, Frame, Layout,
    Margin, RichText, ScrollArea, Stroke, TextureHandle, Ui, Vec2,
};
use ray_proto::Action as FirewallAction;
use ray_proto::ipc::{NetworkRole, NetworkStatus, PeerStatus};

use crate::forms::{FormKind, console_args};
use crate::model::{PendingItem, PendingKind, Snapshot, words};

const BACKGROUND: Color32 = color(0x18181b);
const PANEL: Color32 = color(0x1c1c20);
const DEEP: Color32 = color(0x09090b);
const LINE: Color32 = color(0x27272a);
const BORDER: Color32 = color(0x3f3f46);
const INK: Color32 = color(0xf4f4f5);
const BODY: Color32 = color(0xd4d4d8);
const MUTED: Color32 = color(0xa1a1aa);
const FAINT: Color32 = color(0x71717a);
const ROSE: Color32 = color(0xfb7185);
const ACCENT: Color32 = color(0xf43f5e);
const GREEN: Color32 = color(0x34d399);
const AMBER: Color32 = color(0xfbbf24);

const fn color(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}
fn font(name: &str, size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(name.into()))
}
fn heading(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(font("heading", size)).color(INK)
}
fn mono(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(font("mono", size))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Page {
    Networks,
    Devices,
    Files,
    Settings,
}

impl Page {
    pub const ALL: [Self; 4] = [Self::Networks, Self::Devices, Self::Files, Self::Settings];
    fn title(self) -> &'static str {
        match self {
            Self::Networks => "Networks",
            Self::Devices => "Devices",
            Self::Files => "Files",
            Self::Settings => "Settings",
        }
    }
}

pub(crate) enum Action {
    Refresh,
    Toggle,
    Run(Vec<String>),
    ShowResult { kind: OutputKind, args: Vec<String> },
    Startup(bool),
}

#[derive(Clone, Copy)]
pub(crate) enum OutputKind {
    Command,
    Invite,
    Files,
    Firewall,
}

impl OutputKind {
    fn title(self) -> &'static str {
        match self {
            Self::Command => "Command result",
            Self::Invite => "Invite code",
            Self::Files => "File transfers",
            Self::Firewall => "Suggested firewall rules",
        }
    }

    pub fn prepare(self, text: String) -> String {
        if matches!(self, Self::Invite) {
            let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            if let Some(code) = text
                .lines()
                .map(str::trim)
                .find(|line| line.len() >= 40 && line.chars().all(|ch| alphabet.contains(ch)))
            {
                return code.to_owned();
            }
        }
        text
    }
}

enum Dialog {
    Form {
        kind: FormKind,
        network: Option<String>,
        values: Vec<String>,
        focus: bool,
    },
    Confirm {
        title: String,
        message: String,
        args: Vec<String>,
    },
    Output,
}

pub(crate) struct Dashboard {
    pub snapshot: Option<Box<Snapshot>>,
    pub busy: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub output: String,
    output_kind: OutputKind,
    pub page: Page,
    pub submitted_form: bool,
    dialog: Option<Dialog>,
    console: String,
    logo: TextureHandle,
}

pub(crate) fn configure(ctx: &Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut fonts = FontDefinitions::default();
    for (name, bytes) in [
        (
            "body",
            include_bytes!("../../macos/Rayfish/Fonts/ChakraPetch-Regular.ttf").as_slice(),
        ),
        (
            "heading",
            include_bytes!("../../macos/Rayfish/Fonts/ChakraPetch-SemiBold.ttf").as_slice(),
        ),
        (
            "mono",
            include_bytes!("../../macos/Rayfish/Fonts/IBMPlexMono-Regular.ttf").as_slice(),
        ),
        (
            "logo",
            include_bytes!("../../macos/Rayfish/Fonts/PressStart2P-Regular.ttf").as_slice(),
        ),
    ] {
        fonts
            .font_data
            .insert(name.into(), Arc::new(FontData::from_static(bytes)));
        let mut family = fonts.families[&FontFamily::Proportional].clone();
        family.insert(0, name.into());
        fonts.families.insert(FontFamily::Name(name.into()), family);
    }
    ctx.set_fonts(fonts);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = DEEP;
    style.visuals.faint_bg_color = PANEL;
    style.visuals.override_text_color = Some(BODY);
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, LINE);
    style.visuals.selection.bg_fill = ACCENT.gamma_multiply(0.4);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, INK);
    style.visuals.hyperlink_color = ROSE;
    style.visuals.widgets.inactive.bg_fill = PANEL;
    style.visuals.widgets.inactive.weak_bg_fill = PANEL;
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, BODY);
    style.visuals.widgets.hovered.bg_fill = color(0x27272e);
    style.visuals.widgets.hovered.weak_bg_fill = color(0x27272e);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, MUTED);
    style.visuals.widgets.active.bg_fill = color(0x303038);
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ROSE);
    for widget in [
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
    ] {
        widget.corner_radius = 7.into();
    }
    style.visuals.window_corner_radius = 10.into();
    style.visuals.window_stroke = Stroke::new(1.0_f32, BORDER);
    style.spacing.item_spacing = Vec2::new(10.0, 10.0);
    style.spacing.button_padding = Vec2::new(12.0, 8.0);
    style.spacing.interact_size.y = 32.0;
    style
        .text_styles
        .insert(egui::TextStyle::Body, font("body", 15.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, font("heading", 13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Heading, font("heading", 17.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, font("mono", 12.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, font("body", 12.0));
    ctx.set_style(style);
}

impl Dashboard {
    pub fn new(ctx: &Context) -> anyhow::Result<Self> {
        configure(ctx);
        let image = image::load_from_memory(include_bytes!(
            "../../macos/Rayfish/Assets.xcassets/Logo.imageset/logo.png"
        ))?
        .into_rgba8();
        let size = [image.width() as usize, image.height() as usize];
        let logo = ctx.load_texture(
            "rayfish-logo",
            egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw()),
            egui::TextureOptions::LINEAR,
        );
        Ok(Self {
            snapshot: None,
            busy: false,
            error: None,
            notice: None,
            output: String::new(),
            output_kind: OutputKind::Command,
            page: Page::Networks,
            submitted_form: false,
            dialog: None,
            console: String::new(),
            logo,
        })
    }

    pub fn show_output(&mut self, kind: OutputKind) {
        self.output_kind = kind;
        self.dialog = Some(Dialog::Output);
    }

    pub fn form_succeeded(&mut self) {
        if self.submitted_form {
            self.dialog = None;
        }
        self.submitted_form = false;
    }

    pub fn draw(&mut self, ctx: &Context) -> Vec<Action> {
        let mut actions = Vec::new();
        egui::CentralPanel::default()
            .frame(Frame::new().fill(BACKGROUND))
            .show(ctx, |ui| {
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let width = (ui.available_width() - 56.0).clamp(0.0, 920.0);
                        ui.horizontal(|ui| {
                            ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
                            ui.vertical(|ui| {
                                ui.set_width(width);
                                ui.add_space(28.0);
                                self.header(ui, &mut actions);
                                ui.add_space(18.0);
                                if let Some(snapshot) = &self.snapshot {
                                    ui.horizontal(|ui| {
                                        if let Some(network) = snapshot.status.networks.first() {
                                            let ip = network.my_ipv6.to_string();
                                            if ui
                                                .add(
                                                    egui::Button::new(mono(&ip, 12.0).color(MUTED))
                                                        .frame(false),
                                                )
                                                .on_hover_text("Copy IP address")
                                                .clicked()
                                            {
                                                ctx.copy_text(ip);
                                            }
                                            ui.add_space(8.0);
                                        }
                                        let peers: usize = snapshot
                                            .status
                                            .networks
                                            .iter()
                                            .map(|network| network.peers.len())
                                            .sum();
                                        ui.label(
                                            mono(
                                                format!(
                                                    "{} networks",
                                                    snapshot.status.networks.len()
                                                ),
                                                12.0,
                                            )
                                            .color(MUTED),
                                        );
                                        ui.add_space(8.0);
                                        ui.label(mono(format!("{peers} peers"), 12.0).color(MUTED));
                                    });
                                }
                                if self.busy {
                                    ui.horizontal(|ui| {
                                        ui.spinner();
                                        ui.label(RichText::new("Working...").color(MUTED));
                                    });
                                }
                                if let Some(error) = &self.error {
                                    banner(ui, error, AMBER);
                                }
                                if let Some(snapshot) = &self.snapshot {
                                    for warning in &snapshot.warnings {
                                        banner(ui, warning, AMBER);
                                    }
                                    for network in &snapshot.status.inactive_networks {
                                        banner(
                                            ui,
                                            &format!(
                                                "{}: {}",
                                                network.name,
                                                network
                                                    .reason
                                                    .as_deref()
                                                    .unwrap_or("Restoring network...")
                                            ),
                                            AMBER,
                                        );
                                    }
                                    for error in &snapshot.status.connection_errors {
                                        banner(ui, &error.message, AMBER);
                                    }
                                }
                                ui.add_space(14.0);
                                match self.page {
                                    Page::Networks => self.networks(ui, &mut actions),
                                    Page::Devices => self.devices(ui, &mut actions),
                                    Page::Files => self.files(ui, &mut actions),
                                    Page::Settings => self.settings(ui, &mut actions),
                                }
                                if let Some(notice) = &self.notice {
                                    ui.add_space(14.0);
                                    ui.label(RichText::new(notice).small().color(GREEN));
                                }
                                ui.add_space(28.0);
                            });
                        });
                    });
            });
        self.dialog(ctx, &mut actions);
        actions
    }

    fn header(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let active = self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.status.active);
        ui.horizontal(|ui| {
            ui.add(egui::Image::new(&self.logo).fit_to_exact_size(Vec2::splat(34.0)));
            let mut wordmark = egui::text::LayoutJob::default();
            for (text, color) in [("rayf", INK), ("i", ROSE), ("sh", INK)] {
                wordmark.append(
                    text,
                    0.0,
                    egui::TextFormat {
                        font_id: font("logo", 15.0),
                        color,
                        ..Default::default()
                    },
                );
            }
            ui.label(wordmark);
            ui.add_space(4.0);
            dot(ui, if active { GREEN } else { FAINT });
            let state = if active {
                "connected"
            } else if self.snapshot.is_some() {
                "standby"
            } else {
                "service unreachable"
            };
            ui.label(mono(state, 11.0).color(if active { GREEN } else { FAINT }));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(
                    ui,
                    if active { "Disconnect" } else { "Connect" },
                    if active {
                        Kind::Connected
                    } else {
                        Kind::Primary
                    },
                    !self.busy && self.snapshot.is_some(),
                ) {
                    actions.push(Action::Toggle);
                }
            });
        });
        ui.add_space(14.0);
        let start = ui.cursor().min.y;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 22.0;
            for page in Page::ALL {
                let response = ui.add(
                    egui::Button::new(heading(page.title(), 14.0).color(if self.page == page {
                        INK
                    } else {
                        FAINT
                    }))
                    .frame(false),
                );
                if response.clicked() {
                    self.page = page;
                    self.notice = None;
                }
                if self.page == page {
                    ui.painter().hline(
                        response.rect.x_range(),
                        start + 36.0,
                        Stroke::new(2.0_f32, ACCENT),
                    );
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(mono("PRIVATE MESH", 10.0).color(FAINT));
            });
        });
        let y = start + 37.0;
        ui.painter()
            .hline(ui.max_rect().x_range(), y, Stroke::new(1.0_f32, LINE));
        ui.add_space((y - ui.cursor().min.y).max(0.0));
    }

    fn networks(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let mut dialog = None;
        if let Some(snapshot) = &self.snapshot {
            let pending: Vec<_> = snapshot
                .pending
                .iter()
                .filter(|item| {
                    matches!(
                        item.kind,
                        PendingKind::Join { .. } | PendingKind::Firewall { .. }
                    )
                })
                .collect();
            pending_section(
                ui,
                "Needs attention",
                &pending,
                self.busy,
                actions,
                &mut dialog,
            );
        }
        ui.horizontal(|ui| {
            ui.label(heading("Networks", 17.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "Create a network", Kind::Primary, !self.busy) {
                    dialog = Some(form(FormKind::Create, None, ""));
                }
                if button(ui, "Join with a code", Kind::Secondary, !self.busy) {
                    dialog = Some(form(FormKind::Join, None, ""));
                }
            });
        });
        ui.add_space(4.0);
        let networks = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.status.networks.as_slice())
            .unwrap_or_default();
        if networks.is_empty() {
            empty(
                ui,
                "No networks yet.",
                "Create a private network or join one with an invite code.",
            );
        }
        for network in networks {
            ui.push_id(&network.name, |ui| {
                card().inner_margin(0).show(ui, |ui| {
                    Frame::new().inner_margin(14).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(heading(&network.name, 16.0));
                                    Frame::new()
                                        .stroke(Stroke::new(1.0_f32, BORDER))
                                        .corner_radius(20)
                                        .inner_margin(Margin::symmetric(8, 3))
                                        .show(ui, |ui| {
                                            ui.label(
                                                mono(network.role.to_string().to_uppercase(), 9.0)
                                                    .color(
                                                        if network.role == NetworkRole::Coordinator
                                                        {
                                                            ROSE
                                                        } else {
                                                            MUTED
                                                        },
                                                    ),
                                            );
                                        });
                                });
                                let domain = format!(
                                    "{}.{}.ray",
                                    network.my_hostname.as_deref().unwrap_or("hostname"),
                                    network.name
                                );
                                if ui
                                    .add(
                                        egui::Label::new(mono(&domain, 11.0).color(FAINT))
                                            .sense(egui::Sense::click()),
                                    )
                                    .on_hover_text("Copy domain")
                                    .clicked()
                                {
                                    ui.ctx().copy_text(domain);
                                }
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if button(ui, "Leave", Kind::Danger, !self.busy) {
                                    dialog = Some(Dialog::Confirm {
                                        title: format!("Leave {}?", network.name),
                                        message: "This PC will lose access until it joins again."
                                            .into(),
                                        args: words(&["leave", &network.name]),
                                    });
                                }
                                if button(ui, "Rename", Kind::Secondary, !self.busy) {
                                    dialog = Some(form(
                                        FormKind::Rename,
                                        Some(network.name.clone()),
                                        network.my_hostname.as_deref().unwrap_or(""),
                                    ));
                                }
                                if network.role == NetworkRole::Coordinator
                                    && button(ui, "Invite", Kind::Secondary, !self.busy)
                                {
                                    actions.push(Action::ShowResult {
                                        kind: OutputKind::Invite,
                                        args: words(&["invite", &network.name]),
                                    });
                                }
                            });
                        });
                    });
                    for peer in &network.peers {
                        rule(ui);
                        Frame::new()
                            .inner_margin(Margin::symmetric(14, 11))
                            .show(ui, |ui| {
                                peer_row(ui, peer, network);
                            });
                    }
                    if network.peers.is_empty() {
                        rule(ui);
                        Frame::new().inner_margin(18).show(ui, |ui| {
                            ui.label(mono("Waiting for peers...", 12.0).color(FAINT));
                        });
                    }
                });
            });
            ui.add_space(4.0);
        }
        if let Some(dialog) = dialog {
            self.dialog = Some(dialog);
            self.error = None;
        }
    }

    fn devices(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let mut dialog = None;
        ui.horizontal(|ui| {
            ui.label(heading("Devices", 17.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(
                    ui,
                    "Connect to a peer",
                    Kind::Primary,
                    !self.busy && self.snapshot.as_ref().is_some_and(|s| s.status.active),
                ) {
                    dialog = Some(form(FormKind::Connect, None, ""));
                }
            });
        });
        if let Some(snapshot) = &self.snapshot {
            if let Some(identity) = &snapshot.status.identity {
                card().show(ui, |ui| {
                    ui.label(RichText::new("Your identity").color(MUTED));
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(mono(identity, 11.0))
                                .truncate()
                                .selectable(true),
                        );
                        if button(ui, "Copy", Kind::Secondary, true) {
                            ui.ctx().copy_text(identity.clone());
                        }
                    });
                });
            }
            let connections = snapshot
                .pending
                .iter()
                .filter(|item| matches!(item.kind, PendingKind::Connect { .. }))
                .collect::<Vec<_>>();
            pending_section(
                ui,
                "Connection requests",
                &connections,
                self.busy,
                actions,
                &mut dialog,
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(heading("Machines you control", 17.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if button(ui, "Refresh", Kind::Secondary, !self.busy) {
                        actions.push(Action::Refresh);
                    }
                });
            });
            let machines = snapshot
                .status
                .managed_machines
                .as_deref()
                .unwrap_or_default();
            if machines.is_empty() {
                empty(
                    ui,
                    "No enrolled machines.",
                    "Use ray machines enroll to add a machine you control.",
                );
            }
            for machine in machines {
                let state: &str = machine.state.into();
                card().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        dot(ui, if state == "online" { GREEN } else { FAINT });
                        ui.vertical(|ui| {
                            ui.label(heading(machine.hostname.to_string(), 15.0));
                            ui.label(mono(machine.identity.to_string(), 11.0).color(MUTED));
                            ui.label(
                                mono(
                                    machine
                                        .networks
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                    11.0,
                                )
                                .color(FAINT),
                            );
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(mono(state, 12.0).color(if state == "online" {
                                GREEN
                            } else {
                                FAINT
                            }));
                        });
                    });
                });
            }
            ui.add_space(14.0);
            ui.label(heading("Network peers", 17.0));
            if snapshot
                .status
                .networks
                .iter()
                .all(|network| network.peers.is_empty())
            {
                empty(
                    ui,
                    "No devices to show.",
                    "Devices appear here once this PC joins a network.",
                );
            } else {
                card().show(ui, |ui| {
                    let mut seen = HashSet::new();
                    for network in &snapshot.status.networks {
                        for peer in &network.peers {
                            if seen.insert(peer.endpoint_id) {
                                peer_row(ui, peer, network);
                            }
                        }
                    }
                });
            }
        } else {
            empty(
                ui,
                "Service unreachable.",
                "Check that the Rayfish Windows service is running.",
            );
        }
        if let Some(dialog) = dialog {
            self.dialog = Some(dialog);
            self.error = None;
        }
    }

    fn files(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        ui.horizontal(|ui| {
            ui.label(heading("Files", 17.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "Transfer history", Kind::Secondary, !self.busy) {
                    actions.push(Action::ShowResult {
                        kind: OutputKind::Files,
                        args: words(&["files"]),
                    });
                }
            });
        });
        let pending = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .pending
                    .iter()
                    .filter(|item| matches!(item.kind, PendingKind::File { .. }))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut dialog = None;
        if pending.is_empty() {
            empty(
                ui,
                "Incoming files appear here.",
                "You can accept or decline files sent by your peers.",
            );
        } else {
            pending_section(
                ui,
                "Incoming files",
                &pending,
                self.busy,
                actions,
                &mut dialog,
            );
        }
        if let Some(dialog) = dialog {
            self.dialog = Some(dialog);
        }
    }

    fn settings(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        ui.label(heading("Settings", 17.0));
        card().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(heading("VPN", 15.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let active = self
                        .snapshot
                        .as_ref()
                        .is_some_and(|snapshot| snapshot.status.active);
                    ui.label(
                        mono(if active { "connected" } else { "standby" }, 12.0).color(if active {
                            GREEN
                        } else {
                            MUTED
                        }),
                    );
                });
            });
            ui.label(
                RichText::new("The Rayfish Windows service manages your connection.").color(MUTED),
            );
        });
        ui.add_space(4.0);
        if let Some(snapshot) = &self.snapshot {
            card().show(ui, |ui| {
                let mut value = snapshot.launch_at_login;
                if setting(
                    ui,
                    "Start at login",
                    "Open Rayfish after you sign in.",
                    &mut value,
                    !self.busy,
                ) {
                    actions.push(Action::Startup(value));
                }
            });
            card().show(ui, |ui| {
                for (index, title, detail, key) in [
                    (
                        0,
                        "Magic DNS",
                        "Resolve device names ending in .ray.",
                        "dns",
                    ),
                    (
                        1,
                        "mDNS discovery",
                        "Discover peers on your local network.",
                        "mdns",
                    ),
                    (
                        2,
                        "Automatic updates",
                        "Keep Rayfish up to date.",
                        "auto-update",
                    ),
                ] {
                    if index != 0 {
                        rule(ui);
                    }
                    let mut value = snapshot.enabled(key);
                    if setting(
                        ui,
                        title,
                        detail,
                        &mut value,
                        !self.busy && snapshot.config.is_ok(),
                    ) {
                        actions.push(Action::Run(words(&[
                            key,
                            if value {
                                if key == "dns" { "partial" } else { "on" }
                            } else {
                                "off"
                            },
                        ])));
                    }
                }
                if let Err(error) = &snapshot.config {
                    ui.colored_label(AMBER, error);
                }
            });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(heading("Firewall", 17.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if button(
                        ui,
                        "Add rule",
                        Kind::Primary,
                        !self.busy && snapshot.firewall.is_ok(),
                    ) {
                        self.dialog = Some(form(FormKind::Firewall, None, ""));
                    }
                });
            });
            card().show(ui, |ui| match &snapshot.firewall {
                Ok(firewall) => {
                    ui.horizontal(|ui| {
                        ui.label("Inbound default");
                        ui.label(mono(firewall.default_inbound.to_string(), 12.0).color(MUTED));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, "Change", Kind::Secondary, !self.busy) {
                                let next = if firewall.default_inbound == FirewallAction::Deny {
                                    "allow"
                                } else {
                                    "deny"
                                };
                                self.dialog = Some(Dialog::Confirm {
                                    title: "Change inbound default?".into(),
                                    message: format!(
                                        "Set the default inbound firewall policy to {next}."
                                    ),
                                    args: words(&["firewall", "default", next]),
                                });
                            }
                        });
                    });
                    ui.label(
                        mono(
                            format!("Outbound default: {}", firewall.default_outbound),
                            12.0,
                        )
                        .color(MUTED),
                    );
                    if firewall.rules.is_empty() {
                        rule(ui);
                        ui.label(RichText::new("No firewall rules.").color(FAINT));
                    }
                    for (index, item) in firewall.rules.iter().enumerate() {
                        rule(ui);
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(heading(
                                    format!(
                                        "{} {} {} {}",
                                        item.direction, item.action, item.protocol, item.port
                                    ),
                                    14.0,
                                ));
                                ui.label(
                                    mono(
                                        format!("peer {} / network {}", item.peer, item.network),
                                        11.0,
                                    )
                                    .color(MUTED),
                                );
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if button(ui, "Remove", Kind::Danger, !self.busy) {
                                    actions.push(Action::Run(words(&[
                                        "firewall",
                                        "remove",
                                        &index.to_string(),
                                    ])));
                                }
                            });
                        });
                    }
                }
                Err(error) => {
                    ui.colored_label(AMBER, error);
                }
            });
        }
        ui.add_space(10.0);
        card().show(ui, |ui| {
            egui::CollapsingHeader::new(heading("Advanced", 15.0)).show(ui, |ui| {
                ui.label(
                    RichText::new("Run a ray command. Select output text to copy it.").color(MUTED),
                );
                let mut run = false;
                ui.horizontal(|ui| {
                    let response = ui.add_sized(
                        [ui.available_width() - 80.0, 32.0],
                        egui::TextEdit::singleline(&mut self.console)
                            .font(font("mono", 12.0))
                            .hint_text("ray status"),
                    );
                    run = (response.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                        || button(ui, "Run", Kind::Primary, !self.busy);
                });
                if run {
                    match console_args(&self.console) {
                        Ok(args) => actions.push(Action::Run(args)),
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
                if !self.output.is_empty() {
                    Frame::new()
                        .fill(DEEP)
                        .corner_radius(8)
                        .inner_margin(12)
                        .show(ui, |ui| {
                            ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                                ui.add(egui::Label::new(mono(&self.output, 12.0)).selectable(true));
                            });
                        });
                    if button(ui, "Copy output", Kind::Secondary, true) {
                        ui.ctx().copy_text(self.output.clone());
                    }
                }
            });
        });
    }

    fn dialog(&mut self, ctx: &Context, actions: &mut Vec<Action>) {
        let Some(dialog) = &mut self.dialog else {
            return;
        };
        let mut close = false;
        let response = egui::Modal::new(egui::Id::new("rayfish-dialog"))
            .frame(card().inner_margin(24))
            .show(ctx, |ui| {
                ui.set_width(480.0_f32.min(ctx.content_rect().width() - 80.0));
                match dialog {
                    Dialog::Form {
                        kind,
                        network,
                        values,
                        focus,
                    } => {
                        ui.label(heading(kind.title(), 18.0));
                        ui.add_space(6.0);
                        for (index, field) in kind.fields().iter().enumerate() {
                            ui.label(RichText::new(field.label).size(13.0).color(MUTED));
                            if field.choices.is_empty() {
                                let response = ui.add_sized(
                                    [ui.available_width(), 34.0],
                                    egui::TextEdit::singleline(&mut values[index])
                                        .margin(Vec2::new(11.0, 8.0)),
                                );
                                if *focus && index == 0 {
                                    response.request_focus();
                                }
                            } else {
                                egui::ComboBox::from_id_salt(index)
                                    .width(ui.available_width())
                                    .selected_text(&values[index])
                                    .show_ui(ui, |ui| {
                                        for choice in field.choices {
                                            ui.selectable_value(
                                                &mut values[index],
                                                (*choice).into(),
                                                *choice,
                                            );
                                        }
                                    });
                            }
                            ui.add_space(4.0);
                        }
                        *focus = false;
                        if let Some(error) = &self.error {
                            ui.colored_label(AMBER, error);
                        }
                        ui.add_space(10.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, kind.submit_label(), Kind::Primary, !self.busy) {
                                match kind.command(values, network.as_deref()) {
                                    Ok(args) => {
                                        self.submitted_form = true;
                                        actions.push(Action::Run(args));
                                    }
                                    Err(error) => self.error = Some(error.to_string()),
                                }
                            }
                            close = button(ui, "Cancel", Kind::Secondary, !self.busy);
                        });
                    }
                    Dialog::Confirm {
                        title,
                        message,
                        args,
                    } => {
                        ui.label(heading(title.as_str(), 18.0));
                        ui.label(RichText::new(message.as_str()).color(MUTED));
                        ui.add_space(14.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if button(ui, "Confirm", Kind::Danger, !self.busy) {
                                actions.push(Action::Run(args.clone()));
                                close = true;
                            }
                            close |= button(ui, "Cancel", Kind::Secondary, !self.busy);
                        });
                    }
                    Dialog::Output => {
                        ui.label(heading(self.output_kind.title(), 18.0));
                        ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                            ui.add(egui::Label::new(mono(&self.output, 12.0)).selectable(true));
                        });
                        ui.add_space(12.0);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            close = button(ui, "Done", Kind::Secondary, true);
                            if button(ui, "Copy", Kind::Primary, true) {
                                ctx.copy_text(self.output.clone());
                            }
                        });
                    }
                }
            });
        if close || (!self.busy && response.should_close()) {
            self.dialog = None;
        }
    }
}

fn form(kind: FormKind, network: Option<String>, initial: &str) -> Dialog {
    let mut values = kind
        .fields()
        .iter()
        .map(|field| field.choices.first().copied().unwrap_or("").to_owned())
        .collect::<Vec<_>>();
    if kind.fields()[0].choices.is_empty() {
        values[0] = initial.into();
    }
    Dialog::Form {
        kind,
        network,
        values,
        focus: true,
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Secondary,
    Primary,
    Danger,
    Connected,
}

fn button(ui: &mut Ui, title: &str, kind: Kind, enabled: bool) -> bool {
    let (foreground, border, fill) = match kind {
        Kind::Secondary => (BODY, BORDER, PANEL),
        Kind::Primary => (Color32::WHITE, ACCENT, ACCENT),
        Kind::Danger => (ROSE, color(0x662435), PANEL),
        Kind::Connected => (GREEN, color(0x285b4e), PANEL),
    };
    ui.add_enabled(
        enabled,
        egui::Button::new(
            RichText::new(title)
                .font(font("heading", 13.0))
                .color(foreground),
        )
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, border))
        .corner_radius(7)
        .min_size(Vec2::new(0.0, 32.0)),
    )
    .clicked()
}

fn card() -> Frame {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0_f32, LINE))
        .corner_radius(10)
        .inner_margin(18)
}
fn rule(ui: &mut Ui) {
    ui.add(egui::Separator::default().spacing(10.0));
}
fn dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(7.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 3.5, color);
}

fn banner(ui: &mut Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(color.gamma_multiply(0.05))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.25)))
        .corner_radius(8)
        .inner_margin(14)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(
                egui::Label::new(RichText::new(text).color(color))
                    .wrap()
                    .selectable(true),
            );
        });
}

fn empty(ui: &mut Ui, title: &str, detail: &str) {
    card()
        .inner_margin(Margin::symmetric(18, 40))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.label(RichText::new(title).font(font("body", 16.0)).color(MUTED));
                ui.label(RichText::new(detail).font(font("body", 14.0)).color(FAINT));
            });
        });
}

fn peer_row(ui: &mut Ui, peer: &PeerStatus, network: &NetworkStatus) {
    let state = peer
        .connection
        .as_ref()
        .map(|connection| connection.conn_type.to_string())
        .unwrap_or_else(|| peer.state.to_string());
    let color = if state == "direct" {
        GREEN
    } else if state == "relay" {
        AMBER
    } else {
        FAINT
    };
    ui.horizontal(|ui| {
        dot(ui, color);
        let hostname = peer.hostname.as_deref().unwrap_or("Unnamed peer");
        if ui
            .add(egui::Button::new(mono(hostname, 12.0).color(INK)).frame(false))
            .on_hover_text("Copy domain")
            .clicked()
        {
            ui.ctx()
                .copy_text(format!("{hostname}.{}.ray", network.name));
        }
        if peer.is_own_device {
            ui.label(mono("YOU", 9.0).color(FAINT));
        }
        ui.label(mono(peer.ipv6.to_string(), 12.0).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(latency) = peer
                .connection
                .as_ref()
                .and_then(|connection| connection.rtt_ms)
            {
                ui.label(mono(format!("{latency:.0} ms"), 12.0).color(FAINT));
            }
            ui.label(mono(state, 12.0).color(color));
        });
    });
}

fn pending_section(
    ui: &mut Ui,
    title: &str,
    pending: &[&PendingItem],
    busy: bool,
    actions: &mut Vec<Action>,
    dialog: &mut Option<Dialog>,
) {
    if pending.is_empty() {
        return;
    }
    ui.label(heading(title, 17.0));
    card().show(ui, |ui| {
        for (index, item) in pending.iter().enumerate() {
            if index != 0 { rule(ui); }
            ui.horizontal(|ui| {
                ui.add(egui::Label::new(&item.description).wrap());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if button(ui, "Decline", Kind::Danger, !busy) { actions.push(Action::Run(item.command(false))); }
                    if button(ui, "Accept", Kind::Primary, !busy) {
                        if matches!(item.kind, PendingKind::Firewall { .. }) {
                            *dialog = Some(Dialog::Confirm { title: "Accept firewall rules?".into(), message: "Suggested rules can open ports to peers. Review them before accepting.".into(), args: item.command(true) });
                        } else { actions.push(Action::Run(item.command(true))); }
                    }
                    if let Some(args) = item.review_command() && button(ui, "Review", Kind::Secondary, !busy) { actions.push(Action::ShowResult { kind: OutputKind::Firewall, args }); }
                });
            });
        }
    });
    ui.add_space(14.0);
}

fn setting(ui: &mut Ui, title: &str, detail: &str, value: &mut bool, enabled: bool) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(title);
            ui.label(RichText::new(detail).font(font("body", 14.0)).color(MUTED));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let response = ui.add_enabled_ui(enabled, |ui| {
                let (rect, response) =
                    ui.allocate_exact_size(Vec2::new(36.0, 21.0), egui::Sense::click());
                if response.clicked() {
                    *value = !*value;
                    changed = true;
                }
                response.widget_info(|| {
                    egui::WidgetInfo::selected(egui::WidgetType::Checkbox, enabled, *value, title)
                });
                ui.painter()
                    .rect_filled(rect, 11, if *value { ACCENT } else { BORDER });
                ui.painter().circle_filled(
                    egui::pos2(
                        if *value {
                            rect.right() - 10.5
                        } else {
                            rect.left() + 10.5
                        },
                        rect.center().y,
                    ),
                    7.5,
                    INK,
                );
                response
            });
            response.inner.on_hover_text(title);
        });
    });
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_dialog_copies_only_the_invite_code() {
        let code = "abcd1234".repeat(8);
        let output = format!("Example invite\n\n{code}\n\nExpires tomorrow\n");
        assert_eq!(OutputKind::Invite.prepare(output), code);
        assert_eq!(
            OutputKind::Invite.prepare("example error".into()),
            "example error"
        );
    }

    #[test]
    fn pages_and_forms_render_without_the_windows_desktop_or_daemon() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        for page in Page::ALL {
            app.page = page;
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(1000.0, 680.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    assert!(app.draw(ctx).is_empty());
                },
            );
            assert!(!output.shapes.is_empty());
        }
        for kind in [
            FormKind::Create,
            FormKind::Join,
            FormKind::Connect,
            FormKind::Rename,
            FormKind::Firewall,
        ] {
            app.dialog = Some(form(kind, None, ""));
            let output = ctx.run(egui::RawInput::default(), |ctx| {
                assert!(app.draw(ctx).is_empty());
            });
            assert!(!output.shapes.is_empty());
        }
    }
}
