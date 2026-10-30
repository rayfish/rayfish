//! Rayfish's macOS design expressed as a desktop egui view.

#[path = "ui/ssh.rs"]
mod ssh;

use std::collections::HashSet;
use std::sync::Arc;

use eframe::egui::{
    self, Align, Color32, Context, FontData, FontDefinitions, FontFamily, FontId, Frame, Layout,
    Margin, RichText, ScrollArea, Stroke, TextureHandle, Ui, Vec2,
};
use ray_proto::ipc::{FirewallRuleView, IpcMessage, NetworkRole, NetworkStatus, PeerStatus};
use ray_proto::{Action as FirewallAction, FirewallKey, GlobalKey, NodeKey};

use crate::forms::{FormKind, SshEditor, console_args};
use crate::model::{PendingItem, PendingKind, Snapshot, SshRule};

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
    Firewall,
    Settings,
}

impl Page {
    pub const ALL: [Self; 5] = [
        Self::Networks,
        Self::Devices,
        Self::Files,
        Self::Firewall,
        Self::Settings,
    ];
    fn title(self) -> &'static str {
        match self {
            Self::Networks => "Networks",
            Self::Devices => "Devices",
            Self::Files => "Files",
            Self::Firewall => "Firewall",
            Self::Settings => "Settings",
        }
    }
}

pub(crate) enum Action {
    Refresh,
    Toggle,
    Run(IpcMessage),
    Join {
        request: IpcMessage,
        hostname: String,
    },
    ShowResult {
        kind: OutputKind,
        request: IpcMessage,
    },
    Console(Vec<String>),
    Startup(bool),
}

#[derive(Clone, Copy)]
pub(crate) enum OutputKind {
    Command,
    Invite,
    Files,
    Firewall,
    SshAccess,
}

impl OutputKind {
    fn title(self) -> &'static str {
        match self {
            Self::Command => "Command result",
            Self::Invite => "Invite code",
            Self::Files => "File transfers",
            Self::Firewall => "Suggested firewall rules",
            Self::SshAccess => "SSH access",
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
        request: Option<Box<IpcMessage>>,
    },
    FirewallRemove {
        index: usize,
        rule: Box<FirewallRuleView>,
    },
    SshEditor(Box<SshEditor>),
    SshRemove(Box<SshRule>),
    Output,
}

pub(crate) struct Dashboard {
    pub snapshot: Option<Box<Snapshot>>,
    pub busy: bool,
    pub refreshing: bool,
    pub status_error: Option<String>,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub output: String,
    output_kind: OutputKind,
    pub page: Page,
    pub submitted_form: bool,
    joining: Option<String>,
    dialog: Option<Dialog>,
    console: String,
    advanced_open: bool,
    focus_ssh: bool,
    notice_in_ssh: bool,
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
            refreshing: false,
            status_error: None,
            error: None,
            notice: None,
            output: String::new(),
            output_kind: OutputKind::Command,
            page: Page::Networks,
            submitted_form: false,
            joining: None,
            dialog: None,
            console: String::new(),
            advanced_open: false,
            focus_ssh: false,
            notice_in_ssh: false,
            logo,
        })
    }

    pub fn show_output(&mut self, kind: OutputKind) {
        self.output_kind = kind;
        self.dialog = Some(Dialog::Output);
    }

    fn awaiting_approval(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.status.active
                && snapshot.status.networks.is_empty()
                && !snapshot.status.pending_networks.is_empty()
        })
    }

    pub fn form_succeeded(&mut self) {
        if self.submitted_form {
            self.dialog = None;
        }
        self.submitted_form = false;
    }

    pub fn begin_join(&mut self, hostname: String) {
        self.dialog = None;
        self.submitted_form = false;
        self.joining = Some(hostname);
        self.page = Page::Networks;
    }

    pub fn operation_interrupted(&mut self) {
        self.dialog = None;
        self.joining = None;
        self.submitted_form = false;
        self.error = None;
        self.notice = None;
    }

    pub fn command_finished(&mut self, output: Result<String, String>, kind: Option<OutputKind>) {
        self.joining = None;
        self.notice_in_ssh = matches!(kind, Some(OutputKind::SshAccess));
        match output {
            Ok(text) => {
                let text = match kind {
                    Some(kind) => kind.prepare(text),
                    None => text,
                };
                self.output = if text.is_empty() {
                    "Done.".into()
                } else {
                    text
                };
                self.form_succeeded();
                if self.notice_in_ssh {
                    self.focus_ssh_settings();
                }
                self.notice = Some(if matches!(kind, Some(OutputKind::SshAccess)) {
                    self.output.clone()
                } else {
                    "Done.".into()
                });
            }
            Err(error) => {
                if self.notice_in_ssh {
                    self.focus_ssh_settings();
                }
                self.output = error.clone();
                self.error = Some(error);
                self.submitted_form = false;
            }
        }
        if let Some(kind) = kind
            && !matches!(kind, OutputKind::SshAccess)
        {
            self.show_output(kind);
        }
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
                                        if let Some(network) =
                                            snapshot.status.visible_networks().next()
                                        {
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
                                            .visible_networks()
                                            .map(|network| network.peers.len())
                                            .sum();
                                        let count = snapshot.status.networks.len()
                                            + snapshot.status.inactive_networks.len();
                                        ui.label(
                                            mono(
                                                format!(
                                                    "{count} {}",
                                                    if count == 1 { "network" } else { "networks" }
                                                ),
                                                12.0,
                                            )
                                            .color(MUTED),
                                        );
                                        ui.add_space(8.0);
                                        ui.label(mono(format!("{peers} peers"), 12.0).color(MUTED));
                                    });
                                }
                                if let Some(error) = &self.error {
                                    banner(ui, error, AMBER);
                                }
                                if self.status_error.is_some() && self.snapshot.is_some() {
                                    self.status_panel(ui, &mut actions);
                                }
                                if let Some(snapshot) = &self.snapshot {
                                    for warning in &snapshot.warnings {
                                        banner(ui, warning, AMBER);
                                    }
                                    for error in &snapshot.status.connection_errors {
                                        banner(ui, &error.message, AMBER);
                                    }
                                }
                                ui.add_space(14.0);
                                if self.snapshot.is_none() {
                                    self.status_panel(ui, &mut actions);
                                } else {
                                    match self.page {
                                        Page::Networks => self.networks(ui, &mut actions),
                                        Page::Devices => self.devices(ui, &mut actions),
                                        Page::Files => self.files(ui, &mut actions),
                                        Page::Firewall => self.firewall(ui, &mut actions),
                                        Page::Settings => self.settings(ui, &mut actions),
                                    }
                                }
                                if let Some(notice) = &self.notice
                                    && !self.notice_in_ssh
                                {
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
            let (state, state_color) = if self.status_error.is_some() {
                (
                    if self.refreshing {
                        "retrying status"
                    } else {
                        "status unavailable"
                    },
                    AMBER,
                )
            } else if self.snapshot.is_none() {
                ("loading status", MUTED)
            } else if self.awaiting_approval() {
                ("awaiting approval", AMBER)
            } else if active {
                ("connected", GREEN)
            } else {
                ("standby", FAINT)
            };
            if self.busy || (self.refreshing && self.snapshot.is_none()) {
                ui.spinner().on_hover_text("Updating Rayfish");
            } else {
                dot(ui, state_color);
            }
            ui.label(mono(state, 11.0).color(state_color));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self.status_error.is_some() || self.snapshot.is_none() {
                    if button(
                        ui,
                        if self.refreshing {
                            "Loading..."
                        } else {
                            "Retry"
                        },
                        Kind::Secondary,
                        !self.busy && !self.refreshing,
                    ) {
                        actions.push(Action::Refresh);
                    }
                    return;
                }
                if button(
                    ui,
                    if active { "Disconnect" } else { "Connect" },
                    if active {
                        Kind::Connected
                    } else {
                        Kind::Primary
                    },
                    self.snapshot.is_some() && (active || !self.busy),
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

    fn status_panel(&self, ui: &mut Ui, actions: &mut Vec<Action>) {
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            if let Some(error) = &self.status_error {
                ui.horizontal(|ui| {
                    ui.label(heading("Network status unavailable", 16.0).color(AMBER));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if button(
                            ui,
                            if self.refreshing {
                                "Retrying..."
                            } else {
                                "Retry"
                            },
                            Kind::Secondary,
                            !self.busy && !self.refreshing,
                        ) {
                            actions.push(Action::Refresh);
                        }
                        if button(ui, "Copy error", Kind::Secondary, true) {
                            ui.ctx().copy_text(error.clone());
                        }
                    });
                });
                ui.label(
                    RichText::new(if self.snapshot.is_some() {
                        "Showing the last received status. Rayfish will retry automatically."
                    } else {
                        "Rayfish could not read your network list. It will retry automatically."
                    })
                    .color(MUTED),
                );
                ScrollArea::vertical()
                    .id_salt("status-error")
                    .max_height(80.0)
                    .show(ui, |ui| {
                        ui.add(egui::Label::new(mono(error, 11.0)).wrap().selectable(true));
                    });
            } else {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.vertical(|ui| {
                        ui.label(heading("Loading your networks", 16.0));
                        ui.label(
                            RichText::new("Reading the Rayfish service status...").color(MUTED),
                        );
                    });
                });
            }
        });
    }

    fn networks(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let mut dialog = None;
        let unavailable = self.busy || self.status_error.is_some();
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
                unavailable,
                actions,
                &mut dialog,
            );
        }
        ui.horizontal(|ui| {
            ui.label(heading("Networks", 17.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "Create a network", Kind::Primary, !unavailable) {
                    dialog = Some(form(FormKind::Create, None, ""));
                }
                if button(ui, "Join with a code", Kind::Secondary, !unavailable) {
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
        let inactive = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.status.inactive_networks.as_slice())
            .unwrap_or_default();
        if let Some(hostname) = &self.joining {
            card().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.vertical(|ui| {
                        ui.label(heading("New network", 16.0).color(MUTED));
                        if !hostname.is_empty() {
                            ui.label(mono(hostname, 11.0).color(FAINT));
                        }
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(mono("Joining", 12.0).color(MUTED));
                    });
                });
            });
        }
        if networks.is_empty()
            && inactive.is_empty()
            && self.joining.is_none()
            && self.status_error.is_none()
            && self
                .snapshot
                .as_ref()
                .is_none_or(|snapshot| snapshot.status.pending_networks.is_empty())
        {
            empty(
                ui,
                "No networks yet.",
                "Create a private network or join one with an invite code.",
            );
        }
        for (network, restoring) in
            networks
                .iter()
                .map(|network| (network, None))
                .chain(inactive.iter().filter_map(|inactive| {
                    inactive.saved.as_ref().map(|saved| (saved, Some(inactive)))
                }))
        {
            ui.push_id(&network.name, |ui| {
                card().inner_margin(0).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    Frame::new().inner_margin(14).show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 4.0;
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        heading(&network.name, 16.0)
                                            .color(if restoring.is_some() { MUTED } else { INK }),
                                    );
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
                                if button(ui, "Leave", Kind::Danger, !unavailable) {
                                    dialog = Some(Dialog::Confirm {
                                        title: format!("Leave {}?", network.name),
                                        message: "This PC will lose access until it joins again."
                                            .into(),
                                        request: Some(Box::new(IpcMessage::Leave {
                                            name: network.name.clone(),
                                        })),
                                    });
                                }
                                if restoring.is_some() {
                                    ui.label(mono("Reconnecting", 12.0).color(MUTED));
                                    ui.spinner();
                                    return;
                                }
                                if button(ui, "Rename", Kind::Secondary, !unavailable) {
                                    dialog = Some(form(
                                        FormKind::Rename,
                                        Some(network.name.clone()),
                                        network.my_hostname.as_deref().unwrap_or(""),
                                    ));
                                }
                                if network.role == NetworkRole::Coordinator
                                    && button(ui, "Invite", Kind::Secondary, !unavailable)
                                {
                                    actions.push(Action::ShowResult {
                                        kind: OutputKind::Invite,
                                        request: IpcMessage::InviteCreate {
                                            network: network.name.clone(),
                                            expires_secs: 7 * 24 * 60 * 60,
                                            hostname: None,
                                            reusable: false,
                                        },
                                    });
                                }
                            });
                        });
                        if let Some(inactive) = restoring {
                            ui.label(
                                RichText::new(
                                    inactive
                                        .reason
                                        .as_deref()
                                        .unwrap_or("Syncing membership automatically."),
                                )
                                .small()
                                .color(MUTED),
                            );
                        }
                    });
                    for peer in &network.peers {
                        ui.add(egui::Separator::default().spacing(1.0));
                        peer_entry(
                            ui,
                            peer,
                            network,
                            restoring.is_some() || self.status_error.is_some(),
                        );
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
        for inactive in inactive.iter().filter(|inactive| inactive.saved.is_none()) {
            card().show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(heading(&inactive.name, 16.0).color(MUTED));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(mono("Reconnecting", 12.0).color(MUTED));
                        ui.spinner();
                    });
                });
                ui.label(
                    RichText::new(
                        inactive
                            .reason
                            .as_deref()
                            .unwrap_or("Syncing membership automatically."),
                    )
                    .small()
                    .color(MUTED),
                );
            });
        }
        if let Some(snapshot) = &self.snapshot {
            for network in &snapshot.status.pending_networks {
                card().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(heading(network, 16.0).color(MUTED));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(mono("Awaiting approval", 12.0).color(AMBER));
                            ui.spinner();
                        });
                    });
                    ui.label(
                        RichText::new(
                            "A network coordinator must approve this PC before it can connect.",
                        )
                        .color(MUTED),
                    );
                });
            }
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
                        request: IpcMessage::ListFiles,
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

    fn firewall_ready(&self) -> bool {
        !self.busy
            && self.status_error.is_none()
            && self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.firewall.is_ok())
    }

    fn firewall(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let enabled = self.firewall_ready();
        ui.horizontal(|ui| {
            ui.label(heading("Firewall", 17.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if button(ui, "Add rule", Kind::Primary, enabled) {
                    self.dialog = Some(form(FormKind::Firewall, None, ""));
                    self.error = None;
                }
            });
        });
        ui.label(RichText::new("Rules apply to Rayfish mesh traffic. Windows Firewall can also block these connections.").color(MUTED));
        ui.add_space(8.0);
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let pending = snapshot
            .pending
            .iter()
            .filter(|item| matches!(item.kind, PendingKind::Firewall { .. }))
            .collect::<Vec<_>>();
        let mut dialog = None;
        pending_section(
            ui,
            "Suggested rules",
            &pending,
            !enabled,
            actions,
            &mut dialog,
        );
        if let Some(dialog) = dialog {
            self.dialog = Some(dialog);
        }
        let firewall = match &snapshot.firewall {
            Ok(firewall) => firewall,
            Err(error) => {
                card().show(ui, |ui| {
                    ui.label(heading("Firewall unavailable", 15.0));
                    ui.colored_label(AMBER, error);
                    if button(
                        ui,
                        "Retry firewall",
                        Kind::Secondary,
                        !self.busy && !self.refreshing,
                    ) {
                        actions.push(Action::Refresh);
                    }
                });
                return;
            }
        };
        card().show(ui, |ui| {
            ui.label(heading("Default policies", 15.0));
            for (title, current, key) in [
                ("Inbound", firewall.default_inbound, FirewallKey::DefaultIn),
                ("Outbound", firewall.default_outbound, FirewallKey::DefaultOut),
            ] {
                ui.horizontal(|ui| {
                    ui.label(title);
                    ui.label(mono(current.to_string().to_uppercase(), 11.0).color(if current == FirewallAction::Deny { ROSE } else { GREEN }));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if button(ui, &format!("Change {}", title.to_lowercase()), Kind::Secondary, enabled) {
                            let next = if current == FirewallAction::Deny { FirewallAction::Allow } else { FirewallAction::Deny };
                            self.dialog = Some(Dialog::Confirm {
                                title: format!("Change {} default?", title.to_lowercase()),
                                message: format!("Set the default {} mesh policy to {next}. This applies when no rule matches.", title.to_lowercase()),
                                request: Some(Box::new(IpcMessage::ConfigSet {
                                    key: NodeKey::Firewall(key), value: next.to_string(), replace: false,
                                })),
                            });
                        }
                    });
                });
            }
        });
        ui.add_space(10.0);
        ui.label(heading("Rules", 15.0));
        if firewall.rules.is_empty() {
            empty(
                ui,
                "No firewall rules.",
                "Traffic follows the default policies above.",
            );
            return;
        }
        card().inner_margin(12).show(ui, |ui| {
            ScrollArea::horizontal()
                .id_salt("firewall-columns")
                .show(ui, |ui| {
                    egui::Grid::new("firewall-rules")
                        .num_columns(7)
                        .spacing(Vec2::new(16.0, 4.0))
                        .striped(true)
                        .show(ui, |ui| {
                            for title in [
                                "Direction",
                                "Action",
                                "Protocol",
                                "Ports",
                                "Peer",
                                "Network",
                                "",
                            ] {
                                ui.label(mono(title, 10.0).color(FAINT));
                            }
                            ui.end_row();
                            for (index, item) in firewall.rules.iter().enumerate() {
                                ui.label(mono(item.direction.to_string().to_uppercase(), 11.0));
                                ui.label(mono(item.action.to_string().to_uppercase(), 11.0).color(
                                    if item.action == FirewallAction::Deny {
                                        ROSE
                                    } else {
                                        GREEN
                                    },
                                ));
                                ui.label(
                                    mono(item.protocol.to_string().to_uppercase(), 11.0)
                                        .color(MUTED),
                                );
                                ui.label(mono(scope_label(&item.port), 11.0));
                                ui.add_sized(
                                    [150.0, 22.0],
                                    egui::Label::new(mono(scope_label(&item.peer), 11.0))
                                        .truncate()
                                        .halign(Align::LEFT),
                                )
                                .on_hover_text(&item.peer);
                                ui.add_sized(
                                    [115.0, 22.0],
                                    egui::Label::new(mono(scope_label(&item.network), 11.0))
                                        .truncate()
                                        .halign(Align::LEFT),
                                )
                                .on_hover_text(&item.network);
                                if button(ui, "Remove", Kind::Danger, enabled) {
                                    self.dialog = Some(Dialog::FirewallRemove {
                                        index,
                                        rule: Box::new(item.clone()),
                                    });
                                }
                                ui.end_row();
                            }
                        });
                });
        });
    }

    pub(crate) fn focus_ssh_settings(&mut self) {
        self.page = Page::Settings;
        self.focus_ssh = true;
    }

    #[cfg(any(not(windows), test))]
    pub(crate) fn preview_ssh_editor(&mut self) {
        self.page = Page::Settings;
        let network = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.status.visible_networks().next())
            .map(|network| network.name.as_str());
        self.dialog = Some(Dialog::SshEditor(Box::new(SshEditor::new(network))));
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
                    let (state, color) = if self.status_error.is_some() {
                        ("status unavailable", AMBER)
                    } else if self.awaiting_approval() {
                        ("awaiting approval", AMBER)
                    } else if active {
                        ("connected", GREEN)
                    } else {
                        ("standby", MUTED)
                    };
                    ui.label(mono(state, 12.0).color(color));
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
                        GlobalKey::Dns,
                    ),
                    (
                        1,
                        "mDNS discovery",
                        "Discover peers on your local network.",
                        GlobalKey::Mdns,
                    ),
                    (
                        2,
                        "Automatic updates",
                        "Keep Rayfish up to date.",
                        GlobalKey::AutoUpdate,
                    ),
                ] {
                    if index != 0 {
                        rule(ui);
                    }
                    let mut value = snapshot.enabled(key.name());
                    if setting(
                        ui,
                        title,
                        detail,
                        &mut value,
                        !self.busy && self.status_error.is_none() && snapshot.config.is_ok(),
                    ) {
                        actions.push(Action::Run(IpcMessage::ConfigSet {
                            key: NodeKey::Global(key),
                            value: if value {
                                if key == GlobalKey::Dns {
                                    "partial"
                                } else {
                                    "on"
                                }
                            } else {
                                "off"
                            }
                            .into(),
                            replace: false,
                        }));
                    }
                }
                if let Err(error) = &snapshot.config {
                    ui.colored_label(AMBER, error);
                }
            });
        }
        ui.add_space(10.0);
        self.ssh_settings(ui, actions);
        ui.add_space(10.0);
        card()
            .inner_margin(Margin::symmetric(14, 6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if ui
                    .add_sized(
                        [ui.available_width(), 28.0],
                        egui::Button::new(heading(
                            if self.advanced_open {
                                "- Advanced"
                            } else {
                                "+ Advanced"
                            },
                            14.0,
                        ))
                        .frame(false),
                    )
                    .clicked()
                {
                    self.advanced_open = !self.advanced_open;
                }
                if self.advanced_open {
                    ui.label(
                        RichText::new("Run a ray command. Select output text to copy it.")
                            .color(MUTED),
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
                            Ok(args) => actions.push(Action::Console(args)),
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
                                    ui.add(
                                        egui::Label::new(mono(&self.output, 12.0)).selectable(true),
                                    );
                                });
                            });
                        if button(ui, "Copy output", Kind::Secondary, true) {
                            ui.ctx().copy_text(self.output.clone());
                        }
                    }
                }
            });
    }

    fn dialog(&mut self, ctx: &Context, actions: &mut Vec<Action>) {
        let firewall_ready = self.firewall_ready();
        let ssh_ready = self.ssh_ready();
        let snapshot = self.snapshot.as_deref();
        let firewall_rules = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.firewall.as_ref().ok())
            .map(|firewall| firewall.rules.as_slice());
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
                        ScrollArea::vertical()
                            .id_salt("form-fields")
                            .max_height((ctx.content_rect().height() - 160.0).max(80.0))
                            .show(ui, |ui| {
                                for (index, field) in kind.fields().iter().enumerate() {
                                    ui.label(RichText::new(field.label).size(13.0).color(MUTED));
                                    if *kind == FormKind::Firewall
                                        && index == 3
                                        && values[2] == "icmp"
                                    {
                                        ui.label(RichText::new("Not used for ICMP.").color(FAINT));
                                        ui.add_space(4.0);
                                        continue;
                                    }
                                    if field.choices.is_empty() {
                                        let response = ui.add_sized(
                                            [ui.available_width(), 34.0],
                                            egui::TextEdit::singleline(&mut values[index])
                                                .hint_text(field.hint)
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
                                    if !field.hint.is_empty() && !field.choices.is_empty() {
                                        ui.label(RichText::new(field.hint).small().color(FAINT));
                                    }
                                    ui.add_space(4.0);
                                }
                                *focus = false;
                                if let Some(error) = &self.error {
                                    ui.colored_label(AMBER, error);
                                }
                            });
                        ui.add_space(10.0);
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), 34.0),
                            Layout::right_to_left(Align::Center),
                            |ui| {
                                if button(
                                    ui,
                                    kind.submit_label(),
                                    Kind::Primary,
                                    !self.busy && (*kind != FormKind::Firewall || firewall_ready),
                                ) {
                                    match kind.command(values, network.as_deref()) {
                                        Ok(request) => {
                                            if *kind == FormKind::Join {
                                                actions.push(Action::Join {
                                                    request,
                                                    hostname: values[1].trim().to_owned(),
                                                });
                                            } else {
                                                self.submitted_form = true;
                                                actions.push(Action::Run(request));
                                            }
                                        }
                                        Err(error) => self.error = Some(error.to_string()),
                                    }
                                }
                                close = button(ui, "Cancel", Kind::Secondary, true);
                            },
                        );
                    }
                    Dialog::Confirm {
                        title,
                        message,
                        request,
                    } => {
                        ui.label(heading(title.as_str(), 18.0));
                        ui.label(RichText::new(message.as_str()).color(MUTED));
                        ui.add_space(14.0);
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), 34.0),
                            Layout::right_to_left(Align::Center),
                            |ui| {
                                let enabled = !self.busy
                                    && (firewall_ready
                                        || request
                                            .as_deref()
                                            .is_none_or(|request| !firewall_mutation(request)));
                                if button(ui, "Confirm", Kind::Danger, enabled)
                                    && let Some(request) = request.take()
                                {
                                    actions.push(Action::Run(*request));
                                    close = true;
                                }
                                close |= button(ui, "Cancel", Kind::Secondary, !self.busy);
                            },
                        );
                    }
                    Dialog::FirewallRemove { index, rule } => {
                        ui.label(heading("Remove firewall rule?", 18.0));
                        ui.label(
                            RichText::new(format!(
                                "Remove {} {} {} {} for peer {} on network {}?",
                                rule.direction,
                                rule.action,
                                rule.protocol,
                                scope_label(&rule.port),
                                scope_label(&rule.peer),
                                scope_label(&rule.network)
                            ))
                            .color(MUTED),
                        );
                        let unchanged = firewall_rules
                            .and_then(|rules| rules.get(*index))
                            .is_some_and(|current| current == rule.as_ref());
                        if firewall_ready && !unchanged {
                            ui.colored_label(
                                AMBER,
                                "Rules changed. Cancel and select the rule again.",
                            );
                        }
                        ui.add_space(14.0);
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), 34.0),
                            Layout::right_to_left(Align::Center),
                            |ui| {
                                if button(ui, "Confirm", Kind::Danger, firewall_ready && unchanged)
                                {
                                    actions.push(Action::Run(IpcMessage::FirewallRemove {
                                        index: *index,
                                    }));
                                    close = true;
                                }
                                close |= button(ui, "Cancel", Kind::Secondary, !self.busy);
                            },
                        );
                    }
                    Dialog::SshEditor(editor) => {
                        let result =
                            ssh::editor(ui, editor, snapshot, ssh_ready, self.error.as_deref());
                        if let Some(request) = result.request {
                            self.submitted_form = true;
                            actions.push(Action::ShowResult {
                                kind: OutputKind::SshAccess,
                                request,
                            });
                        }
                        close = result.close;
                    }
                    Dialog::SshRemove(rule) => {
                        ui.label(heading("Remove SSH access?", 18.0));
                        ui.label(
                            RichText::new(
                                "Other matching rules can still grant access to this peer.",
                            )
                            .color(MUTED),
                        );
                        let unchanged = snapshot
                            .and_then(|snapshot| snapshot.ssh.as_ref().ok())
                            .is_some_and(|ssh| ssh.rules.contains(rule.as_ref()));
                        if ssh_ready && !unchanged {
                            ui.colored_label(
                                AMBER,
                                "SSH rules changed. Cancel and select the rule again.",
                            );
                        }
                        ui.add_space(12.0);
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), 34.0),
                            Layout::right_to_left(Align::Center),
                            |ui| {
                                if button(ui, "Remove access", Kind::Danger, ssh_ready && unchanged)
                                {
                                    actions.push(Action::ShowResult {
                                        kind: OutputKind::SshAccess,
                                        request: IpcMessage::FirewallSshAllow {
                                            network: rule.network.clone(),
                                            peer: rule.peer.clone(),
                                            users: Vec::new(),
                                            allow: false,
                                        },
                                    });
                                    close = true;
                                }
                                close |= button(ui, "Cancel", Kind::Secondary, !self.busy);
                            },
                        );
                    }
                    Dialog::Output => {
                        ui.label(heading(self.output_kind.title(), 18.0));
                        ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                            ui.add(egui::Label::new(mono(&self.output, 12.0)).selectable(true));
                        });
                        ui.add_space(12.0);
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), 34.0),
                            Layout::right_to_left(Align::Center),
                            |ui| {
                                close = button(ui, "Done", Kind::Secondary, true);
                                if button(ui, "Copy", Kind::Primary, true) {
                                    ctx.copy_text(self.output.clone());
                                }
                            },
                        );
                    }
                }
            });
        if close || (!self.busy && response.should_close()) {
            self.dialog = None;
        }
    }
}

fn firewall_mutation(request: &IpcMessage) -> bool {
    matches!(
        request,
        IpcMessage::FirewallAdd { .. }
            | IpcMessage::FirewallRemove { .. }
            | IpcMessage::FirewallAccept { .. }
            | IpcMessage::FirewallDeny { .. }
            | IpcMessage::ConfigSet {
                key: NodeKey::Firewall(_),
                ..
            }
    )
}

fn scope_label(value: &str) -> &str {
    if value.is_empty() || matches!(value, "*" | "any") {
        "Any"
    } else {
        value
    }
}

fn form(kind: FormKind, network: Option<String>, initial: &str) -> Dialog {
    let mut values = kind.initial_values();
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

fn peer_entry(ui: &mut Ui, peer: &PeerStatus, network: &NetworkStatus, restoring: bool) {
    Frame::new()
        .inner_margin(Margin::symmetric(14, 8))
        .show(ui, |ui| {
            if restoring {
                ui.multiply_opacity(0.5);
            }
            peer_row(ui, peer, network);
        });
}

fn peer_row(ui: &mut Ui, peer: &PeerStatus, network: &NetworkStatus) {
    ui.spacing_mut().interact_size.y = 18.0;
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
            .add(egui::Label::new(mono(hostname, 12.0).color(INK)).sense(egui::Sense::click()))
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
                            *dialog = Some(Dialog::Confirm { title: "Accept firewall rules?".into(), message: "Suggested rules can open ports to peers. Review them before accepting.".into(), request: Some(Box::new(item.command(true))) });
                        } else { actions.push(Action::Run(item.command(true))); }
                    }
                    if let Some(request) = item.review_command() && button(ui, "Review", Kind::Secondary, !busy) { actions.push(Action::ShowResult { kind: OutputKind::Firewall, request }); }
                });
            });
        }
    });
    ui.add_space(14.0);
}

fn setting(ui: &mut Ui, title: &str, detail: &str, value: &mut bool, enabled: bool) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let detail_width = (ui.available_width() - 56.0).max(80.0);
        ui.vertical(|ui| {
            ui.set_max_width(detail_width);
            ui.label(title);
            ui.add(
                egui::Label::new(RichText::new(detail).font(font("body", 14.0)).color(MUTED))
                    .wrap(),
            );
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
    fn initial_loading_never_claims_the_network_list_is_empty() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.refreshing = true;
        for page in Page::ALL {
            app.page = page;
            render(&mut app, &ctx);
            let labels = render(&mut app, &ctx);
            assert!(
                labels
                    .iter()
                    .any(|(text, _)| text == "Loading your networks")
            );
            assert!(
                !labels
                    .iter()
                    .any(|(text, _)| text == "No networks yet." || text == "service unreachable")
            );
        }
    }

    #[test]
    fn unavailable_status_exposes_its_error_and_retry_without_an_empty_state() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.status_error = Some("Example service connection failed.".into());
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        assert!(
            labels
                .iter()
                .any(|(text, _)| text == "Network status unavailable")
        );
        assert!(
            labels
                .iter()
                .any(|(text, _)| text == "Example service connection failed.")
        );
        assert!(!labels.iter().any(|(text, _)| text == "No networks yet."));
        let pos = labels.iter().find(|(text, _)| text == "Retry").unwrap().1 + Vec2::new(4.0, 8.0);
        let mut actions = Vec::new();
        for pressed in [true, false] {
            let _paint = ctx.run(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ],
                    ..Default::default()
                },
                |ctx| actions.extend(app.draw(ctx)),
            );
        }
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Refresh))
        );
    }

    #[test]
    fn last_known_network_stays_visible_during_a_failed_refresh_and_recovers() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        app.status_error = Some("Example service connection failed.".into());
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        assert!(labels.iter().any(|(text, _)| text == "example"));
        assert!(
            labels
                .iter()
                .any(|(text, _)| text.starts_with("Showing the last received status."))
        );
        assert!(
            !labels
                .iter()
                .any(|(text, _)| text == "connected" || text == "No networks yet.")
        );
        app.page = Page::Settings;
        let labels = render(&mut app, &ctx);
        assert!(!labels.iter().any(|(text, _)| text == "connected"));
        app.status_error = None;
        app.page = Page::Networks;
        let labels = render(&mut app, &ctx);
        assert!(labels.iter().any(|(text, _)| text == "connected"));
        assert!(
            !labels
                .iter()
                .any(|(text, _)| text == "Network status unavailable")
        );
    }

    #[test]
    fn pending_membership_waits_for_approval_without_claiming_connectivity() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        let mut snapshot = crate::preview::fixture(false);
        snapshot.status.pending_networks.push("example".into());
        app.snapshot = Some(Box::new(snapshot));
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        assert!(labels.iter().any(|(text, _)| text == "example"));
        assert!(labels.iter().any(|(text, _)| text == "Awaiting approval"));
        assert!(labels.iter().any(|(text, _)| text == "awaiting approval"));
        assert!(!labels.iter().any(|(text, _)| text == "connected"));
        assert!(!labels.iter().any(|(text, _)| text == "No networks yet."));
        app.page = Page::Settings;
        let labels = render(&mut app, &ctx);
        assert!(labels.iter().any(|(text, _)| text == "awaiting approval"));
        assert!(!labels.iter().any(|(text, _)| text == "connected"));
        app.snapshot.as_mut().unwrap().status.networks =
            crate::preview::fixture(true).status.networks;
        let labels = render(&mut app, &ctx);
        assert!(labels.iter().any(|(text, _)| text == "connected"));
    }

    #[test]
    fn disconnect_stays_clickable_while_a_join_is_running() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(false)));
        app.begin_join("workstation".into());
        app.busy = true;
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        let pos = labels
            .iter()
            .find(|(text, _)| text == "Disconnect")
            .unwrap()
            .1
            + Vec2::new(4.0, 8.0);
        let mut actions = Vec::new();
        for pressed in [true, false] {
            let _paint = ctx.run(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ],
                    ..Default::default()
                },
                |ctx| actions.extend(app.draw(ctx)),
            );
        }
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::Toggle))
        );
    }

    #[test]
    fn accepted_join_closes_the_form_and_shows_progress_until_completion() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(false)));
        app.dialog = Some(form(FormKind::Join, None, "example-invite"));
        app.busy = true;
        app.begin_join("workstation".into());
        assert!(app.dialog.is_none());
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        assert!(labels.iter().any(|(text, _)| text == "Joining"));
        assert!(!labels.iter().any(|(text, _)| text == "No networks yet."));
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        app.command_finished(Ok("Joined example.".into()), None);
        app.busy = false;
        let labels = render(&mut app, &ctx);
        assert!(!labels.iter().any(|(text, _)| text == "Joining"));
        assert!(labels.iter().any(|(text, _)| text == "example"));
    }

    #[test]
    fn failed_join_reports_the_error_without_a_stuck_progress_card() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(false)));
        app.begin_join(String::new());
        app.command_finished(Err("Example invite expired.".into()), None);
        assert!(app.joining.is_none());
        assert!(app.dialog.is_none());
        let labels = render(&mut app, &ctx);
        assert!(
            labels
                .iter()
                .any(|(text, _)| text == "Example invite expired.")
        );
    }

    #[test]
    fn firewall_tab_runs_typed_rules_and_both_default_policy_confirmations() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        assert!(click(&mut app, &ctx, "Firewall").is_empty());
        assert_eq!(app.page, Page::Firewall);
        let labels = render(&mut app, &ctx);
        for title in [
            "Direction",
            "Action",
            "Protocol",
            "Ports",
            "Peer",
            "Network",
            "Any",
        ] {
            assert!(
                labels.iter().any(|(text, _)| text == title),
                "missing firewall column or scope: {title}"
            );
        }
        for (button, key, value) in [
            ("Change inbound", FirewallKey::DefaultIn, "allow"),
            ("Change outbound", FirewallKey::DefaultOut, "deny"),
        ] {
            assert!(click(&mut app, &ctx, button).is_empty());
            let actions = click(&mut app, &ctx, "Confirm");
            assert!(actions.iter().any(|action| matches!(action,
                Action::Run(IpcMessage::ConfigSet { key: NodeKey::Firewall(actual), value: actual_value, replace: false })
                    if *actual == key && actual_value == value
            )));
        }
        assert!(click(&mut app, &ctx, "Remove").is_empty());
        assert!(
            click(&mut app, &ctx, "Confirm")
                .iter()
                .any(|action| matches!(
                    action,
                    Action::Run(IpcMessage::FirewallRemove { index: 1 })
                ))
        );
        assert!(click(&mut app, &ctx, "Add rule").is_empty());
        assert!(click(&mut app, &ctx, "Add rule").iter().any(|action| matches!(action,
            Action::Run(IpcMessage::FirewallAdd { port: Some(port), peer: None, network: None, .. }) if port == "443"
        )));
    }

    #[test]
    fn stale_firewall_cannot_mutate_even_from_an_already_open_dialog() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        app.page = Page::Firewall;
        assert!(click(&mut app, &ctx, "Remove").is_empty());
        app.status_error = Some("Example status connection failed.".into());
        assert!(click(&mut app, &ctx, "Confirm").is_empty());
        app.dialog = None;
        for button in ["Add rule", "Change inbound", "Change outbound", "Remove"] {
            assert!(click(&mut app, &ctx, button).is_empty());
            assert!(app.dialog.is_none());
        }
        app.dialog = Some(form(FormKind::Firewall, None, ""));
        assert!(click(&mut app, &ctx, "Add rule").is_empty());
        app.dialog = None;
        app.status_error = None;
        app.snapshot.as_mut().unwrap().firewall = Err("Example firewall read failed.".into());
        assert!(click(&mut app, &ctx, "Add rule").is_empty());
        assert!(app.dialog.is_none());
        assert!(
            click(&mut app, &ctx, "Retry firewall")
                .iter()
                .any(|action| matches!(action, Action::Refresh))
        );
    }

    #[test]
    fn changed_rules_cannot_delete_a_different_rule_from_an_open_confirmation() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        app.page = Page::Firewall;
        assert!(click(&mut app, &ctx, "Remove").is_empty());
        app.snapshot
            .as_mut()
            .unwrap()
            .firewall
            .as_mut()
            .unwrap()
            .rules
            .swap(0, 1);
        assert!(click(&mut app, &ctx, "Confirm").is_empty());
        let labels = render(&mut app, &ctx);
        assert!(
            labels
                .iter()
                .any(|(text, _)| text == "Rules changed. Cancel and select the rule again.")
        );
    }

    #[test]
    fn an_open_suggestion_confirmation_requires_current_firewall_status() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        let mut snapshot = crate::preview::fixture(true);
        snapshot.pending.push(PendingItem {
            description: "Example suggested rule.".into(),
            kind: PendingKind::Firewall {
                network: "example".into(),
            },
        });
        app.snapshot = Some(Box::new(snapshot));
        app.page = Page::Firewall;
        assert!(click(&mut app, &ctx, "Accept").is_empty());
        app.status_error = Some("Example service read failed.".into());
        assert!(click(&mut app, &ctx, "Confirm").is_empty());
        app.status_error = None;
        app.snapshot.as_mut().unwrap().firewall = Err("Example firewall read failed.".into());
        assert!(click(&mut app, &ctx, "Confirm").is_empty());
        app.snapshot.as_mut().unwrap().firewall = crate::preview::fixture(true).firewall;
        assert!(
            click(&mut app, &ctx, "Confirm")
                .iter()
                .any(|action| matches!(
                    action,
                    Action::Run(IpcMessage::FirewallAccept { network }) if network == "example"
                ))
        );
    }

    #[test]
    fn settings_exposes_mesh_ssh_and_keeps_firewall_rules_on_their_own_page() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        app.page = Page::Settings;
        render(&mut app, &ctx);
        let _paint = ctx.run(
            egui::RawInput {
                events: vec![
                    egui::Event::PointerMoved(egui::pos2(500.0, 500.0)),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: Vec2::new(0.0, -350.0),
                        modifiers: Default::default(),
                    },
                ],
                ..Default::default()
            },
            |ctx| {
                app.draw(ctx);
            },
        );
        let labels = render(&mut app, &ctx);
        assert!(labels.iter().any(|(text, _)| text == "Mesh SSH"));
        assert!(
            labels
                .iter()
                .any(|(text, _)| text.contains("local accounts below"))
        );
        assert!(
            !labels
                .iter()
                .any(|(text, _)| text == "Add rule" || text == "Change inbound")
        );
    }

    fn ssh_app(ctx: &Context) -> Dashboard {
        let mut app = Dashboard::new(ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        app.focus_ssh_settings();
        render(&mut app, ctx);
        render(&mut app, ctx);
        app
    }

    #[test]
    fn ssh_picker_grants_access_and_reports_warnings_without_commands() {
        let ctx = Context::default();
        let mut app = ssh_app(&ctx);
        assert!(click(&mut app, &ctx, "Add access rule").is_empty());
        if let Some(Dialog::SshEditor(editor)) = &mut app.dialog {
            editor.usernames = "local-user".into();
        } else {
            panic!("the access editor should open");
        }
        assert!(click(&mut app, &ctx, "Choose peer").is_empty());
        assert!(click(&mut app, &ctx, "All peers on this network").is_empty());
        let actions = click(&mut app, &ctx, "Save access");
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, Action::ShowResult {
            kind: OutputKind::SshAccess,
            request: IpcMessage::FirewallSshAllow { network, peer, users, allow: true },
        } if network == "example" && peer == "*" && users == &["local-user"]))
        );
        app.command_finished(
            Ok("Saved. Other matching rules can still grant access.".into()),
            Some(OutputKind::SshAccess),
        );
        assert!(app.dialog.is_none());
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        assert!(
            labels
                .iter()
                .any(|(text, _)| text.contains("Other matching rules"))
        );
        assert!(!labels.iter().any(
            |(text, _)| text.contains("Run a ray command") || text.contains("ray firewall ssh")
        ));
        assert!(!app.advanced_open);
    }

    #[test]
    fn ssh_edit_and_revoke_emit_the_exact_selected_permission_request() {
        let ctx = Context::default();
        let mut app = ssh_app(&ctx);
        assert!(click(&mut app, &ctx, "Edit").is_empty());
        let Some(Dialog::SshEditor(editor)) = &mut app.dialog else {
            panic!("edit should open the permission editor");
        };
        editor.usernames = "another-local-user".into();
        let actions = click(&mut app, &ctx, "Save access");
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::ShowResult {
            request: IpcMessage::FirewallSshAllow { network, peer, users, allow: true }, ..
        } if network == "example" && peer == "*" && users == &["another-local-user"]));
        app.command_finished(Ok("Saved.".into()), Some(OutputKind::SshAccess));
        assert!(click(&mut app, &ctx, "Remove").is_empty());
        assert!(click(&mut app, &ctx, "Remove access").iter().any(|action| matches!(action,
            Action::ShowResult { request: IpcMessage::FirewallSshAllow { network, peer, allow: false, .. }, .. }
                if network == "example" && peer == "*"
        )));
    }

    #[test]
    fn ssh_remove_confirmation_keeps_buttons_next_to_its_message() {
        for size in [Vec2::new(820.0, 560.0), Vec2::new(1200.0, 1000.0)] {
            let ctx = Context::default();
            let mut app = ssh_app(&ctx);
            let rule = app.snapshot.as_ref().unwrap().ssh.as_ref().unwrap().rules[0].clone();
            app.preview_ssh_editor();
            render_at(&mut app, &ctx, size);
            render_at(&mut app, &ctx, size);
            app.dialog = Some(Dialog::SshRemove(Box::new(rule)));
            render_at(&mut app, &ctx, size);
            let labels = render_at(&mut app, &ctx, size);
            let title = labels
                .iter()
                .find(|(text, _)| text == "Remove SSH access?")
                .unwrap()
                .1;
            let remove = labels
                .iter()
                .find(|(text, _)| text == "Remove access")
                .unwrap()
                .1;
            assert!(
                remove.y - title.y < 120.0,
                "confirmation has excessive empty space: {title:?}, {remove:?}"
            );
            let modal = ctx
                .memory(|memory| memory.area_rect(egui::Id::new("rayfish-dialog")))
                .unwrap();
            assert!(
                modal.height() < 220.0,
                "confirmation is too tall: {modal:?}"
            );
        }
    }

    #[test]
    fn ssh_read_failures_are_not_empty_access_and_block_open_editors() {
        let ctx = Context::default();
        let mut app = ssh_app(&ctx);
        assert!(click(&mut app, &ctx, "Edit").is_empty());
        app.status_error = Some("Example status read failed.".into());
        assert!(click(&mut app, &ctx, "Save access").is_empty());
        app.status_error = None;
        app.snapshot.as_mut().unwrap().ssh = Err("Example SSH read failed.".into());
        assert!(click(&mut app, &ctx, "Save access").is_empty());
        app.dialog = None;
        app.focus_ssh_settings();
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        assert!(
            labels
                .iter()
                .any(|(text, _)| text == "SSH access unavailable")
        );
        assert!(
            !labels
                .iter()
                .any(|(text, _)| text.contains("No peers have SSH access"))
        );
        assert!(
            click(&mut app, &ctx, "Retry SSH access")
                .iter()
                .any(|action| matches!(action, Action::Refresh))
        );
    }

    #[test]
    fn ssh_editor_keeps_actions_visible_at_the_minimum_window_size() {
        let ctx = Context::default();
        let mut app = ssh_app(&ctx);
        app.preview_ssh_editor();
        app.error = Some("Example permission error. ".repeat(30));
        let size = Vec2::new(820.0, 560.0);
        render_at(&mut app, &ctx, size);
        let labels = render_at(&mut app, &ctx, size);
        for title in ["Save access", "Cancel"] {
            let pos = labels.iter().find(|(text, _)| text == title).unwrap().1;
            assert!(
                pos.y >= 0.0 && pos.y < 530.0 && pos.x < 790.0,
                "{title} must stay in view: {pos:?}"
            );
        }
    }

    #[test]
    fn firewall_columns_keep_long_scopes_compact_at_the_minimum_window_width() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        let mut snapshot = crate::preview::fixture(true);
        for rule in &mut snapshot.firewall.as_mut().unwrap().rules {
            rule.peer = "example-peer-".repeat(8);
            rule.network = "example-network-".repeat(4);
        }
        app.snapshot = Some(Box::new(snapshot));
        app.page = Page::Firewall;
        render_at(&mut app, &ctx, Vec2::new(820.0, 680.0));
        let labels = render_at(&mut app, &ctx, Vec2::new(820.0, 680.0));
        let remove = labels
            .iter()
            .filter(|(text, _)| text == "Remove")
            .collect::<Vec<_>>();
        assert_eq!(remove.len(), 2);
        assert!(remove.iter().all(|(_, pos)| pos.x < 790.0));
        let row_spacing = remove[1].1.y - remove[0].1.y;
        assert!(
            row_spacing <= 40.0,
            "firewall rows are {row_spacing} points apart"
        );
    }

    #[test]
    fn firewall_form_actions_fit_the_minimum_window_height() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        app.page = Page::Firewall;
        for error in [
            None,
            Some("Example invalid rule. Select a valid port and try again.".into()),
        ] {
            app.dialog = Some(form(FormKind::Firewall, None, ""));
            app.error = error;
            render_at(&mut app, &ctx, Vec2::new(820.0, 560.0));
            let labels = render_at(&mut app, &ctx, Vec2::new(820.0, 560.0));
            for title in ["Add rule", "Cancel"] {
                let (_, position) = labels
                    .iter()
                    .rev()
                    .find(|(label, _)| label == title)
                    .unwrap_or_else(|| panic!("missing form action {title}"));
                assert!(
                    position.y >= 0.0 && position.y + 24.0 <= 560.0,
                    "form action {title} is outside the minimum window: {position:?}"
                );
            }
        }
    }

    fn click(app: &mut Dashboard, ctx: &Context, label: &str) -> Vec<Action> {
        render(app, ctx);
        let labels = render(app, ctx);
        let pos = labels
            .iter()
            .rev()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing button {label}"))
            .1
            + Vec2::new(4.0, 8.0);
        let mut actions = Vec::new();
        for pressed in [true, false] {
            let _paint = ctx.run(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: Default::default(),
                        },
                    ],
                    ..Default::default()
                },
                |ctx| actions.extend(app.draw(ctx)),
            );
        }
        actions
    }

    fn render(app: &mut Dashboard, ctx: &Context) -> Vec<(String, egui::Pos2)> {
        render_at(app, ctx, Vec2::new(1000.0, 680.0))
    }

    fn render_at(app: &mut Dashboard, ctx: &Context, size: Vec2) -> Vec<(String, egui::Pos2)> {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            },
            |ctx| {
                app.draw(ctx);
            },
        );
        output
            .shapes
            .into_iter()
            .filter_map(|shape| match shape.shape {
                egui::epaint::Shape::Text(text) => Some((text.galley.job.text.clone(), text.pos)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn six_peers_fit_in_the_default_window_with_compact_rows() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        app.snapshot = Some(Box::new(crate::preview::fixture(true)));
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        let peers: Vec<_> = labels
            .iter()
            .filter(|(text, _)| text.starts_with("workstation-"))
            .collect();
        assert_eq!(
            peers.len(),
            6,
            "all six peers should be visible: {labels:?}"
        );
        for pair in peers.windows(2) {
            assert!(
                pair[1].1.y - pair[0].1.y <= 40.0,
                "peer rows should be at most 40 points apart"
            );
        }
    }

    #[test]
    fn restoring_network_keeps_its_card_and_saved_peers() {
        let ctx = Context::default();
        let mut app = Dashboard::new(&ctx).unwrap();
        let mut snapshot = crate::preview::fixture(true);
        let network = snapshot.status.networks.remove(0);
        snapshot
            .status
            .inactive_networks
            .push(ray_proto::ipc::InactiveNetwork {
                name: network.name.clone(),
                reason: None,
                saved: Some(network),
            });
        app.snapshot = Some(Box::new(snapshot));
        render(&mut app, &ctx);
        let labels = render(&mut app, &ctx);
        assert!(
            labels.iter().any(|(text, _)| text == "example"),
            "saved network card is missing"
        );
        assert!(
            labels.iter().any(|(text, _)| text == "workstation-1"),
            "saved peer is missing"
        );
        assert!(labels.iter().any(|(text, _)| text == "6 peers"));
        assert!(!labels.iter().any(|(text, _)| text == "No networks yet."));
    }

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
