//! Mesh SSH access controls matching the macOS settings and rule editor.

use crate::forms::{SshAccounts, SshPeerScope};

use super::*;

impl Dashboard {
    pub(super) fn ssh_ready(&self) -> bool {
        !self.busy
            && self.status_error.is_none()
            && self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.ssh.is_ok())
    }

    pub(super) fn ssh_settings(&mut self, ui: &mut Ui, actions: &mut Vec<Action>) {
        let ready = self.ssh_ready();
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let panel = card().show(ui, |ui| {
            let mut enabled = snapshot.ssh.as_ref().is_ok_and(|ssh| ssh.enabled);
            if setting(ui, "Mesh SSH", "Allow trusted Rayfish peers to sign in to this PC. Access is limited to the networks, peers, and local accounts below.", &mut enabled, ready) {
                actions.push(Action::ShowResult { kind: OutputKind::SshAccess, request: IpcMessage::ConfigSet {
                    key: NodeKey::Global(GlobalKey::Ssh),
                    value: if enabled { "on" } else { "off" }.into(),
                    replace: false,
                }});
            }
            if self.notice_in_ssh {
                if let Some(notice) = &self.notice { ui.label(RichText::new(notice).color(BODY)); }
                if let Some(error) = &self.error { ui.colored_label(AMBER, error); }
            }
            rule(ui);
            let ssh = match &snapshot.ssh {
                Ok(ssh) => ssh,
                Err(error) => {
                    ui.label(heading("SSH access unavailable", 14.0));
                    ui.colored_label(AMBER, error);
                    if button(ui, "Retry SSH access", Kind::Secondary, !self.busy && !self.refreshing) {
                        actions.push(Action::Refresh);
                    }
                    return;
                }
            };
            ui.label(mono(format!("Port {}", ssh.port), 11.0).color(FAINT));
            if ssh.rules.is_empty() {
                ui.label(RichText::new("No peers have SSH access. Add a rule to allow someone.").color(FAINT));
            }
            for (index, access) in ssh.rules.iter().enumerate() {
                if index != 0 { rule(ui); }
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.set_max_width((ui.available_width() - 155.0).max(180.0));
                        ui.add(egui::Label::new(format!("{} on {}", peer_label(snapshot, access), access.network)).truncate());
                        ui.add(egui::Label::new(mono(accounts_label(&access.users), 11.0).color(MUTED)).truncate())
                            .on_hover_text(accounts_label(&access.users));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if button(ui, "Remove", Kind::Danger, ready) {
                            self.dialog = Some(Dialog::SshRemove(Box::new(access.clone())));
                            self.error = None;
                        }
                        if button(ui, "Edit", Kind::Secondary, ready) {
                            self.dialog = Some(Dialog::SshEditor(Box::new(SshEditor::edit(access.clone()))));
                            self.error = None;
                        }
                    });
                });
            }
            ui.add_space(8.0);
            let network = snapshot.status.visible_networks().next().map(|network| network.name.as_str());
            if button(ui, "Add access rule", Kind::Primary, ready && network.is_some()) {
                self.dialog = Some(Dialog::SshEditor(Box::new(SshEditor::new(network))));
                self.error = None;
            }
            if network.is_none() {
                ui.label(RichText::new("Join or create a network to add SSH access.").color(FAINT));
            } else if !ssh.enabled && !ssh.rules.is_empty() {
                ui.label(RichText::new("SSH is off. These rules take effect when you enable it.").color(FAINT));
            }
        });
        if self.focus_ssh {
            let target = egui::Rect::from_min_max(
                panel.response.rect.min,
                panel.response.rect.max + Vec2::new(0.0, 70.0),
            );
            ui.scroll_to_rect_animation(
                target,
                Some(Align::BOTTOM),
                egui::style::ScrollAnimation::none(),
            );
            self.focus_ssh = false;
        }
    }
}

pub(super) struct EditorResult {
    pub request: Option<IpcMessage>,
    pub close: bool,
}

pub(super) fn editor(
    ui: &mut Ui,
    form: &mut SshEditor,
    snapshot: Option<&Snapshot>,
    ready: bool,
    error: Option<&str>,
) -> EditorResult {
    let editing = form.original.is_some();
    let unchanged = form.original.as_ref().is_none_or(|original| {
        snapshot
            .and_then(|snapshot| snapshot.ssh.as_ref().ok())
            .is_some_and(|ssh| ssh.rules.contains(original))
    });
    ui.label(heading(
        if editing {
            "Edit SSH access"
        } else {
            "Allow SSH access"
        },
        18.0,
    ));
    ui.add_space(6.0);
    ScrollArea::vertical().id_salt("ssh-editor-fields")
        .max_height((ui.ctx().content_rect().height() - 165.0).max(80.0))
        .show(ui, |ui| {
            ui.label(RichText::new("Network").color(MUTED));
            let previous = form.network.clone();
            ui.add_enabled_ui(!editing, |ui| {
                egui::ComboBox::from_id_salt("ssh-network").width(ui.available_width())
                    .selected_text(if form.network.is_empty() { "Choose a network" } else { &form.network })
                    .show_ui(ui, |ui| {
                        if let Some(snapshot) = snapshot {
                            for network in snapshot.status.visible_networks() {
                                ui.selectable_value(&mut form.network, network.name.clone(), &network.name);
                            }
                        }
                    });
            });
            if form.network != previous {
                form.peer.clear();
                form.scope = SshPeerScope::Specific;
            }
            ui.add_space(4.0);
            ui.label(RichText::new("Peer").color(MUTED));
            ui.add_enabled_ui(!editing, |ui| {
                ui.horizontal(|ui| {
                    if form.scope == SshPeerScope::All {
                        ui.add_sized([(ui.available_width() - 120.0).max(120.0), 34.0], egui::Label::new("All peers on this network"));
                    } else {
                        ui.add_sized([(ui.available_width() - 120.0).max(120.0), 34.0], egui::TextEdit::singleline(&mut form.peer).hint_text("Peer name, IP address or identity"));
                    }
                    ui.menu_button("Choose peer", |ui| {
                        if ui.button("All peers on this network").clicked() {
                            form.scope = SshPeerScope::All;
                            form.peer.clear();
                            ui.close();
                        }
                        if ui.button("Enter a specific peer").clicked() {
                            form.scope = SshPeerScope::Specific;
                            form.peer.clear();
                            ui.close();
                        }
                        if let Some(network) = snapshot.and_then(|snapshot| snapshot.status.visible_networks().find(|network| network.name == form.network)) {
                            ui.separator();
                            for peer in &network.peers {
                                let identity = peer.user_identity.unwrap_or(peer.endpoint_id).to_string();
                                if ui.button(peer.hostname.as_deref().unwrap_or("Unnamed peer")).clicked() {
                                    form.peer = identity;
                                    form.scope = SshPeerScope::Specific;
                                    ui.close();
                                }
                            }
                        }
                    });
                });
            });
            if form.scope == SshPeerScope::Specific
                && let Some(name) = snapshot.and_then(|snapshot| chosen_peer_name(snapshot, &form.network, &form.peer))
            {
                ui.label(RichText::new(format!("Selected peer: {name}")).small().color(MUTED));
            }
            ui.add_space(4.0);
            ui.label(RichText::new("Local accounts").color(MUTED));
            egui::ComboBox::from_id_salt("ssh-accounts").width(ui.available_width())
                .selected_text(form.accounts.label()).show_ui(ui, |ui| {
                    for mode in SshAccounts::ALL {
                        ui.selectable_value(&mut form.accounts, mode, mode.label());
                    }
                });
            if form.accounts == SshAccounts::Specific {
                ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut form.usernames).hint_text("Local usernames, separated by commas"));
            }
            ui.label(RichText::new("Rules apply to the peer's identity, including its paired devices. An all-peers rule also covers future members of this network.").color(MUTED));
            if ready && !unchanged {
                ui.colored_label(AMBER, "SSH rules changed. Cancel and select the rule again.");
            }
            if let Err(error) = form.command() {
                ui.label(RichText::new(error.to_string()).color(MUTED));
            }
            if let Some(error) = snapshot.and_then(|snapshot| snapshot.ssh.as_ref().err()) {
                ui.colored_label(AMBER, error);
            } else if !ready {
                ui.label(RichText::new("Waiting for the current operation or a fresh SSH status.").color(MUTED));
            }
            if let Some(error) = error { ui.colored_label(AMBER, error); }
        });
    ui.add_space(8.0);
    let mut result = EditorResult {
        request: None,
        close: false,
    };
    let command = form.command();
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        if button(
            ui,
            "Save access",
            Kind::Primary,
            ready && unchanged && command.is_ok(),
        ) {
            result.request = command.ok();
        }
        result.close = button(ui, "Cancel", Kind::Secondary, true);
    });
    result
}

fn chosen_peer_name<'a>(snapshot: &'a Snapshot, network: &str, selected: &str) -> Option<&'a str> {
    snapshot
        .status
        .visible_networks()
        .find(|item| item.name == network)
        .and_then(|network| {
            network
                .peers
                .iter()
                .find(|peer| peer.user_identity.unwrap_or(peer.endpoint_id).to_string() == selected)
        })
        .and_then(|peer| peer.hostname.as_deref())
}

fn peer_label(snapshot: &Snapshot, rule: &SshRule) -> String {
    if rule.peer == "*" {
        return "All peers".into();
    }
    snapshot
        .status
        .visible_networks()
        .find(|network| network.name == rule.network)
        .and_then(|network| {
            network.peers.iter().find(|peer| {
                peer.user_identity.unwrap_or(peer.endpoint_id).to_string() == rule.peer
            })
        })
        .and_then(|peer| peer.hostname.clone())
        .unwrap_or_else(|| rule.peer.clone())
}

fn accounts_label(users: &[String]) -> String {
    if users.iter().any(|user| user == "*") {
        SshAccounts::All.label().into()
    } else if users.is_empty() {
        SshAccounts::NonAdministrator.label().into()
    } else {
        users.join(", ")
    }
}
