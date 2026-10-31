//! Render the real desktop view with fabricated data for visual inspection.

use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{SyncSender, sync_channel};

use anyhow::{Context, Result};
use eframe::egui::{self, ViewportCommand};
use ray_proto::ipc::{
    FirewallRuleView, InactiveNetwork, NetworkRole, NetworkStatus, PeerState, PeerStatus,
};
use ray_proto::{Action, Direction, Protocol};
use serde_json::{Map, json};

use crate::model::{Firewall, PendingCounts, Snapshot, SshRule, SshState, Status};
use crate::ui::{Dashboard, Page};

pub(crate) enum PreviewState {
    Normal,
    SshSettings,
    SshEditor,
    Joining,
    Reconnecting,
    Loading,
    Unavailable,
    Stale,
}

pub(crate) fn run(
    path: PathBuf,
    populated: bool,
    page: Page,
    state: PreviewState,
    minimum: bool,
) -> Result<()> {
    let (sender, receiver) = sync_channel(1);
    let mut options = crate::window::options()?;
    if minimum {
        options.viewport = options.viewport.with_inner_size([820.0, 560.0]);
    }
    eframe::run_native(
        "Rayfish preview",
        options,
        Box::new(move |cc| {
            let mut dashboard = Dashboard::new(&cc.egui_ctx)?;
            cc.egui_ctx.style_mut(|style| style.animation_time = 0.0);
            let mut snapshot = fixture(
                populated || matches!(state, PreviewState::Reconnecting | PreviewState::Stale),
            );
            if matches!(state, PreviewState::Reconnecting) {
                let mut network = snapshot.status.networks.remove(0);
                for peer in &mut network.peers {
                    peer.state = PeerState::Offline;
                }
                snapshot.status.inactive_networks.push(InactiveNetwork {
                    name: network.name.clone(),
                    reason: None,
                    saved: Some(network),
                });
            }
            dashboard.snapshot =
                if matches!(state, PreviewState::Loading | PreviewState::Unavailable) {
                    None
                } else {
                    Some(Box::new(snapshot))
                };
            dashboard.page = page;
            dashboard.refreshing = matches!(state, PreviewState::Loading);
            if matches!(state, PreviewState::Unavailable | PreviewState::Stale) {
                dashboard.status_error =
                    Some("Could not read the service status: example connection failure.".into());
            }
            if matches!(state, PreviewState::Joining) {
                dashboard.begin_join("workstation".into());
                dashboard.busy = true;
            }
            if matches!(state, PreviewState::SshEditor) {
                dashboard.preview_ssh_editor();
            }
            if matches!(state, PreviewState::SshSettings) {
                dashboard.focus_ssh_settings();
            }
            Ok(Box::new(Preview {
                dashboard,
                path,
                frames: 0,
                requested: false,
                done: false,
                sender,
            }))
        }),
    )
    .map_err(|error| anyhow::anyhow!("rendering the desktop preview: {error}"))?;
    receiver
        .recv()
        .context("the preview closed before rendering")?
        .map_err(|error| anyhow::anyhow!(error))
}

struct Preview {
    dashboard: Dashboard,
    path: PathBuf,
    frames: usize,
    requested: bool,
    done: bool,
    sender: SyncSender<Result<(), String>>,
}

impl eframe::App for Preview {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.dashboard.draw(ctx);
        self.frames += 1;
        if self.frames >= 3 && !self.requested {
            ctx.send_viewport_cmd(ViewportCommand::Screenshot(Default::default()));
            self.requested = true;
        }
        for event in ctx.input(|input| input.events.clone()) {
            if let egui::Event::Screenshot { image, .. } = event
                && !self.done
            {
                let result = save(&image, &self.path).map_err(|error| format!("{error:#}"));
                // Exactly one result fits in the bounded queue. A closed
                // receiver means the preview caller is already shutting down.
                let _ = self.sender.try_send(result);
                self.done = true;
                ctx.send_viewport_cmd(ViewportCommand::Close);
            }
        }
        ctx.request_repaint();
    }
}

fn save(image: &egui::ColorImage, path: &Path) -> Result<()> {
    let rgba = image
        .pixels
        .iter()
        .flat_map(|pixel| pixel.to_array())
        .collect::<Vec<_>>();
    image::save_buffer(
        path,
        &rgba,
        u32::try_from(image.size[0])?,
        u32::try_from(image.size[1])?,
        image::ColorType::Rgba8,
    )
    .context("saving the desktop preview")
}

pub(crate) fn fixture(populated: bool) -> Snapshot {
    let networks = if populated {
        vec![NetworkStatus {
            name: "example".into(),
            role: NetworkRole::Coordinator,
            mode: None,
            my_ipv6: Ipv6Addr::LOCALHOST,
            my_hostname: Some("workstation".into()),
            network_key: None,
            member_count: 1,
            peers: (1..=6).map(peer).collect(),
            pending_suggestions: 0,
            pending_requests: 0,
            aliases: Default::default(),
            ephemeral_ttl_secs: None,
            my_exit_node: None,
            exit_offering: false,
            incompatible: None,
        }]
    } else {
        Vec::new()
    };
    let mut config = Map::new();
    config.insert("dns".into(), json!("partial"));
    config.insert("mdns".into(), json!(true));
    config.insert("auto-update".into(), json!(true));
    config.insert("ssh".into(), json!(true));
    Snapshot {
        status: Status {
            active: true,
            identity: None,
            networks,
            inactive_networks: Vec::new(),
            pending_networks: Vec::new(),
            connection_errors: Vec::new(),
            managed_machines: None,
            pending: PendingCounts::default(),
        },
        config: Ok(config),
        firewall: Ok(Firewall {
            default_inbound: Action::Deny,
            default_outbound: Action::Allow,
            rules: if populated {
                vec![
                    FirewallRuleView {
                        direction: Direction::In,
                        action: Action::Allow,
                        protocol: Protocol::Tcp,
                        port: "443".into(),
                        peer: "any".into(),
                        network: "example".into(),
                        suggested_by: None,
                    },
                    FirewallRuleView {
                        direction: Direction::Out,
                        action: Action::Deny,
                        protocol: Protocol::Udp,
                        port: "8000-9000".into(),
                        peer: "workstation".into(),
                        network: "any".into(),
                        suggested_by: None,
                    },
                ]
            } else {
                Vec::new()
            },
        }),
        ssh: Ok(SshState {
            enabled: true,
            port: 22,
            rules: if populated {
                vec![SshRule {
                    network: "example".into(),
                    peer: "*".into(),
                    users: vec!["local-user".into()],
                }]
            } else {
                Vec::new()
            },
        }),
        pending: Vec::new(),
        warnings: Vec::new(),
        launch_at_login: false,
    }
}

fn peer(index: u8) -> PeerStatus {
    serde_json::from_value(json!({
        "endpoint_id": "5866666666666666666666666666666666666666666666666666666666666666",
        "ipv6": Ipv6Addr::from(u128::from(index)).to_string(),
        "hostname": format!("workstation-{index}"),
        "user_identity": null,
        "connection": null,
        "state": "Idle"
    }))
    .expect("The fabricated peer uses a valid public key and status fields.")
}
