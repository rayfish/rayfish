//! Internal library crate for the `ray` binary. **Not a stable public API** —
//! exposed only so Criterion benchmarks (see `benches/`) and integration tests
//! can exercise the internal data path (the hot forwarding loop, firewall
//! evaluation, packet parsing) without going through the binary. No semver
//! guarantees on any of these modules; depend on the `ray` binary, not this
//! crate. `src/main.rs` is a thin clap CLI + IPC client built on top, importing
//! these modules via `use rayfish::…`.
#![doc(hidden)]

pub const APP_NAME: &str = "ray";
pub const DNS_DOMAIN: &str = "ray";

use futures::StreamExt;
use iroh::endpoint::{Connection as IrohConnection, PathEvent};

/// Logs iroh path events (opened, closed, selected) for a peer connection.
pub(crate) fn spawn_path_logger(conn: IrohConnection, label: String) {
    let paths = conn.paths();
    for path in paths.iter() {
        tracing::info!(
            peer = %label,
            addr = ?path.remote_addr(),
            rtt = ?path.rtt(),
            selected = path.is_selected(),
            "existing path"
        );
    }

    tokio::spawn(async move {
        let mut events = conn.path_events();
        while let Some(event) = events.next().await {
            match event {
                PathEvent::Opened { remote_addr, .. } => {
                    tracing::info!(peer = %label, addr = ?remote_addr, "path opened");
                }
                PathEvent::Closed { remote_addr, .. } => {
                    tracing::info!(peer = %label, addr = ?remote_addr, "path closed");
                }
                PathEvent::Selected { remote_addr, .. } => {
                    tracing::info!(peer = %label, addr = ?remote_addr, "path selected");
                }
                PathEvent::Lagged { missed, .. } => {
                    tracing::warn!(peer = %label, missed, "path events lagged");
                }
                _ => {}
            }
        }
    });
}

pub mod apply;
pub mod audit;
pub mod config;
pub mod control;
pub mod daemon;
pub mod dht;
pub mod dns;
pub mod dns_config;
pub mod dns_packet;
pub mod dns_resolver;
pub mod firewall;
pub mod forward;
pub mod hostname;
pub mod identity;
pub mod invite;
pub mod ipc;
pub mod layout;
pub mod logdir;
pub mod membership;
pub mod network_name;
pub mod onepassword;
pub mod peers;
pub mod picker;
pub mod progress;
pub mod ratelimit;
pub mod reject;
pub mod shutdown;
pub mod ssh;
pub mod stats;
pub mod style;
pub mod transport;
pub mod tun;
