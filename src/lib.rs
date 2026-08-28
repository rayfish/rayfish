//! Internal library crate for the `ray` binary. **Not a stable public API**,
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

/// The async mutex, under a name that cannot be mistaken for the std one.
///
/// `Mutex` is always `std::sync::Mutex` in this crate; when a lock genuinely
/// has to be held across an await, it is an `AsyncMutex` and says so at the
/// field. Two types called `Mutex` distinguished only by their import is the
/// one place that distinction is easy to get wrong, and holding the std one
/// across an await does not fail until it deadlocks.
pub type AsyncMutex<T> = tokio::sync::Mutex<T>;

pub mod apply;
pub mod audit;
pub mod config;
pub mod control;
pub mod daemon;
pub mod deeplink;
pub mod dht;
pub mod dns;
pub mod exit_node;
pub mod firewall;
pub mod forward;
pub mod hostfw;
pub mod hostname;
pub mod identity;
// Linux init-system abstraction (systemd / OpenRC / SysV) behind the service
// management commands. Desktop-only: Android has no `ray` service to install.
#[cfg(all(feature = "desktop", target_os = "linux"))]
pub mod init_system;
pub mod invite;
pub mod ipc;
pub mod keybackup;
// Kernel notification of listen()/close on the host's TCP sockets, which is
// what keeps `v4bridge` off a poll. Internal to that one caller, and desktop
// for the same reason it is.
#[cfg(feature = "desktop")]
mod listen_events;
// Shared by `ssh` and `v4bridge`, so it cannot live in `ssh`: that module is
// Unix-only and `v4bridge` is not. Both are `desktop`-only, and a build without
// that feature (Android) has no listener to bind.
#[cfg(feature = "desktop")]
mod listener;
pub mod logdir;
pub mod membership;
pub mod network_name;
#[cfg(feature = "desktop")]
pub mod onepassword;
pub mod peers;
pub mod ratelimit;
pub mod reject;
pub mod roles;
pub mod shutdown;
#[cfg(feature = "desktop")]
#[cfg(unix)]
pub mod ssh;
#[cfg(all(feature = "desktop", windows))]
#[path = "ssh_windows.rs"]
pub mod ssh;
pub mod stats;
pub mod term;
pub mod transport;
pub mod tun;
#[cfg(windows)]
pub mod windows_identity;
#[cfg(windows)]
pub(crate) mod windows_process;
#[cfg(windows)]
pub(crate) mod windows_security;
#[cfg(windows)]
pub mod windows_service;
// Self-replacing binary update relies on `self-replace` (a desktop-only dep) and
// only ever runs from the desktop daemon/CLI; it is not part of the Android lib.
#[cfg(feature = "desktop")]
pub mod update;
// Bridging the host's IPv4-only listeners onto the mesh address needs to
// enumerate those listeners, which is per-OS and has no answer on Android.
#[cfg(feature = "desktop")]
pub mod v4bridge;
