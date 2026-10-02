//! macOS daemon exit-client firewall. NetworkExtension owns its own settings.

use super::*;

const CLIENT_ANCHOR: &str = "com.apple/rayfish_exit_client";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ControlDnsSocket {
    pub local_port: u16,
    pub server: SocketAddr,
    pub tcp: bool,
}

static DNS_SOCKETS: Mutex<Vec<ControlDnsSocket>> = Mutex::new(Vec::new());
/// Local UDP ports of the endpoint's underlay sockets. They are pinned to the
/// physical interface, so every direct peer path leaves from one of them.
static UNDERLAY_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());
static FILTER_UPDATE: Mutex<()> = Mutex::new(());
static FILTER_READY: AtomicBool = AtomicBool::new(false);

pub(crate) fn allow_control_dns(socket: ControlDnsSocket) -> Result<()> {
    DNS_SOCKETS
        .lock()
        .map_err(|_| anyhow::anyhow!("DNS socket lock poisoned"))?
        .push(socket);
    if let Err(error) = refresh_client_filter() {
        remove_control_dns(&socket);
        return Err(error);
    }
    Ok(())
}

pub(crate) fn remove_control_dns(socket: &ControlDnsSocket) {
    if let Ok(mut sockets) = DNS_SOCKETS.lock() {
        sockets.retain(|s| s != socket);
    }
    if let Err(error) = refresh_client_filter() {
        tracing::warn!(%error, "could not remove DNS transport exception");
    }
}

fn client_snapshot_path() -> Result<PathBuf> {
    Ok(crate::config::config_dir()?.join("exit-client.snapshot"))
}

pub(crate) fn install_client_filter(tun: &str, underlay_ports: &[u16]) -> Result<()> {
    let _guard = FILTER_UPDATE
        .lock()
        .map_err(|_| anyhow::anyhow!("exit filter lock poisoned"))?;
    *UNDERLAY_PORTS
        .lock()
        .map_err(|_| anyhow::anyhow!("underlay port lock poisoned"))? = underlay_ports.to_vec();
    install_filter(tun)
}

fn install_filter(tun: &str) -> Result<()> {
    let path = client_snapshot_path()?;
    let first = !path.exists();
    let mut snap = if first {
        Snapshot::default()
    } else {
        Snapshot::load(&path)
    };
    snap.tun_name = Some(tun.to_owned());
    if snap.pf_token.is_none() {
        snap.pf_token = pf::pf_enable()?;
    }
    snap.save(&path)?;
    pf::ensure_anchor_referenced()?;
    anyhow::ensure!(
        pf::pfctl(&["-sr"])?.contains("anchor \"com.apple/*\""),
        "pf must reference the com.apple/* filter anchor for exit-client protection"
    );
    let excluded = EXCLUDED_IPS
        .lock()
        .map_err(|_| anyhow::anyhow!("exit exclusions lock poisoned"))?;
    let mut rules =
        format!("pass out quick on lo0 all no state\npass out quick on {tun} all no state\n");
    for port in UNDERLAY_PORTS
        .lock()
        .map_err(|_| anyhow::anyhow!("underlay port lock poisoned"))?
        .iter()
    {
        rules.push_str(&format!(
            "pass out quick proto udp from any port {port} user 0 no state\n"
        ));
    }
    for ip in excluded.iter() {
        rules.push_str(&format!(
            "pass out quick proto {{ tcp, udp }} to {ip} user 0 no state\n"
        ));
    }
    for socket in DNS_SOCKETS
        .lock()
        .map_err(|_| anyhow::anyhow!("DNS socket lock poisoned"))?
        .iter()
    {
        let protocol = if socket.tcp { "tcp" } else { "udp" };
        rules.push_str(&format!(
            "pass out quick proto {protocol} from any port {} to {} port {} no state\n",
            socket.local_port,
            socket.server.ip(),
            socket.server.port()
        ));
    }
    rules.push_str("pass out quick inet proto udp from any port 68 to any port 67 no state\n");
    rules.push_str("pass out quick inet6 proto udp from any port 546 to any port 547 no state\n");
    rules.push_str("pass out quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } no state\n");
    for (family, prefix, destination) in [
        ("-inet", ipv4::SERVER_PREFIX, "any"),
        ("-inet6", V6_OVERLAY, "! 200::/7"),
    ] {
        if let Some(route) = pf::physical_default_route(family) {
            let af = if family == "-inet" { "inet" } else { "inet6" };
            rules.push_str(&format!("pass in quick on {tun} route-to ({} {}) {af} from {prefix} to {destination} tag RAYFISH_TRANSIT keep state\n", route.interface, route.gateway));
        }
    }
    rules.push_str("pass out quick tagged RAYFISH_TRANSIT no state\n");
    rules.push_str("block drop out quick all\n");
    pf::pf_load_anchor(CLIENT_ANCHOR, &rules)?;
    if !FILTER_READY.load(Ordering::Acquire) {
        // PF checks established states before filtering. Existing direct flows
        // must reconnect through the exit instead of retaining their bypass.
        pf::pfctl(&["-F", "states"])?;
        FILTER_READY.store(true, Ordering::Release);
    }
    Ok(())
}

pub(super) fn refresh_client_filter() -> Result<()> {
    let _guard = FILTER_UPDATE
        .lock()
        .map_err(|_| anyhow::anyhow!("exit filter lock poisoned"))?;
    let path = client_snapshot_path()?;
    if path.exists()
        && let Some(tun) = Snapshot::load(&path).tun_name
    {
        install_filter(&tun)?;
    }
    Ok(())
}

pub(crate) fn remove_client_filter() {
    let Ok(_guard) = FILTER_UPDATE.lock() else {
        return;
    };
    let Ok(path) = client_snapshot_path() else {
        return;
    };
    if !path.exists() {
        return;
    }
    if pf::pf_load_anchor(CLIENT_ANCHOR, "").is_err() {
        return;
    }
    if let Some(token) = Snapshot::load(&path).pf_token {
        pf::pf_release(&token);
    }
    let _ = fs::remove_file(path);
    FILTER_READY.store(false, Ordering::Release);
}
