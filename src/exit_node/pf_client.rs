//! macOS daemon exit-client firewall. NetworkExtension owns its own settings.

use super::*;

const CLIENT_ANCHOR: &str = "com.apple/rayfish_exit_client";

/// A resolver the endpoint's own DNS client may reach directly, as root.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ControlDnsServer {
    pub server: SocketAddr,
    pub tcp: bool,
}

/// Only grows: the control-plane resolvers are a short fixed list, and keeping
/// them avoids a pf rebuild for every DNS socket the endpoint opens and closes.
static DNS_SERVERS: Mutex<Vec<ControlDnsServer>> = Mutex::new(Vec::new());
static FILTER_UPDATE: Mutex<()> = Mutex::new(());

pub(crate) fn allow_control_dns(server: ControlDnsServer) -> Result<()> {
    {
        let mut servers = DNS_SERVERS
            .lock()
            .map_err(|_| anyhow::anyhow!("DNS server lock poisoned"))?;
        if servers.contains(&server) {
            return Ok(());
        }
        servers.push(server);
    }
    if let Err(error) = refresh_client_filter() {
        if let Ok(mut servers) = DNS_SERVERS.lock() {
            servers.retain(|s| *s != server);
        }
        return Err(error);
    }
    Ok(())
}

fn client_snapshot_path() -> Result<PathBuf> {
    Ok(crate::config::config_dir()?.join("exit-client.snapshot"))
}

pub(crate) fn install_client_filter(tun: &str) -> Result<()> {
    let _guard = FILTER_UPDATE
        .lock()
        .map_err(|_| anyhow::anyhow!("exit filter lock poisoned"))?;
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
    // The endpoint's underlay sockets belong to the root daemon and are pinned
    // to the physical interface. Matching them by owner rather than by port
    // survives iroh rebinding to a new port after a network change.
    rules.push_str("pass out quick proto udp user 0 no state\n");
    for ip in excluded.iter() {
        rules.push_str(&format!(
            "pass out quick proto {{ tcp, udp }} to {ip} user 0 no state\n"
        ));
    }
    for dns in DNS_SERVERS
        .lock()
        .map_err(|_| anyhow::anyhow!("DNS server lock poisoned"))?
        .iter()
    {
        let protocol = if dns.tcp { "tcp" } else { "udp" };
        rules.push_str(&format!(
            "pass out quick proto {protocol} to {} port {} user 0 no state\n",
            dns.server.ip(),
            dns.server.port()
        ));
    }
    rules.push_str("pass out quick inet proto udp from any port 68 to any port 67 no state\n");
    rules.push_str("pass out quick inet6 proto udp from any port 546 to any port 547 no state\n");
    rules.push_str("pass out quick inet6 proto icmp6 icmp6-type { 133, 134, 135, 136 } no state\n");
    // The physical default routes, read on every rebuild, so a guard rebuilt
    // after the uplink changed blocks the new one.
    let mut uplinks: Vec<String> = Vec::new();
    for (family, af, prefix, destination) in [
        ("-inet", "inet", ipv4::SERVER_PREFIX, "any".to_owned()),
        ("-inet6", "inet6", V6_OVERLAY, format!("! {V6_OVERLAY}")),
    ] {
        if let Some(route) = pf::physical_default_route(family) {
            rules.push_str(&format!("pass in quick on {tun} route-to ({} {}) {af} from {prefix} to {destination} tag RAYFISH_TRANSIT keep state\n", route.interface, route.gateway));
            if !uplinks.contains(&route.interface) {
                uplinks.push(route.interface);
            }
        }
    }
    rules.push_str("pass out quick tagged RAYFISH_TRANSIT no state\n");
    rules.push_str(&guard_rules(&uplinks));
    pf::pf_load_anchor(CLIENT_ANCHOR, &rules)?;
    Ok(())
}

/// Refuse to start a flow to a public destination on a physical uplink, the
/// same guard the Linux client installs. LAN and other non-internet ranges,
/// other VPNs' interfaces, and TCP connections already under way are left
/// alone: only a SYN, or a UDP or ICMP packet, to the internet is dropped.
///
/// No uplink means no direct route to leak through, so there is nothing to block.
pub(super) fn guard_rules(uplinks: &[String]) -> String {
    if uplinks.is_empty() {
        return String::new();
    }
    let on = uplinks.join(" ");
    format!(
        "pass out quick inet to {{ {v4} }} no state\n\
         pass out quick inet6 to {{ {v6} }} no state\n\
         block drop out quick on {{ {on} }} proto tcp flags S/SA\n\
         block drop out quick on {{ {on} }} proto {{ udp, icmp, icmp6 }}\n",
        v4 = NON_INTERNET_V4.join(", "),
        v6 = NON_INTERNET_V6.join(", "),
    )
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
}
