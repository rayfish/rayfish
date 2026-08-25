//! Bridging the host's IPv4-only listeners onto this node's mesh address.
//!
//! The overlay is IPv6-only, so a peer reaches a service here as
//! `[<mesh-v6>]:<port>`. A service listening on `0.0.0.0` has an IPv4-only
//! socket and the kernel will never deliver an IPv6 packet to it, so the
//! connection is refused on a port the operator has already opened in `ray
//! firewall`, with nothing to say why. No packet filter can help: neither
//! nftables nor pf translates between address families, so the crossing has to
//! happen in this process.
//!
//! It happens as a bridge, not as a translation. We bind `[<mesh-v6>]:<port>`
//! ourselves and splice each accepted connection to `127.0.0.1:<port>` over
//! IPv4. The alternative, rewriting the IPv6 header to IPv4 in the forwarding
//! path, would need a synthetic IPv4 source pool, IPv4 on the TUN, ICMP
//! translation and fragmentation handling, and would end the overlay's
//! IPv6-only invariant, all to buy one thing: a distinct source address per
//! peer for the local service to see. Here the service sees `127.0.0.1`
//! instead, and per-peer policy lives in `ray firewall` rather than in the app.
//!
//! Two rules keep this from widening what the host exposes:
//!
//! - **Only a wildcard listener is bridged.** A service bound to `127.0.0.1` is
//!   meant to be local and is left alone. A service on `0.0.0.0` already
//!   answers on every other interface the host has, so putting it on the mesh
//!   address adds no reachability the operator had not already granted.
//! - **The firewall is upstream of the socket.** `forward::evaluate_inbound`
//!   runs the mesh firewall and the ingress anti-spoof check before a packet
//!   reaches the TUN, so a bridged port is denied by default like any other and
//!   the SYN for one the rules do not name never arrives here. That is why this
//!   module binds every qualifying port instead of consulting the firewall, and
//!   it is the same property that lets mesh SSH read a peer's identity off the
//!   source address.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::forward::{SSH_LISTEN_PORT, SSH_PORT};
use crate::listen_events;
use crate::ssh::bind_listener;

/// How often the host's listening sockets are re-enumerated where nothing
/// reports a change. A service can start long after `ray up`, so this cannot be
/// a one-shot at activation, and with no notification to wait on the interval
/// is also the worst case for how late the bridge can be. On macOS a rescan
/// spawns `netstat`, which is why it is seconds and not sub-second.
const RESCAN_INTERVAL: Duration = Duration::from_secs(15);

/// The same, on a host where [`listen_events`] reports changes as they happen.
///
/// It is a backstop and not the mechanism: the events carry the latency, and
/// this only bounds how long a missed one can go unnoticed. Something has to,
/// because the ways it can be missed are all silent, and both directions are
/// invisible until someone tries the port. A dropped open leaves a service
/// unreachable exactly as it was before any of this existed; a dropped close
/// leaves us holding a port whose service has moved to an address we cannot
/// reach, which is worse than not bridging it at all.
const BACKSTOP_INTERVAL: Duration = Duration::from_secs(300);

/// How long to let a burst of listen events settle before rescanning. Restarting
/// a service is a close and an open, and binding the mesh address in front of it
/// is a third event of our own; one scan answers all of them.
const EVENT_SETTLE: Duration = Duration::from_millis(200);

/// How long a connection to the local service may take before the bridged
/// connection is dropped.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Ports at or above this are not bridged. A program that takes a fresh high
/// port on every run would otherwise have the bridge bind and unbind it on
/// every rescan, for a socket nobody is going to dial by number.
const EPHEMERAL_FLOOR: u16 = 32768;

/// What the supervisor knows about one candidate port.
enum PortState {
    /// A listener is up on the mesh address; cancelling the token stops it.
    Bound(CancellationToken),
    /// The bind failed (something else holds the address, most likely). Retried
    /// on the next rescan, but only logged the first time.
    Failed,
}

/// Bridges the host's IPv4-only listeners onto one mesh address. Its lifetime
/// is the data plane's: the address it binds goes down with the TUN.
pub struct V4Bridge {
    v6: Ipv6Addr,
}

impl V4Bridge {
    pub fn new(v6: Ipv6Addr) -> Self {
        Self { v6 }
    }

    /// Start the rescan supervisor. Runs until `token` is cancelled, which also
    /// stops every listener it opened (they hold child tokens).
    pub fn spawn(self, token: CancellationToken) {
        tokio::spawn(async move {
            // A host that will tell us when its listeners change; `None` leaves
            // this on its timer alone.
            let mut events = listen_events::watch(&token);
            let mut ports: HashMap<u16, PortState> = HashMap::new();
            loop {
                // The ports we hold on the mesh address, so the enumeration can
                // tell our own listeners from a service's.
                let ours: BTreeSet<u16> = ports
                    .iter()
                    .filter(|(_, state)| matches!(state, PortState::Bound(_)))
                    .map(|(port, _)| *port)
                    .collect();
                match bridgeable_ports(self.v6, &ours) {
                    Some(found) => self.reconcile(&found, &mut ports, &token),
                    // Nothing readable here (an unsupported host, or a listing
                    // we could not parse). Bridge nothing and stay quiet: a
                    // wrong guess about the host's sockets costs more than none.
                    None => debug!("v4 bridge: cannot enumerate local listeners here"),
                }
                // Recomputed each pass: a watcher that stops (a read error, not
                // shutdown) has to put the timer back to being the mechanism.
                let interval = match events {
                    Some(_) => BACKSTOP_INTERVAL,
                    None => RESCAN_INTERVAL,
                };
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {}
                    Some(()) = next_event(&mut events) => {
                        tokio::time::sleep(EVENT_SETTLE).await;
                        // Whatever else the burst carried is answered by the
                        // scan this pass is about to do.
                        drain(&mut events);
                    }
                }
            }
            debug!("v4 bridge stopped");
        });
    }

    /// Bring the bound set in line with what the host is listening on: open a
    /// listener for each new candidate, drop the ones that no longer qualify.
    fn reconcile(
        &self,
        found: &BTreeSet<u16>,
        ports: &mut HashMap<u16, PortState>,
        parent: &CancellationToken,
    ) {
        ports.retain(|port, state| {
            if found.contains(port) {
                return true;
            }
            if let PortState::Bound(token) = state {
                token.cancel();
                // Either the local service stopped, or it grew an IPv6 listener
                // of its own and no longer needs us in front of it. The second
                // is what keeps the bridge from standing between a service and
                // the address it wanted to bind.
                info!(port, "v4 bridge: no longer bridging, unbound");
            }
            false
        });
        for &port in found {
            if matches!(ports.get(&port), Some(PortState::Bound(_))) {
                continue;
            }
            let first_try = !ports.contains_key(&port);
            let listener = match bind_listener(IpAddr::V6(self.v6), port) {
                Ok(l) => l,
                Err(e) => {
                    if first_try {
                        warn!(port, error = %e,
                            "v4 bridge: cannot bind the mesh address for an IPv4-only listener");
                    }
                    ports.insert(port, PortState::Failed);
                    continue;
                }
            };
            let token = parent.child_token();
            spawn_port(port, listener, token.clone());
            ports.insert(port, PortState::Bound(token));
            info!(
                port,
                "v4 bridge: IPv4-only listener now reachable on the mesh address"
            );
        }
    }
}

/// The next listen-change trigger, or a future that never completes on a host
/// with no watcher. A watcher that has stopped clears the option, so the caller
/// puts its timer back rather than waiting on a channel nobody will send on.
async fn next_event(events: &mut Option<Receiver<()>>) -> Option<()> {
    match events {
        Some(rx) => {
            let got = rx.recv().await;
            if got.is_none() {
                *events = None;
            }
            got
        }
        None => std::future::pending().await,
    }
}

/// Discard whatever else is queued. Only ever called immediately before a scan,
/// which is the one thing any of those triggers would have asked for.
fn drain(events: &mut Option<Receiver<()>>) {
    if let Some(rx) = events {
        while rx.try_recv().is_ok() {}
    }
}

/// Accept on one bridged port until the token is cancelled.
fn spawn_port(port: u16, listener: TcpListener, token: CancellationToken) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                accepted = listener.accept() => {
                    let (inbound, from) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            debug!(port, error = %e, "v4 bridge: accept failed");
                            continue;
                        }
                    };
                    tokio::spawn(bridge_conn(inbound, from, port));
                }
            }
        }
        debug!(port, "v4 bridge: listener stopped");
    });
}

/// Join one accepted mesh connection to the local IPv4 service.
async fn bridge_conn(mut inbound: TcpStream, from: SocketAddr, port: u16) {
    // The extra hop must not add a stall of its own: a small write held by
    // Nagle here waits on the far end's delayed ACK exactly as it does on a
    // direct connection, and this connection is one of two carrying the same
    // bytes.
    let _ = inbound.set_nodelay(true);
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut upstream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(port, %from, error = %e, "v4 bridge: local service refused the connection");
            return;
        }
        Err(_) => {
            debug!(port, %from, "v4 bridge: local service did not answer in time");
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    debug!(port, %from, "v4 bridge: connection open");
    if let Err(e) = copy_bidirectional(&mut inbound, &mut upstream).await {
        debug!(port, %from, error = %e, "v4 bridge: connection ended early");
    }
}

/// The ports to bridge: an IPv4 wildcard listener, no IPv6 listener already
/// covering the mesh address, and not one of the ports this daemon owns.
/// `None` means the host's listeners could not be read at all.
///
/// `ours` are the ports this bridge already holds on the mesh address. They
/// have to be named, because a bridged port *is* an IPv6 listener on the mesh
/// address from the next scan's point of view: without this the bridge reads
/// its own socket as the service having grown IPv6 support, unbinds, finds the
/// port bare again and rebinds, leaving every bridged port answering half the
/// time.
fn bridgeable_ports(mesh: Ipv6Addr, ours: &BTreeSet<u16>) -> Option<BTreeSet<u16>> {
    let mut ports = wildcard_v4_only_ports(mesh, ours)?;
    ports.retain(|p| is_bridgeable_port(*p));
    Some(ports)
}

/// Ports the bridge never touches: mesh `:22` and the port behind it belong to
/// the userspace SSH NAT in `forward.rs`, and binding either would fight it.
fn is_bridgeable_port(port: u16) -> bool {
    port != SSH_PORT && port != SSH_LISTEN_PORT && port < EPHEMERAL_FLOOR
}

#[cfg(target_os = "linux")]
fn wildcard_v4_only_ports(mesh: Ipv6Addr, ours: &BTreeSet<u16>) -> Option<BTreeSet<u16>> {
    let v4 = std::fs::read_to_string("/proc/net/tcp").ok()?;
    let v6 = std::fs::read_to_string("/proc/net/tcp6").ok()?;
    Some(parse_proc_net(&v4, &v6, mesh, ours))
}

#[cfg(target_os = "macos")]
fn wildcard_v4_only_ports(mesh: Ipv6Addr, ours: &BTreeSet<u16>) -> Option<BTreeSet<u16>> {
    use std::process::Command;
    let out = Command::new("netstat")
        .args(["-an", "-p", "tcp"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_netstat(
        &String::from_utf8_lossy(&out.stdout),
        mesh,
        ours,
    ))
}

/// Every other host, Android included: its `/proc/net/tcp` shows only the
/// caller's own sockets, so there is nothing to enumerate.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn wildcard_v4_only_ports(_mesh: Ipv6Addr, _ours: &BTreeSet<u16>) -> Option<BTreeSet<u16>> {
    None
}

/// Ports with a `0.0.0.0` TCP listener in `/proc/net/tcp` and no listener in
/// `/proc/net/tcp6` that already covers the mesh address.
///
/// A `::ffff:0.0.0.0` row in `tcp6` is a v4-mapped bind, which accepts IPv4
/// only, so it does not disqualify a port: it is another way to spell the
/// listener we are here to bridge. That is why the address is decoded rather
/// than string-matched.
///
/// A mesh-address row for a port in `ours` is this bridge's own listener and is
/// not coverage; see [`bridgeable_ports`].
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net(v4: &str, v6: &str, mesh: Ipv6Addr, ours: &BTreeSet<u16>) -> BTreeSet<u16> {
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for local in listening_locals(v4) {
        let Some((addr, port)) = local.split_once(':') else {
            continue;
        };
        // Wildcard only: a listener on a specific IPv4 address is not one the
        // host offers everywhere, and a loopback one is deliberately local.
        if addr.len() != 8 || u32::from_str_radix(addr, 16) != Ok(0) {
            continue;
        }
        if let Ok(port) = u16::from_str_radix(port, 16) {
            ports.insert(port);
        }
    }
    for local in listening_locals(v6) {
        let Some((addr, port)) = local.split_once(':') else {
            continue;
        };
        let Some(addr) = parse_proc_v6_addr(addr) else {
            continue;
        };
        if addr != Ipv6Addr::UNSPECIFIED && addr != mesh {
            continue;
        }
        if let Ok(port) = u16::from_str_radix(port, 16)
            && !(addr == mesh && ours.contains(&port))
        {
            ports.remove(&port);
        }
    }
    ports
}

/// The `local_address` column of every row in `TCP_LISTEN` (`0A`). The columns
/// are `sl local_address rem_address st ...` after one header line.
#[cfg(any(target_os = "linux", test))]
fn listening_locals(table: &str) -> impl Iterator<Item = &str> {
    table.lines().skip(1).filter_map(|line| {
        let mut fields = line.split_whitespace();
        let local = fields.nth(1)?;
        let state = fields.nth(1)?;
        (state == "0A").then_some(local)
    })
}

/// Decode the 32 hex characters `/proc/net/tcp6` prints for an address. The
/// kernel prints the four `s6_addr32` words with `%08X`, so on a little-endian
/// host each word comes back byte-swapped and `to_le_bytes` puts it back.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_v6_addr(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        *chunk = word.to_le_bytes();
    }
    Some(Ipv6Addr::from(bytes))
}

/// Ports with a `tcp4` wildcard listener in `netstat -an -p tcp` output and no
/// `tcp6`/`tcp46` listener already covering the mesh address. macOS names the
/// family in the first column, which is the whole signal: `tcp46` is a
/// dual-stack socket and `tcp4` is the IPv4-only one this bridges.
#[cfg(any(target_os = "macos", test))]
fn parse_netstat(out: &str, mesh: Ipv6Addr, ours: &BTreeSet<u16>) -> BTreeSet<u16> {
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    let mut covered: BTreeSet<u16> = BTreeSet::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[fields.len() - 1] != "LISTEN" {
            continue;
        }
        // `<host>.<port>`, where the host is `*` for a wildcard bind and an
        // address (with a `%scope` suffix on a link-local one) otherwise.
        let Some((host, port)) = fields[3].rsplit_once('.') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        match fields[0] {
            "tcp4" if host == "*" => {
                ports.insert(port);
            }
            "tcp6" | "tcp46" => {
                let on_mesh = host
                    .split('%')
                    .next()
                    .and_then(|h| h.parse::<Ipv6Addr>().ok())
                    .is_some_and(|a| a == mesh);
                // A mesh-address listener on a port we hold is our own; see
                // `bridgeable_ports`.
                if on_mesh && ours.contains(&port) {
                    continue;
                }
                if host == "*" || on_mesh {
                    covered.insert(port);
                }
            }
            _ => {}
        }
    }
    ports.retain(|p| !covered.contains(p));
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const MESH: Ipv6Addr = Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 0xbeef);

    /// The bridge holds no port yet, the state every scan but the first sees.
    fn nothing() -> BTreeSet<u16> {
        BTreeSet::new()
    }

    /// The 32 hex characters `/proc/net/tcp6` prints for `addr`.
    fn proc_v6(addr: Ipv6Addr) -> String {
        let octets = addr.octets();
        let mut s = String::new();
        for word in octets.as_chunks::<4>().0 {
            s.push_str(&format!("{:08X}", u32::from_le_bytes(*word)));
        }
        s
    }

    /// A `/proc/net/tcp` table with the header the kernel prints. `rows` are
    /// `local_address` / `state` pairs, the only two columns that matter.
    fn proc_table(rows: &[(&str, &str)]) -> String {
        let mut out = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
        for (i, (local, state)) in rows.iter().enumerate() {
            out.push_str(&format!(
                "{i:4}: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 1000 1 0000000000000000 100 0 0 10 0\n"
            ));
        }
        out
    }

    #[test]
    fn a_wildcard_ipv4_listener_is_bridged() {
        let v4 = proc_table(&[("00000000:0FA0", "0A")]);
        let v6 = proc_table(&[]);
        assert_eq!(
            parse_proc_net(&v4, &v6, MESH, &nothing()),
            BTreeSet::from([4000]),
            "0.0.0.0:4000 is exactly the case this exists for"
        );
    }

    #[test]
    fn a_loopback_listener_is_left_alone() {
        // 127.0.0.1 is `0100007F` little-endian. Bound to loopback on purpose,
        // so the mesh must not be able to reach it.
        let v4 = proc_table(&[("0100007F:0FA0", "0A")]);
        assert!(parse_proc_net(&v4, &proc_table(&[]), MESH, &nothing()).is_empty());
    }

    #[test]
    fn a_listener_on_one_ipv4_address_is_left_alone() {
        // 192.168.1.5, a bind the host does not offer everywhere.
        let v4 = proc_table(&[("0501A8C0:0FA0", "0A")]);
        assert!(parse_proc_net(&v4, &proc_table(&[]), MESH, &nothing()).is_empty());
    }

    #[test]
    fn a_socket_that_is_not_listening_is_not_a_listener() {
        // `01` is TCP_ESTABLISHED: an outbound connection from an ephemeral
        // port, which has no service behind it.
        let v4 = proc_table(&[("00000000:0FA0", "01")]);
        assert!(parse_proc_net(&v4, &proc_table(&[]), MESH, &nothing()).is_empty());
    }

    #[test]
    fn a_dual_stack_listener_needs_no_bridge() {
        // `::` in tcp6 alongside the tcp4 row a dual-stack socket also shows.
        let v4 = proc_table(&[("00000000:0FA0", "0A")]);
        let v6 = proc_table(&[("00000000000000000000000000000000:0FA0", "0A")]);
        assert!(
            parse_proc_net(&v4, &v6, MESH, &nothing()).is_empty(),
            "the port already answers over IPv6"
        );
    }

    #[test]
    fn a_listener_on_the_mesh_address_needs_no_bridge() {
        let v4 = proc_table(&[("00000000:0FA0", "0A")]);
        let v6 = proc_table(&[(format!("{}:0FA0", proc_v6(MESH)).as_str(), "0A")]);
        assert!(parse_proc_net(&v4, &v6, MESH, &nothing()).is_empty());
    }

    #[test]
    fn the_bridges_own_listener_is_not_read_as_coverage() {
        // Live bug: a bridged port is itself an IPv6 listener on the mesh
        // address, so the next scan read it as the service having grown IPv6
        // support and unbound it, and the one after that rebound it. Every
        // bridged port answered for 15 seconds out of every 30.
        let v4 = proc_table(&[("00000000:0FA0", "0A")]);
        let v6 = proc_table(&[(format!("{}:0FA0", proc_v6(MESH)).as_str(), "0A")]);
        assert_eq!(
            parse_proc_net(&v4, &v6, MESH, &BTreeSet::from([4000])),
            BTreeSet::from([4000]),
            "the port we already hold stays bridged"
        );
    }

    #[test]
    fn a_wildcard_listener_still_ends_the_bridge_on_a_port_we_hold() {
        // The other direction: a service that grows a `::` listener while we
        // are in front of it must take its port back, or the bridge stands
        // between it and the address it wanted.
        let v4 = proc_table(&[("00000000:0FA0", "0A")]);
        let v6 = proc_table(&[("00000000000000000000000000000000:0FA0", "0A")]);
        assert!(
            parse_proc_net(&v4, &v6, MESH, &BTreeSet::from([4000])).is_empty(),
            "a `::` listener is never ours"
        );
    }

    #[test]
    fn a_v4_mapped_listener_is_still_ipv4_only() {
        // `::ffff:0.0.0.0` accepts IPv4 alone, so it is another spelling of the
        // listener this bridges, not a reason to skip the port.
        let v4 = proc_table(&[("00000000:0FA0", "0A")]);
        let v6 = proc_table(&[("0000000000000000FFFF000000000000:0FA0", "0A")]);
        assert_eq!(
            parse_proc_net(&v4, &v6, MESH, &nothing()),
            BTreeSet::from([4000])
        );
    }

    #[test]
    fn a_listener_on_ipv6_loopback_does_not_cover_the_mesh_address() {
        let v4 = proc_table(&[("00000000:0FA0", "0A")]);
        let v6 = proc_table(&[("00000000000000000000000001000000:0FA0", "0A")]);
        assert_eq!(
            parse_proc_net(&v4, &v6, MESH, &nothing()),
            BTreeSet::from([4000]),
            "::1 answers nothing a peer can dial"
        );
    }

    #[test]
    fn the_ports_the_daemon_owns_are_never_bridged() {
        assert!(!is_bridgeable_port(SSH_PORT), "mesh :22 is the SSH NAT's");
        assert!(!is_bridgeable_port(SSH_LISTEN_PORT));
        assert!(!is_bridgeable_port(EPHEMERAL_FLOOR));
        assert!(!is_bridgeable_port(50000));
        assert!(is_bridgeable_port(4000));
        assert!(is_bridgeable_port(80));
    }

    #[test]
    fn netstat_tells_ipv4_only_from_dual_stack() {
        let out = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.4000                 *.*                    LISTEN
tcp46      0      0  *.8080                 *.*                    LISTEN
tcp4       0      0  *.8080                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.5000         *.*                    LISTEN
tcp6       0      0  ::1.631                *.*                    LISTEN
tcp4       0      0  192.168.1.5.49152      203.0.113.9.443        ESTABLISHED
";
        assert_eq!(
            parse_netstat(out, MESH, &nothing()),
            BTreeSet::from([4000]),
            "8080 is dual-stack, 5000 is loopback, 631 is v6-only, the last row is not a listener"
        );
    }

    #[test]
    fn netstat_reads_a_listener_on_the_mesh_address_as_covering_the_port() {
        let out = format!(
            "\
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.4000                 *.*                    LISTEN
tcp6       0      0  {MESH}.4000            *.*                    LISTEN
"
        );
        assert!(parse_netstat(&out, MESH, &nothing()).is_empty());
        assert_eq!(
            parse_netstat(&out, MESH, &BTreeSet::from([4000])),
            BTreeSet::from([4000]),
            "on a port we hold, that mesh-address row is our own listener"
        );
    }

    /// The bridge's whole job over loopback: bytes in on IPv6, out on IPv4, and
    /// a close on one side ending the other.
    #[tokio::test]
    async fn a_bridged_connection_carries_bytes_both_ways() {
        let echo = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind the local IPv4 service");
        let port = echo.local_addr().expect("echo address").port();
        tokio::spawn(async move {
            let (mut sock, _) = echo.accept().await.expect("accept from the bridge");
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // Stand in for the mesh address with IPv6 loopback: the bridge only
        // ever binds one specific v6 address and dials `127.0.0.1:<port>`.
        let listener =
            bind_listener(IpAddr::V6(Ipv6Addr::LOCALHOST), port).expect("bind the bridge listener");
        let bridged = listener.local_addr().expect("bridge address");
        let token = CancellationToken::new();
        spawn_port(port, listener, token.clone());

        let mut client = TcpStream::connect(bridged)
            .await
            .expect("connect over IPv6");
        client
            .write_all(b"ping")
            .await
            .expect("write to the bridge");
        let mut buf = [0u8; 4];
        timeout(Duration::from_secs(10), client.read_exact(&mut buf))
            .await
            .expect("the bridged connection never answered")
            .expect("read from the bridge");
        assert_eq!(&buf, b"ping");

        // The echo server closes once the client's write half does; that has to
        // reach the client through the bridge as EOF, not as a hang.
        client.shutdown().await.expect("close the write half");
        let mut rest = Vec::new();
        timeout(Duration::from_secs(10), client.read_to_end(&mut rest))
            .await
            .expect("EOF never came back through the bridge")
            .expect("read to end");
        assert!(rest.is_empty());
        token.cancel();
    }

    #[tokio::test]
    async fn a_dead_local_service_closes_the_bridged_connection() {
        // Nothing listens on the IPv4 side, so the connection must end rather
        // than leave the peer holding an open socket that never answers.
        let claim = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("claim a port");
        let port = claim.local_addr().expect("address").port();
        drop(claim);

        let listener =
            bind_listener(IpAddr::V6(Ipv6Addr::LOCALHOST), port).expect("bind the bridge listener");
        let bridged = listener.local_addr().expect("bridge address");
        let token = CancellationToken::new();
        spawn_port(port, listener, token.clone());

        let mut client = TcpStream::connect(bridged)
            .await
            .expect("connect over IPv6");
        let mut buf = Vec::new();
        timeout(Duration::from_secs(10), client.read_to_end(&mut buf))
            .await
            .expect("the bridge left the connection open")
            .expect("read to end");
        assert!(buf.is_empty());
        token.cancel();
    }
}
