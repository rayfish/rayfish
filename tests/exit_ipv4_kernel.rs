//! Run only inside the isolated container from tests/exit-ipv4-kernel.sh.
#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Child, Command};
use std::time::Duration;

use anyhow::Result;
use rayfish::config::{AppConfig, ServerOverride};
use rayfish::exit_node::{
    ExitServer, disable, install_client_routing, ipv4, teardown_client_routing,
};
use rayfish::membership::ExitFamilies;
use rayfish::tun::{self, TunRead, TunWrite};
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn run(args: &[&str]) -> Result<()> {
    let output = Command::new(args[0]).args(&args[1..]).output()?;
    anyhow::ensure!(
        output.status.success(),
        "{}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

async fn read_ipv4(reader: &mut impl TunRead) -> Result<bytes::Bytes> {
    timeout(Duration::from_secs(3), async {
        loop {
            let packet = reader.read_packet().await?;
            if packet[0] >> 4 == 4 {
                return Ok(packet);
            }
        }
    })
    .await?
}

struct Cleanup {
    echo: Child,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        teardown_client_routing(None);
        disable();
        let _ = self.echo.kill();
        let _ = self.echo.wait();
    }
}

#[tokio::test]
#[ignore = "requires an isolated network namespace and CAP_NET_ADMIN"]
async fn ipv4_client_and_gateway_round_trip() -> Result<()> {
    anyhow::ensure!(
        std::env::var("RAYFISH_ISOLATED_KERNEL_TEST").as_deref() == Ok("1"),
        "run tests/exit-ipv4-kernel.sh"
    );
    let dir = tempfile::tempdir()?;
    rayfish::config::set_config_dir_override(dir.path().to_owned());
    run(&["ip", "netns", "add", "internet"])?;
    run(&[
        "ip", "link", "add", "uplink", "type", "veth", "peer", "name", "remote",
    ])?;
    run(&["ip", "link", "set", "remote", "netns", "internet"])?;
    run(&["ip", "addr", "add", "10.0.0.1/30", "dev", "uplink"])?;
    run(&["ip", "link", "set", "uplink", "up"])?;
    run(&["ip", "route", "add", "default", "via", "10.0.0.2"])?;
    for args in [
        vec!["ip", "addr", "add", "10.0.0.2/30", "dev", "remote"],
        vec!["ip", "addr", "add", "8.8.8.8/32", "dev", "lo"],
        vec!["ip", "link", "set", "lo", "up"],
        vec!["ip", "link", "set", "remote", "up"],
    ] {
        let mut command = vec!["ip", "netns", "exec", "internet"];
        command.extend(args);
        run(&command)?;
    }
    let echo = Command::new("ip")
        .args([
            "netns",
            "exec",
            "internet",
            "python3",
            "-u",
            "-c",
            r#"
import socket, select
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(('8.8.8.8', 9000))
dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns.bind(('8.8.8.8', 53))
while True:
 for s in select.select([udp, dns], [], [])[0]:
  data, peer = s.recvfrom(65535)
  if s is udp:
   reply = peer[0].encode() + b' ' + data
  else:
   end = 12
   while data[end]: end += data[end] + 1
   end += 5
   reply = data[:2] + bytes.fromhex('81800001000100000000') + data[12:end]
   reply += bytes.fromhex('c00c000100010000003c0004') + socket.inet_aton('203.0.113.1')
  s.sendto(reply, peer)
"#,
        ])
        .spawn()?;
    let _cleanup = Cleanup { echo };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut client_read, mut client_write, client_name) = tun::create("200::2".parse()?).await?;
    let server = ExitServer::new();
    server.reload([("example", &["*".to_owned()][..])]);
    if let Some(error) = server.apply_os(&client_name) {
        anyhow::bail!("{error}");
    }
    anyhow::ensure!(
        server.offers_v4() && !server.offers_v6(),
        "IPv4-only gateway capability"
    );
    install_client_routing(&client_name)?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:9000").await?;
    socket.send(b"example payload").await?;
    let request = read_ipv4(&mut client_read).await?;
    anyhow::ensure!(
        request[12..16] == ipv4::LOCAL_CLIENT_ADDR.octets(),
        "client route source"
    );
    // The forwarder's two halves: the client puts the wire address on, the
    // gateway leases it an address from the pool.
    let request = ipv4::client_to_wire(request)?;
    let mapped = server
        .ipv4
        .outbound(request, "200::2".parse()?, "example".into())
        .await?;
    let alias = Ipv4Addr::new(mapped[12], mapped[13], mapped[14], mapped[15]);
    client_write.write_packet(&mapped).await?;
    let reply = read_ipv4(&mut client_read).await?;
    anyhow::ensure!(reply[16..20] == alias.octets(), "kernel NAT return route");
    let restored = ipv4::rewrite(reply, alias, ipv4::WIRE_CLIENT_ADDR)?;
    let restored = ipv4::client_from_wire(restored)?;
    client_write.write_packet(&restored).await?;
    let mut response = [0; 128];
    let length = timeout(Duration::from_secs(3), socket.recv(&mut response)).await??;
    anyhow::ensure!(
        &response[..length] == b"10.0.0.1 example payload",
        "gateway must masquerade IPv4"
    );

    // A marked underlay socket must reach the uplink without entering the TUN.
    let bypass = UdpSocket::bind("0.0.0.0:0").await?;
    socket2::SockRef::from(&bypass).set_mark(rayfish::exit_node::SOCKET_MARK)?;
    bypass.send_to(b"underlay", "8.8.8.8:9000").await?;
    let length = timeout(Duration::from_secs(3), bypass.recv(&mut response)).await??;
    anyhow::ensure!(
        &response[..length] == b"10.0.0.1 underlay",
        "underlay loop prevention"
    );

    // Replies to a connection that arrived on the uplink leave by the uplink.
    let inbound = UdpSocket::bind("10.0.0.1:9100").await?;
    let answer = tokio::spawn(async move {
        let mut buf = [0; 64];
        let (length, from) = inbound.recv_from(&mut buf).await?;
        inbound.send_to(&buf[..length], from).await?;
        anyhow::Ok(())
    });
    let output = tokio::task::spawn_blocking(|| {
        Command::new("ip")
            .args([
                "netns",
                "exec",
                "internet",
                "python3",
                "-c",
                "import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
                 s.settimeout(3)\ns.sendto(b'inbound', ('10.0.0.1', 9100))\n\
                 print(s.recv(64).decode())",
            ])
            .output()
    })
    .await??;
    anyhow::ensure!(
        String::from_utf8_lossy(&output.stdout).trim() == "inbound",
        "inbound reply bypasses the tunnel: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    answer.await??;

    // Reapplying keeps both families captured.
    install_client_routing(&client_name)?;
    for family in ["-4", "-6"] {
        let rules = Command::new("ip").args([family, "rule", "show"]).output()?;
        anyhow::ensure!(
            String::from_utf8_lossy(&rules.stdout)
                .lines()
                .filter(|l| l.starts_with("102:"))
                .count()
                == 1,
            "reapply must not duplicate the catch-all rule"
        );
    }
    let route = Command::new("ip")
        .args(["-6", "route", "get", "2606:4700:4700::1111"])
        .output()?;
    anyhow::ensure!(
        String::from_utf8_lossy(&route.stdout).contains(&client_name),
        "unavailable IPv6 stays captured"
    );

    // Route loss must not allow a new connection or an explicitly bound socket
    // to escape through main. The transport mark must still work.
    for family in ["-4", "-6"] {
        run(&["ip", family, "route", "flush", "table", "29793"])?;
    }
    for bind in ["0.0.0.0:0", "10.0.0.1:0"] {
        let blocked = UdpSocket::bind(bind).await?;
        let _ = blocked.send_to(b"must not escape", "8.8.8.8:9000").await;
        anyhow::ensure!(
            timeout(Duration::from_millis(200), blocked.recv(&mut response))
                .await
                .is_err(),
            "direct fallback leaked"
        );
    }
    bypass.send_to(b"still connected", "8.8.8.8:9000").await?;
    let length = timeout(Duration::from_secs(3), bypass.recv(&mut response)).await??;
    anyhow::ensure!(
        &response[..length] == b"10.0.0.1 still connected",
        "transport survives route loss"
    );
    // The endpoint can bootstrap DNS even with no working exit. Application
    // DNS sockets do not receive its transport exemption.
    let empty = ServerOverride {
        replace: true,
        servers: Vec::new(),
    };
    let settings = AppConfig {
        relay: empty.clone(),
        discovery_dns: empty,
        dns_upstreams: ServerOverride {
            replace: true,
            servers: vec!["8.8.8.8".to_owned()],
        },
        ..AppConfig::default()
    };
    let (endpoint, _) = rayfish::transport::create_endpoint_with_alpns(
        iroh::SecretKey::generate(),
        vec![b"test/1".to_vec()],
        false,
        &settings,
    )
    .await?;
    let addresses: Vec<_> = endpoint
        .dns_resolver()?
        .lookup_ipv4("bootstrap.example", Duration::from_secs(3))
        .await?
        .collect();
    anyhow::ensure!(
        addresses == vec!["203.0.113.1".parse::<IpAddr>()?],
        "transport DNS bypass"
    );
    endpoint.close().await;
    install_client_routing(&client_name)?;

    // A route overlapping the lease pool turns off IPv4 transit, not the gateway.
    run(&["ip", "route", "add", "10.65.4.0/24", "dev", "uplink"])?;
    if let Some(error) = server.apply_os(&client_name) {
        anyhow::bail!("overlapping route disabled the gateway: {error}");
    }
    anyhow::ensure!(!server.offers_v4(), "IPv4 pool conflict still offered");
    let pool = Command::new("ip")
        .args(["-4", "route", "show", ipv4::SERVER_PREFIX])
        .output()?;
    anyhow::ensure!(
        !String::from_utf8_lossy(&pool.stdout).contains(&client_name),
        "lease pool routed over a conflicting route"
    );
    run(&["ip", "route", "del", "10.65.4.0/24", "dev", "uplink"])?;
    if let Some(error) = server.apply_os(&client_name) {
        anyhow::bail!("{error}");
    }
    anyhow::ensure!(server.offers_v4(), "IPv4 transit restored");
    // A broader 10/8 route cannot shadow the pool's /16, so it costs nothing.
    run(&["ip", "route", "add", "10.0.0.0/8", "dev", "uplink"])?;
    if let Some(error) = server.apply_os(&client_name) {
        anyhow::bail!("{error}");
    }
    anyhow::ensure!(server.offers_v4(), "a 10/8 route disabled IPv4 transit");
    let pool = Command::new("ip")
        .args(["-4", "route", "get", "10.65.0.1"])
        .output()?;
    anyhow::ensure!(
        String::from_utf8_lossy(&pool.stdout).contains(&client_name),
        "a 10/8 route shadowed the lease pool"
    );
    run(&["ip", "route", "del", "10.0.0.0/8", "dev", "uplink"])?;

    teardown_client_routing(Some(&client_name));
    disable();
    let direct = UdpSocket::bind("0.0.0.0:0").await?;
    direct.send_to(b"direct", "8.8.8.8:9000").await?;
    let (length, remote) =
        timeout(Duration::from_secs(3), direct.recv_from(&mut response)).await??;
    anyhow::ensure!(remote == "8.8.8.8:9000".parse::<SocketAddr>()?);
    anyhow::ensure!(
        &response[..length] == b"10.0.0.1 direct",
        "teardown restores direct egress"
    );
    let addresses = Command::new("ip")
        .args(["-4", "addr", "show", "dev", &client_name])
        .output()?;
    let addresses = String::from_utf8_lossy(&addresses.stdout);
    anyhow::ensure!(
        !addresses.contains(&ipv4::LOCAL_CLIENT_ADDR.to_string())
            && !addresses.contains(&ipv4::WIRE_CLIENT_ADDR.to_string()),
        "client address removed"
    );
    let routes = Command::new("ip").args(["-4", "route", "show"]).output()?;
    anyhow::ensure!(
        !String::from_utf8_lossy(&routes.stdout).contains(ipv4::SERVER_PREFIX),
        "gateway pool removed"
    );
    Ok(())
}

#[test]
#[ignore = "requires an isolated network namespace and CAP_NET_ADMIN"]
fn gateway_uplinks_follow_policy_routing() -> Result<()> {
    anyhow::ensure!(
        std::env::var("RAYFISH_ISOLATED_KERNEL_TEST").as_deref() == Ok("1"),
        "run tests/exit-ipv4-kernel.sh"
    );
    // Each test needs its own routing tables, including when the suite runs in parallel.
    if std::env::var("RAYFISH_UPLINK_TEST_CHILD").as_deref() != Ok("1") {
        let status = Command::new("unshare")
            .args(["--net"])
            .arg(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "gateway_uplinks_follow_policy_routing",
                "--nocapture",
            ])
            .env("RAYFISH_UPLINK_TEST_CHILD", "1")
            .status()?;
        anyhow::ensure!(status.success(), "isolated uplink regression failed");
        return Ok(());
    }

    let dir = tempfile::tempdir()?;
    rayfish::config::set_config_dir_override(dir.path().to_owned());
    run(&["ip", "link", "add", "uplink", "type", "dummy"])?;
    run(&["ip", "link", "set", "uplink", "up"])?;
    run(&["ip", "addr", "add", "192.0.2.1/24", "dev", "uplink"])?;
    run(&[
        "ip",
        "-6",
        "addr",
        "add",
        "2001:db8:1::1/64",
        "dev",
        "uplink",
        "nodad",
    ])?;
    run(&["ip", "link", "add", "exit0", "type", "dummy"])?;
    run(&["ip", "link", "set", "exit0", "up"])?;
    let server = ExitServer::new();
    server.reload([("example", &["*".to_owned()][..])]);
    let check = |expected| -> Result<()> {
        if let Some(error) = server.apply_os("exit0") {
            anyhow::bail!("{error}");
        }
        let actual = ExitFamilies::from_uplinks(server.offers_v4(), server.offers_v6());
        anyhow::ensure!(actual == expected, "expected {expected:?}, got {actual:?}");
        Ok(())
    };
    check(ExitFamilies::Neither)?;
    let gateways = [("-4", "192.0.2.2"), ("-6", "2001:db8:1::2")];
    for (family, gateway) in gateways {
        run(&["ip", family, "route", "add", "default", "via", gateway])?;
    }
    check(ExitFamilies::Dual)?;
    for (family, gateway) in gateways {
        run(&[
            "ip", family, "route", "add", "default", "via", gateway, "table", "123",
        ])?;
        run(&["ip", family, "route", "del", "default", "via", gateway])?;
    }
    // A default in an unused table is not an uplink.
    check(ExitFamilies::Neither)?;
    for (family, _) in gateways {
        run(&["ip", family, "rule", "add", "pref", "90", "lookup", "123"])?;
    }
    check(ExitFamilies::Dual)?;
    for (family, gateway) in gateways {
        run(&["ip", family, "route", "del", "default", "table", "123"])?;
        let prefixes = if family == "-4" {
            ["0.0.0.0/1", "128.0.0.0/1"]
        } else {
            ["::/1", "8000::/1"]
        };
        for prefix in prefixes {
            run(&[
                "ip", family, "route", "add", prefix, "via", gateway, "dev", "uplink", "onlink",
                "table", "123",
            ])?;
        }
    }
    check(ExitFamilies::Dual)?;
    for (family, _) in gateways {
        run(&["ip", family, "rule", "add", "pref", "80", "blackhole"])?;
    }
    check(ExitFamilies::Neither)?;
    for (family, _) in gateways {
        run(&["ip", family, "rule", "del", "pref", "80"])?;
        run(&["ip", family, "rule", "del", "pref", "90"])?;
        run(&[
            "ip", family, "route", "add", "default", "dev", "exit0", "table", "29793",
        ])?;
        run(&[
            "ip", family, "rule", "add", "pref", "102", "lookup", "29793",
        ])?;
        run(&[
            "ip", family, "rule", "add", "pref", "100", "fwmark", "0x7261", "lookup", "123",
        ])?;
    }
    // Gateway packets carry the same mark as the transport, bypassing the client tunnel.
    check(ExitFamilies::Dual)?;
    for (family, _) in gateways {
        run(&["ip", family, "rule", "del", "pref", "100"])?;
    }
    // The client tunnel by itself cannot provide gateway egress.
    check(ExitFamilies::Neither)?;
    disable();
    Ok(())
}
