//! Run only inside the isolated container from tests/exit-ipv4-kernel.sh.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use rayfish::exit_node::{ExitServer, disable, install_client_routing, teardown_client_routing};
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

struct Cleanup(Child);

impl Drop for Cleanup {
    fn drop(&mut self) {
        teardown_client_routing(None);
        disable();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn read_udp(reader: &mut impl TunRead) -> Result<bytes::Bytes> {
    timeout(Duration::from_secs(3), async {
        loop {
            let packet = reader.read_packet().await?;
            if packet[0] >> 4 == 6 && packet[6] == 17 {
                return Ok(packet);
            }
        }
    })
    .await?
}

// Model two hosts using one TUN: the remote peer has a different mesh address
// from the locally assigned client. UDP's checksum includes both IP addresses.
fn rewrite_address(packet: &mut [u8], offset: usize, address: Ipv6Addr) {
    packet[offset..offset + 16].copy_from_slice(&address.octets());
    packet[46..48].fill(0);
    let mut sum = u32::from(u16::from_be_bytes([packet[4], packet[5]])) + 17;
    for pair in packet[8..].chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    packet[46..48].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
}

#[tokio::test]
#[ignore = "requires an isolated network namespace and CAP_NET_ADMIN"]
async fn ipv6_client_and_gateway_round_trip() -> Result<()> {
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
    run(&["ip", "link", "set", "uplink", "up"])?;
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
    run(&[
        "ip",
        "-6",
        "route",
        "add",
        "default",
        "via",
        "2001:db8:1::2",
    ])?;
    for args in [
        vec!["ip", "link", "set", "lo", "up"],
        vec!["ip", "link", "set", "remote", "up"],
        vec![
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:1::2/64",
            "dev",
            "remote",
            "nodad",
        ],
        vec![
            "ip",
            "-6",
            "addr",
            "add",
            "2001:db8:2::1/128",
            "dev",
            "lo",
            "nodad",
        ],
    ] {
        let mut command = vec!["ip", "netns", "exec", "internet"];
        command.extend(args);
        run(&command)?;
    }
    let mut echo = Command::new("ip")
        .args([
            "netns", "exec", "internet", "python3", "-u", "-c",
            "import socket\ns = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)\n\
             s.bind(('2001:db8:2::1', 9000))\nprint('ready', flush=True)\n\
             while True:\n data, peer = s.recvfrom(65535)\n s.sendto(peer[0].encode() + b' ' + data, peer)",
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = echo.stdout.take().context("echo stdout")?;
    let _cleanup = Cleanup(echo);
    let mut ready = String::new();
    BufReader::new(stdout).read_line(&mut ready)?;
    anyhow::ensure!(ready.trim() == "ready", "echo server failed to start");

    let local: Ipv6Addr = "200::2".parse()?;
    let peer: Ipv6Addr = "200::3".parse()?;
    let (mut reader, mut writer, name) = tun::create(local).await?;
    tun::route_peer_range(&name).await?;
    let server = ExitServer::new();
    server.reload([("example", &["*".to_owned()][..])]);
    if let Some(error) = server.apply_os(&name) {
        anyhow::bail!("{error}");
    }
    anyhow::ensure!(
        server.offers_v6() && !server.offers_v4(),
        "IPv6-only gateway capability"
    );
    install_client_routing(&name)?;

    let socket = UdpSocket::bind("[::]:0").await?;
    socket.connect("[2001:db8:2::1]:9000").await?;
    socket.send(b"payload").await?;
    let mut request = read_udp(&mut reader)
        .await
        .context("IPv6 client request")?
        .to_vec();
    anyhow::ensure!(
        request[8..24] == local.octets(),
        "IPv6 client source must be its mesh address"
    );
    rewrite_address(&mut request, 8, peer);
    writer.write_packet(&request).await?;
    let mut reply = read_udp(&mut reader)
        .await
        .context("IPv6 gateway return")?
        .to_vec();
    anyhow::ensure!(
        reply[24..40] == peer.octets(),
        "IPv6 NAT return destination"
    );
    rewrite_address(&mut reply, 24, local);
    writer.write_packet(&reply).await?;
    let mut response = [0; 128];
    let length = timeout(Duration::from_secs(3), socket.recv(&mut response))
        .await
        .context("IPv6 client delivery")??;
    anyhow::ensure!(
        &response[..length] == b"2001:db8:1::1 payload",
        "IPv6 gateway masquerade"
    );

    let bypass = UdpSocket::bind("[::]:0").await?;
    socket2::SockRef::from(&bypass).set_mark(rayfish::exit_node::SOCKET_MARK)?;
    bypass.send_to(b"underlay", "[2001:db8:2::1]:9000").await?;
    let length = timeout(Duration::from_secs(3), bypass.recv(&mut response))
        .await
        .context("IPv6 underlay response")??;
    anyhow::ensure!(
        &response[..length] == b"2001:db8:1::1 underlay",
        "IPv6 transport bypass"
    );

    // Policy-routed uplinks must be advertised too. The transit and transport
    // packets carry the same mark, so both still reach this default route.
    // Apply the policy to global destinations, preserving mesh return routes.
    run(&[
        "ip",
        "-6",
        "route",
        "add",
        "default",
        "via",
        "2001:db8:1::2",
        "table",
        "100",
    ])?;
    let mark = format!("{:#x}", rayfish::exit_node::SOCKET_MARK);
    run(&[
        "ip", "-6", "rule", "add", "to", "2000::/3", "fwmark", &mark, "table", "100", "pref", "90",
    ])?;
    run(&[
        "ip",
        "-6",
        "route",
        "del",
        "default",
        "via",
        "2001:db8:1::2",
    ])?;
    server.refresh_uplinks();
    anyhow::ensure!(
        server.offers_v6(),
        "policy-routed IPv6 uplink was not advertised"
    );
    socket.send(b"policy payload").await?;
    let mut request = read_udp(&mut reader)
        .await
        .context("policy-routed client request")?
        .to_vec();
    rewrite_address(&mut request, 8, peer);
    writer.write_packet(&request).await?;
    let mut reply = read_udp(&mut reader)
        .await
        .context("policy-routed gateway return")?
        .to_vec();
    rewrite_address(&mut reply, 24, local);
    writer.write_packet(&reply).await?;
    let length = timeout(Duration::from_secs(3), socket.recv(&mut response))
        .await
        .context("policy-routed client delivery")??;
    anyhow::ensure!(
        &response[..length] == b"2001:db8:1::1 policy payload",
        "policy-routed IPv6 gateway round trip"
    );

    // A rejecting default is not an uplink. The client's own tunnel default
    // must not be mistaken for a gateway's physical route either.
    run(&["ip", "-6", "route", "del", "default", "table", "100"])?;
    run(&["ip", "-6", "route", "add", "unreachable", "default"])?;
    server.refresh_uplinks();
    anyhow::ensure!(
        !server.offers_v6(),
        "unreachable IPv6 default was advertised"
    );
    run(&["ip", "-6", "route", "del", "unreachable", "default"])?;
    server.refresh_uplinks();
    anyhow::ensure!(
        !server.offers_v6(),
        "the client's own IPv6 tunnel was advertised as an uplink"
    );
    Ok(())
}
