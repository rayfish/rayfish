//! TUN device creation and I/O.
//!
//! The device is split into independent [`TunReader`] and [`TunWriter`] halves.
//! Linux uses tun-rs framing for segmentation offload, while macOS packet
//! tunnels duplicate the utun descriptor for batched reads and writes. No I/O
//! resource is serialized behind a lock.

#[cfg(target_os = "macos")]
mod apple;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::{overlay_route_warnings, spawn_repair_watcher};

// These support the desktop TUN setup (address/route/link configuration via
// `ifconfig`/`ip`/netlink) and the CGNAT preflight, none of which compile on
// Android where the packet interface is a `VpnService` fd.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use crate::membership::ExitFamilies;
use std::future::Future;
#[cfg(not(target_os = "android"))]
use std::io::Error as IoError;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::mem::{size_of, zeroed};
#[cfg(target_os = "linux")]
use std::net::IpAddr;

#[cfg(not(target_os = "android"))]
use std::net::Ipv6Addr;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd, RawFd};
#[cfg(target_os = "windows")]
use std::path::PathBuf;
// Windows drives the interface through PowerShell (`windows_process`), not a
// synchronous `Command`, so nothing here needs the blocking spawn. Linux does
// every one of these through netlink and spawns nothing at all.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use std::process::Command;
#[cfg(not(target_os = "android"))]
use std::sync::Arc;

#[cfg(not(target_os = "android"))]
use anyhow::Context;
#[cfg(not(target_os = "android"))]
use anyhow::Result;
#[cfg(not(target_os = "android"))]
use anyhow::anyhow;
use bytes::Bytes;
#[cfg(not(target_os = "android"))]
use bytes::BytesMut;
// The desktop TUN device (the `tun-rs` crate) only exists off Android, where the
// packet interface is a `VpnService` fd instead.
#[cfg(target_os = "linux")]
use futures::SinkExt;
#[cfg(not(target_os = "android"))]
use futures::StreamExt;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use libc::{
    AF_SYSTEM, CTLIOCGINFO, F_DUPFD_CLOEXEC, c_char, ctl_info, fcntl, getpeername, ioctl, sockaddr,
    sockaddr_ctl, socklen_t,
};
#[cfg(not(target_os = "android"))]
use tun_rs::AsyncDevice;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tun_rs::DeviceBuilder;
#[cfg(target_os = "linux")]
use tun_rs::async_framed::DeviceFramedWrite;
#[cfg(not(target_os = "android"))]
use tun_rs::async_framed::{BytesCodec, DeviceFramedRead};

/// Read side of a packet interface. Returns one owned IP packet. Abstracts the
/// concrete TUN device so the forwarding loop can run over any packet source:
/// the desktop TUN, an Android `VpnService` fd, or an in-memory fake in tests.
/// The packet's allocation passes directly to the forwarding loop and transport.
///
/// Contract: an empty packet means "no packet this time, retry". End-of-stream
/// must surface as `Err`, never as a stream of empty packets, or `run_mesh`
/// would busy-spin. A packet the device delivered but the reader could not
/// decode surfaces as [`UnreadablePacket`], and the loop keeps reading. Any
/// other error stops the loop.
///
/// **`read_packet` MUST be cancel-safe.** `run_mesh` races it in a `select!` against
/// dial-completion and shutdown, so the future can be dropped before it resolves.
/// A dropped read must leave the reader ready for the next call. Readers should
/// keep their receive allocation internally until a complete packet is ready.
pub trait TunRead: Send + 'static {
    fn read_packet(&mut self) -> impl Future<Output = anyhow::Result<Bytes>> + Send;
}

/// A packet the device delivered that the reader could not decode, such as a
/// Linux offload record that needs more segments than tun-rs can split it into
/// (#237). Only that packet is lost: the next read starts clean, so the
/// forwarding loop counts it and keeps reading.
#[derive(Debug)]
pub struct UnreadablePacket(pub std::io::Error);

impl std::fmt::Display for UnreadablePacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unreadable TUN packet: {}", self.0)
    }
}

impl std::error::Error for UnreadablePacket {}

/// Write side of a packet interface. Writes one IP packet to the device.
pub trait TunWrite: Send + 'static {
    /// Largest IP packet this interface can accept.
    fn mtu(&self) -> u16 {
        TUN_MTU
    }

    /// Whether the interface accepted TCP segmentation/receive offload.
    fn tcp_gso_enabled(&self) -> bool {
        false
    }

    /// Whether the interface accepted UDP segmentation/receive offload.
    fn udp_gso_enabled(&self) -> bool {
        false
    }

    fn write_packet(&mut self, packet: &[u8]) -> impl Future<Output = anyhow::Result<()>> + Send;

    /// Preferred number of packets for one write operation. Implementations
    /// that can coalesce packets should override this together with
    /// [`Self::write_packets`].
    fn write_batch_size(&self) -> usize {
        1
    }

    /// Writes a packet batch. The default preserves the single-packet contract
    /// for platforms without a batching API.
    fn write_packets<'a>(
        &'a mut self,
        packets: &'a [Bytes],
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a {
        async move {
            for packet in packets {
                self.write_packet(packet).await?;
            }
            Ok(())
        }
    }
}

/// Maximum IP packet size for the tunnel. Mesh fragmentation carries packets
/// over smaller QUIC paths. Keep Android's VpnService MTU in sync with this.
pub const TUN_MTU: u16 = 1500;
/// IPv6's minimum link MTU, used when the device rejects the preferred MTU.
pub const MIN_TUN_MTU: u16 = 1280;

/// The MTU a desktop TUN is created with. Linux uses IPv6's minimum, as
/// Tailscale does: a 1500-byte packet never fits one QUIC datagram (about
/// 1420 bytes on a 1500-byte path once discovery has run, about 1170 before),
/// so at 1500 every full-sized packet went out as two mesh fragments, doubling
/// the packet rate and the chance of losing it. 1280 fits one datagram on any
/// ordinary path after discovery; mesh fragmentation still covers the rest.
///
/// Nothing on the wire changes. Each side announces the size it accepts and
/// the other clamps to it, and [`TUN_MTU`] stays the largest packet the mesh
/// carries, so a peer at 1500 and one at 1280 interoperate. Other platforms
/// keep 1500 until their packet interfaces are moved together.
#[cfg(target_os = "linux")]
const PREFERRED_TUN_MTU: u16 = MIN_TUN_MTU;
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "ios")))]
const PREFERRED_TUN_MTU: u16 = TUN_MTU;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn configure_mtu(preferred: u16, mut set: impl FnMut(u16) -> Result<(), IoError>) -> Result<u16> {
    match set(preferred) {
        Ok(()) => Ok(preferred),
        Err(error) if preferred > MIN_TUN_MTU => {
            tracing::warn!(%error, mtu = MIN_TUN_MTU, "TUN rejected preferred MTU; trying fallback");
            set(MIN_TUN_MTU).context("set fallback TUN MTU to 1280")?;
            Ok(MIN_TUN_MTU)
        }
        Err(error) => Err(error).context("set TUN MTU to 1280"),
    }
}

/// Read half of the TUN device. Owned by [`forward::run_mesh`].
#[cfg(not(target_os = "android"))]
pub struct TunReader {
    #[cfg(not(target_os = "macos"))]
    framed: DeviceFramedRead<BytesCodec, Arc<AsyncDevice>>,
    #[cfg(target_os = "macos")]
    inner: MacTunReader,
}

#[cfg(target_os = "macos")]
enum MacTunReader {
    Framed(DeviceFramedRead<BytesCodec, Arc<AsyncDevice>>),
    Batched(apple::Reader),
}

/// Write half of the TUN device. Owned by [`forward::spawn_tun_writer`].
#[cfg(not(target_os = "android"))]
pub struct TunWriter {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    dev: Arc<AsyncDevice>,
    #[cfg(target_os = "linux")]
    framed: DeviceFramedWrite<BytesCodec, Arc<AsyncDevice>>,
    #[cfg(target_os = "linux")]
    tcp_gso: bool,
    #[cfg(target_os = "linux")]
    udp_gso: bool,
    #[cfg(target_os = "macos")]
    inner: MacTunWriter,
    mtu: u16,
}

#[cfg(target_os = "macos")]
enum MacTunWriter {
    Device(Arc<AsyncDevice>),
    Batched(apple::Writer),
}

/// Creates a TUN device with this node's mesh address and shares it between
/// independent read/write halves. The device gets our own `/128` and nothing
/// else; the `200::/7` peer range is routed in separately by [`route_peer_range`]
/// after link-up, because the kernel does not reliably install an IPv6 connected
/// route while the link is down.
///
/// No IPv4 is assigned at all. `100.64.0.0/10` belongs to whatever other VPN
/// shares the host, and the overlay carries no IPv4 to put there.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn create(v6: Ipv6Addr) -> Result<(TunReader, TunWriter, String)> {
    // `ipv6(v6, 128)` assigns just our own address (a /128, no connected route).
    // `enable(true)` brings the link up at creation (as the old `.up()` did);
    // `set_link_up` and the peer-range route helpers still run later on
    // activate. Linux does the same two steps over netlink. No IPv4 is assigned
    // at all: the overlay is IPv6-only, and `100.64.0.0/10` belongs to whatever
    // else may be sharing the host.
    // Create at IPv6's minimum first so a rejected preferred MTU cannot prevent
    // device creation. Upgrade separately: only MTU errors trigger fallback.
    let builder = DeviceBuilder::new().mtu(MIN_TUN_MTU);
    // Linux creates the device bare and configures it in `configure_linux_tun`:
    // its per-device IPv6 settings have to be in place before the address
    // goes on and the link comes up.
    #[cfg(not(target_os = "linux"))]
    let builder = builder.ipv6(v6, 128).enable(true);
    #[cfg(target_os = "linux")]
    let builder = builder.name(LINUX_TUN_NAME).offload(true);
    #[cfg(target_os = "windows")]
    let builder = builder
        .mtu_v6(MIN_TUN_MTU)
        .name(WINDOWS_TUN_NAME)
        .description("Rayfish")
        .wintun_file(wintun_library_path().to_string_lossy().into_owned());
    #[cfg(target_os = "linux")]
    let device = builder.build_async().map_err(linux_create_error)?;
    #[cfg(not(target_os = "linux"))]
    let device = builder.build_async().context("create tun-rs device")?;
    #[cfg(target_os = "linux")]
    configure_linux_tun(&device.name().context("read TUN device name")?, v6).await?;
    let mtu = configure_mtu(PREFERRED_TUN_MTU, |mtu| {
        device.set_mtu(mtu)?;
        #[cfg(target_os = "windows")]
        device.set_mtu_v6(mtu)?;
        Ok(())
    })?;

    let tun_name = device.name().unwrap_or_else(|_| "unknown".to_string());
    #[cfg(target_os = "linux")]
    tracing::info!(
        ipv6 = %v6,
        tun = %tun_name,
        mtu,
        tcp_gso = device.tcp_gso(),
        udp_gso = device.udp_gso(),
        "TUN device created"
    );
    #[cfg(not(target_os = "linux"))]
    tracing::info!(ipv6 = %v6, tun = %tun_name, mtu, "TUN device created");

    let (reader, writer) = split_device(device, mtu);
    Ok((reader, writer, tun_name))
}

#[cfg(not(target_os = "android"))]
fn split_device(device: AsyncDevice, mtu: u16) -> (TunReader, TunWriter) {
    #[cfg(target_os = "linux")]
    let tcp_gso = device.tcp_gso();
    #[cfg(target_os = "linux")]
    let udp_gso = device.udp_gso();
    let dev = Arc::new(device);
    #[cfg(not(target_os = "macos"))]
    let framed = DeviceFramedRead::new(Arc::clone(&dev), BytesCodec::new());
    #[cfg(target_os = "linux")]
    let writer = TunWriter {
        framed: DeviceFramedWrite::new(dev, BytesCodec::new()),
        tcp_gso,
        udp_gso,
        mtu,
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let writer = TunWriter { dev, mtu };
    #[cfg(target_os = "macos")]
    let writer = TunWriter {
        inner: MacTunWriter::Device(Arc::clone(&dev)),
        mtu,
    };
    #[cfg(target_os = "macos")]
    let reader = TunReader {
        inner: MacTunReader::Framed(DeviceFramedRead::new(dev, BytesCodec::new())),
    };
    #[cfg(not(target_os = "macos"))]
    let reader = TunReader { framed };
    (reader, writer)
}

/// Opens the utun interface owned by `NEPacketTunnelProvider` without routing
/// packets through Swift. The provider keeps its descriptor; Rayfish owns a
/// duplicate that is closed when the attached data plane stops.
#[cfg(target_os = "macos")]
pub fn open_packet_tunnel() -> Result<(TunReader, TunWriter)> {
    let fd = packet_tunnel_fd()?;
    if apple::is_available() {
        let (reader, writer) = apple::split(fd).context("enable batched packet tunnel I/O")?;
        return Ok((
            TunReader {
                inner: MacTunReader::Batched(reader),
            },
            TunWriter {
                inner: MacTunWriter::Batched(writer),
                mtu: TUN_MTU,
            },
        ));
    }
    let raw_fd = fd.into_raw_fd();
    // SAFETY: `raw_fd` is an owned duplicate of the provider's open utun fd.
    let device = unsafe { AsyncDevice::from_fd(raw_fd) }.context("open packet tunnel utun fd")?;
    Ok(split_device(device, TUN_MTU))
}

/// Opens the utun interface owned by the iOS `NEPacketTunnelProvider`.
///
/// Unlike macOS this never takes the batched `sendmsg_x`/`recvmsg_x` path: those
/// are private symbols, and App Store review rejects apps that look them up.
#[cfg(target_os = "ios")]
pub fn open_packet_tunnel() -> Result<(TunReader, TunWriter)> {
    let raw_fd = packet_tunnel_fd()?.into_raw_fd();
    // SAFETY: `raw_fd` is an owned duplicate of the provider's open utun fd.
    let device = unsafe { AsyncDevice::from_fd(raw_fd) }.context("open packet tunnel utun fd")?;
    Ok(split_device(device, TUN_MTU))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn packet_tunnel_fd() -> Result<OwnedFd> {
    const MAX_FD: RawFd = 1024;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    // Both C structs are plain integer arrays and are valid when zeroed.
    let mut info: ctl_info = unsafe { zeroed() };
    for (destination, source) in info
        .ctl_name
        .iter_mut()
        .zip(UTUN_CONTROL_NAME.iter().copied())
    {
        *destination = source as c_char;
    }

    for fd in 0..=MAX_FD {
        // `getpeername` initializes the address and updates its length on success.
        let mut address: sockaddr_ctl = unsafe { zeroed() };
        let mut address_len = size_of::<sockaddr_ctl>() as socklen_t;
        // SAFETY: both pointers refer to writable values of the advertised size.
        let result = unsafe {
            getpeername(
                fd,
                (&mut address as *mut sockaddr_ctl).cast::<sockaddr>(),
                &mut address_len,
            )
        };
        if result != 0
            || (address_len as usize) < size_of::<sockaddr_ctl>()
            || i32::from(address.sc_family) != AF_SYSTEM
        {
            continue;
        }

        if info.ctl_id == 0 {
            // SAFETY: `info` is writable and has the layout required by CTLIOCGINFO.
            if unsafe { ioctl(fd, CTLIOCGINFO, &mut info) } != 0 {
                continue;
            }
        }
        if address.sc_id != info.ctl_id {
            continue;
        }

        // SAFETY: `fd` was accepted by `getpeername`; fcntl returns a new owned fd.
        let duplicate = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(IoError::last_os_error()).context("duplicate packet tunnel utun fd");
        }
        // SAFETY: `duplicate` is a fresh descriptor returned by fcntl.
        return Ok(unsafe { OwnedFd::from_raw_fd(duplicate) });
    }

    Err(anyhow!("packet tunnel utun fd was not found"))
}

/// Interface name pattern on Linux. The kernel's default `tun0` says nothing
/// about who owns the device, and on a host with more than one tunnel it is
/// whoever started first. `%d` is `TUNSETIFF`'s own placeholder: the kernel
/// substitutes the lowest free index, so this comes out `rayfish0` and a second
/// device gets `rayfish1` rather than `EBUSY`. `device.name()` reads the
/// resolved name back off the fd, so the rest of the daemon sees the real one.
///
/// Linux only. macOS numbers its own `utunN` and will not take another name,
/// and FreeBSD's `tun` cloner insists on a `tun` prefix.
#[cfg(target_os = "linux")]
const LINUX_TUN_NAME: &str = "rayfish%d";

/// Explains a failed Linux TUN creation. Opening `/dev/net/tun` and claiming an
/// interface are the steps that fail in a container or under a service unit
/// without the capability, and the bare errno says neither.
#[cfg(target_os = "linux")]
fn linux_create_error(error: IoError) -> anyhow::Error {
    let hint = match error.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENODEV) | Some(libc::ENXIO) => Some(
            "/dev/net/tun is missing: load the tun module (modprobe tun), or in a \
             container pass the device in (--device /dev/net/tun)",
        ),
        Some(libc::EPERM) | Some(libc::EACCES) => Some(
            "creating a TUN device needs CAP_NET_ADMIN and access to /dev/net/tun \
             (in a container: --cap-add NET_ADMIN --device /dev/net/tun)",
        ),
        _ => None,
    };
    match hint {
        Some(hint) => anyhow::Error::new(error).context(hint),
        None => anyhow::Error::new(error).context("create tun-rs device"),
    }
}

/// Explains a failed IPv6 address assignment. The kernel answers EACCES when
/// IPv6 is disabled on the device and EAFNOSUPPORT when it is disabled at boot,
/// and the first reads exactly like a missing capability.
#[cfg(any(target_os = "linux", test))]
fn ipv6_disabled_hint(errno: Option<i32>) -> Option<&'static str> {
    matches!(errno, Some(libc::EACCES) | Some(libc::EAFNOSUPPORT)).then_some(
        "IPv6 is disabled on this host (net.ipv6.conf.*.disable_ipv6 or ipv6.disable=1); \
         the mesh is IPv6-only and cannot run without it",
    )
}

/// The OS error code inside a netlink failure, if the kernel sent one.
#[cfg(target_os = "linux")]
fn netlink_errno(error: &anyhow::Error) -> Option<i32> {
    error
        .chain()
        .find_map(|cause| match cause.downcast_ref::<rtnetlink::Error>() {
            Some(rtnetlink::Error::NetlinkError(message)) => message.to_io().raw_os_error(),
            _ => None,
        })
}

/// Per-device IPv6 settings for the TUN, written under
/// `/proc/sys/net/ipv6/conf/<tun>/`. All but `disable_ipv6` are best-effort.
///
/// - `keep_addr_on_down = 1`: Linux otherwise flushes the global address when
///   anything takes the link down, and nothing outside `ray up` puts it back.
/// - `addr_gen_mode = 1`: no link-local address. The mesh never uses one, and
///   without it the kernel sends no router solicitations into the tunnel.
/// - `router_solicitations = 0`: the same, for kernels that ignore the above.
#[cfg(target_os = "linux")]
const LINUX_TUN_IPV6_CONF: [(&str, &str); 3] = [
    ("keep_addr_on_down", "1"),
    ("addr_gen_mode", "1"),
    ("router_solicitations", "0"),
];

#[cfg(target_os = "linux")]
fn set_tun_ipv6_conf(tun_name: &str) {
    use crate::sysctl::{ipv6_conf, read_sysctl, write_sysctl};

    let disable = ipv6_conf(tun_name, "disable_ipv6");
    let current = read_sysctl(&disable);
    if !current.is_empty() && current != "0" {
        match write_sysctl(&disable, "0") {
            Ok(()) => tracing::info!(tun = %tun_name, "enabled IPv6 on the TUN device"),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), tun = %tun_name, "cannot enable IPv6 on the TUN device")
            }
        }
    }
    for (key, value) in LINUX_TUN_IPV6_CONF {
        if let Err(error) = write_sysctl(&ipv6_conf(tun_name, key), value) {
            tracing::warn!(error = %format!("{error:#}"), tun = %tun_name, key, value, "cannot set TUN IPv6 sysctl");
        }
    }
}

/// Configures a freshly created Linux TUN: IPv6 settings first, then our `/128`,
/// then link-up. The settings must precede link-up, since the link-local
/// address is generated the moment the link comes up.
///
/// A host may disable IPv6 for new interfaces by default. The overlay is
/// IPv6-only, so this turns it back on for our own device alone and leaves the
/// host's other interfaces as they are.
#[cfg(target_os = "linux")]
async fn configure_linux_tun(tun_name: &str, v6: Ipv6Addr) -> Result<()> {
    let name = tun_name.to_owned();
    tokio::task::spawn_blocking(move || set_tun_ipv6_conf(&name))
        .await
        .context("TUN IPv6 settings task")?;
    if let Err(error) = ensure_ipv6_addr(tun_name, v6).await {
        return Err(match ipv6_disabled_hint(netlink_errno(&error)) {
            Some(hint) => error.context(hint),
            None => error,
        });
    }
    set_link_up(tun_name).await
}

/// Wintun adapter name. Fixed rather than generated, so a restart reattaches to
/// the adapter this daemon created instead of leaving a second one behind.
#[cfg(target_os = "windows")]
const WINDOWS_TUN_NAME: &str = "rayfish";

#[cfg(target_os = "windows")]
fn wintun_library_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("wintun.dll")))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("wintun.dll"))
}

/// The overlay range, routed into the Wintun adapter. IPv6 only: the mesh
/// carries no IPv4, and `100.64.0.0/10` belongs to whatever else shares the
/// host. `::` is the on-link next hop, matching the interface-scoped routes the
/// other platforms install.
#[cfg(target_os = "windows")]
const WINDOWS_PEER_ROUTES: [(&str, &str); 1] = [("200::/7", "::")];

#[cfg(target_os = "windows")]
fn windows_link_args(tun_name: &str, up: bool) -> [String; 5] {
    let state = if up { "enabled" } else { "disabled" };
    [
        "interface".to_owned(),
        "set".to_owned(),
        "interface".to_owned(),
        format!("name={tun_name}"),
        format!("admin={state}"),
    ]
}

#[cfg(target_os = "windows")]
fn windows_interface_query_script(tun_name: &str) -> String {
    let quoted = tun_name.replace('\'', "''");
    format!(
        "@(Get-NetAdapter | Where-Object {{ $_.Name -eq '{}' }} | Select-Object -ExpandProperty ifIndex)",
        quoted
    )
}

#[cfg(target_os = "windows")]
fn windows_remove_route_script(prefix: &str, index: u32) -> String {
    format!(
        "Remove-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -Confirm:$false -ErrorAction SilentlyContinue",
        prefix, index
    )
}

#[cfg(target_os = "windows")]
fn windows_replace_route_script(prefix: &str, index: u32, next_hop: &str) -> String {
    format!(
        "{}; New-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '{}' -PolicyStore ActiveStore -ErrorAction Stop",
        windows_remove_route_script(prefix, index),
        prefix,
        index,
        next_hop
    )
}

/// The overlay range, `200::/7`, as the netlink route the TUN carries.
#[cfg(target_os = "linux")]
const OVERLAY: Ipv6Addr = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0);
#[cfg(target_os = "linux")]
const OVERLAY_LEN: u8 = 7;

/// The interface index of `tun_name`.
#[cfg(target_os = "linux")]
async fn tun_link_index(handle: &rtnetlink::Handle, tun_name: &str) -> Result<u32> {
    use futures::TryStreamExt;

    Ok(handle
        .link()
        .get()
        .match_name(tun_name.to_owned())
        .execute()
        .try_next()
        .await
        .context("query TUN link")?
        .with_context(|| format!("TUN link {tun_name} not found"))?
        .header
        .index)
}

/// Run `f` with a netlink handle and the interface index of `tun_name`.
///
/// Every netlink call below needs the same preamble (open a socket, spawn the
/// connection driver, resolve the link index) and must abort that driver task on
/// every path out, success or error. Doing it here keeps each caller down to the
/// one call it actually makes.
#[cfg(target_os = "linux")]
async fn with_tun_link<T, F, Fut>(tun_name: &str, f: F) -> Result<T>
where
    F: FnOnce(rtnetlink::Handle, u32) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let (connection, handle, _) = rtnetlink::new_connection().context("open netlink socket")?;
    let conn = tokio::spawn(connection);

    let result = async {
        let index = tun_link_index(&handle, tun_name).await?;
        f(handle.clone(), index).await
    }
    .await;

    conn.abort();
    result
}

/// Re-assigns our own IPv6 `/128` to the TUN. The address is set once at device
/// creation, but Linux flushes an interface's global IPv6 addresses when the link
/// goes down (`keep_addr_on_down` defaults to 0) and never restores them, while
/// IPv4 addresses survive. Without this, a `down`/`up` cycle leaves the node with
/// a working IPv4 overlay and a silently dead IPv6 one: it still routes `200::/7`
/// into the TUN, but owns no address in it, so peers get no answer. Must run after
/// [`set_link_up`]; idempotent (netlink `replace`), safe on every `up` cycle.
#[cfg(target_os = "linux")]
pub async fn ensure_ipv6_addr(tun_name: &str, v6: Ipv6Addr) -> Result<()> {
    with_tun_link(tun_name, async |handle, index| {
        handle
            .address()
            .add(index, IpAddr::V6(v6), 128)
            .replace()
            .execute()
            .await
            .context("add TUN IPv6 address via netlink")
    })
    .await
}

/// Routes the peer range into the TUN. Must be called *after* the interface is
/// up (see [`set_link_up`]): the kernel does not reliably install an IPv6
/// connected route while the link is down, and peer traffic would otherwise leak
/// out the host's default IPv6 route. `200::/7` is the whole range, magic DNS
/// (`dns::MAGIC_DNS_V6`) included, so nothing else needs a host route.
/// Idempotent, safe to call on every `up` cycle.
#[cfg(target_os = "linux")]
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
    use rtnetlink::RouteMessageBuilder;

    with_tun_link(tun_name, async |handle, index| {
        let route = RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(OVERLAY, OVERLAY_LEN)
            .output_interface(index)
            .build();
        handle
            .route()
            .add(route)
            .replace()
            .execute()
            .await
            .context("add 200::/7 route via netlink")
    })
    .await
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
    // utun is point-to-point, so the address prefix alone does not reliably
    // create the range route; macOS also drops it across an `up`/`down` cycle,
    // so it is re-added on every activate. `route add` fails if the route
    // already exists (e.g. an earlier `up`), so delete any stale entry first and
    // ignore its result. `200::/7` covers `dns::MAGIC_DNS_V6` too.
    let ranges: &[(&str, &str)] = &[("-inet6", "200::/7")];
    for (family, net) in ranges.iter().copied() {
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-net", net, "-interface", tun_name])
            .status();
        let status = Command::new("route")
            .args(["-n", "add", family, "-net", net, "-interface", tun_name])
            .status()
            .with_context(|| format!("run route add {family} {net}"))?;
        anyhow::ensure!(
            status.success(),
            "route add {family} {net} failed with {status}"
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub async fn unroute_peer_range(tun_name: &str) -> Result<()> {
    let index = windows_interface_index(tun_name).await?;
    for &(prefix, _) in &WINDOWS_PEER_ROUTES {
        windows_powershell(&windows_remove_route_script(prefix, index)).await?;
    }
    Ok(())
}

#[cfg(all(not(target_os = "android"), not(target_os = "windows")))]
pub async fn unroute_peer_range(_tun_name: &str) -> Result<()> {
    Ok(())
}

/// iOS apps cannot create a TUN device. The packet tunnel provider supplies one
/// through [`open_packet_tunnel`] and NetworkExtension owns its routes.
#[cfg(target_os = "ios")]
pub async fn create(_v6: Ipv6Addr) -> Result<(TunReader, TunWriter, String)> {
    Err(anyhow!(
        "iOS has no TUN device of its own; attach the packet tunnel instead"
    ))
}

#[cfg(target_os = "ios")]
pub async fn route_peer_range(_tun_name: &str) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
pub async fn route_peer_range(tun_name: &str) -> Result<()> {
    let index = windows_interface_index(tun_name).await?;
    let mut installed = Vec::new();
    for &(prefix, next_hop) in &WINDOWS_PEER_ROUTES {
        let result =
            windows_powershell(&windows_replace_route_script(prefix, index, next_hop)).await;
        if let Err(error) = result {
            for previous in installed {
                let _ = windows_powershell(&windows_remove_route_script(previous, index)).await;
            }
            return Err(error);
        }
        installed.push(prefix);
    }
    Ok(())
}

/// The full-tunnel default as two half-space routes per family: `0.0.0.0/1` +
/// `128.0.0.0/1` and `::/1` + `8000::/1`. Each is more specific than a real
/// default route, so together they capture everything by longest-prefix match
/// without touching (or having to restore) the system default. The wg-quick
/// approach; Linux does not use it (its full tunnel is a policy-routing table,
/// see `exit_node::install_client_routing`).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const SPLIT_DEFAULT: [(&str, &str); 4] = [
    ("-inet", "0.0.0.0/1"),
    ("-inet", "128.0.0.0/1"),
    ("-inet6", "::/1"),
    ("-inet6", "8000::/1"),
];

/// Routes all traffic into the TUN via the [`SPLIT_DEFAULT`] half-space routes
/// (the exit-node client full tunnel). Delete-then-add, so it is idempotent
/// across re-applies. The caller is responsible for loop prevention *before*
/// this goes in: from here on, everything the routing table decides, including
/// the daemon's own transport unless it is pinned elsewhere, goes to the TUN.
///
/// Only the halves of the families the tunnel actually carries go in
/// (`ExitFamilies::tunnelled`: what this node's data plane routes, intersected
/// with what the gateway says it can return). That is `::/1` + `8000::/1`, or
/// nothing at all: the overlay carries no IPv4, so IPv4 egress stays with
/// whoever owns `100.64.0.0/10` here. Unlike Linux, no hole has to be
/// punched for that VPN's own prefixes: the split default lives in the one routing
/// table, where its more specific routes already win.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_default_via_tun(tun_name: &str, carries: ExitFamilies) -> Result<()> {
    for step in split_default_plan(carries, tun_name) {
        let _ = Command::new("route").args(&step.delete).status();
        let Some(add) = &step.add else { continue };
        let status = Command::new("route")
            .args(add)
            .status()
            .with_context(|| format!("run route {}", add.join(" ")))?;
        anyhow::ensure!(
            status.success(),
            "route {} failed with {status}",
            add.join(" ")
        );
    }
    Ok(())
}

/// What one [`SPLIT_DEFAULT`] entry costs: always a delete, and an add only if
/// this tunnel carries that family.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
struct SplitDefaultStep {
    delete: Vec<String>,
    add: Option<Vec<String>>,
}

/// The `route` invocations an install makes, as data, so the shape is pinned by a
/// test instead of by reading the loop.
///
/// Every entry is deleted whatever the answer, and only the carried ones are added
/// back. That asymmetry is the point: this is an install, and an install has to be
/// as family-symmetric as a teardown. `carries` follows the gateway's claim, so a
/// live tunnel can narrow (the gateway loses its IPv6 uplink and republishes a
/// narrower claim) and the re-apply arrives with one family fewer. Skipping the
/// dropped family entirely would leave its half-space routes pointing at a utun
/// that is still up, so that family keeps entering a tunnel whose far end cannot
/// return it while the daemon tells the user it is leaving directly.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn split_default_plan(carries: ExitFamilies, tun_name: &str) -> [SplitDefaultStep; 4] {
    SPLIT_DEFAULT.map(|(family, net)| {
        let args = |verb: &str| {
            ["-n", verb, family, "-net", net, "-interface", tun_name]
                .map(str::to_string)
                .to_vec()
        };
        // `Unknown` is not a `tunnelled()` output; read as both families, which is
        // what an absent claim meant before the field existed.
        let wanted = match family {
            "-inet" => carries.carries_v4() || carries.is_unknown(),
            _ => carries.carries_v6() || carries.is_unknown(),
        };
        SplitDefaultStep {
            delete: args("delete"),
            add: wanted.then(|| args("add")),
        }
    })
}

/// Removes the full-tunnel half-space routes. Best-effort and idempotent: routes
/// that are already gone (never installed, or dropped with the utun) are fine.
///
/// Always both families, whatever mode installed them, so a daemon restarted into
/// the other one still clears what the last left behind.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn unroute_default_via_tun(tun_name: &str) {
    for (family, net) in SPLIT_DEFAULT {
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-net", net, "-interface", tun_name])
            .status();
    }
}

/// Install host routes for our *own* dual-stack addresses via the loopback
/// interface so traffic to ourselves (e.g. `ping laptop.field.ray` resolving to
/// our own IP) is short-circuited locally instead of being sent out the TUN,
/// where the forwarding loop would drop it as "no peer for dst".
///
/// On a normal broadcast interface macOS auto-installs a `<own-ip> -> lo0` route
/// for exactly this. A point-to-point `utun` does not get one (the local address
/// only exists as the source end of the `addr --> gateway` pair), so we add it
/// explicitly, mirroring what Tailscale does. Delete-then-add keeps it
/// idempotent across `up`/`down` cycles. Must run after the address is assigned.
///
/// On Linux this is a no-op: assigning an address makes the kernel add a
/// `local` route in the `local` table that already delivers self-traffic via
/// loopback, so pinging your own TUN address works out of the box.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub async fn route_self_loopback(v6: Ipv6Addr) -> Result<()> {
    let families = [("-inet6", v6.to_string())];
    for (family, addr) in families {
        let _ = Command::new("route")
            .args(["-n", "delete", family, "-host", &addr, "-interface", "lo0"])
            .status();
        let status = Command::new("route")
            .args(["-n", "add", family, "-host", &addr, "-interface", "lo0"])
            .status()
            .context("run route add (loopback self-route)")?;
        anyhow::ensure!(
            status.success(),
            "route add {family} -host {addr} via lo0 failed with {status}"
        );
    }
    Ok(())
}

#[cfg(all(
    not(target_os = "macos"),
    not(target_os = "android"),
    not(target_os = "freebsd")
))]
pub async fn route_self_loopback(_v6: Ipv6Addr) -> Result<()> {
    // Linux installs the loopback `local` route automatically on address
    // assignment; self-traffic already works without an explicit route.
    Ok(())
}

/// Bring the TUN interface administratively up (used when activating the VPN).
#[cfg(not(target_os = "android"))]
pub async fn set_link_up(tun_name: &str) -> Result<()> {
    set_link_state(tun_name, true).await
}

/// Bring the TUN interface administratively down (standby). The underlying file
/// descriptor stays open, so the device can be brought back up without
/// recreating it.
#[cfg(not(target_os = "android"))]
pub async fn set_link_down(tun_name: &str) -> Result<()> {
    set_link_state(tun_name, false).await
}

#[cfg(not(target_os = "android"))]
async fn set_link_state(tun_name: &str, up: bool) -> Result<()> {
    // NetworkExtension owns the iOS interface's link state.
    #[cfg(target_os = "ios")]
    let _ = (tun_name, up);
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let state = if up { "up" } else { "down" };
        let status = Command::new("ifconfig")
            .args([tun_name, state])
            .status()
            .context("run ifconfig")?;
        anyhow::ensure!(status.success(), "ifconfig {state} failed with {status}");
    }
    #[cfg(target_os = "linux")]
    {
        // Netlink rather than `ip link set`, for the same reason the address and
        // route helpers above use it: a shell-out puts iproute2 on the daemon's
        // runtime PATH, and a service unit without it fails this one step while
        // every netlink call around it succeeds. That leaves the link never
        // brought up (or, on standby, never brought down) with the address and
        // the `200::/7` route still in place, which reads as a working VPN that
        // silently swallows every packet.
        use rtnetlink::LinkUnspec;

        with_tun_link(tun_name, async |handle, index| {
            let msg = LinkUnspec::new_with_index(index);
            let msg = if up { msg.up() } else { msg.down() };
            handle
                .link()
                .set(msg.build())
                .execute()
                .await
                .context("set TUN link state via netlink")
        })
        .await?;
    }
    #[cfg(target_os = "windows")]
    {
        let args = windows_link_args(tun_name, up);
        let output = crate::windows_process::WindowsProcessRunner::default()
            .output("netsh.exe", args)
            .await
            .context("run netsh interface set interface")?;
        anyhow::ensure!(
            output.status.success(),
            "netsh interface {} failed: {}",
            if up { "enabled" } else { "disabled" },
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn windows_powershell(script: &str) -> Result<String> {
    crate::windows_process::WindowsProcessRunner::default()
        .powershell(
            &format!("$ErrorActionPreference='Stop'; {script}"),
            "run Windows network PowerShell",
        )
        .await
}

#[cfg(target_os = "windows")]
async fn windows_interface_index(tun_name: &str) -> Result<u32> {
    let output = windows_powershell(&windows_interface_query_script(tun_name)).await?;
    anyhow::ensure!(
        !output.is_empty() && !output.contains('\n'),
        "Windows TUN adapter {tun_name:?} was not uniquely found"
    );
    output
        .parse()
        .with_context(|| format!("resolve Windows interface index for {tun_name:?}"))
}

#[cfg(not(target_os = "android"))]
impl TunRead for TunReader {
    async fn read_packet(&mut self) -> anyhow::Result<Bytes> {
        #[cfg(target_os = "macos")]
        match &mut self.inner {
            MacTunReader::Framed(framed) => framed_packet(framed.next().await),
            MacTunReader::Batched(reader) => reader.read_packet().await.map_err(Into::into),
        }
        #[cfg(not(target_os = "macos"))]
        framed_packet(self.framed.next().await)
    }
}

/// One item from a tun-rs framed reader. `None` means the device closed.
#[cfg(not(target_os = "android"))]
fn framed_packet(item: Option<std::io::Result<BytesMut>>) -> anyhow::Result<Bytes> {
    let packet = item.ok_or_else(|| anyhow!("TUN device closed"))?;
    #[cfg(target_os = "linux")]
    let packet = packet.map_err(read_error)?;
    #[cfg(not(target_os = "linux"))]
    let packet = packet?;
    Ok(packet.freeze())
}

/// Sorts a Linux framed read error. A failed read of the device carries an OS
/// error code and stops the forwarding loop. tun-rs raises its own errors,
/// without one, for a record it read but could not split or decode, and its
/// next read starts clean. Other platforms keep every error fatal: their
/// readers have not been checked for this.
#[cfg(any(target_os = "linux", test))]
fn read_error(error: std::io::Error) -> anyhow::Error {
    if error.raw_os_error().is_none() {
        UnreadablePacket(error).into()
    } else {
        error.into()
    }
}

#[cfg(not(target_os = "android"))]
impl TunWrite for TunWriter {
    fn mtu(&self) -> u16 {
        self.mtu
    }

    #[cfg(target_os = "linux")]
    fn tcp_gso_enabled(&self) -> bool {
        self.tcp_gso
    }

    #[cfg(target_os = "linux")]
    fn udp_gso_enabled(&self) -> bool {
        self.udp_gso
    }

    async fn write_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        self.framed.send(Bytes::copy_from_slice(packet)).await?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        self.dev.send(packet).await?;
        #[cfg(target_os = "macos")]
        match &mut self.inner {
            MacTunWriter::Device(dev) => {
                dev.send(packet).await?;
            }
            MacTunWriter::Batched(writer) => {
                writer
                    .write_packets(&[Bytes::copy_from_slice(packet)])
                    .await?
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn write_batch_size(&self) -> usize {
        tun_rs::IDEAL_BATCH_SIZE
    }

    #[cfg(target_os = "macos")]
    fn write_batch_size(&self) -> usize {
        match self.inner {
            MacTunWriter::Device(_) => 1,
            MacTunWriter::Batched(_) => apple::BATCH_SIZE,
        }
    }

    #[cfg(target_os = "linux")]
    async fn write_packets(&mut self, packets: &[Bytes]) -> anyhow::Result<()> {
        let Some((last, packets)) = packets.split_last() else {
            return Ok(());
        };
        for packet in packets {
            self.framed.feed(packet.clone()).await?;
        }
        self.framed.send(last.clone()).await?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn write_packets(&mut self, packets: &[Bytes]) -> anyhow::Result<()> {
        match &mut self.inner {
            MacTunWriter::Device(dev) => {
                for packet in packets {
                    dev.send(packet).await?;
                }
                Ok(())
            }
            MacTunWriter::Batched(writer) => {
                writer.write_packets(packets).await.map_err(Into::into)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "android"))]
    #[test]
    fn preferred_mtu_rejection_retries_at_ipv6_minimum() {
        let mut attempts = Vec::new();
        let mtu = super::configure_mtu(super::TUN_MTU, |mtu| {
            attempts.push(mtu);
            if mtu > 1280 {
                Err(std::io::ErrorKind::InvalidInput.into())
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(mtu, 1280);
        assert_eq!(attempts, [1500, 1280]);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn mtu_setup_does_not_hide_a_failed_fallback() {
        let mut attempts = Vec::new();
        let result = super::configure_mtu(super::TUN_MTU, |mtu| {
            attempts.push(mtu);
            Err(std::io::ErrorKind::PermissionDenied.into())
        });
        assert!(result.is_err());
        assert_eq!(attempts, [1500, 1280]);
    }

    /// A Linux read error with an OS error code means the device failed, so it
    /// still stops the forwarding loop. tun-rs's own errors are about one packet
    /// it read but could not split, which the loop drops and reads past (#237).
    #[test]
    fn only_device_read_errors_are_fatal() {
        let device = super::read_error(std::io::Error::from_raw_os_error(libc::EBADF));
        assert!(!device.is::<super::UnreadablePacket>());
        let packet = super::read_error(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "too many GSO segments",
        ));
        assert!(packet.is::<super::UnreadablePacket>());
        assert_eq!(
            packet.to_string(),
            "unreadable TUN packet: too many GSO segments"
        );
    }

    /// EACCES from an address add is the kernel saying IPv6 is disabled, not
    /// that the daemon lacks a capability, and the error has to say so.
    #[test]
    fn a_refused_ipv6_address_names_disabled_ipv6() {
        for errno in [libc::EACCES, libc::EAFNOSUPPORT] {
            let hint = super::ipv6_disabled_hint(Some(errno)).expect("explained");
            assert!(hint.contains("IPv6 is disabled"), "{hint}");
        }
        assert_eq!(super::ipv6_disabled_hint(Some(libc::EEXIST)), None);
        assert_eq!(super::ipv6_disabled_hint(None), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_tun_open_names_the_device_or_the_capability() {
        use super::IoError;

        let missing = super::linux_create_error(IoError::from_raw_os_error(libc::ENOENT));
        assert!(format!("{missing:#}").contains("/dev/net/tun is missing"));
        let denied = super::linux_create_error(IoError::from_raw_os_error(libc::EPERM));
        assert!(format!("{denied:#}").contains("CAP_NET_ADMIN"));
        let other = super::linux_create_error(IoError::from_raw_os_error(libc::EBUSY));
        assert!(format!("{other:#}").starts_with("create tun-rs device"));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn a_minimum_preferred_mtu_is_set_once() {
        use std::io::ErrorKind;

        let mut attempts = Vec::new();
        let result = super::configure_mtu(super::MIN_TUN_MTU, |mtu| {
            attempts.push(mtu);
            Err(ErrorKind::PermissionDenied.into())
        });
        assert!(result.is_err());
        assert_eq!(attempts, [1280]);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn supported_preferred_mtu_needs_no_retry() {
        let mut attempts = Vec::new();
        let mtu = super::configure_mtu(super::TUN_MTU, |mtu| {
            attempts.push(mtu);
            Ok(())
        })
        .unwrap();
        assert_eq!(mtu, 1500);
        assert_eq!(attempts, [1500]);
    }

    /// A narrowing tunnel must delete the family it stopped carrying.
    ///
    /// `carries` follows the gateway's claim, so it changes under a live tunnel:
    /// the gateway republishes a claim with no IPv6 in it, and the re-apply
    /// arrives with one family fewer. The utun is still up, so nothing reaps the
    /// dropped family's half-space routes on their own, and that family keeps
    /// entering a tunnel whose far end cannot return it while
    /// `ray exit-node status` says it is leaving directly.
    ///
    /// `tunnelled` narrows to `V6` or `Neither`, but the plan is written against
    /// the whole enum because the claim rides the signed roster and is decoded
    /// as well as written.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn the_split_default_plan_visits_every_family_and_adds_only_what_it_carries() {
        use crate::membership::ExitFamilies::{Dual, Neither, Unknown, V4, V6};

        let deletes = |carries| -> Vec<String> {
            super::split_default_plan(carries, "utun9")
                .into_iter()
                .map(|s| s.delete.join(" "))
                .collect()
        };
        let adds = |carries| -> Vec<String> {
            super::split_default_plan(carries, "utun9")
                .into_iter()
                .filter_map(|s| s.add.map(|a| a.join(" ")))
                .collect()
        };

        // Every family is deleted whatever the tunnel carries. This is the half
        // that a narrowing tunnel depends on, and the half that reads as dead code
        // if you only look at the family it is installing.
        let all_four = [
            "-n delete -inet -net 0.0.0.0/1 -interface utun9",
            "-n delete -inet -net 128.0.0.0/1 -interface utun9",
            "-n delete -inet6 -net ::/1 -interface utun9",
            "-n delete -inet6 -net 8000::/1 -interface utun9",
        ];
        for carries in [Dual, V6, V4, Neither, Unknown] {
            assert_eq!(deletes(carries), all_four, "{carries:?}");
        }

        // And only the carried family is added back. `V6` and `Neither` are the
        // two a real selection produces.
        assert_eq!(
            adds(V6),
            [
                "-n add -inet6 -net ::/1 -interface utun9",
                "-n add -inet6 -net 8000::/1 -interface utun9",
            ]
        );
        assert!(adds(Neither).is_empty(), "nothing to carry, nothing to add");
        assert_eq!(
            adds(V4),
            [
                "-n add -inet -net 0.0.0.0/1 -interface utun9",
                "-n add -inet -net 128.0.0.0/1 -interface utun9",
            ]
        );
        assert_eq!(adds(Dual).len(), 4);
        // An absent claim predates the field, so it is read as both families.
        assert_eq!(adds(Unknown).len(), 4);
    }

    /// The Wintun adapter is configured by generated PowerShell, so the
    /// generators are what there is to pin without a Windows host: an
    /// apostrophe in an adapter name must not end the quoted argument, and the
    /// route script must scope itself to our interface index rather than
    /// touching the machine's routing table at large.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_link_args_cover_up_down_and_name_boundary() {
        let up = super::windows_link_args("Rayfish Tunnel", true);
        assert_eq!(
            up,
            [
                "interface",
                "set",
                "interface",
                "name=Rayfish Tunnel",
                "admin=enabled",
            ]
        );

        let down = super::windows_link_args("O'Brien", false);
        assert_eq!(down[3], "name=O'Brien");
        assert_eq!(down[4], "admin=disabled");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_interface_query_quotes_powershell_boundaries() {
        let script = super::windows_interface_query_script("O'Brien");
        assert!(script.contains("Name -eq 'O''Brien'"));
        assert!(script.contains("ExpandProperty ifIndex"));
    }

    /// The overlay is IPv6-only. A `100.64.0.0/10` entry here would put a route
    /// for another VPN's range into our adapter.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_peer_routes_are_the_overlay_range_only() {
        assert_eq!(super::WINDOWS_PEER_ROUTES, [("200::/7", "::")]);
        assert_eq!(super::WINDOWS_TUN_NAME, "rayfish");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_route_scripts_are_scoped_and_idempotent() {
        let remove = super::windows_remove_route_script("200::/7", 17);
        assert!(remove.contains("Remove-NetRoute"));
        assert!(remove.contains("-InterfaceIndex 17"));
        assert!(remove.contains("-ErrorAction SilentlyContinue"));

        // Replace is remove-then-add, so re-running it is a no-op rather than a
        // duplicate route.
        let replace = super::windows_replace_route_script("200::/7", 17, "::");
        assert!(replace.starts_with(&remove));
        assert!(replace.contains("New-NetRoute"));
        assert!(replace.contains("-DestinationPrefix '200::/7'"));
        assert!(replace.contains("-NextHop '::'"));
        assert!(replace.contains("-PolicyStore ActiveStore"));
    }

    /// `tun-rs` loads Wintun by path, so the wrong name here is a runtime
    /// failure with no compile-time signal.
    #[cfg(target_os = "windows")]
    #[test]
    fn wintun_library_contract_ends_in_dll() {
        assert_eq!(
            super::wintun_library_path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("wintun.dll")
        );
    }
}
