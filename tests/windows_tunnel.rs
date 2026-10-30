//! Packet checks against an installed service on a disposable Windows runner.
#![cfg(all(windows, feature = "desktop"))]

use std::ffi::OsStr;
use std::io::Error as IoError;
use std::mem::size_of_val;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::ptr::{null, null_mut};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use ray_proto::GroupMode;
use ray_proto::ipc::{self, IpcMessage};
use rayfish::dns::MAGIC_DNS_V6;
use simple_dns::{CLASS, Name, Packet, PacketFlag, QTYPE, Question, RCODE, TYPE, rdata::RData};
use tokio::runtime::{Builder, Runtime};
use tokio::time::timeout;
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMPV6_ECHO_REPLY_LH, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

const IPC_DEADLINE: Duration = Duration::from_secs(90);
const DNS_DEADLINE: Duration = Duration::from_secs(10);
const NETWORK: &str = "test-network";
const HOST: &str = "test-host";
const FQDN: &str = "test-host.test-network.ray";

fn request(runtime: &Runtime, message: IpcMessage) -> Result<IpcMessage> {
    runtime.block_on(async {
        timeout(IPC_DEADLINE, async {
            let mut connection = ipc::connect().await?;
            ipc::send(&mut connection, message).await?;
            ipc::recv(&mut connection).await
        })
        .await
        .context("the installed service IPC request timed out")?
    })
}

fn mutation(runtime: &Runtime, message: IpcMessage) -> Result<()> {
    match request(runtime, message)? {
        IpcMessage::Ok { .. } => Ok(()),
        IpcMessage::Error { message } => {
            bail!("the installed service rejected the test mutation: {message}")
        }
        _ => bail!("the installed service returned an unexpected mutation response"),
    }
}

fn require_clean_standby(runtime: &Runtime) -> Result<()> {
    match request(runtime, IpcMessage::Status)? {
        IpcMessage::StatusResponse {
            active,
            networks,
            pending_networks,
            inactive_networks,
            ..
        } => ensure!(
            !active
                && networks.is_empty()
                && pending_networks.is_empty()
                && inactive_networks.is_empty(),
            "the packet test requires an empty installed service on standby"
        ),
        _ => bail!("the installed service did not return its status"),
    }
    Ok(())
}

fn service_pid() -> Result<u32> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service("rayfish", ServiceAccess::QUERY_STATUS)?;
    let status = service.query_status()?;
    ensure!(
        status.current_state == ServiceState::Running,
        "the installed service stopped during the packet test"
    );
    let pid = status
        .process_id
        .context("the installed service has no process")?;
    ensure!(pid != 0, "the installed service has an invalid process");
    Ok(pid)
}

fn query_through_windows_tunnel(address: Ipv6Addr) -> Result<()> {
    // Binding the assigned overlay address and sending to Magic DNS exercises
    // Windows routing, the Wintun reader, and reply injection into the kernel.
    // No system resolver or cached DNS response participates in this exchange.
    let socket = UdpSocket::bind((address, 0)).context("binding the tunnel's assigned address")?;
    socket.set_read_timeout(Some(DNS_DEADLINE))?;
    socket.set_write_timeout(Some(DNS_DEADLINE))?;
    let destination = SocketAddr::from((MAGIC_DNS_V6, 53));
    let id = rand::random::<u16>();
    let mut query = Packet::new_query(id);
    query.questions.push(Question::new(
        Name::new(FQDN)?,
        QTYPE::TYPE(TYPE::AAAA),
        CLASS::IN.into(),
        false,
    ));
    let bytes = query.build_bytes_vec()?;
    ensure!(
        socket.send_to(&bytes, destination)? == bytes.len(),
        "Windows did not send the complete DNS query"
    );
    let mut response = [0; 4096];
    let (length, source) = socket
        .recv_from(&mut response)
        .context("Magic DNS did not answer a real Windows tunnel packet")?;
    ensure!(
        source == destination,
        "the DNS reply came from another endpoint"
    );
    let response = Packet::parse(&response[..length])?;
    ensure!(
        response.id() == id,
        "the DNS response did not match the fresh query"
    );
    ensure!(
        response.has_flags(PacketFlag::RESPONSE) && response.rcode() == RCODE::NoError,
        "the tunnel's DNS responder did not return a successful reply"
    );
    ensure!(
        response.questions.len() == 1 && response.questions[0].qname == Name::new(FQDN)?,
        "the tunnel's DNS reply answered another question"
    );
    ensure!(
        response.answers.iter().any(|answer| {
            answer.name == Name::new_unchecked(FQDN)
                && matches!(&answer.rdata, RData::AAAA(value) if value.address == u128::from(address))
        }),
        "the tunnel's DNS reply did not contain the created network address"
    );
    Ok(())
}

fn ping_magic_dns(address: Ipv6Addr) -> Result<()> {
    let socket_address = |ip: Ipv6Addr| SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: ip.octets() },
        },
        ..Default::default()
    };
    let source = socket_address(address);
    let destination = socket_address(MAGIC_DNS_V6);
    let payload = b"resolver-probe";
    // Aligned storage for one reply header, payload, and the API's error quote.
    let mut buffer = [0u64; 128];
    let buffer_size = u32::try_from(size_of_val(&buffer))?;
    let payload_size = u16::try_from(payload.len())?;
    // SAFETY: This call has no pointer parameters and creates an owned ICMP handle.
    let handle = unsafe { Icmp6CreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        return Err(IoError::last_os_error()).context("opening the Windows ICMPv6 probe");
    }
    // SAFETY: All buffers and socket addresses are valid until this synchronous
    // call returns. Null event/callback select the bounded five-second wait.
    let replies = unsafe {
        Icmp6SendEcho2(
            handle,
            null_mut(),
            None,
            null(),
            &source,
            &destination,
            payload.as_ptr().cast(),
            payload_size,
            null(),
            buffer.as_mut_ptr().cast(),
            buffer_size,
            5000,
        )
    };
    let query_error = (replies == 0).then(IoError::last_os_error);
    // SAFETY: The probe completed and this code exclusively owns the ICMP handle.
    let closed = unsafe { IcmpCloseHandle(handle) };
    if closed == 0 {
        return Err(IoError::last_os_error()).context("closing the Windows ICMPv6 probe");
    }
    if let Some(error) = query_error {
        return Err(error).context("Magic DNS did not answer Windows ICMPv6 echo");
    }
    // SAFETY: A successful synchronous call populated a reply header in aligned
    // storage whose capacity exceeds ICMPV6_ECHO_REPLY_LH plus the sent payload.
    let reply = unsafe { buffer.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>().read() };
    ensure!(
        reply.Status == 0,
        "Windows received an ICMPv6 error instead of a resolver echo reply (status {})",
        reply.Status
    );
    let responder = reply.Address.sin6_addr;
    ensure!(
        Ipv6Addr::from(responder.map(u16::from_be)) == MAGIC_DNS_V6,
        "the resolver echo reply came from another address"
    );
    Ok(())
}

#[test]
#[ignore = "requires the installed MSI service on a disposable Windows runner"]
fn installed_service_routes_magic_dns_packets_through_windows() -> Result<()> {
    ensure!(
        std::env::var("RAYFISH_WINDOWS_INSTALL_TEST").as_deref() == Ok("1"),
        "set RAYFISH_WINDOWS_INSTALL_TEST=1 only on a disposable installation"
    );
    let runtime = Builder::new_current_thread().enable_all().build()?;
    // Refuse to alter a real installation even if someone sets the test guard.
    require_clean_standby(&runtime)?;
    let original_pid = service_pid()?;
    let mut network_requested = false;
    let result = (|| -> Result<()> {
        mutation(&runtime, IpcMessage::Up { hostname: None })?;
        ensure!(
            service_pid()? == original_pid,
            "Up restarted the installed service"
        );
        network_requested = true;
        let created = request(
            &runtime,
            IpcMessage::Create {
                mode: GroupMode::Restricted,
                name: Some(NETWORK.to_owned()),
                hostname: Some(HOST.to_owned()),
                transport: None,
            },
        )?;
        let address = match created {
            IpcMessage::Created { name, my_ipv6, .. } if name == NETWORK => my_ipv6,
            IpcMessage::Error { message } => {
                bail!("the installed service could not create the private test network: {message}")
            }
            _ => bail!("the installed service did not create the private test network"),
        };
        query_through_windows_tunnel(address)?;
        ping_magic_dns(address)?;
        ensure!(
            service_pid()? == original_pid,
            "the installed service restarted while processing tunnel packets"
        );
        Ok(())
    })();

    let mut cleanup_errors = Vec::new();
    if network_requested
        && let Err(error) = mutation(
            &runtime,
            IpcMessage::Leave {
                name: NETWORK.to_owned(),
            },
        )
    {
        cleanup_errors.push(format!("removing the private test network: {error:#}"));
    }
    if let Err(error) = mutation(&runtime, IpcMessage::Down) {
        cleanup_errors.push(format!(
            "returning the installed service to standby: {error:#}"
        ));
    }
    if let Err(error) = require_clean_standby(&runtime) {
        cleanup_errors.push(format!("checking packet test cleanup: {error:#}"));
    }
    match service_pid() {
        Ok(pid) if pid == original_pid => {}
        Ok(_) => cleanup_errors.push("the installed service restarted during cleanup".to_owned()),
        Err(error) => cleanup_errors.push(format!("checking the service process: {error:#}")),
    }
    if !cleanup_errors.is_empty() {
        let cleanup = cleanup_errors.join("; ");
        return match result {
            Ok(()) => bail!("packet test cleanup failed: {cleanup}"),
            Err(error) => Err(error.context(format!("packet test cleanup also failed: {cleanup}"))),
        };
    }
    result
}
