use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use iroh::SecretKey;
use ray_proto::ipc::{self, IpcMessage};
use tokio::time::timeout;
use tun_rs::{AsyncDevice, DeviceBuilder};
use windows_sys::Win32::UI::Shell::{CSIDL_PROGRAM_FILES, SHGFP_TYPE_CURRENT, SHGetFolderPathW};

use super::super::windows_routes;
use super::*;
use crate::membership::derive_ipv6;

const DEADLINE: Duration = Duration::from_secs(15);

fn installed_wintun() -> Result<PathBuf> {
    let mut folder = [0u16; 260];
    // SAFETY: SHGetFolderPathW writes at most MAX_PATH UTF-16 units into the
    // supplied buffer. Null HWND/token select this process's known folder.
    let status = unsafe {
        SHGetFolderPathW(
            null_mut(),
            i32::try_from(CSIDL_PROGRAM_FILES)?,
            null_mut(),
            u32::try_from(SHGFP_TYPE_CURRENT)?,
            folder.as_mut_ptr(),
        )
    };
    ensure!(
        status >= 0,
        "could not locate the installed Program Files directory"
    );
    let length = folder
        .iter()
        .position(|value| *value == 0)
        .context("the Program Files directory was not terminated")?;
    let path = PathBuf::from(OsString::from_wide(&folder[..length]))
        .join("Rayfish")
        .join("wintun.dll");
    ensure!(
        path.is_absolute() && path.is_file(),
        "the installed Wintun DLL is missing"
    );
    Ok(path)
}

async fn require_disposable_standby() -> Result<()> {
    ensure!(
        std::env::var("RAYFISH_WINDOWS_INSTALL_TEST").as_deref() == Ok("1"),
        "this test requires the disposable Windows installation guard"
    );
    let response = timeout(DEADLINE, async {
        let mut connection = ipc::connect().await?;
        ipc::send(&mut connection, IpcMessage::Status).await?;
        ipc::recv(&mut connection).await
    })
    .await
    .context("the installed service did not answer its status")??;
    ensure!(
        matches!(response, IpcMessage::StatusResponse {
        active: false, networks, inactive_networks, pending_networks, ..
    } if networks.is_empty() && inactive_networks.is_empty() && pending_networks.is_empty()),
        "the kernel echo test requires an empty installed service on standby"
    );
    Ok(())
}

struct TestInterface {
    alias: String,
    index: u32,
    rule: String,
    local: Ipv6Addr,
    remote: Ipv6Addr,
}

impl TestInterface {
    fn configure_script(&self) -> String {
        let local = quote(&self.local.to_string());
        format!(
            "$ErrorActionPreference='Stop'; \
             Set-NetIPInterface -InterfaceIndex {index} -AddressFamily IPv6 -DadTransmits 0 -RouterDiscovery Disabled; \
             New-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv6 -IPAddress {local} -PrefixLength 128 | Out-Null",
            index = self.index,
        )
    }

    fn prepare_route_repair_script(&self, unrelated: Ipv6Addr) -> String {
        let segments = self.remote.segments();
        let gateway = Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        );
        format!(
            "$ErrorActionPreference='Stop'; \
             Get-NetRoute -InterfaceIndex {index} -DestinationPrefix {prefix} -PolicyStore ActiveStore | Set-NetRoute -RouteMetric 37 | Out-Null; \
             New-NetRoute -InterfaceIndex {index} -DestinationPrefix {prefix} -NextHop {gateway} -RouteMetric 81 -PolicyStore ActiveStore | Out-Null; \
             New-NetRoute -InterfaceIndex {index} -DestinationPrefix {unrelated} -NextHop '::' -RouteMetric 41 -PolicyStore ActiveStore | Out-Null",
            index = self.index,
            prefix = quote(&format!("{}/128", self.remote)),
            gateway = quote(&gateway.to_string()),
            unrelated = quote(&format!("{unrelated}/128")),
        )
    }

    fn verify_route_script(&self, unrelated: Ipv6Addr) -> String {
        format!(
            "$ErrorActionPreference='Stop'; $routes=@(Get-NetRoute -InterfaceIndex {index} -DestinationPrefix {prefix} -PolicyStore ActiveStore); \
             if ($routes.Count -ne 1 -or $routes[0].NextHop -ne '::' -or $routes[0].Protocol -ne 'NetMgmt' -or $routes[0].RouteMetric -ne 37) {{ throw 'Native route reconciliation changed the route or its metric.' }}; \
             $other=@(Get-NetRoute -InterfaceIndex {index} -DestinationPrefix {unrelated} -PolicyStore ActiveStore); \
             if ($other.Count -ne 1 -or $other[0].RouteMetric -ne 41) {{ throw 'Native route reconciliation modified another prefix.' }}",
            index = self.index,
            prefix = quote(&format!("{}/128", self.remote)),
            unrelated = quote(&format!("{unrelated}/128")),
        )
    }

    fn verify_rule_script(&self) -> String {
        let name = quote(&self.rule);
        let alias = quote(&self.alias);
        let address = quote(&self.local.to_string());
        format!(
            "$ErrorActionPreference='Stop'; \
             $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {{ $_.Name -eq {name} }}); \
             if ($rules.Count -ne 1) {{ throw 'The scoped echo rule was not installed exactly once.' }}; \
             $rule=$rules[0]; \
             if ($rule.Group -ne 'Rayfish' -or $rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or $rule.Enabled -ne 'True' -or $rule.Profile -ne 'Any') {{ throw 'The echo rule has unexpected policy settings.' }}; \
             $port=$rule | Get-NetFirewallPortFilter; \
             if ($port.Protocol -notin @('ICMPv6','58') -or @($port.IcmpType).Count -ne 1 -or [string]$port.IcmpType -notmatch '^128(?::(?:Any|[*]))?$') {{ throw 'The echo rule permits an unexpected protocol or ICMP type.' }}; \
             $iface=$rule | Get-NetFirewallInterfaceFilter; \
             if (@($iface.InterfaceAlias).Count -ne 1 -or [string]$iface.InterfaceAlias -cne {alias}) {{ throw 'The echo rule is not limited to its own adapter.' }}; \
             $addresses=$rule | Get-NetFirewallAddressFilter; \
             if (@($addresses.LocalAddress).Count -ne 1 -or [System.Net.IPAddress](([string]$addresses.LocalAddress -split '/')[0]) -ne [System.Net.IPAddress]{address} -or @($addresses.RemoteAddress).Count -ne 1 -or [string]$addresses.RemoteAddress -ne '200::/7') {{ throw 'The echo rule is not limited to its own address and mesh peers.' }}"
        )
    }

    fn cleanup_script(&self) -> String {
        let name = quote(&self.rule);
        let remote = quote(&format!("{}/128", self.remote));
        format!(
            "$ErrorActionPreference='Stop'; \
             $failures=[System.Collections.Generic.List[string]]::new(); \
             try {{ Get-NetRoute -PolicyStore ActiveStore | Where-Object {{ $_.InterfaceIndex -eq {index} -and $_.DestinationPrefix -eq {remote} }} | Remove-NetRoute -Confirm:$false }} catch {{ $failures.Add('test route cleanup failed: '+$_.Exception.Message) }}; \
             try {{ $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {{ $_.Name -eq {name} }}); \
                 if ($rules | Where-Object {{ $_.Group -notin @('Rayfish','Rayfish test collision') }}) {{ throw 'An unrelated rule replaced the test rule.' }}; \
                 $rules | Remove-NetFirewallRule -Confirm:$false \
             }} catch {{ $failures.Add('test rule cleanup failed: '+$_.Exception.Message) }}; \
             if ($failures.Count) {{ throw ($failures -join '; ') }}",
            index = self.index,
        )
    }
}

fn words(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|chunk| {
            u32::from(u16::from_be_bytes([
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
            ]))
        })
        .sum()
}

fn icmp_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> Result<u16> {
    let mut sum = words(&source.octets())
        + words(&destination.octets())
        + u32::try_from(message.len())?
        + 58
        + words(message);
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    Ok(!u16::try_from(sum)?)
}

struct EchoProbe {
    id: u16,
    sequence: u16,
    payload: [u8; 24],
}

impl EchoProbe {
    fn packet(&self, interface: &TestInterface) -> Result<Vec<u8>> {
        let mut packet = vec![0; 48 + self.payload.len()];
        let payload_length = u16::try_from(packet.len() - 40)?;
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&interface.remote.octets());
        packet[24..40].copy_from_slice(&interface.local.octets());
        packet[40] = 128;
        packet[44..46].copy_from_slice(&self.id.to_be_bytes());
        packet[46..48].copy_from_slice(&self.sequence.to_be_bytes());
        packet[48..].copy_from_slice(&self.payload);
        let checksum = icmp_checksum(interface.remote, interface.local, &packet[40..])?;
        packet[42..44].copy_from_slice(&checksum.to_be_bytes());
        Ok(packet)
    }

    async fn receive_reply(&self, device: &AsyncDevice, interface: &TestInterface) -> Result<()> {
        let mut packet = [0; 2048];
        timeout(DEADLINE, async {
            loop {
                let count = device
                    .recv(&mut packet)
                    .await
                    .context("reading the test Wintun adapter")?;
                let packet = &packet[..count];
                if packet.len() < 48
                    || packet[0] >> 4 != 6
                    || packet[6] != 58
                    || packet[40] != 129
                    || packet[44..46] != self.id.to_be_bytes()
                    || packet[46..48] != self.sequence.to_be_bytes()
                {
                    continue;
                }
                ensure!(
                    packet[8..24] == interface.local.octets()
                        && packet[24..40] == interface.remote.octets(),
                    "the kernel echo reply used unexpected addresses"
                );
                ensure!(
                    packet[41] == 0 && packet[48..] == self.payload,
                    "the kernel did not echo the fresh payload"
                );
                ensure!(
                    usize::from(u16::from_be_bytes([packet[4], packet[5]])) == packet.len() - 40,
                    "the kernel echo reply has an invalid payload length"
                );
                ensure!(
                    icmp_checksum(interface.local, interface.remote, &packet[40..])? == 0,
                    "the kernel echo reply checksum is invalid"
                );
                return Ok(());
            }
        })
        .await
        .context("Windows did not return the injected ICMPv6 echo request")?
    }
}

#[tokio::test]
#[ignore = "requires an empty installed MSI on a disposable administrator Windows runner"]
async fn windows_kernel_echo_reply_uses_scoped_host_rule() -> Result<()> {
    require_disposable_standby().await?;
    let suffix = rand::random::<u64>();
    let alias = format!("ray-icmp-test-{suffix:x}");
    let rule = format!("Rayfish-ICMP-Test-{suffix:x}");
    let runner = WindowsProcessRunner::default();
    runner.powershell(&format!(
        "$ErrorActionPreference='Stop'; \
         if (Get-NetAdapter | Where-Object {{ $_.Name -eq {alias} }}) {{ throw 'The disposable test adapter already exists.' }}; \
         if (Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {{ $_.Name -eq {rule} }}) {{ throw 'The disposable test rule already exists.' }}",
        alias = quote(&alias), rule = quote(&rule),
    ), "checking disposable ICMPv6 test resources").await?;
    let device = DeviceBuilder::new()
        .name(&alias)
        .description("Rayfish ICMP test")
        .mtu(1280)
        .mtu_v6(1280)
        .enable(true)
        .delete_driver(false)
        .wintun_file(installed_wintun()?.to_string_lossy().into_owned())
        .build_async()
        .context("creating the disposable Wintun adapter")?;
    let interface = TestInterface {
        alias: device
            .name()
            .context("reading the disposable adapter name")?,
        index: device
            .if_index()
            .context("reading the disposable adapter index")?,
        rule,
        local: derive_ipv6(&SecretKey::generate().public()),
        remote: derive_ipv6(&SecretKey::generate().public()),
    };
    let result = async {
        ensure!(interface.alias == alias, "the disposable adapter name changed unexpectedly");
        runner.powershell(&interface.configure_script(), "configuring the disposable ICMPv6 route").await?;
        windows_routes::ensure(&interface.alias, interface.remote, 128).await?;
        let unrelated = derive_ipv6(&SecretKey::generate().public());
        ensure!(unrelated != interface.remote && unrelated != interface.local, "the generated route fixtures collided");
        runner.powershell(&interface.prepare_route_repair_script(unrelated), "preparing disposable native route repair fixtures").await?;
        windows_routes::ensure(&interface.alias, interface.remote, 128).await?;
        windows_routes::ensure(&interface.alias, interface.remote, 128).await?;
        runner.powershell(&interface.verify_route_script(unrelated), "checking native route scope and existing metric").await?;
        // An unrelated rule with the same name must survive unchanged.
        runner.powershell(&format!(
            "New-NetFirewallRule -Name {name} -DisplayName 'Rayfish test collision' -Group 'Rayfish test collision' -Direction Inbound -Action Block -Protocol ICMPv6 -IcmpType 128 -InterfaceAlias {alias} -LocalAddress {local} -RemoteAddress '200::/7' -PolicyStore PersistentStore -ErrorAction Stop | Out-Null",
            name = quote(&interface.rule), alias = quote(&interface.alias), local = quote(&interface.local.to_string()),
        ), "creating an unrelated disposable firewall rule").await?;
        ensure!(ensure_rule(&interface.rule, &interface.alias, interface.local).await.is_err(), "the echo rule replaced an unrelated firewall rule");
        runner.powershell(&format!(
            "$ErrorActionPreference='Stop'; $rule=Get-NetFirewallRule -Name {name} -PolicyStore PersistentStore; if ($rule.Group -ne 'Rayfish test collision' -or $rule.Action -ne 'Block') {{ throw 'The unrelated test rule was modified.' }}; $rule | Remove-NetFirewallRule -Confirm:$false",
            name = quote(&interface.rule),
        ), "checking the unrelated rule was preserved").await?;
        ensure_rule(&interface.rule, &interface.alias, interface.local).await?;
        ensure_rule(&interface.rule, &interface.alias, interface.local).await?;
        runner.powershell(&interface.verify_rule_script(), "checking the installed ICMPv6 rule filters").await?;
        let probe = EchoProbe { id: rand::random(), sequence: rand::random(), payload: rand::random() };
        let packet = probe.packet(&interface)?;
        let written = timeout(DEADLINE, device.send(&packet)).await.context("injecting the kernel echo request timed out")??;
        ensure!(written == packet.len(), "the Wintun echo request was truncated");
        probe.receive_reply(&device, &interface).await
    }.await;
    let cleanup = runner
        .powershell(
            &interface.cleanup_script(),
            "removing disposable ICMPv6 resources",
        )
        .await;
    drop(device);
    let adapter_cleanup = runner.powershell(&format!(
        "$ErrorActionPreference='Stop'; if (Get-NetAdapter | Where-Object {{ $_.Name -eq {alias} }}) {{ throw 'The disposable Wintun adapter was not removed.' }}",
        alias = quote(&interface.alias),
    ), "checking disposable adapter removal").await;
    let mut failures = Vec::new();
    if let Err(error) = cleanup {
        failures.push(format!("{error:#}"));
    }
    if let Err(error) = adapter_cleanup {
        failures.push(format!("{error:#}"));
    }
    if !failures.is_empty() {
        let failures = failures.join("; ");
        return match result {
            Ok(()) => bail!("ICMPv6 test cleanup failed: {failures}"),
            Err(error) => {
                Err(error.context(format!("ICMPv6 test cleanup also failed: {failures}")))
            }
        };
    }
    result
}

#[test]
fn echo_rule_rejects_adapter_wildcards_and_non_mesh_addresses() {
    let address = derive_ipv6(&SecretKey::generate().public());
    assert!(echo_rule_script("test", "rayfish*", address).is_err());
    assert!(echo_rule_script("test", "rayfish", Ipv6Addr::LOCALHOST).is_err());
    assert!(echo_rule_script("test", "adapter's name", address).is_ok());
}
