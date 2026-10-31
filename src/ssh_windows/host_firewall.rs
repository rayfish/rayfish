//! Allow only this executable's SSH listener on its overlay addresses.

use std::net::IpAddr;

use anyhow::{Result, ensure};

use crate::windows_process::WindowsProcessRunner;

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(super) async fn ensure_listener_access(addrs: &[IpAddr]) -> Result<()> {
    if addrs.is_empty() {
        return Ok(());
    }
    ensure!(
        addrs
            .iter()
            .all(|addr| matches!(addr, IpAddr::V6(ip) if ip.segments()[0] & 0xfe00 == 0x0200)),
        "SSH listener requires overlay IPv6 addresses"
    );
    let executable = std::env::current_exe()?;
    let program = quote(&executable.to_string_lossy());
    let addresses = addrs
        .iter()
        .map(|addr| quote(&addr.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let port = super::SSH_LISTEN_PORT;
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $name='Rayfish-Mesh-SSH'; \
         $rule=Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue; \
         if ($rule -and $rule.Group -ne 'Rayfish') {{ throw 'An unrelated firewall rule owns the Rayfish SSH rule name.' }}; \
         $parameters=@{{Direction='Inbound';Action='Allow';Enabled='True';Profile='Any';Protocol='TCP';LocalPort={port};Program={program};LocalAddress=@({addresses});RemoteAddress='200::/7'}}; \
         if ($rule) {{ Set-NetFirewallRule -Name $name -PolicyStore PersistentStore @parameters }} \
         else {{ New-NetFirewallRule -Name $name -DisplayName 'Rayfish mesh SSH' -Group 'Rayfish' -PolicyStore PersistentStore @parameters | Out-Null }}"
    );
    WindowsProcessRunner::default()
        .powershell(&script, "allowing SSH on the Rayfish interface")
        .await?;
    Ok(())
}
