//! Permit mesh echo requests for the Windows kernel on its own adapter.

use std::net::Ipv6Addr;

use anyhow::{Result, ensure};

use crate::windows_process::WindowsProcessRunner;

const ECHO_RULE_NAME: &str = "Rayfish-Mesh-ICMPv6-Echo";

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn echo_rule_script(name: &str, interface: &str, address: Ipv6Addr) -> Result<String> {
    ensure!(
        !interface.is_empty()
            && !interface
                .chars()
                .any(|value| matches!(value, '*' | '?' | '[' | ']' | '`')),
        "the ICMPv6 rule requires one exact adapter name"
    );
    ensure!(
        address.octets()[0] & 0xfe == 0x02,
        "the ICMPv6 rule requires an overlay IPv6 address"
    );
    let name = quote(name);
    let interface = quote(interface);
    let address = quote(&address.to_string());
    Ok(format!(
        "$ErrorActionPreference='Stop'; \
         $name={name}; \
         $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object {{ $_.Name -eq $name }}); \
         if ($rules.Count -gt 1) {{ throw 'Multiple firewall rules own the Rayfish ICMPv6 rule name.' }}; \
         if ($rules.Count -eq 1 -and $rules[0].Group -ne 'Rayfish') {{ throw 'An unrelated firewall rule owns the Rayfish ICMPv6 rule name.' }}; \
         $parameters=@{{Direction='Inbound';Action='Allow';Enabled='True';Profile='Any';Protocol='ICMPv6';IcmpType='128';InterfaceAlias={interface};LocalAddress={address};RemoteAddress='200::/7';EdgeTraversalPolicy='Block'}}; \
         if ($rules.Count -eq 1) {{ $rules[0] | Set-NetFirewallRule @parameters | Out-Null }} \
         else {{ New-NetFirewallRule -Name $name -DisplayName 'Rayfish mesh ICMPv6 echo' -Group 'Rayfish' -PolicyStore PersistentStore @parameters | Out-Null }}"
    ))
}

async fn ensure_rule(name: &str, interface: &str, address: Ipv6Addr) -> Result<()> {
    WindowsProcessRunner::default()
        .powershell(
            &echo_rule_script(name, interface, address)?,
            "allowing mesh ICMPv6 echo requests on the Windows adapter",
        )
        .await?;
    Ok(())
}

pub(crate) async fn ensure_echo_request_access(interface: &str, address: Ipv6Addr) -> Result<()> {
    ensure_rule(ECHO_RULE_NAME, interface, address).await
}

#[cfg(test)]
#[path = "windows_firewall_tests.rs"]
mod tests;
