//! Interface-scoped active routes through the native IP Helper API.

use std::io::Error as IoError;
use std::mem::size_of;
use std::net::Ipv6Addr;
use std::ptr::{NonNull, addr_of, null_mut};
use std::slice;

use anyhow::{Context, Result, bail, ensure};
use tokio::task::spawn_blocking;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
    GetIpForwardTable2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    SetIpForwardEntry2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, MIB_IPPROTO_NETMGMT, SOCKADDR_IN6, SOCKADDR_INET,
};

const INITIAL_METRIC: u32 = 256;

fn check(code: u32, operation: &str) -> Result<()> {
    if code == NO_ERROR {
        return Ok(());
    }
    Err(IoError::from_raw_os_error(i32::try_from(code)?)).context(operation.to_owned())
}

fn wide_alias(alias: &str) -> Result<Vec<u16>> {
    ensure!(
        !alias.is_empty() && !alias.contains('\0'),
        "invalid Windows adapter alias"
    );
    Ok(alias.encode_utf16().chain(Some(0)).collect())
}

fn interface_luid(alias: &str) -> Result<NET_LUID_LH> {
    let alias = wide_alias(alias)?;
    let mut luid = NET_LUID_LH::default();
    // SAFETY: alias is terminated and remains live; luid is a writable output.
    check(
        unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) },
        "resolve Windows TUN adapter",
    )?;
    Ok(luid)
}

fn ipv6_sockaddr(address: Ipv6Addr) -> SOCKADDR_INET {
    let mut ipv6 = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        ..Default::default()
    };
    ipv6.sin6_addr.u.Byte = address.octets();
    SOCKADDR_INET { Ipv6: ipv6 }
}

fn ipv6_address(address: &SOCKADDR_INET) -> Option<Ipv6Addr> {
    // SAFETY: every SOCKADDR_INET variant starts with its initialized family.
    if unsafe { address.si_family } != AF_INET6 {
        return None;
    }
    // SAFETY: the family selects the IPv6 union variant; its bytes are initialized.
    Some(Ipv6Addr::from(unsafe { address.Ipv6.sin6_addr.u.Byte }))
}

fn validate_prefix(address: Ipv6Addr, prefix: u8) -> Result<()> {
    ensure!(
        (7..=128).contains(&prefix) && address.octets()[0] & 0xfe == 0x02,
        "Windows TUN routes must stay inside the IPv6 overlay"
    );
    let host_bits = 128 - u32::from(prefix);
    ensure!(
        u128::from(address) & ((1u128 << host_bits) - 1) == 0,
        "Windows TUN route prefix has nonzero host bits"
    );
    Ok(())
}

fn in_scope(row: &MIB_IPFORWARD_ROW2, luid: &NET_LUID_LH, address: Ipv6Addr, prefix: u8) -> bool {
    // SAFETY: Value represents all bits of the initialized NET_LUID union.
    let same_interface = unsafe { row.InterfaceLuid.Value == luid.Value };
    same_interface
        && row.DestinationPrefix.PrefixLength == prefix
        && ipv6_address(&row.DestinationPrefix.Prefix) == Some(address)
}

fn is_on_link(row: &MIB_IPFORWARD_ROW2) -> bool {
    ipv6_address(&row.NextHop) == Some(Ipv6Addr::UNSPECIFIED)
}

fn is_correct(row: &MIB_IPFORWARD_ROW2) -> bool {
    is_on_link(row)
        && row.Protocol == MIB_IPPROTO_NETMGMT
        && !row.Loopback
        && !row.AutoconfigureAddress
        && !row.Publish
        && row.ValidLifetime == u32::MAX
        && row.PreferredLifetime == u32::MAX
}

fn new_route(luid: NET_LUID_LH, address: Ipv6Addr, prefix: u8, metric: u32) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: row points to a fully writable SDK route structure.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = ipv6_sockaddr(address);
    row.DestinationPrefix.PrefixLength = prefix;
    row.SitePrefixLength = 0;
    row.NextHop = ipv6_sockaddr(Ipv6Addr::UNSPECIFIED);
    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row
}

struct RouteTable(NonNull<MIB_IPFORWARD_TABLE2>);

impl Drop for RouteTable {
    fn drop(&mut self) {
        // SAFETY: the pointer was allocated by GetIpForwardTable2 and is freed once.
        unsafe { FreeMibTable(self.0.as_ptr().cast()) };
    }
}

fn routes() -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table = null_mut();
    // SAFETY: table is a writable out-pointer; AF_INET6 is a supported family.
    let status = unsafe { GetIpForwardTable2(AF_INET6, &mut table) };
    if status == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }
    check(status, "read Windows IPv6 routes")?;
    let table = RouteTable(NonNull::new(table).context("Windows returned a null route table")?);
    // SAFETY: success returns an initialized table header. Read the field
    // directly without borrowing a full table when there are no rows.
    let count = usize::try_from(unsafe { addr_of!((*table.0.as_ptr()).NumEntries).read() })?;
    if count == 0 {
        return Ok(Vec::new());
    }
    ensure!(
        count <= usize::try_from(isize::MAX)? / size_of::<MIB_IPFORWARD_ROW2>(),
        "Windows route table is too large"
    );
    // SAFETY: the SDK repr(C) Table field accounts for header and row alignment;
    // the API owns count initialized rows, all borrowed before RouteTable drops.
    let rows = unsafe {
        slice::from_raw_parts(
            addr_of!((*table.0.as_ptr()).Table).cast::<MIB_IPFORWARD_ROW2>(),
            count,
        )
    };
    Ok(rows.to_vec())
}

fn delete(row: &MIB_IPFORWARD_ROW2) -> Result<()> {
    // SAFETY: row is an initialized entry copied from the native route table.
    let status = unsafe { DeleteIpForwardEntry2(row) };
    if status == ERROR_NOT_FOUND {
        // Another reconciler already removed this same route.
        return Ok(());
    }
    check(status, "remove Windows TUN route")
}

fn reconcile(alias: &str, address: Ipv6Addr, prefix: u8) -> Result<()> {
    validate_prefix(address, prefix)?;
    let luid = interface_luid(alias)?;
    for attempt in 0..2 {
        let scoped: Vec<_> = routes()?
            .into_iter()
            .filter(|row| in_scope(row, &luid, address, prefix))
            .collect();
        if let Some(current) = scoped.iter().find(|row| is_on_link(row)) {
            if !is_correct(current) {
                let replacement = new_route(luid, address, prefix, current.Metric);
                // SAFETY: replacement has a valid existing key and initialized fields.
                check(
                    unsafe { SetIpForwardEntry2(&replacement) },
                    "repair Windows TUN route",
                )?;
            }
        } else {
            let replacement = new_route(luid, address, prefix, INITIAL_METRIC);
            // SAFETY: prefix, family, lifetimes and interface LUID are initialized.
            let status = unsafe { CreateIpForwardEntry2(&replacement) };
            if status == ERROR_OBJECT_ALREADY_EXISTS && attempt == 0 {
                // Re-read once if another reconciler won the creation race.
                continue;
            }
            check(status, "create Windows TUN route")?;
        }
        for row in scoped.iter().filter(|row| !is_on_link(row)) {
            delete(row)?;
        }
        return Ok(());
    }
    bail!("Windows TUN route changed during reconciliation")
}

pub(super) async fn ensure(alias: &str, address: Ipv6Addr, prefix: u8) -> Result<()> {
    let alias = alias.to_owned();
    spawn_blocking(move || reconcile(&alias, address, prefix))
        .await
        .context("join native Windows route setup")?
}

pub(super) async fn remove(alias: &str, address: Ipv6Addr, prefix: u8) -> Result<()> {
    let alias = alias.to_owned();
    spawn_blocking(move || {
        validate_prefix(address, prefix)?;
        let luid = interface_luid(&alias)?;
        for row in routes()?
            .iter()
            .filter(|row| in_scope(row, &luid, address, prefix))
        {
            delete(row)?;
        }
        Ok(())
    })
    .await
    .context("join native Windows route cleanup")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_keep_native_defaults_and_only_match_their_exact_scope() {
        let interface = NET_LUID_LH { Value: 7 };
        let other = NET_LUID_LH { Value: 8 };
        let prefix = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0);
        let mut row = new_route(interface, prefix, 7, 37);
        assert!(is_correct(&row));
        assert!(in_scope(&row, &interface, prefix, 7));
        assert!(!in_scope(&row, &other, prefix, 7));
        assert!(!in_scope(&row, &interface, prefix, 128));
        assert_eq!(row.Metric, 37);
        assert!(row.SitePrefixLength <= row.DestinationPrefix.PrefixLength);
        assert_eq!(row.ValidLifetime, u32::MAX);
        row.NextHop = ipv6_sockaddr(prefix);
        assert!(!is_correct(&row));
        row.NextHop = ipv6_sockaddr(Ipv6Addr::UNSPECIFIED);
        row.Loopback = true;
        assert!(!is_correct(&row));
        row.Loopback = false;
        row.ValidLifetime = 10;
        assert!(!is_correct(&row));
        row.ValidLifetime = u32::MAX;
        row.Protocol = 0;
        assert!(!is_correct(&row));
    }

    #[test]
    fn native_route_inputs_reject_broad_prefixes_and_alias_terminators() {
        let overlay = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 0);
        assert!(validate_prefix(overlay, 7).is_ok());
        assert!(validate_prefix(overlay, 6).is_err());
        assert!(validate_prefix(Ipv6Addr::LOCALHOST, 128).is_err());
        assert!(validate_prefix(Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1), 7).is_err());
        assert!(wide_alias("adapter's name").is_ok());
        assert!(wide_alias("adapter\0other").is_err());
    }
}
