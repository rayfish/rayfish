//! Keeping the Linux TUN's address, route and link state in place while the
//! VPN is up, and spotting other interfaces that claim part of the overlay.
//!
//! `ray up` configures the device once. Anything else on the host can undo
//! that afterwards: `ip link set rayfish0 down` drops the `200::/7` route (and,
//! without `keep_addr_on_down`, the address), and nothing would put them back
//! until the next `ray up`, while `ray status` kept saying the VPN was up. The
//! watcher listens for the kernel's own change notifications rather than
//! polling, so it costs nothing while nothing changes, and it only reacts to
//! losses: re-adding what is missing raises "new" notifications, which it
//! ignores, so a repair cannot feed itself.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::{StreamExt, TryStreamExt};
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};
use rtnetlink::{MulticastGroup, RouteMessageBuilder};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::{OVERLAY, OVERLAY_LEN, tun_link_index, with_tun_link};
use crate::membership::is_overlay_ip;

/// How long to let a burst of notifications settle before repairing. Taking a
/// link down removes the route and raises several messages; one repair answers
/// all of them, and the wait also caps repairs at about one a second if
/// something keeps undoing them.
const SETTLE: Duration = Duration::from_secs(1);

/// Whether a notification says the TUN lost something `ray up` put there: its
/// link went down, an address was removed from it, or a route through it was
/// deleted.
fn is_loss(message: &RouteNetlinkMessage, index: u32) -> bool {
    match message {
        RouteNetlinkMessage::NewLink(link) => {
            link.header.index == index && !link.header.flags.contains(LinkFlags::Up)
        }
        RouteNetlinkMessage::DelAddress(address) => address.header.index == index,
        // Only our own range: the exit-node full tunnel adds and removes routes
        // through the TUN as a selection changes, and those are not losses.
        RouteNetlinkMessage::DelRoute(route) => {
            route_oif(route) == Some(index)
                && route.header.destination_prefix_length == OVERLAY_LEN
                && route_destination(route) == Some(OVERLAY)
        }
        _ => false,
    }
}

fn route_destination(route: &RouteMessage) -> Option<Ipv6Addr> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet6(prefix)) => Some(*prefix),
            _ => None,
        })
}

fn route_oif(route: &RouteMessage) -> Option<u32> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
}

/// Watches the TUN until `token` is cancelled and puts the link, our `/128` and
/// the `200::/7` route back whenever the kernel reports one of them gone.
/// `active` is checked again before each repair, so a `ray down` that races a
/// notification is never undone. A link that went down also took the exit
/// client's default route through the TUN, so each repair nudges
/// `exit_reapply` to put that back too.
pub(crate) fn spawn_repair_watcher(
    tun_name: String,
    v6: Ipv6Addr,
    active: Arc<AtomicBool>,
    exit_reapply: Arc<Notify>,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        if let Err(error) = watch(&tun_name, v6, &active, &exit_reapply, &token).await {
            tracing::warn!(error = %format!("{error:#}"), tun = %tun_name,
                "TUN watcher stopped; a link, address or route removed by something else will not be restored until the next `ray up`");
        }
    });
}

async fn watch(
    tun_name: &str,
    v6: Ipv6Addr,
    active: &AtomicBool,
    exit_reapply: &Notify,
    token: &CancellationToken,
) -> Result<()> {
    let (connection, handle, mut messages) = rtnetlink::new_multicast_connection(&[
        MulticastGroup::Link,
        MulticastGroup::Ipv6Ifaddr,
        MulticastGroup::Ipv6Route,
    ])
    .context("open netlink notification socket")?;
    let driver = tokio::spawn(connection);
    let result = async {
        let index = tun_link_index(&handle, tun_name).await?;
        loop {
            // Biased: once `ray down` cancels, a notification that arrives in
            // the same poll (its own link going down) must not win.
            let message = tokio::select! {
                biased;
                _ = token.cancelled() => return Ok(()),
                message = messages.next() => message.context("netlink notifications ended")?,
            };
            let NetlinkPayload::InnerMessage(message) = message.0.payload else {
                continue;
            };
            if !is_loss(&message, index) {
                continue;
            }
            tokio::select! {
                biased;
                _ = token.cancelled() => return Ok(()),
                _ = tokio::time::sleep(SETTLE) => {}
            }
            while messages.try_recv().is_ok() {}
            if token.is_cancelled() || !active.load(Ordering::SeqCst) {
                continue;
            }
            tracing::warn!(tun = %tun_name, "TUN lost its link, address or route; restoring");
            let stopped = || token.is_cancelled() || !active.load(Ordering::SeqCst);
            tokio::select! {
                biased;
                _ = token.cancelled() => return Ok(()),
                result = repair(tun_name, v6, &stopped) => match result {
                    Ok(Repair::Done) => exit_reapply.notify_one(),
                    Ok(Repair::Stopped) => {}
                    Err(error) => tracing::warn!(error = %format!("{error:#}"), tun = %tun_name, "failed to restore the TUN"),
                },
            }
        }
    }
    .await;
    driver.abort();
    result
}

/// How a [`repair`] ended without an error.
#[derive(Debug, PartialEq, Eq)]
enum Repair {
    Done,
    /// `ray down` began partway through, so the rest was left undone: it is
    /// taking the link down on purpose.
    Stopped,
}

/// The same three steps `ray up` takes, in the same order. Each is idempotent.
/// `stopped` is checked before each one, so a repair that races `ray down`
/// does not bring back up what it is tearing down.
async fn repair(
    tun_name: &str,
    v6: Ipv6Addr,
    stopped: &(dyn Fn() -> bool + Sync),
) -> Result<Repair> {
    if stopped() {
        return Ok(Repair::Stopped);
    }
    super::set_link_up(tun_name).await?;
    if stopped() {
        return Ok(Repair::Stopped);
    }
    super::ensure_ipv6_addr(tun_name, v6).await?;
    if stopped() {
        return Ok(Repair::Stopped);
    }
    super::route_peer_range(tun_name).await?;
    Ok(Repair::Done)
}

/// A route on another interface that covers part of the overlay range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverlayRoute {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub oif: u32,
}

/// Whether `prefix/len` lies inside `200::/7`. A shorter route that merely
/// contains the range (a default route, `::/1`) loses to our `/7` by prefix
/// length and is no conflict.
fn inside_overlay(prefix: Ipv6Addr, len: u8) -> bool {
    len >= OVERLAY_LEN && is_overlay_ip(IpAddr::V6(prefix))
}

/// The unicast routes through other interfaces that overlap the overlay. One
/// with the same `/7` and a lower metric (Yggdrasil's connected route sits at
/// 256, ours at the default 1024) takes the whole mesh; a longer one takes the
/// part it covers. Either way those packets never reach the TUN.
fn overlay_conflicts(routes: &[RouteMessage], our_index: u32) -> Vec<OverlayRoute> {
    routes
        .iter()
        .filter(|route| route.header.kind == RouteType::Unicast)
        .filter_map(|route| {
            let oif = route_oif(route)?;
            let prefix = route_destination(route)?;
            let len = route.header.destination_prefix_length;
            (oif != our_index && inside_overlay(prefix, len)).then_some(OverlayRoute {
                prefix,
                len,
                oif,
            })
        })
        .collect()
}

/// One warning per route through another interface that overlaps `200::/7`,
/// naming that interface. Read once at `ray up`; a full route dump is too
/// heavy to repeat on a host carrying a large table.
pub(crate) async fn overlay_route_warnings(tun_name: &str) -> Result<Vec<String>> {
    with_tun_link(tun_name, async |handle, our_index| {
        let routes: Vec<RouteMessage> = handle
            .route()
            .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
            .execute()
            .try_collect()
            .await
            .context("list IPv6 routes")?;
        let mut warnings = Vec::new();
        for conflict in overlay_conflicts(&routes, our_index) {
            let device = link_name(&handle, conflict.oif)
                .await
                .unwrap_or_else(|| format!("interface #{}", conflict.oif));
            warnings.push(format!(
                "route {}/{} on {device} overlaps the mesh range 200::/7, so mesh traffic to it goes to {device} instead of rayfish (another overlay such as Yggdrasil uses this range too)",
                conflict.prefix, conflict.len
            ));
        }
        Ok(warnings)
    })
    .await
}

async fn link_name(handle: &rtnetlink::Handle, index: u32) -> Option<String> {
    let link = handle
        .link()
        .get()
        .match_index(index)
        .execute()
        .try_next()
        .await
        .ok()??;
    link.attributes
        .into_iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(name) => Some(name),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_route::address::AddressMessage;
    use rtnetlink::packet_route::link::LinkMessage;

    const TUN: u32 = 7;

    /// A repair that finds `ray down` already under way touches nothing. The
    /// interface name does not exist, so any step it did take would fail.
    #[tokio::test]
    async fn a_stopped_repair_changes_nothing() {
        let repaired = repair("rf-none-such", Ipv6Addr::LOCALHOST, &|| true).await;
        assert_eq!(repaired.expect("no step ran"), Repair::Stopped);
    }

    fn link(index: u32, flags: LinkFlags) -> RouteNetlinkMessage {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.header.flags = flags;
        RouteNetlinkMessage::NewLink(message)
    }

    fn route(prefix: &str, len: u8, oif: u32) -> RouteMessage {
        let mut message = RouteMessage::default();
        message.header.kind = RouteType::Unicast;
        message.header.destination_prefix_length = len;
        message.attributes = vec![
            RouteAttribute::Destination(RouteAddress::Inet6(prefix.parse().expect("prefix"))),
            RouteAttribute::Oif(oif),
        ];
        message
    }

    #[test]
    fn losses_on_our_device_trigger_a_repair() {
        assert!(is_loss(&link(TUN, LinkFlags::empty()), TUN));
        let mut address = AddressMessage::default();
        address.header.index = TUN;
        assert!(is_loss(&RouteNetlinkMessage::DelAddress(address), TUN));
        assert!(is_loss(
            &RouteNetlinkMessage::DelRoute(route("200::", 7, TUN)),
            TUN
        ));
    }

    /// The repair itself raises these. Reacting to them would loop.
    #[test]
    fn additions_and_other_devices_do_not() {
        assert!(!is_loss(&link(TUN, LinkFlags::Up), TUN));
        assert!(!is_loss(&link(TUN + 1, LinkFlags::empty()), TUN));
        assert!(!is_loss(
            &RouteNetlinkMessage::NewRoute(route("200::", 7, TUN)),
            TUN
        ));
        assert!(!is_loss(
            &RouteNetlinkMessage::DelRoute(route("200::", 7, TUN + 1)),
            TUN
        ));
        // An exit-node half-default leaving with its selection.
        assert!(!is_loss(
            &RouteNetlinkMessage::DelRoute(route("::", 1, TUN)),
            TUN
        ));
    }

    #[test]
    fn routes_inside_the_overlay_on_other_devices_are_conflicts() {
        let routes = [
            route("200::", 7, TUN),     // ours
            route("200::", 7, 3),       // another overlay's whole range
            route("300::", 64, 3),      // a subnet inside it
            route("::", 0, 2),          // the default route
            route("::", 1, 2),          // half of a full tunnel
            route("2001:db8::", 32, 2), // ordinary global unicast
            route("fe80::", 64, 2),     // link-local
        ];
        let conflicts = overlay_conflicts(&routes, TUN);
        assert_eq!(
            conflicts,
            [
                OverlayRoute {
                    prefix: "200::".parse().expect("prefix"),
                    len: 7,
                    oif: 3
                },
                OverlayRoute {
                    prefix: "300::".parse().expect("prefix"),
                    len: 64,
                    oif: 3
                },
            ]
        );
    }

    #[test]
    fn local_routes_are_not_conflicts() {
        let mut local = route("200::1", 128, 3);
        local.header.kind = RouteType::Local;
        assert!(overlay_conflicts(&[local], TUN).is_empty());
    }
}
