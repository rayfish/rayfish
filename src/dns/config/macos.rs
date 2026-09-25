use std::net::Ipv6Addr;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::schema_definitions::{
    kSCPropInterfaceName, kSCPropNetDNSSearchDomains, kSCPropNetDNSServerAddresses,
    kSCPropNetDNSSupplementalMatchDomains, kSCPropNetIPv6Addresses, kSCPropNetIPv6PrefixLength,
    kSCPropNetIPv6Router, kSCPropNetInterfaceDeviceName,
};

use async_trait::async_trait;

use super::{DNS_DOMAIN, DnsConfigurator};

const SC_DNS_KEY: &str = "State:/Network/Service/rayfish/DNS";
/// The IPv6 half of the same service, written alongside the DNS key; see
/// [`write_service_config`].
const SC_IPV6_KEY: &str = "State:/Network/Service/rayfish/IPv6";
/// The service itself, carrying only its rank. See [`write_service_config`].
const SC_SERVICE_KEY: &str = "State:/Network/Service/rayfish";
/// The interface our service runs on, in the `Setup:` half of the store.
///
/// The only key here that is not for configd. See [`write_service_config`].
const SC_SETUP_INTERFACE_KEY: &str = "Setup:/Network/Service/rayfish/Interface";
/// The service id, which is the last path component of the keys above.
/// `ConfirmedServiceID` has to repeat it to be believed; see
/// [`write_dns_config`].
const SC_SERVICE_ID: &str = "rayfish";

struct SendSyncStore(SCDynamicStore);

// SCDynamicStore communicates with configd via Mach IPC. The set/remove
// calls are thread-safe when no callback context is registered (our case).
unsafe impl Send for SendSyncStore {}
unsafe impl Sync for SendSyncStore {}

static STORE: OnceLock<Mutex<SendSyncStore>> = OnceLock::new();

fn get_or_init_store() -> Result<&'static Mutex<SendSyncStore>> {
    STORE
        .get()
        .context("SCDynamicStore not initialized (call detect_and_configure first)")
}

fn init_store() -> Result<&'static Mutex<SendSyncStore>> {
    if let Some(existing) = STORE.get() {
        return Ok(existing);
    }
    let store = SCDynamicStoreBuilder::new("rayfish")
        .session_keys(true)
        .build()
        .context("failed to create SCDynamicStore session")?;
    let _ = STORE.set(Mutex::new(SendSyncStore(store)));
    Ok(STORE.get().unwrap())
}

/// Who holds [`SC_DNS_KEY`] right now, as one re-assert pass sees it.
///
/// The two bad states are separated because only one of them is ours to
/// repair. A VPN that takes DNS for the duration of its tunnel writes its
/// own resolver over every service's key, ours included, and re-asserts
/// that on a notification of its own; racing it for the key would be two
/// daemons overwriting each other for as long as it stays connected, which
/// is the fight `MERGE_COOLDOWN` exists to avoid on Linux. A key
/// that is simply *gone* has no owner to fight, and is what a VPN leaves
/// behind on the way out: it removes the key rather than restoring the
/// value it found, so `.ray` stops resolving when the other VPN
/// disconnects, not while it is up.
pub enum DnsKeyState {
    /// Our resolver is installed and nothing has touched it.
    Ours,
    /// The key is not in the store. Nobody owns it, so re-applying is safe.
    Gone,
    /// Somebody else's resolver sits at our key. Leave it to them.
    Foreign,
}

/// Read [`SC_DNS_KEY`] back and classify it.
///
/// `ServerAddresses` is the marker: ours names the one address the mesh
/// resolver answers on, so any other value is a dictionary we did not
/// write. A key we cannot parse counts as foreign, because re-applying over
/// something we do not understand is the fight, not the repair.
pub(super) fn dns_key_state() -> DnsKeyState {
    // No store means `apply` never ran, so there is nothing of ours to miss.
    let Some(store) = STORE.get() else {
        return DnsKeyState::Gone;
    };
    let store = store.lock().unwrap();
    let Some(plist) = store.0.get(SC_DNS_KEY) else {
        return DnsKeyState::Gone;
    };
    let Some(dict) = plist.downcast::<CFDictionary>() else {
        return DnsKeyState::Foreign;
    };
    // Typed only for the read: `downcast` can only produce the untyped
    // dictionary, and `find` needs a key type it can turn into a void
    // pointer. Same re-wrap the write path does, in the other direction.
    let dict =
        unsafe { CFDictionary::<CFType, CFType>::wrap_under_get_rule(dict.as_concrete_TypeRef()) };
    let server_key =
        unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) }.as_CFType();
    let ours = dict
        .find(&server_key)
        .and_then(|v| v.downcast::<CFArray>())
        // Typed the same way round as the dictionary above, and to `CFType`
        // rather than `CFString` because this array is whatever the last
        // writer put there: an element that is not a string is skipped, not
        // reinterpreted as one.
        .map(|servers| unsafe {
            CFArray::<CFType>::wrap_under_get_rule(servers.as_concrete_TypeRef())
        })
        .is_some_and(|servers| {
            let mine = CFString::new(&super::resolver_addr().to_string());
            servers
                .iter()
                .filter_map(|v| v.downcast::<CFString>())
                .any(|s| s == mine)
        });
    if ours {
        DnsKeyState::Ours
    } else {
        DnsKeyState::Foreign
    }
}

/// Drop every key this backend owns. Idempotent, and safe with no store.
pub fn remove_dns_config() {
    if let Some(store) = STORE.get() {
        let store = store.lock().unwrap();
        store.0.remove(SC_DNS_KEY);
        store.0.remove(SC_IPV6_KEY);
        store.0.remove(SC_SERVICE_KEY);
        store.0.remove(SC_SETUP_INTERFACE_KEY);
    }
    tracing::info!("removed SCDynamicStore DNS configuration");
}

pub fn write_dns_config(search_domains: &[super::SearchDomain], tun_name: &str) -> Result<()> {
    let store = get_or_init_store()?;
    let store = store.lock().unwrap();

    let server_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
    let server_val = CFArray::from_CFTypes(&[CFString::new(&super::resolver_addr().to_string())]);

    // Route .ray to our resolver. Only .ray: a bare network name as a match
    // domain would hijack the public domain of the same name.
    let match_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSupplementalMatchDomains) };
    let mut match_domains: Vec<CFString> = vec![CFString::new(DNS_DOMAIN)];
    // Full tunnel (an exit node is selected): become the default resolver for
    // *all* queries too. An empty match domain is macOS's catch-all: it makes
    // our resolver handle everything not matched more specifically, so name
    // resolution is forwarded upstream *through the tunnel* (from the daemon)
    // instead of leaking out the physical link, where macOS scopes the query
    // and it never traverses the exit. Split (.ray only) when no exit is up.
    if crate::exit_node::full_tunnel_active() {
        match_domains.push(CFString::new(""));
    }
    let match_val = CFArray::from_CFTypes(&match_domains);

    let search_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSearchDomains) };
    let search_cfstrings: Vec<CFString> = search_domains
        .iter()
        .map(|s| CFString::new(s.as_str()))
        .collect();
    let search_val = CFArray::from_CFTypes(&search_cfstrings);

    // Ask configd to trust this resolver, which is the only way it is ever
    // asked for AAAA, and AAAA is the only answer a `.ray` name has. configd
    // computes the per-resolver "Request A / Request AAAA" flags, and for a
    // supplemental resolver there is exactly one branch that sets them from
    // the resolver's own service: the one guarded by an internal
    // `__SCOPED_QUERY__` marker (configd's dns-configuration.c). Fail it and
    // configd strips the InterfaceName below, assigns no families of its
    // own, and falls back to merging in the flags of the *default* resolver.
    // On a Mac with no native IPv6 that fallback is A-only, so `.ray` names
    // resolve to nothing while `dig` against the same resolver answers fine.
    //
    // We cannot write that marker: configd rebuilds this dictionary from a
    // fixed list of keys and would drop it. It sets the marker itself for a
    // `State:`-only service (we have no `Setup:` half, and no
    // NetworkExtension) on one condition, that the dictionary names its own
    // service id back. Hence `ConfirmedServiceID`, which is also how another
    // VPN's supplemental resolver earns both families.
    //
    // Trust alone only carries the flags across; [`write_service_config`] is
    // what makes there be an AAAA flag to carry.
    //
    // Values are type-erased to `CFType` because these are strings where the
    // rest are arrays, and `from_CFType_pairs` takes one value type.
    let mut pairs: Vec<(CFString, CFType)> = vec![
        (server_key, server_val.as_CFType()),
        (match_key, match_val.as_CFType()),
        (search_key, search_val.as_CFType()),
    ];
    if !tun_name.is_empty() {
        let iface_key = unsafe { CFString::wrap_under_get_rule(kSCPropInterfaceName) };
        pairs.push((iface_key, CFString::new(tun_name).as_CFType()));
        pairs.push((
            CFString::new("ConfirmedServiceID"),
            CFString::new(SC_SERVICE_ID).as_CFType(),
        ));
    }
    let typed_dict = CFDictionary::from_CFType_pairs(&pairs);
    let dict = unsafe { CFDictionary::wrap_under_get_rule(typed_dict.as_concrete_TypeRef()) };

    anyhow::ensure!(
        store.0.set(SC_DNS_KEY, dict),
        "SCDynamicStoreSetValue failed for {SC_DNS_KEY}"
    );
    Ok(())
}

/// Publish the IPv6 half of our service, plus its rank and its interface.
///
/// This is what puts the AAAA flag on the resolver written above. configd
/// asks one question of a service before it will request a family for it:
/// does the service have a *default route* of that family (`ip_plugin.c`,
/// `service_is_routable` over `kRouteListFlagsHasDefault`). Address,
/// prefix and interface are not enough, and the answer turns on the
/// presence of `Router` and nothing else. Note what is *not* asked: no part
/// of that path inspects the address range, so our `200::/7`, which is
/// IETF-reserved rather than global unicast or ULA, counts exactly as much
/// as another VPN's ULA. The same flag is what admits an interface to
/// `scutil --nwi`, which is why ours was missing from it.
///
/// `Router` pointing back at our own address is the "all routes local"
/// case: configd wants a default route to exist in its own model of the
/// service, and gets one with no gateway. `PrimaryRank = Never` is what
/// keeps that model from reaching the kernel: the service can never win the
/// primary election, so it claims no `::/0` and cannot capture the host's
/// IPv6 traffic, and it stays out of the flag set configd merges into every
/// other resolver. In practice the routing table is unchanged, byte for
/// byte, before and after this key is written.
///
/// The rank goes first, and the ordering is load-bearing: it is the only
/// thing keeping the `Router` below from being taken seriously. Publish the
/// address without it and configd is free to elect us the primary IPv6
/// service and put a real `::/0` on the utun, so a failure here has to stop
/// us before we publish anything routable, never after.
fn write_service_config(tun_name: &str, mesh_v6: Ipv6Addr) -> Result<()> {
    let store = get_or_init_store()?;
    let store = store.lock().unwrap();

    let rank = CFDictionary::from_CFType_pairs(&[(
        CFString::new("PrimaryRank"),
        CFString::new("Never").as_CFType(),
    )]);
    let rank = unsafe { CFDictionary::wrap_under_get_rule(rank.as_concrete_TypeRef()) };
    // Our session's keys are reclaimed by configd when the session ends, but
    // a copy left behind by anyone else is not, and a session store cannot
    // overwrite one. Drop it first so a stray key cannot wedge us for good.
    store.0.remove(SC_SERVICE_KEY);
    anyhow::ensure!(
        store.0.set(SC_SERVICE_KEY, rank),
        "SCDynamicStoreSetValue failed for {SC_SERVICE_KEY}"
    );

    // Name our interface in the `Setup:` half of the store as well. configd
    // does not need this: it is what another VPN reads before it will read
    // our DNS key at all.
    //
    // Mullvad's talpid-dns derives this path from the DNS key it found, by
    // rewriting `State:` to `Setup:` and `/DNS` to `/Interface`, and treats
    // its absence as a hard failure that loads the whole service as
    // "no DNS". Nothing it can write ever equals that, so every pass decides
    // our service still needs writing, and each write re-triggers the store
    // notification it is reacting to. The result is a rewrite of every
    // service's DNS a few times a second, host resolution included, for as
    // long as that VPN is connected: not our DNS breaking, but the machine's.
    // Publishing the key ends it after one pass.
    //
    // The same read is what it restores on disconnect. Without the key it
    // records "no DNS" as our previous state and removes our resolver on the
    // way out, which is the disconnect breakage `run_sc_reassert` repairs
    // from the other side; with it, our resolver is put back and that watcher
    // becomes a safety net rather than the thing holding `.ray` up.
    //
    // A `Setup:` key usually means persistent configuration, but ours is a
    // session key in the dynamic store, not a preferences entry, and it joins
    // no service set or service order, so it is not a network service the UI
    // can see.
    let device_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetInterfaceDeviceName) };
    let iface =
        CFDictionary::from_CFType_pairs(&[(device_key, CFString::new(tun_name).as_CFType())]);
    let iface = unsafe { CFDictionary::wrap_under_get_rule(iface.as_concrete_TypeRef()) };
    store.0.remove(SC_SETUP_INTERFACE_KEY);
    anyhow::ensure!(
        store.0.set(SC_SETUP_INTERFACE_KEY, iface),
        "SCDynamicStoreSetValue failed for {SC_SETUP_INTERFACE_KEY}"
    );

    let addr_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetIPv6Addresses) };
    let addr_val = CFArray::from_CFTypes(&[CFString::new(&mesh_v6.to_string())]);
    let prefix_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetIPv6PrefixLength) };
    let prefix_val = CFArray::from_CFTypes(&[CFNumber::from(128i32)]);
    let iface_key = unsafe { CFString::wrap_under_get_rule(kSCPropInterfaceName) };
    let router_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetIPv6Router) };

    let pairs: Vec<(CFString, CFType)> = vec![
        (addr_key, addr_val.as_CFType()),
        (prefix_key, prefix_val.as_CFType()),
        (iface_key, CFString::new(tun_name).as_CFType()),
        (router_key, CFString::new(&mesh_v6.to_string()).as_CFType()),
    ];
    let typed_dict = CFDictionary::from_CFType_pairs(&pairs);
    let dict = unsafe { CFDictionary::wrap_under_get_rule(typed_dict.as_concrete_TypeRef()) };

    anyhow::ensure!(
        store.0.set(SC_IPV6_KEY, dict),
        "SCDynamicStoreSetValue failed for {SC_IPV6_KEY}"
    );
    Ok(())
}

/// Read the system's current default-resolver upstreams from `scutil --dns`,
/// so a full-tunnel catch-all can forward non-`.ray` queries to them. Captured
/// once, before we install our own config, so we never capture ourselves.
/// `resolver #1` is macOS's primary (default) resolver; skip our magic IP.
pub(super) fn capture_system_upstreams() -> Vec<std::net::Ipv4Addr> {
    let out = std::process::Command::new("scutil")
        .arg("--dns")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let magic = crate::dns::MAGIC_DNS_V4;
    let mut ups = Vec::new();
    let mut in_first = false;
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("resolver #") {
            // Stop once we pass the first resolver block; take only #1.
            if in_first {
                break;
            }
            in_first = rest.trim() == "1";
            continue;
        }
        if in_first
            && t.starts_with("nameserver[")
            && let Some(ip) = t.split(':').nth(1).and_then(|s| s.trim().parse().ok())
            && ip != magic
            && !ups.contains(&ip)
        {
            ups.push(ip);
        }
    }
    ups
}

pub struct MacosDynamicStoreDns {
    captured: Vec<std::net::Ipv4Addr>,
    /// The utun the resolver is scoped to (see [`write_dns_config`]).
    tun_name: String,
    /// This node's mesh IPv6, published as the service's address
    /// (see [`write_service_config`]).
    mesh_v6: Ipv6Addr,
}

impl MacosDynamicStoreDns {
    pub fn new(tun_name: String, mesh_v6: Ipv6Addr) -> Self {
        Self {
            captured: capture_system_upstreams(),
            tun_name,
            mesh_v6,
        }
    }
}

#[async_trait]
impl DnsConfigurator for MacosDynamicStoreDns {
    async fn apply(&self) -> Result<()> {
        init_store()?;
        // The service first: the DNS key is only scoped to the interface if
        // configd already knows the service has one.
        if !self.tun_name.is_empty() {
            write_service_config(&self.tun_name, self.mesh_v6)?;
        }
        write_dns_config(&[super::SearchDomain::root()], &self.tun_name)?;
        tracing::info!(
            key = SC_DNS_KEY,
            interface = %self.tun_name,
            full_tunnel = crate::exit_node::full_tunnel_active(),
            "configured macOS DNS via SCDynamicStore"
        );
        Ok(())
    }

    fn captured_upstreams(&self) -> Vec<std::net::Ipv4Addr> {
        self.captured.clone()
    }

    async fn revert(&self) -> Result<()> {
        remove_dns_config();
        Ok(())
    }

    fn name(&self) -> &'static str {
        "macos-scdynamicstore"
    }
}
