//! The settings key namespace: one type per store, one variant per settable
//! value.
//!
//! The names live here, in the wire crate, so `ConfigSet`/`NetConfigSet` can
//! carry a key that is parsed once (at the CLI edge, or at deserialization)
//! and never re-validated. What each key *means* stays in the daemon crate
//! (`config::settings`), which owns the config types these keys write into.
//!
//! The split by store is what makes the daemon's `apply_*`/`render_*` matches
//! exhaustive: a new variant here fails to compile until every handler for its
//! scope grows an arm, so the key list and the handlers cannot drift apart.
//! A flat key enum would not do that, since each handler would still need a
//! catch-all arm to reject the other scopes' keys.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Define one store's key enum plus its name/help metadata.
///
/// Adding a setting means adding a line here and an arm in the daemon's
/// matching `apply_*`/`render_*`, and nothing else: no IPC variant, no daemon
/// handler, no new CLI plumbing.
macro_rules! setting_keys {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $variant:ident = $key:literal, $help:literal; )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                #[doc = $help]
                $variant,
            )*
        }

        impl $name {
            /// Every key in this scope, in the order `ray config get` prints them.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),* ];

            /// The wire name, which is also what the user types.
            pub const fn name(self) -> &'static str {
                match self { $( Self::$variant => $key, )* }
            }

            /// One-line description, for the `ray config` help text (see
            /// [`node_key_help`]).
            pub const fn help(self) -> &'static str {
                match self { $( Self::$variant => $help, )* }
            }

            /// Match a name in this scope only. Returns `None` for a name that
            /// belongs to another scope, so callers can tell "wrong scope" from
            /// "no such key" and say which.
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $( $key => Some(Self::$variant), )*
                    _ => None,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

setting_keys! {
    /// Keys backed by `settings.toml`.
    GlobalKey {
        Mdns = "mdns", "LAN peer discovery over mDNS (on|off)";
        Relay = "relay", "iroh relay servers (preset or URL, comma-separated)";
        DiscoveryDns = "discovery-dns", "pkarr discovery server (preset or URL)";
        DnsUpstreams = "dns-upstreams", "Magic DNS upstream forwarders (IP addresses, comma-separated)";
        AutoUpdate = "auto-update", "install new releases automatically (on|off)";
        OnDemand = "on-demand", "dial peers lazily on first packet (on|off)";
        Ssh = "ssh", "embedded mesh SSH server (on|off)";
        V4Bridge = "v4-bridge", "reach this host's IPv4-only listeners over the mesh (on|off)";
        DownloadDir = "download-dir", "directory accepted files land in (absolute path, empty to clear)";
        DownloadUser = "download-user", "uid that owns accepted files (numeric, empty to clear)";
    }
}

setting_keys! {
    /// Keys backed by `firewall.toml`.
    ///
    /// `firewall.default-out` (`default_outbound`) is deliberately absent:
    /// no command has ever set it, so a key for it would be new user-facing
    /// surface rather than a migration of an existing one.
    FirewallKey {
        Enabled = "firewall.enabled", "enforce the firewall at all (on|off)";
        Reject = "firewall.reject", "reply RST/unreachable instead of dropping (on|off)";
        DefaultIn = "firewall.default-in", "default action for inbound traffic (allow|deny)";
    }
}

setting_keys! {
    /// Keys backed by `networks/<name>.toml`. Every one needs a network name
    /// alongside it, which is why they ride `NetConfigSet`/`NetConfigGet` and
    /// are unrepresentable on `ConfigSet`.
    NetworkKey {
        AutoAcceptFirewall = "net.auto-accept-firewall", "install coordinator-suggested rules without review (on|off)";
        AutoAcceptFiles = "net.auto-accept-files", "auto-accept file offers from your own devices (on|off)";
        EphemeralTtl = "net.ephemeral-ttl", "coordinator: drop members offline longer than N seconds (>=3600, empty to disable)";
    }
}

/// A node-scoped key: one that needs no network argument, and so is what
/// `ConfigSet`/`ConfigUnset`/`ConfigGet` carry. The two stores behind it are
/// different files served by different handlers, which is why the scope stays
/// visible in the type rather than being flattened away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKey {
    Global(GlobalKey),
    Firewall(FirewallKey),
}

impl NodeKey {
    /// Every node-scoped key, globals first, in `ray config get` order.
    pub fn all() -> impl Iterator<Item = Self> {
        GlobalKey::ALL
            .iter()
            .copied()
            .map(NodeKey::Global)
            .chain(FirewallKey::ALL.iter().copied().map(NodeKey::Firewall))
    }

    pub const fn name(self) -> &'static str {
        match self {
            NodeKey::Global(k) => k.name(),
            NodeKey::Firewall(k) => k.name(),
        }
    }

    pub const fn help(self) -> &'static str {
        match self {
            NodeKey::Global(k) => k.help(),
            NodeKey::Firewall(k) => k.help(),
        }
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Every node key with its one-line description, for `ray config --help`.
/// Generated rather than written out, so a key cannot exist without being
/// documented where the user goes looking for it.
pub fn node_key_help() -> String {
    NodeKey::all()
        .map(|k| format!("  {:<24} {}", k.name(), k.help()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every key name in every scope, comma-joined: the tail of the "unknown config
/// key" error.
pub fn key_list() -> String {
    GlobalKey::ALL
        .iter()
        .map(|k| k.name())
        .chain(FirewallKey::ALL.iter().map(|k| k.name()))
        .chain(NetworkKey::ALL.iter().map(|k| k.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parsing a node key rejects a per-network one by name rather than lumping it
/// in with the unknown keys: `net.ephemeral-ttl` is real, it just needs a
/// network alongside it.
impl FromStr for NodeKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(k) = GlobalKey::parse(s) {
            return Ok(NodeKey::Global(k));
        }
        if let Some(k) = FirewallKey::parse(s) {
            return Ok(NodeKey::Firewall(k));
        }
        if NetworkKey::parse(s).is_some() {
            return Err(format!(
                "'{s}' is a per-network setting, not a global one; it needs a network"
            ));
        }
        Err(format!("unknown config key: {s} ({})", key_list()))
    }
}

/// The mirror of [`NodeKey::from_str`]: a node key names the command that does
/// serve it. The two stores share a namespace only by convention (the `net.`
/// prefix), so without this a global key written into a network file would
/// persist somewhere nothing ever reads back.
impl FromStr for NetworkKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(k) = NetworkKey::parse(s) {
            return Ok(k);
        }
        if FirewallKey::parse(s).is_some() {
            return Err(format!(
                "'{s}' is a firewall setting, not a per-network one \
                 (set it with `ray config set {s} <value>`)"
            ));
        }
        if GlobalKey::parse(s).is_some() {
            return Err(format!(
                "'{s}' is a global setting, not a per-network one \
                 (set it with `ray config set {s} <value>`)"
            ));
        }
        Err(format!(
            "unknown per-network key: {s} ({})",
            NetworkKey::ALL
                .iter()
                .map(|k| k.name())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Keys travel as their plain name, the same bytes the pre-enum `key: String`
/// sent. A frontend built against an older version of this crate keeps
/// interoperating for every key both versions know.
macro_rules! impl_key_serde {
    ($name:ident) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.name())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(D::Error::custom)
            }
        }
    };
}

impl_key_serde!(NodeKey);
impl_key_serde!(NetworkKey);

#[cfg(test)]
mod tests {
    use super::*;

    /// The `ray config --help` listing is generated, so a key added tomorrow is
    /// documented without anyone remembering to edit clap. This pins that it
    /// really covers all of them rather than a snapshot of today's set.
    #[test]
    fn the_help_listing_names_every_node_key() {
        let help = node_key_help();
        for k in NodeKey::all() {
            assert!(help.contains(k.name()), "{} missing from help", k.name());
            assert!(help.contains(k.help()), "{} has no description", k.name());
        }
    }

    #[test]
    fn every_key_round_trips_through_its_name() {
        for k in NodeKey::all() {
            assert_eq!(k.name().parse::<NodeKey>().unwrap(), k);
        }
        for &k in NetworkKey::ALL {
            assert_eq!(k.name().parse::<NetworkKey>().unwrap(), k);
        }
    }

    #[test]
    fn names_are_unique_across_every_scope() {
        let mut names: Vec<&str> = NodeKey::all()
            .map(|k| k.name())
            .chain(NetworkKey::ALL.iter().map(|k| k.name()))
            .collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "two keys share a name: {names:?}");
    }

    /// A wrong-scope key is a different error from an unknown one, and says
    /// which command serves it. These strings are what the user reads.
    #[test]
    fn a_wrong_scope_key_explains_itself_instead_of_reading_as_unknown() {
        let err = "net.ephemeral-ttl".parse::<NodeKey>().unwrap_err();
        assert_eq!(
            err,
            "'net.ephemeral-ttl' is a per-network setting, not a global one; it needs a network"
        );

        let err = "mdns".parse::<NetworkKey>().unwrap_err();
        assert_eq!(
            err,
            "'mdns' is a global setting, not a per-network one \
             (set it with `ray config set mdns <value>`)"
        );

        let err = "firewall.reject".parse::<NetworkKey>().unwrap_err();
        assert_eq!(
            err,
            "'firewall.reject' is a firewall setting, not a per-network one \
             (set it with `ray config set firewall.reject <value>`)"
        );
    }

    #[test]
    fn an_unknown_key_lists_the_valid_ones() {
        let err = "not-a-key".parse::<NodeKey>().unwrap_err();
        assert!(err.starts_with("unknown config key: not-a-key ("), "{err}");
        assert!(err.contains("mdns"), "{err}");
        assert!(err.contains("firewall.enabled"), "{err}");

        let err = "not-a-key".parse::<NetworkKey>().unwrap_err();
        assert!(
            err.starts_with("unknown per-network key: not-a-key ("),
            "{err}"
        );
        assert!(err.contains("net.ephemeral-ttl"), "{err}");
    }

    /// The wire form is the bare name, unchanged from when these fields were
    /// `String`, so a frontend built against either version interoperates.
    #[test]
    fn keys_encode_as_their_plain_name() {
        let encoded = rmp_serde::to_vec_named(&NodeKey::Global(GlobalKey::Mdns)).unwrap();
        assert_eq!(encoded, rmp_serde::to_vec_named("mdns").unwrap());

        let decoded: NodeKey = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded, NodeKey::Global(GlobalKey::Mdns));

        let net = rmp_serde::to_vec_named(&NetworkKey::EphemeralTtl).unwrap();
        assert_eq!(net, rmp_serde::to_vec_named("net.ephemeral-ttl").unwrap());
    }

    /// An unregistered key on the wire fails the decode rather than reaching a
    /// handler. The shipped CLI parses before sending, so this is the path a
    /// hand-rolled or newer client takes.
    #[test]
    fn an_unknown_key_on_the_wire_fails_to_decode() {
        let bytes = rmp_serde::to_vec_named("no-such-key").unwrap();
        let err = rmp_serde::from_slice::<NodeKey>(&bytes).unwrap_err();
        assert!(err.to_string().contains("unknown config key"), "{err}");
    }
}
