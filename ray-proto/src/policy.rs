//! Coordinator-suggested firewall rules, distributed in the signed `GroupBlob`.
//!
//! These types are the single authoritative shape for a trusted network's
//! suggested firewall: they ride in the blob, cross the IPC boundary
//! ([`crate::ipc::IpcMessage::FirewallSuggest`]), and are what a `ray apply`
//! spec deserializes into. They are deliberately keyed by **hostname**, so an
//! admin can author rules before any host has joined; each node materializes
//! the rules targeting its own hostname, resolving peer hostnames to identities
//! from the same blob's member list.
//!
//! A subject or peer key is a hostname, the wildcard `*`, or a **role**
//! (`role:sentry`, see [`ROLE_PREFIX`]). A role names a class of nodes rather
//! than one machine, so a rule written against it covers every member the
//! coordinator has assigned that role, including ones that join later.
//!
//! [`BTreeMap`] keys give a canonical (sorted) serialization, so the blob hash
//! is stable regardless of authoring order.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Suggested firewall rules for one subject host, keyed by peer hostname.
///
/// **Neither field may carry `skip_serializing_if`.** This type rides the signed
/// `GroupBlob`, which is array-encoded (`canonical_group_bytes`), so a skipped
/// `allows` leaves no hole: `denies` slides into slot 0 and every member reads
/// the blacklist as a whitelist. Both fields are `BTreeMap<String, String>`, so
/// nothing errors on the way through, and a coordinator's `deny` installs as an
/// `allow` network-wide (`firewall::materialize_suggestions`). Kept empty rather
/// than absent costs one byte per side.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSuggestions {
    /// peer hostname -> proto:ports spec (e.g. `"tcp:22"`, `"icmp"`, `"tcp:*"`):
    /// the subject accepts inbound from that peer. Suggestions are additive —
    /// each entry materializes one allow rule and nothing else; the node's own
    /// inbound default (Deny by default) already drops anything not listed, so
    /// no catch-all deny is synthesized.
    #[serde(default)]
    pub allows: BTreeMap<String, String>,
    /// peer hostname -> ports the subject explicitly denies inbound from. Use
    /// this for a blacklist (everything allowed except these peers).
    #[serde(default)]
    pub denies: BTreeMap<String, String>,
}

/// Subject hostname -> its suggested rules. Sorted keys ⇒ canonical bytes.
pub type SuggestedFirewall = BTreeMap<String, HostSuggestions>;

/// Marks a subject or peer key as naming a **role** instead of a hostname.
///
/// Roles are assigned by the coordinator from the redeemed join key, never
/// claimed by the joining node, so a rule keyed on one cannot be captured by a
/// peer picking a convenient name for itself.
pub const ROLE_PREFIX: &str = "role:";

/// The role a subject/peer key names, or `None` if it names a hostname or `*`.
///
/// The single parser for the prefix, shared by the authoring side (a `ray apply`
/// spec passes a role through unexpanded, exactly like `*`) and the node side
/// (`materialize_suggestions` resolves it against the blob's member list). A
/// bare `role:` with nothing after it is not a role: it would match every member
/// carrying the empty role, which no member can carry.
pub fn role_of(key: &str) -> Option<&str> {
    match key.strip_prefix(ROLE_PREFIX) {
        Some("") | None => None,
        Some(role) => Some(role),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_keys_are_recognised() {
        assert_eq!(role_of("role:sentry"), Some("sentry"));
        assert_eq!(role_of("role:non-validating"), Some("non-validating"));
    }

    #[test]
    fn hostnames_and_wildcards_are_not_roles() {
        assert_eq!(role_of("sentry"), None);
        assert_eq!(role_of("*"), None);
        assert_eq!(role_of("sentry-01.hyperliquid.ray"), None);
    }

    /// A bare prefix would otherwise resolve to the empty role and match on a
    /// value no member can hold; treat it as a plain (odd) hostname instead.
    #[test]
    fn a_bare_prefix_is_not_a_role() {
        assert_eq!(role_of("role:"), None);
    }
}
