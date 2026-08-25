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
