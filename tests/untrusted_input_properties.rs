//! Property tests for the decoders that read bytes from someone else: peers on
//! the mesh, files, pair, connect and management ALPNs, any local user on the
//! IPC socket, and anyone publishing to the DHT.
//!
//! Random bytes rarely get past a msgpack decoder's first byte, so most
//! properties here build structured msgpack instead: a real variant name with
//! a random payload tree. That reaches the field decoders (endpoint ids,
//! hostnames, tickets, hashes) where a hand-written `Deserialize` could panic.

use std::sync::LazyLock;

use iroh::{EndpointId, SecretKey};
use iroh_dns::pkarr::SignedPacket;
use proptest::prelude::*;
use proptest::sample::Index;
use rayfish::control::{ConnectMsg, ControlFrame, DeviceCert, FileReply, PairMsg};
use rayfish::dht::{
    decode_network_record, encode_network_record, mesh_version_from_record, verify_network_record,
};
use rayfish::ipc::IpcMessage;
use rayfish::management::ManagementMsg;
use rayfish::membership::decode_group_blob;
use rayfish::term::style::{printable, printable_lines};
use serde::de::DeserializeOwned;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};

fn id_from_seed(seed: [u8; 32]) -> EndpointId {
    SecretKey::from(seed).public()
}

// ---------------------------------------------------------------------------
// Structured msgpack
// ---------------------------------------------------------------------------

/// Any msgpack value, encoded as itself.
#[derive(Clone, Debug)]
enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(String),
    Bin(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Nil => s.serialize_unit(),
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Int(i) => s.serialize_i64(*i),
            Value::Uint(u) => s.serialize_u64(*u),
            Value::Float(f) => s.serialize_f64(*f),
            Value::Str(text) => s.serialize_str(text),
            Value::Bin(bytes) => s.serialize_bytes(bytes),
            Value::Array(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Value::Map(entries) => {
                let mut map = s.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

fn encode(value: &Value) -> Vec<u8> {
    rmp_serde::to_vec(value).expect("a msgpack value always encodes")
}

/// Leaves biased toward what the wire types hold: 32- and 64-byte keys and
/// signatures, endpoint ids as text, and integers at their type limits.
fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Nil),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::Int),
        prop_oneof![
            0u64..300,
            Just(u64::from(u16::MAX) + 1),
            Just(u64::from(u32::MAX) + 1),
            Just(u64::MAX),
        ]
        .prop_map(Value::Uint),
        any::<f64>().prop_map(Value::Float),
        ".{0,24}".prop_map(Value::Str),
        any::<[u8; 32]>().prop_map(|seed| Value::Str(id_from_seed(seed).to_string())),
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..8),
            prop::collection::vec(any::<u8>(), 32),
            prop::collection::vec(any::<u8>(), 64),
        ]
        .prop_map(Value::Bin),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec((inner.clone(), inner), 0..4).prop_map(Value::Map),
        ]
    })
}

/// The variant names of an externally tagged enum, read from the error serde
/// gives for a name it does not know. Kept in step with the enum for free.
fn variant_names<T: DeserializeOwned>() -> Vec<String> {
    let probe = encode(&Value::Str("\u{1}not a variant".into()));
    let Err(err) = rmp_serde::from_slice::<T>(&probe) else {
        panic!("a nonsense variant name decoded");
    };
    let err = err.to_string();
    let (_, listed) = err
        .split_once("expected")
        .unwrap_or_else(|| panic!("serde lists the variants it expected: {err}"));
    let names: Vec<String> = listed
        .split('`')
        .skip(1)
        .step_by(2)
        .map(String::from)
        .collect();
    assert!(!names.is_empty(), "no variant names in {err}");
    names
}

/// A value of an externally tagged enum: the bare name of a unit variant, or
/// a one-entry map from the name to its payload.
fn tagged(names: Vec<String>) -> impl Strategy<Value = Value> {
    (prop::sample::select(names), value(), any::<bool>()).prop_map(|(name, payload, unit)| {
        if unit {
            Value::Str(name)
        } else {
            Value::Map(vec![(Value::Str(name), payload)])
        }
    })
}

/// Up to four bytes overwritten, then maybe cut short: what a corrupted or
/// truncated frame looks like.
#[derive(Clone, Debug)]
struct Damage {
    writes: Vec<(Index, u8)>,
    cut: Option<Index>,
}

fn damage() -> impl Strategy<Value = Damage> {
    (
        prop::collection::vec((any::<Index>(), any::<u8>()), 0..4),
        prop::option::of(any::<Index>()),
    )
        .prop_map(|(writes, cut)| Damage { writes, cut })
}

fn damaged(mut bytes: Vec<u8>, damage: &Damage) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }
    for (at, byte) in &damage.writes {
        let i = at.index(bytes.len());
        bytes[i] = *byte;
    }
    if let Some(cut) = &damage.cut {
        bytes.truncate(cut.index(bytes.len()));
    }
    bytes
}

static IPC_VARIANTS: LazyLock<Vec<String>> = LazyLock::new(variant_names::<IpcMessage>);
static CONTROL_VARIANTS: LazyLock<Vec<String>> =
    LazyLock::new(variant_names::<rayfish::control::ControlMsg>);

fn decodes_or_errs<T: DeserializeOwned>(bytes: &[u8]) {
    let _ = rmp_serde::from_slice::<T>(bytes);
}

#[test]
fn variant_names_are_read_from_the_enums() {
    for (names, expected) in [
        (&*IPC_VARIANTS, "Status"),
        (&*CONTROL_VARIANTS, "JoinRequest"),
    ] {
        assert!(names.iter().any(|n| n == expected), "{names:?}");
    }
    assert!(variant_names::<PairMsg>().len() > 1);
}

// ---------------------------------------------------------------------------
// Messages from peers and local users
// ---------------------------------------------------------------------------

/// A mesh frame is `[net, msg]`: the network key, or nil for a
/// connection-level message, then the control message.
fn control_frame() -> impl Strategy<Value = Value> {
    let net = prop_oneof![
        Just(Value::Nil),
        any::<[u8; 32]>().prop_map(|seed| Value::Bin(id_from_seed(seed).as_bytes().to_vec())),
        value(),
    ];
    (net, tagged(CONTROL_VARIANTS.clone())).prop_map(|(net, msg)| Value::Array(vec![net, msg]))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Any local user can write to the IPC socket, and the daemon decodes the
    /// request before it checks who sent it.
    #[test]
    fn ipc_request_decode_never_panics(
        msg in tagged(IPC_VARIANTS.clone()),
        hurt in damage(),
    ) {
        let bytes = encode(&msg);
        decodes_or_errs::<IpcMessage>(&bytes);
        decodes_or_errs::<IpcMessage>(&damaged(bytes, &hurt));
    }

    /// Every mesh member sends control frames, joined or not.
    #[test]
    fn control_frame_decode_never_panics(frame in control_frame(), hurt in damage()) {
        let bytes = encode(&frame);
        decodes_or_errs::<ControlFrame>(&bytes);
        decodes_or_errs::<ControlFrame>(&damaged(bytes, &hurt));
    }

    /// Pair, file and unpair streams carry `PairMsg`; `ray connect` and
    /// private invitations carry `ConnectMsg`; a controller and its machines
    /// exchange `ManagementMsg`.
    #[test]
    fn peer_message_decode_never_panics(
        pair in tagged(variant_names::<PairMsg>()),
        connect in tagged(variant_names::<ConnectMsg>()),
        management in tagged(variant_names::<ManagementMsg>()),
        reply in tagged(variant_names::<FileReply>()),
        hurt in damage(),
    ) {
        for (msg, decode) in [
            (pair, decodes_or_errs::<PairMsg> as fn(&[u8])),
            (connect, decodes_or_errs::<ConnectMsg>),
            (management, decodes_or_errs::<ManagementMsg>),
            (reply, decodes_or_errs::<FileReply>),
        ] {
            let bytes = encode(&msg);
            decode(&bytes);
            decode(&damaged(bytes, &hurt));
        }
    }

    /// A device certificate arrives inside a join request, from a device the
    /// coordinator has not admitted yet.
    #[test]
    fn device_cert_decode_never_panics(
        fields in prop::collection::vec(value(), 0..8),
        hurt in damage(),
    ) {
        let bytes = encode(&Value::Array(fields));
        decodes_or_errs::<DeviceCert>(&bytes);
        decodes_or_errs::<DeviceCert>(&damaged(bytes, &hurt));
    }

    /// The group blob is fetched by hash from whichever peer serves it.
    #[test]
    fn structured_group_blob_decode_never_panics(
        fields in prop::collection::vec(value(), 0..6),
        hurt in damage(),
    ) {
        let bytes = encode(&Value::Array(fields));
        let _ = decode_group_blob(&bytes);
        let _ = decode_group_blob(&damaged(bytes, &hurt));
    }

    /// Random bytes for every decoder at once, for the paths structure skips.
    #[test]
    fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        decodes_or_errs::<IpcMessage>(&bytes);
        decodes_or_errs::<ControlFrame>(&bytes);
        decodes_or_errs::<PairMsg>(&bytes);
        decodes_or_errs::<ConnectMsg>(&bytes);
        decodes_or_errs::<ManagementMsg>(&bytes);
        decodes_or_errs::<DeviceCert>(&bytes);
    }
}

// ---------------------------------------------------------------------------
// Signed network records
// ---------------------------------------------------------------------------

/// TXT strings a record may hold: the version, well-formed and malformed
/// hash and peer entries, a mesh version, and junk.
fn txt_entry() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("v1".to_string()),
        "[a-z0-9,]{0,20}",
        any::<[u8; 32]>().prop_map(|b| format!("h,{}", blake3::hash(&b))),
        "[0-9a-f]{0,70}".prop_map(|s| format!("h,{s}")),
        any::<[u8; 32]>().prop_map(|seed| format!("p,{}", id_from_seed(seed))),
        "[a-z0-9]{0,60}".prop_map(|s| format!("p,{s}")),
        ".{0,12}".prop_map(|s| format!("m,{s}")),
    ]
}

/// What `decode_network_record` must return for these TXT strings: the last
/// hash and every peer, or an error when the version is not first, an entry
/// is malformed, or there is no hash.
fn expected_record(entries: &[String]) -> Option<(blake3::Hash, Vec<EndpointId>)> {
    let (version, rest) = entries.split_first()?;
    if version != "v1" {
        return None;
    }
    let mut hash = None;
    let mut peers = Vec::new();
    for entry in rest {
        if let Some(h) = entry.strip_prefix("h,") {
            hash = Some(h.parse().ok()?);
        } else if let Some(p) = entry.strip_prefix("p,") {
            peers.push(p.parse().ok()?);
        }
    }
    Some((hash?, peers))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Records come off the DHT and from peers, signed by whoever made them.
    #[test]
    fn signed_record_bytes_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..1100),
        key in any::<[u8; 32]>(),
    ) {
        let _ = verify_network_record(&bytes, id_from_seed(key));
    }

    /// The decoder takes exactly what the record says, in order, and refuses
    /// anything else: a peer list it half-read would seed joins wrongly.
    #[test]
    fn record_decode_matches_its_entries(
        key in any::<[u8; 32]>(),
        entries in prop::collection::vec(txt_entry(), 0..8),
    ) {
        let key = SecretKey::from(key);
        let packet = SignedPacket::from_txt_strings(&key, "_rayfish", entries.clone(), 300);
        prop_assume!(packet.is_ok());
        let packet = packet.unwrap();
        let _ = mesh_version_from_record(&packet);
        let decoded = decode_network_record(&packet).ok();
        prop_assert_eq!(decoded, expected_record(&entries));
    }

    /// Any one flipped bit (key, signature, timestamp or body) makes the
    /// record fail verification. A record that still verified would let
    /// anyone on the path edit the roster pointer or the floor timestamp.
    #[test]
    fn a_flipped_bit_fails_verification(
        key in any::<[u8; 32]>(),
        peers in prop::collection::vec(any::<[u8; 32]>(), 0..4),
        at in any::<Index>(),
        bit in 0u8..8,
    ) {
        let key = SecretKey::from(key);
        let peers: Vec<EndpointId> = peers.into_iter().map(id_from_seed).collect();
        let packet = encode_network_record(&key, &blake3::hash(b"roster"), &peers)
            .expect("a small record encodes");
        let mut bytes = packet.as_bytes().to_vec();
        let i = at.index(bytes.len());
        bytes[i] ^= 1 << bit;
        prop_assert!(verify_network_record(&bytes, key.public()).is_err(), "byte {i}");
    }
}

// ---------------------------------------------------------------------------
// Peer-supplied text in the terminal
// ---------------------------------------------------------------------------

fn is_unsafe_on_a_terminal(c: char, keep_newlines: bool) -> bool {
    (c.is_control() && !(keep_newlines && c == '\n'))
        || matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// Text heavy in the characters that matter: C0, DEL, C1, bidi controls.
fn hostile_text() -> impl Strategy<Value = String> {
    let c = prop_oneof![
        any::<char>(),
        (0u32..0x20).prop_map(|u| char::from_u32(u).expect("C0 is valid")),
        Just('\u{7f}'),
        (0x80u32..0xa0).prop_map(|u| char::from_u32(u).expect("C1 is valid")),
        prop::sample::select(vec!['\u{202e}', '\u{2066}', '\u{200f}', '\u{061c}', '\n']),
    ];
    prop::collection::vec(c, 0..40).prop_map(|cs| cs.into_iter().collect())
}

proptest! {
    /// A peer's hostname or file name printed by `ray` cannot carry a
    /// character that moves the cursor, rewrites the screen or reorders the
    /// line, and text without one is printed as it is.
    #[test]
    fn printable_leaves_no_terminal_controls(s in hostile_text()) {
        for (out, keep_newlines) in [(printable(&s), false), (printable_lines(&s), true)] {
            prop_assert!(
                !out.chars().any(|c| is_unsafe_on_a_terminal(c, keep_newlines)),
                "{:?} -> {:?}", s, out
            );
            if !s.chars().any(|c| is_unsafe_on_a_terminal(c, keep_newlines)) {
                prop_assert_eq!(out.as_ref(), s.as_str());
            }
        }
        prop_assert_eq!(
            printable_lines(&s).matches('\n').count(),
            s.matches('\n').count()
        );
    }
}
