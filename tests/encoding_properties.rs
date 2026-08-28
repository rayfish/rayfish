//! Property tests for the encodings users paste and peers send: invite codes,
//! pairing tickets, control frames, the signed group blob, and the firewall
//! port-spec grammar.
//!
//! Two shapes of property here. Round-trips (decode(encode(x)) == x) pin the
//! encodings so a serialization change can't silently break peers on the old
//! build. Never-panic properties cover the decoders, which run on strings a
//! user pasted or bytes a peer sent, neither of which is trustworthy.

use proptest::prelude::*;
use rayfish::control::{
    ControlFrame, ControlMsg, decode_pairing_ticket, encode_msg, encode_pairing_ticket,
};
use rayfish::firewall::{PortRange, Protocol, parse_port_list, parse_port_range, parse_spec_token};
use rayfish::invite::{decode_invite_code, encode_invite_code};
use rayfish::membership::decode_group_blob;

use iroh::EndpointId;

fn id_from_seed(seed: u32) -> EndpointId {
    let mut key_bytes = [0u8; 32];
    key_bytes[..4].copy_from_slice(&seed.to_le_bytes());
    iroh::SecretKey::from(key_bytes).public()
}

// ---------------------------------------------------------------------------
// Invite codes and pairing tickets
// ---------------------------------------------------------------------------

proptest! {
    /// An invite code carries the network key, the coordinator, and the
    /// secret. All three must survive the base58 round-trip: a corrupted
    /// coordinator sends the joiner to the wrong peer, a corrupted secret
    /// fails admission.
    #[test]
    fn invite_code_round_trips(
        net_seed in any::<u32>(),
        coord_seed in any::<u32>(),
        secret in prop::collection::vec(any::<u8>(), 16..=16),
    ) {
        let net = id_from_seed(net_seed);
        let coord = id_from_seed(coord_seed);

        let code = encode_invite_code(&net, &coord, &secret);
        let (got_net, got_coord, got_secret) = decode_invite_code(&code)
            .expect("a freshly encoded invite must decode");

        prop_assert_eq!(got_net, net);
        prop_assert_eq!(got_coord, coord);
        prop_assert_eq!(got_secret, secret);
    }

    /// Invite codes get pasted out of chat clients that mangle text. Decoding
    /// arbitrary input must error, never panic.
    #[test]
    fn invite_decode_never_panics(s in ".{0,200}") {
        let _ = decode_invite_code(&s);
    }

    /// A truncated code is rejected, and never decodes to the invite it was
    /// cut from. This is what the trailing checksum buys: base58 has no error
    /// detection of its own, so without it dropping a character divides the
    /// encoded number by 58 and can still land on a payload of the right
    /// length, which decodes into a well-formed invite for a network that
    /// doesn't exist.
    ///
    /// The one gap is structural, not a defect in the checksum: the decoder
    /// still accepts the older unchecksummed format, which is distinguished
    /// only by being 4 bytes shorter. A truncation that happens to shrink the
    /// payload by exactly those 4 bytes therefore lands on the legacy shape
    /// and takes the unchecked path. It still can't reproduce the original
    /// invite, which is what this asserts for that case. The gap closes when
    /// legacy support is dropped.
    #[test]
    fn truncated_invite_code_rejected(
        net_seed in any::<u32>(),
        coord_seed in any::<u32>(),
        secret in prop::collection::vec(any::<u8>(), 16..=16),
        cut in 1usize..40,
    ) {
        let net = id_from_seed(net_seed);
        let coord = id_from_seed(coord_seed);
        let code = encode_invite_code(&net, &coord, &secret);
        let truncated = &code[..code.len().saturating_sub(cut)];

        if let Ok((got_net, got_coord, got_secret)) = decode_invite_code(truncated) {
            prop_assert!(
                (got_net, got_coord, got_secret) != (net, coord, secret.clone()),
                "a truncated code decoded back to the original invite",
            );
        }
    }

    /// Corrupting any single character is caught. A checksum that only
    /// detected truncation would miss the more common paste error.
    #[test]
    fn corrupted_invite_code_rejected(
        net_seed in any::<u32>(),
        coord_seed in any::<u32>(),
        secret in prop::collection::vec(any::<u8>(), 16..=16),
        pos in any::<prop::sample::Index>(),
        replacement in "[1-9A-HJ-NP-Za-km-z]",
    ) {
        let net = id_from_seed(net_seed);
        let coord = id_from_seed(coord_seed);
        let code = encode_invite_code(&net, &coord, &secret);

        let i = pos.index(code.len());
        let mut corrupted: Vec<char> = code.chars().collect();
        prop_assume!(corrupted[i] != replacement.chars().next().unwrap());
        corrupted[i] = replacement.chars().next().unwrap();
        let corrupted: String = corrupted.into_iter().collect();

        match decode_invite_code(&corrupted) {
            Err(_) => {}
            Ok((got_net, got_coord, got_secret)) => prop_assert!(
                (got_net, got_coord, got_secret) != (net, coord, secret.clone()),
                "a corrupted code decoded back to the original invite",
            ),
        }
    }

    /// A pairing ticket carries the primary device's endpoint and the shared
    /// secret that authenticates the pairing.
    #[test]
    fn pairing_ticket_round_trips(seed in any::<u32>(), secret in any::<[u8; 32]>()) {
        let endpoint = id_from_seed(seed);
        let ticket = encode_pairing_ticket(endpoint, &secret);
        let (got_endpoint, got_secret) = decode_pairing_ticket(&ticket)
            .expect("a freshly encoded ticket must decode");
        prop_assert_eq!(got_endpoint, endpoint);
        prop_assert_eq!(got_secret, secret);
    }

    /// Tickets are typed in by hand, so surrounding whitespace is expected and
    /// must not change the result.
    #[test]
    fn pairing_ticket_tolerates_whitespace(
        seed in any::<u32>(),
        secret in any::<[u8; 32]>(),
        pad in "[ \t\n]{0,4}",
    ) {
        let endpoint = id_from_seed(seed);
        let ticket = encode_pairing_ticket(endpoint, &secret);
        let padded = format!("{pad}{ticket}{pad}");
        let (got_endpoint, got_secret) = decode_pairing_ticket(&padded)
            .expect("padded ticket must decode");
        prop_assert_eq!(got_endpoint, endpoint);
        prop_assert_eq!(got_secret, secret);
    }

    #[test]
    fn pairing_ticket_decode_never_panics(s in ".{0,200}") {
        let _ = decode_pairing_ticket(&s);
    }
}

// ---------------------------------------------------------------------------
// Control frames
// ---------------------------------------------------------------------------

/// Control messages spanning the payload shapes on the wire: payload-free
/// triggers, opaque byte blobs, strings, and optional fields.
fn control_msg_strategy() -> impl Strategy<Value = ControlMsg> {
    prop_oneof![
        Just(ControlMsg::MemberSync),
        Just(ControlMsg::JoinPending),
        ".{0,40}".prop_map(|reason| ControlMsg::JoinDenied { reason }),
        prop::collection::vec(any::<u8>(), 0..64)
            .prop_map(|packet| ControlMsg::SignedRecord { packet }),
        (
            prop::option::of(prop::collection::vec(any::<u8>(), 0..32)),
            prop::option::of("[a-z][a-z0-9]{0,6}"),
        )
            .prop_map(|(invite_secret, hostname)| ControlMsg::JoinRequest {
                invite_secret,
                hostname,
                device_cert: None,
                roles: Default::default(),
            }),
    ]
}

proptest! {
    /// A control frame's length prefix must describe its body exactly. A
    /// mismatch desynchronizes the stream: the reader takes the next frame's
    /// bytes as this one's payload.
    #[test]
    fn control_frame_length_prefix_matches_body(
        net in prop::option::of(any::<u32>()),
        msg in control_msg_strategy(),
    ) {
        let net = net.map(id_from_seed);
        let encoded = encode_msg(net, &msg);
        prop_assert!(encoded.len() >= 4);
        let declared = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
        prop_assert_eq!(declared, encoded.len() - 4);
    }

    /// The frame body decodes back to the network and message that went in,
    /// including the `None` network that marks a connection-level message.
    #[test]
    fn control_frame_round_trips(
        net in prop::option::of(any::<u32>()),
        msg in control_msg_strategy(),
    ) {
        let net = net.map(id_from_seed);
        let encoded = encode_msg(net, &msg);
        let frame: ControlFrame = rmp_serde::from_slice(&encoded[4..])
            .expect("a freshly encoded frame must decode");
        prop_assert_eq!(frame.net, net);
        prop_assert_eq!(frame.msg, msg);
    }
}

// ---------------------------------------------------------------------------
// Group blob
// ---------------------------------------------------------------------------

proptest! {
    /// The blob is fetched from the DHT, where anyone can publish. Decoding
    /// must reject junk rather than panic on it.
    #[test]
    fn group_blob_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_group_blob(&bytes);
    }
}

// ---------------------------------------------------------------------------
// Port specs
// ---------------------------------------------------------------------------

proptest! {
    /// Anything the user types at `--port` must produce a range or an error.
    #[test]
    fn port_range_parse_never_panics(s in ".{0,40}") {
        let _ = parse_port_range(&s);
    }

    #[test]
    fn port_list_parse_never_panics(s in ".{0,60}") {
        let _ = parse_port_list(&s);
    }

    #[test]
    fn spec_token_parse_never_panics(s in ".{0,40}") {
        let _ = parse_spec_token(&s);
    }

    /// A parsed range is well-formed: start never exceeds end, so
    /// `PortRange::contains` can't be vacuously false for every port.
    #[test]
    fn parsed_port_ranges_are_ordered(s in ".{0,40}") {
        if let Ok(range) = parse_port_range(&s) {
            prop_assert!(range.start <= range.end);
        }
    }

    /// A single port parses to the range holding exactly it.
    #[test]
    fn single_port_round_trips(port in any::<u16>()) {
        let range = parse_port_range(&port.to_string()).expect("a bare port must parse");
        prop_assert_eq!(&range, &PortRange { start: port, end: port });
        prop_assert!(range.contains(port));
    }

    /// A `start-end` range parses to exactly those bounds and contains every
    /// port between them.
    #[test]
    fn port_range_round_trips(a in any::<u16>(), b in any::<u16>(), probe in any::<u16>()) {
        let (start, end) = (a.min(b), a.max(b));
        let range = parse_port_range(&format!("{start}-{end}")).expect("a valid range must parse");
        prop_assert_eq!(&range, &PortRange { start, end });
        prop_assert_eq!(range.contains(probe), probe >= start && probe <= end);
    }

    /// An inverted range is a user error, not a silently-empty rule that
    /// matches nothing.
    #[test]
    fn inverted_port_range_rejected(a in any::<u16>(), b in any::<u16>()) {
        prop_assume!(a != b);
        let (lo, hi) = (a.min(b), a.max(b));
        let inverted = format!("{hi}-{lo}");
        prop_assert!(parse_port_range(&inverted).is_err());
    }

    /// A comma-separated list yields one range per non-empty item, in order,
    /// each matching what that item parses to on its own.
    #[test]
    fn port_list_matches_its_items(ports in prop::collection::vec(any::<u16>(), 1..6)) {
        let joined = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
        let ranges = parse_port_list(&joined).expect("a list of valid ports must parse");
        prop_assert_eq!(ranges.len(), ports.len());
        for (range, port) in ranges.iter().zip(&ports) {
            prop_assert_eq!(range, &PortRange { start: *port, end: *port });
        }
    }

    /// Empty items (a trailing or doubled comma) are skipped, not treated as
    /// port 0.
    #[test]
    fn port_list_skips_empty_items(ports in prop::collection::vec(any::<u16>(), 1..5)) {
        let joined = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",,");
        let ranges = parse_port_list(&format!("{joined},")).expect("must parse");
        prop_assert_eq!(ranges.len(), ports.len());
    }

    /// `proto:port` tokens keep their protocol and port. This is the grammar
    /// a coordinator's suggested firewall arrives in, so a misparse installs
    /// the wrong rule on every member.
    #[test]
    fn spec_token_keeps_protocol_and_port(
        tcp in any::<bool>(),
        port in any::<u16>(),
    ) {
        let proto = if tcp { "tcp" } else { "udp" };
        let (got_proto, got_port) = parse_spec_token(&format!("{proto}:{port}"))
            .expect("a well-formed token must parse");
        prop_assert_eq!(got_proto, if tcp { Protocol::Tcp } else { Protocol::Udp });
        prop_assert_eq!(got_port, Some(PortRange { start: port, end: port }));
    }

    /// A bare port with no protocol is rejected rather than defaulting to TCP:
    /// an implicit protocol would silently open the wrong one.
    #[test]
    fn bare_port_token_rejected(port in any::<u16>()) {
        prop_assert!(parse_spec_token(&port.to_string()).is_err());
    }

    /// The wildcard means every port, whatever spelling it arrives in.
    #[test]
    fn wildcard_covers_every_port(probe in any::<u16>()) {
        let range = parse_port_range("*").expect("wildcard must parse");
        prop_assert!(range.contains(probe));

        let (_, tcp_all) = parse_spec_token("tcp:*").expect("tcp:* must parse");
        prop_assert!(tcp_all.expect("tcp:* carries a range").contains(probe));

        let (_, bare_tcp) = parse_spec_token("tcp").expect("bare tcp must parse");
        prop_assert!(bare_tcp.expect("bare tcp carries a range").contains(probe));
    }

    /// Port-less protocols carry no range, so a rule built from them can't
    /// accidentally be port-scoped.
    #[test]
    fn portless_protocols_carry_no_range(spec in prop_oneof![
        Just("icmp"), Just("any"), Just("icmp:*"), Just("any:*"),
    ]) {
        let (_, port) = parse_spec_token(spec).expect("port-less token must parse");
        prop_assert_eq!(port, None);
    }
}
