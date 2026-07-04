//! Length-prefixed msgpack control protocol over QUIC bidirectional streams.
//!
//! Each message is encoded as a 4-byte big-endian length prefix followed by a msgpack body.
//! Control messages manage membership (join, approve, sync) and mesh topology (hello, reconnect).

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::membership::{ApprovedEntry, Member};

/// Certificate proving a device belongs to a user identity.
///
/// The user's private key signs the device's public key. Any peer can verify
/// the binding using only the user's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCert {
    pub user_identity: EndpointId,
    pub device_key: EndpointId,
    pub signature: Signature,
}

impl DeviceCert {
    pub fn create(user_secret: &SecretKey, device_pubkey: &EndpointId) -> Self {
        let signature = user_secret.sign(device_pubkey.as_bytes());
        Self {
            user_identity: user_secret.public(),
            device_key: *device_pubkey,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        self.user_identity
            .verify(self.device_key.as_bytes(), &self.signature)
            .is_ok()
    }
}

/// One of the primary's networks, shared during pairing so the new device can
/// auto-join it. `network_key` is the network public key (bare room id) as a
/// hex string; no secret is shared because the device cert is the credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairNetwork {
    pub name: String,
    pub network_key: String,
}

/// Messages for the device pairing protocol (ALPN `rayfish/pair/1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PairMsg {
    Request {
        secret: [u8; 32],
        device_pubkey: EndpointId,
    },
    Response {
        cert: DeviceCert,
        #[serde(default)]
        networks: Vec<PairNetwork>,
    },
}

/// Messages for the `ray connect` friend-request handshake (ALPN
/// `rayfish/connect/1`). The initiator (A) dials the recipient's (B) contact
/// key, sends `Request`, and polls until `Approved`. Approval is recipient-only:
/// only B acts, A just waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectMsg {
    /// A → B: request a direct connection. `from_endpoint` is A's transport id
    /// (the key B pre-approves into the minted network); `from_contact_id` is
    /// A's own contact key (for display/dedupe on B).
    Request {
        from_contact_id: EndpointId,
        from_endpoint: EndpointId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
    },
    /// B → A: queued, not yet approved. A retries with backoff.
    Pending,
    /// B → A: approved. Carries the minted 2-peer network's room id and B as the
    /// pinned coordinator, so A joins it like an invite-pinned join.
    Approved {
        room_id: EndpointId,
        coordinator: EndpointId,
    },
    /// B → A: request rejected.
    Denied { reason: String },
}

/// Control messages exchanged between peers over QUIC bidirectional streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// Sent by a joining peer as the first message on an initial (non-reconnect)
    /// join. Carries an optional invite secret (for invite-gated admission) and
    /// the joiner's desired hostname/device cert. The coordinator branches on the
    /// secret and the network's access mode to admit, gate, or deny.
    JoinRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invite_secret: Option<Vec<u8>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_cert: Option<DeviceCert>,
    },
    /// Coordinator response telling the joiner it has been queued for live
    /// approval (closed network, no invite). The joiner retries until accepted.
    JoinPending,
    JoinApproved {
        your_ip: Ipv4Addr,
        members: Vec<Member>,
    },
    JoinDenied {
        reason: String,
    },
    /// Notify connected members that the roster/blob changed. Payload-free: it
    /// is a *trigger only*. Receivers reconverge from the network-key-signed
    /// pkarr record, never from any peer-supplied membership data.
    MemberSync,
    MeshHello {
        identity: EndpointId,
        ip: Ipv4Addr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_cert: Option<DeviceCert>,
    },
    MemberApproved {
        identity: EndpointId,
        ip: Ipv4Addr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_cert: Option<DeviceCert>,
    },
    Welcome {
        members: Vec<Member>,
        approved: Vec<ApprovedEntry>,
    },
    /// Notify connected members that the signed group blob changed. Payload-free:
    /// a *trigger only*. Receivers reconverge from the network-key-signed pkarr
    /// record, never from any peer-supplied hash.
    BlobUpdated,
    /// Coordinator grants the per-network secret key to another member, making it
    /// a co-coordinator (can publish the signed blob / suggest firewall rules).
    /// Sent over the network's authenticated mesh ALPN, so only the targeted peer
    /// receives it. The recipient stores the key and spawns a publisher.
    AdminGrant {
        network_pubkey: EndpointId,
        /// 32-byte per-network secret key (`SecretKey::to_bytes`).
        secret_key: [u8; 32],
    },
    FileOffer {
        from: EndpointId,
        filename: String,
        size: u64,
        mime_type: String,
        blob_hash: blake3::Hash,
    },
    /// Coordinator → coordinators: share a minted single-use invite's hash so any
    /// coordinator can redeem it. Carries the hash only, never the secret.
    InviteShare {
        id: String,
        secret_hash: Vec<u8>,
        expires: u64,
    },
    /// Coordinator → coordinators: a shared single-use invite was redeemed; burn it.
    InviteUsed {
        secret_hash: Vec<u8>,
    },
    /// Active liveness probe for `ray ping`. The receiver echoes back a `Pong`
    /// carrying the same nonce over a fresh stream (the control readers drop the
    /// stream's send half, so the reply cannot ride the request stream). The
    /// pinging side correlates by nonce to measure round-trip time.
    Ping {
        nonce: u64,
    },
    /// Echo reply to a `Ping`, carrying the originating nonce.
    Pong {
        nonce: u64,
    },
}

pub fn encode_msg(msg: &ControlMsg) -> Vec<u8> {
    let body = rmp_serde::to_vec_named(msg).expect("serialize control message");
    let len = (body.len() as u32).to_be_bytes();
    [len.as_slice(), &body].concat()
}

#[cfg(test)]
fn decode_msg(data: &[u8]) -> Result<ControlMsg> {
    anyhow::ensure!(data.len() >= 4, "message too short");
    let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    anyhow::ensure!(data.len() >= 4 + len, "incomplete message");
    rmp_serde::from_slice(&data[4..4 + len]).context("invalid control message")
}

pub async fn send_msg(stream: &mut SendStream, msg: &ControlMsg) -> Result<()> {
    let data = encode_msg(msg);
    stream
        .write_all(&data)
        .await
        .context("send control message")?;
    // Finish the stream so the FIN flushes the message. The protocol sends
    // exactly one message per bidirectional stream (the reader does
    // `accept_bi → recv_msg` in a loop), so finishing here is always correct.
    // Without it, dropping the `SendStream` resets it (RESET_STREAM) and the
    // peer loses any data not yet acknowledged — e.g. roster broadcasts sent
    // over a persistent connection. (Delivery before a *connection* drop still
    // needs the caller to wait on `conn.closed()`.)
    let _ = stream.finish();
    Ok(())
}

pub async fn recv_msg(stream: &mut RecvStream) -> Result<ControlMsg> {
    recv_framed(stream).await
}

/// Send any serializable message as a length-prefixed msgpack frame, then finish
/// the stream (same one-message-per-stream contract as [`send_msg`]). Used by
/// the `ray connect` handshake (`ConnectMsg`).
pub async fn send_framed<T: Serialize>(stream: &mut SendStream, msg: &T) -> Result<()> {
    let body = rmp_serde::to_vec_named(msg).context("serialize framed message")?;
    let len = (body.len() as u32).to_be_bytes();
    stream
        .write_all(&[len.as_slice(), &body].concat())
        .await
        .context("send framed message")?;
    let _ = stream.finish();
    Ok(())
}

/// Read a length-prefixed msgpack frame into any deserializable type.
pub async fn recv_framed<T: serde::de::DeserializeOwned>(stream: &mut RecvStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= 65536, "framed message too large");
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .context("read message body")?;
    rmp_serde::from_slice(&body).context("decode framed message")
}

/// A pairing ticket is `bs58(endpoint_id[32] || secret[32])`, minted by the
/// primary device's `start_pairing` and presented by the joining device.
pub fn encode_pairing_ticket(endpoint: EndpointId, secret: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(endpoint.as_bytes());
    buf.extend_from_slice(secret);
    bs58::encode(buf).into_string()
}

pub fn decode_pairing_ticket(s: &str) -> Result<(EndpointId, [u8; 32])> {
    let raw = bs58::decode(s.trim())
        .into_vec()
        .context("ticket is not base58")?;
    anyhow::ensure!(
        raw.len() == 64,
        "pairing ticket must be 64 bytes, got {}",
        raw.len()
    );
    let endpoint = EndpointId::from_bytes(&raw[..32].try_into().unwrap())
        .context("ticket endpoint id invalid")?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&raw[32..]);
    Ok((endpoint, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_id(seed: u8) -> EndpointId {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        iroh::SecretKey::from(key_bytes).public()
    }

    #[test]
    fn test_roundtrip_join_approved() {
        let msg = ControlMsg::JoinApproved {
            your_ip: Ipv4Addr::new(100, 64, 0, 3),
            members: vec![Member {
                identity: test_id(1),
                ip: Ipv4Addr::new(100, 64, 0, 2),
                is_coordinator: true,
                hostname: None,
                user_identity: None,
                device_cert: None,
                collision_index: 0,
            }],
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_mesh_hello() {
        let msg = ControlMsg::MeshHello {
            identity: test_id(1),
            ip: Ipv4Addr::new(100, 64, 0, 4),
            hostname: None,
            device_cert: None,
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_join_request() {
        let msg = ControlMsg::JoinRequest {
            invite_secret: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            hostname: Some("alice".to_string()),
            device_cert: None,
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_join_request_no_invite() {
        let msg = ControlMsg::JoinRequest {
            invite_secret: None,
            hostname: None,
            device_cert: None,
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_join_pending() {
        let msg = ControlMsg::JoinPending;
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_connect_msg() {
        let msgs = vec![
            ConnectMsg::Request {
                from_contact_id: test_id(1),
                from_endpoint: test_id(2),
                hostname: Some("dario".to_string()),
            },
            ConnectMsg::Pending,
            ConnectMsg::Approved {
                room_id: test_id(3),
                coordinator: test_id(4),
            },
            ConnectMsg::Denied {
                reason: "no".to_string(),
            },
        ];
        for msg in msgs {
            let body = rmp_serde::to_vec_named(&msg).unwrap();
            let decoded: ConnectMsg = rmp_serde::from_slice(&body).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_roundtrip_join_denied() {
        let msg = ControlMsg::JoinDenied {
            reason: "not authorized".to_string(),
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_member_sync() {
        let msg = ControlMsg::MemberSync;
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_member_approved() {
        let msg = ControlMsg::MemberApproved {
            identity: test_id(1),
            ip: Ipv4Addr::new(100, 64, 12, 34),
            hostname: None,
            device_cert: None,
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_welcome() {
        use crate::membership::ApprovedEntry;
        let msg = ControlMsg::Welcome {
            members: vec![Member {
                identity: test_id(1),
                ip: Ipv4Addr::new(100, 64, 0, 2),
                is_coordinator: true,
                hostname: None,
                user_identity: None,
                device_cert: None,
                collision_index: 0,
            }],
            approved: vec![ApprovedEntry {
                identity: test_id(2),
                ip: Ipv4Addr::new(100, 64, 0, 5),
                hostname: None,
                user_identity: None,
                device_cert: None,
                collision_index: 0,
            }],
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_file_offer() {
        let msg = ControlMsg::FileOffer {
            from: test_id(1),
            filename: "report.pdf".to_string(),
            size: 1_048_576,
            mime_type: "application/pdf".to_string(),
            blob_hash: blake3::hash(b"file contents"),
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_blob_updated() {
        let msg = ControlMsg::BlobUpdated;
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_admin_grant() {
        let key = test_key(7);
        let msg = ControlMsg::AdminGrant {
            network_pubkey: test_id(1),
            secret_key: key.to_bytes(),
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
        if let ControlMsg::AdminGrant { secret_key, .. } = decoded {
            assert_eq!(SecretKey::from(secret_key).public(), key.public());
        }
    }

    fn test_key(seed: u8) -> SecretKey {
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = seed;
        SecretKey::from(key_bytes)
    }

    #[test]
    fn test_device_cert_sign_verify() {
        let user_key = test_key(1);
        let device_key = test_key(2);
        let cert = DeviceCert::create(&user_key, &device_key.public());
        assert!(cert.verify());
        assert_eq!(cert.user_identity, user_key.public());
        assert_eq!(cert.device_key, device_key.public());
    }

    #[test]
    fn test_device_cert_rejects_wrong_signer() {
        let user_key = test_key(1);
        let device_key = test_key(2);
        let wrong_key = test_key(3);
        let mut cert = DeviceCert::create(&user_key, &device_key.public());
        cert.user_identity = wrong_key.public();
        assert!(!cert.verify());
    }

    #[test]
    fn test_roundtrip_mesh_hello_with_cert() {
        let user_key = test_key(1);
        let device_key = test_key(2);
        let cert = DeviceCert::create(&user_key, &device_key.public());
        let msg = ControlMsg::MeshHello {
            identity: device_key.public(),
            ip: Ipv4Addr::new(100, 64, 0, 5),
            hostname: Some("alice".to_string()),
            device_cert: Some(cert),
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
        if let ControlMsg::MeshHello {
            device_cert: Some(c),
            ..
        } = &decoded
        {
            assert!(c.verify());
        } else {
            panic!("expected MeshHello with cert");
        }
    }

    #[test]
    fn test_roundtrip_invite_share_and_used() {
        for msg in [
            ControlMsg::InviteShare {
                id: "ab3f".into(),
                secret_hash: vec![1, 2, 3],
                expires: 42,
            },
            ControlMsg::InviteUsed {
                secret_hash: vec![4, 5, 6],
            },
        ] {
            let bytes = encode_msg(&msg);
            assert_eq!(decode_msg(&bytes).unwrap(), msg);
        }
    }

    #[test]
    fn test_roundtrip_ping_pong() {
        for msg in [
            ControlMsg::Ping { nonce: 0 },
            ControlMsg::Ping { nonce: u64::MAX },
            ControlMsg::Pong {
                nonce: 0x0123_4567_89ab_cdef,
            },
        ] {
            let bytes = encode_msg(&msg);
            assert_eq!(decode_msg(&bytes).unwrap(), msg);
        }
    }

    #[test]
    fn pairing_ticket_roundtrips() {
        let endpoint = iroh::SecretKey::generate().public();
        let secret = [7u8; 32];
        let ticket = encode_pairing_ticket(endpoint, &secret);
        let (got_endpoint, got_secret) = decode_pairing_ticket(&ticket).unwrap();
        assert_eq!(got_endpoint, endpoint);
        assert_eq!(got_secret, secret);
    }

    #[test]
    fn decode_pairing_ticket_rejects_wrong_length() {
        // 64-byte payload is required (32 + 32); an invite code (80 bytes) must not parse.
        let eighty = bs58::encode(vec![0u8; 80]).into_string();
        assert!(decode_pairing_ticket(&eighty).is_err());
        assert!(decode_pairing_ticket("not-base58!!").is_err());
    }

    #[test]
    fn pair_response_networks_defaults_when_absent() {
        // An old Response encoded without the networks field must still decode,
        // with an empty list.
        #[derive(serde::Serialize)]
        enum OldPairMsg {
            Response { cert: DeviceCert },
        }
        let user = SecretKey::generate();
        let device = SecretKey::generate().public();
        let cert = DeviceCert::create(&user, &device);
        let bytes = rmp_serde::to_vec_named(&OldPairMsg::Response { cert: cert.clone() }).unwrap();

        let decoded: PairMsg = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            PairMsg::Response { networks, .. } => assert!(networks.is_empty()),
            _ => panic!("expected Response"),
        }
    }
}
