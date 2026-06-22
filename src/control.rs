//! Length-prefixed msgpack control protocol over QUIC bidirectional streams.
//!
//! Each message is encoded as a 4-byte big-endian length prefix followed by a msgpack body.
//! Control messages manage membership (join, approve, sync) and mesh topology (hello, reconnect).

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use iroh::{EndpointId, SecretKey, Signature};
use iroh::endpoint::{RecvStream, SendStream};
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

/// Messages for the device pairing protocol (ALPN `pitopi/pair/1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PairMsg {
    Request {
        secret: [u8; 32],
        device_pubkey: EndpointId,
    },
    Response {
        cert: DeviceCert,
    },
}

/// Control messages exchanged between peers over QUIC bidirectional streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    JoinApproved {
        your_ip: Ipv4Addr,
        members: Vec<Member>,
    },
    JoinDenied {
        reason: String,
    },
    MemberSync {
        members: Vec<Member>,
    },
    ReconnectRequest {
        identity: EndpointId,
        ip: Ipv4Addr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_cert: Option<DeviceCert>,
    },
    MeshHello {
        identity: EndpointId,
        ip: Ipv4Addr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_cert: Option<DeviceCert>,
    },
    MeshWelcome {
        identity: EndpointId,
        ip: Ipv4Addr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_cert: Option<DeviceCert>,
    },
    AdvertiseServices {
        ip: Ipv4Addr,
        services: Vec<ServiceTag>,
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
    BlobUpdated {
        hash: blake3::Hash,
    },
    FileOffer {
        from: EndpointId,
        filename: String,
        size: u64,
        mime_type: String,
        blob_hash: blake3::Hash,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceTag {
    pub name: String,
    pub port: u16,
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
    Ok(())
}

pub async fn recv_msg(stream: &mut RecvStream) -> Result<ControlMsg> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= 65536, "control message too large");
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .context("read message body")?;
    rmp_serde::from_slice(&body).context("decode control message")
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
        let msg = ControlMsg::MemberSync {
            members: vec![
                Member {
                    identity: test_id(1),
                    ip: Ipv4Addr::new(100, 64, 0, 2),
                    is_coordinator: true,
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                },
                Member {
                    identity: test_id(2),
                    ip: Ipv4Addr::new(100, 64, 0, 3),
                    is_coordinator: false,
                    hostname: None,
                    user_identity: None,
                    device_cert: None,
                },
            ],
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_roundtrip_reconnect_request() {
        let msg = ControlMsg::ReconnectRequest {
            identity: test_id(1),
            ip: Ipv4Addr::new(100, 64, 7, 42),
            device_cert: None,
        };
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
            }],
            approved: vec![ApprovedEntry {
                identity: test_id(2),
                ip: Ipv4Addr::new(100, 64, 0, 5),
                hostname: None,
                user_identity: None,
                device_cert: None,
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
        let msg = ControlMsg::BlobUpdated {
            hash: blake3::hash(b"test blob"),
        };
        let bytes = encode_msg(&msg);
        let decoded = decode_msg(&bytes).unwrap();
        assert_eq!(msg, decoded);
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
        if let ControlMsg::MeshHello { device_cert: Some(c), .. } = &decoded {
            assert!(c.verify());
        } else {
            panic!("expected MeshHello with cert");
        }
    }
}
