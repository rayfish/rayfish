//! Length-prefixed msgpack control protocol over QUIC bidirectional streams.
//!
//! Each message is encoded as a 4-byte big-endian length prefix followed by a msgpack body.
//! Control messages manage membership (join, approve, sync) and mesh topology (hello, reconnect).

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use iroh::EndpointId;
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::membership::{ApprovedEntry, Member};

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
    },
    MeshHello {
        identity: EndpointId,
        ip: Ipv4Addr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
    },
    MeshWelcome {
        identity: EndpointId,
        ip: Ipv4Addr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
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
                },
                Member {
                    identity: test_id(2),
                    ip: Ipv4Addr::new(100, 64, 0, 3),
                    is_coordinator: false,
                    hostname: None,
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
            }],
            approved: vec![ApprovedEntry {
                identity: test_id(2),
                ip: Ipv4Addr::new(100, 64, 0, 5),
                hostname: None,
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
}
