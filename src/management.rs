//! Direct controller-to-machine management protocol.
//!
//! This protocol has its own ALPN because the two machines do not need to share
//! a Rayfish network. Iroh authenticates each endpoint before these messages are
//! read; the managed machine then checks that endpoint against its local grants.

use std::fmt;

use anyhow::{Result, bail};
use iroh::EndpointId;
use ray_proto::ipc::{EnrollmentTicket, MachineHostname, NetworkName};
use serde::{Deserialize, Serialize};

pub const ALPN: &[u8] = b"rayfish/manage/1";
const SECRET_LEN: usize = 32;
const PAYLOAD_LEN: usize = 32 + SECRET_LEN;
const CHECKSUM_LEN: usize = 4;

/// Enrollment secret carried only in the ticket and enrollment handshake.
/// Its debug form is deliberately redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentSecret([u8; SECRET_LEN]);

impl EnrollmentSecret {
    pub fn generate() -> Self {
        Self(rand::random())
    }

    pub fn hash(&self) -> blake3::Hash {
        blake3::hash(&self.0)
    }
}

impl fmt::Debug for EnrollmentSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentSecret([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInvite(String);

impl NetworkInvite {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NetworkInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkInvite([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementRequestId(u64);

impl ManagementRequestId {
    pub fn generate() -> Self {
        Self(rand::random())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ManagementAction {
    Status,
    Join {
        invite: NetworkInvite,
        network_name: NetworkName,
        hostname: MachineHostname,
        auto_accept_firewall: bool,
        auto_accept_files: bool,
    },
    Leave {
        network_name: NetworkName,
    },
}

impl fmt::Debug for ManagementAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status => f.write_str("Status"),
            Self::Join {
                network_name,
                hostname,
                auto_accept_firewall,
                auto_accept_files,
                ..
            } => f
                .debug_struct("Join")
                .field("invite", &"[redacted]")
                .field("network_name", network_name)
                .field("hostname", hostname)
                .field("auto_accept_firewall", auto_accept_firewall)
                .field("auto_accept_files", auto_accept_files)
                .finish(),
            Self::Leave { network_name } => f
                .debug_struct("Leave")
                .field("network_name", network_name)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManagementResult {
    Status {
        hostname: MachineHostname,
        networks: Vec<NetworkName>,
    },
    Applied {
        message: String,
    },
    Unauthorized,
    Error {
        message: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ManagementMsg {
    Enroll {
        secret: EnrollmentSecret,
        hostname: MachineHostname,
    },
    Enrolled,
    EnrollmentRejected {
        message: String,
    },
    ProtocolError {
        message: String,
    },
    Request {
        request_id: ManagementRequestId,
        action: ManagementAction,
    },
    Response {
        request_id: ManagementRequestId,
        result: ManagementResult,
    },
}

impl fmt::Debug for ManagementMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enroll { hostname, .. } => f
                .debug_struct("Enroll")
                .field("secret", &"[redacted]")
                .field("hostname", hostname)
                .finish(),
            Self::Enrolled => f.write_str("Enrolled"),
            Self::EnrollmentRejected { message } => f
                .debug_struct("EnrollmentRejected")
                .field("message", message)
                .finish(),
            Self::ProtocolError { message } => f
                .debug_struct("ProtocolError")
                .field("message", message)
                .finish(),
            Self::Request { request_id, action } => f
                .debug_struct("Request")
                .field("request_id", request_id)
                .field("action", action)
                .finish(),
            Self::Response { request_id, result } => f
                .debug_struct("Response")
                .field("request_id", request_id)
                .field("result", result)
                .finish(),
        }
    }
}

fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let hash = blake3::hash(payload);
    let mut out = [0; CHECKSUM_LEN];
    out.copy_from_slice(&hash.as_bytes()[..CHECKSUM_LEN]);
    out
}

pub fn encode_ticket(controller: EndpointId, secret: &EnrollmentSecret) -> EnrollmentTicket {
    let mut bytes = Vec::with_capacity(PAYLOAD_LEN + CHECKSUM_LEN);
    bytes.extend_from_slice(controller.as_bytes());
    bytes.extend_from_slice(&secret.0);
    bytes.extend_from_slice(&checksum(&bytes));
    EnrollmentTicket::new(bs58::encode(bytes).into_string())
}

pub fn decode_ticket(ticket: &EnrollmentTicket) -> Result<(EndpointId, EnrollmentSecret)> {
    let bytes = bs58::decode(ticket.expose().trim())
        .into_vec()
        .map_err(|error| anyhow::anyhow!("invalid controller ticket: {error}"))?;
    if bytes.len() != PAYLOAD_LEN + CHECKSUM_LEN {
        bail!(
            "invalid controller ticket: expected {} bytes, got {}",
            PAYLOAD_LEN + CHECKSUM_LEN,
            bytes.len()
        );
    }
    let (payload, supplied_checksum) = bytes.split_at(PAYLOAD_LEN);
    if supplied_checksum != checksum(payload) {
        bail!("invalid controller ticket: checksum mismatch");
    }
    let controller_bytes: [u8; 32] = payload[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid controller identity"))?;
    let secret_bytes: [u8; SECRET_LEN] = payload[32..]
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid controller ticket secret"))?;
    let controller = EndpointId::from_bytes(&controller_bytes)
        .map_err(|error| anyhow::anyhow!("invalid controller identity: {error}"))?;
    Ok((controller, EnrollmentSecret(secret_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn ticket_roundtrip() {
        let controller = SecretKey::generate().public();
        let secret = EnrollmentSecret::generate();
        let ticket = encode_ticket(controller, &secret);
        let (decoded_controller, decoded_secret) = decode_ticket(&ticket).unwrap();
        assert_eq!(decoded_controller, controller);
        assert_eq!(decoded_secret, secret);
    }

    #[test]
    fn ticket_rejects_damage() {
        let controller = SecretKey::generate().public();
        let secret = EnrollmentSecret::generate();
        let ticket = encode_ticket(controller, &secret);
        let mut bytes = bs58::decode(ticket.expose()).into_vec().unwrap();
        bytes[10] ^= 1;
        let damaged = EnrollmentTicket::new(bs58::encode(bytes).into_string());
        assert!(decode_ticket(&damaged).is_err());
    }
}
