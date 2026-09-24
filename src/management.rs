//! Direct controller-to-machine management protocol.
//!
//! This protocol has its own ALPN because the two machines do not need to share
//! a Rayfish network. Iroh authenticates each endpoint before these messages are
//! read; the managed machine then checks that endpoint against its local grants.

use std::fmt;

use ray_proto::ipc::{MachineHostname, NetworkName};
use serde::{Deserialize, Serialize};

/// ALPN negotiated for direct controller-to-machine connections.
pub const ALPN: &[u8] = b"rayfish/manage/1";
const SECRET_LEN: usize = 32;

/// Enrollment secret carried only in the ticket and enrollment handshake.
/// Its debug form is deliberately redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentSecret([u8; SECRET_LEN]);

impl EnrollmentSecret {
    /// Generates a new random enrollment secret.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// Returns the hash persisted by the controller.
    pub fn hash(&self) -> blake3::Hash {
        blake3::hash(&self.0)
    }

    /// Creates a secret from the bytes carried in an enrollment ticket.
    pub(crate) fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the bytes to place in an enrollment ticket.
    pub(crate) fn to_bytes(&self) -> [u8; SECRET_LEN] {
        self.0
    }
}

impl fmt::Debug for EnrollmentSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentSecret([redacted])")
    }
}

/// Network invite carried in an authenticated management request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInvite(String);

impl NetworkInvite {
    /// Wraps an encoded network invite.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the encoded invite.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NetworkInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkInvite([redacted])")
    }
}

/// Correlates a management response with its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementRequestId(u64);

impl ManagementRequestId {
    /// Generates a random request identifier.
    pub fn generate() -> Self {
        Self(rand::random())
    }
}

/// Operation requested by an authorized controller.
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

/// Result of a controller management request.
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

/// Message exchanged over the direct management protocol.
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
