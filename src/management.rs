//! Direct controller-to-machine management protocol.
//!
//! This protocol has its own ALPN because the two machines do not need to share
//! a Rayfish network. Iroh authenticates each endpoint before these messages are
//! read; the managed machine then checks that endpoint against its local grants.
//!
//! Enrollment returns a controller-signed receipt kept by the managed machine.
//! Its hello can rebuild a lost controller inventory, but grants no authority on
//! the machine. Explicitly forgotten identities remain blocked until enrollment
//! or local confirmation clears the controller's durable removal record. Losing
//! that record loses the distinction between a forgotten and a missing machine.

use std::fmt;

use iroh::{EndpointId, SecretKey, Signature};
use ray_proto::ipc::{MachineHostname, NetworkName, UnixTimestampSecs};
use serde::{Deserialize, Serialize};

/// ALPN negotiated for direct controller-to-machine connections.
pub const ALPN: &[u8] = b"rayfish/manage/2";
const SECRET_LEN: usize = 32;

/// Proof of a past enrollment, bound to the machine's authenticated endpoint.
/// This is not a bearer credential: presenting it from another endpoint fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentReceipt {
    pub controller: EndpointId,
    pub machine: EndpointId,
    pub enrollment_id: [u8; 32],
    pub enrolled_at: UnixTimestampSecs,
    pub signature: Signature,
}

impl EnrollmentReceipt {
    pub(crate) fn issue(
        key: &SecretKey,
        machine: EndpointId,
        enrolled_at: UnixTimestampSecs,
    ) -> Self {
        let controller = key.public();
        let enrollment_id = rand::random();
        let signature = key.sign(&Self::signing_bytes(
            controller,
            machine,
            &enrollment_id,
            enrolled_at,
        ));
        Self {
            controller,
            machine,
            enrollment_id,
            enrolled_at,
            signature,
        }
    }

    fn signing_bytes(
        controller: EndpointId,
        machine: EndpointId,
        enrollment_id: &[u8; 32],
        enrolled_at: UnixTimestampSecs,
    ) -> Vec<u8> {
        let mut bytes = b"rayfish/enrollment-receipt/1\0".to_vec();
        bytes.extend_from_slice(controller.as_bytes());
        bytes.extend_from_slice(machine.as_bytes());
        bytes.extend_from_slice(enrollment_id);
        bytes.extend_from_slice(&enrolled_at.as_secs().to_le_bytes());
        bytes
    }

    /// Check both the signature and the identities expected by this connection.
    pub(crate) fn verify(&self, controller: EndpointId, machine: EndpointId) -> bool {
        self.controller == controller
            && self.machine == machine
            && controller
                .verify(
                    &Self::signing_bytes(
                        self.controller,
                        self.machine,
                        &self.enrollment_id,
                        self.enrolled_at,
                    ),
                    &self.signature,
                )
                .is_ok()
    }
}

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
    /// Sent only after the local operator explicitly confirms an existing grant.
    ConfirmEnrollment {
        receipt: EnrollmentReceipt,
    },
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
            Self::ConfirmEnrollment { .. } => f.write_str("ConfirmEnrollment"),
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
    Enrolled {
        receipt: EnrollmentReceipt,
    },
    ControllerHello {
        receipt: EnrollmentReceipt,
        hostname: MachineHostname,
    },
    HelloAccepted,
    HelloRejected {
        message: String,
    },
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
            Self::Enrolled { .. } => f.write_str("Enrolled"),
            Self::ControllerHello { hostname, .. } => f
                .debug_struct("ControllerHello")
                .field("hostname", hostname)
                .finish(),
            Self::HelloAccepted => f.write_str("HelloAccepted"),
            Self::HelloRejected { message } => f
                .debug_struct("HelloRejected")
                .field("message", message)
                .finish(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_binds_every_field_and_both_connection_identities() {
        let key = SecretKey::generate();
        let machine = SecretKey::generate().public();
        let stranger = SecretKey::generate().public();
        let receipt = EnrollmentReceipt::issue(&key, machine, UnixTimestampSecs::from_secs(100));
        assert!(receipt.verify(key.public(), machine));
        assert!(!receipt.verify(stranger, machine));
        assert!(!receipt.verify(key.public(), stranger));
        let mut forged = receipt.clone();
        forged.controller = stranger;
        assert!(!forged.verify(stranger, machine));
        let mut forged = receipt.clone();
        forged.machine = stranger;
        assert!(!forged.verify(key.public(), stranger));
        let mut forged = receipt.clone();
        forged.enrollment_id[0] ^= 1;
        assert!(!forged.verify(key.public(), machine));
        let mut forged = receipt.clone();
        forged.enrolled_at = UnixTimestampSecs::from_secs(101);
        assert!(!forged.verify(key.public(), machine));
        let mut forged = receipt;
        forged.signature = key.sign(b"unrelated signed message");
        assert!(!forged.verify(key.public(), machine));
    }

    #[test]
    fn receipt_survives_wire_encoding() {
        let key = SecretKey::generate();
        let machine = SecretKey::generate().public();
        let receipt = EnrollmentReceipt::issue(&key, machine, UnixTimestampSecs::from_secs(100));
        for message in [
            ManagementMsg::Enrolled {
                receipt: receipt.clone(),
            },
            ManagementMsg::ControllerHello {
                receipt: receipt.clone(),
                hostname: "build-box".parse().unwrap(),
            },
        ] {
            let bytes = rmp_serde::to_vec(&message).unwrap();
            let decoded: ManagementMsg = rmp_serde::from_slice(&bytes).unwrap();
            let restored = match decoded {
                ManagementMsg::Enrolled { receipt }
                | ManagementMsg::ControllerHello { receipt, .. } => receipt,
                _ => panic!("wrong message"),
            };
            assert_eq!(restored, receipt);
            assert!(restored.verify(key.public(), machine));
        }
        assert_eq!(ALPN, b"rayfish/manage/2");
    }
}
