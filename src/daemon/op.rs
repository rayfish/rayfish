//! Typed results of the daemon's operations. An operation returns
//! [`OpResult`]; only the IPC edge turns that into an [`IpcMessage`], so the
//! embedders (`ray-mobile`, `ray-apple`) read fields instead of re-matching
//! reply variants.

use std::net::Ipv6Addr;

use iroh::EndpointId;

use crate::ipc::IpcMessage;

/// A failed operation, carrying the message a person reads.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct OpError(String);

impl OpError {
    pub fn msg(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl From<anyhow::Error> for OpError {
    fn from(error: anyhow::Error) -> Self {
        Self(format!("{error:#}"))
    }
}

impl From<OpError> for IpcMessage {
    fn from(error: OpError) -> Self {
        IpcMessage::Error { message: error.0 }
    }
}

pub type OpResult<T> = Result<T, OpError>;

/// The IPC reply for an operation's result.
pub(crate) fn reply<T: Into<IpcMessage>>(result: OpResult<T>) -> IpcMessage {
    result.map_or_else(IpcMessage::from, Into::into)
}

/// An operation that succeeded with only a confirmation to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done(pub String);

impl From<Done> for IpcMessage {
    fn from(Done(message): Done) -> Self {
        IpcMessage::Ok { message }
    }
}

/// A network this node created, or restored as its coordinator.
#[derive(Debug, Clone)]
pub struct CreatedNetwork {
    pub name: String,
    pub network_key: EndpointId,
    pub my_ipv6: Ipv6Addr,
}

impl From<CreatedNetwork> for IpcMessage {
    fn from(created: CreatedNetwork) -> Self {
        IpcMessage::Created {
            name: created.name,
            network_key: created.network_key,
            my_ipv6: created.my_ipv6,
        }
    }
}

/// A network this node is now a live member of.
#[derive(Debug, Clone)]
pub struct JoinedNetwork {
    pub name: String,
    pub my_ipv6: Ipv6Addr,
}

impl From<JoinedNetwork> for IpcMessage {
    fn from(joined: JoinedNetwork) -> Self {
        IpcMessage::Joined {
            name: joined.name,
            my_ipv6: joined.my_ipv6,
        }
    }
}

/// How a join request ended.
#[derive(Debug, Clone)]
pub enum JoinOutcome {
    Joined(JoinedNetwork),
    /// Waiting for a coordinator to approve it; retried in the background.
    Queued(Done),
}

impl From<JoinOutcome> for IpcMessage {
    fn from(outcome: JoinOutcome) -> Self {
        match outcome {
            JoinOutcome::Joined(joined) => joined.into(),
            JoinOutcome::Queued(done) => done.into(),
        }
    }
}

/// A freshly minted invite code.
#[derive(Debug, Clone)]
pub struct CreatedInvite {
    pub code: String,
    pub id: String,
    pub expires_secs: u64,
}

impl From<CreatedInvite> for IpcMessage {
    fn from(invite: CreatedInvite) -> Self {
        IpcMessage::InviteCreated {
            code: invite.code,
            id: invite.id,
            expires_secs: invite.expires_secs,
        }
    }
}
