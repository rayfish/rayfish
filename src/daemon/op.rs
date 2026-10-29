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

/// The IPC reply for a result whose value the caller wraps itself, for the
/// replies that are just a list.
pub(crate) fn reply_with<T>(result: OpResult<T>, ok: impl FnOnce(T) -> IpcMessage) -> IpcMessage {
    result.map_or_else(IpcMessage::from, ok)
}

/// `Err` with `message`, for an operation's early returns.
pub(crate) fn op_err<T>(message: impl Into<String>) -> OpResult<T> {
    Err(OpError::msg(message))
}

/// How `ray connect` ended.
#[derive(Debug, Clone)]
pub enum ConnectOutcome {
    /// The peer approved at once and this node joined the network it minted.
    Joined(JoinOutcome),
    /// Waiting for approval, or already connected; the message says which.
    Done(Done),
}

impl ConnectOutcome {
    /// One line for an app to show.
    pub fn summary(self) -> String {
        match self {
            ConnectOutcome::Joined(JoinOutcome::Joined(joined)) => {
                format!("Connected on {}", joined.name)
            }
            ConnectOutcome::Joined(JoinOutcome::Queued(Done(message)))
            | ConnectOutcome::Done(Done(message)) => message,
        }
    }
}

impl From<ConnectOutcome> for IpcMessage {
    fn from(outcome: ConnectOutcome) -> Self {
        match outcome {
            ConnectOutcome::Joined(joined) => joined.into(),
            ConnectOutcome::Done(done) => done.into(),
        }
    }
}

/// Every file this node is receiving, sending or has just moved.
#[derive(Debug)]
pub struct FileQueues {
    /// Offers waiting for `ray files accept`.
    pub incoming: Vec<ray_proto::ipc::PendingFileInfo>,
    /// Sends queued until their peer comes online.
    pub outbox: Vec<ray_proto::ipc::OutboxFileInfo>,
    /// In-flight and recently finished transfers.
    pub transfers: Vec<ray_proto::ipc::TransferFileInfo>,
}

impl From<FileQueues> for IpcMessage {
    fn from(queues: FileQueues) -> Self {
        IpcMessage::FileList {
            files: queues.incoming,
            outbox: queues.outbox,
            transfers: queues.transfers,
        }
    }
}
