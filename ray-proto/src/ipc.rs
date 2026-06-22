use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use bytes::{Buf, BufMut, BytesMut};
use iroh::EndpointId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::net::UnixStream;
use tokio_util::codec::{Decoder, Encoder, Framed};

use crate::{GroupMode, TransportMode};

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcMessage {
    // Requests
    Create {
        mode: GroupMode,
        name: Option<String>,
        hostname: Option<String>,
        transport: Option<TransportMode>,
    },
    Join {
        network_key: String,
        name: Option<String>,
        hostname: Option<String>,
        transport: Option<TransportMode>,
    },
    Leave {
        name: String,
    },
    Nuke {
        name: String,
        force: bool,
    },
    Status,
    Shutdown,
    /// Activate the VPN: bring the TUN interface up, configure system DNS, and
    /// reconnect all saved networks. Handled by the already-running daemon, so
    /// no root privileges are needed on the client.
    Up,
    /// Put the daemon on standby: tear down active network connections, revert
    /// system DNS, and bring the TUN interface down. The daemon process keeps
    /// running so it can be reactivated with `Up`.
    Down,
    AclTag {
        network: String,
        tag: String,
        peer_ids: Vec<String>,
    },
    AclUntag {
        network: String,
        tag: String,
        peer_id: String,
    },
    AclAllow {
        network: String,
        src: String,
        dst: String,
    },
    AclRemove {
        network: String,
        index: usize,
    },
    AclShow {
        network: String,
    },
    AclApply {
        network: String,
    },
    FirewallAdd {
        direction: String,
        action: String,
        protocol: String,
        port: Option<String>,
        peer: Option<String>,
    },
    FirewallRemove {
        index: usize,
    },
    FirewallShow,
    FirewallDefault {
        action: String,
    },
    SetHostname {
        network: String,
        hostname: String,
    },
    SendFile {
        path: String,
        peer: String,
    },
    ListFiles,
    AcceptFile {
        id: u64,
        output: Option<String>,
    },
    StartPairing,
    PairWithDevice {
        endpoint_id: EndpointId,
        secret: Vec<u8>,
    },

    // Responses
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
    Created {
        name: String,
        network_key: EndpointId,
        my_ip: Ipv4Addr,
        my_ipv6: Option<Ipv6Addr>,
    },
    Joined {
        name: String,
        my_ip: Ipv4Addr,
        my_ipv6: Option<Ipv6Addr>,
    },
    StatusResponse {
        endpoint_id: EndpointId,
        mdns_enabled: bool,
        /// Whether the VPN is active (TUN up, networks connected) or on standby.
        active: bool,
        networks: Vec<NetworkStatus>,
        packets_rx: u64,
        packets_tx: u64,
        bytes_rx: u64,
        bytes_tx: u64,
    },
    AclState {
        display: String,
    },
    FirewallState {
        display: String,
    },
    FileList {
        files: Vec<PendingFileInfo>,
    },
    PairingTicket {
        ticket: String,
    },
    PairingComplete {
        user_identity: EndpointId,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingFileInfo {
    pub id: u64,
    pub from: String,
    pub filename: String,
    pub size: u64,
    pub mime_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub name: String,
    pub role: NetworkRole,
    pub my_ip: Ipv4Addr,
    pub my_ipv6: Option<Ipv6Addr>,
    pub my_hostname: Option<String>,
    pub network_key: Option<String>,
    pub member_count: usize,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, derive_more::IsVariant)]
pub enum NetworkRole {
    Coordinator,
    Member,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub endpoint_id: EndpointId,
    pub ip: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub hostname: Option<String>,
    pub user_identity: Option<EndpointId>,
    pub connection: Option<ConnectionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub conn_type: ConnType,
    pub remote_addr: Option<String>,
    pub rtt_ms: Option<f64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub datagrams_tx: u64,
    pub datagrams_rx: u64,
    pub lost_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, derive_more::IsVariant)]
pub enum ConnType {
    Direct,
    Relay,
    Tor,
    Unknown,
}

pub struct MsgpackCodec<T>(PhantomData<T>);

impl<T> MsgpackCodec<T> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> Default for MsgpackCodec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Serialize> Encoder<T> for MsgpackCodec<T> {
    type Error = anyhow::Error;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<()> {
        let body = rmp_serde::to_vec(&item).context("serialize IPC message")?;
        dst.put_u32(body.len() as u32);
        dst.extend_from_slice(&body);
        Ok(())
    }
}

impl<T: DeserializeOwned> Decoder for MsgpackCodec<T> {
    type Item = T;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<T>> {
        if src.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes(src[..4].try_into().unwrap()) as usize;
        anyhow::ensure!(len <= 1_048_576, "IPC message too large");
        if src.len() < 4 + len {
            return Ok(None);
        }
        src.advance(4);
        let body = src.split_to(len);
        Ok(Some(
            rmp_serde::from_slice(&body).context("decode IPC message")?,
        ))
    }
}

pub type IpcFramed = Framed<UnixStream, MsgpackCodec<IpcMessage>>;

pub fn socket_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/rayfish.sock")
    } else {
        PathBuf::from("/var/run/rayfish/rayfish.sock")
    }
}

pub async fn connect() -> Result<IpcFramed> {
    let path = socket_path();
    let stream = UnixStream::connect(&path)
        .await
        .context("daemon not running — start it with: sudo rayfish daemon")?;
    Ok(Framed::new(stream, MsgpackCodec::new()))
}

pub fn framed(stream: UnixStream) -> IpcFramed {
    Framed::new(stream, MsgpackCodec::new())
}

pub async fn send(framed: &mut IpcFramed, msg: IpcMessage) -> Result<()> {
    use futures::SinkExt;
    framed.send(msg).await
}

pub async fn recv(framed: &mut IpcFramed) -> Result<IpcMessage> {
    use futures::StreamExt;
    framed.next().await.context("connection closed")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let req = IpcMessage::Create {
            mode: GroupMode::Open,
            name: None,
            hostname: None,
            transport: None,
        };
        let bytes = rmp_serde::to_vec(&req).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::Create { mode, .. } => {
                assert_eq!(mode, GroupMode::Open);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let key = iroh::SecretKey::generate().public();
        let resp = IpcMessage::Created {
            name: "test".to_string(),
            network_key: key,
            my_ip: Ipv4Addr::new(100, 64, 10, 5),
            my_ipv6: None,
        };
        let bytes = rmp_serde::to_vec(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::Created {
                name,
                network_key,
                my_ip,
                ..
            } => {
                assert_eq!(name, "test");
                assert_eq!(network_key, key);
                assert_eq!(my_ip, Ipv4Addr::new(100, 64, 10, 5));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_acl_tag_roundtrip() {
        let req = IpcMessage::AclTag {
            network: "gentle-amber-fox".to_string(),
            tag: "servers".to_string(),
            peer_ids: vec!["ab3f".to_string(), "d92c".to_string()],
        };
        let bytes = rmp_serde::to_vec(&req).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::AclTag {
                network,
                tag,
                peer_ids,
            } => {
                assert_eq!(network, "gentle-amber-fox");
                assert_eq!(tag, "servers");
                assert_eq!(peer_ids.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_acl_state_roundtrip() {
        let resp = IpcMessage::AclState {
            display: "Tags:\n  servers: ab3f\n".to_string(),
        };
        let bytes = rmp_serde::to_vec(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::AclState { display } => {
                assert!(display.contains("servers"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_status_response_roundtrip() {
        let ep_id = iroh::SecretKey::generate().public();
        let peer_id = iroh::SecretKey::generate().public();
        let resp = IpcMessage::StatusResponse {
            endpoint_id: ep_id,
            mdns_enabled: true,
            active: true,
            networks: vec![NetworkStatus {
                name: "gaming".to_string(),
                role: NetworkRole::Coordinator,
                my_ip: Ipv4Addr::new(100, 64, 10, 5),
                my_ipv6: None,
                my_hostname: Some("alice".to_string()),
                network_key: Some("abc123".to_string()),
                member_count: 2,
                peers: vec![PeerStatus {
                    endpoint_id: peer_id,
                    ip: Ipv4Addr::new(100, 64, 10, 6),
                    ipv6: None,
                    hostname: None,
                    user_identity: None,
                    connection: None,
                }],
            }],
            packets_rx: 0,
            packets_tx: 0,
            bytes_rx: 0,
            bytes_tx: 0,
        };
        let bytes = rmp_serde::to_vec(&resp).unwrap();
        let decoded: IpcMessage = rmp_serde::from_slice(&bytes).unwrap();
        match decoded {
            IpcMessage::StatusResponse {
                endpoint_id,
                networks,
                ..
            } => {
                assert_eq!(endpoint_id, ep_id);
                assert_eq!(networks.len(), 1);
                assert_eq!(networks[0].peers[0].endpoint_id, peer_id);
            }
            _ => panic!("wrong variant"),
        }
    }
}
