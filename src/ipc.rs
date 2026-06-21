use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use iroh::EndpointId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::membership::GroupMode;

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    Create {
        mode: GroupMode,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        hostname: Option<String>,
    },
    Join {
        network_key: String,
        name: Option<String>,
        #[serde(default)]
        hostname: Option<String>,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
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
    },
    Joined {
        name: String,
        my_ip: Ipv4Addr,
    },
    Status {
        endpoint_id: EndpointId,
        networks: Vec<NetworkStatus>,
        #[serde(default)]
        packets_rx: u64,
        #[serde(default)]
        packets_tx: u64,
        #[serde(default)]
        bytes_rx: u64,
        #[serde(default)]
        bytes_tx: u64,
    },
    AclState {
        display: String,
    },
    FirewallState {
        display: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub name: String,
    pub role: NetworkRole,
    pub my_ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub my_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_key: Option<String>,
    pub member_count: usize,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkRole {
    Coordinator,
    Member,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub endpoint_id: EndpointId,
    pub ip: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub conn_type: ConnType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub datagrams_tx: u64,
    pub datagrams_rx: u64,
    pub lost_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnType {
    Direct,
    Relay,
    Unknown,
}

pub fn socket_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/pitopi.sock")
    } else {
        PathBuf::from("/var/run/pitopi/pitopi.sock")
    }
}

pub async fn connect() -> Result<UnixStream> {
    let path = socket_path();
    UnixStream::connect(&path)
        .await
        .context("daemon not running — start it with: sudo pitopi daemon")
}

pub async fn send_msg<T: Serialize>(stream: &mut UnixStream, msg: &T) -> Result<()> {
    let json = serde_json::to_vec(msg).context("serialize IPC message")?;
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len).await.context("write IPC length")?;
    stream.write_all(&json).await.context("write IPC body")?;
    stream.flush().await.context("flush IPC")?;
    Ok(())
}

pub async fn recv_msg<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read IPC length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= 1_048_576, "IPC message too large");
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .await
        .context("read IPC body")?;
    serde_json::from_slice(&body).context("decode IPC message")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_roundtrip() {
        let req = IpcRequest::Create {
            mode: GroupMode::Open,
            name: None,
            hostname: None,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: IpcRequest = serde_json::from_slice(&json).unwrap();
        match decoded {
            IpcRequest::Create { mode, .. } => {
                assert_eq!(mode, GroupMode::Open);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let key = iroh::SecretKey::generate().public();
        let resp = IpcResponse::Created {
            name: "test".to_string(),
            network_key: key,
            my_ip: Ipv4Addr::new(100, 64, 10, 5),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: IpcResponse = serde_json::from_slice(&json).unwrap();
        match decoded {
            IpcResponse::Created { name, network_key, my_ip } => {
                assert_eq!(name, "test");
                assert_eq!(network_key, key);
                assert_eq!(my_ip, Ipv4Addr::new(100, 64, 10, 5));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_acl_tag_roundtrip() {
        let req = IpcRequest::AclTag {
            network: "gentle-amber-fox".to_string(),
            tag: "servers".to_string(),
            peer_ids: vec!["ab3f".to_string(), "d92c".to_string()],
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: IpcRequest = serde_json::from_slice(&json).unwrap();
        match decoded {
            IpcRequest::AclTag { network, tag, peer_ids } => {
                assert_eq!(network, "gentle-amber-fox");
                assert_eq!(tag, "servers");
                assert_eq!(peer_ids.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_acl_state_response_roundtrip() {
        let resp = IpcResponse::AclState {
            display: "Tags:\n  servers: ab3f\n".to_string(),
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: IpcResponse = serde_json::from_slice(&json).unwrap();
        match decoded {
            IpcResponse::AclState { display } => {
                assert!(display.contains("servers"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_status_response_roundtrip() {
        let ep_id = iroh::SecretKey::generate().public();
        let peer_id = iroh::SecretKey::generate().public();
        let resp = IpcResponse::Status {
            endpoint_id: ep_id,
            networks: vec![NetworkStatus {
                name: "gaming".to_string(),
                role: NetworkRole::Coordinator,
                my_ip: Ipv4Addr::new(100, 64, 10, 5),
                my_hostname: Some("alice".to_string()),
                network_key: Some("abc123".to_string()),
                member_count: 2,
                peers: vec![PeerStatus {
                    endpoint_id: peer_id,
                    ip: Ipv4Addr::new(100, 64, 10, 6),
                    hostname: None,
                    connection: None,
                }],
            }],
            packets_rx: 0,
            packets_tx: 0,
            bytes_rx: 0,
            bytes_tx: 0,
        };
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: IpcResponse = serde_json::from_slice(&json).unwrap();
        match decoded {
            IpcResponse::Status { endpoint_id, networks, .. } => {
                assert_eq!(endpoint_id, ep_id);
                assert_eq!(networks.len(), 1);
                assert_eq!(networks[0].peers[0].endpoint_id, peer_id);
            }
            _ => panic!("wrong variant"),
        }
    }
}
