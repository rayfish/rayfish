mod forward;
mod identity;
mod shutdown;
mod transport;
mod tun;

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::EndpointId;

const SELF_IP_CREATE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const PEER_IP_CREATE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

#[derive(Parser)]
#[command(name = "pitopi", about = "P2P mesh VPN powered by iroh")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new network and wait for peers
    Create,
    /// Join an existing network using a node ID
    Join {
        /// The endpoint ID of the network creator
        node_id: EndpointId,
    },
}

fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("pitopi requires root privileges to create TUN devices. Run with sudo.");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    check_root();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let cli = Cli::parse();

    match cli.command {
        Command::Create => cmd_create().await,
        Command::Join { node_id } => cmd_join(node_id).await,
    }
}

async fn cmd_create() -> Result<()> {
    let key = identity::load_or_create()?;
    let ep = transport::create_endpoint(key).await?;

    tracing::info!("network created");
    tracing::info!(ip = %SELF_IP_CREATE, "your virtual IP");
    tracing::info!(node_id = %ep.id(), "share this node ID with your peer");
    tracing::info!("waiting for a peer to join...");

    let conn = transport::accept_connection(&ep).await?;
    tracing::info!("peer connected, tunnel active");

    let tun = tun::TunDevice::create(SELF_IP_CREATE, PEER_IP_CREATE)
        .context("failed to create TUN device (are you running as root?)")?;

    forward::run(tun, conn).await
}

async fn cmd_join(node_id: EndpointId) -> Result<()> {
    let key = identity::load_or_create()?;
    let ep = transport::create_endpoint(key).await?;

    tracing::info!("connecting to network...");
    let conn = transport::connect_to_peer(&ep, node_id).await?;
    tracing::info!(ip = %PEER_IP_CREATE, "connected, tunnel active");

    let tun = tun::TunDevice::create(PEER_IP_CREATE, SELF_IP_CREATE)
        .context("failed to create TUN device (are you running as root?)")?;

    forward::run(tun, conn).await
}
