mod forward;
mod identity;
mod shutdown;
mod stats;
mod transport;
mod tun;

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::EndpointId;

const SELF_IP_CREATE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const PEER_IP_CREATE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

const BACKOFF_INITIAL: std::time::Duration = std::time::Duration::from_secs(1);
const BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30);

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

    let token = shutdown::token();
    let stats = stats::Stats::new();
    stats.spawn_logger(token.clone());

    match cli.command {
        Command::Create => cmd_create(token, stats).await,
        Command::Join { node_id } => cmd_join(node_id, token, stats).await,
    }
}

async fn cmd_create(
    token: tokio_util::sync::CancellationToken,
    stats: std::sync::Arc<stats::Stats>,
) -> Result<()> {
    let key = identity::load_or_create()?;
    let ep = transport::create_endpoint(key).await?;

    tracing::info!("network created");
    tracing::info!(ip = %SELF_IP_CREATE, "your virtual IP");
    tracing::info!(node_id = %ep.id(), "share this node ID with your peer");

    let tun = tun::TunDevice::create(SELF_IP_CREATE, PEER_IP_CREATE)
        .context("failed to create TUN device")?;

    let mut backoff = BACKOFF_INITIAL;

    loop {
        tracing::info!("waiting for a peer to join...");

        let conn = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = transport::accept_connection(&ep) => {
                match result {
                    Ok(conn) => {
                        backoff = BACKOFF_INITIAL;
                        conn
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to accept connection");
                        backoff_sleep(&token, &mut backoff).await;
                        continue;
                    }
                }
            }
        };

        tracing::info!("peer connected, tunnel active");

        if let Err(e) = forward::run(tun.share(), conn, token.clone(), stats.clone()).await {
            if token.is_cancelled() {
                return Ok(());
            }
            tracing::warn!(error = %e, "connection lost, reconnecting...");
            backoff_sleep(&token, &mut backoff).await;
        }
    }
}

async fn cmd_join(
    node_id: EndpointId,
    token: tokio_util::sync::CancellationToken,
    stats: std::sync::Arc<stats::Stats>,
) -> Result<()> {
    let key = identity::load_or_create()?;
    let ep = transport::create_endpoint(key).await?;

    let tun = tun::TunDevice::create(PEER_IP_CREATE, SELF_IP_CREATE)
        .context("failed to create TUN device")?;

    let mut backoff = BACKOFF_INITIAL;

    loop {
        tracing::info!("connecting to network...");

        let conn = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = transport::connect_to_peer(&ep, node_id) => {
                match result {
                    Ok(conn) => {
                        backoff = BACKOFF_INITIAL;
                        conn
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to connect");
                        backoff_sleep(&token, &mut backoff).await;
                        continue;
                    }
                }
            }
        };

        tracing::info!(ip = %PEER_IP_CREATE, "connected, tunnel active");

        if let Err(e) = forward::run(tun.share(), conn, token.clone(), stats.clone()).await {
            if token.is_cancelled() {
                return Ok(());
            }
            tracing::warn!(error = %e, "connection lost, reconnecting...");
            backoff_sleep(&token, &mut backoff).await;
        }
    }
}

async fn backoff_sleep(
    token: &tokio_util::sync::CancellationToken,
    backoff: &mut std::time::Duration,
) {
    tracing::info!(secs = backoff.as_secs(), "retrying in");
    tokio::select! {
        _ = token.cancelled() => {}
        _ = tokio::time::sleep(*backoff) => {}
    }
    *backoff = (*backoff * 2).min(BACKOFF_MAX);
}
