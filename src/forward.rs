use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::Connection;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::stats::Stats;
use crate::tun::TunDevice;

pub async fn run(
    tun: TunDevice,
    conn: Connection,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);

    let tun_to_iroh = tokio::spawn(tun_read_loop(
        tun,
        conn.clone(),
        tun_rx,
        token.clone(),
        stats.clone(),
    ));
    let iroh_to_tun = tokio::spawn(iroh_read_loop(conn, tun_tx, token.clone(), stats));

    tokio::select! {
        r = tun_to_iroh => r??,
        r = iroh_to_tun => r??,
    }

    Ok(())
}

async fn tun_read_loop(
    tun: TunDevice,
    conn: Connection,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = tun.read_packet(&mut buf) => {
                let n = result?;
                if n > 0 {
                    match conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                        Ok(()) => stats.record_tx(n),
                        Err(_) => stats.record_drop(),
                    }
                }
            }
            Some(packet) = incoming.recv() => {
                tun.write_packet(&packet).await?;
            }
        }
    }
}

async fn iroh_read_loop(
    conn: Connection,
    tun_tx: mpsc::Sender<Vec<u8>>,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = conn.read_datagram() => {
                let datagram = result?;
                stats.record_rx(datagram.len());
                if tun_tx.send(datagram.to_vec()).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}
