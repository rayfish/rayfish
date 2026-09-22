use std::sync::Arc;

use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use tokio::sync::mpsc;

use crate::PacketFlow;

pub(crate) const PACKET_QUEUE_CAPACITY: usize = 256;

pub(crate) struct AppleTunReader {
    packets: mpsc::Receiver<Vec<u8>>,
}

impl AppleTunReader {
    pub(crate) fn new(packets: mpsc::Receiver<Vec<u8>>) -> Self {
        Self { packets }
    }
}

impl rayfish::tun::TunRead for AppleTunReader {
    async fn read_into(&mut self, buf: &mut BytesMut) -> Result<usize> {
        let packet = self
            .packets
            .recv()
            .await
            .context("packet tunnel flow closed")?;
        if packet.len() > usize::from(rayfish::tun::TUN_MTU) {
            bail!("packet tunnel flow produced an oversized packet");
        }
        buf.extend_from_slice(&packet);
        Ok(packet.len())
    }
}

pub(crate) struct AppleTunWriter {
    flow: Arc<dyn PacketFlow>,
}

impl AppleTunWriter {
    pub(crate) fn new(flow: Box<dyn PacketFlow>) -> Self {
        Self { flow: flow.into() }
    }
}

impl rayfish::tun::TunWrite for AppleTunWriter {
    fn write_packet(&mut self, packet: &[u8]) -> impl Future<Output = Result<()>> + Send {
        let flow = Arc::clone(&self.flow);
        let packet = packet.to_vec();
        async move {
            flow.write_packet(packet);
            Ok(())
        }
    }
}
