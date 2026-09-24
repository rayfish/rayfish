use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use rayfish::tun::{TUN_MTU, TunRead, TunWrite};
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

impl TunRead for AppleTunReader {
    async fn read_into(&mut self, buf: &mut BytesMut) -> Result<usize> {
        let packet = self
            .packets
            .recv()
            .await
            .context("packet tunnel flow closed")?;
        if packet.len() > usize::from(TUN_MTU) {
            bail!("packet tunnel flow produced an oversized packet");
        }
        buf.extend_from_slice(&packet);
        Ok(packet.len())
    }
}

pub(crate) struct AppleTunWriter {
    flow: Box<dyn PacketFlow>,
}

impl AppleTunWriter {
    pub(crate) fn new(flow: Box<dyn PacketFlow>) -> Self {
        Self { flow }
    }
}

impl TunWrite for AppleTunWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.flow.write_packet(packet.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[tokio::test]
    async fn reader_appends_packets_and_reports_closed_flow() {
        let (sender, receiver) = mpsc::channel(PACKET_QUEUE_CAPACITY);
        let mut reader = AppleTunReader::new(receiver);
        let mut buffer = BytesMut::from(&b"prefix"[..]);
        sender.send(b"packet".to_vec()).await.unwrap();
        assert_eq!(reader.read_into(&mut buffer).await.unwrap(), 6);
        assert_eq!(&buffer[..], b"prefixpacket");
        drop(sender);
        assert!(reader.read_into(&mut buffer).await.is_err());
    }

    #[tokio::test]
    async fn reader_rejects_oversized_packets_without_changing_buffer() {
        let (sender, receiver) = mpsc::channel(PACKET_QUEUE_CAPACITY);
        let mut reader = AppleTunReader::new(receiver);
        let mut buffer = BytesMut::from(&b"prefix"[..]);
        sender
            .send(vec![0; usize::from(TUN_MTU) + 1])
            .await
            .unwrap();
        assert!(reader.read_into(&mut buffer).await.is_err());
        assert_eq!(&buffer[..], b"prefix");
    }

    struct RecordingFlow(Arc<Mutex<Vec<Vec<u8>>>>);

    impl PacketFlow for RecordingFlow {
        fn write_packet(&self, packet: Vec<u8>) {
            self.0.lock().unwrap().push(packet);
        }
    }

    #[tokio::test]
    async fn writer_delivers_packets_to_the_flow() {
        let packets = Arc::new(Mutex::new(Vec::new()));
        let mut writer = AppleTunWriter::new(Box::new(RecordingFlow(Arc::clone(&packets))));
        writer.write_packet(b"packet").await.unwrap();
        assert_eq!(*packets.lock().unwrap(), [b"packet".to_vec()]);
    }
}
