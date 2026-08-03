#![cfg(windows)]

//! Windows adapter contracts that do not require Administrator, Wintun, or a
//! live mesh. Privileged MSI/service/DNS tests stay in the manual lane.

use bytes::BytesMut;
use rayfish::tun::{TunRead, TunWrite};

#[test]
fn console_process_does_not_claim_windows_service_dispatch() {
    assert!(
        !rayfish::windows_service::run_if_service()
            .expect("console invocation should return the dispatcher fallback")
    );
}

#[tokio::test]
async fn tun_ports_preserve_packet_bytes_across_the_interface() {
    let packet = b"windows-contract-packet".to_vec();
    let mut reader = OnePacketReader {
        packet: Some(packet.clone()),
    };
    let mut buf = BytesMut::new();

    let read = reader
        .read_into(&mut buf)
        .await
        .expect("fake reader should yield one packet");
    assert_eq!(read, packet.len());
    assert_eq!(&buf[..], packet.as_slice());

    let mut writer = RecordingWriter::default();
    writer
        .write_packet(&buf)
        .await
        .expect("fake writer should accept one packet");
    assert_eq!(writer.packets, vec![packet]);
}

struct OnePacketReader {
    packet: Option<Vec<u8>>,
}

impl TunRead for OnePacketReader {
    async fn read_into(&mut self, buf: &mut BytesMut) -> anyhow::Result<usize> {
        let packet = self
            .packet
            .take()
            .ok_or_else(|| anyhow::anyhow!("fake reader closed"))?;
        let len = packet.len();
        buf.extend_from_slice(&packet);
        Ok(len)
    }
}

#[derive(Default)]
struct RecordingWriter {
    packets: Vec<Vec<u8>>,
}

impl TunWrite for RecordingWriter {
    async fn write_packet(&mut self, packet: &[u8]) -> anyhow::Result<()> {
        self.packets.push(packet.to_vec());
        Ok(())
    }
}
