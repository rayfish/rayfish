### Performance

- Linux peers use TUN offload and QUIC UDP segmentation together to improve throughput. If the kernel rejects segmented UDP sends, existing connections fall back to single datagrams.
