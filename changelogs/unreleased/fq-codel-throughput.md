### Performance

- The `fq-codel` forwarding engine lets QUIC queue about 3 ms of traffic instead of a fixed 16 KiB, which raises its throughput on fast links by roughly a quarter while keeping latency on slow links where it was.
