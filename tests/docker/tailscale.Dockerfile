FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables iptables ca-certificates && rm -rf /var/lib/apt/lists/*
