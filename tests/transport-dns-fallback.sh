#!/usr/bin/env bash
# Outbound DNS fallback with plain DNS blocked inside an isolated container.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo -q test --locked -p rayfish --lib --no-run --message-format=json > target/transport-dns-build.json
binary=$(python3 -c 'import json; print(next(m["executable"] for line in open("target/transport-dns-build.json") if (m:=json.loads(line)).get("executable") and m.get("target",{}).get("name")=="rayfish"))')
docker build -q -t rayfish-exit-ipv4-test -f tests/docker/exit-ipv4.Dockerfile tests/docker >/dev/null
docker run --rm -i --cap-add NET_ADMIN -e RAYFISH_BLOCK_PLAIN_DNS_TEST=1 -v "$binary:/test:ro" rayfish-exit-ipv4-test bash <<'CONTAINER'
set -euo pipefail
nft -f - <<'RULES'
table inet block_plain_dns {
    chain output {
        type filter hook output priority 0; policy accept;
        udp dport 53 drop
        tcp dport 53 drop
    }
}
RULES
/test --ignored --nocapture transport::dns::tests::public_discovery_dns_survives_blocked_plain_dns
CONTAINER
