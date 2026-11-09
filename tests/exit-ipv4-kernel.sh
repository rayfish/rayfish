#!/usr/bin/env bash
# IPv4 and IPv6 kernel routing tests. No external network or host routes.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target
cargo -q test --locked -p rayfish --test exit_ipv4_kernel --test exit_ipv6_kernel --no-run --message-format=json > target/exit-ipv4-build.json
binaries=$(python3 -c 'import json; print("\n".join(m["executable"] for line in open("target/exit-ipv4-build.json") if (m:=json.loads(line)).get("executable") and m.get("target",{}).get("name") in ("exit_ipv4_kernel", "exit_ipv6_kernel")))')
docker build -q -t rayfish-exit-ipv4-test -f tests/docker/exit-ipv4.Dockerfile tests/docker >/dev/null
while IFS= read -r binary; do
    docker run --rm --network none --privileged -e RAYFISH_ISOLATED_KERNEL_TEST=1 -v "$binary:/test:ro" rayfish-exit-ipv4-test /test --ignored --nocapture
done <<< "$binaries"
