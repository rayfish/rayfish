#!/usr/bin/env bash
# Kernel routing test. No external network, published ports, or host routes.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo -q test --locked -p rayfish --test exit_ipv4_kernel --no-run --message-format=json > target/exit-ipv4-build.json
binary=$(python3 -c 'import json; print(next(m["executable"] for line in open("target/exit-ipv4-build.json") if (m:=json.loads(line)).get("executable") and m.get("target",{}).get("name")=="exit_ipv4_kernel"))')
docker build -q -t rayfish-exit-ipv4-test -f tests/docker/exit-ipv4.Dockerfile tests/docker >/dev/null
docker run --rm --network none --privileged -e RAYFISH_ISOLATED_KERNEL_TEST=1 -v "$binary:/test:ro" rayfish-exit-ipv4-test /test --ignored --nocapture
