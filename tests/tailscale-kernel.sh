#!/usr/bin/env bash
# Test Tailscale path exclusion without external networking or host rule changes.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p "${CARGO_TARGET_DIR:-target}"
build_info=$(mktemp "${CARGO_TARGET_DIR:-target}/tailscale-build.XXXXXX")
trap 'rm -f "$build_info"' EXIT
cargo -q test --locked -p rayfish --lib --no-run --message-format=json > "$build_info"
binary=$(python3 -c 'import json,sys; print(next(m["executable"] for line in open(sys.argv[1]) if (m:=json.loads(line)).get("executable") and m.get("target",{}).get("name")=="rayfish"))' "$build_info")
docker build -q -t rayfish-tailscale-test -f tests/docker/tailscale.Dockerfile tests/docker >/dev/null
docker run --rm --network none --privileged --cgroupns private -e RAYFISH_ISOLATED_KERNEL_TEST=1 \
  -v "$binary:/test:ro" rayfish-tailscale-test /test --ignored --exact \
  hostfw::tailscale::tests::marked_udp_is_excluded_from_mesh_paths --nocapture
