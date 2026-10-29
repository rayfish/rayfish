#!/usr/bin/env bash
# Run the complete scenario as an ordinary user in an isolated container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BINARY="$(python3 - "$ROOT" <<'PY'
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
if not target.is_absolute():
    target = root / target
binary = Path(os.environ.get("RAY_BIN", target / "debug/ray")).expanduser().resolve()
if not binary.is_file() or not os.access(binary, os.X_OK):
    raise SystemExit("ray binary missing: run cargo -q build, or set RAY_BIN")
print(binary)
PY
)"

exec docker run --rm --init --read-only \
  --cap-drop ALL --security-opt no-new-privileges --user 65532:65532 \
  --pids-limit 256 --memory 2g \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --env HOME=/tmp --env RAY_BIN=/usr/local/bin/ray \
  --mount "type=bind,src=$BINARY,dst=/usr/local/bin/ray,readonly" \
  --mount "type=bind,src=$ROOT/tests/e2e/rootless/run.py,dst=/suite/tests/e2e/rootless/run.py,readonly" \
  python:3.11-slim python3 -c '
import os
from pathlib import Path
import runpy

assert os.geteuid() != 0
status = Path("/proc/self/status").read_text().splitlines()
assert int(next(line.split()[1] for line in status if line.startswith("CapEff:")), 16) == 0
assert not Path("/dev/net/tun").exists()
print("PASS: ordinary container user, zero capabilities and no TUN device", flush=True)
runpy.run_path("/suite/tests/e2e/rootless/run.py", run_name="__main__")
'
