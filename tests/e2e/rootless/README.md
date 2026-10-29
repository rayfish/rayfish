# Rootless mesh E2E

```bash
cargo -q build
tests/e2e.sh rootless
```

Requires Linux, Python 3.10+ and an ordinary user. No sudo, Docker or TUN device is
needed. Uses normal iroh discovery and relay connectivity.

Two real daemons use temporary private state and ephemeral loopback listeners.
Both firewalls stay enabled. The test creates a private network, joins by invite,
checks automatic IPC selection and rejected credentials, then exercises streamed
HTTP, SOCKS5 and CONNECT against explicitly exposed fixtures. Tunnel checks send
large payloads and half-close before reading the response. CONNECT also sends
bytes before receiving its success response.

`RAY_BIN=/path/to/ray` selects another binary. Otherwise the test uses
`${CARGO_TARGET_DIR:-target}/debug/ray`. Shutdown removes private IPC sockets;
failure cleanup stops both daemons and deletes their state. Diagnostics report
stages and error counts without credentials or raw daemon logs.

`tests/e2e.sh rootless provision` and `teardown` are no-ops.

For an isolated Docker run:

```bash
E2E_BACKEND=docker tests/e2e.sh rootless
```

Both daemons run in one container as an ordinary user, with a read-only root
filesystem, no capabilities and no TUN device. The binary and test are mounted
read-only. Docker is required on the runner; nothing runs through sudo.
