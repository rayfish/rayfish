# `closed-net` e2e scenario

Three hosts on a closed network `priv` (coordinator `srv-a`, members `srv-b` and
`srv-c`), exercising the admission + lifecycle command surface the other
scenarios don't cover.

## What it proves

| Step | Coverage |
|------|----------|
| 2 | **Live approval** with no invite: `srv-b` dials the closed net → `ray requests` shows it → `ray requests <net> accept` admits it. |
| 3 | **Live denial**: `srv-c` dials → `ray requests <net> deny` rejects it → it never becomes a member. |
| 4 | **Co-coordinator grant**: `ray admin add` promotes `srv-b`; `ray admin list` shows two key-holders. |
| 5 | **Gatekeeper resilience**: with `srv-a` taken offline (`ray down`), the co-coordinator `srv-b` mints a `ray invite --reusable` key and admits `srv-c` unattended (`--auto-accept-firewall`). |
| 6 | **Hostname change**: `ray hostname` propagates to the coordinator's roster and the magic-DNS name `srv-bb.priv.ray` resolves + answers. |
| 7 | **Graceful leave + nuke**: `ray leave` prunes the member promptly; `ray nuke` drops the network. |
| 8 | **`ray apply` smoke**: `--example` prints a template and `--dry-run` normalizes a spec without creating anything. |

Single-use invite redemption is already covered by the `device-cert` scenario.

## Run

```bash
tests/e2e.sh closed-net            # provision (if needed) + deploy + drive + assert
tests/e2e.sh closed-net teardown   # destroy the instances
```

See [`../README.md`](../README.md) for prerequisites and environment overrides.
