---
paths:
  - "src/control.rs"
  - "src/membership.rs"
  - "src/invite.rs"
  - "src/transport.rs"
  - "src/identity.rs"
  - "src/firewall.rs"
  - "src/apply.rs"
  - "ray-proto/src/*.rs"
---

# Changing the wire

**ALPN negotiation is the only compatibility gate** (`rayfish/{mesh,files,pair,connect}/<v>`). There is no in-band version handshake, so an incompatible change bumps that protocol's version **in the same commit**. Wire format is a 4-byte BE length plus msgpack; TUN MTU is 1280.

Control frames, the pair/connect/files protocols and `canonical_group_bytes` are msgpack **array**-encoded (`rmp_serde::to_vec`). A struct's declaration order *is* the wire format, and its field count is part of it.

- **Adding, removing, retyping or reordering a field each need a version bump.** Appending with `#[serde(default)]` buys one direction only: a new build defaults an older peer's shorter array, but an older build rejects the longer one whole.
- **Reordering is the dangerous one.** Between differently-typed fields it errors loudly. Between two `bool`s it decodes clean and silently swapped, and the diff looks like a moved line.
- **Never put `skip_serializing_if` on a wire struct.** In an array there is no key to omit, so a skipped field shifts every later field one place left. This shipped once in `HostSuggestions` and turned every coordinator `deny` into an `allow`.
- **A `Member` field is not a free additive change.** The roster blob is array-encoded but rides `iroh_blobs`' shared, unversioned ALPN, so nothing stops an old peer fetching bytes it cannot decode. Bump the mesh version so the ALPN splits the network visibly instead.
- **Two callers stay on `to_vec_named` and must not be "made consistent":** `identity::store_device_cert` (on disk, no ALPN gate, and a re-encode strands every paired device) and IPC (`ray-proto/src/ipc.rs`, no version negotiation, read by a CLI swapped before the daemon restarts). `skip_serializing_if` is safe in those two.

Tests in `membership.rs` pin the short-array default, the long-array rejection, and the silent bool swap. Keep them passing.
