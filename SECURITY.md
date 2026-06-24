# Security Policy

## Supported versions

Rayfish is pre-1.0. Security fixes are applied to the latest released version
and `master`. Please upgrade to the latest release before reporting an issue.

| Version | Supported |
| ------- | --------- |
| latest release / `master` | ✅ |
| older releases | ❌ |

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public
GitHub issue.

- Preferred: [GitHub private vulnerability reporting](https://github.com/rayfish/rayfish/security/advisories/new).
- Or email **dario@rayfish.xyz**.

Include enough detail to reproduce: affected version/commit, configuration, and
a description (ideally a proof of concept). We will acknowledge your report,
keep you updated on remediation, and credit you in the release notes unless you
prefer to remain anonymous.

## Security model (context for reviewers)

A few load-bearing properties, so reports can be scoped accurately:

- **Identity, not IP.** Peers are addressed by cryptographic identity
  (EndpointId); virtual addresses are derived from the identity and transport is
  end-to-end encrypted by iroh.
- **Discovery vs. admission.** A network's room id (public key) is a *discovery*
  key published to the DHT — on a closed network it is **not** sufficient to
  join. Admission runs through the coordinator via single-use invites or live
  approval.
- **Signed group state.** The per-network pkarr record is signed by the network
  secret key (the pkarr address *is* the network public key), so the `GroupBlob`
  and the firewall suggestions that ride in it are MITM-resistant. Suggested
  firewall rules are consumed only from the verified blob, never from a peer
  control message.
- **Local privilege.** The daemon authorizes each IPC request by the caller's
  UID (`SO_PEERCRED`), not by socket file permissions. Mutating commands require
  root or the configured operator.
- **Secrets at rest.** Invite ledgers are written `0600`; invite secrets are
  stored only as blake3 hashes; identity backups are encrypted (argon2 +
  chacha20poly1305). `ray report` bundles a *sanitized* status with no secret
  keys.
