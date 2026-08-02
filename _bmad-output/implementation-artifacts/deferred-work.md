# Deferred work from Windows port review

These items are outside the approved issue #25 v1 boundary or require a release/UX decision.

| Priority | Item | Reason |
|---|---|---|
| High | Make `ray update` download and launch the signed Windows MSI | The current updater swaps executable assets; MSI upgrade needs a separate elevation and rollback flow. |
| Medium | Cap concurrent named-pipe handlers and add a global transfer quota | Per-read timeout and startup stale-upload cleanup now bound idle transfers; fleet-wide resource policy remains to be chosen. |
| Medium | Preserve IPv6 DNS upstreams and make NRPT updates transactional | Existing `DnsConfigurator` contract stores IPv4 upstreams; extending it changes cross-platform state shape. |
| Medium | Implement Windows `files download-user` auto-accept | The current Windows port intentionally focuses on bounded outbound in-band sends. |
| Low | Make the standalone Wintun verifier always require the pinned archive hash | CI already passes `-ArchivePath`; changing the default CLI contract needs packaging UX review. |
