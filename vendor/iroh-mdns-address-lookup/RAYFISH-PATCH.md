Based on the crates.io release iroh-mdns-address-lookup 0.4.0 (MIT OR Apache-2.0), from https://github.com/n0-computer/iroh-address-lookups.

Local changes: configurable discovery cadence; cache and compare endpoint information instead of Peer timestamps; replace cached information after address changes. Rayfish selects five seconds for its long-lived discovery service. The upstream interactive default remains unchanged for other callers. The underlying swarm-discovery computes peer-expiry grace from the chosen cadence. This also means peers running the older interactive cadence may temporarily expire slower-advertising peers; update LAN peers together for consistent discovery.

This patch can be removed when an upstream release provides these controls and fixes. No device diagnostics are included.
