# iroh-mdns-address-lookup

mDNS-based address lookup for [iroh](https://github.com/n0-computer/iroh).

This crate uses an mDNS-like swarm discovery service to find address
information about endpoints on your local network — no relay or outside
internet needed. See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery)
crate for more details.

When `MdnsAddressLookup` is enabled, you can get a stream of locally
discovered endpoints by calling `MdnsAddressLookup::subscribe`.

```rust,no_run
use std::time::Duration;

use iroh::endpoint::{Endpoint, presets};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;

#[tokio::main]
async fn main() {
    let endpoint = Endpoint::bind(presets::Minimal).await.unwrap();

    // Register the address lookup with the endpoint.
    let mdns = MdnsAddressLookup::builder().build(endpoint.id()).unwrap();
    endpoint.address_lookup().unwrap().add(mdns.clone());

    // Subscribe to the mdns discovery events.
    let mut events = mdns.subscribe().await;
    while let Some(event) = events.next().await {
        match event {
            DiscoveryEvent::Discovered { endpoint_info, .. } => {
                println!("MDNS discovered: {:?}", endpoint_info);
            }
            DiscoveryEvent::Expired { endpoint_id } => {
                println!("MDNS expired: {endpoint_id}");
            }
            _ => {}
        }
    }
}
```

## Filtering

By default, `MdnsAddressLookup` publishes all addresses it receives:
direct IP addresses and up to one `RelayUrl`. The following constraints
apply regardless of any user-supplied filter:

- Only the first `RelayUrl` in the address set is published.
- A `RelayUrl` longer than 249 bytes is silently dropped.

You can supply an `iroh::address_lookup::AddrFilter` via
`MdnsAddressLookupBuilder::addr_filter` to control which addresses are
published and in what order.

## License

Copyright 2025 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
