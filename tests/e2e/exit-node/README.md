# exit-node e2e

Three DigitalOcean Linux hosts: one exit gateway, one allowed client, and one
client outside the gateway's allow-list.

```sh
./tests/e2e.sh exit-node
./tests/e2e.sh exit-node teardown
```

The scenario checks:

- Gateway forwarding, IPv4 lease routing, NAT, and signed exit advertisement.
- IPv4 egress through the gateway, plus IPv6 when both hosts have connectivity.
  A family the gateway cannot carry stays blocked while selected.
- Mesh transport and inbound SSH connections survive full-tunnel selection.
- Existing outbound TCP connections keep working; new connections forced onto
  the physical uplink are blocked.
- LAN access, Docker-style bridges, and routes owned by another VPN keep working.
  Internet traffic forwarded from the bridge uses the selected exit.
- Public and mesh DNS resolve while the tunnel is selected.
- Losing the tunnel default route does not leak traffic through the uplink.
- A client outside the allow-list gets no internet through the gateway or its
  own uplink while the exit is selected.
- Deselecting the exit restores direct egress and removes client kernel state.
  Stopping the gateway restores forwarding settings and removes NAT and leases.

Before each selection, the harness arms a timed recovery command on the client.
If a routing regression cuts off SSH, the client clears the selection and
restarts its tunnel. Successful checks cancel the recovery command.
