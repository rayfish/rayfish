# Rayfish for iOS

A SwiftUI app with a packet tunnel app extension. The extension hosts the Rust
core from `ray-mobile` and owns the utun; the app talks to it with provider
messages (`Shared/Protocol.swift`). `project.yml` is the XcodeGen source.

```bash
just ios-sim        # build, then run the UI walkthrough in the simulator
just ios            # generate and open the project for a device build
just ios-run        # build, install, and launch on a connected iPhone
just ios-bindings   # regenerate Generated/ after a ray-mobile API change
```

## Simulator

Packet tunnels do not run in the simulator. The simulator build starts the
node inside the app instead (`SimulatorTunnel`), so networks, invites,
pairing, files and identity backup all work there. Only traffic through the
tunnel needs a device.

## Device

Needs a paid Apple developer team and an iPhone paired with Xcode with
Developer Mode enabled. `just ios-run` uses the local Apple Development
certificate's team; `IOS_TEAM_ID` overrides it. Pass a device ID or name
to select one, for example `just ios-run "My iPhone"`.

Enable these capabilities for `xyz.rayfish.ios`, `xyz.rayfish.ios.tunnel` and
`xyz.rayfish.ios.controls` (the Control Center toggle, iOS 18 and later):

- Network Extensions: Packet Tunnel
- App Groups: `group.xyz.rayfish.ios`

## Differences from Android

- The node runs only while the VPN is on. With it off, the app answers from
  the saved config, and backup and restore work, but peers cannot reach this
  device and files do not move.
- iOS limits a packet tunnel extension to about 50 MiB of memory. The core
  runs two tokio workers on iOS for that reason.
- The extension cannot write where the Files app looks. Downloads land in the
  shared container and the app moves them into its Documents folder the next
  time it is opened.
- Peer traffic uses `200::/7`. DNS covers only `.ray` names; other lookups
  stay on the system resolver.
- The batched `sendmsg_x`/`recvmsg_x` utun path used on macOS is private API
  and stays off on iOS.
- No crash telemetry, quick settings tile or share extension yet.
