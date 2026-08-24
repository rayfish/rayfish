# Changelog

All notable changes to Rayfish are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Exit nodes tunnel IPv6.** `ray exit-node use` routes your IPv6 internet
  traffic through the gateway and leaves your IPv4 traffic leaving directly,
  which both `ray exit-node use` and `ray exit-node status` say out loud rather
  than leaving you to find out from a leak test. The mesh carries no IPv4, so
  there is no IPv4 for a tunnel to source transit from; claiming your IPv4
  default would take it from whatever else is using the box and send it into a
  hole. Offering an exit node is unaffected.
- **A gateway that cannot carry IPv6 is refused, with a reason.** Gateways report
  whether they have an IPv6 uplink, and ones that do are marked `(IPv6)` in
  `ray exit-node status`. Picking one that reports otherwise is refused rather
  than left to time out. The check runs on every re-apply, not only when you
  pick, so a gateway that loses its uplink stops tunnelling with a message
  instead of silently carrying nothing, and picks the tunnel back up by itself
  when it reports one again. A gateway on a network whose coordinator predates
  this feature reports nothing either way: it stays selectable, since refusing
  would rule out every gateway on such a network, and `ray exit-node use` tells
  you the claim is unverified.
- **DNS follows the tunnel.** While a tunnel is up, the daemon's own DNS
  forwarder is pointed at an IPv6 resolver, so its lookups go through the exit
  rather than around it. On Linux hosts using systemd-resolved or resolvconf,
  applications' non-`.ray` lookups still leave directly, and the daemon logs a
  warning saying so. If you pinned your own resolvers with `ray config set
  dns-upstreams … --replace` and none of them are IPv6, yours are kept rather
  than swapped for public ones: they stay reachable over the IPv4 a tunnel
  leaves direct, so those lookups go around the exit instead of to a resolver
  you did not choose.
- **`ray config set dns-upstreams` takes IPv6 addresses.** Naming only IPv6
  servers no longer lets rayfish take over `/etc/resolv.conf` on a host where it
  found no working resolver of its own: those entries are reachable only through
  the tunnel, so counting them would have taken the file and left the machine
  unable to resolve anything.
- **Android notifies you when someone sends you a file.** An incoming file from
  another peer used to arrive in silence: notifications only covered transfers
  that were already under way, and a file waiting on your decision has no
  transfer behind it yet, so the only place it appeared was the app's own list.
  Sent while the app was closed, it sat there unannounced until you next opened
  it. There is now a notification naming the file, who sent it and how big it
  is, with Save and Reject on it so you can take the file without opening the
  app at all. Files from your own paired devices are unaffected: those are still
  saved automatically and reported as they download.
- **`ray logs`: read the daemon's log without hunting for the files.** The logs
  are root-owned under `/var/log/rayfish` (`/Library/Logs/rayfish` on macOS),
  so until now looking at them meant `sudo cat` and knowing which file, or
  `ray report`, which bundles a week of them into a tarball meant for sharing.
  `ray logs` prints today's, from the daemon over IPC, so it needs no root:

  ```bash
  ray logs                 # everything since the last daily rotation
  ray logs --since 2h30m   # only the last two and a half hours
  ray logs -f              # keep streaming new lines, like tail -f
  ray logs --since 5m -f   # the last five minutes, then keep streaming
  ```

  Output goes through `$PAGER` (`less`) on a terminal and straight through
  when piped or following, so `ray logs | grep peer` and `ray logs -f` both
  behave the way you would expect.
- **Tab completion covers the ids you copy out of a listing.** `ray requests
  <net> accept`, `ray requests <net> deny`, `ray connect approve`, `ray invite
  <net> revoke`, `ray files accept`, `ray files cancel` and `ray firewall
  remove` now complete their argument from what is actually waiting, each
  candidate carrying who or what it refers to, so an id printed one line up no
  longer has to be retyped. `ray requests <net>` joins the other listings in
  being readable by any local user, so the tab answers without sudo; admitting
  still needs root or the operator.

### Changed

- **Nodes on this version and older ones cannot see each other.** The member
  list changed shape, and it is served over a channel that has no version check
  of its own, so an older node would fetch the new list and fail to read it on
  every refresh. The mesh protocol version is bumped instead, which splits the
  network where the split is visible: peers on different versions do not connect,
  and `ray status` says so. The device pairing and `ray connect` protocols are
  bumped for the same reason. Upgrade coordinators and members together.

- **A join with no `--hostname` takes this machine's name.** `ray create` and
  `ray join` used to fall back to a random noun, so `ray status` on a fleet read
  as a list of animals nobody could match to a box. They now use the machine's
  own hostname, folded into a mesh name (`Alice's MacBook.local` becomes
  `alice-s-macbook`). A random name is still used when the machine has nothing
  usable to offer (`localhost`, which is what Android reports) and when the name
  is already on the network you are joining, since `laptop-1` would read as the
  name of the `laptop` that is already there. `ray up --hostname <name>` still
  wins over both, and naming one explicitly is unaffected.

- **Rayfish is IPv6-only. Mesh IPv4 is gone.** Every peer had two mesh addresses:
  an IPv4 in `100.64.0.0/10` and an IPv6 in `200::/7`. Only the IPv6 remains.
  It is blake3 of the peer's identity, so it is collision-free, never rotates,
  and is derived locally by every node rather than carried on the wire. `ray
  status`, `ray ping`, Magic DNS, the exit node and the Android app all use it.
  A `.ray` name answers AAAA only; an A query returns NODATA, because there is
  no IPv4 address to give.

  Two consequences worth knowing before you upgrade:

  - **Every node must upgrade together.** The mesh protocol goes to 4 and peers
    on different versions cannot connect at all, so a node left behind stops
    seeing the network rather than degrading. `ray status` marks such a peer
    incompatible, and a join against a network on another version fails naming
    both.
  - **Check what your services listen on.** `0.0.0.0` is the IPv4 wildcard, not
    "any address", so a service bound there has no IPv6 socket and peers can no
    longer reach it. Bind `::` instead, which accepts both families on Linux.
    Go and Node already do this; nginx needs `listen [::]:80;` adding, and
    `--bind 0.0.0.0` defaults and Docker published ports need the flag changed.
    `ss -tlnp` shows which is which: `0.0.0.0:port` is affected, `[::]:port` is
    not.

- **`ipv6-only` is gone as a setting.** `ray config set ipv6-only` and `ray up
  --ipv6-only` no longer exist, and neither does the startup scan behind them.
  There is nothing left to choose: the overlay never claims `100.64.0.0/10`, so
  sharing a host with Tailscale needs no mode and no configuration. A stale
  `ipv6_only` key in `settings.toml` is ignored rather than an error.
- **Magic DNS answers at `200::53` only.** The old `100.100.100.53` is not used;
  an upgrade strips it from `/etc/resolv.conf` on the way through. Use
  `dig @200::53 <host>.ray`.
- **NetworkManager is no longer used to configure DNS.** Its D-Bus interface can
  only carry an IPv4 nameserver, so it cannot point the system at an IPv6
  resolver. The detection ladder falls through to resolvconf or a direct
  `/etc/resolv.conf`, both of which take either family.
- **The wire is more compact.** Control frames, pairing, `ray connect`, file
  transfer and the signed roster are array-encoded, taking a bit under 30% off
  the largest thing on the wire (a 50-member roster drops from 5194 to 3764
  bytes). Dropping the mesh IPv4 and its collision index takes more off again.
  This is part of what the protocol bump above covers. Nothing on disk changes,
  so upgrading in place keeps your networks, identity and pairings.

- **`ray firewall --help` is grouped, and every help page reads in one pass.**
  The firewall's 13 actions are now listed under Rules, Mode, Coordinator
  suggestions and Mesh SSH, the way `ray --help` has been grouped for a while.
  Everywhere else, a command's one-line summary is now actually one line:
  descriptions that ran to a full paragraph on a single unwrapped line have
  been cut back to a summary, with the detail moved into
  `ray help <command> <action>`, which now wraps to your terminal instead of
  printing one very long line.
- **Four commands moved next to the thing they act on.** `ray connections` is
  now `ray connect` (bare, it lists incoming requests) and `ray connections
  approve <id>` is `ray connect approve <id>`. `ray accept <net> <id>` and
  `ray deny <net> <id>` are now `ray requests <net> accept <id>` and
  `ray requests <net> deny <id>`. `ray auto-update on|off` is now
  `ray config set auto-update on|off`. The old spellings all still work, so
  existing scripts are unaffected; they no longer appear in `ray --help` or in
  tab completion. `ray open` (the `rayfish://` link handler, which nobody types)
  is hidden for the same reason.
- **Android 8.0 (API 26) is now the minimum.** Every notification the app posts
  goes through a notification channel, which is an 8.0 API, so on 7.x the calls
  threw and were swallowed: transfers and incoming files were announced by
  nothing at all, on a build that otherwise looked like it worked. Rather than
  keep a tier where the app is quietly half-functional, 7.x is dropped. Android
  8.0 and later are unaffected.
- **The address on the mobile app's rows is readable again.** A node's only
  address is now a full mesh IPv6, which did not fit on one line beside its
  label, so it was ellipsised in the middle: unreadable, and impossible to check
  against `ray status`. Those rows wrap to a second line instead.
- **The mobile app stops waking the radio every minute.** Every node used to
  re-resolve each network's signed record once a minute, whether or not
  anything had changed, which on a phone is a wakeup per network per minute for
  a day at a time. On Android that poll now runs every 15 minutes and is a
  backstop rather than the mechanism: coordinators push membership changes to
  members directly, and the poll runs immediately when the VPN comes up, so a
  kick, a firewall suggestion or a new member still lands right away. Desktop
  and server nodes keep the 60-second poll.

### Fixed

- **Android: `.ray` names now open in Chrome on an IPv4-only network.** The
  browser showed `DNS_PROBE_FINISHED_NXDOMAIN` for a name that every other app
  on the phone resolved fine. Chrome only asks for an IPv6 address once it has
  checked that IPv6 works, by connecting to a fixed global address, and on a
  Wi-Fi with no IPv6 that check failed. It then asked for an IPv4 address alone,
  which the mesh does not have and never will, so nothing on the mesh was
  reachable by name from the browser. The tunnel now carries a route for that
  check, and only on networks with no IPv6 of their own. Real IPv6 traffic is
  untouched.
- **Android: "Send diagnostics" now actually sends the diagnostics.** The button
  reported success and delivered an empty report: the log snapshot, the node
  health block, and the install and transport tags were all attached to the
  event in a way the Sentry SDK dropped on the way out, so every report for the
  past month arrived as a bare "rayfish diagnostics" line with nothing in it.
  There was no way to tell from the app, since the report itself went through.
  The same loss applied to the automatic report a node sends when it fails to
  start, which is the one report nobody is around to notice is empty. Both now
  carry their logs. A report that Sentry refuses also says "Diagnostics
  unavailable" instead of claiming it was sent.

- **A network running a different mesh protocol version no longer disappears
  from `ray status`.** Rejoining a saved network stopped at the version check, so
  a network whose coordinator had moved to a newer (or older) protocol was never
  registered and was listed nowhere at all: it read as gone, not as out of step.
  Such a network now appears marked `incompatible`, saying which version it runs
  and which your build speaks, with the same `ray update` nudge an incompatible
  peer already gets. Its peers stay unreachable, since the version gate is what
  it always was, and the daemon keeps watching: the network goes back to normal
  on its own once its coordinator republishes at a version you speak. A
  first-time `ray join` against such a network still fails with the version
  message, because there is no way for its coordinator to admit you.

- **`ray status` shows saved networks the daemon never brought up.** It looked
  for them in the config directory of whoever ran it, which on macOS is not the
  daemon's (the daemon runs as root, so its config lives under `/var/root`), and
  found an empty one it had just created. Any network whose restore was failing
  was therefore missing from the output entirely rather than listed as inactive.
  The daemon now reports them itself, along with why the last restore attempt
  failed, so the reason is on screen instead of only in the log.

- **A kicked member now actually leaves the network.** `ray kick` removed the
  member from the roster and cut its connection, but never told it *which*
  network it had been removed from: a connection close code cannot name one. The
  kicked node fell back to noticing at its next group poll, and all that does is
  stop polling, so the network stayed in `ray status` and on disk with the roster
  frozen at the moment of the kick: joined-looking, carrying no traffic, and
  needing a manual `ray leave` to clear. It now receives the same in-band,
  network-scoped notice the automatic (`ray ephemeral`) removal has always sent,
  confirms it against the signed record, and leaves that one network on its own.
  Other members were never affected: they reconverge from the published roster.

- **`ray` exits non-zero when a command fails.** Every command that talks to the
  daemon printed a rejection to stderr and then exited 0, so `ray join` on a
  spent invite, `ray exit-node use` on a gateway that cannot carry IPv6, and
  forty-odd others reported success to whatever ran them. They now exit 1.
  Scripts that only checked the exit status were being told every command
  worked; scripts that deliberately relied on the old behaviour will need
  updating. A reply the CLI does not recognise, which is what a `ray` binary
  and a daemon on different versions produce, exits non-zero for the same
  reason and now names the version skew as the likely cause.
- **Taking over `/etc/resolv.conf` no longer breaks DNS on a NetworkManager
  host that runs its own resolver.** With NetworkManager in `dns=dnsmasq` mode,
  the server rayfish found in `resolv.conf` is NetworkManager's own local
  forwarder, and telling NetworkManager to stop managing DNS is exactly what
  stops it. Rayfish checked for a working upstream *before* that, took the file
  over on the strength of a resolver it then shut down, and left the host unable
  to resolve anything outside `.ray`. The check now runs on both sides of that
  step, and the difference between them is the verdict: if servers that were
  answering a moment earlier stop, rayfish hands the file back and refuses the
  takeover with the reason, leaving the host with working DNS and no Magic DNS.
  A host with no working DNS to begin with (mid-boot, a link still associating)
  is an ordinary retry rather than that verdict, and the verdict itself has to
  hold twice before rayfish stops trying, so a passing failure no longer costs
  you Magic DNS until the next restart.
- **macOS: `ray down` no longer leaves the machine pointed at a dead resolver.**
  Bringing the data plane down removed rayfish's DNS configuration and then
  immediately wrote part of it back, so the Mac was left with a resolver entry
  naming an address that stops answering the moment the tunnel interface goes.
  With an exit node selected it was worse: the entry it restored was the
  catch-all one, so every name on the machine went to it, not just `.ray`.
- **macOS: a host that both offers and uses an exit node no longer advertises
  IPv6 it cannot carry.** Checking for an IPv6 uplink asked the routing table,
  which by then answered with the machine's own tunnel. It published itself as
  IPv6-capable on the strength of that, and clients that believed it got a
  tunnel with nowhere to send their traffic.
- **Offering an exit node no longer turns the host into an IPv4 router.**
  `ray exit-node allow` enabled IPv4 forwarding and installed an IPv4 NAT rule
  for `100.64.0.0/10` alongside the IPv6 ones. The mesh carries no IPv4, so
  there was nothing of ours for either to act on. On macOS and FreeBSD the NAT
  rule matched on the uplink rather than on the rayfish interface, so the only
  traffic it could still have caught belonged to another VPN sharing the host.
  Both are gone; teardown still restores the IPv4 forwarding setting, so a host
  that enabled it under an older release is put back as before.
- **Re-applying an exit node no longer lets traffic out around the tunnel while
  it rebuilds.** Every `ray exit-node` command, and every roster change that
  reaches a live tunnel, rebuilds the routing rules. The catch-all that sends
  traffic into the tunnel was torn down first and re-added last, so anything
  sent in between left the physical uplink with the host's own address. It now
  stays in place across the rebuild.
- **Using an exit node no longer cuts off another VPN on the same host.** The
  full tunnel's routing rules sit above the ones Tailscale (and anything else
  doing policy routing) installs, and their routes live in a table of their own
  rather than the main one, so turning our tunnel on black-holed them entirely.
  Their routes are now copied into the tunnel's own table, and their
  destinations are directed there, so that VPN keeps working. This covers
  connections that arrived over it too: an SSH session into this host over its
  Tailscale address used to die the moment `ray exit-node use` ran, because the
  replies are sourced from that address and took a rule that looks up the main
  routing table, where the route isn't.
- **`ray exit-node status` says when the exit node you picked is not actually
  carrying anything.** The selection is config and the tunnel is kernel state,
  and they are allowed to differ: a gateway that stops being usable does not
  clear your selection, so you can still see what to change. But the line read
  `using: <peer>` either way, while every packet left directly. It now says the
  selection is not in effect and why (the routing rules would not install, the
  data plane is down, the peer is not in the roster yet, or the gateway cannot
  carry the family this node tunnels).
- **`.ray` names now resolve alongside another VPN that manages
  `/etc/resolv.conf`.** On a host with no DNS manager (no systemd-resolved in
  the resolution path), Rayfish and a VPN like Tailscale both want that file.
  Rayfish used to refuse it and `.ray` names stopped resolving for anything
  that goes through the system resolver, and in the other start order the two
  overwrote each other every few milliseconds. Rayfish now shares the file
  instead: its resolver goes in ahead of the other VPN's, the other VPN's stays
  behind it as the next nameserver, both sets of search domains are kept, and
  everything outside `.ray` is forwarded to it. Both meshes resolve, whichever
  VPN wrote the file last. Rayfish writes at most once a minute, so the two
  cannot spin against each other, and it goes back to managing the file alone
  once the other VPN leaves.
- **The other VPN's names keep resolving too.** Sharing `/etc/resolv.conf`
  means Rayfish is asked first for every name on the host, including the other
  VPN's. Rather than relay those, Rayfish declines anything outside `.ray`, and
  the system resolver asks the next server in the file, which is the other
  VPN's. Its own DNS behaviour applies unchanged, nothing is proxied through
  Rayfish, and the two cannot end up forwarding to each other in a circle.
- **DNS comes back when the other VPN leaves.** Neither VPN overwrites a
  `/etc/resolv.conf` the other is holding, so one that shuts down leaves its
  resolver named in a file nobody will correct. Rayfish now notices that
  resolver has stopped answering and releases DNS, so the host regenerates the
  file and Rayfish takes it over again, instead of the machine being left
  pointed at a server that is gone.
- **Shutting down no longer takes the other VPN's DNS with it.** When Rayfish
  shares `/etc/resolv.conf`, `ray down` (and a crash, and a restart) removes
  only the lines Rayfish added, leaving the other VPN's resolver and search
  domains in place, rather than restoring a snapshot of the file from before
  either VPN was on the host.
- **Bare hostnames now resolve on hosts without a DNS manager.** `ping box`
  and `ssh box` worked through systemd-resolved but not on a machine where
  Rayfish manages `/etc/resolv.conf` or registers with `resolvconf`: the
  `<network>.ray` and `ray` search domains were only ever handed to
  systemd-resolved, so on those hosts only the full `box.homelab.ray` resolved.
  They are now written wherever DNS actually lives, and follow every join and
  leave.
- **Rayfish says so when another VPN's resolver outranks it.** With
  `resolvconf` in the path, both VPNs register a resolver and the system tries
  them in order, stopping at the first that answers. Second place never sees a
  `.ray` query, and Rayfish reported success anyway. It now logs which resolver
  is ahead of it and what to do about it.
- **The metrics endpoint no longer answers the local network.** The Prometheus
  exporter bound `0.0.0.0:9090`, so any device on the same Wi-Fi could read
  it. Its counters name every peer by mesh IP with per-peer round-trip times
  and traffic volumes, which is a usable picture of who a node talks to and
  when. It now binds `127.0.0.1:9090`. Scraping from the same machine is
  unaffected; if you scraped a node remotely, reach it over the mesh.
- **The mobile app no longer runs a metrics collector.** The Prometheus
  exporter and its per-peer sampling loop were started on Android too, waking
  the app every 60 seconds to measure connections for an endpoint that
  nothing on a phone can scrape. Neither is started there now.
- **Membership changes reach devices that aren't currently connected.** A
  coordinator's kick, firewall suggestion or roster edit was only delivered to
  peers holding a live connection at that moment. Phones and other on-demand
  nodes drop their links after a couple of idle minutes while remaining
  reachable, so they routinely missed the notification and worked from a stale
  roster until their next poll. Coordinators now dial those members to deliver
  it. Devices that are genuinely offline are left alone for five minutes
  between attempts rather than being re-dialed on every change.

### Security

- **A network's member list is no longer readable from its room id alone.** The
  room id is a discovery address, not a credential, but until now anyone holding
  one could look up the network and download the whole member list from it:
  every member's identity and mesh address, hostnames, who the coordinators are,
  which nodes offer an exit node, the suggested firewall rules, and the reusable
  key metadata. That held even for a closed network that would never have
  admitted the reader, which is what made a leaked invite a disclosure of the
  roster rather than just a spent credential. The member list is now encrypted
  under a per-network read key that travels in the code you share, so the room id
  still finds the network and no longer opens it.

  Because that key has to be in the code, **`ray create` and `ray invite` now
  print a longer one**, and `ray status` shows it in place of the bare room id.
  Codes you have already shared keep working: a network created before this
  version has no read key and its list stays readable until its coordinator
  restarts on this version, which is when the key is created. Members pick the
  key up automatically the next time they reconnect, or ask for it themselves if
  they were offline when it was created. Anyone removed from a network keeps the
  key they already had, so rotating it on `ray kick` is still to come.

- **Android: a device identifier no longer leaks onto unrelated crash reports.**
  The install id and network transport meant for diagnostics reports were being
  written somewhere longer-lived than the report itself, and turned up on an
  unrelated crash captured seconds later. They are now attached to the one event
  they belong to and to nothing else.

- **A peer could get past the inbound firewall with a fragmented IPv6 packet.**
  The packet parser read the protocol and ports at fixed offsets, so any packet
  carrying an IPv6 extension header (a fragment, hop-by-hop, routing or
  destination-options header) was recorded as protocol 44 with no ports. That is
  a single connection-tracking entry matching *every* such packet from that peer,
  so one ordinary outbound fragment (any UDP send larger than the 1280-byte
  tunnel MTU) opened a 30-second window in which that peer could reach any local
  port, whatever the firewall said. The parser now walks the header chain to the
  real protocol, so a chained packet is classified on its own ports. Fragments
  are refused outright, first one included: a fragment after the first carries no
  transport header to classify, and forwarding the first one alone would only put
  a datagram on the wire that the peer can never reassemble. So a datagram large
  enough to be fragmented does not cross the mesh. Lower your application's
  datagram size or let TCP
  handle it. Refusals are counted as `malformed` drops in `ray status`, so
  traffic that stops this way is visible rather than silent.
- **An exit node no longer gives its clients a route onto its own network.** A
  gateway refused to forward traffic into private IPv4 ranges, loopback and
  link-local, but an IPv6 LAN is normally a *global* prefix handed out by the
  ISP, which none of those checks can recognise. A client of the exit node could
  therefore reach every other machine on the gateway's LAN. The gateway now reads
  the prefixes it is directly attached to and refuses transit into them, which is
  what the IPv4 side already had for free.
- **Knowing a network's room id no longer lets a stranger talk to it.** A mesh
  control message is addressed to a network by its public key, and that key is
  a discovery key by design: it is in every invite code and it is the address
  the network publishes under. Nothing checked that the sender of such a
  message was actually in the network it named, so anyone who had ever seen an
  invite could reach the handlers meant for members. They are now refused
  unless the sender is on that network's roster, apart from the three messages
  by which a peer that is not on it yet legitimately makes contact (a join
  request, a hello, and a network-signed record, which is verified against the
  network key regardless of who carried it).
- **A device certificate is verified before it can speak for its user.**
  Certificates bind a device key to a user identity, and that binding is what
  the inbound firewall, mesh SSH authorization, and own-device file
  auto-accept match on. A peer that presented a certificate under its own key
  had that certificate recorded without its signature being checked, so an
  unsigned one naming somebody else handed the sender that person's firewall
  rules and SSH access on the receiving node. Certificates are now verified on
  every path, and one revoked with `ray unpair` grants nothing even though its
  signature stays valid forever.
- **Only a coordinator can say who was admitted.** The message announcing a new
  member was accepted from any sender. Acting on it seats the named peer at an
  address the message chose, publishes its `.ray` name, and routes to it, so an
  entry in a node's `.ray` DNS was something a stranger could place there until
  the next roster sync. It is now honored only from a coordinator.
- **A signed membership record cannot be rolled back to an older one.** A
  signature says who wrote a record, never when, and an old record for a network
  stays valid forever. Nodes compared only whether a record differed from the
  one they held, so replaying a copy the network had published earlier (which
  anyone holding the room id could have fetched) re-seated removed members,
  restored revoked devices, and reverted the suggested firewall. Records are now
  accepted only if they were authored after the last one applied, on both the
  mesh and the lookup path.
- **A pairing ticket now expires.** Opening a pairing session and never
  completing it left the daemon willing to certify a new device for whoever
  presented the ticket, indefinitely. Tickets are good for five minutes.
- **A `ray connect` link hands its key to the one peer it was made for.**
  Approving a direct connection makes the other peer a co-coordinator, since
  the link is symmetric. That rule keyed on the network rather than the peer,
  so anyone approved onto that network afterwards silently received the network
  key as well. The grant now follows the peer the link was created for.
- **A wrong guess no longer closes an open pairing window.** The pairing secret
  was consumed before it was compared, so any dial carrying the wrong bytes
  ended the pairing session and the real device had to start over. The secret
  now survives a mismatch, and the comparison is constant-time.
- **Queues a stranger could grow without limit are now bounded.** Incoming
  `ray connect` requests and incoming file offers are both capped the way
  pending join requests already were, dropping the oldest unanswered entry
  rather than growing forever on a dial anyone can make.
- **A leave from a peer that was never a member costs nothing.** Such a message
  still made a coordinator re-sign and republish its membership record and
  notify every member, each of whom answered with a lookup of their own. It is
  now ignored.

## [0.3.0] - 2026-08-15

Peers on 0.2.x still connect: the mesh protocol is unchanged (`rayfish/mesh/2`),
and the signed roster only gained an optional field older builds ignore. Two
things do break across versions. `--json` goes after the command now
(`ray status --json`, not `ray --json status`), and an invite code minted by
this build cannot be redeemed by a peer still on 0.2.x.

### Added

- **Run alongside Tailscale (or any VPN on `100.64.0.0/10`), without setting
  anything up.** Both claim that range, so until now one of the two lost its
  IPv4 half and the daemon refused to start. It now notices the other VPN at
  startup and runs the data plane over `200::/7` only, leaving the CGNAT range
  to it, saying so in the log and marking it `ipv6-only on (auto)` in
  `ray status`. Everything keeps working over IPv6: peers, mesh SSH, file
  transfer, and `.ray` names, which answer AAAA only so nothing hands an app an
  address that goes nowhere. Peers are told, too, so they stop handing out
  yours. Exit nodes are the exception; `ray exit-node use` says so.

  The mode ends when the other VPN does, since nothing is written to your
  config. To pin it either way: `ray config set ipv6-only on` keeps it on
  regardless, and `off` restores the old behaviour of refusing to start on such
  a host. `auto` (the default) hands the decision back to the daemon.

- **IPv6-only mode on Android**, under **You**, as Auto / On / Off with Auto the
  default. The case there is not another VPN (Android runs one at a time) but a
  carrier that hands the phone a `100.64.x.x` address of its own, which the
  tunnel would otherwise swallow whole. On Auto the app checks the device's own
  addresses each time the node starts and switches only when it finds one, so
  the mode follows the network you are on: the card says which way it went.
  Changing it reconnects, because the tunnel's addressing is fixed when it is
  built, so the node is rebuilt and the VPN comes back if it was on.

- **Tab completion, already installed.** The installer and `sudo ray up` write
  completion scripts for bash, zsh and fish into the directories those shells
  already search, so there is nothing to source and no rc file to edit: open a
  new shell and press tab. Completion is live rather than a frozen script, so it
  offers the networks and peers you actually have (`ray leave <TAB>`,
  `ray ping <TAB>`, `ray exit-node use <net> <TAB>`), scoped to the network you
  already named on the line, with each peer's mesh IP and state alongside it.
  Fixed-choice arguments (`in`/`out`, `allow`/`deny`, `on`/`off`, protocols)
  complete too. `ray config set <TAB>` lists every settings key with its
  one-line description, and `ray config set <key> <TAB>` offers that key's
  values where it has a fixed set (`on`/`off`, `allow`/`deny`) and stays out of
  the way where it doesn't. A tab never starts the daemon and gives up rather
  than blocking your shell if it is wedged. `ray uninstall` removes the
  scripts; `ray completions --install` sets them up on a binary-only install.

- **Mesh SSH supports port forwarding.** `ssh -L`, `ssh -D` and `ProxyJump`
  through a mesh host work now. Before, the embedded SSH server had no handler
  for forwarded connections, so every one of them was refused with "channel N:
  open failed: administratively prohibited" while the shell on the same
  connection kept working. Any peer allowed to log in can forward; the target
  socket is opened by the daemon on the remote host, so it reaches loopback-only
  services there, the same as a shell on that host.

- **Mesh SSH supports reverse forwarding, unix sockets and agent forwarding.**
  `ssh -R` publishes a port (or a unix socket) from your machine on the remote
  one, `ssh -L <port>:/path/to.sock` reaches a socket like docker's or
  gpg-agent's, and `ssh -A` gives the session an `SSH_AUTH_SOCK` that talks back
  to your agent, so keys stay on your machine. Reverse forwards bind loopback on
  the remote host, matching sshd's default `GatewayPorts no`. A socket forward
  is allowed only where the account you logged in as could have used or created
  that socket itself, so the root daemon doing the work grants nothing extra.

- **A mesh SSH login is a real login now.** An interactive session goes through
  the host's `login(1)`, so it gets what a directly-spawned shell skipped: the
  PAM account check (a locked or expired account is refused instead of let in),
  a proper PAM/logind session with its `XDG_RUNTIME_DIR` and resource limits,
  the utmp/wtmp records behind `who` and `last`, `/etc/nologin`, and the motd.
  Root sessions and non-interactive commands still spawn the shell directly:
  `login` refuses root on a pseudo-terminal, by hanging rather than failing.
  Set `RAYFISH_SSH_NO_LOGIN=1` on the daemon to turn the handoff off.

- **Sessions know they are remote.** `SSH_CONNECTION`, `SSH_CLIENT` and (on a
  terminal) `SSH_TTY` are set, so prompts, `screen`, and scripts that check
  whether they are running over SSH behave the way they do everywhere else.

- **Mesh SSH passes locale environment variables and signals.** `SendEnv` /
  `SetEnv` of `LANG`, `LC_*`, `TZ`, `TERM` and `COLORTERM` reach the session
  (anything else is refused, since it would let the other side steer your login
  shell), a client's signal request reaches the running process, and a process
  killed by a signal is reported as that signal instead of a made-up exit code.
  X11 forwarding is still not supported, but `ssh -X` now says so instead of
  waiting on a reply that never came.

- **`ray mdns scan` lists the rayfish nodes on your LAN.** mDNS discovery has
  always run in the background, but it only fed the connection layer: there was
  no way to see what it found. The scan shows each neighbour's id, addresses,
  how long ago it was seen, and whether you already share a network with it.
  `ray status` grew a "nearby" block listing the ones you are not connected to
  (up to five, then it points at the scan), so a new machine on the LAN is
  visible without knowing the command exists. Seeing a node grants it nothing:
  it is a sighting, not a relationship.

- **`ray connect` accepts a LAN neighbour's id.** Passing an id from `ray mdns
  scan` dials that peer straight over the local network, skipping the DHT
  contact lookup, so two machines can link up on a LAN with no internet.
  Approval is unchanged: the other side still has to run `ray connections
  approve`. Note this means anyone on your LAN can send you a connect request
  without knowing your contact id, so rotating that id no longer stops local
  requests. They still cannot link to you without your approval.

- **Service management works on Linux without systemd.** `ray up`, `install`,
  `start`, `stop`, `restart` and `uninstall` now detect the host's init system
  and install the matching service: a systemd unit, an OpenRC service (Alpine,
  Gentoo), or an LSB SysV init script (MX Linux, Devuan, antiX). Previously
  every one of these commands shelled out to `systemctl` and failed with
  "systemctl not found" on a non-systemd host. If none of the three is
  recognised, the error now tells you to run `sudo ray daemon` directly instead
  of leaving you to guess. Under SysV init nothing supervises the daemon, so
  `ray up` says so: a crash stays down until the next `ray start`.

- **Android: toggle the tunnel from quick settings.** Rayfish now offers a
  quick settings tile, so the tunnel goes on and off from the shade without
  opening the app. Turning it off there does exactly what the app's toggle and
  the notification's "Disable" button do, so files keep working with the VPN
  off unless you asked to go fully offline when disabled. The tile shows
  whether the tunnel is actually up, not just whether it was asked for. On a
  device that has not granted the VPN yet, the first tap raises the system
  consent dialog and then brings the tunnel up; after that the tile does its
  work without opening anything.

- **The Android app can cancel a queued send.** A send waiting on a peer that
  hasn't picked it up now shows under Notifications with a Cancel button, the
  same thing `ray files cancel` does on desktop. Only works before the offer
  reaches the peer: once it lands, the file is theirs to accept or decline.

- **A "Share services" toggle on each network card in the GUI.** One click
  allows the network's peers to reach every TCP service on this machine (the
  firewall otherwise denies unsolicited inbound, so a freshly joined server is
  unreachable beyond ping). The toggle shows the current state, asks before
  opening or closing, and maps to a single inbound allow rule you can also
  manage from `ray firewall`.

### Changed

- **`ray config get`/`set` now reaches every single-value setting**, not just
  the relay/DNS ones: `firewall.enabled`, `firewall.reject`,
  `firewall.default-in`, `ssh`, `mdns`, `download-dir` and `download-user` are
  all settable by name. The dedicated commands (`ray firewall off`,
  `ray firewall ssh on`, `ray files download-dir`, `ray mdns off`, …) are
  unchanged and still the recommended spelling; they now share one code path
  with `ray config`, so a setting behaves the same whichever way you write it.
  A bare `ray config get` prints all twelve, and `ray config set --help` lists
  each key with a one-line description, so nothing is reachable only by
  guessing its name.

- **`ray firewall default ALLOW` is accepted**, matching
  `ray config set firewall.default-in ALLOW`. The two spellings of the same
  setting disagreed on capitalisation.

- **A mistyped config key is reported by name, even with the daemon stopped.**
  `ray config get|set|unset <key>` checks the key before it connects, so a typo
  reads as "unknown config key: …" with the list of valid ones instead of
  "rayfish daemon is not running". A request the daemon cannot decode at all now
  comes back as an error rather than a closed connection, which the client could
  only report as "connection closed".

- **`ray -h` groups its commands instead of listing all 44 in one run.** The
  list is now broken into Networks, Members & access, Devices & links, Files,
  Policy, Service, Diagnostics and Setup, so you can find the command you want
  by looking in the obvious place rather than reading the whole page. Each
  command is described in one line that fits an 80-column terminal, where
  several used to be full paragraphs that wrapped; the detail they carried moved
  to `ray help <command>`, which the foot of the page now points at.

- **`--json` is only accepted by the commands that produce JSON.** It used to be
  accepted everywhere and honoured by 16 commands, so `ray version --json` and
  `ray up --json` printed their usual text and gave no hint that the flag did
  nothing. Those now report an unknown argument, and `--json` is listed only in
  the help of commands that support it. **This is a breaking change** if you
  wrote the flag before the command: `ray --json status` no longer parses, and
  becomes `ray status --json` (the form the docs already used, and the one the
  error message suggests). Writing it after a subcommand's action, as in
  `ray firewall show --json`, is unaffected.

- **Magic DNS falls back to your normal DNS for any name the mesh doesn't
  hold.** A network named `dev` used to be registered with the OS as its own
  domain, so every lookup under it, `zed.dev` included, was captured by rayfish
  and answered NXDOMAIN instead of going to the real internet. Rayfish now
  answers only names its roster actually has, and hands everything else to the
  system resolver: `zed.dev` reaches the real site, while a peer named `box` on
  network `dev` still resolves as `box`, `box.ray`, `box.dev` and
  `box.dev.ray`. The `.ray` suffix itself stays rayfish's either way: a name
  under it that no peer holds is failed here rather than asked of a public
  resolver, so it starts resolving the moment the peer appears instead of
  staying cached as missing for up to a day. Bare network names are no longer
  registered with the OS, so
  the suffix-less `<host>.<network>` form works where rayfish sees all your
  queries (the resolv.conf backend, an active exit node, Android) and `.ray`
  works everywhere. One consequence worth knowing: if a peer's name matches the
  public name you wanted (a peer literally called `zed` on network `dev`), the
  peer wins; use the public FQDN or rename the peer.

- **Android crash reports now say how the app died when it dies silently.** A
  low-memory kill or a background stall used to leave either nothing at all or a
  report with no indication of what was stuck, which is the difference between a
  bug that can be fixed and one that can only be guessed at. Reports now carry
  Android's own record of the exit, including which component was busy. Still
  covered by the crash reporting toggle in You: turn it off and nothing is read
  or sent.

- **Android transfer notifications show the percentage next to the progress
  bar.** A bar on its own says something is moving but not how far along it is,
  and on a large file it can look stuck.

- **The `ray gui` dashboard got a redesign.** The overview now shows live data
  instead of raw command output: a mesh map of your peers, per-network peer
  tables with connection type and latency, and pending items (join requests,
  firewall suggestions, file offers) as one-click chips. Status refreshes
  quietly every few seconds, network name fields auto-complete, IPs and the
  contact id copy on click, and the join form now labels `--name` as
  "local name" so it is no longer mistaken for the device hostname.

- **`RAYFISH_CONFIG_DIR` works on every platform.** The variable used to be read
  only on Android, so there was no way to point a desktop daemon at a config tree
  outside `/etc/rayfish` (Linux) or `~/.config/rayfish` (macOS). Set it and both
  the daemon and the CLI use that directory instead, which makes side-by-side
  test nodes and non-standard install layouts possible. The daemon and the CLI
  have to agree, so export it in the service environment as well as your shell.
  Leaving it unset (or empty) keeps the previous per-platform paths exactly.

- **Invite codes carry a checksum.** A code that lost or gained characters on
  its way through a chat client now fails immediately with "invalid invite
  code" instead of decoding into a well-formed invite for a network that
  doesn't exist, which surfaced later as a confusing join failure. Codes minted
  by older builds still work; codes minted now are four characters longer, so a
  peer on a build older than this one cannot redeem them.

### Fixed

- **A host whose own DNS is broken no longer takes Rayfish down with it.** The
  daemon looked up the relay and the discovery server through whatever
  `/etc/resolv.conf` named, so a machine whose nameserver had stopped answering
  got no relay connection, no record publishing, and a `ray join` that failed
  with a DNS error there was nothing to do about. It now keeps its own short
  list of resolvers for those two names: your configured `dns_upstreams` first,
  then the host's, then a public resolver as a last resort, so the node still
  reaches the network while the host's DNS is down. Only Rayfish's own
  infrastructure names go there, never anything from the mesh or from your
  traffic, and `ray config set dns-upstreams <ip> --replace` pins it to servers
  you name. This also settles a chicken-and-egg case: a daemon that started
  while its own Magic DNS address was still listed in `resolv.conf` (after a
  crash, or a restart before the file was restored) used to wait for the tunnel
  it was trying to bring up.

- **A network a peer has left no longer blocks traffic to that peer.** Where you
  shared two networks with someone and they left one without you hearing about
  it — they were offline, or you hold the network so nothing corrects your
  roster — every packet to them was stamped with the network they had left, and
  they dropped all of it. Their `.ray` names still resolved, so it looked like
  the mesh was up and the connection simply timed out both ways, and deleting
  the leftover network fixed it instantly. Traffic is now attributed to a
  network the peer agrees you share, and the log names the one that fell away.

- **`.ray` names now resolve on macOS in IPv6-only mode.** `ssh <host>.<net>.ray`
  failed with "nodename nor servname provided" on a Mac sharing the host with
  another VPN, while `dig` against the same resolver answered instantly: macOS
  was never asking us for AAAA records, and AAAA is the only answer that mode
  has. It asks for both families now. The mesh range being `200::/7` had nothing
  to do with it; macOS was declining to ask because our resolver's service
  published no default route and so did not count as having IPv6 at all. The
  service now says it has one, while ranking itself so it can never become the
  primary route or take over the host's IPv6 traffic. Another VPN's DNS, routes
  and search domains are untouched.

- **Direct connections over IPv6.** The daemon bound a UDP socket for IPv4 only,
  so a peer on an IPv6-only network could be reached through a relay and never
  directly, and this node offered no IPv6 address for others to try. Both
  families are bound now, on any interface. A host with IPv6 disabled is
  unaffected: that bind is allowed to fail.

- **A tailnet address is no longer published in your public record.** A host
  running Rayfish next to Tailscale advertised its `fd7a:115c:a1e0::/48` address
  as a way to reach it. No peer could route to it, and it told anyone reading
  the record that the tailnet exists.

- **Two VPNs no longer fight over `/etc/resolv.conf`.** Where Rayfish manages
  that file directly and re-asserts it on every write, another VPN doing the
  same thing meant the pair rewrote each other and the host's DNS came and went.
  Rayfish now leaves the file to whoever holds it and says what to do instead.

- **A clash on `100.64.0.0/10` is now detected on a stock server.** The startup
  check shelled out to `ifconfig` and treated a missing binary as "no clash", so
  on hosts without net-tools (most of them) Rayfish started anyway and quietly
  lost its IPv4 half to the other VPN. It reads the kernel's address list now.

- **The host-firewall warning now reads the ruleset that actually applies.** It
  always checked `iptables`, but in IPv6-only mode mesh SSH listens on IPv6, so
  a host with a default-DROP `ip6tables` policy was told everything was fine and
  `ssh` hung with no explanation. It reads `ip6tables` in that mode, and the
  command it prints opens the right family.

- **An exit node no longer masquerades another VPN's traffic.** The NAT rule
  matched any packet sourced from `100.64.0.0/10`, a range Rayfish does not own
  exclusively, so a host acting as both a Rayfish exit node and a Tailscale
  subnet router NAT'd the other's forwarded traffic too. It now matches only
  what arrived on the Rayfish interface.

- **On Android, Rayfish comes back after being turned off with "go fully
  offline when disabled" set.** Turning it back on could leave the phone
  offline for good: the previous node released its blob store only after the
  fact, if at all, and a start that overlapped it waited for a database lock
  that was never coming, with nothing in the app to say so. Stopping now
  releases the store before it returns, starting gives up rather than waiting
  forever, and a start that does fail is reported instead of passing in
  silence.

- **On Android, moving between networks no longer leaves the phone on dead
  sockets.** Only a full network switch was forwarded to the core, so a Wi-Fi
  roam between access points, a DHCP renew or an address change on the same
  network went unnoticed and the phone stayed invisible to its peers. Those
  changes now rebind, and turning Rayfish off and on does too, so the obvious
  thing to try when peers look disconnected actually recovers it.

- **A mesh SSH terminal session can no longer go silent while its shell keeps
  running.** If the program on the far end closed and reopened its terminal
  while starting up, the daemon's read of the pseudo-terminal ended there and
  nothing it printed after that reached you, with the session apparently hung.

- **A dropped mesh SSH connection no longer leaves your login shell running.**
  When a session channel closed, or the whole connection went away, whatever was
  running under it kept running on the remote host. It now gets hung up, the way
  a stock sshd does.

- **Mesh SSH serves every session on a multiplexed connection, not just the
  first.** With `ControlMaster` (`ssh -M`, and every tool that reuses one
  connection, such as Zed remote development) only the first command ran: each
  later one hung forever with no output, no exit status, and no error on either
  side. The server kept the login and channel state in one slot per connection,
  so the first session consumed it and the rest quietly started nothing.
  Sessions are now tracked per channel, concurrent channels no longer take over
  each other's PTY or output, and a session that cannot start closes its channel
  with an error instead of hanging.

- **`scp` and `sftp` work over mesh SSH.** Both hung with no output and no
  error until you interrupted them. OpenSSH 9.0 and newer `scp` copies files
  over the SFTP protocol rather than the old rcp one, and the mesh SSH server
  had no handler for the `sftp` subsystem, so it never answered the request and
  the client waited forever. It now serves the subsystem using the host's
  sftp-server, picking up the path and flags from the host's own sshd config.
  On a host with no sftp-server installed the client is told so straight away
  instead of hanging, and the daemon log names the package to install.
  Interactive `ssh` was unaffected.

- **`ray firewall ssh allow` now tells you when the SSH server is off.** The
  rule was saved and reported as if it had taken effect, but with the server off
  a connection falls through to the host's own sshd and asks for a password,
  which looks like the rule was ignored rather than never applied. Both `allow`
  and `ssh show` now say the rules are inactive and point at
  `ray firewall ssh on`.

- **A saved network no longer stays dead until you restart the daemon.** A
  network that failed to connect at startup stayed in your config but was never
  restored: peers on it were unreachable and their packets were dropped as
  belonging to an unknown network, while the node otherwise looked healthy. The
  daemon now re-checks every minute that each saved network is actually
  connected and restarts the ones that aren't, and a peer sending traffic for a
  network in that state triggers the retry immediately instead of waiting for
  the next check. This covers coordinator networks too, which previously got one
  attempt at startup and no retry at all. `ray status` spells out what the
  `inactive` marker means (saved, not connected, peers unreachable, being
  retried) instead of leaving it as a one-word footnote, and the daemon log
  records why a restore stopped rather than ending it silently.

- **The Android app no longer crashes when Android restarts it in the
  background.** After the system killed the app to reclaim memory, it would
  restart the Rayfish service to put it back in standby (VPN off, files and mesh
  visibility still working). Android refuses that kind of background start unless
  a tunnel is up, and the refusal took the whole app down: a crash report, and a
  device that quietly dropped off the mesh instead of coming back. The refusal is
  now handled: the app stops cleanly and restores standby the next time you open
  it or turn the VPN on.

- **Android no longer leaves a VPN connected after a failed tunnel start.** When
  bringing the tunnel up failed partway (the mesh node had not started yet, say),
  the app fell back to standby and reported the tunnel off, but the VPN interface
  Android had already created stayed behind: the system kept showing a connected
  VPN, and the only way out was disconnecting it from Settings, which then left
  the app unable to start the tunnel again. Apps that refuse to run while a VPN
  is up (Android Auto) saw a VPN that no longer existed as far as the app was
  concerned. The tunnel handle is now released on every failure path, so the
  system VPN goes away with it, and a mesh node that fails to start no longer
  gets as far as asking Android for a VPN interface in the first place.

- **"Copy code" on the Android QR sheet confirms the copy.** The sheet draws in
  its own window on top of the screen that hosts the confirmation, so the
  "Copied" message was hidden behind it and the button looked dead. The button
  itself now says "Copied", or "Copy failed" if Android refuses the clipboard
  write instead of failing silently.

- **A node that reboots faster than its network comes up rejoins on its own.**
  The daemon starts as soon as the service manager says the network is ready,
  which on a hard reboot can be before DNS answers. Finding a saved network
  needs a DNS lookup, and that one failed lookup used to be final: the network
  showed as `·inactive·` in `ray status` and stayed that way, with peers still
  seeing the node online, until someone ran `ray restart` by hand. Restoring a
  network now retries with backoff until it lands.

- **Magic DNS comes up on its own when the host's DNS was down at boot.**
  rayfish refuses to take over `/etc/resolv.conf` while the host has no working
  upstream to forward to (taking it over would break all resolution). That
  verdict was permanent, so a node that booted before its DNS settled had no
  `.ray` name resolution until the next restart. It now keeps trying in the
  background and configures Magic DNS as soon as the host can resolve again.

- **Magic DNS works on hosts where systemd-resolved runs but nothing asks it.**
  Many cloud images (Vultr, some Hetzner and DigitalOcean builds) leave
  `systemd-resolved` enabled while `/etc/resolv.conf` still points straight at
  the provider's nameservers. rayfish handed `.ray` to resolved anyway, so
  `resolvectl query host.ray` answered while `ping host.ray` said "Name or
  service not known", and every name-based command silently failed. rayfish now
  checks that resolved is actually in the host's resolution path before using
  it, and takes over `/etc/resolv.conf` when it isn't.

- **`ray up` warns when the host firewall will swallow mesh SSH.** The embedded
  SSH server cannot bind port 22 next to a system sshd, so it listens on 30022
  and rewrites the port internally. A ufw or firewalld rule allowing "22/tcp"
  therefore does not cover it, and the connection hangs with no clue anywhere:
  ping works, the mesh is up, SSH just stops. rayfish now detects that case and
  prints the exact command to open it. It only ever reads your firewall.

- **Peers no longer show as `Idle` on one shared network while connected on
  another.** One connection carries every network two peers share, but it was
  only registered for the networks whose roster already listed the peer when its
  handshake arrived. A hello that landed mid-reconverge (after a restart, or a
  fresh join) left the link carrying a network the peer table didn't know about,
  which showed as `Idle` in `ray status` **and** silently dropped that network's
  inbound traffic until something re-dialed. Reconverge now repairs it.

- **A failed mesh SSH login says why.** Mesh SSH offers only identity-based
  auth, so a peer that wasn't authorized was refused with no explanation and the
  client fell through to a password prompt from the system sshd. Every
  authorization problem looked like a password or network problem. The server
  now sends the reason and the `ray firewall ssh allow` command that fixes it.

- **Reverting DNS no longer deletes `/etc/resolv.conf`.** If the backup was
  missing, the revert removed the file outright, taking the host's entire DNS
  with it over what should have been an undo of one line. It now edits our own
  entries out in place and leaves anything it didn't write alone.

- **File transfers no longer leave a copy of every file behind.** The blob store
  each transfer runs through was never cleaned up, so `blobs/` kept a copy of
  everything you had ever sent, and everything you had ever received sat there a
  second time next to the one in Downloads. Both ends now release their copy once
  the transfer is done, and the store reclaims the space.

- **Sending or receiving a large file no longer loads it entirely into memory.**
  Both ends streamed to disk in the middle but still buffered the whole file at
  the edges, so a big video could exhaust memory. Worst hit was the Android app,
  which the system would kill outright.

- **Sharing from the Android app no longer says "No peers online" when peers are
  right there.** The app runs the mesh on demand, so a link closes after a couple
  of idle minutes and the share picker, which only listed peers holding a live
  connection, went empty. It now lists every peer in your networks and marks each
  one connected, idle, or offline. Picking an idle peer wakes it first and the
  notification says so; if it does not answer, the files queue and deliver when it
  comes back, same as before.

- **Android: turning the VPN off no longer crashes the app.** If a DNS lookup was
  still in flight the moment the tunnel came down, the system resolver delivered
  its answer to the proxy's already-shut-down callback thread, and the resulting
  rejection landed on the main thread outside any of our code, killing the
  process. Teardown now cancels the outstanding lookups and drops any answer that
  still arrives. Most likely to be hit when switching the VPN off, when another
  VPN app takes the slot, or when bring-up fails.

- **Magic DNS no longer takes a host's DNS down with it.** When rayfish falls
  back to managing `/etc/resolv.conf` itself, it used to forward every non-`.ray`
  lookup to whatever nameserver the file happened to list, without checking that
  the nameserver answers. On a machine whose `resolv.conf` is rendered by another
  program (NetworkManager, most often) that entry can name a server that no
  longer replies, and the result was a box with no DNS at all: ordinary names
  stopped resolving, and `ray join` failed with `Service 'pkarr' failed` because
  the daemon could not look up the discovery server either. Rayfish now checks
  each nameserver before trusting it, keeps a working one listed in
  `resolv.conf` after its own so the host still resolves names if the daemon
  stops, and refuses to take the file over at all when nothing answers, telling
  you to set `dns_upstreams` rather than leaving you without DNS. A lookup that
  can't be forwarded now fails immediately instead of hanging until the client
  gives up.

- **Failed lookups say what actually went wrong.** `ray join` reported every
  discovery failure as `failed to resolve network record: failed to resolve
  network record: Service 'pkarr' failed`, which repeated itself and named
  neither the cause nor the server it tried. It now names the discovery server
  and keeps the underlying reason, so an unreachable server, a DNS failure, and
  a network that was never published are told apart. A lookup also gives up
  after 15 seconds instead of potentially hanging forever.

- **Firewall rules now match the real ports of every packet.** An IPv4 packet
  claiming a header shorter than 20 bytes was still evaluated, with its "ports"
  and TCP flags read from bytes inside the IP header, so a peer could pick which
  rule such a packet appeared to match. These packets are now dropped as
  malformed, which is what every OS does with them on receive anyway.

- **Android app reports the right version.** The APK version was pinned to 0.1.4
  and no longer tracked releases, so the manifest, the version shown in the app
  and the crash-report release tag were all wrong. It now comes from the crate
  version.

### Performance

- **Mesh SSH commands start faster.** The sockets carrying SSH left Nagle on, so
  every small request/response exchange waited on the Nagle/delayed-ACK standoff
  instead of going out at once. Over a 34 ms link, opening a session channel on
  an established connection cost 117 ms, roughly 3.4 round trips where 1-2 is
  the floor. Ansible, which opens a channel per task, paid that on every one.
  Forwarded connections in both directions and the local `ray gui` server got
  the same treatment.

- **Cheaper per-packet receive.** Every datagram arriving from a peer re-resolved
  the TUN writer through two atomic reference-count operations. Readers now keep
  a cached view that only refreshes when the writer actually changes (a VPN
  toggle), taking that step from ~11 ns to ~1 ns per packet.

## [0.2.1] - 2026-07-24

### Added

- **Exit nodes.** A node can offer itself as an internet gateway for a network so
  other members route all their non-mesh traffic through it (like a Tailscale exit
  node). On the gateway: `ray exit-node allow <net> <peer|*>`
  permits peers (and turns on kernel forwarding + NAT on `ray up`);
  `ray exit-node disallow` revokes. On a client: `ray exit-node use <net> <peer>`
  routes all internet-bound traffic out through that peer, `ray exit-node none`
  restores direct egress. Availability is advertised in the signed roster, so
  `ray status` flags exit-capable peers, marks the one actually carrying your
  traffic, shows when this node is itself offering an exit, and
  `ray exit-node status` lists the lot.
  Full-stack IPv4 + IPv6. Connections that reach the client from outside the
  tunnel keep answering out the interface they arrived on, including ones already
  open when the tunnel comes up, so a headless host stays reachable on its public
  IP and the SSH session you turn the tunnel on from survives it. Offering an
  exit node works on Linux (nftables), macOS and FreeBSD (pf); using one works on
  Linux (fwmark loop-prevention) and macOS (sockets pinned to the physical
  interface); the `allow` / advertise / `status` surface is cross-platform.
  Traffic routed through an exit node whose packets exceed what a single QUIC
  datagram can carry on the peer's path (common over a relayed link) now gets a
  path-MTU signal (ICMP "fragmentation needed" / "packet too big") back to the
  sender so it shrinks to fit, instead of being silently dropped. An
  exit node is strictly an *internet* gateway: it forwards to
  globally-routable addresses only, so permitting a peer to route out through you
  never also hands it your private LAN, your loopback, your cloud instance
  metadata service, or services on the gateway host itself.
  Backward compatible on the wire: peers on the previous release stay connected,
  they just cannot offer or discover exit nodes until they update (an old
  coordinator ignores the exit-node advertisement, so offers on its networks do
  not propagate until it runs the new version). From this release on, a peer that
  receives a control message it cannot decode tells the sender, so a version
  mismatch shows up in the sender's log instead of features failing silently.

- **Android: disabling Rayfish no longer takes the phone offline.** Turning the VPN
  off (in the app, or because another VPN app took the slot) now drops the tunnel
  and releases the VPN slot but keeps Rayfish's control plane connected, so files
  still arrive and still send and the phone stays visible in the mesh. Android only
  allows one VPN at a time, so this is what lets you run another VPN (Tailscale,
  say) alongside Rayfish. A new "Go fully offline when disabled" toggle in You
  (default off) is there for anyone who wants the old behavior back.
- **Android: accurate notifications for sent and received files.** Sending a file
  now shows a progress bar and only reports "Sent" once the recipient has actually
  pulled the bytes, not just once the offer went out (a manual accept on the other
  end can take a while, or never happen). Receiving a file, including an
  auto-accepted one from your own paired device, now posts its own progress and
  "Saved" notification instead of landing in Downloads silently. Both keep working
  in the background, including with the VPN off.
- **Android: a one-tap "Disable" on the VPN notification.** While the VPN is on, its
  persistent notification now carries a Disable action, so you can drop the tunnel
  and free the VPN slot from the notification shade (as Tailscale does) without
  opening the app. Under the default above, the control plane stays up, so files
  keep working after you disable.
- **The install script now lives in the repo** as `install.sh`, so the one command
  users are asked to pipe into a root shell can be read, reviewed, and tested like
  the rest of the code. CI lints it and installs the latest release with it on
  Linux (glibc and musl) and macOS on every change. rayfish.xyz serves a copy of
  this file, and its CI fails if the two drift apart.

- **`ray send` no longer blocks, and sending to an offline device just works.**
  The command returns as soon as the daemon has the file: if the peer is
  connected the offer goes out immediately, otherwise it is queued and delivered
  automatically the moment the device comes back online (sends survive a daemon
  restart). Queued sends show up in `ray files` and can be dropped with
  `ray files cancel <id>`. Previously `ray send` sat silent for as long as the
  dial took and failed outright if the peer was offline.
- **`ray send` takes multiple files.** `ray send <peer> <file> <file> ...` sends
  each one; a failure on one file doesn't stop the rest.

- **Android: the app now notices network changes.** Switching between Wi-Fi and
  mobile data (or roaming access points) used to leave the app on dead sockets:
  Android does not let apps observe route changes natively, so the core never
  rebound and the device silently dropped off the mesh until the VPN was toggled
  by hand. The app now forwards Android's connectivity callbacks to the core,
  which rebinds and re-probes immediately.

- **On-demand mesh connections (near-zero idle battery).** A node connects to its
  peers at startup (so it knows immediately who is reachable), then closes any
  connection that sees no traffic in either direction for the idle timeout (default
  120s), returning to zero peer connections so it stops waking the radio for QUIC
  keepalives. The link re-forms on the next packet either side sends. Idle teardown
  coexists with older peers: a node only closes an idle link to a peer whose build
  also understands the idle close, so a peer on an earlier release is held open
  instead of flapped. On by default; turn it off with `ray config set on-demand off`
  (and `idle_timeout_secs` tunes the window).
- **`ray config` now covers the `auto-update` and `on-demand` toggles.** Both
  on/off daemon settings are settable through the standard config surface (e.g.
  `ray config set on-demand off`, `ray config set auto-update on`,
  `ray config unset on-demand`), and bare `ray config` lists their current value
  alongside relay/discovery-dns/dns-upstreams. `ray auto-update on|off` still works
  as a shorthand.
- **`ray status` shows peers as idle, active, or offline.** With on-demand
  connections a reachable peer usually has no live link, so status now renders three
  states (Tailscale-style): `active` (connected now), `idle` (a roster member with
  no current link, presumed reachable), and `offline` (only after an actual reach
  attempt failed). `ray ping <peer>` dials on demand and refreshes a peer's state.
- **Static musl Linux binaries.** Every release and nightly now also ships
  `ray-linux-{x86_64,aarch64}-musl`: fully static builds with no glibc dependency
  that run on any Linux, including musl distros (Alpine) and hosts with a glibc
  older than the gnu build floor. The installer picks them automatically when the
  glibc binary won't run on the host (and a musl asset exists for that version),
  and `ray update` on a musl-built daemon self-updates to the musl asset.

### Changed

- **`ray send` argument order flipped** to make room for multiple files: it is
  now `ray send <peer> <files...>` (was `ray send <file> <peer>`). The `--json`
  output of `ray files` is now an object with `pending` (inbound offers) and
  `queued` (outbound sends) arrays instead of a bare array.
- **Desktop TUN now runs on `tun-rs`.** Swapped the `tun` crate for `tun-rs` on
  Linux, macOS, and the other desktop targets (Android is unaffected, it uses the
  `VpnService` fd). Behavior is unchanged: same 1280 MTU, addresses and routes are
  still installed by our own netlink/`ifconfig` helpers. This is the groundwork for
  a later Linux GRO/GSO offload path that batches TUN writes.
- **FreeBSD improvements.** The logs will be stored in /var/log and the configs
  will be stored at /usr/local/etc.

### Fixed

- **IPv6 no longer dies after `ray down` + `ray up` (Linux).** Linux flushes an
  interface's global IPv6 addresses when its link goes down, and the overlay `/128`
  was only assigned when the TUN was created, so a standby cycle left the node
  reachable over IPv4 while every IPv6 peer silently got no answer (until the
  daemon was restarted). The address is now re-assigned on every activate.
- **No more ANSI color codes in syslog.** The daemon colors its console logs only
  when stdout is actually a terminal, so logs collected by systemd/journald (and
  any piped output) are plain text instead of escape-code soup.
- **`ray send` now works from Documents, Desktop, and other protected folders on
  macOS, and for files only your user can read.** The CLI used to hand the daemon
  a path and the daemon (running as root) did the read, which failed with
  `Operation not permitted` in TCC-protected folders (the daemon has no Full Disk
  Access, and root does not bypass TCC) and quietly meant the daemon would read
  anything root could. `ray send` now opens the file itself, with your own
  permissions, and passes the open file descriptor to the daemon over the IPC
  socket (SCM_RIGHTS), so the daemon never touches a path on your behalf. An
  updated CLI still falls back to the old path-based request when talking to a
  daemon that predates this.

- **`ray send` now works with relative paths.** The path was resolved by the
  daemon, whose working directory is not the caller's, so `ray send ./file peer`
  failed with `No such file or directory` even though the file was right there.
  The CLI now resolves the path against your shell's working directory before
  handing it to the daemon, and reports a missing file immediately.

- **`curl -fsSL https://rayfish.xyz/install.sh | sh` works again.** The installer
  detected the host OS inside a command substitution, which runs in a subshell, so
  the value was lost in the caller and the script aborted with `OS: parameter not
  set` on every Linux and macOS host. Reported in #95, fixed by @nemanjaglumac in
  #97.

- **The installer no longer asks for `sudo` when it doesn't need it.** Pointing
  `INSTALL_DIR` at a path that didn't exist yet (`~/.local/bin`, typically) was
  treated as "not writable", so the install escalated and left a root-owned
  directory in the user's home. It now tests the nearest existing parent.

- **The installer refuses to install a binary it can't verify.** A missing `.sha256`
  sidecar silently skipped checksum verification. Every release publishes one, so a
  missing sidecar now aborts the install (`RAY_SKIP_VERIFY=1` overrides).

- **`ray mdns off` (and the other config-writing commands) now take effect on
  non-Linux hosts.** `ray mdns`, `ray auto-update`, `ray config set|unset`, and
  `ray files download-dir|download-user` wrote `settings.toml` from the CLI
  process. On Linux the config dir is a fixed `/etc/rayfish`, so this was fine, but
  on macOS/FreeBSD it is derived from the process environment: a CLI running under
  a different `HOME` than the daemon service wrote a `settings.toml` the daemon
  never read, so the setting silently reverted on restart. These commands now route
  through the daemon, which writes (and reads) its own config dir. They now require
  the daemon to be running.

- **Desktop data plane no longer wedges after an on-demand dial.** The desktop TUN
  read grew the packet pool before its `await` and truncated after, so when
  `run_mesh` cancelled the read (which it does the moment a lazy dial completes) the
  pool kept stray bytes. Every subsequent packet was then read at the wrong offset
  and parsed as garbage, silently killing all forwarding and Magic DNS until a
  restart. The read is now cancel-safe (reads into an owned buffer, commits to the
  pool only after the read returns).

- **Android: disabling the VPN now fully tears the tunnel down.** Turning the
  tunnel off dropped the mesh connection but left the VPN interface up (the key
  icon stayed and the `tun` device lingered), because the offline path closed the
  endpoint without releasing the tunnel fd. Disable now detaches the data plane
  first, so both the interface and the control plane go down and the device stops
  using the radio.

## [0.2.0] - 2026-07-08

### Changed

- **`ray status` flags peers on an incompatible mesh version.** A peer running a
  mismatched mesh protocol can't connect (the version-gated ALPN rejects it) and
  used to look like any other offline peer. Such a peer is now shown as
  `incompatible` with a `ray update` nudge, instead of plain `offline`, so it is
  clear the peer just needs updating. (Connected peers are same-version by
  definition, so this only ever applies to unreachable ones.)
- **`ray status` groups your paired devices under their user.** Devices that
  share a user identity (multi-device pairing) now nest under a parent row for
  that user showing a `N devices, M online` rollup, instead of listing flat with
  a `(user …)` tag. Standalone members are unchanged. The device columns stay
  aligned across the tree.
- **One mesh connection per peer, not per network**: peers now hold a single
  QUIC connection per device identity that carries traffic for every network they
  share, instead of one connection per shared network. A host you share two
  networks with is one connection with one round-trip estimate, so `ray status`
  and `ray ping` report the **same** RTT for it everywhere (previously each could
  read a different, sometimes-stale, per-network connection). Networks are now a
  membership/policy layer decoupled from the transport. **This is a breaking
  mesh-protocol change** — every peer must be on the new version to connect (older
  peers are cleanly severed by the protocol-version gate; run `ray update`). A
  peer kicked or removed from one shared network stays reachable on the others.
- **`ray connect` links are now symmetric**: when a direct 2-peer connection is
  approved, both peers become coordinators of the auto-created network (the
  requester is granted the network key on admission). Either side can now manage
  the link (rename, re-invite, keep it alive) instead of only the peer who
  approved it.

### Fixed

- **A flapping connection no longer evicts a valid member from the network.** A
  coordinator treated any graceful close (a `ray leave` *or* a kick) as a
  departure, so when a peer closed a link with the *kick* code (it had pruned what
  it thought was a stale roster entry, e.g. while a connection flapped), the
  coordinator wrongly dropped that member from the signed roster and republished
  without it. On a closed network the member then had to be re-admitted with `ray
  accept`, and an unstable link could repeat this indefinitely. Membership is now
  decided only by the signed record: a connection close never evicts a member and
  never makes one leave. A `ray kick` is delivered as an explicit, network-scoped
  message to the kicked member, which confirms it against the signed record and
  leaves that network (only that one) when the record confirms the removal, so a
  stale or spurious close can't evict anyone.
- **The mesh no longer tries to reach peers over their own overlay IP.** A node's
  rayfish mesh address (`100.64.0.0/10` or `200::/7`), bound on the TUN device,
  could leak into the transport addresses it advertised, so peers tried to reach
  it *through the tunnel it carries* — a self-looping path that flapped open and
  closed and could cascade into the eviction above. Those overlay ranges are now
  stripped from the addresses iroh publishes, so peers only dial real underlay
  addresses and relays.
- **`ray status` no longer lists a peer's primary device twice.** Viewed from
  another node, a user whose primary device was itself a member showed up both as
  a flat row and again as a separate group header for the same identity. The
  primary's own row (with its address and RTT) now anchors the group, and the
  paired devices nest beneath it.
- **Unpairing a device from the device itself now revokes it on the primary.** A
  secondary that unpaired itself only tore down locally; its primary kept it in
  the roster with no nullifier written, so it lingered as an offline member until
  you ran `ray unpair` on the primary. The device now asks its primary to write
  the authoritative nullifier as it leaves (best-effort, while the link is still
  up). If the device is offline from its primary at that moment, `ray unpair
  <device>` on the primary is still the way to revoke it.
- **Android no longer downgrades public DNS to cleartext.** While the VPN was up,
  non-`.ray` lookups were forwarded as plaintext UDP on port 53 to the network's
  IPv4 resolvers, ignoring any Private DNS (DoT/DoH) the device had configured.
  Rayfish now runs a small loopback proxy that forwards those lookups through the
  Android platform resolver (`DnsResolver.rawQuery`), so they honor the system
  Private DNS setting. The app is also excluded from its own tunnel so its
  sockets use the real underlying network. Devices below Android 10 (no
  `DnsResolver`) fall back to the previous plaintext behavior.
- **A reconnecting peer shows the current roster within seconds, not up to a
  minute.** After a restart a node connected to its coordinator almost instantly
  but its own `ray status` could sit on a stale roster (peers missing or shown
  offline) for ~60-90s, because it only learned the live membership from a DHT
  lookup that can serve a stale record right after boot, plus a 60s poll. A
  coordinator now hands a reconnecting member its current network-key-signed
  record directly over the mesh, so the member converges to the live roster in
  about a second. The record is still signature-verified against the network key,
  so the trust model is unchanged.
- **Leaving one network no longer disconnects you from the others you share
  with the same peer.** With one connection per peer now carrying every shared
  network, `ray leave <net>` used to tear down the whole link, cutting the peer on
  networks you never left, and if that peer coordinated one of them it could even
  drop you from its roster. Departure is now signalled in-band and scoped to the
  single network, so the rest stay up.
- **A co-coordinator renaming itself now reaches the other coordinators.**
  On a network with more than one coordinator (via `ray admin add` or a `ray
  connect` link), when one coordinator changed its own hostname the other
  coordinators never learned it: their `ray status` roster and `*.ray` DNS kept
  showing the old name. The rename now propagates to peer coordinators
  immediately, so every node converges on the new name.
- **QR scanner preview no longer appears sideways** when pairing a device on
  Android: the scanner is now pinned to portrait so the camera preview stays
  upright.

### Added

- **Desktop GUI**: `ray gui` now opens a local browser control panel with guided
  forms for status, networks, invites, firewall, files, devices, settings, and
  service actions, plus an advanced command box that runs any normal `ray`
  subcommand through the same CLI engine.
- **Unpair this device (Android)**: a paired phone can now unpair itself from the
  You screen. It leaves every network it joined, deletes its pairing certificate,
  and other peers disconnect from it right away. Re-pair from your primary device
  to rejoin. (This is the device-side counterpart to running `ray unpair` on your
  primary.)
- **Share with Rayfish (Android)**: photos, videos, and any file can now be shared
  straight to a mesh peer from the Android system share sheet. Pick an online peer
  and the file is delivered in the background (a notification confirms it was sent),
  so you are never left waiting. Sharing several items at once is supported. Files
  sent to one of your **own** paired devices are auto-accepted there and saved to
  Downloads with no tap — this is on by default and can be turned off under
  "Auto-accept from my devices" in the You screen. (Own-device is determined from
  the device pairing certificate, so a file from someone else always asks first.)
- **Ephemeral peer auto-kick**: a per-network policy that automatically removes
  members which stay offline longer than a configured time, the same as
  `ray kick`. Set it with `ray ephemeral <net> <duration>` (`12h`, `7d`, `1w`;
  minimum 1 hour), turn it off with `ray ephemeral <net> off`, and read it with
  `ray ephemeral <net> show`. Off by default; the current TTL shows on the
  network's line in `ray status`. Only the coordinator enforces it, and only
  offline peers are pruned, so it applies to open and closed networks alike (a
  removed peer can simply re-join or re-request later).
- **`ray unpair <device>`**: revoke one of your paired devices, for example a
  lost or stolen laptop. Run it from your **primary** device (the one you paired
  the others from). Revocation is **per device**: unpairing adds just that
  device's key to each affected network's signed membership record, so every peer
  rejects its certificate the moment it reconverges. Your **other** devices are
  completely untouched (no fleet-wide certificate rotation, nothing to re-issue).
  The removed device is dropped from your networks, stops being treated as one of
  your own devices (no silent auto-admit, no own-device file auto-accept), and, if
  online and cooperative, is told to leave the mesh and delete its own certificate.
  **Re-authorize later** by simply re-pairing the device: that clears the
  revocation and issues a fresh certificate. List your paired devices first with
  `ray pair list` (`--json` supported). Note: revocation currently applies to the
  networks **you coordinate**; to retire a device from a network someone else
  runs, ask that network's coordinator to remove it too.
- **Consistent Android device name**: the phone now uses one device name across
  every network instead of a different random name per network. It is seeded from
  your device model on first run and can be changed in the You screen (the change
  applies to all your networks and to any you join later).
- **Android app exclusions and mesh IPv6 on the phone**: apps that break behind a
  VPN (Android Auto, Chromecast/Google Home, RCS messaging, GoPro, Sonos) now
  bypass the tunnel, so wireless Android Auto keeps working with Rayfish on. The
  Android tunnel also routes mesh IPv6 (the `200::/7` range), which previously did
  not work on mobile.
- **Android diagnostics**: the app now captures the mesh core's recent logs and
  reports lightweight health (networks, peers online, transport, and a WARN/ERROR
  count) to crash reporting automatically when the tunnel goes up or down and when
  the connection changes between wifi and cellular. A new "Send diagnostics" button
  in the You screen attaches the full recent log to a report so connection problems
  can be diagnosed. All of this respects the existing crash-reporting toggle; the
  toggle now reads "diagnostics". Diagnostic data (the log lines and recent errors)
  can include network addresses such as relay hosts and your device's public IP, so
  it is only sent while crash reporting is on.
- **Device ownership in `ray status`**: peer rows that are your own paired
  devices are now tagged `(your device)`, and a paired device belonging to
  another user is labelled `(user <id>)` (or shows that user's alias when you
  have set one) so it is clear which user each device belongs to. The `--json`
  output gains an `is_own_device` flag on each peer.
- **Opt-in automatic updates**: enable with `sudo ray install --auto-update` or
  `ray auto-update on`, and the daemon checks GitHub about every 6 hours for a
  newer **stable** release, then downloads, verifies (SHA-256), swaps the binary,
  and restarts itself onto the new version — no manual `sudo ray update`. Off by
  default; nightlies are never auto-installed. Applying an update restarts the
  daemon, which briefly drops the VPN (peers reconnect automatically), so it stays
  opt-in. A backoff guard means a bad release is retried at most once a day
  instead of looping. `ray status` shows when auto-update is on.
- **Auto-accept files from your own devices**: incoming file transfers from your
  own paired devices land automatically in your `~/Downloads`, with no manual
  `ray files accept`. Only offers whose sender is one of your own devices (same
  paired identity) on that network are accepted; files from anyone else still
  queue for review. This is now **on by default** (it is identity-checked, so it
  only ever accepts your own devices). Opt out for a network with
  `ray files auto-accept <net> off`, or when joining with
  `ray join <net> --no-auto-accept-files`.
- **Configurable auto-accept download location**: `ray files download-dir <path>`
  sends auto-accepted files to an absolute directory (owned by the dir's owner or
  `download-user`); `ray files download-user <user>` routes them to that user's
  `~/Downloads`, owned by them. With neither set, the operator's `~/Downloads` is
  used; if nothing resolves the offer stays queued rather than being written as
  root. `--clear` unsets; no argument shows the current value.
- **`ray alias <network> <key> <alias>`**: give a peer a friendly, node-local
  name. `ray alias <net> set <key> <name>` binds an alias to a user, where `key`
  is either an identity string (from `ray identityof`) or a currently-joined
  hostname. The alias then shows inline in `ray status` (as `host.net.ray
  [name]`) and seeds `ray apply`'s `aliases:` map, so a spec can reference the
  name without re-declaring it (the spec still wins on a name conflict).
  `ray alias <net> list` and `ray alias <net> rm <name>` manage the set. Aliases
  are local and display-only: they are never published to the network.
- **`ray kick <network> <peer>`**: coordinators can now remove a member from a
  closed network. Identify the peer by hostname, mesh IP, or short id. The member
  is dropped from the network's roster, and every node disconnects from it: the
  kicked peer is severed mesh-wide, not just from the coordinator. It cannot
  re-join the closed network without a fresh invite or approval (to bar it
  permanently, also revoke its invite or reusable key). Kicking is refused on open
  networks (where the peer could immediately re-join) and against another
  coordinator or yourself.
- **`ray firewall off` / `ray firewall on`**: a global switch to disable the
  userspace firewall on a device. `off` allows every mesh packet (rules and the
  secure default are bypassed; mesh membership still gates who can reach you, and
  spoofed source addresses are still dropped), for simple setups that don't want a
  second firewall layered on top of the host/kernel firewall. `on` restores
  enforcement. The disabled state is shown in `ray firewall show`.

### Changed

- **Own-device file receipt is on by default**: accepting files from your own
  paired devices (identity-checked, so never anyone else) no longer needs a flag.
  New joins get it automatically; opt out with `ray join --no-auto-accept-files`
  or `ray files auto-accept <net> off`. The old `ray join --auto-accept-files`
  flag is replaced by `--no-auto-accept-files`.
- **`ray firewall show` clarifies the firewall is separate from your host
  firewall**: the output now notes that this is a mesh firewall applied on top of
  your host/kernel firewall (both must allow a packet), so it is not forgotten
  when auditing an OS firewall. Enabling mesh SSH with `ray firewall ssh on` now
  reminds you to authorize a peer with `ray firewall ssh allow` when none is set
  yet (the server rejects all logins until a peer is on the allow list).
- **Bounded pending-join queue** — on a closed network, the coordinator's queue
  of join requests awaiting `ray accept` is now capped (oldest request evicted
  when full), so a peer churning fresh identities can no longer grow it without
  limit. Legitimate queues are far below the cap, so this is invisible in normal
  use.

### Performance

- **Drop-newest under datagram backpressure** — when a peer's QUIC datagram send
  buffer is momentarily full, the new packet is dropped at the application
  boundary instead of letting QUIC evict an older already-queued one (drop-newest
  beats drop-oldest for a VPN), and the QUIC transport is tuned for the one
  datagram stream per peer shape. Keeps the send path non-blocking with no
  cross-peer head-of-line blocking.
- **Faster reconnect on startup**: when a coordinator rejoins its networks it now
  dials all known members concurrently instead of one at a time, so restore no
  longer slows down with roster size or stalls on the first unreachable peer.
- **No boot stall when a member is offline**: joining or reconnecting to a network
  no longer waits to dial the whole roster before the network comes up. A single
  unreachable member (for example a stale, offline device still on the roster)
  used to block startup for the full per-peer connection timeout, tens of seconds,
  before any other peer connected. The network is now usable as soon as the
  coordinator link is up, and the remaining peers connect concurrently in the
  background. This was most visible on the Android app as a long delay before
  peers showed online.

### Fixed

- **An unpaired device now removes itself even if it missed the live signal**: a
  device no longer relies only on the best-effort "you were unpaired" message. When
  it reconverges the signed membership record (on startup, reconnect, or the
  periodic refresh) and finds its own certificate on the deny-list, it deletes the
  certificate and leaves every network on its own. On Android this also stops the
  app from still showing the device as paired after the fact.
- **Peers now disconnect from an unpaired device right away**: after `ray unpair`
  (or a device unpairing itself), other peers could stay connected to it for a
  while. The unpaired device now tears itself out of the mesh (leaves its networks)
  as soon as it learns it was unpaired, and coordinators/members drop a revoked
  device the moment they see the updated deny-list, instead of waiting up to a
  minute for the next roster refresh.
- **Re-pairing a previously-unpaired device no longer flaps**: after unpairing and
  then re-pairing the same device, it could rapidly connect and drop over and over
  (its old key was still on your deny-list, so your primary kept rejecting the
  fresh certificate). Re-pairing now clears the device from the deny-list, so it
  reconnects cleanly and stays connected.
- **`ray status` no longer flashes "no active networks" right after a daemon
  (re)start**: the daemon began answering commands a moment before it finished
  restoring your saved networks, so a `ray status` in that window (common right
  after `ray restart` or an update) wrongly reported no networks even though they
  were intact on disk. Coordinator networks are now registered before the daemon
  accepts commands, so they show up immediately; connecting to peers still happens
  in the background.
- **QR scanner no longer opens sideways (including on foldables)**: the
  pairing/join camera scanner followed the rotation sensor and came up in
  landscape. Locking it to the launch orientation was not enough on foldables
  (Galaxy Z Fold), which report landscape at launch, so the scanner is now pinned
  to portrait outright.
- **"Send diagnostics" (Android) now reliably delivers each report**: repeat
  sends folded into a single report and the send was fire-and-forget, so a tap
  could look like it did nothing. Each report is now delivered before the "sent"
  confirmation and recorded separately.
- **Pairing no longer hangs forever when the primary is unreachable**: scanning a
  pairing code dialed the primary device with no timeout, so if it could not be
  reached (offline, no open pairing session, or an unreachable network path) the
  pairing call hung indefinitely with no feedback. It now fails within 20 seconds
  with a clear message telling you to check that the primary is online and that
  you opened pairing on it.
- **`ray status` peer traffic counters now line up**: the per-peer up/down
  columns were packed into a single field, so the `↓` counter drifted from row to
  row and the block did not read as a table. Up and down are now their own
  right-aligned columns, so the arrows and digits line up down the list.
- **`ray firewall add --peer` now accepts any peer identifier**: previously it
  only matched a short id / endpoint-id prefix, so the natural things to type
  (`--peer alice`, `--peer alice.homenet.ray`, `--peer 100.x.y.z`) failed with
  "unknown peer". It now resolves a hostname, mesh IPv4/IPv6, short id, full
  endpoint id, or a paired user identity, the same way `ray ping`, `ray send`,
  and `ray firewall ssh allow` already do. It also fixes a case where an
  **inbound** rule scoped to a paired (multi-device) peer never matched: the rule
  is now keyed on the peer's user identity, so `allow in ... --peer alice` covers
  every one of that user's devices (an outbound rule stays scoped to the named
  device).
- **Member network vanished when the coordinator was offline at startup**: a
  member (non-coordinator) whose daemon restarted while its coordinator was
  unreachable would silently drop the network from its running state. `ray
  status` showed "no active networks" and the node rejected inbound mesh
  connections, and it stayed that way until it happened to restart again while
  the coordinator was online (its config was never lost). Restore now registers
  the network immediately from the verified group blob it already holds, whether
  or not the coordinator answers, and hands off to the reconnect loop to dial the
  coordinator back with backoff. The network stays visible in `ray status`
  (peers show offline) and reconnects on its own when the coordinator returns. As
  a side effect, a network no longer takes ~30s to appear in `ray status` after a
  member restart.
- **Mesh SSH host-key mismatch**: enabling `ray firewall ssh on` no longer makes
  `ssh <host>.ray` fail with a "REMOTE HOST IDENTIFICATION HAS CHANGED" warning.
  The embedded SSH server now presents the machine's existing OpenSSH ed25519
  host key (discovered via `sshd -T`) instead of a separate generated key, so
  clients that already trust the host keep matching the fingerprint pinned in
  their `known_hosts`. Hosts without a usable OpenSSH key fall back to a
  generated key as before.

## [0.1.4]

### Added

- **Mesh SSH (`ray firewall ssh`)**: Tailscale-style SSH with no SSH keys to
  manage. `ray firewall ssh on` runs an embedded SSH server on this node's mesh
  IPs (port 22); `ray firewall ssh allow <network> <peer>` authorizes a peer
  (hostname, mesh IP, short id, or `*` for any peer on the network) to log in.
  Connect with a stock client: `ssh user@host.ray`. The connecting peer is
  identified by its mesh identity (already proven by the encrypted mesh link), so
  there are no `authorized_keys` to distribute. Each grant restricts which local
  unix users the peer may log in as: `ray firewall ssh allow <net> <peer>` permits
  any **non-root** user by default, `--user alice,deploy` limits it to named
  accounts, and `--user '*'` permits any user including root. The check is by uid,
  so a uid-0 account under any name is blocked unless root is explicitly granted.
  `ray firewall ssh deny` revokes a peer; `ray firewall ssh show` lists state and
  per-network allow lists with their permitted users. As a security prerequisite,
  inbound mesh packets whose source IP is not the sending peer's assigned mesh
  address are now dropped (ingress anti-spoofing), so no peer can forge another's
  mesh IP.
- **Aliases and groups in `ray apply`**: a spec can now define optional
  top-level `aliases:` (a friendly name to a user's identity string) and
  `groups:` (a name to a list of aliases and/or hostnames), then reference them
  as firewall subjects or peers instead of listing every hostname. An alias
  names a person and expands to all of that person's currently-joined devices;
  a group expands to the union of its members. Expansion happens client-side at
  apply time, so the published rules are plain per-host suggestions. Aliases
  resolve only for members that have already joined (a `note:` is printed and
  the rule skipped until they do); literal hostnames still work before a host
  joins. `ray apply --dry-run` shows the fully expanded result.
- **`ray identityof <net> <host>`**: print a host's identity string (the value
  to paste into a spec's `aliases:`). Resolves to the user identity if the
  device is paired, else the device's transport identity. `--json` supported.

### Fixed

- **Accepted firewall suggestions no longer pile up duplicates.** Any change to a
  network's signed blob (a join, a rename, a new reusable key) re-materialized the
  whole suggested-firewall set and re-queued it for review, even the rules this
  node had already accepted. Accepting one of those repeats via the picker then
  appended a second identical rule. Already-installed suggestions are now kept out
  of the pending queue, and the picker merges by selector (newest wins), so a
  re-suggested rule replaces its predecessor instead of stacking.
- **`ray update` no longer bricks the system service.** After swapping its own
  binary, `ray update` rewrote the service unit using the path of the running
  executable, which Linux reports with a trailing `" (deleted)"` once the old
  binary is unlinked. The unit ended up as `ExecStart=/usr/local/bin/ray (deleted)
  daemon`, so the daemon crash-looped with `unrecognized subcommand '(deleted)'`
  and the node went offline until a manual reinstall. The path is now sanitized,
  making remote self-update safe.

## [0.1.3]

### Added

- **Custom relay, discovery, and DNS-upstream servers (`ray config`)**: override
  the default iroh relay and discovery servers, or the upstream resolvers used for
  non-`.ray` queries, with `ray config set relay|discovery-dns|dns-upstreams
  <value>`. Values are a comma list of presets (`rayfish`/`n0`), URLs, or IPv4s;
  the default augments the n0 defaults, `--replace` swaps them out, and `n0`/empty
  resets. `ray config get`/`unset` read and clear overrides. Applied on
  `sudo ray restart`.
- **`ray ping <peer>`**: active mesh diagnostics: sends live echo probes to a
  peer (by hostname, mesh IP, or short id) and reports per-probe round-trip
  latency, packet loss, and whether the path is direct or relayed. `-c/--count`
  and `-i/--interval` tune the probe run; `--json` emits the per-probe array.
  Unlike `ray status` (a passive snapshot), this verifies the round-trip works
  end to end.
- **`ray netcheck`**: local network diagnostics: bound UDP port (and whether
  it is the fixed forwardable port or an ephemeral fallback), home relay and its
  latency, public IPv4/IPv6 addresses, and whether UDP is working. `--json`
  supported.
- **Release notes on `ray update`**: before swapping the binary (and in
  `ray update --check` when behind), print what the update brings: the stable
  channel walks every release in `(current, latest]` newest-first, while
  `--nightly`/`--version` show the resolved release's notes. Best-effort, so a
  fetch failure never blocks the update.
- **Standby control plane (`ray up`/`down`)**: `ray down` now takes only the
  data plane offline (TUN, routes, Magic DNS, inbound forward gate) while staying
  connected to peers, so the node keeps receiving roster/blob/firewall updates and
  `ray up` is near-instant with no re-dial. `sudo ray start`/`stop` remain the
  fully-offline switch.
- **Fail-fast firewall REJECT mode**: `ray firewall reject on|off` (opt-in,
  default off): a denied packet gets a TCP RST / ICMP-unreachable reply in both
  directions so the initiator fails immediately ("connection refused") instead of
  hanging. Off keeps the stealthy silent-drop posture.
- **`ray start` / `ray stop`** service commands to bring the whole daemon online
  or fully offline.
- **Comma-list firewall ports + short CLI aliases**: `--port`/`-P` takes a
  single port, a `start-end` range, or a comma list (`80,443`, `22,8000-9000`)
  expanded to one rule per item.
- **Control-plane abuse defense**: per-connection token-bucket rate limiting that
  closes sustained flooders, with a per-network debounced reconverge worker so a
  trigger burst coalesces into a single pkarr resolve + reconverge.

### Changed

- **Richer daemon log files**: the rolling daily logs (bundled by `ray report`)
  now capture `debug`-level detail for Rayfish itself while the console stays at
  `info`, so diagnostics like hostname propagation are traceable in a report
  without re-running with `RUST_LOG`. Dependency logs stay at `info`; `RUST_LOG`
  still overrides everything.
- **Additive firewall suggestions**: each suggested token becomes one allow/deny
  rule with no synthesized catch-all (allow-list relies on the node's own inbound
  default-deny; denies-only = blacklist). `ray status` ends with a `pending`
  summary of things awaiting the user.

### Fixed

- **`ray hostname` rename now reliably propagates.** A member's rename is kept as
  a durable pending intent and re-delivered to a coordinator on every reconnect
  and reconverge until the signed roster confirms it, so the new name reaches the
  coordinator and all peers instead of sticking only on the renamed node. The
  renamed node keeps showing its new name across reconverges rather than briefly
  reverting to the old one.
- **`ray status` no longer shows `?` for a live connection's path.** A connection
  that is up but whose path iroh hasn't marked "selected" yet (during holepunch or
  migration) now reports its actual `direct`/`relay`/`tor` path instead of `?`.
- **`ray status` no longer glues a network's `join <room-id>` onto the last peer
  row.** The room-id line now prints on its own line.
- Publish the contact record regardless of data-plane state, so `ray connect`
  resolves a peer that is on standby (`ray down`).

## [0.1.2]

### Changed

- **Magic DNS reworked to TUN interception**: `.ray` queries are intercepted in
  the TUN read loop and answered in-daemon via the magic IP `100.100.100.53`, so
  the resolver never binds the host's port 53. Non-`.ray` queries forward to the
  captured upstreams.
- **Direct-mode DNS takeover (Tailscale-style)**: on hosts without split-DNS,
  take over `/etc/resolv.conf` with an inotify re-assert loop that repairs it in
  ~ms when NetworkManager/dhclient overwrites it, plus a `dns=none` NM drop-in so
  NM stops regenerating it. Both are marker-guarded and crash-safe (panic hook +
  next-start cleanup restore the host's DNS).
- **Sharded, atomic per-network config**: globals in `settings.toml`, each
  network in `networks/<name>.toml`, all written via temp-file + atomic rename.
  Replaces the single `networks.toml` whose non-atomic rewrites raced and silently
  dropped networks; legacy files auto-migrate on first load.
- Retain only the 7 most recent daily log files.
- Authenticate GitHub API calls in `ray update` with a `gh` token (lifts the
  anonymous rate limit).

### Fixed

- Scope suggested firewall rules to non-joined networks correctly, and default a
  suggestion's peer to "any" so rules propagate instantly.
- Point systemd-resolved (`SetLinkDNS`) at the magic IP; fix the NetworkManager
  mode read on Linux.

## [0.1.1]

### Added

- **Direct connections (`ray connect`)**: link two peers with no shared room id
  or invite via a rotatable, published **contact id**. `ray connect <contact-id>`
  sends a friend request; `ray connections [approve <id>]` reviews and admits it,
  minting a 2-peer network with the requester pre-approved. `ray contact
  [id|rotate]` prints or rotates the contact key.
- **Reusable invite keys**: `ray invite <net> --reusable [--expires]` mints a
  multi-use, expiring key that rides the signed `GroupBlob`, for unattended
  fleets (`ray join <key> --hostname H --auto-accept-firewall`). Revocation
  propagates via the blob.
- **Cross-coordinator invite gossip**: single-use invites are gossiped
  (`InviteShare`/`InviteUsed`) so any coordinator can validate and burn a
  cross-minted invite; combined with dial-fallback across the published
  coordinator set, fresh joins survive any single coordinator being offline.
- **Self-update (`ray update`)**: update from GitHub releases with SHA-256
  verification and atomic binary swap; `--check`, `--list`, `--force`,
  `--nightly` (rolling pre-release), and `--version V` (pinned, downgrades
  allowed). `ray version` / `--version` print the compiled version + git SHA.
- **Stable listen port**: the shared endpoint binds a fixed UDP port (41383) so
  it survives restarts and can be manually port-forwarded for guaranteed direct
  reachability, falling back to an ephemeral port if the port is in use.
- **CLI polish**: ANSI-aligned tables, progress spinners, an interactive
  `ray firewall pending` picker, and a global `--json` flag for machine-readable
  output.
- **Per-node firewall auto-accept**: `ray join --auto-accept-firewall` /
  `ray firewall auto-accept <net> on|off` to auto-install suggested rules.
- **IPv4 collision handling**: per-member `collision_index` with `assign_ip`
  rotation, index-aware validation, duplicate-IP rejection, and a deterministic
  reconverge tiebreak.
- **Opt-in QR invites**: `ray invite --qr` prints a scannable code.

### Changed

- **Secure-by-default inbound firewall**: unsolicited inbound TCP/UDP is now
  denied by default (inbound ICMP allowed, outbound allowed), with a stateful
  conntrack letting return traffic pass. `ray firewall default allow|deny` flips
  the inbound default.
- **Removed `trusted` networks** in favor of per-device, per-network firewall
  auto-accept; coordinators suggest rules on any network and nodes consent
  per-node (auto-accept or manual `ray firewall accept`/`deny`).
- **`ray apply` is YAML-only** (previously YAML/TOML/JSON), with each network
  mapping directly to its firewall subjects.
- **Mesh ALPN is versioned as the protocol-compatibility gate**: peers on
  different mesh versions share no common ALPN and can't connect. `ray join`
  pre-checks the coordinator's signed mesh version and dials surface an
  incompatible-version hint suggesting `ray update`.
- Roster and firewall state reconverge from the network-key-signed pkarr record,
  not from peer control messages (which are payload-free triggers).

### Fixed

- **ICMP conntrack** is now echo-type-aware, closing an inbound leak where reply
  packets could be treated as solicited.
- macOS routing: assert the IPv4 `100.64.0.0/10` route on activate, and install
  a loopback self-route so you can ping your own `*.ray` IP.
- Flush control-protocol QUIC streams and the pairing device-cert response so
  messages always reach the peer before the connection drops.
- `AdminGrant` keys are self-authenticated against the network public key.

### Performance

- Zero-copy TUN read and datagram forwarding path, with Criterion microbenchmarks
  (`benches/forward.rs`) over the per-packet data path.

## [0.1.0]

First public release.

### Added

- **P2P mesh VPN** over [iroh](https://iroh.computer): peers connect by
  cryptographic identity (EndpointId), not IP. NAT traversal, hole-punching, and
  end-to-end encryption are handled by iroh, with encrypted relay fallback.
- **Dual-stack addressing** derived from identity: stable IPv4 in `100.64.0.0/10`
  (FNV-1a) and stable IPv6 in `200::/7` (blake3, 120-bit, never rotates).
- **Networks & access modes**: closed by default; `--open` for public networks.
  Closed networks admit via one-time **invite codes** (`ray invite`) or **live
  approval** (`ray requests` / `ray accept` / `ray deny`). The room id is a
  discovery key, never an admission credential.
- **Coordinator / membership model**: single signed `GroupBlob` per network
  published to a per-network pkarr record; gatekeeper admission, member roster,
  and `MemberApproved` broadcast so the coordinator need not be online for a
  member's later reconnects.
- **Co-coordinators**: `ray admin add` grants the network key over the
  authenticated mesh, enabling multiple machines to publish the signed blob.
- **Magic DNS**: reach peers at `name.network.ray` (A/AAAA/PTR/SOA), rebuilt
  from the roster on every membership change.
- **Per-device firewall**: directional, protocol-, port-, and network-scoped
  rules with a stateful conntrack; `firewall.toml`.
- **Trusted networks**: coordinators can suggest firewall rules that ride the
  signed blob; nodes auto-take (`--allow-trusted`) or queue them for manual
  `ray firewall accept` / `deny`.
- **Declarative provisioning**: `ray apply <spec>` reconciles trusted networks +
  suggested firewalls from a YAML/TOML/JSON spec, with `--prune`, `--dry-run`,
  `--invite-missing`, and `--example`.
- **Multi-device identity**: `ray pair` (ticket-based), plus encrypted
  backup/restore, including optional 1Password storage of the encrypted blob via
  the `op` CLI (`ray pair backup --1password` / `ray pair restore --1password`).
- **File sharing**: `ray send` / `ray files accept` over iroh-blobs.
- **mDNS local discovery** (`ray mdns on|off`, default on).
- **Service management**: `ray up`/`down`, `ray install`/`restart`/`uninstall`,
  and the Tailscale-style operator model (`ray set-operator`).
- **Audit log**: append-only peer connect/disconnect events at
  `~/.config/rayfish/audit.log`.
- **Diagnostics**: Prometheus metrics on `:9090`, rolling daily logs, and
  `ray report` to bundle logs + metrics + sanitized status.
- **Optional transports / export**: `--features tor` (Tor transport) and
  `--features otel` (OTLP span export).

[Unreleased]: https://github.com/rayfish/rayfish/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/rayfish/rayfish/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/rayfish/rayfish/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rayfish/rayfish/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/rayfish/rayfish/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/rayfish/rayfish/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/rayfish/rayfish/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/rayfish/rayfish/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rayfish/rayfish/releases/tag/v0.1.0
