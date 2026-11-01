# manage e2e

Remote management end to end, through the real CLI: `ray machines`,
`ray controller`, `ray join --delegate`, `ray leave --delegate`, and the SSH
grants `ray apply` sends to a managed machine. The rule under test: a
controller may only make a managed machine join or leave networks the
controller coordinates, and its SSH grants only apply on those networks.

## Topology

```
srv-c  controller; coordinator of the closed network `ctl`
srv-m  managed machine, enrolled with srv-c
srv-y  coordinator of the closed network `other`; srv-c is only a member there
```

## What it proves

1. **Enrollment.** srv-m runs `ray controller add` with srv-c's one-time
   ticket. srv-m lists srv-c in `ray controller list --json` and in
   `ray status --json`; srv-c's `ray machines --json` probes srv-m as
   `online`, and `ray status --machines --json` lists it. The same ticket is
   refused on srv-y, which ends up trusting nobody.
2. **Delegated join.** `ray join --delegate <srv-m> ctl` puts srv-m on `ctl`
   as a member: both rosters hold the other, ping works both ways, and srv-c's
   probe reports the network.
3. **SSH grants.** Before the grant a stock `ssh` from srv-c to srv-m's mesh
   address cannot log in. `ray apply` with an `ssh:` block for srv-m saves a
   controller grant on srv-m (`managed_ssh_allow`), `ray ssh show` lists it,
   and the same `ssh` then logs in as the granted account.
4. **Delegated leave.** `ray leave --delegate <srv-m> ctl` takes srv-m off
   `ctl`, srv-c's roster drops it, and srv-m still trusts srv-c.
5. **Leave outside the controller's networks.** srv-m and srv-c both join
   `other` with srv-y's invites, so the network is active on srv-c and its
   request reaches srv-m. The delegated leave fails with srv-m's own
   "controller does not coordinate network" answer; srv-m stays on `other`,
   srv-y keeps it in the roster, and ping still works.
6. **SSH grants outside the controller's networks.** `ray apply` for `other`
   gets "controller is not a coordinator of this network" back from srv-m.
   Nothing is saved, nothing is listed, and with the mesh SSH server running
   (step 3 started it) srv-c cannot log in over `other`. As a control, a
   grant srv-m adds itself with `ray ssh allow` lets the same login in.
7. **Join outside the controller's networks.** srv-m leaves `other` itself,
   then `ray join --delegate <srv-m> other` fails and srv-m stays off `other`
   for 30 seconds, with srv-y never admitting it.
8. **Restart.** After `systemctl restart` on srv-m, it still lists srv-c,
   srv-c probes it as online, and a delegated join of `ctl` works again.
9. **Revocation.** `ray controller revoke` on srv-m empties its controller
   list. srv-c's next delegated leave fails as "revoked this controller",
   srv-m stays on `ctl`, and srv-c probes it as `unauthorized`.
10. **Logs.** No panic and no crash restart on any host.

## What the unit tests cover instead

A delegated join always mints its invite on the controller
(`ManagementService::delegated_join`), and minting needs the network key. So
in step 7 the refusal comes from srv-c before anything reaches srv-m: the CLI
cannot send srv-m a join for a network srv-c does not coordinate. The
machine-side half of the rule is covered in
`src/daemon/management_service/scope_tests.rs`:

- `controller_cannot_join_a_machine_with_a_foreign_invite`: an invite whose
  coordinator field is not the controller is refused.
- `a_delegated_join_dials_only_a_controller_the_roster_names_a_coordinator`:
  a controller that writes itself into another network's invite gets a join
  that dials only the controller, and only when the signed roster names it a
  coordinator.
- `controller_can_only_leave_networks_it_coordinates`: the leave check, also
  on management v1 (step 5 covers it over the current ALPN only).

## Run

```bash
tests/e2e.sh manage            # provision (if needed) + deploy + drive + assert
tests/e2e.sh manage teardown   # destroy the hosts
```

See [`../README.md`](../README.md) for prerequisites and environment overrides.
