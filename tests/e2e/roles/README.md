# roles

Three hosts. Proves the one thing a hostname-keyed rule cannot do: cover a class
of nodes whose size changes.

| Host | Part |
|------|------|
| `srv-a` | coordinator, `ray apply` driver, the validator the rule protects |
| `srv-b` | sentry, joined with a reusable `--role sentry` key |
| `srv-c` | sentry, joined with the **same** key |

A hostname names one machine, and a reusable key refuses to bind one precisely
because it admits many. A role is shared by a class on purpose, so it can ride
that key: one code in a machine image or Terraform user-data seats the whole
group.

What each step asserts:

1. A `role:` spec publishes against an empty network. The role is reported as
   covering nobody rather than as a host that failed to turn up, and it never
   appears in the `--invite-missing` gap: there is no single machine to bind an
   invite to.
2. `--hostname` is still refused on a reusable key; `--role` is not. Both
   members redeem the same code and land under distinct names.
3. The roster carries the role. The coordinator wrote it from the redeemed key,
   so it is not something either node claimed about itself.
4. **The scale-out property.** The suggestion published in step 1 named no
   members. Two rules exist now, one per sentry, and nothing was applied in
   between: each node re-resolved `role:sentry` against the roster when it
   changed.
5. The resolved allow opens tcp:4000 over the TUN, and an un-listed port stays
   shut, so this is a real rule and not a display artefact.
6. `ray join --role validator` on a sentry key is refused, and says why. A role
   request can only ever narrow what the credential grants.
7. Re-joining with the granted role puts the rule count back, again with no
   apply.

Run it:

```bash
tests/e2e.sh roles                    # droplets
E2E_BACKEND=docker tests/e2e.sh roles # local containers
```
