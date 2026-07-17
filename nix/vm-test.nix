# Boot-tests the NixOS module in an offline VM: daemon up, IPC socket, TUN
# device, declarative settings converged (including the one settings-triggered
# restart), `ray apply` reconciled a network, and the operator model works.
#
# The VM has no internet, so everything asserted here must be offline-safe:
# pkarr/relay publishes are best-effort background work, and network creation
# is local-first.
{ rayfishModule }:
{
  name = "rayfish";

  nodes.machine =
    { ... }:
    {
      imports = [ rayfishModule ];

      services.resolved.enable = true;
      users.users.alice = {
        isNormalUser = true;
        password = "";
      };

      services.rayfish = {
        enable = true;
        operator = "alice";
        settings.dnsUpstreams = [ "9.9.9.9" ];
        apply.spec.networks.ci-net = { };
      };

      virtualisation.cores = 2;
      virtualisation.memorySize = 2048;
    };

  testScript = ''
    machine.wait_for_unit("rayfish.service")
    machine.wait_until_succeeds("test -S /var/run/rayfish/rayfish.sock", timeout=90)
    # `ray config get` fails while the daemon is unreachable (`ray status`
    # exits 0 even then, so it can't serve as a readiness probe).
    machine.wait_until_succeeds("ray config get", timeout=90)
    # The TUN device name is kernel-assigned (tun0, ...); assert on the mesh
    # route the daemon installs through it instead.
    machine.succeed("ip route show | grep -E '^100\\.64\\.0\\.0/10 dev tun'")

    # Settings oneshot converged (includes the one settings-triggered restart).
    machine.wait_for_unit("rayfish-settings.service")
    machine.succeed("ray config get dns-upstreams | grep -F 9.9.9.9")

    # Apply oneshot created the declared network.
    machine.wait_for_unit("rayfish-apply.service")
    machine.wait_until_succeeds("ray status | grep -F ci-net", timeout=60)

    # Operator model: alice may run mutating commands without root.
    machine.succeed("su - alice -c 'ray mdns off'")
  '';
}
