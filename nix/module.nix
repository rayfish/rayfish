# NixOS module for the rayfish daemon.
#
# The daemon owns /etc/rayfish as *mutable* state: settings.toml and
# networks/<name>.toml mix operator config with runtime state (rosters,
# pending joins, cert generation) and are rewritten atomically by the daemon.
# Managing those files from the store would be silently clobbered on the
# first daemon write, so this module never touches them; every declarative
# knob is applied through the daemon's own idempotent CLI/IPC surface
# (`ray set-operator`, `ray config set`, `ray mdns`, `ray apply`) after the
# daemon is up.
#
# This file is flake-free on purpose (nixpkgs-adoptable); the flake wrapper
# in flake.nix defaults services.rayfish.package to the flake's build.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.rayfish;
  yamlFormat = pkgs.formats.yaml { };
  ray = lib.getExe cfg.package;

  # Effective apply spec file: an explicit specFile wins over rendered attrs.
  applySpecFile =
    if cfg.apply.specFile != null then
      cfg.apply.specFile
    else if cfg.apply.spec != null then
      # `ray apply` rejects anything not named *.yaml/*.yml.
      yamlFormat.generate "rayfish-apply.yaml" cfg.apply.spec
    else
      null;

  onOff = b: if b then "on" else "off";

  # Settings that the daemon only reads at startup; changing them requires a
  # daemon restart to take effect. Keyed list of `ray config set` invocations.
  restartRequiredSettings = lib.filterAttrs (_: v: v != null) {
    "relay" = cfg.settings.relay;
    "discovery-dns" = cfg.settings.discoveryDns;
    "dns-upstreams" = cfg.settings.dnsUpstreams;
    "on-demand" = cfg.settings.onDemand;
  };

  configSetLines = lib.mapAttrsToList (
    key: value:
    let
      rendered = if lib.isList value then lib.concatStringsSep "," value else onOff value;
    in
    "${ray} config set ${key} ${lib.escapeShellArg rendered} --replace"
  ) restartRequiredSettings;

  # Restart exactly once per change to the restart-required desired state
  # (not on package bumps — those already restart the unit via the normal
  # NixOS unit-change path).
  settingsGeneration = builtins.hashString "sha256" (builtins.toJSON restartRequiredSettings);

  wantSettingsUnit =
    cfg.operator != null || cfg.settings.mdns != null || restartRequiredSettings != { };
in
{
  options.services.rayfish = {
    enable = lib.mkEnableOption "rayfish P2P mesh VPN daemon";

    package = lib.mkPackageOption pkgs "rayfish" { };

    operator = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "alice";
      description = ''
        Unprivileged user authorized for mutating `ray` commands (the
        Tailscale operator model). Applied at runtime via `ray set-operator`;
        reads are open to any local user regardless.
      '';
    };

    logLevel = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "rayfish=trace";
      description = ''
        `RUST_LOG` filter for the daemon. When unset the daemon defaults to
        console `info` and rolling file logs at `rayfish=debug`.
      '';
    };

    extraFlags = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Extra command-line arguments passed to `ray daemon`.";
    };

    settings = {
      relay = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        example = [
          "n0"
          "https://relay.example.com"
        ];
        description = ''
          Relay servers (presets like `rayfish`/`n0`, or URLs), replacing the
          default set. `null` leaves the daemon's own setting alone.
        '';
      };

      discoveryDns = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        description = ''
          Discovery DNS servers (presets or URLs), replacing the default set.
          `null` leaves the daemon's own setting alone.
        '';
      };

      dnsUpstreams = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        example = [ "9.9.9.9" ];
        description = ''
          Upstream resolvers for non-`.ray` names traversing Magic DNS,
          replacing the default set. `null` leaves the daemon's own setting
          alone.
        '';
      };

      onDemand = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        description = ''
          Dial peers lazily on first packet and drop idle connections
          (daemon default: on). Set `false` on latency-sensitive nodes to
          keep connections warm. `null` leaves the daemon's own setting alone.
        '';
      };

      mdns = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        description = ''
          Local-network peer discovery via mDNS (daemon default: on).
          `null` leaves the daemon's own setting alone.
        '';
      };
    };

    apply = {
      spec = lib.mkOption {
        type = lib.types.nullOr yamlFormat.type;
        default = null;
        example = lib.literalExpression ''
          {
            networks.homelab = {
              server.allows."*" = "tcp:22,tcp:443";
            };
          }
        '';
        description = ''
          Declarative provisioning spec, rendered to YAML and reconciled with
          `ray apply` after the daemon starts (see the "Declarative
          provisioning" section of the README for the format). This is
          coordinator-side: it creates missing networks and publishes
          suggested firewalls, but never joins this node to a network —
          joining stays a one-time `ray join <invite>`. The spec carries no
          secrets, so it is safe in the world-readable Nix store.
        '';
      };

      specFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Path to a ready-made `ray apply` YAML spec (must end in `.yaml` or
          `.yml`). Mutually exclusive with {option}`services.rayfish.apply.spec`.
        '';
      };

      prune = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Pass `--prune` to `ray apply`: drop suggested-firewall subjects that
          are no longer in the spec instead of merging over the live set.
        '';
      };

      inviteMissing = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Pass `--invite-missing` to `ray apply`: mint one-time hostname-bound
          invites for hosts the spec expects but that haven't joined yet. The
          invites are printed to the unit's journal.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.apply.spec != null && cfg.apply.specFile != null);
        message = "services.rayfish.apply: set either `spec` or `specFile`, not both.";
      }
    ];

    warnings = lib.optional (!config.services.resolved.enable) ''
      services.rayfish: systemd-resolved is not enabled. Rayfish will fall
      back to NetworkManager/resolvconf or, as a last resort, take over
      /etc/resolv.conf directly for Magic DNS — which fights NixOS's
      declarative resolv.conf management. `services.resolved.enable = true`
      is strongly recommended.
    '';

    # Non-secret config files are chowned root:rayfish for group read.
    users.groups.rayfish = { };

    environment.systemPackages = [ cfg.package ];

    systemd.services.rayfish = {
      description = "rayfish P2P mesh VPN";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # `ip` for TUN link management; systemd for the resolvectl DNS fallback
      # (the preferred systemd-resolved path is D-Bus and needs no binary).
      path = [
        pkgs.iproute2
        config.systemd.package
      ];
      environment = lib.optionalAttrs (cfg.logLevel != null) { RUST_LOG = cfg.logLevel; };
      serviceConfig = {
        # The daemon requires root (TUN creation, /etc/rayfish, OS DNS) and
        # creates/owns /etc/rayfish, /var/log/rayfish and /var/run/rayfish
        # itself — the module deliberately manages none of them.
        ExecStart = "${ray} daemon ${lib.escapeShellArgs cfg.extraFlags}";
        # The daemon's panic hook restores DNS then abort()s, expecting the
        # supervisor to restart it from clean state; `ray stop`/`ray down`
        # semantics rely on clean exits staying down.
        Restart = "on-failure";
        RestartSec = 5;
      };
    };

    # Post-start convergence for operator + global settings. A oneshot whose
    # script embeds the desired values, so `nixos-rebuild switch` reruns it
    # exactly when they change.
    systemd.services.rayfish-settings = lib.mkIf wantSettingsUnit {
      description = "rayfish declarative settings";
      wantedBy = [ "multi-user.target" ];
      # Wants, not Requires: this unit restarts rayfish.service below, and a
      # Requires dependency would take this unit down with it.
      after = [ "rayfish.service" ];
      wants = [ "rayfish.service" ];
      # seq/sleep/cat for the script; systemctl for the settings-change restart.
      path = [
        pkgs.coreutils
        config.systemd.package
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "rayfish";
      };
      script = ''
        # `ray config get` is a real IPC round-trip that fails while the daemon
        # is down (`ray status` deliberately exits 0 then, showing saved config).
        wait_ready() {
          for _ in $(seq 60); do
            ${ray} config get >/dev/null 2>&1 && return 0
            sleep 1
          done
          echo "rayfish daemon did not become ready" >&2
          exit 1
        }
        wait_ready

        ${lib.optionalString (cfg.operator != null) "${ray} set-operator ${lib.escapeShellArg cfg.operator}"}
        ${lib.optionalString (cfg.settings.mdns != null) "${ray} mdns ${onOff cfg.settings.mdns}"}

        ${lib.concatStringsSep "\n" configSetLines}
        ${lib.optionalString (restartRequiredSettings != { }) ''
          # relay/discovery-dns/dns-upstreams/on-demand are read at daemon
          # startup; restart once per change to this desired state. The stamp
          # hashes the values (not the script path), so package bumps alone
          # don't cause a redundant extra restart. First boot restarts once
          # more than strictly needed (no stamp yet) — harmless.
          stamp=/var/lib/rayfish/nixos-settings-generation
          want=${settingsGeneration}
          if [ "$(cat "$stamp" 2>/dev/null || true)" != "$want" ]; then
            systemctl restart rayfish.service
            wait_ready
            echo "$want" > "$stamp"
          fi
        ''}
      '';
    };

    # Declarative one-shot reconcile of networks + suggested firewalls.
    systemd.services.rayfish-apply = lib.mkIf (applySpecFile != null) {
      description = "rayfish declarative network reconcile (ray apply)";
      wantedBy = [ "multi-user.target" ];
      after = [ "rayfish.service" ] ++ lib.optional wantSettingsUnit "rayfish-settings.service";
      wants = [ "rayfish.service" ];
      path = [ pkgs.coreutils ];
      restartTriggers = [ applySpecFile ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        for _ in $(seq 60); do
          ${ray} config get >/dev/null 2>&1 && break
          sleep 1
        done
        ${ray} apply ${applySpecFile} ${lib.optionalString cfg.apply.prune "--prune"} ${lib.optionalString cfg.apply.inviteMissing "--invite-missing"}
      '';
    };
  };
}
