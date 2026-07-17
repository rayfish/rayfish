{
  description = "Rayfish — P2P mesh VPN powered by iroh";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      eachSystem = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      gitSha = self.shortRev or self.dirtyShortRev or "unknown";
    in
    {
      overlays.default = final: _prev: {
        rayfish = final.callPackage ./nix/package.nix { inherit gitSha; };
      };

      packages = eachSystem (pkgs: rec {
        rayfish = pkgs.callPackage ./nix/package.nix { inherit gitSha; };
        default = rayfish;
      });

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            just
          ];
        };
      });

      # nix/module.nix is flake-free (nixpkgs-adoptable); this wrapper defaults
      # services.rayfish.package to the flake's build so consumers don't need
      # the overlay.
      nixosModules.rayfish =
        { pkgs, lib, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.rayfish.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.rayfish;
        };
      nixosModules.default = self.nixosModules.rayfish;

      checks = eachSystem (
        pkgs:
        {
          package = self.packages.${pkgs.stdenv.hostPlatform.system}.rayfish;
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          vm-test = pkgs.testers.runNixOSTest (
            import ./nix/vm-test.nix { rayfishModule = self.nixosModules.rayfish; }
          );
        }
      );
    };
}
