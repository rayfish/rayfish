# Nixpkgs-style derivation for the ray CLI/daemon. Kept callPackage-compatible
# so it could move into nixpkgs unchanged; flake-specific wiring (gitSha) stays
# an optional argument.
{
  lib,
  rustPlatform,
  gitSha ? "unknown",
}:

rustPlatform.buildRustPackage {
  pname = "rayfish";
  version = (lib.importTOML ../Cargo.toml).package.version;

  # Everything cargo needs and nothing else, so docs/CI edits don't rebuild.
  # ray-mobile and benches are never built here but must be present: cargo
  # resolves workspace members and [[bench]] target paths at manifest parse
  # time. A new workspace member or moved source dir must be added here — the
  # nix CI job fails loudly if it isn't.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../build.rs
      ../src
      ../ray-proto
      ../ray-mobile
      ../benches
      # include_str!'d service templates (src/cli/service.rs)
      ../contrib
    ];
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
    # The [patch.crates-io] iroh fork is the only non-crates.io source; all
    # four crates come from the same repo+rev, so all four hashes are one
    # value. When the fork branch/rev changes: replace all four with
    # lib.fakeHash, `nix build`, copy the "got: sha256-…" hash from the error.
    outputHashes = {
      "iroh-1.0.2" = "sha256-oKDacCJxij/ydMVeqYXeUA8zkTYgnZTh/nt2Te4+WHE=";
      "iroh-base-1.0.2" = "sha256-oKDacCJxij/ydMVeqYXeUA8zkTYgnZTh/nt2Te4+WHE=";
      "iroh-dns-1.0.2" = "sha256-oKDacCJxij/ydMVeqYXeUA8zkTYgnZTh/nt2Te4+WHE=";
      "iroh-relay-1.0.2" = "sha256-oKDacCJxij/ydMVeqYXeUA8zkTYgnZTh/nt2Te4+WHE=";
    };
  };

  # Root package only; ray-mobile is Android-only and must not build here.
  cargoBuildFlags = [
    "--bin"
    "ray"
  ];

  # Unit tests run in .github/workflows/ci.yml with network available. The nix
  # sandbox has none; keeping checks off makes this derivation's failures mean
  # exactly "packaging broke".
  doCheck = false;

  # Consumed by build.rs (env override; no .git in the sandbox).
  env.RAY_GIT_SHA = gitSha;

  meta = {
    description = "P2P mesh VPN powered by iroh — connect peers by cryptographic identity, not IP address";
    homepage = "https://github.com/rayfish/rayfish";
    license = lib.licenses.mpl20;
    mainProgram = "ray";
    platforms = lib.platforms.linux ++ lib.platforms.darwin;
  };
}
