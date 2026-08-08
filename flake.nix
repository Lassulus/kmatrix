{
  description = "kmatrix - on-device Matrix client for jailbroken e-readers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # The devices run a 32-bit hard-float ARM userland on glibc ~2.20.
        # nixpkgs ships glibc 2.42, so a dynamic glibc build dies with
        # "GLIBC_2.xx not found", and a *static* glibc build dies even earlier
        # with the 4.9-kernel assertion
        #   _dl_call_libc_early_init: Assertion `sym != NULL' failed
        # Static musl is therefore the only viable link mode.
        #
        # The toolchain is zig, not a nixpkgs cross stdenv:
        # pkgsCross.armv7l-hf-multiplatform.pkgsMusl.buildPackages.gcc fails to
        # evaluate through to a build on current nixpkgs because it drags in a
        # cross glibc 2.42 that does not compile. zig ships musl headers and
        # libs for every target it knows, so cargo-zigbuild needs no cross
        # bootstrap at all and still builds the C dependencies (bundled
        # SQLite, vodozemac's C shims).
        target = "armv7-unknown-linux-musleabihf";
        targetEnv = "ARMV7_UNKNOWN_LINUX_MUSLEABIHF";
      in
      {
        # No packages.default: rustPlatform.buildRustPackage requires a
        # committed Cargo.lock (cargoLock.lockFile / cargoHash) and this repo
        # does not vendor one. Build via the devShell instead.

        # `nix fmt` hands the formatter bare paths, including directories and
        # non-Nix files, which nixfmt itself rejects. Fan out to *.nix and run
        # shfmt over the scripts in the same pass.
        formatter = pkgs.writeShellApplication {
          name = "kmatrix-fmt";
          runtimeInputs = [
            pkgs.nixfmt
            pkgs.shfmt
            pkgs.findutils
          ];
          text = ''
            for path in "''${@:-.}"; do
              if [ -d "$path" ]; then
                find "$path" -name '*.nix' -exec nixfmt {} +
                find "$path" -name '*.sh' -exec shfmt -w {} +
              else
                case "$path" in
                *.nix) nixfmt "$path" ;;
                *.sh) shfmt -w "$path" ;;
                esac
              fi
            done
          '';
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.rustup
            pkgs.gcc # host cc, for build scripts
            pkgs.zig # target cc, for C deps (sqlite, ...)
            pkgs.cargo-zigbuild
            pkgs.qemu # run the result without a device
            pkgs.binutils # strip, readelf
            pkgs.file # the static-link check in scripts/package.sh
            pkgs.matrix-conduit # local test homeserver
            pkgs.curl # CS-API pokes from scripts/testserver.sh
            pkgs.jq
            pkgs.shellcheck
          ];

          # The Kindle PW5 is a cortex-a53; koxtoolchain builds with -mfpu=neon
          # while rustc's default for this target is only VFPv3-D16, so ask for
          # NEON back. crt-static is what makes the binary standalone.
          env = {
            "CARGO_TARGET_${targetEnv}_RUSTFLAGS" =
              "-C target-feature=+crt-static,+neon -C target-cpu=cortex-a53";
          };

          shellHook = ''
                  export XDG_CACHE_HOME="''${XDG_CACHE_HOME:-$HOME/.cache}"
                  rustup target add ${target} 2>/dev/null || true
                  cat <<'EOF'
              kmatrix dev shell (target: armv7-unknown-linux-musleabihf, static musl)

                ./scripts/package.sh                 build + verify + bundle into dist/
                ./scripts/testserver.sh start        local conduit on 127.0.0.1:6167
                ./scripts/testserver.sh register u p create a test account

                cargo zigbuild --release --target armv7-unknown-linux-musleabihf
                qemu-arm ./target/armv7-unknown-linux-musleabihf/release/kmatrixd

              Verify before copying to the device:
                file <bin>   # must say "statically linked"
            EOF
          '';
        };
      }
    );
}
