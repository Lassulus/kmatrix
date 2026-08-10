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

        version = "0.1.0";

        # Host build. Handy for `nix run` against a local homeserver and for
        # running the test suite outside a dev shell.
        kmatrixd = pkgs.rustPlatform.buildRustPackage {
          pname = "kmatrixd";
          inherit version;
          src = ./daemon;
          cargoLock.lockFile = ./daemon/Cargo.lock;
          meta = {
            description = "On-device Matrix daemon for e-ink readers";
            mainProgram = "kmatrixd";
          };
        };

        # Device build: 32-bit hard-float ARM, statically linked against musl.
        crossPkgs = pkgs.pkgsCross.armv7l-hf-multiplatform.pkgsMusl;
        kmatrixdArmv7 = crossPkgs.rustPlatform.buildRustPackage {
          pname = "kmatrixd-armv7";
          inherit version;
          src = ./daemon;
          cargoLock.lockFile = ./daemon/Cargo.lock;
          # A dynamically linked binary would need the device's glibc; see the
          # note above. Force a fully static link and prove it stuck.
          RUSTFLAGS = "-C target-feature=+crt-static";
          doCheck = false; # host cannot execute ARM test binaries
          # The default fixup strips debug info only (-S), leaving ~1 MB of
          # symbols on a device where every megabyte is user storage.
          stripAllList = [ "bin" ];
          postInstall = ''
            if ! "$READELF" -h "$out/bin/kmatrixd" | grep -q 'ARM'; then
              echo "not an ARM binary" >&2; exit 1
            fi
            if "$READELF" -d "$out/bin/kmatrixd" 2>/dev/null | grep -q NEEDED; then
              echo "binary is dynamically linked; it will not run on the device" >&2
              exit 1
            fi
          '';
          READELF = "${crossPkgs.stdenv.cc.bintools.bintools}/bin/${crossPkgs.stdenv.cc.targetPrefix}readelf";
          meta.description = "kmatrixd for armv7 e-ink readers (static musl)";
        };

        # What you actually copy to a device: the ARM daemon plus the plugin.
        bundle = pkgs.runCommand "kmatrix-${version}-armv7" { } ''
          mkdir -p "$out/kmatrix" "$out/kmatrix.koplugin"
          cp ${kmatrixdArmv7}/bin/kmatrixd "$out/kmatrix/kmatrixd"
          chmod +x "$out/kmatrix/kmatrixd"
          cp ${./plugin/kmatrix.koplugin}/*.lua "$out/kmatrix.koplugin/"
        '';

        # Single file to move onto the device over USB or scp.
        tarball = pkgs.runCommand "kmatrix-${version}-armv7.tar.gz" { } ''
          tar -czf "$out" -C ${bundle} --owner=0 --group=0 kmatrix kmatrix.koplugin
        '';

        # Headless regression test for the plugin: it loads the real main.lua
        # with the whole KOReader layer stubbed, so it needs neither a daemon
        # nor a network nor a device -- only luajit, the interpreter the
        # devices actually run. Laid out as a checkout so the script finds the
        # plugin next to itself, the same way it does in a working tree.
        plugintest =
          pkgs.runCommand "kmatrix-plugintest"
            {
              nativeBuildInputs = [ pkgs.luajit ];
            }
            ''
              set -o pipefail
              mkdir -p src/scripts src/plugin
              cp ${./scripts/plugintest.lua} src/scripts/plugintest.lua
              cp -r ${./plugin/kmatrix.koplugin} src/plugin/kmatrix.koplugin
              luajit src/scripts/plugintest.lua 2>&1 | tee "$out"
            '';
      in
      {
        packages = {
          default = bundle;
          inherit kmatrixd bundle tarball;
          armv7 = kmatrixdArmv7;
        };

        apps.default = {
          type = "app";
          program = "${kmatrixd}/bin/kmatrixd";
        };

        checks = {
          inherit plugintest;
        };

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

              Reproducible sandboxed build (same static binary):
                nix build .#tarball

              Verify before copying to the device:
                file <bin>   # must say "statically linked"
            EOF
          '';
        };
      }
    );
}
