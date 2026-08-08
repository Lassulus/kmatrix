#!/usr/bin/env bash
# Build kmatrixd for armv7 static musl and assemble a device-installable bundle.
#
# The single most common way to ship a broken build here is to link against the
# host toolchain or against glibc: the devices run glibc ~2.20 on a 4.9 kernel,
# where both a newer dynamic glibc and a static glibc fail at process start.
# The `file` assertion below is therefore load-bearing, not decoration.
#
# This is the fast, incremental path via cargo-zigbuild, for iterating inside
# `nix develop`. For a reproducible sandboxed build use the flake instead:
#   nix build .#tarball
# Both produce the same static binary.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="armv7-unknown-linux-musleabihf"
BIN_NAME="kmatrixd"
MANIFEST="$ROOT/daemon/Cargo.toml"
BUILT="$ROOT/daemon/target/$TARGET/release/$BIN_NAME"
PLUGIN_SRC="$ROOT/plugin/kmatrix.koplugin"
DIST="$ROOT/dist"
TARBALL="$DIST/kmatrix-armv7.tar.gz"

die() {
	printf 'package: %s\n' "$*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 ||
		die "$1 is required but not on PATH (enter the dev shell: nix develop)"
}

need cargo
need cargo-zigbuild
need file
need tar

[ -f "$MANIFEST" ] || die "no daemon manifest at $MANIFEST"
[ -d "$PLUGIN_SRC" ] || die "plugin sources not found at $PLUGIN_SRC"
for lua in _meta.lua main.lua ipc.lua; do
	[ -f "$PLUGIN_SRC/$lua" ] || die "plugin file missing: $PLUGIN_SRC/$lua"
done

printf '==> building %s for %s\n' "$BIN_NAME" "$TARGET"
cargo zigbuild --release --target "$TARGET" --manifest-path "$MANIFEST"
[ -f "$BUILT" ] || die "build produced no binary at $BUILT"

printf '==> verifying link mode\n'
DESC="$(file -b "$BUILT")"
printf '    %s\n' "$DESC"
case "$DESC" in
*"ELF 32-bit"*ARM*"statically linked"*) ;;
*)
	die "REFUSING TO PACKAGE: $BUILT is not a statically linked 32-bit ARM ELF.
     file says: $DESC
     A dynamically linked or 64-bit binary will not start on the device."
	;;
esac

printf '==> assembling dist tree\n'
rm -rf "$DIST"
mkdir -p "$DIST/kmatrix" "$DIST/kmatrix.koplugin"

install -m 0755 "$BUILT" "$DIST/kmatrix/$BIN_NAME"
if command -v strip >/dev/null 2>&1; then
	strip --strip-all "$DIST/kmatrix/$BIN_NAME" 2>/dev/null ||
		printf '    strip refused the cross binary, shipping as built\n' >&2
fi

cp "$PLUGIN_SRC"/*.lua "$DIST/kmatrix.koplugin/"
chmod 0644 "$DIST/kmatrix.koplugin"/*.lua

printf '==> creating %s\n' "$TARBALL"
tar -czf "$TARBALL" -C "$DIST" kmatrix kmatrix.koplugin

printf '    %s: %s\n' "$BIN_NAME" "$(du -h "$DIST/kmatrix/$BIN_NAME" | cut -f1)"

cat <<EOF

Bundle: $TARBALL

Install. Paths below use the Kindle KOReader root /mnt/us/koreader; substitute
your KOReader data directory on reMarkable or Kobo.

  1. Copy the tarball to the device and unpack it:
       tar -xzf kmatrix-armv7.tar.gz -C /tmp

  2. Plugin -> KOReader's plugin directory:
       cp -r /tmp/kmatrix.koplugin /mnt/us/koreader/plugins/

  3. Daemon -> the kmatrix/ subdirectory of the KOReader data directory:
       mkdir -p /mnt/us/koreader/kmatrix
       cp /tmp/kmatrix/$BIN_NAME /mnt/us/koreader/kmatrix/
       chmod +x /mnt/us/koreader/kmatrix/$BIN_NAME

  4. Restart KOReader. The plugin launches
       $BIN_NAME --data-dir /mnt/us/koreader/kmatrix
     and connects over 127.0.0.1 using the port and token from
     kmatrix.port. The daemon keeps kmatrix.port, kmatrix.log and
     kmatrix.sqlite3 in that same directory.
EOF
