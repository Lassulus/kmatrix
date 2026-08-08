# kmatrix

A Matrix client that runs on the e-reader itself. It targets jailbroken devices
running KOReader: Kindle Paperwhite 5, reMarkable 2, and armv7 Kobo hardware.
Everything — TLS, sync, end-to-end encryption, message storage — happens on the
device; there is no companion server and no phone in the loop.

## Architecture

kmatrix is two processes:

- `kmatrixd` — a Rust daemon. Owns the network connection, TLS, the Matrix
  client-server API, streaming JSON decoding, the SQLite message store, and all
  Olm/Megolm crypto.
- `kmatrix.koplugin` — a KOReader Lua plugin. Draws the UI and nothing else.

They talk line-delimited JSON over TCP on `127.0.0.1`, authenticated with a
token the daemon writes to `kmatrix.port` (mode 0600). See `PROTOCOL.md`.

The split is not stylistic. KOReader's Lua environment cannot do this job:

- No async HTTP. A long-poll `/sync` from Lua blocks the UI thread for the
  duration of the poll.
- Its bundled LuaSec is configured with `verify = "none"`, so TLS certificates
  are not validated. Putting a Matrix access token behind that is not
  acceptable.
- Its bundled LuaSocket exports only `luaopen_socket_score`; there is no
  `socket.unix`, hence loopback TCP rather than a unix socket.
- No Olm/Megolm bindings, and no way to decode a multi-megabyte sync response
  without materialising all of it.

The daemon solves each of these once, in a language with the right libraries,
and hands the plugin small already-decrypted records.

## Measured behaviour

- The sync path deserializes straight into narrow typed structs rather than a
  generic JSON tree. Peak heap stays around 4 MiB regardless of account size;
  the generic-tree approach peaked 369x higher on the same payload. There is
  deliberately no catch-all `serde_json::Value` on the room-event path.
- Daemon RSS is about 3 MB under crypto workloads. Olm/Megolm costs roughly
  0.6 ms per message on these CPUs, which is not a constraint.
- One static armv7 musl binary runs unmodified on Kindle PW5, reMarkable 2 and
  armv7 Kobo.

## Building

The devices run a 32-bit hard-float ARM userland on glibc ~2.20 with a 4.9
kernel. A dynamically linked build fails with `GLIBC_2.xx not found`; a static
glibc build fails earlier still, inside `_dl_call_libc_early_init`. Static musl
is the only link mode that works, and the toolchain is zig via
`cargo-zigbuild` — the nixpkgs armv7 musl cross stdenv currently fails to build
because it pulls in a cross glibc that does not compile.

```sh
nix develop
./scripts/package.sh
```

`package.sh` builds `daemon/` for `armv7-unknown-linux-musleabihf`, asserts via
`file` that the result is a statically linked 32-bit ARM ELF (it refuses to
package anything else), strips it, and writes `dist/kmatrix-armv7.tar.gz`
containing `kmatrix/kmatrixd` and `kmatrix.koplugin/`.

To build by hand inside the dev shell:

```sh
cargo zigbuild --release --target armv7-unknown-linux-musleabihf \
  --manifest-path daemon/Cargo.toml
qemu-arm daemon/target/armv7-unknown-linux-musleabihf/release/kmatrixd
```

The flake exposes only `devShells.default`. There is no `packages.default`:
`rustPlatform.buildRustPackage` needs a committed `Cargo.lock`, and this repo
does not vendor one.

## Installing

Unpack `dist/kmatrix-armv7.tar.gz` on the device and place the two pieces.
Paths below use the Kindle KOReader root `/mnt/us/koreader`; substitute your
KOReader data directory on reMarkable or Kobo.

- `kmatrix.koplugin/` into KOReader's plugin directory:
  `/mnt/us/koreader/plugins/kmatrix.koplugin/`
- `kmatrixd` into the `kmatrix/` subdirectory of the KOReader data directory:
  `/mnt/us/koreader/kmatrix/kmatrixd`, and `chmod +x` it

Restart KOReader. The plugin launches
`kmatrixd --data-dir /mnt/us/koreader/kmatrix` on demand; the daemon keeps
`kmatrix.port`, `kmatrix.log` and `kmatrix.sqlite3` in that directory.

## Testing

`scripts/testserver.sh` runs a local `matrix-conduit` on
`http://127.0.0.1:6167` with open registration and encryption enabled. State
lives in `${TMPDIR:-/tmp}/kmatrix-testserver`.

```sh
./scripts/testserver.sh start
./scripts/testserver.sh register alice hunter2
./scripts/testserver.sh status
./scripts/testserver.sh stop
```

`register` drives the `m.login.dummy` UIAA flow over the CS-API and prints the
`user_id`, `device_id` and `access_token`. `start` blocks until
`/_matrix/client/versions` answers and fails with the server log tail if it
does not.

Point the daemon at `http://127.0.0.1:6167` to exercise login, sync, encrypted
room creation and message round-trips against it. Registering two accounts and
logging one of them in from a second client is enough to cover the
device-key/Olm/Megolm path.

## Layout

```
daemon/    kmatrixd, Rust
plugin/    kmatrix.koplugin, Lua
scripts/   testserver.sh, package.sh
PROTOCOL.md  daemon <-> plugin IPC contract
```
