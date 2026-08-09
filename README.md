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
is the only link mode that works.

### Flake outputs

```sh
nix build .#            # bundle: kmatrix/kmatrixd + kmatrix.koplugin/
nix build .#tarball     # the same, as a single .tar.gz to copy to a device
nix build .#armv7       # just the static armv7 daemon
nix build .#kmatrixd    # host build, runs the test suite in checkPhase
nix run   .# -- --data-dir ./scratch   # run the host daemon
```

`armv7` cross-compiles through `pkgsCross.armv7l-hf-multiplatform.pkgsMusl`
with `-C target-feature=+crt-static`, and its `postInstall` refuses to produce
an output that is not a statically linked ARM ELF — shipping a dynamic binary
is the easiest way to get a device that silently does nothing. Note that
`pkgsCross...pkgsMusl.buildPackages.gcc` does fail on current nixpkgs (it pulls
in a cross glibc that does not compile), but `pkgsMusl.rustPlatform` does not
go through that attribute and builds cleanly.

### Dev-shell build

The dev shell uses `cargo-zigbuild` instead, which is incremental and much
faster to iterate on. Both paths produce the same 2.8 MB static binary.

```sh
nix develop
./scripts/package.sh    # build, assert static ARM ELF, strip, write dist/

# or by hand
cargo zigbuild --release --target armv7-unknown-linux-musleabihf \
  --manifest-path daemon/Cargo.toml
qemu-arm daemon/target/armv7-unknown-linux-musleabihf/release/kmatrixd
```

## Installing

Unpack the tarball on the device — either `nix build .#tarball` (the result
symlink is the `.tar.gz`) or `dist/kmatrix-armv7.tar.gz` from `package.sh` —
and place the two pieces. Paths below use the Kindle KOReader root
`/mnt/us/koreader`; substitute your KOReader data directory on reMarkable or
Kobo.

- `kmatrix.koplugin/` into KOReader's plugin directory:
  `/mnt/us/koreader/plugins/kmatrix.koplugin/`
- `kmatrixd` into the `kmatrix/` subdirectory of the KOReader data directory:
  `/mnt/us/koreader/kmatrix/kmatrixd`, and `chmod +x` it

Restart KOReader. The plugin launches
`kmatrixd --data-dir /mnt/us/koreader/kmatrix` on demand; the daemon keeps
`kmatrix.port`, `kmatrix.log` and `kmatrix.sqlite3` in that directory.

### Data at rest

On a Kindle the KOReader directory lives on `/mnt/us`, which is the USB
mass-storage volume: plug the device into any computer and every file reads
out, no jailbreak and no authentication. The database holds message text,
room names, the access token and the key-backup private key.

So the store is encrypted, and the key is kept somewhere USB cannot reach —
`/var/local/kmatrix/store.key`, mode 0600, on `/dev/mmcblk0p9`, a separate
internal partition. Override with `--key-dir`, or opt out with
`--no-encryption`.

Encrypted: message bodies and retained ciphertext, room names and previews,
the access token, the key-backup key, and the pickle key (so the Olm/Megolm
pickles are protected transitively). Each value carries a fresh 16-byte salt
and is keyed by `master || salt` through vodozemac's `Cipher`, whose HKDF
gives every value its own AES key, MAC key and IV; the 32-byte HMAC is
verified before decrypting.

**Not** encrypted, and worth being clear about: event ids, room ids, senders
and timestamps. Message *contents* are protected; the *metadata* of who you
talk to and when is not. This defends against someone with a USB cable, not
against someone with a root shell — the key is readable by root on the
device.

An existing plaintext database is migrated in place on first run (~12 s for
12k messages on a PW5). If the key is ever lost, the data cannot be
recovered; `--reset-store` deletes the database so you can log in again.

## Testing

`scripts/testserver.sh` runs a local `matrix-conduit` on
`http://127.0.0.1:6167` with open registration and encryption enabled. State
lives in `/tmp/kmatrix-testserver` (override with `KMATRIX_TESTSERVER_DIR`);
it deliberately does not follow `$TMPDIR`, because `nix develop` sets a fresh
one per invocation and `start`/`stop` would lose each other.

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
room creation and message round-trips against it. Running two daemons with
separate `--data-dir`s and logging in as two accounts covers the whole
device-key/Olm/Megolm path, including key sharing over `/sendToDevice`.

`scripts/ipctest.lua` drives the plugin's `ipc.lua` against a running daemon
with the KOReader modules stubbed, so the non-blocking read, partial-line
buffering and request/response correlation can be checked without a device:

```sh
mkdir -p /tmp/kt/kmatrix
./daemon/target/release/kmatrixd --data-dir /tmp/kt/kmatrix &
luajit scripts/ipctest.lua /tmp/kt
```

It needs `luasocket` and a `json` module on `LUA_PATH` (`dkjson` works;
KOReader bundles its own).

## Layout

```
daemon/    kmatrixd, Rust
plugin/    kmatrix.koplugin, Lua
scripts/   testserver.sh, package.sh, ipctest.lua
PROTOCOL.md  daemon <-> plugin IPC contract
```

## License

MIT, see [LICENSE](LICENSE).
