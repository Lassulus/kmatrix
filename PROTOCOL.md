# kmatrix IPC protocol

The daemon (`kmatrixd`) and the KOReader plugin (`kmatrix.koplugin`) both run **on the
device**. They talk over TCP on `127.0.0.1` — KOReader's bundled LuaSocket exports only
`luaopen_socket_score`, with no `socket.unix`, so AF_UNIX is not available.

## Handshake and authentication

On start the daemon writes `$DATADIR/kmatrix.port` with mode `0600`:

```
<port>\n<token>\n
```

A client MUST send `hello` with that token as its first line. Any other first command,
or a bad token, closes the connection. This keeps other local processes away from the
access token and decrypted message bodies.

## Framing

Line-delimited JSON, UTF-8, `\n` terminated. No embedded newlines (JSON escapes them).

- **Request** — client to daemon: `{"id": <u64>, "cmd": "<name>", ...}`
- **Response** — daemon to client, echoes `id`: `{"id": <u64>, "ok": true, ...}`
  or `{"id": <u64>, "ok": false, "error": "<message>"}`
- **Event** — daemon to client, unsolicited, never has `id`: `{"event": "<name>", ...}`

A client MUST tolerate events arriving between a request and its response, and MUST
match responses by `id` rather than by arrival order.

## Commands

| cmd | fields | response |
|---|---|---|
| `hello` | `token` | `{ok, version}` |
| `status` | | `{ok, state, user_id?, device_id?, homeserver?, error?}` |
| `login` | `homeserver`, `user`, `password` | `{ok, user_id, device_id}` |
| `logout` | | `{ok}` |
| `rooms` | | `{ok, rooms: [Room]}` |
| `messages` | `room`, `limit` | `{ok, room, messages: [Message]}` |
| `send` | `room`, `body` | `{ok, event_id}` |
| `mark_read` | `room`, `event_id` | `{ok}` |
| `sync_now` | | `{ok}` — wake the sync loop immediately |
| `backup_key` | `key` | `{ok, restored}` — see below |
| `verify_confirm` | `transaction`, `confirm` | `{ok}` — answer to the emoji prompt |
| `shutdown` | | `{ok}` |

`state` is one of `logged_out`, `connecting`, `syncing`, `offline`.
`status` also returns `backup`: whether a key-backup recovery key is held.

`backup_key` takes the server-side key backup's recovery key (Element calls it
the Security Key), validates it against the backup's advertised public key —
a wrong key is rejected immediately rather than producing garbage later — and
stores it. `restored` counts messages decrypted right away in the few most
recent rooms.

Recovery is otherwise **lazy**: `messages` triggers a per-room, per-session
fetch from the backup for that room's undecryptable history. A bulk
`GET /room_keys/keys` is deliberately not used; a real account here holds ~51k
sessions, which would cost tens of MB of RAM and rows on a 474 MB device.

## Events

| event | fields | meaning |
|---|---|---|
| `state` | `state`, `error?` | daemon state changed |
| `rooms` | `rooms: [Room]` | room list changed (name, unread, preview) |
| `messages` | `room`, `messages: [Message]` | new messages arrived |
| `verification` | `phase`, … | interactive device verification, see below |

### Verification

The daemon is **responder only**: verification is started from another client
(Element → Settings → Devices → Verify), never from here.

| phase | fields | meaning |
|---|---|---|
| `emoji` | `transaction`, `device`, `emoji: [[glyph, name], …7]` | show these and await `verify_confirm` |
| `done` | `device` | verified; the daemon now requests the backup key |
| `cancelled` | `reason` | the other side or we gave up |
| `secret` | `name` | a shared secret arrived and was accepted |

After `done` the daemon sends `m.secret.request` for `m.megolm_backup.v1` to
the account's other devices. A device that has just verified us will answer
with the backup key over Olm, so the recovery key never has to be typed. The
secret is validated against the backup's public key before being accepted.

## Types

```jsonc
// Room
{
  "id": "!abc:example.org",
  "name": "Team",           // falls back to room id when unnamed
  "encrypted": true,
  "unread": 3,
  "last_ts": 1732000000000, // ms since epoch, 0 if unknown
  "last_preview": "see you then"
}

// Message
{
  "event_id": "$abc",
  "room": "!abc:example.org",
  "sender": "@alice:example.org",
  "ts": 1732000000000,
  "body": "see you then",   // decryption failure -> placeholder, decrypted=false
  "encrypted": true,        // arrived as m.room.encrypted
  "decrypted": true,        // body is real plaintext
  "mine": false             // sent by us
}
```

Messages are ordered oldest-first. `body` is plain text; formatted bodies are flattened.
