//! Persistence. One SQLite file holds everything the daemon must survive a
//! restart with: the login session, the sync token, the room list, a message
//! backlog, and the pickled Olm/Megolm state.
//!
//! The device is slow and may lose power at any moment, so the connection runs
//! in WAL mode with `synchronous=NORMAL`: commits are durable across a process
//! crash without paying an fsync per transaction on every sync round.
//!
//! # Encryption at rest
//!
//! This file lives on `/mnt/us`, the partition the Kindle exports over USB
//! mass storage: plug the device into any computer and the whole database
//! reads out, no authentication involved. So the sensitive columns are
//! encrypted here and the master key lives on an internal partition that USB
//! never exposes; the caller loads it and hands it to [`Store::open`].
//!
//! That is the whole of the threat model, stated honestly: this defends
//! against someone with the USB cable. It does not defend against a root
//! shell on the device, which can read the key file just as easily as the
//! database. Anyone extending this should not mistake it for more.
//!
//! Encrypted: message bodies, room names and previews, the retained Megolm
//! ciphertext, and the `session`, `backup_key` and `pickle_key` entries of
//! `meta` -- the access token and both long-term secrets.
//!
//! Deliberately **not** encrypted, and you should know this before trusting
//! the file: event ids, room ids, senders, timestamps, and the `pickle`
//! table's `kind`/`id`/`extra` columns. Message *contents* are protected;
//! *metadata* -- who talked to whom, when, in which room -- is not. Hiding it
//! would mean giving up the `(room, ts)` index the device needs to open a
//! room without a full scan, and the session-id lookups the crypto layer does
//! on every encrypted event.
//!
//! The pickle blobs themselves are also left alone, on purpose. A libolm
//! pickle is already AES-256-CBC ciphertext under `pickle_key`, and
//! `pickle_key` is now itself encrypted, so the pickles are protected
//! transitively. Encrypting them again would buy nothing and cost a second
//! decrypt for every Megolm session at startup, of which there are hundreds.
//!
//! An encrypted value is stored as TEXT in the column it replaces:
//!
//! ```text
//! "k1:" || base64_standard( salt[16] || mac[32] || aes_256_cbc_ciphertext )
//! ```
//!
//! Every value gets a fresh 16-byte salt and is keyed with `master || salt`.
//! That is not belt-and-braces: `Cipher::new_pickle` derives the AES key, the
//! MAC key *and the IV* from the key material it is given, so one key means
//! one IV, and a fixed IV across values is a textbook CBC break -- two
//! messages sharing a prefix would share leading ciphertext blocks. The salt
//! is what makes each value's IV distinct.
//!
//! The `k1:` prefix is how an encrypted value is told from a legacy plaintext
//! one, which is what lets a database be migrated in place and stay readable
//! while half-migrated. A plaintext value that happened to begin with `k1:`
//! would be misread, but the window for that closes at migration: afterwards
//! every value in these columns really is `k1:`-prefixed.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;
use vodozemac::hazmat::{Cipher, Mac};

use crate::model::{Message, Room, Session};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS room (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    encrypted    INTEGER NOT NULL,
    unread       INTEGER NOT NULL,
    last_ts      INTEGER NOT NULL,
    last_preview TEXT NOT NULL,
    -- Backwards-pagination edge: how far into the room's history we have
    -- walked. Seeded once from the first `prev_batch` sync reports for the
    -- room, then only ever moved further back by /messages?dir=b. Never
    -- touched by a room upsert, so a later sync cannot skip history.
    back_token   TEXT,
    back_done    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS message (
    event_id  TEXT PRIMARY KEY,
    room      TEXT NOT NULL,
    sender    TEXT NOT NULL,
    ts        INTEGER NOT NULL,
    body      TEXT NOT NULL,
    encrypted INTEGER NOT NULL,
    decrypted INTEGER NOT NULL,
    mine      INTEGER NOT NULL,
    -- Set only while an encrypted event is still undecryptable, so that a room
    -- key recovered from the server-side backup later can turn the placeholder
    -- into the real message without refetching it. Cleared on success.
    session_id TEXT,
    ciphertext TEXT
);
CREATE INDEX IF NOT EXISTS message_room_ts ON message(room, ts);
CREATE TABLE IF NOT EXISTS pickle (
    kind   TEXT NOT NULL,
    id     TEXT NOT NULL,
    extra  TEXT NOT NULL,
    pickle TEXT NOT NULL,
    PRIMARY KEY (kind, id)
);
";

/// Key under which the serialized [`Session`] lives in `meta`.
const SESSION_KEY: &str = "session";

/// The `meta` entries that are secrets, each with the label used when an error
/// has to name it. Everything else in `meta` stays plaintext: `sync_token`,
/// `backup_version` and `device_keys_published` are not secrets, and
/// [`ENCRYPTED_FLAG`] in particular has to be readable *before* the key is
/// known.
const SECRET_META_KEYS: [(&str, &str); 3] = [
    (SESSION_KEY, "meta.session"),
    ("backup_key", "meta.backup_key"),
    ("pickle_key", "meta.pickle_key"),
];

/// Plaintext `meta` flag, set once every value covered by encryption has been
/// re-encrypted. Its absence, with a key configured, is what triggers the
/// one-time migration.
const ENCRYPTED_FLAG: &str = "store_encrypted";

/// Marks a column value as encrypted and names the format, so a future format
/// can be told from this one instead of being decrypted as garbage.
const ENC_PREFIX: &str = "k1:";

/// Per-value salt. Sixteen bytes is the CBC block size and plenty to keep the
/// derived IVs from colliding across the ~12k values on a real device.
const SALT_LEN: usize = 16;

/// Full-length HMAC-SHA256 tag, as produced by [`Cipher::mac`].
const MAC_LEN: usize = Mac::LENGTH;

pub struct Store {
    conn: Connection,
    /// The master key, or `None` to run unencrypted exactly as before it
    /// existed. Every read and write in this file goes through it.
    key: Option<[u8; 32]>,
}

/// `meta` is matched against a fixed list rather than encrypted wholesale,
/// because [`ENCRYPTED_FLAG`] and the sync token must stay readable without a
/// key.
fn secret_meta_label(k: &str) -> Option<&'static str> {
    SECRET_META_KEYS
        .iter()
        .find(|(name, _)| *name == k)
        .map(|(_, label)| *label)
}

/// The cipher for one value. `Cipher::new_pickle` accepts an arbitrary-length
/// key and runs HKDF-SHA256 over it, so appending a fresh salt to the master
/// key gives this value its own AES key, MAC key and IV.
fn value_cipher(master: &[u8; 32], salt: &[u8; SALT_LEN]) -> Cipher {
    let mut keyed = [0u8; 32 + SALT_LEN];
    keyed[..32].copy_from_slice(master);
    keyed[32..].copy_from_slice(salt);
    Cipher::new_pickle(&keyed)
}

/// Encrypt one value into the `k1:` form described at the top of the file.
fn seal(master: &[u8; 32], plaintext: &str) -> String {
    let salt: [u8; SALT_LEN] = rand::random();
    let cipher = value_cipher(master, &salt);
    let ciphertext = cipher.encrypt(plaintext.as_bytes());
    let mac = cipher.mac(&ciphertext);

    let mut blob = Vec::with_capacity(SALT_LEN + MAC_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(mac.as_bytes());
    blob.extend_from_slice(&ciphertext);

    let mut out = String::with_capacity(ENC_PREFIX.len() + blob.len().div_ceil(3) * 4);
    out.push_str(ENC_PREFIX);
    base64::engine::general_purpose::STANDARD.encode_string(&blob, &mut out);
    out
}

/// Read one stored value back. `column` names the column in any error, since
/// by the time this fails the caller has lost sight of what it was reading.
///
/// A value without the prefix is legacy plaintext and comes back untouched --
/// by value, so the common case does not copy. That is what keeps an
/// unencrypted database working and a half-migrated one intact.
fn unseal(master: Option<&[u8; 32]>, column: &str, stored: String) -> Result<String> {
    let Some(encoded) = stored.strip_prefix(ENC_PREFIX) else {
        return Ok(stored);
    };
    let Some(master) = master else {
        // Never fall back to handing the ciphertext or an empty string to the
        // caller: that would look like an empty room to the UI, and the next
        // write would overwrite real history with the emptiness.
        bail!(
            "{column} is encrypted but no store key is configured -- the store key file \
             is missing or unreadable. The message history and the access token are in \
             this database and cannot be recovered without that key; restore it rather \
             than deleting anything."
        );
    };

    let blob = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("decode encrypted {column}"))?;
    if blob.len() < SALT_LEN + MAC_LEN {
        bail!(
            "encrypted {column} is truncated: {} bytes, need at least {}",
            blob.len(),
            SALT_LEN + MAC_LEN
        );
    }
    let (salt, rest) = blob.split_at(SALT_LEN);
    let (mac, ciphertext) = rest.split_at(MAC_LEN);
    let mut salt_buf = [0u8; SALT_LEN];
    salt_buf.copy_from_slice(salt);
    let cipher = value_cipher(master, &salt_buf);

    // Authenticate before decrypting, so a tampered blob never reaches the
    // unpadding code. `Cipher::verify_mac` is gated behind vodozemac's
    // `experimental-session-config` feature, which we do not enable;
    // `verify_truncated_mac` is the same constant-time HMAC comparison against
    // the leftmost `tag.len()` bytes, so handing it all 32 verifies the whole
    // tag with no truncation at all.
    cipher.verify_truncated_mac(ciphertext, mac).map_err(|_| {
        anyhow!(
            "{column} failed authentication: the stored value has been altered, or the \
             store key does not belong to this database -- the data cannot be recovered \
             without the key it was written with"
        )
    })?;
    let plain = cipher
        .decrypt(ciphertext)
        .map_err(|e| anyhow!("decrypt {column}: {e}"))?;
    String::from_utf8(plain).with_context(|| format!("decrypted {column} is not valid UTF-8"))
}

impl Store {
    /// `key` is the master key for encryption at rest, or `None` to run
    /// unencrypted exactly as this store did before encryption existed. Where
    /// the key file lives and how it is created is the caller's business; this
    /// module never touches it.
    ///
    /// Opening with a key on a database that has not been encrypted yet
    /// migrates it in place, once. Opening *without* a key on one that has is
    /// refused outright rather than quietly writing plaintext beside it.
    pub fn open(path: &Path, key: Option<[u8; 32]>) -> Result<Store> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("create store directory {}", dir.display()))?;
            }
        }
        let mut conn = Connection::open(path)
            .with_context(|| format!("open store database {}", path.display()))?;

        // `journal_mode` reports the resulting mode as a result row, so it has
        // to be *queried*; `execute` would reject it as returning results. A
        // filesystem that cannot do WAL falls back silently rather than
        // refusing to start — a rollback-journal store still works.
        let _mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .context("set journal mode")?;
        conn.execute_batch("PRAGMA synchronous = NORMAL;")
            .context("set synchronous mode")?;
        // This file holds an access token and Olm/Megolm pickles. Without
        // secure_delete SQLite only unlinks freed pages, leaving the plaintext
        // readable in the file after logout.
        conn.execute_batch("PRAGMA secure_delete = ON;")
            .context("enable secure delete")?;
        // Equivalent to `PRAGMA busy_timeout = 5000`, without the result row.
        conn.busy_timeout(Duration::from_millis(5000))
            .context("set busy timeout")?;

        conn.execute_batch(SCHEMA).context("create schema")?;
        migrate(&conn)?;

        // Plaintext by design: this flag has to be legible before the key is
        // known, since it is what says whether a key is needed at all.
        let flag: Option<String> = conn
            .query_row(
                "SELECT v FROM meta WHERE k = ?1",
                params![ENCRYPTED_FLAG],
                |row| row.get(0),
            )
            .optional()
            .context("read store encryption flag")?;
        let encrypted = flag.as_deref() == Some("1");

        match &key {
            Some(master) if !encrypted => encrypt_existing(&mut conn, master)?,
            None if encrypted => bail!(
                "store database {} is encrypted but no store key was supplied -- the key \
                 file is missing or unreadable. The message history, the room list and \
                 the access token in it cannot be read or recovered without that key. \
                 Nothing has been modified; restore the key file.",
                path.display()
            ),
            // Key and flag agree, or there is nothing to protect: carry on.
            _ => {}
        }

        Ok(Store { conn, key })
    }

    // ----------------------------------------------------------- encryption

    /// Wrap a value on its way into the database. Borrows straight through
    /// when no key is configured, so the unencrypted path costs no allocation.
    fn protect<'a>(&self, plain: &'a str) -> Cow<'a, str> {
        match &self.key {
            Some(master) => Cow::Owned(seal(master, plain)),
            None => Cow::Borrowed(plain),
        }
    }

    fn protect_opt<'a>(&self, plain: Option<&'a str>) -> Option<Cow<'a, str>> {
        plain.map(|p| self.protect(p))
    }

    /// Unwrap a value read back out of `column`, which names the column in any
    /// error so a failure points at the row that caused it.
    fn reveal(&self, column: &str, stored: String) -> Result<String> {
        unseal(self.key.as_ref(), column, stored)
    }

    fn reveal_opt(&self, column: &str, stored: Option<String>) -> Result<Option<String>> {
        match stored {
            Some(s) => Ok(Some(self.reveal(column, s)?)),
            None => Ok(None),
        }
    }

    // -------------------------------------------------------------- session

    pub fn save_session(&self, s: &Session) -> Result<()> {
        let json = serde_json::to_string(s).context("serialize session")?;
        self.set_meta(SESSION_KEY, &json)
    }

    pub fn load_session(&self) -> Result<Option<Session>> {
        match self.get_meta(SESSION_KEY)? {
            Some(json) => Ok(Some(
                serde_json::from_str(&json).context("parse stored session")?,
            )),
            None => Ok(None),
        }
    }

    /// Wipe every table. Logout must not leave an access token or any crypto
    /// state on the device.
    pub fn clear(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "BEGIN;
                 DELETE FROM meta;
                 DELETE FROM room;
                 DELETE FROM message;
                 DELETE FROM pickle;
                 COMMIT;",
            )
            .context("clear store")?;
        // The wipe took `store_encrypted` with it. Put it straight back while
        // the key is still in hand, so the invariant "key configured implies
        // flag set" holds and the next open does not walk an empty database
        // looking for values to migrate.
        if self.key.is_some() {
            mark_encrypted(&self.conn)?;
        }
        // DELETE only frees pages; the file never shrinks on its own. VACUUM
        // rebuilds it compactly -- but in WAL mode the rebuilt pages land in
        // the WAL, so the *old* pages (with the access token) stay in the main
        // file until a checkpoint folds the new ones in. Order matters:
        // vacuum, then checkpoint. Measured on a real Kindle at 667 KB of WAL
        // against a 4 KB database.
        self.conn.execute_batch("VACUUM;").context("vacuum store")?;
        self.checkpoint()
    }

    /// Fold the write-ahead log back into the database and truncate it.
    /// SQLite never shrinks a WAL on its own, so a long-lived daemon on flash
    /// storage has to ask.
    pub fn checkpoint(&self) -> Result<()> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(()),
                other => Err(other),
            })
            .context("wal checkpoint")
    }

    // ----------------------------------------------------------------- meta

    /// Only the three secret keys are encrypted; see [`SECRET_META_KEYS`] for
    /// why the rest must stay legible.
    pub fn set_meta(&self, k: &str, v: &str) -> Result<()> {
        let stored = match secret_meta_label(k) {
            Some(_) => self.protect(v),
            None => Cow::Borrowed(v),
        };
        self.conn
            .execute(
                "INSERT INTO meta (k, v) VALUES (?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![k, stored.as_ref()],
            )
            .with_context(|| format!("write meta key {k}"))?;
        Ok(())
    }

    pub fn get_meta(&self, k: &str) -> Result<Option<String>> {
        let stored: Option<String> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |row| {
                row.get(0)
            })
            .optional()
            .with_context(|| format!("read meta key {k}"))?;
        match secret_meta_label(k) {
            Some(label) => self.reveal_opt(label, stored),
            None => Ok(stored),
        }
    }

    // ---------------------------------------------------------------- rooms

    /// Writes only the columns sync owns. `back_token` and `back_done` are
    /// deliberately absent from both the insert list and the conflict update:
    /// sync upserts a room on every round, and including them would reset the
    /// pagination edge to NULL each time, losing the backfill progress.
    pub fn upsert_room(&self, r: &Room) -> Result<()> {
        let name = self.protect(&r.name);
        let preview = self.protect(&r.last_preview);
        self.conn
            .execute(
                "INSERT INTO room (id, name, encrypted, unread, last_ts, last_preview)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                     name         = excluded.name,
                     encrypted    = excluded.encrypted,
                     unread       = excluded.unread,
                     last_ts      = excluded.last_ts,
                     last_preview = excluded.last_preview",
                params![
                    r.id,
                    name.as_ref(),
                    r.encrypted as i64,
                    r.unread as i64,
                    r.last_ts as i64,
                    preview.as_ref(),
                ],
            )
            .with_context(|| format!("upsert room {}", r.id))?;
        Ok(())
    }

    pub fn list_rooms(&self) -> Result<Vec<Room>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, name, encrypted, unread, last_ts, last_preview
                 FROM room ORDER BY last_ts DESC, id ASC",
            )
            .context("prepare room list")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Room {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    encrypted: row.get::<_, i64>(2)? != 0,
                    unread: row.get::<_, i64>(3)?.max(0) as u32,
                    last_ts: row.get::<_, i64>(4)?.max(0) as u64,
                    last_preview: row.get(5)?,
                })
            })
            .context("query rooms")?;
        let mut out = Vec::new();
        for r in rows {
            let mut r = r.context("read room row")?;
            r.name = self.reveal("room.name", r.name)?;
            r.last_preview = self.reveal("room.last_preview", r.last_preview)?;
            out.push(r);
        }
        Ok(out)
    }

    /// Fetch one room by id. The sync loop needs this per room in a batch;
    /// doing it with `list_rooms()` is a full table scan each time, which on
    /// a 766-room account is ~590k row materializations per full sync.
    pub fn get_room(&self, id: &str) -> Result<Option<Room>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, name, encrypted, unread, last_ts, last_preview
                 FROM room WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Room {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        encrypted: row.get::<_, i64>(2)? != 0,
                        unread: row.get::<_, i64>(3)?.max(0) as u32,
                        last_ts: row.get::<_, i64>(4)?.max(0) as u64,
                        last_preview: row.get(5)?,
                    })
                },
            )
            .optional()
            .with_context(|| format!("get room {id}"))?;
        match row {
            Some(mut r) => {
                r.name = self.reveal("room.name", r.name)?;
                r.last_preview = self.reveal("room.last_preview", r.last_preview)?;
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }

    // ------------------------------------------------- backwards pagination

    /// The room's backwards-pagination edge as `(token, done)`.
    ///
    /// `None` means no `prev_batch` has ever been recorded for the room, so
    /// there is nowhere to page back from yet. `done` is set once the server
    /// has told us we reached the start of the room. An unknown room reads as
    /// `(None, false)`.
    pub fn back_token(&self, room: &str) -> Result<(Option<String>, bool)> {
        let row = self
            .conn
            .query_row(
                "SELECT back_token, back_done FROM room WHERE id = ?1",
                params![room],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()
            .with_context(|| format!("read back token for {room}"))?;
        Ok(row.unwrap_or((None, false)))
    }

    /// Record the first `prev_batch` we ever saw for a room, and only that
    /// one: returns `true` when it was written, `false` when a token was
    /// already there. Every later sync reports a `prev_batch` pointing at a
    /// *newer* position, so overwriting would jump the edge forward and skip
    /// the history in between.
    ///
    /// The room row is written by [`Store::upsert_room`] first; seeding a room
    /// the store has never seen writes nothing and returns `false`.
    pub fn seed_back_token(&self, room: &str, token: &str) -> Result<bool> {
        let n = self
            .conn
            .execute(
                "UPDATE room SET back_token = ?2
                 WHERE id = ?1 AND back_token IS NULL",
                params![room, token],
            )
            .with_context(|| format!("seed back token for {room}"))?;
        Ok(n > 0)
    }

    /// Move the walking edge to where the last `/messages?dir=b` page ended.
    /// `done` marks that the start of the room has been reached, which is what
    /// a missing `end` token or an empty chunk means.
    pub fn set_back_token(&self, room: &str, token: Option<&str>, done: bool) -> Result<()> {
        self.conn
            .execute(
                "UPDATE room SET back_token = ?2, back_done = ?3 WHERE id = ?1",
                params![room, token, done as i64],
            )
            .with_context(|| format!("set back token for {room}"))?;
        Ok(())
    }

    // ------------------------------------------------------------- messages

    /// Idempotent by `event_id`. A re-insert may only *upgrade* a row: when a
    /// room key arrives late, the same event is written again with the plain
    /// body and `decrypted = 1`, replacing the placeholder in place.
    ///
    /// `ciphertext` is encrypted along with `body`. It is Megolm ciphertext,
    /// so it is not readable plaintext to begin with -- but it is readable to
    /// anyone who later gets the room key, which is exactly what the key
    /// backup hands out, and it sits in the same column family as the body it
    /// will become. Encrypting it keeps one rule for the whole row instead of
    /// an exception to explain. `session_id` stays plaintext: it is a lookup
    /// key, and the crypto layer matches on it.
    pub fn insert_message(&self, m: &Message) -> Result<()> {
        let body = self.protect(&m.body);
        let ciphertext = self.protect_opt(m.ciphertext.as_deref());
        self.conn
            .execute(
                "INSERT INTO message
                     (event_id, room, sender, ts, body, encrypted, decrypted, mine,
                      session_id, ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(event_id) DO UPDATE SET
                     body       = excluded.body,
                     decrypted  = excluded.decrypted,
                     session_id = excluded.session_id,
                     ciphertext = excluded.ciphertext",
                params![
                    m.event_id,
                    m.room,
                    m.sender,
                    m.ts as i64,
                    body.as_ref(),
                    m.encrypted as i64,
                    m.decrypted as i64,
                    m.mine as i64,
                    m.session_id,
                    ciphertext.as_deref(),
                ],
            )
            .with_context(|| format!("insert message {}", m.event_id))?;
        Ok(())
    }

    /// The newest `limit` messages of `room`, returned oldest-first so the UI
    /// can append them in reading order.
    pub fn recent_messages(&self, room: &str, limit: u32) -> Result<Vec<Message>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT event_id, room, sender, ts, body, encrypted, decrypted, mine,
                        session_id, ciphertext
                 FROM message WHERE room = ?1
                 ORDER BY ts DESC, event_id DESC LIMIT ?2",
            )
            .context("prepare message query")?;
        let rows = stmt
            .query_map(params![room, limit as i64], |row| {
                Ok(Message {
                    event_id: row.get(0)?,
                    room: row.get(1)?,
                    sender: row.get(2)?,
                    ts: row.get::<_, i64>(3)?.max(0) as u64,
                    body: row.get(4)?,
                    encrypted: row.get::<_, i64>(5)? != 0,
                    decrypted: row.get::<_, i64>(6)? != 0,
                    mine: row.get::<_, i64>(7)? != 0,
                    session_id: row.get(8)?,
                    ciphertext: row.get(9)?,
                })
            })
            .with_context(|| format!("query messages for {room}"))?;
        let mut out = Vec::with_capacity(limit.min(512) as usize);
        for m in rows {
            let mut m = m.context("read message row")?;
            m.body = self.reveal("message.body", m.body)?;
            m.ciphertext = self.reveal_opt("message.ciphertext", m.ciphertext.take())?;
            out.push(m);
        }
        out.reverse();
        Ok(out)
    }

    /// How many recent messages in a room are locked with nothing left to
    /// retry: stored before the client began retaining ciphertext, so the
    /// only way to read them is to fetch the original events again.
    pub fn placeholders_without_ciphertext(&self, room: &str, limit: u32) -> Result<usize> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM (
                     SELECT 1 FROM message
                     WHERE room = ?1 AND encrypted = 1 AND decrypted = 0
                       AND ciphertext IS NULL
                     ORDER BY ts DESC LIMIT ?2)",
                params![room, limit as i64],
                |row| row.get(0),
            )
            .with_context(|| format!("count stale placeholders for {room}"))?;
        Ok(n as usize)
    }

    /// Undecryptable messages in a room, newest first, that still carry the
    /// ciphertext needed to retry. Returns `(event_id, session_id, ciphertext)`.
    ///
    /// Rows written before the ciphertext columns existed, and rows we can
    /// already read, are skipped: there is nothing to retry for either.
    pub fn undecrypted_in_room(
        &self,
        room: &str,
        limit: u32,
    ) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT event_id, session_id, ciphertext
                 FROM message
                 WHERE room = ?1 AND encrypted = 1 AND decrypted = 0
                   AND session_id IS NOT NULL AND ciphertext IS NOT NULL
                 ORDER BY ts DESC, event_id DESC LIMIT ?2",
            )
            .context("prepare undecrypted message query")?;
        let rows = stmt
            .query_map(params![room, limit as i64], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .with_context(|| format!("query undecrypted messages for {room}"))?;
        let mut out = Vec::new();
        for r in rows {
            let (event_id, session_id, ciphertext): (String, String, String) =
                r.context("read undecrypted message row")?;
            let ciphertext = self.reveal("message.ciphertext", ciphertext)?;
            out.push((event_id, session_id, ciphertext));
        }
        Ok(out)
    }

    /// A message we could not read before has been decrypted with a key
    /// recovered from the backup: replace the placeholder body in place and drop
    /// the retained ciphertext, which has done its job.
    ///
    /// A row that is no longer there is not an error; the backlog may have been
    /// trimmed between listing the retries and finishing them.
    pub fn upgrade_message(&self, event_id: &str, body: &str) -> Result<()> {
        let body = self.protect(body);
        self.conn
            .execute(
                "UPDATE message
                 SET body = ?2, decrypted = 1, session_id = NULL, ciphertext = NULL
                 WHERE event_id = ?1",
                params![event_id, body.as_ref()],
            )
            .with_context(|| format!("upgrade message {event_id}"))?;
        Ok(())
    }

    // -------------------------------------------------------------- pickles

    pub fn put_pickle(&self, kind: &str, id: &str, extra: &str, pickle: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO pickle (kind, id, extra, pickle) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(kind, id) DO UPDATE SET
                     extra  = excluded.extra,
                     pickle = excluded.pickle",
                params![kind, id, extra, pickle],
            )
            .with_context(|| format!("store {kind} pickle {id}"))?;
        Ok(())
    }

    pub fn all_pickles(&self, kind: &str) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, extra, pickle FROM pickle WHERE kind = ?1 ORDER BY id ASC")
            .context("prepare pickle query")?;
        let rows = stmt
            .query_map(params![kind], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .with_context(|| format!("query {kind} pickles"))?;
        let mut out = Vec::new();
        for p in rows {
            out.push(p.context("read pickle row")?);
        }
        Ok(out)
    }
}

/// Bring an existing database up to the current schema. `CREATE TABLE IF NOT
/// EXISTS` leaves an already-present table exactly as it was, so columns added
/// after a release have to be bolted on by hand — a device holding thousands of
/// messages cannot afford to have the table dropped and rebuilt.
fn migrate(conn: &Connection) -> Result<()> {
    // (table, column, declaration). Grouped by table so each one is inspected
    // once; a fresh database created from SCHEMA already has every column and
    // this whole pass is a no-op.
    const ADDED: [(&str, &[(&str, &str)]); 2] = [
        ("message", &[("session_id", "TEXT"), ("ciphertext", "TEXT")]),
        (
            "room",
            &[
                ("back_token", "TEXT"),
                ("back_done", "INTEGER NOT NULL DEFAULT 0"),
            ],
        ),
    ];

    for (table, columns) in ADDED {
        let mut present: Vec<String> = Vec::new();
        conn.pragma(None, "table_info", table, |row| {
            present.push(row.get(1)?);
            Ok(())
        })
        .with_context(|| format!("inspect {table} columns"))?;

        for (column, decl) in columns {
            if present.iter().any(|c| c == column) {
                continue;
            }
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl};"))
                .with_context(|| format!("add {table} column {column}"))?;
        }
    }
    Ok(())
}

/// Set the plaintext flag that says every value covered by encryption is
/// encrypted. Takes a bare `&Connection` so it can be written through a
/// transaction handle, landing atomically with the values it describes.
fn mark_encrypted(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (k, v) VALUES (?1, '1')
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![ENCRYPTED_FLAG],
    )
    .context("mark store encrypted")?;
    Ok(())
}

/// Re-encrypt everything encryption covers, then set [`ENCRYPTED_FLAG`], all
/// in one transaction. Runs once, on the first open with a key.
///
/// Idempotent by construction: a value that already carries [`ENC_PREFIX`] is
/// left exactly as it is, so an interrupted run costs only the work it had
/// already done. Nothing here can lose data -- either the transaction commits
/// whole or the database is untouched and the flag stays unset, and the next
/// open tries again.
fn encrypt_existing(conn: &mut Connection, master: &[u8; 32]) -> Result<()> {
    // Immediate, not deferred: take the write lock up front rather than
    // discovering halfway through a 12k-row rewrite that another process holds
    // it and having to roll the whole thing back.
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin store encryption")?;

    for (key, label) in SECRET_META_KEYS {
        let stored: Option<String> = tx
            .query_row("SELECT v FROM meta WHERE k = ?1", params![key], |row| {
                row.get(0)
            })
            .optional()
            .with_context(|| format!("read {label} for encryption"))?;
        let Some(value) = stored else { continue };
        if value.starts_with(ENC_PREFIX) {
            continue;
        }
        tx.execute(
            "UPDATE meta SET v = ?2 WHERE k = ?1",
            params![key, seal(master, &value)],
        )
        .with_context(|| format!("encrypt {label}"))?;
    }

    // Rooms are few -- hundreds even on a heavy account -- and names and
    // previews are short, so the whole table fits in memory comfortably.
    let rooms: Vec<(String, String, String)> = {
        let mut stmt = tx
            .prepare("SELECT id, name, last_preview FROM room")
            .context("prepare room encryption scan")?;
        let mapped = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .context("scan rooms for encryption")?;
        let mut rooms = Vec::new();
        for r in mapped {
            rooms.push(r.context("read room row for encryption")?);
        }
        rooms
    };
    {
        let mut update = tx
            .prepare("UPDATE room SET name = ?2, last_preview = ?3 WHERE id = ?1")
            .context("prepare room encryption update")?;
        for (id, name, preview) in rooms {
            let name_done = name.starts_with(ENC_PREFIX);
            let preview_done = preview.starts_with(ENC_PREFIX);
            if name_done && preview_done {
                continue;
            }
            let name = if name_done { name } else { seal(master, &name) };
            let preview = if preview_done {
                preview
            } else {
                seal(master, &preview)
            };
            update
                .execute(params![id, name, preview])
                .with_context(|| format!("encrypt room {id}"))?;
        }
    }

    // Messages are the big table: ~12k rows on the live device, bodies of
    // arbitrary length. Walk it in rowid-ordered chunks so peak memory stays
    // bounded by the chunk rather than the backlog, and so the scan never
    // reads rows this same transaction is rewriting -- SQLite leaves that
    // undefined. Rewriting a body cannot change a rowid, so the cursor keeps
    // moving forward.
    const CHUNK: usize = 512;
    let mut after: i64 = 0;
    let mut batch: Vec<(i64, String, Option<String>)> = Vec::with_capacity(CHUNK);
    loop {
        batch.clear();
        {
            let mut stmt = tx
                .prepare_cached(
                    "SELECT rowid, body, ciphertext FROM message
                     WHERE rowid > ?1 ORDER BY rowid LIMIT ?2",
                )
                .context("prepare message encryption scan")?;
            let mapped = stmt
                .query_map(params![after, CHUNK as i64], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .context("scan messages for encryption")?;
            for m in mapped {
                batch.push(m.context("read message row for encryption")?);
            }
        }
        let Some((last, _, _)) = batch.last() else {
            break;
        };
        after = *last;

        let mut update = tx
            .prepare_cached("UPDATE message SET body = ?2, ciphertext = ?3 WHERE rowid = ?1")
            .context("prepare message encryption update")?;
        for (rowid, body, ciphertext) in batch.drain(..) {
            let body_done = body.starts_with(ENC_PREFIX);
            let ciphertext_done = match &ciphertext {
                Some(c) => c.starts_with(ENC_PREFIX),
                // Nothing to encrypt is nothing to do.
                None => true,
            };
            if body_done && ciphertext_done {
                continue;
            }
            let body = if body_done { body } else { seal(master, &body) };
            let ciphertext = match ciphertext {
                Some(c) if !ciphertext_done => Some(seal(master, &c)),
                other => other,
            };
            update
                .execute(params![rowid, body, ciphertext])
                .with_context(|| format!("encrypt message rowid {rowid}"))?;
        }
    }

    mark_encrypted(&tx)?;
    tx.commit().context("commit store encryption")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Owns a scratch directory under the system temp dir and removes it (plus
    /// the WAL sidecar files) when the test ends, panic or not.
    struct TempDb {
        dir: PathBuf,
    }

    impl TempDb {
        fn new() -> TempDb {
            let n: u64 = rand::random();
            TempDb {
                dir: std::env::temp_dir().join(format!("kmatrix-store-test-{n:016x}")),
            }
        }

        fn path(&self) -> PathBuf {
            self.dir.join("store.db")
        }

        /// The unencrypted store, which is what the pre-encryption tests all
        /// exercise.
        fn open(&self) -> Store {
            match Store::open(&self.path(), None) {
                Ok(s) => s,
                Err(e) => panic!("open store: {e:#}"),
            }
        }

        /// The same store with encryption on, under [`KEY_A`].
        fn keyed(&self) -> Store {
            match Store::open(&self.path(), Some(KEY_A)) {
                Ok(s) => s,
                Err(e) => panic!("open keyed store: {e:#}"),
            }
        }

        /// A second, plain connection to the same file. Encryption tests read
        /// raw column text through this to check what actually hit the disk;
        /// asking the `Store` would only ever show them the plaintext again.
        fn raw(&self) -> Connection {
            match Connection::open(self.path()) {
                Ok(c) => c,
                Err(e) => panic!("open raw connection: {e}"),
            }
        }
    }

    const KEY_A: [u8; 32] = [0x5a; 32];
    const KEY_B: [u8; 32] = [0xa5; 32];

    /// One TEXT cell, straight off the disk with no decryption in the way.
    fn raw_cell(conn: &Connection, sql: &str, key: &str) -> String {
        match conn.query_row(sql, params![key], |row| row.get::<_, String>(0)) {
            Ok(v) => v,
            Err(e) => panic!("read raw cell ({sql}) for {key}: {e}"),
        }
    }

    fn raw_body(conn: &Connection, event_id: &str) -> String {
        raw_cell(
            conn,
            "SELECT body FROM message WHERE event_id = ?1",
            event_id,
        )
    }

    fn raw_meta(conn: &Connection, k: &str) -> String {
        raw_cell(conn, "SELECT v FROM meta WHERE k = ?1", k)
    }

    /// Asserts that `stored` is an encrypted blob and that `plain` is nowhere
    /// in it -- the second half is the point, since a prefix alone would also
    /// be satisfied by `"k1:" + plaintext`.
    fn assert_sealed(stored: &str, plain: &str, what: &str) {
        assert!(
            stored.starts_with(ENC_PREFIX),
            "{what} was stored unencrypted: {stored}"
        );
        assert!(
            !stored.contains(plain),
            "{what} leaks its plaintext into the stored blob: {stored}"
        );
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn msg(event_id: &str, ts: u64, body: &str, decrypted: bool) -> Message {
        Message {
            event_id: event_id.into(),
            room: "!r:example.org".into(),
            sender: "@alice:example.org".into(),
            ts,
            body: body.into(),
            encrypted: true,
            decrypted,
            mine: false,
            session_id: None,
            ciphertext: None,
        }
    }

    /// An undecryptable message that still has everything needed for a retry.
    fn retryable(event_id: &str, ts: u64) -> Message {
        let mut m = msg(event_id, ts, "[encrypted]", false);
        m.session_id = Some(format!("S-{event_id}"));
        m.ciphertext = Some(format!("C-{event_id}"));
        m
    }

    #[test]
    fn session_round_trip() {
        let tmp = TempDb::new();
        let store = tmp.open();

        assert!(store.load_session().expect("load empty").is_none());

        let session = Session {
            homeserver: "https://example.org".into(),
            user_id: "@alice:example.org".into(),
            device_id: "DEV1".into(),
            access_token: "syt_secret".into(),
        };
        store.save_session(&session).expect("save session");

        let got = store
            .load_session()
            .expect("load")
            .expect("session present");
        assert_eq!(got.homeserver, session.homeserver);
        assert_eq!(got.user_id, session.user_id);
        assert_eq!(got.device_id, session.device_id);
        assert_eq!(got.access_token, session.access_token);
    }

    #[test]
    fn open_creates_missing_parent_dirs() {
        let tmp = TempDb::new();
        let path = tmp.dir.join("nested/deeper/store.db");
        let store = Store::open(&path, None).expect("open nested");
        store.set_meta("k", "v").expect("write");
        assert!(path.exists());
    }

    #[test]
    fn clear_wipes_every_table() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store
            .save_session(&Session {
                homeserver: "https://example.org".into(),
                user_id: "@alice:example.org".into(),
                device_id: "DEV1".into(),
                access_token: "syt_secret".into(),
            })
            .expect("save session");
        store.set_meta("sync_token", "s123").expect("save token");
        store
            .upsert_room(&Room {
                id: "!r:example.org".into(),
                name: "Room".into(),
                encrypted: true,
                unread: 3,
                last_ts: 10,
                last_preview: "hi".into(),
            })
            .expect("upsert room");
        store
            .insert_message(&msg("$1", 10, "hi", true))
            .expect("insert message");
        store
            .put_pickle("account", "self", "", "PICKLE")
            .expect("put pickle");

        store.clear().expect("clear");

        assert!(store.load_session().expect("load session").is_none());
        assert!(store.get_meta("sync_token").expect("get meta").is_none());
        assert!(store.list_rooms().expect("list rooms").is_empty());
        assert!(store
            .recent_messages("!r:example.org", 50)
            .expect("recent")
            .is_empty());
        assert!(store.all_pickles("account").expect("pickles").is_empty());
    }

    /// Logout must not leave the access token recoverable in the write-ahead
    /// log, and must not leave the WAL occupying device flash. Measured on a
    /// real Kindle: 667 KB of WAL against a 4 KB database before this.
    #[test]
    fn clear_truncates_the_wal_and_leaves_no_token() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store
            .save_session(&Session {
                homeserver: "https://example.org".into(),
                user_id: "@alice:example.org".into(),
                device_id: "DEV1".into(),
                access_token: "syt_supersecret_token".into(),
            })
            .expect("save session");
        for i in 0..500 {
            store
                .insert_message(&msg(&format!("$e{i}"), i as u64, "padding padding", true))
                .expect("insert");
        }
        let db = tmp.path();
        let wal = db.with_file_name("store.db-wal");
        let shm = db.with_file_name("store.db-shm");
        let before = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert!(before > 0, "expected a non-empty WAL to have built up");

        store.clear().expect("clear");

        let after = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert!(after < before, "WAL did not shrink: {before} -> {after}");

        // The token must not survive anywhere in the on-disk files.
        for p in [db, wal, shm] {
            if let Ok(bytes) = std::fs::read(&p) {
                assert!(
                    !bytes
                        .windows(b"syt_supersecret_token".len())
                        .any(|w| w == b"syt_supersecret_token"),
                    "access token still present in {}",
                    p.display()
                );
            }
        }
    }

    #[test]
    fn insert_message_upgrades_in_place() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store
            .insert_message(&msg("$evt", 100, "[encrypted]", false))
            .expect("insert placeholder");
        store
            .insert_message(&msg("$evt", 100, "the real text", true))
            .expect("insert upgrade");

        let all = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(all.len(), 1, "re-insert must not duplicate the event");
        assert_eq!(all[0].body, "the real text");
        assert!(all[0].decrypted);
        assert!(all[0].encrypted);
    }

    #[test]
    fn recent_messages_is_chronological_and_limited() {
        let tmp = TempDb::new();
        let store = tmp.open();

        for (i, ts) in [10u64, 20, 30, 40].iter().enumerate() {
            store
                .insert_message(&msg(&format!("$e{i}"), *ts, &format!("body {i}"), true))
                .expect("insert");
        }
        let mut elsewhere = msg("$other", 25, "elsewhere", true);
        elsewhere.room = "!q:example.org".into();
        store.insert_message(&elsewhere).expect("insert other room");

        let all = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(
            all.iter().map(|m| m.ts).collect::<Vec<_>>(),
            vec![10, 20, 30, 40],
            "messages must come back oldest-first"
        );

        let tail = store
            .recent_messages("!r:example.org", 2)
            .expect("recent 2");
        assert_eq!(
            tail.iter().map(|m| m.ts).collect::<Vec<_>>(),
            vec![30, 40],
            "limit must keep the newest, still oldest-first"
        );

        let other = store.recent_messages("!q:example.org", 50).expect("other");
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].body, "elsewhere");
    }

    #[test]
    fn rooms_sorted_by_recency() {
        let tmp = TempDb::new();
        let store = tmp.open();

        let mut a = Room {
            id: "!a:example.org".into(),
            name: "A".into(),
            encrypted: false,
            unread: 0,
            last_ts: 100,
            last_preview: "old".into(),
        };
        let b = Room {
            id: "!b:example.org".into(),
            name: "B".into(),
            encrypted: true,
            unread: 7,
            last_ts: 200,
            last_preview: "new".into(),
        };
        store.upsert_room(&a).expect("upsert a");
        store.upsert_room(&b).expect("upsert b");

        let rooms = store.list_rooms().expect("list");
        assert_eq!(
            rooms.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["!b:example.org", "!a:example.org"]
        );
        assert!(rooms[0].encrypted);
        assert_eq!(rooms[0].unread, 7);

        a.last_ts = 300;
        a.unread = 2;
        a.last_preview = "bumped".into();
        store.upsert_room(&a).expect("re-upsert a");

        let rooms = store.list_rooms().expect("list again");
        assert_eq!(rooms.len(), 2, "upsert must not duplicate the room");
        assert_eq!(rooms[0].id, "!a:example.org");
        assert_eq!(rooms[0].last_preview, "bumped");
        assert_eq!(rooms[0].unread, 2);
    }

    #[test]
    fn pickle_upsert_round_trip() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store
            .put_pickle("megolm_in", "sess1", "!r:example.org", "P1")
            .expect("put 1");
        store
            .put_pickle("megolm_in", "sess2", "!r:example.org", "P2")
            .expect("put 2");
        store
            .put_pickle("olm", "curve-key", "", "OLM")
            .expect("put olm");

        store
            .put_pickle("megolm_in", "sess1", "!other:example.org", "P1-ratcheted")
            .expect("overwrite 1");

        let megolm = store.all_pickles("megolm_in").expect("all megolm");
        assert_eq!(
            megolm,
            vec![
                (
                    "sess1".to_string(),
                    "!other:example.org".to_string(),
                    "P1-ratcheted".to_string()
                ),
                (
                    "sess2".to_string(),
                    "!r:example.org".to_string(),
                    "P2".to_string()
                ),
            ]
        );

        let olm = store.all_pickles("olm").expect("all olm");
        assert_eq!(olm.len(), 1, "kinds are separate namespaces");
        assert_eq!(olm[0].2, "OLM");

        assert!(store.all_pickles("nothing").expect("empty kind").is_empty());
    }

    #[test]
    fn store_survives_reopen() {
        let tmp = TempDb::new();
        {
            let store = tmp.open();
            store.set_meta("sync_token", "s42").expect("set");
        }
        let store = tmp.open();
        assert_eq!(
            store.get_meta("sync_token").expect("get").as_deref(),
            Some("s42")
        );
    }

    #[test]
    fn migration_adds_the_ciphertext_columns_to_an_old_database() {
        let tmp = TempDb::new();
        let path = tmp.path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create db directory");
        }

        // A database as written by a build that predates the two columns.
        {
            let conn = Connection::open(&path).expect("open raw connection");
            conn.execute_batch(
                "CREATE TABLE message (
                     event_id  TEXT PRIMARY KEY,
                     room      TEXT NOT NULL,
                     sender    TEXT NOT NULL,
                     ts        INTEGER NOT NULL,
                     body      TEXT NOT NULL,
                     encrypted INTEGER NOT NULL,
                     decrypted INTEGER NOT NULL,
                     mine      INTEGER NOT NULL
                 );
                 INSERT INTO message
                 VALUES ('$old', '!r:example.org', '@alice:example.org', 5, '[encrypted]', 1, 0, 0);",
            )
            .expect("create pre-migration schema");
        }

        // Opening migrates in place: the row survives and the new columns work.
        let store = tmp.open();
        store
            .insert_message(&retryable("$old", 5))
            .expect("record ciphertext");

        let rows = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(rows.len(), 1, "migration must not drop or duplicate rows");
        assert_eq!(rows[0].session_id.as_deref(), Some("S-$old"));
        assert_eq!(rows[0].ciphertext.as_deref(), Some("C-$old"));

        // Idempotent: a second open finds both columns and leaves them alone.
        drop(store);
        let store = tmp.open();
        let rows = store
            .recent_messages("!r:example.org", 50)
            .expect("recent after reopen");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ciphertext.as_deref(), Some("C-$old"));
    }

    #[test]
    fn decrypting_clears_the_stored_ciphertext() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store
            .insert_message(&retryable("$evt", 100))
            .expect("insert placeholder");
        assert_eq!(
            store
                .undecrypted_in_room("!r:example.org", 50)
                .expect("undecrypted"),
            vec![(
                "$evt".to_string(),
                "S-$evt".to_string(),
                "C-$evt".to_string()
            )]
        );

        // The room key showed up: body and flag are upgraded, and the ciphertext
        // is dropped, since keeping it costs device flash for nothing.
        store
            .insert_message(&msg("$evt", 100, "the real text", true))
            .expect("upgrade");

        let rows = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].body, "the real text");
        assert!(rows[0].decrypted);
        assert!(rows[0].session_id.is_none(), "session id must be cleared");
        assert!(rows[0].ciphertext.is_none(), "ciphertext must be cleared");
        assert!(store
            .undecrypted_in_room("!r:example.org", 50)
            .expect("undecrypted after")
            .is_empty());
    }

    #[test]
    fn upgrade_message_replaces_the_placeholder_in_place() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store
            .insert_message(&retryable("$evt", 100))
            .expect("insert");
        store
            .insert_message(&retryable("$keep", 90))
            .expect("insert");

        store
            .upgrade_message("$evt", "recovered from the backup")
            .expect("upgrade");

        let rows = store.recent_messages("!r:example.org", 50).expect("recent");
        let upgraded = match rows.iter().find(|m| m.event_id == "$evt") {
            Some(m) => m,
            None => panic!("the upgraded message disappeared"),
        };
        assert_eq!(upgraded.body, "recovered from the backup");
        assert!(upgraded.decrypted);
        assert!(upgraded.session_id.is_none(), "session id must be cleared");
        assert!(upgraded.ciphertext.is_none(), "ciphertext must be cleared");

        // Only that row changed, and it is no longer up for retry.
        let pending = store
            .undecrypted_in_room("!r:example.org", 50)
            .expect("undecrypted");
        assert_eq!(
            pending,
            vec![(
                "$keep".to_string(),
                "S-$keep".to_string(),
                "C-$keep".to_string()
            )]
        );

        // A row that is already gone is not an error.
        store
            .upgrade_message("$vanished", "nothing to do")
            .expect("upgrade missing row");
    }

    #[test]
    fn undecrypted_in_room_only_returns_retryable_rows() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store.insert_message(&retryable("$a", 10)).expect("a");
        store.insert_message(&retryable("$b", 20)).expect("b");
        // Undecryptable, but with nothing to retry with.
        store
            .insert_message(&msg("$c", 30, "[encrypted]", false))
            .expect("c");
        // Already readable.
        let mut readable = retryable("$d", 40);
        readable.decrypted = true;
        store.insert_message(&readable).expect("d");
        // Never encrypted.
        let mut plain = msg("$e", 50, "hello", true);
        plain.encrypted = false;
        store.insert_message(&plain).expect("e");
        // Another room.
        let mut elsewhere = retryable("$f", 60);
        elsewhere.room = "!q:example.org".into();
        store.insert_message(&elsewhere).expect("f");

        let got = store
            .undecrypted_in_room("!r:example.org", 50)
            .expect("undecrypted");
        assert_eq!(
            got,
            vec![
                ("$b".to_string(), "S-$b".to_string(), "C-$b".to_string()),
                ("$a".to_string(), "S-$a".to_string(), "C-$a".to_string()),
            ],
            "newest first, only rows that still carry ciphertext"
        );

        let limited = store
            .undecrypted_in_room("!r:example.org", 1)
            .expect("limited");
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].0, "$b");
    }

    /// The complement of `undecrypted_in_room`: rows a key alone cannot fix,
    /// because the ciphertext was never kept. Only these justify re-fetching
    /// a room's history over the radio.
    #[test]
    fn placeholder_count_ignores_anything_a_key_could_still_unlock() {
        let tmp = TempDb::new();
        let store = tmp.open();

        store
            .insert_message(&msg("$a", 10, "[encrypted]", false))
            .expect("a");
        store
            .insert_message(&msg("$b", 20, "[encrypted]", false))
            .expect("b");
        // Locked, but retryable: a key would do, no refetch needed.
        store.insert_message(&retryable("$c", 30)).expect("c");
        // Already readable.
        let mut readable = msg("$d", 40, "hi", true);
        readable.encrypted = true;
        store.insert_message(&readable).expect("d");
        // Never encrypted.
        let mut plain = msg("$e", 50, "hello", true);
        plain.encrypted = false;
        store.insert_message(&plain).expect("e");
        // Another room entirely.
        let mut elsewhere = msg("$f", 60, "[encrypted]", false);
        elsewhere.room = "!q:example.org".into();
        store.insert_message(&elsewhere).expect("f");

        assert_eq!(
            store
                .placeholders_without_ciphertext("!r:example.org", 50)
                .expect("count"),
            2
        );
        assert_eq!(
            store
                .placeholders_without_ciphertext("!r:example.org", 1)
                .expect("limited"),
            1,
            "the limit bounds the window that is examined"
        );
    }

    /// A room as sync writes it; the pagination columns are never part of it.
    fn room(name: &str, unread: u32, last_ts: u64) -> Room {
        Room {
            id: "!r:example.org".into(),
            name: name.into(),
            encrypted: true,
            unread,
            last_ts,
            last_preview: "hi".into(),
        }
    }

    #[test]
    fn back_token_defaults_to_unseeded() {
        let tmp = TempDb::new();
        let store = tmp.open();

        // A room the store has never seen.
        assert_eq!(
            store.back_token("!nope:example.org").expect("unknown room"),
            (None, false)
        );

        store.upsert_room(&room("Room", 0, 10)).expect("upsert");
        assert_eq!(
            store.back_token("!r:example.org").expect("fresh room"),
            (None, false),
            "a freshly synced room has no pagination edge yet"
        );
    }

    #[test]
    fn seed_back_token_writes_only_once() {
        let tmp = TempDb::new();
        let store = tmp.open();
        store.upsert_room(&room("Room", 0, 10)).expect("upsert");

        assert!(
            store
                .seed_back_token("!r:example.org", "t_first")
                .expect("first seed"),
            "the first prev_batch must be recorded"
        );
        assert_eq!(
            store.back_token("!r:example.org").expect("read"),
            (Some("t_first".to_string()), false)
        );

        // A later sync reports a newer prev_batch; taking it would skip the
        // history between the two positions.
        assert!(
            !store
                .seed_back_token("!r:example.org", "t_later")
                .expect("second seed"),
            "an existing edge must not be reseeded"
        );
        assert_eq!(
            store.back_token("!r:example.org").expect("read again"),
            (Some("t_first".to_string()), false)
        );

        // Nothing to seed for a room that was never upserted.
        assert!(!store
            .seed_back_token("!missing:example.org", "t")
            .expect("seed unknown room"));
    }

    #[test]
    fn set_back_token_walks_the_edge_and_marks_done() {
        let tmp = TempDb::new();
        let store = tmp.open();
        store.upsert_room(&room("Room", 0, 10)).expect("upsert");
        store
            .seed_back_token("!r:example.org", "t_first")
            .expect("seed");

        store
            .set_back_token("!r:example.org", Some("t_page1"), false)
            .expect("first page");
        assert_eq!(
            store.back_token("!r:example.org").expect("read"),
            (Some("t_page1".to_string()), false)
        );

        // The server ran out of history: no end token, start of room reached.
        store
            .set_back_token("!r:example.org", None, true)
            .expect("exhausted");
        assert_eq!(
            store.back_token("!r:example.org").expect("read done"),
            (None, true)
        );
    }

    #[test]
    fn upsert_room_does_not_clobber_the_pagination_edge() {
        let tmp = TempDb::new();
        let store = tmp.open();
        store.upsert_room(&room("Room", 0, 10)).expect("upsert");
        store
            .seed_back_token("!r:example.org", "t_edge")
            .expect("seed");
        store
            .set_back_token("!r:example.org", Some("t_edge"), true)
            .expect("mark done");

        // Sync upserts the room again with fresh metadata, as it does every
        // round.
        store
            .upsert_room(&room("Renamed", 7, 99))
            .expect("re-upsert");

        assert_eq!(
            store.back_token("!r:example.org").expect("read"),
            (Some("t_edge".to_string()), true),
            "sync must not reset backfill progress"
        );
        let got = store
            .get_room("!r:example.org")
            .expect("get room")
            .expect("room present");
        assert_eq!(got.name, "Renamed");
        assert_eq!(got.unread, 7);
        assert_eq!(got.last_ts, 99);
    }

    #[test]
    fn migration_adds_the_pagination_columns_to_an_old_database() {
        let tmp = TempDb::new();
        let path = tmp.path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create db directory");
        }

        // A `room` table as written by a build that predates backfill.
        {
            let conn = Connection::open(&path).expect("open raw connection");
            conn.execute_batch(
                "CREATE TABLE room (
                     id           TEXT PRIMARY KEY,
                     name         TEXT NOT NULL,
                     encrypted    INTEGER NOT NULL,
                     unread       INTEGER NOT NULL,
                     last_ts      INTEGER NOT NULL,
                     last_preview TEXT NOT NULL
                 );
                 INSERT INTO room VALUES ('!r:example.org', 'Room', 1, 3, 10, 'hi');",
            )
            .expect("create pre-migration schema");
        }

        // Opening migrates in place: the row survives and the columns work.
        let store = tmp.open();
        let rooms = store.list_rooms().expect("list rooms");
        assert_eq!(rooms.len(), 1, "migration must not drop or duplicate rows");
        assert_eq!(rooms[0].name, "Room");
        assert_eq!(
            store.back_token("!r:example.org").expect("read"),
            (None, false),
            "the migrated column defaults to unseeded"
        );

        assert!(store
            .seed_back_token("!r:example.org", "t_first")
            .expect("seed"));
        store
            .set_back_token("!r:example.org", Some("t_page1"), true)
            .expect("walk");

        // Idempotent: a second open finds both columns and leaves them alone.
        drop(store);
        let store = tmp.open();
        assert_eq!(
            store
                .back_token("!r:example.org")
                .expect("read after reopen"),
            (Some("t_page1".to_string()), true)
        );
        assert_eq!(store.list_rooms().expect("list after reopen").len(), 1);
    }

    // -------------------------------------------------- encryption at rest

    fn sample_session() -> Session {
        Session {
            homeserver: "https://example.org".into(),
            user_id: "@alice:example.org".into(),
            device_id: "DEV1".into(),
            access_token: "syt_supersecret_token".into(),
        }
    }

    /// Every value-bearing cell of every table encryption touches, exactly as
    /// stored. Used to prove an operation left the database alone.
    fn snapshot(conn: &Connection) -> Vec<String> {
        const QUERIES: [&str; 3] = [
            "SELECT k || '=' || v FROM meta ORDER BY k",
            "SELECT id || '=' || name || '/' || last_preview FROM room ORDER BY id",
            "SELECT event_id || '=' || body || '/' || COALESCE(ciphertext, '')
             FROM message ORDER BY event_id",
        ];
        let mut out = Vec::new();
        for sql in QUERIES {
            let mut stmt = match conn.prepare(sql) {
                Ok(s) => s,
                Err(e) => panic!("prepare snapshot query: {e}"),
            };
            let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
                Ok(r) => r,
                Err(e) => panic!("run snapshot query: {e}"),
            };
            for r in rows {
                match r {
                    Ok(v) => out.push(v),
                    Err(e) => panic!("read snapshot row: {e}"),
                }
            }
        }
        out
    }

    #[test]
    fn message_contents_round_trip_and_never_reach_the_disk_in_the_clear() {
        let tmp = TempDb::new();
        let store = tmp.keyed();
        const BODY: &str = "the quick brown fox jumps over the lazy dog";
        const MEGOLM: &str = "AwgAEnB1-MEGOLM-CIPHERTEXT";

        let mut m = msg("$e1", 10, BODY, true);
        m.session_id = Some("SESSION-1".into());
        m.ciphertext = Some(MEGOLM.into());
        store.insert_message(&m).expect("insert");

        let got = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, BODY);
        assert_eq!(got[0].ciphertext.as_deref(), Some(MEGOLM));

        let raw = tmp.raw();
        assert_sealed(&raw_body(&raw, "$e1"), BODY, "message.body");
        assert_sealed(
            &raw_cell(
                &raw,
                "SELECT ciphertext FROM message WHERE event_id = ?1",
                "$e1",
            ),
            MEGOLM,
            "message.ciphertext",
        );
        // The other half of the decision, asserted so it is impossible to
        // change it by accident: metadata is stored in the clear.
        assert_eq!(
            raw_cell(
                &raw,
                "SELECT session_id FROM message WHERE event_id = ?1",
                "$e1"
            ),
            "SESSION-1",
            "session_id is a lookup key the crypto layer matches on"
        );
        assert_eq!(
            raw_cell(
                &raw,
                "SELECT sender FROM message WHERE event_id = ?1",
                "$e1"
            ),
            "@alice:example.org",
            "senders are metadata and are not protected"
        );
    }

    #[test]
    fn room_and_secret_meta_are_encrypted_but_the_sync_token_is_not() {
        let tmp = TempDb::new();
        let store = tmp.keyed();

        store
            .upsert_room(&Room {
                id: "!r:example.org".into(),
                name: "Nuclear Codes".into(),
                encrypted: true,
                unread: 2,
                last_ts: 99,
                last_preview: "meet me at midnight".into(),
            })
            .expect("upsert room");
        store.save_session(&sample_session()).expect("save session");
        store
            .set_meta("pickle_key", "PICKLE-KEY-MATERIAL")
            .expect("pickle key");
        store
            .set_meta("backup_key", "BACKUP-KEY-MATERIAL")
            .expect("backup key");
        store.set_meta("sync_token", "s_12345").expect("sync token");
        store
            .set_meta("backup_version", "7")
            .expect("backup version");

        // Everything reads back exactly as written, through both room paths.
        let got = store
            .get_room("!r:example.org")
            .expect("get room")
            .expect("room present");
        assert_eq!(got.name, "Nuclear Codes");
        assert_eq!(got.last_preview, "meet me at midnight");
        let listed = store.list_rooms().expect("list rooms");
        assert_eq!(listed[0].name, "Nuclear Codes");
        assert_eq!(listed[0].last_preview, "meet me at midnight");
        assert_eq!(
            store
                .load_session()
                .expect("load session")
                .expect("session present")
                .access_token,
            "syt_supersecret_token"
        );
        assert_eq!(
            store.get_meta("pickle_key").expect("get").as_deref(),
            Some("PICKLE-KEY-MATERIAL")
        );
        assert_eq!(
            store.get_meta("backup_key").expect("get").as_deref(),
            Some("BACKUP-KEY-MATERIAL")
        );
        assert_eq!(
            store.get_meta("sync_token").expect("get").as_deref(),
            Some("s_12345")
        );

        let raw = tmp.raw();
        assert_sealed(
            &raw_cell(
                &raw,
                "SELECT name FROM room WHERE id = ?1",
                "!r:example.org",
            ),
            "Nuclear Codes",
            "room.name",
        );
        assert_sealed(
            &raw_cell(
                &raw,
                "SELECT last_preview FROM room WHERE id = ?1",
                "!r:example.org",
            ),
            "meet me at midnight",
            "room.last_preview",
        );
        assert_eq!(
            raw_cell(&raw, "SELECT id FROM room WHERE id = ?1", "!r:example.org"),
            "!r:example.org",
            "room ids are metadata and stay plaintext"
        );

        assert_sealed(
            &raw_meta(&raw, SESSION_KEY),
            "syt_supersecret_token",
            "meta.session",
        );
        assert_sealed(
            &raw_meta(&raw, "pickle_key"),
            "PICKLE-KEY-MATERIAL",
            "meta.pickle_key",
        );
        assert_sealed(
            &raw_meta(&raw, "backup_key"),
            "BACKUP-KEY-MATERIAL",
            "meta.backup_key",
        );
        assert_eq!(
            raw_meta(&raw, "sync_token"),
            "s_12345",
            "the sync token is not a secret and must stay readable"
        );
        assert_eq!(raw_meta(&raw, "backup_version"), "7");
        assert_eq!(
            raw_meta(&raw, ENCRYPTED_FLAG),
            "1",
            "the flag has to be legible before the key is known"
        );
    }

    /// The IV is derived from the key material, so a fixed key means a fixed
    /// IV, and CBC under a fixed IV turns equal plaintexts into equal
    /// ciphertexts. This is the test that catches that.
    #[test]
    fn identical_plaintext_encrypts_to_different_blobs() {
        let tmp = TempDb::new();
        let store = tmp.keyed();
        const BODY: &str = "the same words twice, under the same master key";

        store
            .insert_message(&msg("$first", 10, BODY, true))
            .expect("insert first");
        store
            .insert_message(&msg("$second", 20, BODY, true))
            .expect("insert second");

        let raw = tmp.raw();
        let a = raw_body(&raw, "$first");
        let b = raw_body(&raw, "$second");
        assert_sealed(&a, BODY, "message.body");
        assert_sealed(&b, BODY, "message.body");
        assert_ne!(
            a, b,
            "the same plaintext under the same master key produced the same stored blob: \
             the per-value salt is not being applied and the CBC IV is being reused"
        );

        // Not just different overall -- different in the salt, which is what
        // makes the rest differ.
        let decode = |s: &str| {
            let encoded = match s.strip_prefix(ENC_PREFIX) {
                Some(e) => e,
                None => panic!("stored value is not encrypted: {s}"),
            };
            match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(b) => b,
                Err(e) => panic!("decode stored blob: {e}"),
            }
        };
        assert_ne!(
            decode(&a)[..SALT_LEN],
            decode(&b)[..SALT_LEN],
            "the two values were salted identically"
        );

        // Both still decrypt to what went in.
        let got = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(
            got.iter().map(|m| m.body.as_str()).collect::<Vec<_>>(),
            vec![BODY, BODY]
        );
    }

    #[test]
    fn a_tampered_blob_fails_loudly_instead_of_decoding_to_garbage() {
        // Once for each region of the blob: the salt, the MAC, the ciphertext.
        // A flip anywhere must be caught before anything is handed back.
        for byte in [0usize, SALT_LEN, SALT_LEN + MAC_LEN] {
            let tmp = TempDb::new();
            let store = tmp.keyed();
            store
                .insert_message(&msg("$e1", 10, "authentic and unaltered", true))
                .expect("insert");

            let raw = tmp.raw();
            let stored = raw_body(&raw, "$e1");
            let encoded = match stored.strip_prefix(ENC_PREFIX) {
                Some(e) => e,
                None => panic!("stored value is not encrypted: {stored}"),
            };
            let mut blob = match base64::engine::general_purpose::STANDARD.decode(encoded) {
                Ok(b) => b,
                Err(e) => panic!("decode stored blob: {e}"),
            };
            assert!(byte < blob.len(), "blob too short to tamper at {byte}");
            blob[byte] ^= 0x01;
            let tampered = format!(
                "{ENC_PREFIX}{}",
                base64::engine::general_purpose::STANDARD.encode(&blob)
            );
            raw.execute(
                "UPDATE message SET body = ?2 WHERE event_id = ?1",
                params!["$e1", tampered],
            )
            .expect("write tampered body");

            let err = store
                .recent_messages("!r:example.org", 50)
                .expect_err("a tampered body must not be readable");
            let text = format!("{err:#}");
            assert!(
                text.contains("message.body"),
                "byte {byte}: the error must name the column: {text}"
            );
            assert!(
                text.contains("failed authentication"),
                "byte {byte}: the error must say the MAC failed: {text}"
            );
        }
    }

    #[test]
    fn a_wrong_master_key_cannot_read_the_store() {
        let tmp = TempDb::new();
        {
            let store = tmp.keyed();
            store
                .insert_message(&msg("$e1", 10, "for my eyes only", true))
                .expect("insert");
            store.set_meta("pickle_key", "PICKLE").expect("pickle key");
        }

        // The open itself succeeds: a key was supplied and the flag is set, so
        // nothing looks wrong until a value is actually read.
        let store = Store::open(&tmp.path(), Some(KEY_B)).expect("open with the wrong key");

        let err = store
            .recent_messages("!r:example.org", 50)
            .expect_err("the wrong key must not decrypt message bodies");
        assert!(
            format!("{err:#}").contains("failed authentication"),
            "{err:#}"
        );

        let err = store
            .get_meta("pickle_key")
            .expect_err("the wrong key must not decrypt secret meta");
        let text = format!("{err:#}");
        assert!(text.contains("meta.pickle_key"), "{text}");

        // The right key still works, so nothing was damaged by trying.
        let store = tmp.keyed();
        assert_eq!(
            store.recent_messages("!r:example.org", 50).expect("recent")[0].body,
            "for my eyes only"
        );
    }

    #[test]
    fn opening_an_encrypted_store_without_a_key_errors_and_changes_nothing() {
        let tmp = TempDb::new();
        {
            let store = tmp.keyed();
            store
                .insert_message(&msg("$e1", 10, "history", true))
                .expect("insert");
            store
                .insert_message(&msg("$e2", 20, "more history", true))
                .expect("insert");
            store.save_session(&sample_session()).expect("session");
        }

        let before = snapshot(&tmp.raw());
        let rows_before = before.len();
        assert!(rows_before > 0, "the fixture wrote nothing");

        // Not `expect_err`: that would need `Debug` on `Store`, and a store
        // holds the master key -- it has no business being printable.
        let text = match Store::open(&tmp.path(), None) {
            Ok(_) => panic!("opening an encrypted store with no key must fail"),
            Err(e) => format!("{e:#}"),
        };
        assert!(text.contains("encrypted"), "{text}");
        assert!(text.contains("key"), "{text}");

        let after = snapshot(&tmp.raw());
        assert_eq!(after.len(), rows_before, "a refused open dropped rows");
        assert_eq!(
            after, before,
            "a refused open must not alter a single stored value"
        );

        // And the data is still there for the key that does exist.
        let store = tmp.keyed();
        let got = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(
            got.iter().map(|m| m.body.as_str()).collect::<Vec<_>>(),
            vec!["history", "more history"]
        );
    }

    #[test]
    fn opening_with_a_key_migrates_a_plaintext_database_once() {
        // More rows than one migration chunk, so the chunked walk is exercised
        // rather than just its first pass.
        const ROWS: usize = 600;
        let tmp = TempDb::new();
        {
            let store = tmp.open();
            store
                .upsert_room(&Room {
                    id: "!r:example.org".into(),
                    name: "Plaintext Room".into(),
                    encrypted: true,
                    unread: 1,
                    last_ts: 5,
                    last_preview: "old preview".into(),
                })
                .expect("upsert room");
            for i in 0..ROWS {
                store
                    .insert_message(&msg(
                        &format!("$e{i:04}"),
                        i as u64,
                        &format!("legacy body {i}"),
                        true,
                    ))
                    .expect("insert");
            }
            store
                .insert_message(&retryable("$pending", 9999))
                .expect("insert retryable");
            store.save_session(&sample_session()).expect("session");
            store.set_meta("pickle_key", "PICKLE").expect("pickle key");
            store.set_meta("backup_key", "BACKUP").expect("backup key");
            store
                .set_meta("sync_token", "s_before")
                .expect("sync token");

            assert!(
                store.get_meta(ENCRYPTED_FLAG).expect("flag").is_none(),
                "an unencrypted store must not claim to be encrypted"
            );
            let raw = tmp.raw();
            assert_eq!(raw_body(&raw, "$e0000"), "legacy body 0");
        }

        let store = tmp.keyed();

        // Everything still reads, through every accessor.
        let msgs = store
            .recent_messages("!r:example.org", 1000)
            .expect("recent");
        assert_eq!(msgs.len(), ROWS + 1);
        assert_eq!(msgs[0].body, "legacy body 0");
        assert_eq!(msgs[ROWS - 1].body, format!("legacy body {}", ROWS - 1));
        assert_eq!(
            store
                .get_room("!r:example.org")
                .expect("get room")
                .expect("room present")
                .name,
            "Plaintext Room"
        );
        assert_eq!(
            store.list_rooms().expect("list")[0].last_preview,
            "old preview"
        );
        assert_eq!(
            store
                .load_session()
                .expect("load")
                .expect("present")
                .access_token,
            "syt_supersecret_token"
        );
        assert_eq!(
            store.get_meta("pickle_key").expect("get").as_deref(),
            Some("PICKLE")
        );
        assert_eq!(
            store.get_meta("backup_key").expect("get").as_deref(),
            Some("BACKUP")
        );
        assert_eq!(
            store.get_meta("sync_token").expect("get").as_deref(),
            Some("s_before")
        );
        assert_eq!(
            store
                .undecrypted_in_room("!r:example.org", 10)
                .expect("pending"),
            vec![(
                "$pending".to_string(),
                "S-$pending".to_string(),
                "C-$pending".to_string()
            )]
        );

        // And it is all stored encrypted now, with the flag set.
        let raw = tmp.raw();
        assert_sealed(
            &raw_body(&raw, "$e0000"),
            "legacy body 0",
            "migrated message.body",
        );
        assert_sealed(
            &raw_body(&raw, &format!("$e{:04}", ROWS - 1)),
            &format!("legacy body {}", ROWS - 1),
            "migrated message.body beyond the first chunk",
        );
        assert_sealed(
            &raw_cell(
                &raw,
                "SELECT ciphertext FROM message WHERE event_id = ?1",
                "$pending",
            ),
            "C-$pending",
            "migrated message.ciphertext",
        );
        assert_sealed(
            &raw_cell(
                &raw,
                "SELECT name FROM room WHERE id = ?1",
                "!r:example.org",
            ),
            "Plaintext Room",
            "migrated room.name",
        );
        assert_sealed(
            &raw_cell(
                &raw,
                "SELECT last_preview FROM room WHERE id = ?1",
                "!r:example.org",
            ),
            "old preview",
            "migrated room.last_preview",
        );
        assert_sealed(
            &raw_meta(&raw, SESSION_KEY),
            "syt_supersecret_token",
            "migrated meta.session",
        );
        assert_eq!(
            raw_meta(&raw, "sync_token"),
            "s_before",
            "the migration must not sweep up the non-secret meta keys"
        );
        assert_eq!(raw_meta(&raw, ENCRYPTED_FLAG), "1");

        // Reopening is a no-op. Byte-identical blobs is the strong form of
        // that: re-encrypting would have drawn fresh salts and changed them.
        let before = snapshot(&raw);
        drop(store);
        let store = tmp.keyed();
        assert_eq!(
            snapshot(&tmp.raw()),
            before,
            "a second open re-encrypted values that were already encrypted"
        );
        assert_eq!(
            store
                .recent_messages("!r:example.org", 1000)
                .expect("recent after reopen")
                .len(),
            ROWS + 1
        );
    }

    #[test]
    fn legacy_plaintext_values_read_straight_through() {
        // The unit of the rule, both ways round: no prefix means plaintext,
        // with or without a key.
        assert_eq!(
            unseal(None, "message.body", "no prefix here".to_string()).expect("keyless"),
            "no prefix here"
        );
        assert_eq!(
            unseal(Some(&KEY_A), "message.body", "no prefix here".to_string()).expect("keyed"),
            "no prefix here"
        );

        // And in place: a row as an older build left it, sitting in a database
        // that is otherwise encrypted. This is the half-migrated shape, and it
        // must read through rather than error or come back as ciphertext.
        let tmp = TempDb::new();
        let store = tmp.keyed();
        store
            .insert_message(&msg("$sealed", 10, "sealed", true))
            .expect("insert");
        tmp.raw()
            .execute(
                "INSERT INTO message
                     (event_id, room, sender, ts, body, encrypted, decrypted, mine,
                      session_id, ciphertext)
                 VALUES ('$legacy', '!r:example.org', '@bob:example.org', 20,
                         'written before the key existed', 0, 1, 0, NULL, NULL)",
                [],
            )
            .expect("insert legacy row");
        tmp.raw()
            .execute(
                "INSERT INTO room (id, name, encrypted, unread, last_ts, last_preview)
                 VALUES ('!legacy:example.org', 'Old Name', 0, 0, 1, 'old preview')",
                [],
            )
            .expect("insert legacy room");

        let got = store.recent_messages("!r:example.org", 50).expect("recent");
        assert_eq!(
            got.iter().map(|m| m.body.as_str()).collect::<Vec<_>>(),
            vec!["sealed", "written before the key existed"]
        );
        let legacy = store
            .get_room("!legacy:example.org")
            .expect("get legacy room")
            .expect("legacy room present");
        assert_eq!(legacy.name, "Old Name");
        assert_eq!(legacy.last_preview, "old preview");
    }
}
