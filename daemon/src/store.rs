//! Persistence. One SQLite file holds everything the daemon must survive a
//! restart with: the login session, the sync token, the room list, a message
//! backlog, and the pickled Olm/Megolm state.
//!
//! The device is slow and may lose power at any moment, so the connection runs
//! in WAL mode with `synchronous=NORMAL`: commits are durable across a process
//! crash without paying an fsync per transaction on every sync round.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::Duration;

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
    last_preview TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS message (
    event_id  TEXT PRIMARY KEY,
    room      TEXT NOT NULL,
    sender    TEXT NOT NULL,
    ts        INTEGER NOT NULL,
    body      TEXT NOT NULL,
    encrypted INTEGER NOT NULL,
    decrypted INTEGER NOT NULL,
    mine      INTEGER NOT NULL
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

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("create store directory {}", dir.display()))?;
            }
        }
        let conn = Connection::open(path)
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
        Ok(Store { conn })
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

    pub fn set_meta(&self, k: &str, v: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO meta (k, v) VALUES (?1, ?2)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![k, v],
            )
            .with_context(|| format!("write meta key {k}"))?;
        Ok(())
    }

    pub fn get_meta(&self, k: &str) -> Result<Option<String>> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |row| {
                row.get(0)
            })
            .optional()
            .with_context(|| format!("read meta key {k}"))
    }

    // ---------------------------------------------------------------- rooms

    pub fn upsert_room(&self, r: &Room) -> Result<()> {
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
                    r.name,
                    r.encrypted as i64,
                    r.unread as i64,
                    r.last_ts as i64,
                    r.last_preview,
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
            out.push(r.context("read room row")?);
        }
        Ok(out)
    }

    /// Fetch one room by id. The sync loop needs this per room in a batch;
    /// doing it with `list_rooms()` is a full table scan each time, which on
    /// a 766-room account is ~590k row materializations per full sync.
    pub fn get_room(&self, id: &str) -> Result<Option<Room>> {
        self.conn
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
            .with_context(|| format!("get room {id}"))
    }

    // ------------------------------------------------------------- messages

    /// Idempotent by `event_id`. A re-insert may only *upgrade* a row: when a
    /// room key arrives late, the same event is written again with the plain
    /// body and `decrypted = 1`, replacing the placeholder in place.
    pub fn insert_message(&self, m: &Message) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO message
                     (event_id, room, sender, ts, body, encrypted, decrypted, mine)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(event_id) DO UPDATE SET
                     body      = excluded.body,
                     decrypted = excluded.decrypted",
                params![
                    m.event_id,
                    m.room,
                    m.sender,
                    m.ts as i64,
                    m.body,
                    m.encrypted as i64,
                    m.decrypted as i64,
                    m.mine as i64,
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
                "SELECT event_id, room, sender, ts, body, encrypted, decrypted, mine
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
                })
            })
            .with_context(|| format!("query messages for {room}"))?;
        let mut out = Vec::with_capacity(limit.min(512) as usize);
        for m in rows {
            out.push(m.context("read message row")?);
        }
        out.reverse();
        Ok(out)
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

        fn open(&self) -> Store {
            match Store::open(&self.dir.join("store.db")) {
                Ok(s) => s,
                Err(e) => panic!("open store: {e:#}"),
            }
        }
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
        }
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
        let store = Store::open(&path).expect("open nested");
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
}
