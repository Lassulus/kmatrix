//! kmatrixd — on-device Matrix daemon for e-ink readers.
//!
//! Runs beside KOReader on the device itself. It owns everything KOReader's Lua
//! side cannot do safely: verified TLS, a blocking `/sync` long-poll that would
//! otherwise freeze the UI thread, streaming JSON so peak heap stays flat, and
//! Olm/Megolm via vodozemac.
//!
//! Locking: four small locks rather than one big one, because a `/sync`
//! long-poll runs for 30s and must never block an IPC `status` query.
//!   `api` — cloned out as an `Arc` and dropped immediately; never held across I/O.
//!   `net` — crypto state. Taken around crypto calls only, released during HTTP.
//!   `db`  — SQLite. Short reads and writes.
//!   `st`  — a few scalars describing daemon state.

mod api;
mod crypto;
mod emoji;
mod ipc;
mod model;
mod store;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{anyhow, Context, Result};

use crate::api::Api;
use crate::crypto::Crypto;
use crate::model::*;
use crate::store::Store;

/// How long the server holds a `/sync` open with no events.
const SYNC_TIMEOUT_MS: u32 = 30_000;
/// One-time keys we try to keep published.
const OTK_TARGET: u32 = 50;

/// The only key-backup algorithm Matrix defines, and the only one vodozemac's
/// `pk_encryption` implements.
const BACKUP_ALGORITHM: &str = "m.megolm_backup.v1.curve25519-aes-sha2";
/// How many recent messages of a room we try to recover keys for when it is
/// opened. Bounded on purpose: the backup holds tens of thousands of sessions
/// and each fetch is a request over a slow radio.
const BACKUP_RESTORE_WINDOW: u32 = 100;
/// Rooms to restore eagerly right after the recovery key is accepted, so the
/// user sees an immediate effect instead of a silent success.
const BACKUP_EAGER_ROOMS: usize = 3;

pub struct NetState {
    pub crypto: Option<Crypto>,
}

pub struct Status {
    pub state: State,
    pub error: Option<String>,
    pub session: Option<Session>,
}

pub struct Shared {
    pub db: Mutex<Store>,
    pub net: Mutex<NetState>,
    pub api: Mutex<Option<Arc<Api>>>,
    pub st: Mutex<Status>,
    pub bus: ipc::Bus,
    pub wake: (Mutex<bool>, Condvar),
    pub running: AtomicBool,
    pub data_dir: PathBuf,
    /// IPC listener credentials. Deliberately NOT in the store: `clear()`
    /// wipes every table on login and logout, which would silently revoke the
    /// token in the port file and make every later `hello` fail with "bad
    /// token" — the existing connection keeps working, so it presents as the
    /// UI going blank only after a reconnect (Kindle suspend/resume).
    /// They are per-process values and have no business being persisted.
    pub ipc_token: std::sync::OnceLock<String>,
    pub ipc_port: std::sync::OnceLock<u16>,
}

impl Shared {
    pub fn set_state(&self, s: State, err: Option<String>) {
        {
            let mut st = match self.st.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            st.state = s;
            st.error = err.clone();
        }
        let mut ev = serde_json::json!({ "event": "state", "state": s.as_str() });
        if let Some(e) = err {
            ev["error"] = serde_json::Value::String(e);
        }
        self.bus.publish(&ev);
    }

    pub fn session(&self) -> Option<Session> {
        match self.st.lock() {
            Ok(g) => g.session.clone(),
            Err(p) => p.into_inner().session.clone(),
        }
    }

    pub fn api(&self) -> Option<Arc<Api>> {
        match self.api.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Wake the sync loop out of its inter-poll wait.
    pub fn kick(&self) {
        let (lock, cv) = &self.wake;
        if let Ok(mut w) = lock.lock() {
            *w = true;
            cv.notify_all();
        }
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.kick();
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("kmatrixd: fatal: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut data_dir: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => data_dir = args.next().map(PathBuf::from),
            "--version" => {
                println!("{CLIENT_VERSION}");
                return Ok(());
            }
            "--help" | "-h" => {
                println!("usage: kmatrixd --data-dir <dir>");
                return Ok(());
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }
    let data_dir = data_dir.ok_or_else(|| anyhow!("--data-dir is required"))?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let store = Store::open(&data_dir.join("kmatrix.sqlite3")).context("opening store")?;
    let session = store.load_session().context("loading session")?;

    let shared = Arc::new(Shared {
        db: Mutex::new(store),
        net: Mutex::new(NetState { crypto: None }),
        api: Mutex::new(None),
        st: Mutex::new(Status {
            state: if session.is_some() {
                State::Connecting
            } else {
                State::LoggedOut
            },
            error: None,
            session: session.clone(),
        }),
        bus: ipc::Bus::new(),
        wake: (Mutex::new(false), Condvar::new()),
        running: AtomicBool::new(true),
        data_dir: data_dir.clone(),
        ipc_token: std::sync::OnceLock::new(),
        ipc_port: std::sync::OnceLock::new(),
    });

    // Restore an existing login before serving, so the first `status` is honest.
    if let Some(s) = session {
        match Api::new(&s.homeserver) {
            Ok(mut a) => {
                a.set_auth(&s.access_token);
                if let Ok(mut g) = shared.api.lock() {
                    *g = Some(Arc::new(a));
                }
                let c = {
                    let db = shared.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
                    Crypto::load_or_create(&db)
                };
                match c {
                    Ok(c) => {
                        if let Ok(mut n) = shared.net.lock() {
                            n.crypto = Some(c);
                        }
                    }
                    Err(e) => eprintln!("kmatrixd: crypto init failed: {e:#}"),
                }
            }
            Err(e) => eprintln!("kmatrixd: restoring session failed: {e:#}"),
        }
    }

    let listener = ipc::listen(&shared).context("starting IPC listener")?;

    let sync_shared = Arc::clone(&shared);
    let sync_thread = std::thread::Builder::new()
        .name("sync".into())
        .spawn(move || sync_loop(sync_shared))
        .context("spawning sync thread")?;

    ipc::serve(&shared, listener);

    shared.shutdown();
    // Do NOT join the sync thread: it is usually parked in a 30 s /sync
    // long-poll, so joining makes "stop the daemon" look wedged for half a
    // minute. Every store write is its own transaction and the WAL is
    // checkpointed each sync, so exiting from under it is safe.
    drop(sync_thread);
    let _ = std::fs::remove_file(data_dir.join("kmatrix.port"));
    Ok(())
}

// ------------------------------------------------------------------ sync

fn sync_loop(sh: Arc<Shared>) {
    let mut backoff = 1u64;
    while sh.running.load(Ordering::SeqCst) {
        let (api, session) = (sh.api(), sh.session());
        let (api, session) = match (api, session) {
            (Some(a), Some(s)) => (a, s),
            _ => {
                wait_for_kick(&sh, 1000);
                continue;
            }
        };

        match sync_once(&sh, &api, &session) {
            Ok(()) => {
                backoff = 1;
                // Loop straight back into the next long-poll.
            }
            Err(e) => {
                if !sh.running.load(Ordering::SeqCst) {
                    break;
                }
                eprintln!("kmatrixd: sync: {e:#}");
                sh.set_state(State::Offline, Some(format!("{e:#}")));
                wait_for_kick(&sh, backoff * 1000);
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

fn wait_for_kick(sh: &Shared, ms: u64) {
    let (lock, cv) = &sh.wake;
    let Ok(mut w) = lock.lock() else { return };
    if *w {
        *w = false;
        return;
    }
    let (mut w2, _) = cv
        .wait_timeout(w, std::time::Duration::from_millis(ms))
        .unwrap_or_else(|p| p.into_inner());
    *w2 = false;
}

fn sync_once(sh: &Arc<Shared>, api: &Arc<Api>, session: &Session) -> Result<()> {
    let since = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.get_meta("sync_token")?
    };

    // No lock held across the long-poll: IPC stays responsive for 30s.
    let resp = api.sync(since.as_deref(), SYNC_TIMEOUT_MS)?;

    sh.set_state(State::Syncing, None);
    process_sync(sh, api, session, resp)
}

fn process_sync(
    sh: &Arc<Shared>,
    api: &Arc<Api>,
    session: &Session,
    resp: SyncResponse,
) -> Result<()> {
    // 1. To-device first: a room key in this batch may unlock messages below.
    //
    // Verification events travel in the clear and are handled by their own
    // state machine; everything else goes through the Olm path.
    if !resp.to_device.events.is_empty() {
        let (verification, encrypted): (Vec<&ToDeviceEvent>, Vec<&ToDeviceEvent>) = resp
            .to_device
            .events
            .iter()
            .partition(|e| e.kind.starts_with("m.key.verification."));

        let secrets = {
            let owned: Vec<ToDeviceEvent> = encrypted
                .into_iter()
                .map(|e| ToDeviceEvent {
                    kind: e.kind.clone(),
                    sender: e.sender.clone(),
                    content: e.content.clone(),
                })
                .collect();
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
            match net.crypto.as_mut() {
                Some(c) => match c.handle_to_device(&db, &owned) {
                    Ok(out) => out,
                    Err(e) => {
                        eprintln!("kmatrixd: to-device: {e:#}");
                        Vec::new()
                    }
                },
                None => Vec::new(),
            }
        };
        for outcome in secrets {
            handle_secret(sh, api, session, outcome);
        }

        for ev in verification {
            if let Err(e) = handle_verification_event(sh, api, session, ev) {
                eprintln!("kmatrixd: verification: {e:#}");
            }
        }
    }

    // 2. Rooms.
    let mut changed_rooms: Vec<Room> = Vec::new();
    let mut new_messages: Vec<(String, Vec<Message>)> = Vec::new();

    for (room_id, jr) in resp.rooms.join {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let mut room = db.get_room(&room_id)?.unwrap_or_else(|| Room {
            id: room_id.clone(),
            name: room_id.clone(),
            ..Default::default()
        });
        drop(db);

        for ev in &jr.state.events {
            match ev.kind.as_str() {
                "m.room.name" => {
                    if let Some(n) = ev.content.name.as_deref() {
                        if !n.is_empty() {
                            room.name = n.to_string();
                        }
                    }
                }
                "m.room.canonical_alias" => {
                    if room.name == room.id {
                        if let Some(a) = ev.content.alias.as_deref() {
                            room.name = a.to_string();
                        }
                    }
                }
                "m.room.encryption" => room.encrypted = true,
                _ => {}
            }
        }
        room.unread = jr.unread_notifications.notification_count;

        let mut msgs = Vec::new();
        for ev in &jr.timeline.events {
            if let Some(m) = convert_event(sh, &room_id, ev, session)? {
                msgs.push(m);
            }
            if ev.kind == "m.room.encryption" {
                room.encrypted = true;
            }
        }

        if let Some(last) = msgs.last() {
            room.last_ts = last.ts;
            room.last_preview = preview(&last.body, 64);
        }

        {
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            for m in &msgs {
                db.insert_message(m)?;
            }
            db.upsert_room(&room)?;
            // Seed the backwards-pagination edge the first time we see this
            // room, and only then: a later `limited` sync's prev_batch points
            // at a newer position, so adopting it would silently skip history.
            if let Some(prev) = jr.timeline.prev_batch.as_deref() {
                db.seed_back_token(&room_id, prev)?;
            }
        }

        if !msgs.is_empty() {
            new_messages.push((room_id.clone(), msgs));
        }
        changed_rooms.push(room);
    }

    // 3. Persist the token only after the batch is durably stored, then fold
    //    the WAL back in. SQLite never shrinks a WAL by itself and this daemon
    //    runs for days on flash storage, so an unbounded WAL is a slow leak.
    {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.set_meta("sync_token", &resp.next_batch)?;
        if let Err(e) = db.checkpoint() {
            eprintln!("kmatrixd: wal checkpoint: {e:#}");
        }
    }

    // 4. Keep one-time keys topped up.
    if let Err(e) = maintain_otks(
        sh,
        api,
        session,
        resp.device_one_time_keys_count.signed_curve25519,
    ) {
        eprintln!("kmatrixd: otk upload: {e:#}");
    }

    // 5. Tell the UI.
    for (room, msgs) in new_messages {
        sh.bus.publish(&serde_json::json!({
            "event": "messages", "room": room, "messages": msgs
        }));
    }
    if !changed_rooms.is_empty() {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let rooms = db.list_rooms()?;
        drop(db);
        sh.bus
            .publish(&serde_json::json!({ "event": "rooms", "rooms": rooms }));
    }
    Ok(())
}

/// Turn a timeline event into a `Message`, decrypting when needed.
/// Returns `Ok(None)` for events we do not render.
fn convert_event(
    sh: &Arc<Shared>,
    room_id: &str,
    ev: &RoomEvent,
    session: &Session,
) -> Result<Option<Message>> {
    let mine = ev.sender == session.user_id;
    match ev.kind.as_str() {
        "m.room.message" => {
            let body = ev.content.body.clone().unwrap_or_default();
            if body.is_empty() {
                return Ok(None);
            }
            Ok(Some(Message {
                event_id: ev.event_id.clone(),
                room: room_id.to_string(),
                sender: ev.sender.clone(),
                ts: ev.origin_server_ts,
                body,
                encrypted: false,
                decrypted: true,
                mine,
                session_id: None,
                ciphertext: None,
            }))
        }
        "m.room.encrypted" => {
            let (Some(ct), Some(sid)) = (
                ev.content.ciphertext.as_deref(),
                ev.content.session_id.as_deref(),
            ) else {
                return Ok(None);
            };
            let plain = {
                let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
                match net.crypto.as_mut() {
                    Some(c) => c.decrypt(sid, ct),
                    None => Err(anyhow!("no crypto state")),
                }
            };
            let (body, decrypted) = match plain {
                Ok(json) => match serde_json::from_str::<serde_json::Value>(&json) {
                    Ok(v) => {
                        let b = v
                            .get("content")
                            .and_then(|c| c.get("body"))
                            .and_then(|b| b.as_str())
                            .unwrap_or_default()
                            .to_string();
                        if b.is_empty() {
                            return Ok(None);
                        }
                        (b, true)
                    }
                    Err(e) => (format!("[malformed plaintext: {e}]"), false),
                },
                Err(_) => ("[encrypted — no key for this message]".to_string(), false),
            };
            Ok(Some(Message {
                event_id: ev.event_id.clone(),
                room: room_id.to_string(),
                sender: ev.sender.clone(),
                ts: ev.origin_server_ts,
                body,
                encrypted: true,
                decrypted,
                mine,
                // Keep what a later key recovery needs, and only that: once
                // decrypted these are stored as NULL again.
                session_id: if decrypted { None } else { Some(sid.to_string()) },
                ciphertext: if decrypted { None } else { Some(ct.to_string()) },
            }))
        }
        _ => Ok(None),
    }
}

fn maintain_otks(sh: &Arc<Shared>, api: &Arc<Api>, session: &Session, have: u32) -> Result<()> {
    let published = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.get_meta("device_keys_published")?.is_some()
    };
    if have >= OTK_TARGET && published {
        return Ok(());
    }

    let body = {
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        let Some(c) = net.crypto.as_mut() else {
            return Ok(());
        };
        c.keys_upload_body(&session.user_id, &session.device_id, have, !published)?
    };
    let Some(body) = body else { return Ok(()) };

    api.keys_upload(&body)?;

    let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
    let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
    if let Some(c) = net.crypto.as_mut() {
        c.mark_published(&db)?;
    }
    db.set_meta("device_keys_published", "1")?;
    Ok(())
}

// ------------------------------------------------------------------ actions

pub fn do_login(sh: &Arc<Shared>, homeserver: &str, user: &str, password: &str) -> Result<Session> {
    sh.set_state(State::Connecting, None);
    let mut a = Api::new(homeserver)?;
    let session = a.login(user, password)?;

    {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.clear()?;
        db.save_session(&session)?;
    }
    {
        let mut g = sh.api.lock().map_err(|_| anyhow!("api lock poisoned"))?;
        *g = Some(Arc::new(a));
    }
    {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let c = Crypto::load_or_create(&db)?;
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        net.crypto = Some(c);
    }
    {
        let mut st = sh.st.lock().map_err(|_| anyhow!("st lock poisoned"))?;
        st.session = Some(session.clone());
    }
    sh.set_state(State::Syncing, None);
    sh.kick();
    Ok(session)
}

pub fn do_logout(sh: &Arc<Shared>) -> Result<()> {
    if let Some(api) = sh.api() {
        let _ = api.logout();
    }
    {
        let mut g = sh.api.lock().map_err(|_| anyhow!("api lock poisoned"))?;
        *g = None;
    }
    {
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        net.crypto = None;
    }
    {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.clear()?;
    }
    {
        let mut st = sh.st.lock().map_err(|_| anyhow!("st lock poisoned"))?;
        st.session = None;
    }
    sh.set_state(State::LoggedOut, None);
    Ok(())
}

/// Send a message, establishing Megolm key sharing first when the room is encrypted.
pub fn do_send(sh: &Arc<Shared>, room: &str, body: &str) -> Result<String> {
    let api = sh.api().ok_or_else(|| anyhow!("not logged in"))?;
    let session = sh.session().ok_or_else(|| anyhow!("not logged in"))?;

    let encrypted = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.list_rooms()?
            .into_iter()
            .find(|r| r.id == room)
            .map(|r| r.encrypted)
            .unwrap_or(false)
    };

    let txn = format!("kmatrix{}", now_ms());
    let content = serde_json::json!({ "msgtype": "m.text", "body": body });

    if !encrypted {
        return api.send_event(room, "m.room.message", &txn, &content);
    }

    // Ensure we hold an outbound Megolm session and every device has the key.
    let need_share = {
        let net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        match net.crypto.as_ref() {
            Some(c) => !c.has_outbound(room),
            None => return Err(anyhow!("no crypto state")),
        }
    };

    if need_share {
        let members = api.joined_members(room)?;
        let kq = api.keys_query(&members)?;

        let (devices, need) = {
            let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
            let c = net
                .crypto
                .as_mut()
                .ok_or_else(|| anyhow!("no crypto state"))?;
            let devices = c.parse_device_keys(&kq);
            let need = c.devices_needing_session(&devices);
            // Keep the ed25519 keys around: device verification MACs are
            // checked against them later.
            c.remember_devices(&devices);
            (devices, need)
        };

        if !need.is_empty() {
            let claim = api.keys_claim(&Crypto::claim_body(&need))?;
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
            let c = net
                .crypto
                .as_mut()
                .ok_or_else(|| anyhow!("no crypto state"))?;
            c.create_outbound_olm(&db, &claim, &need)?;
        }

        let messages = {
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
            let c = net
                .crypto
                .as_mut()
                .ok_or_else(|| anyhow!("no crypto state"))?;
            c.encrypt_room_key_to_devices(
                &db,
                room,
                &devices,
                &session.user_id,
                &session.device_id,
            )?
        };
        let ktxn = format!("kmatrixkey{}", now_ms());
        api.send_to_device("m.room.encrypted", &ktxn, &messages)?;
    }

    let envelope = serde_json::json!({
        "type": "m.room.message",
        "room_id": room,
        "content": content,
    });
    let enc = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        let c = net
            .crypto
            .as_mut()
            .ok_or_else(|| anyhow!("no crypto state"))?;
        c.encrypt(&db, room, &envelope, &session.user_id, &session.device_id)?
    };
    api.send_event(room, "m.room.encrypted", &txn, &enc)
}

/// Accept the user's key-backup recovery key and remember which backup
/// version it belongs to. Restoring itself is lazy: see `restore_room`.
pub fn do_backup_key(sh: &Arc<Shared>, key: &str) -> Result<usize> {
    let api = sh.api().ok_or_else(|| anyhow!("not logged in"))?;
    let info = api
        .backup_version()?
        .ok_or_else(|| anyhow!("this account has no server-side key backup"))?;
    if info.algorithm != BACKUP_ALGORITHM {
        return Err(anyhow!(
            "unsupported key backup algorithm {} (expected {BACKUP_ALGORITHM})",
            info.algorithm
        ));
    }

    {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        let c = net.crypto.as_mut().ok_or_else(|| anyhow!("no crypto state"))?;
        c.set_backup_key(&db, key, &info.public_key)?;
        db.set_meta("backup_version", &info.version)?;
    }

    // Upgrade what the user is most likely to look at first, so the effect is
    // visible immediately rather than only on the next room they open.
    let rooms = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.list_rooms()?
    };
    let mut restored = 0usize;
    for room in rooms.iter().take(BACKUP_EAGER_ROOMS) {
        restored += restore_room(sh, &api, &info.version, &room.id)?;
    }
    Ok(restored)
}

/// Pull the room keys needed by this room's undecryptable messages out of the
/// server-side backup, then re-decrypt them in place.
///
/// Deliberately per-session and per-room rather than a bulk
/// `GET /room_keys/keys`: this account's backup holds ~51k sessions, which
/// would be tens of MB of RAM and rows on a 474 MB device. Opening a room
/// fetches only the handful of sessions that room's visible history needs.
pub fn restore_room(
    sh: &Arc<Shared>,
    api: &Arc<Api>,
    version: &str,
    room: &str,
) -> Result<usize> {
    let pending = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.undecrypted_in_room(room, BACKUP_RESTORE_WINDOW)?
    };
    if pending.is_empty() {
        return Ok(0);
    }

    // Many messages share one Megolm session; fetch each session once.
    let mut wanted: Vec<String> = Vec::new();
    for (_, session_id, _) in &pending {
        if !wanted.iter().any(|s| s == session_id) {
            wanted.push(session_id.clone());
        }
    }

    let mut imported = 0usize;
    for session_id in &wanted {
        let entry = match api.backup_session(version, room, session_id) {
            Ok(Some(e)) => e,
            Ok(None) => continue, // not in the backup; nothing to be done
            Err(e) => {
                eprintln!("kmatrixd: backup fetch {session_id}: {e:#}");
                continue;
            }
        };
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        let c = net.crypto.as_mut().ok_or_else(|| anyhow!("no crypto state"))?;
        match c.import_backup_session(&db, room, session_id, &entry) {
            Ok(true) => imported += 1,
            Ok(false) => {}
            Err(e) => eprintln!("kmatrixd: backup import {session_id}: {e:#}"),
        }
    }
    if imported == 0 {
        return Ok(0);
    }

    // Retry the messages those sessions unlock.
    let mut upgraded = 0usize;
    for (event_id, session_id, ciphertext) in &pending {
        let plain = {
            let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
            let c = net.crypto.as_mut().ok_or_else(|| anyhow!("no crypto state"))?;
            c.decrypt(session_id, ciphertext)
        };
        let Ok(json) = plain else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else {
            continue;
        };
        let body = v
            .get("content")
            .and_then(|c| c.get("body"))
            .and_then(|b| b.as_str())
            .unwrap_or_default();
        if body.is_empty() {
            continue;
        }
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.upgrade_message(event_id, body)?;
        upgraded += 1;
    }
    Ok(upgraded)
}

/// Best-effort key recovery for a room the user just opened.
///
/// Never fails the caller: if there is no backup key, no network, or the
/// backup does not have the session, the room simply renders the placeholders
/// it already had.
pub fn try_restore_room(sh: &Arc<Shared>, room: &str) {
    let has_key = match sh.net.lock() {
        Ok(g) => g.crypto.as_ref().is_some_and(|c| c.has_backup_key()),
        Err(_) => return,
    };
    if !has_key {
        return;
    }
    let Some(api) = sh.api() else { return };
    let version = match sh.db.lock() {
        Ok(db) => db.get_meta("backup_version").ok().flatten(),
        Err(_) => None,
    };
    let Some(version) = version else { return };
    match restore_room(sh, &api, &version, room) {
        Ok(0) => {}
        Ok(n) => eprintln!("kmatrixd: recovered {n} message(s) in {room} from key backup"),
        Err(e) => eprintln!("kmatrixd: backup restore for {room}: {e:#}"),
    }
}

// ----------------------------------------------------------- verification

/// Push a `VerifyStep` out: send its to-device events, tell the UI.
fn apply_verify_step(
    sh: &Arc<Shared>,
    api: &Arc<Api>,
    session: &Session,
    step: crate::crypto::VerifyStep,
) -> Result<()> {
    for (kind, device, content) in step.send {
        let messages = serde_json::json!({ &session.user_id: { device: content } });
        let txn = format!("kmxv{}", now_ms());
        if let Err(e) = api.send_to_device(&kind, &txn, &messages) {
            eprintln!("kmatrixd: sending {kind}: {e:#}");
        }
    }

    if let Some((transaction, device, indices)) = step.emoji {
        let emoji: Vec<serde_json::Value> = indices
            .iter()
            .map(|i| {
                let (glyph, name) = crate::emoji::SAS_EMOJI[(*i as usize) % 64];
                serde_json::json!([glyph, name])
            })
            .collect();
        sh.bus.publish(&serde_json::json!({
            "event": "verification", "phase": "emoji",
            "transaction": transaction, "device": device, "emoji": emoji
        }));
    }

    if let Some(device) = step.done {
        sh.bus.publish(&serde_json::json!({
            "event": "verification", "phase": "done", "device": device
        }));
        // Now that the other device trusts us, ask it for the backup key
        // instead of making the user type 58 base58 characters on e-ink.
        request_backup_secret(sh, api, session);
    }

    if let Some(reason) = step.cancelled {
        sh.bus.publish(&serde_json::json!({
            "event": "verification", "phase": "cancelled", "reason": reason
        }));
    }
    Ok(())
}

fn handle_verification_event(
    sh: &Arc<Shared>,
    api: &Arc<Api>,
    session: &Session,
    ev: &ToDeviceEvent,
) -> Result<()> {
    // The MAC step needs the peer's ed25519 key, and at the start of a
    // verification nothing has queried our own devices yet. Do it once, here,
    // so the registry is populated before the MACs arrive.
    if ev.kind == "m.key.verification.request" || ev.kind == "m.key.verification.start" {
        match api.keys_query(std::slice::from_ref(&session.user_id)) {
            Ok(kq) => {
                let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
                if let Some(c) = net.crypto.as_mut() {
                    let devices = c.parse_device_keys(&kq);
                    c.remember_devices(&devices);
                }
            }
            Err(e) => eprintln!("kmatrixd: keys_query for verification: {e:#}"),
        }
    }

    let step = {
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        let c = net.crypto.as_mut().ok_or_else(|| anyhow!("no crypto state"))?;
        c.handle_verification(
            &session.user_id,
            &session.device_id,
            &ev.sender,
            &ev.kind,
            &ev.content,
        )?
    };
    apply_verify_step(sh, api, session, step)
}

pub fn do_verify_confirm(sh: &Arc<Shared>, transaction: &str, confirm: bool) -> Result<()> {
    let api = sh.api().ok_or_else(|| anyhow!("not logged in"))?;
    let session = sh.session().ok_or_else(|| anyhow!("not logged in"))?;
    let step = {
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        let c = net.crypto.as_mut().ok_or_else(|| anyhow!("no crypto state"))?;
        c.confirm_verification(&session.user_id, &session.device_id, transaction, confirm)?
    };
    apply_verify_step(sh, &api, &session, step)
}

/// Ask our other devices for the key-backup private key over encrypted
/// to-device secret sharing. Best effort: a device that does not trust us
/// simply will not answer.
fn request_backup_secret(sh: &Arc<Shared>, api: &Arc<Api>, session: &Session) {
    let already = match sh.net.lock() {
        Ok(g) => g.crypto.as_ref().is_some_and(|c| c.has_backup_key()),
        Err(_) => return,
    };
    if already {
        return;
    }

    let devices = match api.keys_query(std::slice::from_ref(&session.user_id)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kmatrixd: keys_query for secret request: {e:#}");
            return;
        }
    };
    let (request_id, content) = {
        let mut net = match sh.net.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let Some(c) = net.crypto.as_mut() else { return };
        c.secret_request(&session.device_id, crate::crypto::MEGOLM_BACKUP_SECRET)
    };
    let _ = request_id;

    let mut targets = serde_json::Map::new();
    if let Some(list) = devices
        .get("device_keys")
        .and_then(|d| d.get(&session.user_id))
        .and_then(|d| d.as_object())
    {
        for device_id in list.keys() {
            if device_id == &session.device_id {
                continue;
            }
            targets.insert(device_id.clone(), content.clone());
        }
    }
    if targets.is_empty() {
        return;
    }
    let messages = serde_json::json!({ &session.user_id: targets });
    let txn = format!("kmxs{}", now_ms());
    if let Err(e) = api.send_to_device("m.secret.request", &txn, &messages) {
        eprintln!("kmatrixd: secret request: {e:#}");
    }
}

/// A secret arrived from one of our own verified devices.
fn handle_secret(
    sh: &Arc<Shared>,
    api: &Arc<Api>,
    session: &Session,
    outcome: crate::crypto::ToDeviceOutcome,
) {
    let crate::crypto::ToDeviceOutcome::Secret {
        name,
        secret,
        request_id,
    } = outcome;
    if name != crate::crypto::MEGOLM_BACKUP_SECRET {
        return;
    }

    // The backup's public key pins what a valid secret must derive to, so a
    // device that sends us the wrong key is rejected rather than silently
    // producing sessions that decrypt nothing.
    let expected = api.backup_version().ok().flatten();
    let version = expected.as_ref().map(|b| b.version.clone());
    let public = expected.as_ref().map(|b| b.public_key.clone());

    let stored = {
        let db = match sh.db.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let mut net = match sh.net.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let Some(c) = net.crypto.as_mut() else { return };
        let r = c.set_backup_key_base64(&db, &secret, public.as_deref());
        if let (Ok(()), Some(v)) = (&r, &version) {
            let _ = db.set_meta("backup_version", v);
        }
        r
    };
    match stored {
        Ok(()) => {
            eprintln!("kmatrixd: adopted {name} from secret sharing");
            sh.bus.publish(&serde_json::json!({
                "event": "verification", "phase": "secret", "name": name
            }));
        }
        Err(e) => {
            eprintln!("kmatrixd: rejecting shared secret: {e:#}");
            return;
        }
    }

    // Stop the other devices from answering the same request.
    let cancel = {
        let net = match sh.net.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        net.crypto
            .as_ref()
            .map(|c| c.secret_cancellation(&session.device_id, &request_id))
    };
    let Some(cancel) = cancel else { return };
    if let Ok(devices) = api.keys_query(std::slice::from_ref(&session.user_id)) {
        let mut targets = serde_json::Map::new();
        if let Some(list) = devices
            .get("device_keys")
            .and_then(|d| d.get(&session.user_id))
            .and_then(|d| d.as_object())
        {
            for device_id in list.keys() {
                if device_id != &session.device_id {
                    targets.insert(device_id.clone(), cancel.clone());
                }
            }
        }
        if !targets.is_empty() {
            let messages = serde_json::json!({ &session.user_id: targets });
            let txn = format!("kmxc{}", now_ms());
            let _ = api.send_to_device("m.secret.request", &txn, &messages);
        }
    }
}

// --------------------------------------------------------------- backfill

/// Fetch one page of older history for a room.
///
/// `/sync` never revisits the past, so this is the only source of events
/// older than the window we first saw — and the only way to obtain the
/// ciphertext of the placeholders stored before ciphertext retention existed.
/// Returns (messages stored, reached the start of the room).
pub fn do_load_older(sh: &Arc<Shared>, room: &str, limit: u32) -> Result<(usize, bool)> {
    let api = sh.api().ok_or_else(|| anyhow!("not logged in"))?;
    let session = sh.session().ok_or_else(|| anyhow!("not logged in"))?;

    let (token, done) = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.back_token(room)?
    };
    if done {
        return Ok((0, true));
    }
    // No token means this room has not appeared in a sync batch since we
    // logged in — very common, since incremental syncs only carry rooms with
    // new activity. Omitting `from` starts the server at the newest visible
    // event (Matrix v1.3+), which is exactly where we want to begin.
    let page = api.messages(room, token.as_deref(), limit)?;
    let exhausted = page.end.is_none() || page.chunk.is_empty();

    let mut stored = 0usize;
    for ev in &page.chunk {
        if let Some(m) = convert_event(sh, room, ev, &session)? {
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            db.insert_message(&m)?;
            stored += 1;
        }
    }

    {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.set_back_token(room, page.end.as_deref(), exhausted)?;
    }

    // Freshly fetched ciphertext is exactly what the key backup can unlock,
    // so try immediately rather than making the user open the room twice.
    try_restore_room(sh, room);

    if stored > 0 {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let msgs = db.recent_messages(room, limit.max(50))?;
        drop(db);
        sh.bus.publish(&serde_json::json!({
            "event": "messages", "room": room, "messages": msgs
        }));
    }
    Ok((stored, exhausted))
}
