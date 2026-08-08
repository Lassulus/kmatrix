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
    let _ = sync_thread.join();
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
    if !resp.to_device.events.is_empty() {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let mut net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
        if let Some(c) = net.crypto.as_mut() {
            if let Err(e) = c.handle_to_device(&db, &resp.to_device.events) {
                eprintln!("kmatrixd: to-device: {e:#}");
            }
        }
    }

    // 2. Rooms.
    let mut changed_rooms: Vec<Room> = Vec::new();
    let mut new_messages: Vec<(String, Vec<Message>)> = Vec::new();

    for (room_id, jr) in resp.rooms.join {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let mut room = db
            .list_rooms()?
            .into_iter()
            .find(|r| r.id == room_id)
            .unwrap_or_else(|| Room {
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
            let net = sh.net.lock().map_err(|_| anyhow!("net lock poisoned"))?;
            let c = net
                .crypto
                .as_ref()
                .ok_or_else(|| anyhow!("no crypto state"))?;
            let devices = c.parse_device_keys(&kq);
            let need = c.devices_needing_session(&devices);
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
