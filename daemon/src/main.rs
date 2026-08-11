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

use std::collections::{BTreeMap, BTreeSet};
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

/// Placeholder events re-fetched per room open. Each costs one small request
/// and permanently fixes that message, so a room with a long locked history
/// clears over a few visits rather than in one burst.
const REPAIR_EVENTS: u32 = 25;

/// Rooms to restore eagerly right after the recovery key is accepted, so the
/// user sees an immediate effect instead of a silent success.
const BACKUP_EAGER_ROOMS: usize = 3;

/// Rooms visited per naming pass. Each may cost one small request, and the
/// pass sits between long-polls, so this trades how fast the sweep clears
/// against how long syncing is held up.
const NAME_BATCH: usize = 25;

/// Bumped whenever the naming rules change, so the sweep runs again over
/// rooms it has already seen and corrects names derived under the old rules.
const NAME_SCHEMA: &str = "6";

/// Sender profiles looked up when a room is opened. Bounded so opening a
/// room with a long unnamed cast costs a few small requests, not hundreds.
const SENDER_LOOKUPS: usize = 8;

/// One-to-one chats a user must appear in, beside a counterpart already named
/// by `m.direct`, before being treated as the bridge's own rather than as
/// someone you talk to. Two could be coincidence between mutual contacts.
const BRIDGE_UBIQUITY: usize = 3;

/// Distinct speakers below which a room we have never inspected is treated as
/// a small chat worth naming after its members. Bridge portals have two.
const SMALL_ROOM: usize = 8;

/// Members listed in a computed room name before the rest become "and N
/// others". Matches the cap the server applies to `m.heroes`.
const HERO_CAP: usize = 5;

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

/// Internal partition holding the store key. On a Kindle `/mnt/us` is the
/// USB mass-storage volume — plug the device into any computer and the whole
/// database reads out — whereas `/var/local` is a separate ext3 partition
/// (`/dev/mmcblk0p9`) that USB does not expose.
const DEFAULT_KEY_DIR: &str = "/var/local/kmatrix";

/// An exclusive lock on the data directory, held for the lifetime of the
/// process. `flock` is released by the kernel when the process exits by any
/// route, including a kill, so there is no stale lock to clean up.
struct InstanceLock {
    /// The open descriptor *is* the lock: the kernel releases it when this
    /// closes, so the file is held rather than read.
    _file: std::fs::File,
}

impl InstanceLock {
    fn take(dir: &std::path::Path) -> Result<InstanceLock> {
        let path = dir.join("kmatrix.lock");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: a plain flock on a descriptor we own.
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&f);
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Err(anyhow!(
                    "another kmatrixd is already running on {}",
                    dir.display()
                ));
            }
            return Err(err).with_context(|| format!("locking {}", path.display()));
        }
        Ok(InstanceLock { _file: f })
    }
}

/// Load the store encryption key, creating one on first run.
///
/// Returns `None` only when encryption is explicitly disabled, in which case
/// the store is kept in the clear. A key that cannot be created is fatal
/// rather than a silent downgrade: quietly writing an unprotected database
/// full of message text and access tokens is exactly the failure this guards
/// against.
fn load_or_create_store_key(key_dir: Option<&std::path::Path>) -> Result<Option<[u8; 32]>> {
    let dir = match key_dir {
        // `--no-encryption`
        Some(p) if p.as_os_str().is_empty() => {
            eprintln!("kmatrixd: WARNING: encryption disabled, the store is readable by anyone");
            return Ok(None);
        }
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(DEFAULT_KEY_DIR),
    };
    let path = dir.join("store.key");

    match std::fs::read(&path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "store key {} is {} bytes, expected 32 — refusing to continue rather than \
                     risk making the database unreadable",
                    path.display(),
                    bytes.len()
                )
            })?;
            Ok(Some(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("creating key dir {}", dir.display()))?;
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);

            let tmp = dir.join("store.key.tmp");
            std::fs::write(&tmp, key).with_context(|| format!("writing {}", tmp.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("chmod {}", tmp.display()))?;
            }
            std::fs::rename(&tmp, &path)
                .with_context(|| format!("installing {}", path.display()))?;
            eprintln!("kmatrixd: created store key at {}", path.display());
            Ok(Some(key))
        }
        Err(e) => Err(e).with_context(|| format!("reading store key {}", path.display())),
    }
}

fn run() -> Result<()> {
    let mut data_dir: Option<PathBuf> = None;
    let mut key_dir: Option<PathBuf> = None;
    let mut reset_store = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => data_dir = args.next().map(PathBuf::from),
            "--key-dir" => key_dir = args.next().map(PathBuf::from),
            "--no-encryption" => key_dir = Some(PathBuf::new()),
            "--reset-store" => reset_store = true,
            "--version" => {
                println!("{CLIENT_VERSION}");
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "usage: kmatrixd --data-dir <dir> [--key-dir <dir>]\n\
                     [--no-encryption] [--reset-store]\n\
                     \n\
                     The database holds message text and access tokens, and on a Kindle\n\
                     --data-dir sits on the USB-exported partition. The store is therefore\n\
                     encrypted with a key kept in --key-dir, which defaults to\n\
                     {DEFAULT_KEY_DIR} -- a separate internal partition that USB does not\n\
                     expose. --no-encryption opts out and stores everything in the clear.\n\
                     --reset-store deletes the database, for when the key is gone and the\n\
                     data can no longer be read; you will have to log in again."
                );
                return Ok(());
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }
    let data_dir = data_dir.ok_or_else(|| anyhow!("--data-dir is required"))?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    // One daemon per data directory. Two of them share a store, both sync the
    // same account, and -- since a daemon exits with its last client and takes
    // the port file with it -- the second one to leave deletes the port file
    // the first one is still listening behind, which leaves a live daemon
    // nothing can find. The lock is held for as long as the process runs and
    // released by the kernel however it dies, so a crash cannot wedge it.
    let _instance = InstanceLock::take(&data_dir)?;

    let db_path = data_dir.join("kmatrix.sqlite3");
    if reset_store {
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", db_path.display()));
            match std::fs::remove_file(&p) {
                Ok(()) => eprintln!("kmatrixd: removed {}", p.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
            }
        }
    }

    let key = load_or_create_store_key(key_dir.as_deref())?;
    // Both the open and the first read can fail on a key mismatch, and the
    // way out is the same either way, so they share one explanation.
    let opened = Store::open(&db_path, key).and_then(|s| {
        let session = s.load_session()?;
        Ok((s, session))
    });
    let (store, session) = opened.map_err(|e| {
        anyhow!(
            "{e:#}\n\nIf the store key was lost (a factory reset or a wiped /var/local \
             will do it) the database cannot be recovered. Start over with:\n  \
             kmatrixd --data-dir {} --reset-store\nYou will need to log in again.",
            data_dir.display()
        )
    })?;

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
    ipc::remove_own_port_file(&shared, &data_dir);
    Ok(())
}

// ------------------------------------------------------------------ sync

/// Name a room from its members, per the spec's "Calculating the display name
/// for a room". Only reached when the room has no `m.room.name` and no
/// canonical alias, which is the normal state of a direct message.
fn name_from_heroes(jr: &JoinedRoom) -> Option<String> {
    let s = &jr.summary;
    let members = s.joined_member_count + s.invited_member_count;
    if s.heroes.is_empty() {
        // A joined room always contains us, so a count of zero means the
        // server sent no summary at all rather than that the room is empty.
        // Any other heroless room has members we simply cannot name.
        return (members == 1).then(|| "Empty room".to_string());
    }
    let names: Vec<String> = s.heroes.iter().map(|h| hero_name(jr, h)).collect();
    Some(compose_name(&names, members))
}

/// Name a room from the full joined-member list, for rooms the server never
/// sent a summary for. Same output as the hero path: the first few members,
/// then a count of everyone else.
///
/// `skip` drops the bridge's own users, without which every bridged chat is
/// named after us and a bot as much as after the person.
fn name_from_members(
    me: &str,
    joined: &BTreeMap<String, Option<String>>,
    skip: &BTreeSet<String>,
) -> Option<String> {
    let people: Vec<&String> = joined
        .keys()
        .filter(|u| u.as_str() != me && !skip.contains(*u))
        .collect();
    // A room of nothing but bridge users is still a room; name it after
    // everyone rather than call it empty.
    let people: Vec<&String> = if people.is_empty() {
        joined.keys().filter(|u| u.as_str() != me).collect()
    } else {
        people
    };
    if people.is_empty() {
        return (joined.len() <= 1).then(|| "Empty room".to_string());
    }
    let counted = people.len() as u32 + 1;
    let names: Vec<String> = people
        .iter()
        .take(HERO_CAP)
        .map(|user_id| person_name(user_id, joined))
        .collect();
    Some(compose_name(&names, counted))
}

/// Users who turn up in one-to-one chats without being the other person:
/// our own bridge ghosts and the bridge bots.
///
/// A Signal portal holds the contact's ghost, ours, and the bot, so its
/// member list reads "me, them, Signal Bridge Bot". Nothing in the protocol
/// marks which is which, and the bridge does not record every portal in
/// `m.direct` — but across the chats it does record, the same few users
/// appear beside a counterpart that is already known. Those are the ones.
fn bridge_users(db: &Store, me: &str, counterpart: &BTreeMap<&str, &str>) -> BTreeSet<String> {
    let partners: BTreeSet<&str> = counterpart.values().copied().collect();
    let mut seen_in: BTreeMap<String, usize> = BTreeMap::new();
    for (room, partner) in counterpart {
        let Ok(ids) = db.member_ids(room) else {
            continue;
        };
        for id in ids {
            if id == me || id == *partner || partners.contains(id.as_str()) {
                continue;
            }
            *seen_in.entry(id).or_default() += 1;
        }
    }
    seen_in
        .into_iter()
        .filter(|(_, rooms)| *rooms >= BRIDGE_UBIQUITY)
        .map(|(user, _)| user)
        .collect()
}

/// "alice, bob and 4 others" — the listed names, then whoever is left once
/// they and the logged-in user are accounted for.
fn compose_name(names: &[String], members: u32) -> String {
    let others = members.saturating_sub(1).saturating_sub(names.len() as u32);
    let listed = names.join(", ");
    match others {
        0 => listed,
        1 => format!("{listed} and 1 other"),
        n => format!("{listed} and {n} others"),
    }
}

/// A hero's display name if the server sent their membership — under lazy
/// loading it does so for anyone who has spoken — else their localpart,
/// which is still far more use than a room id.
fn hero_name(jr: &JoinedRoom, user_id: &str) -> String {
    let member = jr
        .state
        .events
        .iter()
        .chain(jr.timeline.events.iter())
        .find(|ev| ev.kind == "m.room.member" && ev.state_key.as_deref() == Some(user_id));
    if let Some(name) = member.and_then(|ev| ev.content.displayname.as_deref()) {
        if !name.is_empty() {
            return name.to_string();
        }
    }
    localpart(user_id).to_string()
}

/// `@alice:example.com` -> `alice`. Still far more use than a room id, and it
/// fits an e-reader's room list where the full id does not.
fn localpart(user_id: &str) -> &str {
    let user_id = user_id.strip_prefix('@').unwrap_or(user_id);
    user_id.split(':').next().unwrap_or(user_id)
}

fn sync_loop(sh: Arc<Shared>) {
    let mut backoff = 1u64;
    // The sweep is recorded in the store, so it runs once per schema version
    // rather than on every launch.
    let mut names_done = sh
        .db
        .lock()
        .ok()
        .and_then(|db| db.get_meta("room_names_schema").ok().flatten())
        .is_some_and(|v| v == NAME_SCHEMA);
    while sh.running.load(Ordering::SeqCst) {
        let (api, session) = (sh.api(), sh.session());
        let (api, session) = match (api, session) {
            (Some(a), Some(s)) => (a, s),
            _ => {
                wait_for_kick(&sh, 1000);
                continue;
            }
        };

        // Between polls, not after one: this needs nothing from the sync, and
        // a long-poll can sit idle for its full 30 s window before returning.
        if !names_done {
            match backfill_room_names(&sh, &api, &session.user_id) {
                Ok((n, done)) => {
                    names_done = done;
                    if n > 0 {
                        eprintln!("kmatrixd: named {n} room(s)");
                    }
                }
                Err(e) => {
                    names_done = true;
                    eprintln!("kmatrixd: room naming: {e:#}");
                }
            }
        }

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

        // Lazy loading sends the membership of anyone who speaks in the batch,
        // which is exactly whose name the timeline is about to need.
        let names: BTreeMap<String, Option<String>> = jr
            .state
            .events
            .iter()
            .chain(jr.timeline.events.iter())
            .filter(|ev| ev.kind == "m.room.member")
            .filter_map(|ev| {
                let user = ev.state_key.clone()?;
                Some((user, ev.content.displayname.clone()))
            })
            .collect();
        if !names.is_empty() {
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            db.remember_members(&room_id, &names)?;
        }

        // A room with neither a name nor an alias — most direct messages —
        // is named after its members, not left labelled by its id.
        if room.name == room.id {
            if let Some(n) = name_from_heroes(&jr) {
                room.name = n;
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

/// Name a batch of rooms, sweeping the whole list once per schema version.
///
/// Two things need fixing that `/sync` will not tell us. Rooms stored before
/// the client understood `m.heroes` keep their ids, and an initial sync to
/// collect every summary 504s on a large account. And a direct chat cannot be
/// named from its members at all when it is bridged: a Signal portal holds
/// the contact's ghost, our own ghost, and the bridge bot, so the member list
/// reads "me, them, Signal Bridge Bot". `m.direct` says who the chat is with.
///
/// The sweep walks rooms in id order, `NAME_BATCH` per pass, recording how far
/// it got. Rooms needing nothing cost no request at all.
///
/// Returns the number renamed and whether the sweep has reached the end.
fn backfill_room_names(sh: &Arc<Shared>, api: &Arc<Api>, me: &str) -> Result<(usize, bool)> {
    // Without this every bridged chat would be named after its cast list, so
    // a pass that cannot read it must make no progress at all rather than
    // write names it would only have to correct later.
    let direct = match api.direct_rooms(me) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("kmatrixd: m.direct: {e:#}");
            return Ok((0, false));
        }
    };
    let mut counterpart: BTreeMap<&str, &str> = BTreeMap::new();
    for (user, rooms) in &direct {
        for room in rooms {
            counterpart.entry(room.as_str()).or_insert(user.as_str());
        }
    }
    if !counterpart.is_empty() {
        eprintln!("kmatrixd: {} direct chat(s) known", counterpart.len());
    }

    let (batch, done, bridge) = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let bridge = bridge_users(&db, me, &counterpart);
        // The cursor carries the rules it was recorded under: a new schema
        // must re-walk the whole list, not resume where the old one stopped.
        let cursor = db
            .get_meta("room_names_cursor")?
            .and_then(|v| {
                v.strip_prefix(NAME_SCHEMA)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let mut rooms: Vec<Room> = db
            .list_rooms()?
            .into_iter()
            .filter(|r| r.id > cursor)
            .collect();
        rooms.sort_by(|a, b| a.id.cmp(&b.id));
        let done = rooms.len() <= NAME_BATCH;
        rooms.truncate(NAME_BATCH);
        (rooms, done, bridge)
    };

    let mut renamed = 0usize;
    let mut reached = None;
    // A lookup that fails is almost always the radio, not the room: an
    // e-reader spends most of its life asleep with the wifi down. Stopping
    // leaves the cursor on the last room actually dealt with, so the sweep
    // resumes there instead of marching to the end having named nothing.
    let mut offline = false;
    for room in &batch {
        let partner = counterpart.get(room.id.as_str()).copied();
        let (known_members, spoke) = {
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            (
                !db.member_ids(&room.id)?.is_empty(),
                db.distinct_senders(&room.id)?,
            )
        };
        // Worth asking about if it has no name, if it is a direct chat, or if
        // it is a small room we have never looked at — the last catches the
        // bridge portals the bridge forgot to record in `m.direct`. A room a
        // crowd talks in is left alone: naming it would mean pulling a
        // membership list of thousands to render five.
        let consider =
            room.name == room.id || partner.is_some() || (!known_members && spoke <= SMALL_ROOM);
        if !consider {
            reached = Some(room.id.clone());
            continue;
        }

        // A name the room carries outranks anything we compute. Asking beats
        // trying to tell, from the stored string alone, whether an earlier
        // pass took it from the server or built it from the members.
        let given = if room.name == room.id {
            None
        } else {
            match api.room_name(&room.id) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("kmatrixd: naming {}: {e:#}", room.id);
                    offline = true;
                    break;
                }
            }
        };
        let members = match api.member_names(&room.id) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("kmatrixd: naming {}: {e:#}", room.id);
                offline = true;
                break;
            }
        };
        {
            // Already paid for over the radio; keeping the names spares every
            // message in this room from being attributed to a bare id.
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            db.remember_members(&room.id, &members)?;
        }
        reached = Some(room.id.clone());

        let wanted = match (given, partner) {
            (Some(given), _) => given,
            (None, Some(user)) => person_name(user, &members),
            (None, None) => match name_from_members(me, &members, &bridge) {
                Some(n) => n,
                None => continue,
            },
        };
        if room.name == wanted {
            continue;
        }
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let Some(mut stored) = db.get_room(&room.id)? else {
            continue;
        };
        stored.name = wanted;
        db.upsert_room(&stored)?;
        renamed += 1;
    }

    let done = done && !offline;
    {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        if let Some(reached) = reached {
            db.set_meta("room_names_cursor", &format!("{NAME_SCHEMA}:{reached}"))?;
        }
        if done {
            db.set_meta("room_names_schema", NAME_SCHEMA)?;
        }
    }
    if renamed > 0 {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        let rooms = db.list_rooms()?;
        drop(db);
        sh.bus
            .publish(&serde_json::json!({ "event": "rooms", "rooms": rooms }));
    }
    Ok((renamed, done))
}

/// One person's name as this room knows them, else their localpart.
fn person_name(user_id: &str, members: &BTreeMap<String, Option<String>>) -> String {
    match members.get(user_id).and_then(|d| d.as_deref()) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => localpart(user_id).to_string(),
    }
}

/// Record a replacement if this content is one, and report whether it was.
///
/// Matrix sends an edit as an ordinary `m.room.message` carrying the new text
/// under `m.new_content` and a `m.replace` relation naming what it replaces.
/// Its top-level body is a `"* new text"` fallback for clients that cannot
/// apply edits — render that and the reader sees the message twice.
fn record_if_edit(sh: &Arc<Shared>, ts: u64, content: &EventContent) -> Result<bool> {
    let Some(rel) = content.relates_to.as_ref() else {
        return Ok(false);
    };
    if rel.rel_type.as_deref() != Some("m.replace") {
        return Ok(false);
    }
    let Some(target) = rel.event_id.as_deref() else {
        return Ok(false);
    };
    let body = content
        .new_content
        .as_deref()
        .and_then(|c| c.body.as_deref())
        .or_else(|| {
            content
                .body
                .as_deref()
                .map(|b| b.strip_prefix("* ").unwrap_or(b))
        })
        .unwrap_or_default();
    // An empty replacement is still an edit event, and still must not render.
    if !body.is_empty() {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.record_edit(target, ts, body)?;
    }
    Ok(true)
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
            if record_if_edit(sh, ev.origin_server_ts, &ev.content)? {
                return Ok(None);
            }
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
                // Attached when reading, from what the room calls the sender.
                sender_name: None,
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
                Ok(json) => match serde_json::from_str::<DecryptedEvent>(&json) {
                    Ok(p) => {
                        // An edit is encrypted like any other message, so this
                        // is the first point at which one can be recognised.
                        if record_if_edit(sh, ev.origin_server_ts, &p.content)? {
                            return Ok(None);
                        }
                        let b = p.content.body.unwrap_or_default();
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
                sender_name: None,
                // Keep what a later key recovery needs, and only that: once
                // decrypted these are stored as NULL again.
                session_id: if decrypted {
                    None
                } else {
                    Some(sid.to_string())
                },
                ciphertext: if decrypted {
                    None
                } else {
                    Some(ct.to_string())
                },
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
        let c = net
            .crypto
            .as_mut()
            .ok_or_else(|| anyhow!("no crypto state"))?;
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
pub fn restore_room(sh: &Arc<Shared>, api: &Arc<Api>, version: &str, room: &str) -> Result<usize> {
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
        let c = net
            .crypto
            .as_mut()
            .ok_or_else(|| anyhow!("no crypto state"))?;
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
            let c = net
                .crypto
                .as_mut()
                .ok_or_else(|| anyhow!("no crypto state"))?;
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

/// Make a room as readable as it can be, at the moment it is opened.
///
/// Two different things lock a message. One is a missing room key, which the
/// backup can supply. The other is older: messages stored before the client
/// kept the ciphertext have nothing left to decrypt, and no key will bring
/// them back — only re-fetching the original events will. So when the recent
/// history is full of those, page it in once and try the backup again.
pub fn repair_room(sh: &Arc<Shared>, room: &str) {
    try_restore_room(sh, room);
    name_visible_senders(sh, room);

    match refetch_placeholders(sh, room) {
        Ok(0) => return,
        Ok(n) => eprintln!("kmatrixd: refetched {n} event(s) in {room} to unlock history"),
        Err(e) => {
            eprintln!("kmatrixd: refetching in {room}: {e:#}");
            return;
        }
    }
    try_restore_room(sh, room);
}

/// Put a name to the people visible in a room whose names we never learned.
///
/// `/sync` names anyone who speaks while we are running, but history synced
/// earlier carries senders we know nothing about — and in a bridged room that
/// means every message is signed `signal_<uuid>` or a phone number. Only the
/// senders actually on screen are looked up, a few per open, so a room with a
/// long cast converges over a few visits instead of one enormous fetch.
fn name_visible_senders(sh: &Arc<Shared>, room: &str) {
    let Some(api) = sh.api() else { return };
    let unknown: Vec<String> = {
        let Ok(db) = sh.db.lock() else { return };
        let Ok(msgs) = db.recent_messages(room, BACKUP_RESTORE_WINDOW) else {
            return;
        };
        let mut seen: Vec<String> = Vec::new();
        for m in &msgs {
            if m.sender_name.is_none() && !seen.contains(&m.sender) {
                seen.push(m.sender.clone());
            }
        }
        seen.truncate(SENDER_LOOKUPS);
        seen
    };
    if unknown.is_empty() {
        return;
    }

    let mut found: BTreeMap<String, Option<String>> = BTreeMap::new();
    for user in unknown {
        match api.profile_name(&user) {
            Ok(Some(name)) => {
                found.insert(user, Some(name));
            }
            // No display name, or the lookup failed: their localpart is what
            // the timeline will keep showing, which is no worse than before.
            Ok(None) => {}
            Err(e) => eprintln!("kmatrixd: naming {user}: {e:#}"),
        }
    }
    if found.is_empty() {
        return;
    }
    if let Ok(db) = sh.db.lock() {
        if let Err(e) = db.remember_members(room, &found) {
            eprintln!("kmatrixd: remembering names in {room}: {e:#}");
        }
    }
}

/// Ask the server again for the messages we hold without their ciphertext.
///
/// Stored before the client kept any, they have nothing a room key can act
/// on. Re-reading the room's newest page is one request rather than many,
/// but it only reaches as far back as that page — and these are the oldest
/// messages in the room, so a page never reaches them and the same page gets
/// re-read on every open. Asking for each event by id costs a request each
/// and ends: once an event is back, it is no longer a placeholder.
fn refetch_placeholders(sh: &Arc<Shared>, room: &str) -> Result<usize> {
    let wanted = {
        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
        db.placeholder_event_ids(room, REPAIR_EVENTS)?
    };
    if wanted.is_empty() {
        return Ok(0);
    }
    let api = sh.api().ok_or_else(|| anyhow!("not logged in"))?;
    let session = sh.session().ok_or_else(|| anyhow!("not logged in"))?;
    let mut stored = 0usize;
    for event_id in &wanted {
        // A redacted or purged event is simply gone; the placeholder stays
        // and the rest of the batch still gets its chance.
        let ev = match api.event(room, event_id) {
            Ok(ev) => ev,
            Err(e) => {
                eprintln!("kmatrixd: refetching {event_id}: {e:#}");
                continue;
            }
        };
        if let Some(m) = convert_event(sh, room, &ev, &session)? {
            let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
            db.insert_message(&m)?;
            stored += 1;
        }
    }
    Ok(stored)
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
        let c = net
            .crypto
            .as_mut()
            .ok_or_else(|| anyhow!("no crypto state"))?;
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
        let c = net
            .crypto
            .as_mut()
            .ok_or_else(|| anyhow!("no crypto state"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(json: &str) -> JoinedRoom {
        serde_json::from_str(json).expect("joined room")
    }

    #[test]
    fn prefers_a_heros_display_name_over_their_id() {
        let jr = joined(
            r#"{"summary":{"m.heroes":["@alice:example.com"],"m.joined_member_count":2},
                "state":{"events":[{"type":"m.room.member","state_key":"@alice:example.com",
                                    "content":{"displayname":"Alice"}}]}}"#,
        );
        assert_eq!(name_from_heroes(&jr).as_deref(), Some("Alice"));
    }

    #[test]
    fn falls_back_to_the_localpart_when_no_membership_was_sent() {
        let jr = joined(
            r#"{"summary":{"m.heroes":["@alice:example.com","@bob:example.com"],
                           "m.joined_member_count":3}}"#,
        );
        assert_eq!(name_from_heroes(&jr).as_deref(), Some("alice, bob"));
    }

    #[test]
    fn counts_the_members_the_five_hero_cap_leaves_out() {
        let jr = joined(
            r#"{"summary":{"m.heroes":["@a:h","@b:h","@c:h","@d:h","@e:h"],
                           "m.joined_member_count":9,"m.invited_member_count":1}}"#,
        );
        // 9 + 1 members, minus ourselves, minus the five named.
        assert_eq!(
            name_from_heroes(&jr).as_deref(),
            Some("a, b, c, d, e and 4 others")
        );
    }

    #[test]
    fn a_single_remaining_member_is_not_pluralised() {
        let jr = joined(r#"{"summary":{"m.heroes":["@a:h"],"m.joined_member_count":3}}"#);
        assert_eq!(name_from_heroes(&jr).as_deref(), Some("a and 1 other"));
    }

    #[test]
    fn names_a_room_everyone_else_has_left() {
        let jr = joined(r#"{"summary":{"m.heroes":[],"m.joined_member_count":1}}"#);
        assert_eq!(name_from_heroes(&jr).as_deref(), Some("Empty room"));
    }

    #[test]
    fn declines_to_invent_a_name_without_heroes() {
        // A populated room that sent no heroes tells us nothing; the caller
        // must keep the room id rather than mislabel the room.
        let jr = joined(r#"{"summary":{"m.heroes":[],"m.joined_member_count":40}}"#);
        assert_eq!(name_from_heroes(&jr), None);
        assert_eq!(name_from_heroes(&joined("{}")), None);
    }

    fn members(pairs: &[(&str, Option<&str>)]) -> BTreeMap<String, Option<String>> {
        pairs
            .iter()
            .map(|(u, d)| (u.to_string(), d.map(str::to_string)))
            .collect()
    }

    fn nobody() -> BTreeSet<String> {
        BTreeSet::new()
    }

    /// The plugin's JSON decoder renders a null as a truthy sentinel, so
    /// `msg.sender_name or fallback` yields the sentinel and the next
    /// concatenation throws — taking the whole timeline with it. An absent
    /// name must therefore be an absent field, not a null one.
    #[test]
    fn an_unknown_sender_name_is_left_out_rather_than_sent_as_null() {
        let m = Message {
            event_id: "$e".into(),
            room: "!r:h".into(),
            sender: "@a:h".into(),
            ts: 1,
            sender_name: None,
            body: "hi".into(),
            encrypted: false,
            decrypted: true,
            mine: false,
            session_id: None,
            ciphertext: None,
        };
        let json = serde_json::to_string(&m).expect("serialise");
        assert!(
            !json.contains("sender_name"),
            "an unknown name must not reach the plugin at all: {json}"
        );

        let named = Message {
            sender_name: Some("Oliver Habryka (S)".into()),
            ..m
        };
        let json = serde_json::to_string(&named).expect("serialise");
        assert!(json.contains(r#""sender_name":"Oliver Habryka (S)""#), "{json}");
    }

    #[test]
    fn names_a_room_after_everyone_but_us() {
        let m = members(&[
            ("@me:h", Some("Me")),
            ("@alice:h", Some("Alice")),
            ("@bob:h", None),
        ]);
        // Display name where the server has one, localpart where it does not.
        assert_eq!(
            name_from_members("@me:h", &m, &nobody()).as_deref(),
            Some("Alice, bob")
        );
    }

    #[test]
    fn a_room_containing_only_us_is_empty() {
        let m = members(&[("@me:h", Some("Me"))]);
        assert_eq!(
            name_from_members("@me:h", &m, &nobody()).as_deref(),
            Some("Empty room")
        );
    }

    #[test]
    fn a_crowd_is_capped_and_counted() {
        let mut pairs: Vec<(String, Option<String>)> =
            (0..12).map(|i| (format!("@u{i:02}:h"), None)).collect();
        pairs.push(("@me:h".to_string(), None));
        let m: BTreeMap<_, _> = pairs.into_iter().collect();
        // Five named, thirteen members, ourselves excluded: seven left.
        assert_eq!(
            name_from_members("@me:h", &m, &nobody()).as_deref(),
            Some("u00, u01, u02, u03, u04 and 7 others")
        );
    }

    #[test]
    fn a_bridged_chat_is_named_after_the_person_not_the_plumbing() {
        // What a Signal portal actually holds.
        let m = members(&[
            ("@lassulus:h", Some("me")),
            ("@signal_aaa:h", Some("lassulus (S)")),
            ("@signal_bbb:h", Some("Oliver Habryka (S)")),
            ("@signalbot:h", Some("Signal Bridge Bot")),
        ]);
        let bridge: BTreeSet<String> = ["@signal_aaa:h", "@signalbot:h"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            name_from_members("@lassulus:h", &m, &bridge).as_deref(),
            Some("Oliver Habryka (S)"),
            "our own ghost and the bot are not who the chat is with"
        );
    }

    #[test]
    fn a_room_of_nothing_but_bridge_users_still_gets_a_name() {
        // Excluding everyone would leave nothing to call it; the plumbing is
        // a worse name than the person, but it beats "Empty room".
        let m = members(&[("@me:h", Some("Me")), ("@signalbot:h", Some("Bot"))]);
        let bridge: BTreeSet<String> = ["@signalbot:h".to_string()].into_iter().collect();
        assert_eq!(
            name_from_members("@me:h", &m, &bridge).as_deref(),
            Some("Bot")
        );
    }
}
