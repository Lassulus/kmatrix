//! Local IPC: line-delimited JSON over TCP on 127.0.0.1.
//!
//! Loopback TCP rather than a unix socket because KOReader's bundled LuaSocket
//! exports only `luaopen_socket_score` — there is no `socket.unix` on any
//! shipped target. A loopback listener is reachable by every local process, so
//! the port file is 0600 and carries a random token that clients must present
//! before anything else. See PROTOCOL.md.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use serde_json::json;

use crate::model::*;
use crate::Shared;

/// Fan-out of unsolicited events to every authenticated client.
pub struct Bus {
    clients: Mutex<Vec<TcpStream>>,
}

impl Bus {
    pub fn new() -> Bus {
        Bus {
            clients: Mutex::new(Vec::new()),
        }
    }

    fn add(&self, s: TcpStream) {
        if let Ok(mut v) = self.clients.lock() {
            v.push(s);
        }
    }

    /// Write one event line to every client, dropping those that error.
    pub fn publish(&self, ev: &serde_json::Value) {
        let Ok(mut line) = serde_json::to_string(ev) else {
            return;
        };
        line.push('\n');
        let Ok(mut v) = self.clients.lock() else {
            return;
        };
        v.retain_mut(|c| c.write_all(line.as_bytes()).and_then(|_| c.flush()).is_ok());
    }
}

impl Default for Bus {
    fn default() -> Self {
        Bus::new()
    }
}

fn random_token() -> String {
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Bind an ephemeral loopback port and publish it, with a token, at 0600.
pub fn listen(sh: &Arc<Shared>) -> Result<TcpListener> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .context("binding 127.0.0.1")?;
    let port = listener.local_addr()?.port();
    let token = random_token();

    let path = sh.data_dir.join("kmatrix.port");
    let tmp = sh.data_dir.join("kmatrix.port.tmp");
    std::fs::write(&tmp, format!("{port}\n{token}\n")).context("writing port file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .context("chmod port file")?;
    }
    std::fs::rename(&tmp, &path).context("installing port file")?;

    if let Ok(mut st) = sh.st.lock() {
        st.error = None;
    }
    // In memory, not in the store: `Store::clear()` runs on login and logout
    // and would otherwise revoke the token we just wrote to the port file.
    let _ = sh.ipc_token.set(token);
    let _ = sh.ipc_port.set(port);
    eprintln!("kmatrixd: listening on 127.0.0.1:{port}");
    Ok(listener)
}

pub fn serve(sh: &Arc<Shared>, listener: TcpListener) {
    for conn in listener.incoming() {
        if !sh.running.load(Ordering::SeqCst) {
            break;
        }
        match conn {
            Ok(stream) => {
                let sh2 = Arc::clone(sh);
                if let Err(e) = std::thread::Builder::new()
                    .name("ipc".into())
                    .spawn(move || {
                        if let Err(e) = handle_client(&sh2, stream) {
                            eprintln!("kmatrixd: client: {e:#}");
                        }
                    })
                {
                    eprintln!("kmatrixd: spawn client thread: {e}");
                }
            }
            Err(e) => eprintln!("kmatrixd: accept: {e}"),
        }
        if !sh.running.load(Ordering::SeqCst) {
            break;
        }
    }
}

fn handle_client(sh: &Arc<Shared>, stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true).ok();
    let mut writer = stream.try_clone().context("cloning stream")?;
    let reader = BufReader::new(stream);
    let mut authed = false;

    for line in reader.lines() {
        let line = line.context("reading line")?;
        if line.trim().is_empty() {
            continue;
        }

        let env: Envelope = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                // Recover the id even though the command did not parse.
                // Clients match responses to requests by id, so answering
                // with a placeholder id leaves the caller waiting forever —
                // an unknown command must fail the request, not wedge it.
                let id = serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
                    .unwrap_or(0);
                reply(
                    &mut writer,
                    &json!({"id": id, "ok": false, "error": format!("bad request: {e}")}),
                )?;
                continue;
            }
        };

        // The first command must be a valid `hello`.
        if !authed {
            match &env.cmd {
                Request::Hello { token } => {
                    let expected = sh.ipc_token.get().map(String::as_str);
                    if expected == Some(token.as_str()) {
                        authed = true;
                        reply(
                            &mut writer,
                            &json!({"id": env.id, "ok": true, "version": CLIENT_VERSION}),
                        )?;
                        sh.bus.add(writer.try_clone().context("cloning for bus")?);
                        continue;
                    }
                    reply(
                        &mut writer,
                        &json!({"id": env.id, "ok": false, "error": "bad token"}),
                    )?;
                    return Ok(());
                }
                _ => {
                    reply(
                        &mut writer,
                        &json!({"id": env.id, "ok": false, "error": "expected hello"}),
                    )?;
                    return Ok(());
                }
            }
        }

        let resp = dispatch(sh, env.id, env.cmd);
        reply(&mut writer, &resp)?;

        if resp.get("__shutdown").is_some() {
            sh.shutdown();
            // `incoming()` blocks until the next connection, so make one.
            let port = sh.ipc_port.get().copied();
            if let Some(port) = port {
                let _ = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
            }
            return Ok(());
        }
    }
    Ok(())
}

fn reply(w: &mut TcpStream, v: &serde_json::Value) -> Result<()> {
    let mut line = serde_json::to_string(v).context("encoding response")?;
    line.push('\n');
    w.write_all(line.as_bytes()).context("writing response")?;
    w.flush().context("flushing response")?;
    Ok(())
}

fn err(id: u64, e: impl std::fmt::Display) -> serde_json::Value {
    json!({ "id": id, "ok": false, "error": format!("{e:#}") })
}

fn dispatch(sh: &Arc<Shared>, id: u64, cmd: Request) -> serde_json::Value {
    match cmd {
        Request::Hello { .. } => json!({"id": id, "ok": true, "version": CLIENT_VERSION}),

        Request::Status => {
            let backup = match sh.net.lock() {
                Ok(g) => g.crypto.as_ref().is_some_and(|c| c.has_backup_key()),
                Err(p) => p.into_inner().crypto.as_ref().is_some_and(|c| c.has_backup_key()),
            };
            let st = match sh.st.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let mut v =
                json!({ "id": id, "ok": true, "state": st.state.as_str(), "backup": backup,
                        "clock_skew_ms": sh.api().map(|a| a.clock_skew_ms()).unwrap_or(0) });
            if let Some(s) = &st.session {
                v["user_id"] = json!(s.user_id);
                v["device_id"] = json!(s.device_id);
                v["homeserver"] = json!(s.homeserver);
            }
            if let Some(e) = &st.error {
                v["error"] = json!(e);
            }
            v
        }

        Request::Login {
            homeserver,
            user,
            password,
        } => match crate::do_login(sh, &homeserver, &user, &password) {
            Ok(s) => json!({"id": id, "ok": true, "user_id": s.user_id, "device_id": s.device_id}),
            Err(e) => {
                sh.set_state(State::LoggedOut, Some(format!("{e:#}")));
                err(id, e)
            }
        },

        Request::Logout => match crate::do_logout(sh) {
            Ok(()) => json!({"id": id, "ok": true}),
            Err(e) => err(id, e),
        },

        Request::Rooms => {
            let r = sh
                .db
                .lock()
                .map_err(|_| anyhow!("db lock poisoned"))
                .and_then(|db| db.list_rooms());
            match r {
                Ok(rooms) => json!({"id": id, "ok": true, "rooms": rooms}),
                Err(e) => err(id, e),
            }
        }

        Request::Messages { room, limit } => {
            // Opening a room is the moment we know which history the user
            // actually wants, so it is also the moment to spend requests
            // recovering exactly those room keys from the backup.
            crate::try_restore_room(sh, &room);
            let r = sh
                .db
                .lock()
                .map_err(|_| anyhow!("db lock poisoned"))
                .and_then(|db| db.recent_messages(&room, limit));
            match r {
                Ok(msgs) => json!({"id": id, "ok": true, "room": room, "messages": msgs}),
                Err(e) => err(id, e),
            }
        }

        Request::Send { room, body } => match crate::do_send(sh, &room, &body) {
            Ok(event_id) => json!({"id": id, "ok": true, "event_id": event_id}),
            Err(e) => err(id, e),
        },

        Request::MarkRead { room, event_id } => match sh.api() {
            Some(api) => match api.read_receipt(&room, &event_id) {
                Ok(()) => json!({"id": id, "ok": true}),
                Err(e) => err(id, e),
            },
            None => err(id, anyhow!("not logged in")),
        },

        Request::SyncNow => {
            sh.kick();
            json!({"id": id, "ok": true})
        }


        Request::LoadOlder { room, limit } => match crate::do_load_older(sh, &room, limit) {
            Ok((added, exhausted)) => {
                json!({"id": id, "ok": true, "added": added, "exhausted": exhausted})
            }
            Err(e) => err(id, e),
        },

        Request::VerifyConfirm {
            transaction,
            confirm,
        } => match crate::do_verify_confirm(sh, &transaction, confirm) {
            Ok(()) => json!({"id": id, "ok": true}),
            Err(e) => err(id, e),
        },
        Request::BackupKey { key } => match crate::do_backup_key(sh, &key) {
            Ok(n) => json!({"id": id, "ok": true, "restored": n}),
            Err(e) => err(id, e),
        },

        Request::Shutdown => json!({"id": id, "ok": true, "__shutdown": true}),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::State;
    use crate::{NetState, Shared, Status};
    use std::sync::atomic::AtomicBool;
    use std::sync::Condvar;

    fn shared(dir: &std::path::Path) -> Arc<Shared> {
        let store = crate::store::Store::open(&dir.join("s.db"), None).expect("open store");
        Arc::new(Shared {
            db: Mutex::new(store),
            net: Mutex::new(NetState { crypto: None }),
            api: Mutex::new(None),
            st: Mutex::new(Status {
                state: State::LoggedOut,
                error: None,
                session: None,
            }),
            bus: Bus::new(),
            wake: (Mutex::new(false), Condvar::new()),
            running: AtomicBool::new(true),
            data_dir: dir.to_path_buf(),
            ipc_token: std::sync::OnceLock::new(),
            ipc_port: std::sync::OnceLock::new(),
        })
    }

    /// Regression: the IPC token used to live in the `meta` table, which
    /// `Store::clear()` wipes on every login and logout. That silently
    /// revoked the token already written to the port file, so the running
    /// client kept working while every reconnect failed with "bad token" —
    /// on a Kindle, the UI simply went blank after the first suspend.
    #[test]
    fn ipc_token_survives_store_clear() {
        let dir =
            std::env::temp_dir().join(format!("kmatrix-ipc-test-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sh = shared(&dir);

        let _ = sh.ipc_token.set("secret-token".to_string());
        let _ = sh.ipc_port.set(4242);

        // What login and logout both do.
        sh.db.lock().expect("db").clear().expect("clear");

        assert_eq!(sh.ipc_token.get().map(String::as_str), Some("secret-token"));
        assert_eq!(sh.ipc_port.get().copied(), Some(4242));

        // And it must not be recoverable from the store either way.
        let leaked = sh
            .db
            .lock()
            .expect("db")
            .get_meta("ipc_token")
            .expect("get_meta");
        assert!(leaked.is_none(), "IPC token must never be persisted");

        let _ = std::fs::remove_dir_all(&dir);
    }
}