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
    // Stash the token for connection auth.
    if let Ok(db) = sh.db.lock() {
        db.set_meta("ipc_token", &token)?;
    }
    if let Ok(db) = sh.db.lock() {
        db.set_meta("ipc_port", &port.to_string())?;
    }
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
                reply(
                    &mut writer,
                    &json!({"id": 0, "ok": false, "error": format!("bad request: {e}")}),
                )?;
                continue;
            }
        };

        // The first command must be a valid `hello`.
        if !authed {
            match &env.cmd {
                Request::Hello { token } => {
                    let expected = {
                        let db = sh.db.lock().map_err(|_| anyhow!("db lock poisoned"))?;
                        db.get_meta("ipc_token")?
                    };
                    if expected.as_deref() == Some(token.as_str()) {
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
            let port = sh
                .db
                .lock()
                .ok()
                .and_then(|db| db.get_meta("ipc_port").ok().flatten())
                .and_then(|p| p.parse::<u16>().ok());
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
            let st = match sh.st.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let mut v = json!({ "id": id, "ok": true, "state": st.state.as_str() });
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

        Request::Shutdown => json!({"id": id, "ok": true, "__shutdown": true}),
    }
}
