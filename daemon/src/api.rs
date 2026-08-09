//! Matrix Client-Server API over `ureq` 3 + rustls.
//!
//! Two rules govern this module:
//!
//! 1. **One agent, reused.** TLS handshakes over a Kindle's radio cost seconds.
//!    A single [`ureq::Agent`] keeps the connection pooled across every call.
//! 2. **`/sync` streams.** The sync response is the only large payload the
//!    daemon ever touches, and it is deserialized straight off the socket into
//!    the narrow structs in [`crate::model`]. Nothing here ever materializes a
//!    sync body as `String`, `Vec<u8>`, or `serde_json::Value`.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::Deserialize;
use serde_json::json;
use ureq::http::Response;
use ureq::typestate::{WithBody, WithoutBody};
use ureq::{Agent, Body, RequestBuilder};

use crate::model::{RoomEvent, Session, SyncResponse, CLIENT_VERSION, SYNC_FILTER};

/// Ceiling for a normal request. Generous because EDGE/2.4GHz-on-a-Kindle is
/// slow, but bounded so a wedged server cannot hang the daemon forever.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// Connect (DNS + TCP + TLS) budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// `.well-known` discovery is best-effort and must not stall login. A server
/// advertising an unroutable base (Conduit's default) otherwise burns the full
/// connect budget before we fall back.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Slack added on top of the server-side long-poll window for `/sync`.
const SYNC_SLACK: Duration = Duration::from_secs(60);

/// Body ceiling. We stream and never retain the bytes, so this exists purely as
/// a runaway guard; ureq's convenience readers would otherwise cap us at 10 MiB
/// and silently error out on a fat initial sync.
const MAX_BODY: u64 = 64 * 1024 * 1024;

/// Error bodies are read in full (they are tiny) but reported truncated.
const ERR_BODY_READ: u64 = 64 * 1024;
const ERR_BODY_CHARS: usize = 512;

// --------------------------------------------------------------------- types

pub struct Api {
    agent: Agent,
    base: String,
    token: Option<String>,
    /// Device clock minus real time, in milliseconds, as last observed from a
    /// response `Date` header.
    ///
    /// E-readers routinely have no RTC battery and no NTP, and this Kindle in
    /// particular keeps local time in a clock labelled UTC — its own UI looks
    /// right only because that error cancels against a `GMT` timezone setting.
    /// Rendering honest UTC timestamps there looks two hours stale. Measuring
    /// the offset lets the UI display times in the same frame the user sees
    /// everywhere else, and collapses to zero on a correctly set device.
    clock_skew_ms: std::sync::atomic::AtomicI64,
}

#[derive(Deserialize)]
struct WellKnown {
    #[serde(rename = "m.homeserver")]
    homeserver: Option<WellKnownBase>,
}

#[derive(Deserialize)]
struct WellKnownBase {
    base_url: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    user_id: String,
    device_id: String,
    access_token: String,
}

#[derive(Deserialize)]
struct EventIdResponse {
    event_id: String,
}

/// Only the member ids are wanted; `IgnoredAny` skips each member's profile
/// object without allocating it.
#[derive(Deserialize)]
struct JoinedMembersResponse {
    #[serde(default)]
    joined: BTreeMap<String, IgnoredAny>,
}

/// Same endpoint as `JoinedMembersResponse`, but keeping display names.
#[derive(Deserialize)]
struct MemberNamesResponse {
    #[serde(default)]
    joined: BTreeMap<String, MemberName>,
}

#[derive(Deserialize)]
struct MemberName {
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct DisplayNameResponse {
    #[serde(default)]
    displayname: Option<String>,
}

#[derive(Deserialize)]
struct RoomNameResponse {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct MatrixError {
    errcode: Option<String>,
    error: Option<String>,
}

/// The account's current room-key backup.
pub struct BackupInfo {
    pub version: String,
    pub algorithm: String,
    pub public_key: String,
}

#[derive(Deserialize)]
struct BackupVersionResponse {
    version: String,
    algorithm: String,
    auth_data: BackupAuthData,
}

/// `auth_data` is algorithm-specific; for
/// `m.megolm_backup.v1.curve25519-aes-sha2` the field we need is the public
/// half of the backup key, which the recovery key must reproduce.
#[derive(Deserialize)]
struct BackupAuthData {
    public_key: String,
}

/// A page of room history from `/messages`.
#[derive(Deserialize)]
pub struct Page {
    /// Events, newest first when paging backwards.
    #[serde(default)]
    pub chunk: Vec<RoomEvent>,
    /// Token for the next page further back. Absent at the start of the room.
    #[serde(default)]
    pub end: Option<String>,
}

/// Same shape as the sync filter's room section: skip bulk membership, which
/// is the bulk of a backfill page and which we never render.
const MESSAGES_FILTER: &str = r#"{"lazy_load_members":true}"#;

// ---------------------------------------------------------------------- impl

impl Api {
    pub fn new(homeserver: &str) -> Result<Api> {
        let base = normalize_base(homeserver)?;
        let agent = build_agent();
        let base = discover(&agent, &base).unwrap_or(base);
        Ok(Api {
            agent,
            base,
            token: None,
            clock_skew_ms: std::sync::atomic::AtomicI64::new(0),
        })
    }

    pub fn set_auth(&mut self, access_token: &str) {
        self.token = Some(access_token.to_owned());
    }

    pub fn homeserver(&self) -> &str {
        &self.base
    }

    pub fn login(&mut self, user: &str, password: &str) -> Result<Session> {
        let body = json!({
            "type": "m.login.password",
            "identifier": { "type": "m.id.user", "user": user },
            "password": password,
            "initial_device_display_name": "kmatrix",
        });
        // Name the base we actually dialled. Discovery may have redirected us,
        // and a mistyped homeserver surfaces here as an opaque TLS or DNS
        // error -- on a device with a LAN search domain, a bare `matrix`
        // silently becomes `matrix.<search-domain>`, and "certificate not
        // valid" is not an obvious way to be told you dropped a dot.
        let res = self
            .post(&self.url("/_matrix/client/v3/login"))?
            .content_type("application/json")
            .send(serde_json::to_string(&body)?)
            .with_context(|| format!("connecting to homeserver {}", self.base))?;
        let parsed: LoginResponse = finish(res, "login")?;

        self.set_auth(&parsed.access_token);
        Ok(Session {
            homeserver: self.base.clone(),
            user_id: parsed.user_id,
            device_id: parsed.device_id,
            access_token: parsed.access_token,
        })
    }

    pub fn logout(&self) -> Result<()> {
        let res = self
            .post_auth(&self.url("/_matrix/client/v3/logout"))?
            .content_type("application/json")
            .send("{}")?;
        discard(res, "logout")
    }

    /// Joined members of one room with their display names, for naming rooms
    /// that have neither a name nor a canonical alias.
    ///
    /// The documented route is `m.heroes` from `/sync`, but the server only
    /// sends a summary when it changes, so rooms stored before the client
    /// understood heroes would keep their ids forever — and re-running an
    /// initial sync to collect them is not available: over a large account it
    /// takes long enough that a reverse proxy answers 504, with or without a
    /// room filter. One small call per affected room is what is left.
    ///
    /// Unlike `joined_members`, this keeps the names, so it costs a string
    /// per member. Only rooms that need naming are ever asked.
    pub fn member_names(&self, room: &str) -> Result<BTreeMap<String, Option<String>>> {
        let url = self.url(&format!(
            "/_matrix/client/v3/rooms/{}/joined_members",
            encode_segment(room)
        ));
        let parsed: MemberNamesResponse = finish(self.get_auth(&url)?.call()?, "member names")?;
        Ok(parsed
            .joined
            .into_iter()
            .map(|(user_id, m)| (user_id, m.display_name))
            .collect())
    }

    /// The account's `m.direct`: which user each direct-message room is with.
    ///
    /// Needed because a bridged DM cannot be named from its member list. A
    /// Signal portal holds the contact's ghost, *our own* ghost — a different
    /// user id from ours, so it survives every "not me" filter — and the
    /// bridge bot, which is how a private chat ends up displayed as
    /// "me, them, Signal Bridge Bot". `m.direct` names the counterpart
    /// outright. An account that has never had a DM answers 404, which is
    /// an empty map rather than an error.
    pub fn direct_rooms(&self, user_id: &str) -> Result<BTreeMap<String, Vec<String>>> {
        let url = self.url(&format!(
            "/_matrix/client/v3/user/{}/account_data/m.direct",
            encode_segment(user_id)
        ));
        let res = self.get_auth(&url)?.call()?;
        if res.status().as_u16() == 404 {
            return Ok(BTreeMap::new());
        }
        finish(res, "m.direct")
    }

    /// One user's display name, globally rather than per room.
    ///
    /// Used for the handful of senders visible in a room whose name we never
    /// learned. The per-room answer would be `joined_members`, but that pulls
    /// the entire membership — tens of thousands of names for a large public
    /// room, to identify the four people on screen. A profile lookup is a few
    /// bytes. Users without a display name answer 404.
    pub fn profile_name(&self, user_id: &str) -> Result<Option<String>> {
        let url = self.url(&format!(
            "/_matrix/client/v3/profile/{}/displayname",
            encode_segment(user_id)
        ));
        let res = self.get_auth(&url)?.call()?;
        if res.status().as_u16() == 404 {
            return Ok(None);
        }
        let parsed: DisplayNameResponse = finish(res, "profile displayname")?;
        Ok(parsed.displayname.filter(|n| !n.is_empty()))
    }

    /// The room's own `m.room.name`, if it has one.
    ///
    /// Asked for a direct chat before naming it after the person, because a
    /// name the room carries outranks one we compute. Checking is cheaper and
    /// surer than trying to recognise, from the stored string alone, whether
    /// an earlier pass took it from the server or built it from the members.
    /// A room without a name answers 404.
    pub fn room_name(&self, room: &str) -> Result<Option<String>> {
        let url = self.url(&format!(
            "/_matrix/client/v3/rooms/{}/state/m.room.name",
            encode_segment(room)
        ));
        let res = self.get_auth(&url)?.call()?;
        if res.status().as_u16() == 404 {
            return Ok(None);
        }
        let parsed: RoomNameResponse = finish(res, "room name")?;
        Ok(parsed.name.filter(|n| !n.is_empty()))
    }

    /// One event by id, as the server still holds it.
    ///
    /// Used to recover the ciphertext of a message stored before the client
    /// kept any. Paging the room's recent history is cheaper per event but
    /// only reaches as far back as its window, and the messages that need
    /// this are the oldest ones — the ones a window never reaches.
    pub fn event(&self, room: &str, event_id: &str) -> Result<RoomEvent> {
        let url = self.url(&format!(
            "/_matrix/client/v3/rooms/{}/event/{}",
            encode_segment(room),
            encode_segment(event_id)
        ));
        finish(self.get_auth(&url)?.call()?, "event")
    }

    /// Long-poll `/sync`.
    ///
    /// The response is deserialized directly from the socket. Do NOT replace
    /// this with `read_to_string()` / `read_json()` / a `serde_json::Value`:
    /// buffering the body is a measured 369x peak-heap regression and defeats
    /// the entire design of this daemon.
    pub fn sync(&self, since: Option<&str>, timeout_ms: u32) -> Result<SyncResponse> {
        // A single agent-wide timeout cannot cover both a 5 s /messages call
        // and a 30 s long-poll, so the sync call overrides `timeout_per_call`
        // with the server's poll window plus slack.
        let budget = Duration::from_millis(u64::from(timeout_ms)) + SYNC_SLACK;
        let mut req = self
            .get_auth(&self.url("/_matrix/client/v3/sync"))?
            .config()
            .timeout_per_call(Some(budget))
            .build()
            .query("filter", SYNC_FILTER)
            .query("timeout", timeout_ms.to_string());
        if let Some(since) = since {
            req = req.query("since", since);
        }
        let res = req.call()?;
        self.note_server_time(&res);
        finish(res, "sync")
    }

    /// Milliseconds the device clock runs ahead of real time (negative if
    /// behind). Zero until a response has been seen.
    pub fn clock_skew_ms(&self) -> i64 {
        self.clock_skew_ms
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn note_server_time(&self, res: &Response<Body>) {
        let Some(date) = res.headers().get("date").and_then(|v| v.to_str().ok()) else {
            return;
        };
        let Some(server_ms) = parse_http_date_ms(date) else {
            return;
        };
        let skew = crate::model::now_ms() as i64 - server_ms;
        self.clock_skew_ms
            .store(skew, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn send_event(
        &self,
        room: &str,
        kind: &str,
        txn: &str,
        content: &serde_json::Value,
    ) -> Result<String> {
        let url = self.url(&format!(
            "/_matrix/client/v3/rooms/{}/send/{}/{}",
            encode_segment(room),
            encode_segment(kind),
            encode_segment(txn)
        ));
        let res = self
            .put_auth(&url)?
            .content_type("application/json")
            .send(serde_json::to_string(content)?)?;
        let parsed: EventIdResponse = finish(res, "send_event")?;
        Ok(parsed.event_id)
    }

    pub fn keys_upload(&self, body: &serde_json::Value) -> Result<()> {
        let res = self
            .post_auth(&self.url("/_matrix/client/v3/keys/upload"))?
            .content_type("application/json")
            .send(serde_json::to_string(body)?)?;
        discard(res, "keys_upload")
    }

    pub fn keys_query(&self, users: &[String]) -> Result<serde_json::Value> {
        let mut device_keys = serde_json::Map::with_capacity(users.len());
        for u in users {
            device_keys.insert(u.clone(), serde_json::Value::Array(Vec::new()));
        }
        let body = json!({ "device_keys": serde_json::Value::Object(device_keys) });
        let res = self
            .post_auth(&self.url("/_matrix/client/v3/keys/query"))?
            .content_type("application/json")
            .send(serde_json::to_string(&body)?)?;
        finish(res, "keys_query")
    }

    pub fn keys_claim(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        let res = self
            .post_auth(&self.url("/_matrix/client/v3/keys/claim"))?
            .content_type("application/json")
            .send(serde_json::to_string(body)?)?;
        finish(res, "keys_claim")
    }

    pub fn send_to_device(
        &self,
        kind: &str,
        txn: &str,
        messages: &serde_json::Value,
    ) -> Result<()> {
        let url = self.url(&format!(
            "/_matrix/client/v3/sendToDevice/{}/{}",
            encode_segment(kind),
            encode_segment(txn)
        ));
        let body = json!({ "messages": messages });
        let res = self
            .put_auth(&url)?
            .content_type("application/json")
            .send(serde_json::to_string(&body)?)?;
        discard(res, "send_to_device")
    }

    pub fn joined_members(&self, room: &str) -> Result<Vec<String>> {
        let url = self.url(&format!(
            "/_matrix/client/v3/rooms/{}/joined_members",
            encode_segment(room)
        ));
        let res = self.get_auth(&url)?.call()?;
        let parsed: JoinedMembersResponse = finish(res, "joined_members")?;
        Ok(parsed.joined.into_keys().collect())
    }

    pub fn read_receipt(&self, room: &str, event_id: &str) -> Result<()> {
        let url = self.url(&format!(
            "/_matrix/client/v3/rooms/{}/receipt/m.read/{}",
            encode_segment(room),
            encode_segment(event_id)
        ));
        let res = self
            .post_auth(&url)?
            .content_type("application/json")
            .send("{}")?;
        discard(res, "read_receipt")
    }

    /// Current server-side room-key backup, if the account has one.
    /// A 404 (`M_NOT_FOUND`) means no backup exists and is not an error.
    pub fn backup_version(&self) -> Result<Option<BackupInfo>> {
        let url = self.url("/_matrix/client/v3/room_keys/version");
        let res = self.get_auth(&url)?.call()?;
        if res.status().as_u16() == 404 {
            return Ok(None);
        }
        let parsed: BackupVersionResponse = finish(res, "backup_version")?;
        Ok(Some(BackupInfo {
            version: parsed.version,
            algorithm: parsed.algorithm,
            public_key: parsed.auth_data.public_key,
        }))
    }

    /// One session out of the backup. Deliberately per-session rather than a
    /// bulk `GET /room_keys/keys`: this account's backup holds 51k sessions,
    /// and importing them all would cost tens of MB of RAM and rows on a
    /// device with 474 MB total. A 404 means the backup has no such session.
    pub fn backup_session(
        &self,
        version: &str,
        room: &str,
        session_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        let url = self.url(&format!(
            "/_matrix/client/v3/room_keys/keys/{}/{}?version={}",
            encode_segment(room),
            encode_segment(session_id),
            encode_segment(version)
        ));
        let res = self.get_auth(&url)?.call()?;
        if res.status().as_u16() == 404 {
            return Ok(None);
        }
        let parsed: serde_json::Value = finish(res, "backup_session")?;
        Ok(Some(parsed))
    }

    /// Page backwards through a room's history.
    ///
    /// `/sync` only moves forward and hands us a fixed window, so this is the
    /// only way to see anything older — and the only way to recover the
    /// ciphertext of encrypted events stored as placeholders before we began
    /// retaining it.
    ///
    /// `from` is optional since Matrix v1.3: without it the server starts at
    /// the most recent visible event. That matters here, because a room only
    /// gets a `prev_batch` when it appears in a sync batch, so rooms that have
    /// been quiet since we logged in would otherwise have no way in.
    pub fn messages(&self, room: &str, from: Option<&str>, limit: u32) -> Result<Page> {
        let url = self.url(&format!(
            "/_matrix/client/v3/rooms/{}/messages",
            encode_segment(room)
        ));
        let mut req = self
            .get_auth(&url)?
            .query("dir", "b")
            .query("limit", limit.to_string())
            .query("filter", MESSAGES_FILTER);
        if let Some(from) = from {
            req = req.query("from", from);
        }
        finish(req.call()?, "messages")
    }

    // ------------------------------------------------------------- internals

    fn url(&self, path: &str) -> String {
        let mut s = String::with_capacity(self.base.len() + path.len());
        s.push_str(&self.base);
        s.push_str(path);
        s
    }

    fn bearer(&self) -> Result<&str> {
        self.token
            .as_deref()
            .ok_or_else(|| anyhow!("not authenticated: no access token"))
    }

    fn get(&self, url: &str) -> RequestBuilder<WithoutBody> {
        self.agent.get(url)
    }

    fn post(&self, url: &str) -> Result<RequestBuilder<WithBody>> {
        Ok(self.agent.post(url))
    }

    fn get_auth(&self, url: &str) -> Result<RequestBuilder<WithoutBody>> {
        Ok(self
            .get(url)
            .header("authorization", bearer(self.bearer()?)))
    }

    fn post_auth(&self, url: &str) -> Result<RequestBuilder<WithBody>> {
        Ok(self
            .agent
            .post(url)
            .header("authorization", bearer(self.bearer()?)))
    }

    fn put_auth(&self, url: &str) -> Result<RequestBuilder<WithBody>> {
        Ok(self
            .agent
            .put(url)
            .header("authorization", bearer(self.bearer()?)))
    }
}

// ------------------------------------------------------------------ helpers

fn bearer(token: &str) -> String {
    let mut s = String::with_capacity(7 + token.len());
    s.push_str("Bearer ");
    s.push_str(token);
    s
}

fn build_agent() -> Agent {
    let config = Agent::config_builder()
        // We surface Matrix's `errcode`/`error` ourselves, which requires
        // reading the body of a non-2xx response instead of letting ureq
        // collapse it into a bare `Error::StatusCode`.
        .http_status_as_error(false)
        // A *global* timeout would abort /sync long-polls, so leave it unset
        // and bound each call individually; /sync overrides this per request.
        .timeout_global(None)
        .timeout_per_call(Some(CALL_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .user_agent(CLIENT_VERSION)
        .build();
    Agent::new_with_config(config)
}

/// Normalize `example.org`, `https://example.org`, `example.org/`,
/// `https://example.org/` -> `https://example.org`.
fn normalize_base(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty homeserver"));
    }
    let has_scheme = {
        let lower = trimmed.to_ascii_lowercase();
        lower.starts_with("https://") || lower.starts_with("http://")
    };
    let mut base = if has_scheme {
        trimmed.to_owned()
    } else {
        let mut s = String::with_capacity(8 + trimmed.len());
        s.push_str("https://");
        s.push_str(trimmed);
        s
    };
    while base.ends_with('/') {
        base.pop();
    }
    // Guard against input that was nothing but a scheme and slashes.
    let authority = base
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    if authority.is_empty() {
        return Err(anyhow!("invalid homeserver: {input}"));
    }
    Ok(base)
}

/// `.well-known/matrix/client` discovery. Absent or broken discovery is normal
/// (most homeservers are their own delegation target), so every failure path
/// simply yields `None` and the caller keeps the user-supplied base.
///
/// The discovered base is VALIDATED before it is adopted, as the spec requires
/// ("Well-known URI", step 6: GET `base_url/_matrix/client/versions`; anything
/// other than 200 is a discovery failure). Skipping this is not academic —
/// Conduit advertises `https://<server_name>` by default, so a homeserver
/// reachable on `http://host:6167` would otherwise send us to a dead port 443.
///
/// Both requests are bounded by `DISCOVERY_TIMEOUT` rather than the normal
/// per-call timeout. Discovery is best-effort, but a homeserver that
/// advertises an unroutable base (Conduit's default `https://<server_name>`)
/// makes the validation probe hang until it times out, and on a device that
/// turns "log in" into a minute of nothing. Fail fast and keep the base the
/// user typed.
fn discover(agent: &Agent, base: &str) -> Option<String> {
    let get = |url: String| {
        agent
            .get(url)
            .config()
            .timeout_per_call(Some(DISCOVERY_TIMEOUT))
            .timeout_connect(Some(DISCOVERY_TIMEOUT))
            .build()
            .call()
            .ok()
    };

    let mut res = get(format!("{base}/.well-known/matrix/client"))?;
    if res.status().as_u16() != 200 {
        return None;
    }
    let rdr = res.body_mut().with_config().limit(ERR_BODY_READ).reader();
    let wk: WellKnown = serde_json::from_reader(rdr).ok()?;
    let candidate = normalize_base(&wk.homeserver?.base_url).ok()?;
    if candidate == base {
        return None;
    }
    let probe = get(format!("{candidate}/_matrix/client/versions"))?;
    if probe.status().as_u16() == 200 {
        Some(candidate)
    } else {
        None
    }
}

/// Check the status, then stream-deserialize the body into `T`.
///
/// `serde_json::from_reader` pulls straight off the socket; the body is never
/// held in memory as a whole. This is the only body-reading path for success
/// responses in this module.
fn finish<T: DeserializeOwned>(mut res: Response<Body>, what: &str) -> Result<T> {
    check_status(&mut res, what)?;
    let rdr = res.body_mut().with_config().limit(MAX_BODY).reader();
    serde_json::from_reader(rdr).with_context(|| format!("{what}: malformed response body"))
}

/// Parse an RFC 7231 IMF-fixdate — `Sun, 06 Nov 1994 08:49:37 GMT` — into
/// milliseconds since the epoch. This is the only date format a server is
/// required to emit, and hand-parsing it avoids pulling in a date crate for
/// one header.
fn parse_http_date_ms(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    let rest = s.split_once(", ")?.1;
    let mut parts = rest.split(' ');
    let day: i64 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let year: i64 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let month = MONTHS.iter().position(|m| *m == month_name)? as i64 + 1;

    let mut hms = time.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let min: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next()?.parse().ok()?;

    // Days from civil epoch (Howard Hinnant's algorithm), valid for any date.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Some(((days * 86_400 + hour * 3_600 + min * 60 + sec) * 1000) as i64)
}

/// Check the status of a response whose body carries nothing we need.
fn discard(mut res: Response<Body>, what: &str) -> Result<()> {
    check_status(&mut res, what)
}

fn check_status(res: &mut Response<Body>, what: &str) -> Result<()> {
    let status = res.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(());
    }
    Err(anyhow!("{what}: HTTP {status} {}", error_detail(res)))
}

/// Render Matrix's error envelope, falling back to a truncated raw body.
fn error_detail(res: &mut Response<Body>) -> String {
    let raw = res
        .body_mut()
        .with_config()
        .limit(ERR_BODY_READ)
        .lossy_utf8(true)
        .read_to_string()
        .unwrap_or_default();

    if let Ok(m) = serde_json::from_str::<MatrixError>(&raw) {
        match (m.errcode, m.error) {
            (Some(code), Some(msg)) => return truncate(&format!("{code}: {msg}"), ERR_BODY_CHARS),
            (Some(code), None) => return code,
            (None, Some(msg)) => return truncate(&msg, ERR_BODY_CHARS),
            (None, None) => {}
        }
    }
    if raw.trim().is_empty() {
        "(empty body)".to_owned()
    } else {
        truncate(&raw, ERR_BODY_CHARS)
    }
}

fn truncate(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        None => s.to_owned(),
        Some((idx, _)) => {
            let mut out = String::with_capacity(idx + 3);
            out.push_str(&s[..idx]);
            out.push_str("...");
            out
        }
    }
}

/// Percent-encode one URL path segment: everything outside the unreserved set
/// `A-Za-z0-9-._~` is escaped. Room ids (`!abc:example.org`) and event ids
/// (`$abc`) both need this.
fn encode_segment(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

// -------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::{encode_segment, normalize_base, parse_http_date_ms, truncate};

    #[test]
    fn normalizes_all_input_forms() {
        for input in [
            "example.org",
            "example.org/",
            "https://example.org",
            "https://example.org/",
        ] {
            let got = normalize_base(input).expect("valid homeserver");
            assert_eq!(got, "https://example.org", "input {input}");
        }
    }

    #[test]
    fn normalize_keeps_explicit_http_and_port_and_path() {
        assert_eq!(
            normalize_base("http://10.0.0.5:8008/").expect("valid"),
            "http://10.0.0.5:8008"
        );
        assert_eq!(
            normalize_base("  matrix.example.org:8448  ").expect("valid"),
            "https://matrix.example.org:8448"
        );
        assert_eq!(
            normalize_base("https://example.org/_sub//").expect("valid"),
            "https://example.org/_sub"
        );
    }

    #[test]
    fn normalize_rejects_empty_authority() {
        assert!(normalize_base("").is_err());
        assert!(normalize_base("   ").is_err());
        assert!(normalize_base("https://").is_err());
        assert!(normalize_base("https:///").is_err());
    }

    #[test]
    fn encodes_room_id() {
        assert_eq!(encode_segment("!abc:example.org"), "%21abc%3Aexample.org");
    }

    #[test]
    fn encodes_event_id_and_leaves_unreserved_alone() {
        assert_eq!(encode_segment("$aBc-1._~"), "%24aBc-1._~");
        assert_eq!(encode_segment("m.room.message"), "m.room.message");
        // Slashes must not survive: they would forge a new path segment.
        assert_eq!(encode_segment("a/b"), "a%2Fb");
        // Multi-byte UTF-8 is escaped per byte.
        assert_eq!(encode_segment("é"), "%C3%A9");
    }

    /// The device this was written for reports a clock two hours ahead of
    /// real time, so getting this parse right is what keeps chat timestamps
    /// agreeing with everything else on screen.
    #[test]
    fn parses_imf_fixdate() {
        // Canonical example from RFC 7231.
        assert_eq!(
            parse_http_date_ms("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777_000)
        );
        // The Unix epoch itself.
        assert_eq!(parse_http_date_ms("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        // A leap day, to exercise the civil-days arithmetic.
        assert_eq!(
            parse_http_date_ms("Mon, 29 Feb 2016 12:00:00 GMT"),
            Some(1_456_747_200_000)
        );
        assert_eq!(parse_http_date_ms("not a date"), None);
        assert_eq!(parse_http_date_ms("Sun, 06 Xxx 1994 08:49:37 GMT"), None);
    }

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate("abcdef", 3), "abc...");
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(truncate("ééé", 2), "éé...");
    }
}
