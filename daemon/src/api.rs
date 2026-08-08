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

use crate::model::{Session, SyncResponse, CLIENT_VERSION, SYNC_FILTER};

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

#[derive(Deserialize)]
struct MatrixError {
    errcode: Option<String>,
    error: Option<String>,
}

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
        // error -- on a device with a LAN search domain, `lassulus` silently
        // becomes `lassulus.<search-domain>`, and "certificate not valid" is
        // not an obvious way to be told you dropped a dot.
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
        finish(req.call()?, "sync")
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
    use super::{encode_segment, normalize_base, truncate};

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

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate("abcdef", 3), "abc...");
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(truncate("ééé", 2), "éé...");
    }
}
