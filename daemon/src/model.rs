//! Shared types. This is the contract every module codes against.
//!
//! The `sync` types deliberately name only the fields the client uses: serde
//! walks past everything else without allocating, which is what keeps peak heap
//! independent of account size. Do not add a `serde_json::Value` catch-all to
//! the room-event path — that is precisely the 369x regression.

use serde::{Deserialize, Serialize};

pub const CLIENT_VERSION: &str = "kmatrix 0.1.0";

/// Sync filter. Bounds the payload at the request so streaming never has to
/// work hard: no presence, no account data, no ephemeral, lazy members.
pub const SYNC_FILTER: &str = concat!(
    r#"{"presence":{"not_types":["*"]},"#,
    r#""account_data":{"not_types":["*"]},"#,
    r#""room":{"account_data":{"not_types":["*"]},"#,
    r#""ephemeral":{"not_types":["*"]},"#,
    r#""state":{"lazy_load_members":true},"#,
    r#""timeline":{"limit":30,"lazy_load_members":true}}}"#
);

// ---------------------------------------------------------------- persisted

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub homeserver: String,
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Room {
    pub id: String,
    pub name: String,
    pub encrypted: bool,
    pub unread: u32,
    pub last_ts: u64,
    pub last_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub event_id: String,
    pub room: String,
    pub sender: String,
    pub ts: u64,
    pub body: String,
    pub encrypted: bool,
    pub decrypted: bool,
    pub mine: bool,
    /// Kept only for `m.room.encrypted` events we could not decrypt, so a
    /// room key recovered later (from the server-side backup) can turn the
    /// placeholder into the real message without refetching from the server.
    /// Cleared once decrypted. Not part of the IPC surface.
    #[serde(skip)]
    pub session_id: Option<String>,
    #[serde(skip)]
    pub ciphertext: Option<String>,
}

// --------------------------------------------------------------------- IPC

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    LoggedOut,
    Connecting,
    Syncing,
    Offline,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::LoggedOut => "logged_out",
            State::Connecting => "connecting",
            State::Syncing => "syncing",
            State::Offline => "offline",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub id: u64,
    #[serde(flatten)]
    pub cmd: Request,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Hello {
        token: String,
    },
    Status,
    Login {
        homeserver: String,
        user: String,
        password: String,
    },
    Logout,
    Rooms,
    Messages {
        room: String,
        #[serde(default = "default_limit")]
        limit: u32,
    },
    Send {
        room: String,
        body: String,
    },
    MarkRead {
        room: String,
        event_id: String,
    },
    SyncNow,
    /// Supply the server-side key-backup recovery key ("Security Key"), so
    /// history predating this device can be decrypted on demand.
    BackupKey {
        key: String,
    },
    /// Answer to the emoji comparison shown during device verification.
    VerifyConfirm {
        transaction: String,
        confirm: bool,
    },
    Shutdown,
}

fn default_limit() -> u32 {
    50
}

// ------------------------------------------------------------ sync payload

#[derive(Debug, Deserialize, Default)]
pub struct SyncResponse {
    pub next_batch: String,
    #[serde(default)]
    pub rooms: SyncRooms,
    #[serde(default)]
    pub to_device: ToDevice,
    #[serde(default)]
    pub device_one_time_keys_count: OtkCount,
    #[serde(default)]
    pub device_lists: DeviceLists,
}

#[derive(Debug, Deserialize, Default)]
pub struct SyncRooms {
    #[serde(default)]
    pub join: std::collections::HashMap<String, JoinedRoom>,
    #[serde(default)]
    pub leave: std::collections::HashMap<String, serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize, Default)]
pub struct JoinedRoom {
    #[serde(default)]
    pub timeline: Timeline,
    #[serde(default)]
    pub state: StateBlock,
    #[serde(default)]
    pub unread_notifications: UnreadNotifications,
}

#[derive(Debug, Deserialize, Default)]
pub struct Timeline {
    #[serde(default)]
    pub events: Vec<RoomEvent>,
    #[serde(default)]
    pub prev_batch: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct StateBlock {
    #[serde(default)]
    pub events: Vec<RoomEvent>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UnreadNotifications {
    #[serde(default)]
    pub notification_count: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct OtkCount {
    #[serde(default)]
    pub signed_curve25519: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct DeviceLists {
    #[serde(default)]
    pub changed: Vec<String>,
    #[serde(default)]
    pub left: Vec<String>,
}

/// A room event, state or timeline.
#[derive(Debug, Deserialize, Default)]
pub struct RoomEvent {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub origin_server_ts: u64,
    #[serde(default)]
    pub state_key: Option<String>,
    #[serde(default)]
    pub content: EventContent,
}

/// Union of every content field we consume, across all event types. Anything
/// not named here (`displayname`, `avatar_url`, ...) is skipped without
/// allocating. This is the memory-critical type.
#[derive(Debug, Deserialize, Default)]
pub struct EventContent {
    // m.room.message
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub msgtype: Option<String>,
    // m.room.name / m.room.canonical_alias
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    // m.room.encryption / m.room.encrypted
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub ciphertext: Option<String>,
    #[serde(default)]
    pub sender_key: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    // m.room.member (membership only; display name and avatar are skipped)
    #[serde(default)]
    pub membership: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ToDevice {
    #[serde(default)]
    pub events: Vec<ToDeviceEvent>,
}

/// To-device events are few per sync (one per key share), so an untyped
/// content is acceptable here — the Olm `ciphertext` map is irregular.
#[derive(Debug, Deserialize)]
pub struct ToDeviceEvent {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub content: serde_json::Value,
}

// ------------------------------------------------------------------ helpers

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Collapse a message body to a single line for the room-list preview.
pub fn preview(body: &str, max: usize) -> String {
    let flat: String = body
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        flat
    } else {
        let mut s: String = flat.chars().take(max.saturating_sub(1)).collect();
        s.push('\u{2026}');
        s
    }
}
