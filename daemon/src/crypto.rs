//! End-to-end encryption: Olm (1:1 key transport) and Megolm (room messages).
//!
//! Every piece of long-lived cryptographic state lives in the SQLite `pickle`
//! table, encrypted with a per-device random pickle key kept in `meta`. The
//! four pickle kinds are:
//!
//! | kind         | id                | extra                |
//! |--------------|-------------------|----------------------|
//! | `account`    | `self`            | (empty)              |
//! | `olm`        | olm session id    | sender curve25519    |
//! | `megolm_in`  | megolm session id | room id              |
//! | `megolm_out` | room id           | message index        |
//!
//! The server-side key backup's private key is not a pickle: it lives in
//! `meta` under `backup_key`, base64-encoded, next to the pickle key.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use serde_json::{Map, Value};
use vodozemac::{
    megolm::{
        ExportedSessionKey, GroupSession, GroupSessionPickle, InboundGroupSession,
        InboundGroupSessionPickle, MegolmMessage, SessionConfig as MegolmConfig, SessionKey,
    },
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig as OlmConfig, SessionPickle},
    pk_encryption::{Message as PkMessage, PkDecryption},
    sas::{EstablishedSas, Mac, Sas},
    Curve25519PublicKey, Curve25519SecretKey,
};

use crate::model::ToDeviceEvent;
use crate::store::Store;

pub const OLM_ALGORITHM: &str = "m.olm.v1.curve25519-aes-sha2";
pub const MEGOLM_ALGORITHM: &str = "m.megolm.v1.aes-sha2";

/// How many one-time keys we try to keep published on the server.
const OTK_TARGET: usize = 50;

const KIND_ACCOUNT: &str = "account";
const KIND_OLM: &str = "olm";
const KIND_MEGOLM_IN: &str = "megolm_in";
const KIND_MEGOLM_OUT: &str = "megolm_out";
const PICKLE_KEY_META: &str = "pickle_key";
const BACKUP_KEY_META: &str = "backup_key";

/// Bitcoin's base58 alphabet, which the Matrix recovery key encoding uses.
/// `0`, `O`, `I` and `l` are absent so they cannot be confused for each other.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The two bytes every recovery key starts with.
const RECOVERY_KEY_PREFIX: [u8; 2] = [0x8b, 0x01];

/// Prefix (2) + Curve25519 private key (32) + parity byte (1).
const RECOVERY_KEY_LEN: usize = 35;

/// The only verification method we implement, and the only one Element needs
/// for self-verification.
const SAS_METHOD: &str = "m.sas.v1";

/// The algorithms we insist on. `hkdf-hmac-sha256.v2` is deliberate: version 1
/// inherited libolm's base64 bug, where the MAC was encoded out of a buffer
/// that the encoder had already overwritten.
const KEY_AGREEMENT_PROTOCOL: &str = "curve25519-hkdf-sha256";
const SAS_HASH: &str = "sha256";
const MAC_METHOD: &str = "hkdf-hmac-sha256.v2";
const SAS_EMOJI_STRING: &str = "emoji";

/// A verification the user never answers must not sit in memory forever, and
/// the other side will have given up long before this too.
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(600);

/// The secret we ask our other devices for once SAS has made them trust us.
pub const MEGOLM_BACKUP_SECRET: &str = "m.megolm_backup.v1";

/// One remote device, as far as we need to know it to send it a room key.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub user_id: String,
    pub device_id: String,
    pub curve_key: String,
    pub ed_key: String,
}

/// What the daemon must do next after feeding an event into the verification
/// state machine. Everything is optional: most events only produce a reply.
#[derive(Default)]
pub struct VerifyStep {
    /// Plaintext to-device events to send: (event type, target device id,
    /// content). The target is always a device of the user who sent us the
    /// event that produced this step.
    pub send: Vec<(String, String, Value)>,
    /// Show these emoji and wait for [`Crypto::confirm_verification`].
    /// (transaction id, their device id, seven six-bit emoji indices)
    pub emoji: Option<(String, String, [u8; 7])>,
    /// Verification completed with this device id.
    pub done: Option<String>,
    /// Verification ended early; human-readable reason.
    pub cancelled: Option<String>,
}

/// Something an Olm-encrypted to-device event asked us to act on beyond the
/// Megolm key transport, which [`Crypto`] handles internally.
pub enum ToDeviceOutcome {
    /// A secret we asked for arrived, already Olm-decrypted.
    Secret {
        name: String,
        secret: String,
        request_id: String,
    },
}

/// One in-flight SAS verification, keyed by its transaction id.
///
/// We are always the responder: the other side sends `start`, we `accept`, and
/// the commitment we put in that accept binds our ephemeral key to their exact
/// start content, so `start` is kept verbatim rather than re-serialised.
struct Verification {
    their_user: String,
    their_device: String,
    created: Instant,
    /// Our ephemeral key. The Diffie-Hellman consumes it by value, so it is
    /// `None` before the start arrives and again once the exchange is done.
    sas: Option<Sas>,
    /// Our ephemeral public key, base64. Outlives `sas`.
    our_public_key: Option<String>,
    /// Their `m.key.verification.start` content, verbatim.
    start: Option<Value>,
    their_public_key: Option<String>,
    established: Option<EstablishedSas>,
    we_sent_mac: bool,
    they_sent_mac: bool,
    we_sent_done: bool,
    they_sent_done: bool,
}

impl Verification {
    fn new(their_user: &str, their_device: &str) -> Verification {
        Verification {
            their_user: their_user.to_string(),
            their_device: their_device.to_string(),
            created: Instant::now(),
            sas: None,
            our_public_key: None,
            start: None,
            their_public_key: None,
            established: None,
            we_sent_mac: false,
            they_sent_mac: false,
            we_sent_done: false,
            they_sent_done: false,
        }
    }

    /// Both sides have MAC'd their keys and both have said `done`.
    fn complete(&self) -> bool {
        self.we_sent_mac && self.they_sent_mac && self.we_sent_done && self.they_sent_done
    }
}

pub struct Crypto {
    account: Account,
    pickle_key: [u8; 32],
    /// megolm session id -> inbound session (receiving)
    inbound: HashMap<String, InboundGroupSession>,
    /// room id -> outbound megolm session (sending)
    outbound: HashMap<String, GroupSession>,
    /// their curve25519 identity key -> olm sessions with that device
    olm_sessions: HashMap<String, Vec<Session>>,
    /// their curve25519 identity key -> (user id, device id). Keyed by curve
    /// key because that is the only identifier an incoming Olm message carries,
    /// which lets us attribute a key share without allocating a lookup key.
    known_devices: HashMap<String, (String, String)>,
    /// The private half of the server-side key backup, once the user has typed
    /// their recovery key. `Some` means we can pull single sessions out of the
    /// backup on demand.
    backup_key: Option<PkDecryption>,
    /// (user id, device id) -> their ed25519 key. Populated from
    /// `/keys/query` via [`Crypto::remember_devices`]; SAS MACs are taken over
    /// these keys, so without an entry a peer's MAC cannot be checked.
    device_ed_keys: HashMap<(String, String), String>,
    /// transaction id -> in-flight SAS verification.
    verifications: HashMap<String, Verification>,
    /// request id -> secret name, for the `m.secret.request`s we sent out.
    secret_requests: HashMap<String, String>,
}

impl Crypto {
    pub fn load_or_create(store: &Store) -> Result<Crypto> {
        let pickle_key = load_pickle_key(store)?;

        let account = match store
            .all_pickles(KIND_ACCOUNT)?
            .into_iter()
            .find(|(id, _, _)| id == "self")
        {
            Some((_, _, pickle)) => Account::from_pickle(
                AccountPickle::from_encrypted(&pickle, &pickle_key)
                    .context("unpickle olm account")?,
            ),
            None => {
                let account = Account::new();
                store.put_pickle(
                    KIND_ACCOUNT,
                    "self",
                    "",
                    &account.pickle().encrypt(&pickle_key),
                )?;
                account
            }
        };

        let mut olm_sessions: HashMap<String, Vec<Session>> = HashMap::new();
        for (id, sender_key, pickle) in store.all_pickles(KIND_OLM)? {
            match SessionPickle::from_encrypted(&pickle, &pickle_key) {
                Ok(p) => olm_sessions
                    .entry(sender_key)
                    .or_default()
                    .push(Session::from_pickle(p)),
                Err(e) => eprintln!("kmatrixd: dropping unreadable olm session {id}: {e}"),
            }
        }

        let mut inbound = HashMap::new();
        for (id, _room, pickle) in store.all_pickles(KIND_MEGOLM_IN)? {
            match InboundGroupSessionPickle::from_encrypted(&pickle, &pickle_key) {
                Ok(p) => {
                    inbound.insert(id, InboundGroupSession::from_pickle(p));
                }
                Err(e) => eprintln!("kmatrixd: dropping unreadable megolm session {id}: {e}"),
            }
        }

        let mut outbound = HashMap::new();
        for (room, _index, pickle) in store.all_pickles(KIND_MEGOLM_OUT)? {
            match GroupSessionPickle::from_encrypted(&pickle, &pickle_key) {
                Ok(p) => {
                    outbound.insert(room, GroupSession::from_pickle(p));
                }
                Err(e) => {
                    eprintln!("kmatrixd: dropping unreadable outbound session for {room}: {e}")
                }
            }
        }

        let known_devices = HashMap::new();

        let backup_key = match store.get_meta(BACKUP_KEY_META)? {
            Some(encoded) => match decode_backup_key(&encoded) {
                Ok(secret) => Some(PkDecryption::from_key(secret)),
                Err(e) => {
                    eprintln!("kmatrixd: ignoring unreadable stored backup key: {e:#}");
                    None
                }
            },
            None => None,
        };

        Ok(Crypto {
            account,
            pickle_key,
            inbound,
            outbound,
            olm_sessions,
            known_devices,
            backup_key,
            device_ed_keys: HashMap::new(),
            verifications: HashMap::new(),
            secret_requests: HashMap::new(),
        })
    }

    pub fn curve25519_key(&self) -> String {
        self.account.curve25519_key().to_base64()
    }

    pub fn ed25519_key(&self) -> String {
        self.account.ed25519_key().to_base64()
    }

    /// Build the `/keys/upload` body: signed device keys (once) plus enough
    /// signed one-time keys to bring the server back up to [`OTK_TARGET`].
    pub fn keys_upload_body(
        &mut self,
        user_id: &str,
        device_id: &str,
        server_otk_count: u32,
        include_device_keys: bool,
    ) -> Result<Option<Value>> {
        let mut body = Map::new();

        if include_device_keys {
            body.insert(
                "device_keys".to_string(),
                self.signed_device_keys(user_id, device_id),
            );
        }

        let wanted = OTK_TARGET
            .saturating_sub(server_otk_count as usize)
            .min(self.account.max_number_of_one_time_keys());
        if wanted > 0 {
            self.account.generate_one_time_keys(wanted);
        }

        let mut unpublished: Vec<_> = self.account.one_time_keys().into_iter().collect();
        // `one_time_keys()` is a HashMap; publish in key-id order so retries
        // produce byte-identical requests.
        unpublished.sort_by_key(|(id, _)| *id);

        if !unpublished.is_empty() {
            let mut keys = Map::new();
            for (key_id, key) in unpublished {
                let mut signed = Map::new();
                signed.insert("key".to_string(), Value::String(key.to_base64()));
                let signature = self
                    .account
                    .sign(canonical_json(&Value::Object(signed.clone())))
                    .to_base64();
                signed.insert(
                    "signatures".to_string(),
                    signatures_for(user_id, device_id, &signature),
                );
                keys.insert(
                    format!("signed_curve25519:{}", key_id.to_base64()),
                    Value::Object(signed),
                );
            }
            body.insert("one_time_keys".to_string(), Value::Object(keys));
        }

        if body.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Value::Object(body)))
        }
    }

    /// Called after `/keys/upload` succeeded: the account must remember that
    /// these one-time keys are on the server so it stops re-uploading them.
    pub fn mark_published(&mut self, store: &Store) -> Result<()> {
        self.account.mark_keys_as_published();
        self.persist_account(store)
    }

    /// Decrypt a Megolm room message. Returns the plaintext event JSON.
    pub fn decrypt(&mut self, session_id: &str, ciphertext: &str) -> Result<String> {
        let session = self
            .inbound
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("unknown session {session_id}"))?;
        let message = MegolmMessage::from_base64(ciphertext).context("decode megolm message")?;
        let decrypted = session.decrypt(&message).context("megolm decrypt")?;
        String::from_utf8(decrypted.plaintext).context("megolm plaintext is not utf-8")
    }

    /// Process incoming to-device events. A single malformed or undecryptable
    /// event must never cost us the rest of the batch.
    ///
    /// Megolm keys are absorbed here; anything the daemon has to act on — a
    /// shared secret, so far — comes back in the returned list.
    pub fn handle_to_device(
        &mut self,
        store: &Store,
        events: &[ToDeviceEvent],
    ) -> Result<Vec<ToDeviceOutcome>> {
        let mut outcomes = Vec::new();
        for event in events {
            if event.kind != "m.room.encrypted" {
                continue;
            }
            match self.handle_olm_event(store, event) {
                Ok(Some(outcome)) => outcomes.push(outcome),
                Ok(None) => {}
                Err(e) => eprintln!(
                    "kmatrixd: to-device event from {} dropped: {e:#}",
                    event.sender
                ),
            }
        }
        Ok(outcomes)
    }

    fn handle_olm_event(
        &mut self,
        store: &Store,
        event: &ToDeviceEvent,
    ) -> Result<Option<ToDeviceOutcome>> {
        let content = &event.content;
        if content.get("algorithm").and_then(Value::as_str) != Some(OLM_ALGORITHM) {
            return Ok(None);
        }
        let sender_key = content
            .get("sender_key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("olm event without sender_key"))?;

        let our_key = self.account.curve25519_key().to_base64();
        let message = content
            .get("ciphertext")
            .and_then(|c| c.get(&our_key))
            .ok_or_else(|| anyhow!("olm event not addressed to this device"))?;
        let message_type = message
            .get("type")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("olm ciphertext without type"))?;
        let body = message
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("olm ciphertext without body"))?;

        let raw = vodozemac::base64_decode(body).context("decode olm body")?;
        let olm_message =
            OlmMessage::from_parts(message_type as usize, &raw).context("decode olm message")?;

        let plaintext = match self.decrypt_with_existing(store, sender_key, &olm_message) {
            Some(plaintext) => plaintext,
            None => match &olm_message {
                OlmMessage::PreKey(pre_key) => {
                    let identity = Curve25519PublicKey::from_base64(sender_key)
                        .context("bad sender curve25519 key")?;
                    let result = self
                        .account
                        .create_inbound_session(OlmConfig::version_1(), identity, pre_key)
                        .context("create inbound olm session")?;
                    store.put_pickle(
                        KIND_OLM,
                        &result.session.session_id(),
                        sender_key,
                        &result.session.pickle().encrypt(&self.pickle_key),
                    )?;
                    // The pre-key message consumed one of our one-time keys.
                    self.persist_account(store)?;
                    self.olm_sessions
                        .entry(sender_key.to_string())
                        .or_default()
                        .push(result.session);
                    result.plaintext
                }
                OlmMessage::Normal(_) => {
                    return Err(anyhow!(
                        "no olm session for sender key {sender_key} and message is not a pre-key"
                    ))
                }
            },
        };

        self.handle_olm_plaintext(store, sender_key, &plaintext)
    }

    fn handle_olm_plaintext(
        &mut self,
        store: &Store,
        sender_key: &str,
        plaintext: &[u8],
    ) -> Result<Option<ToDeviceOutcome>> {
        let event: Value = serde_json::from_slice(plaintext).context("parse olm plaintext")?;
        match event.get("type").and_then(Value::as_str) {
            Some("m.room_key") => {}
            Some("m.secret.send") => return self.handle_secret_send(sender_key, &event),
            // m.dummy, m.forwarded_room_key, verification traffic: nothing we
            // act on, and nothing worth an error.
            _ => return Ok(None),
        }
        let content = event
            .get("content")
            .ok_or_else(|| anyhow!("m.room_key without content"))?;
        if content.get("algorithm").and_then(Value::as_str) != Some(MEGOLM_ALGORITHM) {
            return Ok(None);
        }

        // Anti-spoofing: the Olm channel proves which device sent this, so the
        // envelope must not claim to come from someone else, and must have been
        // addressed to us rather than replayed from another recipient.
        if let Some((user_id, device_id)) = self.known_devices.get(sender_key) {
            let claimed = event.get("sender").and_then(Value::as_str);
            if claimed != Some(user_id.as_str()) {
                return Err(anyhow!(
                    "m.room_key over the olm channel with {user_id}/{device_id} claims sender {}",
                    claimed.unwrap_or("<missing>")
                ));
            }
        }
        if let Some(recipient_key) = event
            .get("recipient_keys")
            .and_then(|k| k.get("ed25519"))
            .and_then(Value::as_str)
        {
            if recipient_key != self.account.ed25519_key().to_base64() {
                return Err(anyhow!("m.room_key was addressed to a different device"));
            }
        }
        let room_id = content
            .get("room_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("m.room_key without room_id"))?;
        let session_key = content
            .get("session_key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("m.room_key without session_key"))?;
        let session_key =
            SessionKey::from_base64(session_key).context("decode megolm session key")?;

        let session = InboundGroupSession::new(&session_key, MegolmConfig::version_1());
        let session_id = session.session_id();
        store.put_pickle(
            KIND_MEGOLM_IN,
            &session_id,
            room_id,
            &session.pickle().encrypt(&self.pickle_key),
        )?;
        self.inbound.insert(session_id, session);
        Ok(None)
    }

    /// A secret one of our other devices shared with us. The Olm channel
    /// proves which device sent it; the request id proves it answers something
    /// we asked for, since we picked it at random and only ever sent it to our
    /// own devices.
    fn handle_secret_send(
        &self,
        sender_key: &str,
        event: &Value,
    ) -> Result<Option<ToDeviceOutcome>> {
        let content = event
            .get("content")
            .ok_or_else(|| anyhow!("m.secret.send without content"))?;
        let request_id = content
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("m.secret.send without request_id"))?;
        let secret = content
            .get("secret")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("m.secret.send without secret"))?;

        let Some(name) = self.secret_requests.get(request_id) else {
            eprintln!(
                "kmatrixd: ignoring m.secret.send for request {request_id}, which is not ours"
            );
            return Ok(None);
        };

        if let Some((user_id, device_id)) = self.known_devices.get(sender_key) {
            let claimed = event.get("sender").and_then(Value::as_str);
            if claimed != Some(user_id.as_str()) {
                return Err(anyhow!(
                    "m.secret.send over the olm channel with {user_id}/{device_id} claims sender {}",
                    claimed.unwrap_or("<missing>")
                ));
            }
        }

        Ok(Some(ToDeviceOutcome::Secret {
            name: name.clone(),
            secret: secret.to_string(),
            request_id: request_id.to_string(),
        }))
    }

    pub fn parse_device_keys(&self, keys_query: &Value) -> Vec<DeviceInfo> {
        let mut out = Vec::new();
        let Some(users) = keys_query.get("device_keys").and_then(Value::as_object) else {
            return out;
        };
        for (user_id, devices) in users {
            let Some(devices) = devices.as_object() else {
                continue;
            };
            for (device_id, info) in devices {
                let Some(keys) = info.get("keys").and_then(Value::as_object) else {
                    continue;
                };
                let curve = keys
                    .get(&format!("curve25519:{device_id}"))
                    .and_then(Value::as_str);
                let ed = keys
                    .get(&format!("ed25519:{device_id}"))
                    .and_then(Value::as_str);
                let (Some(curve_key), Some(ed_key)) = (curve, ed) else {
                    continue;
                };
                out.push(DeviceInfo {
                    user_id: user_id.clone(),
                    device_id: device_id.clone(),
                    curve_key: curve_key.to_string(),
                    ed_key: ed_key.to_string(),
                });
            }
        }
        out
    }

    /// Record what `/keys/query` told us about a set of devices. SAS MACs are
    /// taken over the peer's ed25519 key, so the key has to be on hand before
    /// the `m.key.verification.mac` arrives.
    pub fn remember_devices(&mut self, devices: &[DeviceInfo]) {
        for device in devices {
            self.device_ed_keys.insert(
                (device.user_id.clone(), device.device_id.clone()),
                device.ed_key.clone(),
            );
            self.known_devices.insert(
                device.curve_key.clone(),
                (device.user_id.clone(), device.device_id.clone()),
            );
        }
    }

    /// Devices we cannot yet talk to over Olm. Our own device is never in the
    /// list: claiming our own one-time key would burn it for nothing.
    pub fn devices_needing_session(&self, all: &[DeviceInfo]) -> Vec<DeviceInfo> {
        let ours = self.account.curve25519_key().to_base64();
        all.iter()
            .filter(|d| d.curve_key != ours)
            .filter(|d| {
                self.olm_sessions
                    .get(&d.curve_key)
                    .is_none_or(|sessions| sessions.is_empty())
            })
            .cloned()
            .collect()
    }

    pub fn claim_body(devices: &[DeviceInfo]) -> Value {
        let mut users: Map<String, Value> = Map::new();
        for device in devices {
            let entry = users
                .entry(device.user_id.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(map) = entry.as_object_mut() {
                map.insert(
                    device.device_id.clone(),
                    Value::String("signed_curve25519".to_string()),
                );
            }
        }
        let mut body = Map::new();
        body.insert("one_time_keys".to_string(), Value::Object(users));
        Value::Object(body)
    }

    pub fn create_outbound_olm(
        &mut self,
        store: &Store,
        claim_response: &Value,
        devices: &[DeviceInfo],
    ) -> Result<()> {
        let claimed = claim_response.get("one_time_keys");
        for device in devices {
            // A retry may hand us a stale "needs a session" list; don't burn a
            // second claimed one-time key on a device we can already reach.
            if self
                .olm_sessions
                .get(&device.curve_key)
                .is_some_and(|sessions| !sessions.is_empty())
            {
                continue;
            }
            let key = claimed
                .and_then(|v| v.get(&device.user_id))
                .and_then(|v| v.get(&device.device_id))
                .and_then(Value::as_object)
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|(k, _)| k.starts_with("signed_curve25519"))
                        .map(|(_, v)| v)
                })
                .and_then(one_time_key_value);
            let Some(key) = key else {
                eprintln!(
                    "kmatrixd: no one-time key claimed for {}/{}",
                    device.user_id, device.device_id
                );
                continue;
            };
            if let Err(e) = self.start_olm_session(store, device, key) {
                eprintln!(
                    "kmatrixd: olm session with {}/{} failed: {e:#}",
                    device.user_id, device.device_id
                );
            }
        }
        Ok(())
    }

    fn start_olm_session(&mut self, store: &Store, device: &DeviceInfo, otk: &str) -> Result<()> {
        let identity =
            Curve25519PublicKey::from_base64(&device.curve_key).context("bad device curve key")?;
        let one_time_key = Curve25519PublicKey::from_base64(otk).context("bad one-time key")?;
        let session = self
            .account
            .create_outbound_session(OlmConfig::version_1(), identity, one_time_key)
            .context("create outbound olm session")?;
        store.put_pickle(
            KIND_OLM,
            &session.session_id(),
            &device.curve_key,
            &session.pickle().encrypt(&self.pickle_key),
        )?;
        self.olm_sessions
            .entry(device.curve_key.clone())
            .or_default()
            .push(session);
        self.known_devices.insert(
            device.curve_key.clone(),
            (device.user_id.clone(), device.device_id.clone()),
        );
        Ok(())
    }

    /// Share the room's outbound Megolm session with every listed device.
    /// Returns a `/sendToDevice` `messages` map.
    pub fn encrypt_room_key_to_devices(
        &mut self,
        store: &Store,
        room: &str,
        devices: &[DeviceInfo],
        our_user_id: &str,
        our_device_id: &str,
    ) -> Result<Value> {
        let our_curve = self.account.curve25519_key().to_base64();
        let our_ed = self.account.ed25519_key().to_base64();

        let (session_id, session_key, chain_index) = {
            let session = self.get_or_create_outbound(store, room)?;
            (
                session.session_id(),
                session.session_key().to_base64(),
                session.message_index(),
            )
        };

        let mut key_content = Map::new();
        key_content.insert(
            "algorithm".to_string(),
            Value::String(MEGOLM_ALGORITHM.to_string()),
        );
        key_content.insert("chain_index".to_string(), Value::from(chain_index));
        key_content.insert("room_id".to_string(), Value::String(room.to_string()));
        key_content.insert("session_id".to_string(), Value::String(session_id));
        key_content.insert("session_key".to_string(), Value::String(session_key));
        let key_content = Value::Object(key_content);

        let mut messages: Map<String, Value> = Map::new();
        for device in devices {
            if device.curve_key == our_curve {
                continue;
            }
            let envelope =
                room_key_envelope(&key_content, our_user_id, our_device_id, &our_ed, device);
            let plaintext = serde_json::to_vec(&envelope).context("serialize m.room_key")?;
            let (message_type, body) = match self.olm_encrypt(store, &device.curve_key, &plaintext)
            {
                Ok(parts) => parts,
                Err(e) => {
                    eprintln!(
                        "kmatrixd: cannot share room key with {}/{}: {e:#}",
                        device.user_id, device.device_id
                    );
                    continue;
                }
            };

            let content = olm_to_device_content(&our_curve, &device.curve_key, message_type, &body);
            let entry = messages
                .entry(device.user_id.clone())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(map) = entry.as_object_mut() {
                map.insert(device.device_id.clone(), content);
            }
            self.known_devices.insert(
                device.curve_key.clone(),
                (device.user_id.clone(), device.device_id.clone()),
            );
        }

        Ok(Value::Object(messages))
    }

    /// Megolm-encrypt a full room event envelope for `room`.
    pub fn encrypt(
        &mut self,
        store: &Store,
        room: &str,
        plaintext: &Value,
        _our_user_id: &str,
        our_device_id: &str,
    ) -> Result<Value> {
        let our_curve = self.account.curve25519_key().to_base64();
        let pickle_key = self.pickle_key;
        let raw = serde_json::to_vec(plaintext).context("serialize room event")?;

        let session = self.get_or_create_outbound(store, room)?;
        let message = session.encrypt(&raw);
        let session_id = session.session_id();
        let index = session.message_index();
        store.put_pickle(
            KIND_MEGOLM_OUT,
            room,
            &index.to_string(),
            &session.pickle().encrypt(&pickle_key),
        )?;

        let mut content = Map::new();
        content.insert(
            "algorithm".to_string(),
            Value::String(MEGOLM_ALGORITHM.to_string()),
        );
        content.insert("ciphertext".to_string(), Value::String(message.to_base64()));
        content.insert(
            "device_id".to_string(),
            Value::String(our_device_id.to_string()),
        );
        content.insert("sender_key".to_string(), Value::String(our_curve));
        content.insert("session_id".to_string(), Value::String(session_id));
        Ok(Value::Object(content))
    }

    pub fn has_outbound(&self, room: &str) -> bool {
        self.outbound.contains_key(room)
    }

    // ------------------------------------------------ server-side key backup

    /// Validate a recovery key against the backup's advertised public key and
    /// persist it. A key that does not match is rejected here, at the one point
    /// where the user can still fix their typo, rather than silently producing
    /// garbage plaintext on every later restore.
    pub fn set_backup_key(
        &mut self,
        store: &Store,
        recovery_key: &str,
        expected_public_key: &str,
    ) -> Result<()> {
        let bytes = decode_recovery_key(recovery_key)?;
        let decryption = PkDecryption::from_key(Curve25519SecretKey::from_slice(&bytes));
        let derived = decryption.public_key().to_base64();
        // Homeservers may pad their base64; vodozemac never does.
        if derived != expected_public_key.trim().trim_end_matches('=') {
            return Err(anyhow!(
                "this recovery key does not match this backup: it unlocks {derived}, \
                 but the backup was made for {expected_public_key}"
            ));
        }
        store.set_meta(
            BACKUP_KEY_META,
            &base64::engine::general_purpose::STANDARD.encode(bytes),
        )?;
        self.backup_key = Some(decryption);
        Ok(())
    }

    /// Adopt a backup key handed to us over encrypted secret sharing.
    ///
    /// The secret an `m.secret.send` carries is standard base64 of the raw 32
    /// byte Curve25519 private key — not the base58 recovery key the user
    /// would otherwise have typed. Both entry points converge on the same
    /// `meta` row, so a restart cannot tell them apart.
    pub fn set_backup_key_base64(
        &mut self,
        store: &Store,
        secret_b64: &str,
        expected_public_key: Option<&str>,
    ) -> Result<()> {
        // Tolerate a missing or present pad: implementations disagree, and
        // four bytes of base64 trivia must not cost the user their history.
        let raw = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(secret_b64.trim().trim_end_matches('='))
            .context("decode shared backup key")?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("shared backup key is {} bytes, expected 32", raw.len()))?;

        let decryption = PkDecryption::from_key(Curve25519SecretKey::from_slice(&bytes));
        let derived = decryption.public_key().to_base64();
        if let Some(expected) = expected_public_key {
            if derived != expected.trim().trim_end_matches('=') {
                return Err(anyhow!(
                    "the shared backup key does not match this backup: it unlocks {derived}, \
                     but the backup was made for {expected}"
                ));
            }
        }
        store.set_meta(
            BACKUP_KEY_META,
            &base64::engine::general_purpose::STANDARD.encode(bytes),
        )?;
        self.backup_key = Some(decryption);
        Ok(())
    }

    pub fn has_backup_key(&self) -> bool {
        self.backup_key.is_some()
    }

    /// Decrypt one `/room_keys/keys` entry and register the Megolm session it
    /// carries. `entry` is the server's per-session object: `session_data`
    /// (`ciphertext`, `mac`, `ephemeral`) plus `first_message_index`.
    ///
    /// Returns `Ok(true)` when a session was imported and `Ok(false)` when the
    /// entry was of no use: a non-Megolm algorithm, or a session we already
    /// hold from an equally early or earlier message index.
    ///
    /// A backed up key carries no signature from the device that created the
    /// session, so the imported session is unverified — the same trust level
    /// libolm gives to key exports.
    pub fn import_backup_session(
        &mut self,
        store: &Store,
        room: &str,
        session_id: &str,
        entry: &Value,
    ) -> Result<bool> {
        let first_message_index = entry
            .get("first_message_index")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        // Reject before spending an ECDH: we may already hold this session from
        // the same index or an earlier one.
        if let Some(existing) = self.inbound.get(session_id) {
            if u64::from(existing.first_known_index()) <= first_message_index {
                return Ok(false);
            }
        }

        let decryption = self
            .backup_key
            .as_ref()
            .ok_or_else(|| anyhow!("no backup recovery key has been entered"))?;
        let data = entry
            .get("session_data")
            .ok_or_else(|| anyhow!("backup entry for {session_id} has no session_data"))?;
        // The spec encodes these unpadded, but tolerate padding rather than
        // fail a restore over four bytes of base64 trivia.
        let part = |name: &str| -> Result<&str> {
            data.get(name)
                .and_then(Value::as_str)
                .map(|s| s.trim_end_matches('='))
                .ok_or_else(|| anyhow!("backup session_data for {session_id} has no {name}"))
        };
        let message = PkMessage::from_base64(part("ciphertext")?, part("mac")?, part("ephemeral")?)
            .context("decode backup session_data")?;
        let plaintext = decryption
            .decrypt(&message)
            .context("decrypt backup session_data")?;

        let decoded: Value =
            serde_json::from_slice(&plaintext).context("parse backup session plaintext")?;
        if decoded.get("algorithm").and_then(Value::as_str) != Some(MEGOLM_ALGORITHM) {
            // Some other kind of backed up key. Not ours to import, and not
            // worth failing over.
            return Ok(false);
        }
        let session_key = decoded
            .get("session_key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("backed up session {session_id} has no session_key"))?;
        // Backups hold the *exported* form: a ratchet at some index, without the
        // creator's signature, so this is an import and not a `new`.
        let exported = ExportedSessionKey::from_base64(session_key.trim_end_matches('='))
            .context("decode exported megolm session key")?;
        let session = InboundGroupSession::import(&exported, MegolmConfig::version_1());
        let imported_id = session.session_id();
        if imported_id != session_id {
            return Err(anyhow!(
                "backup entry filed under {session_id} actually holds session {imported_id}"
            ));
        }
        // The entry's advertised index is a hint; the ratchet itself decides.
        if let Some(existing) = self.inbound.get(&imported_id) {
            if existing.first_known_index() <= session.first_known_index() {
                return Ok(false);
            }
        }
        store.put_pickle(
            KIND_MEGOLM_IN,
            &imported_id,
            room,
            &session.pickle().encrypt(&self.pickle_key),
        )?;
        self.inbound.insert(imported_id, session);
        Ok(true)
    }

    // ------------------------------------------------- SAS device verification

    /// Feed one plaintext `m.key.verification.*` to-device event into the
    /// state machine.
    ///
    /// We are always the responder. Element sends the request, we answer
    /// `ready`, it sends `start`, and from there we drive accept -> key ->
    /// emoji -> (user) -> mac -> done.
    ///
    /// Events for a transaction we do not know are ignored in silence rather
    /// than cancelled: Element sends the same request to every one of our
    /// devices and cancels the ones that lose the race, so a stranger
    /// transaction id is the normal case, not an attack.
    pub fn handle_verification(
        &mut self,
        our_user: &str,
        our_device: &str,
        sender: &str,
        kind: &str,
        content: &Value,
    ) -> Result<VerifyStep> {
        self.expire_verifications();

        let Some(transaction) = content.get("transaction_id").and_then(Value::as_str) else {
            // In-room verification uses m.relates_to instead; we only speak
            // to-device.
            return Ok(VerifyStep::default());
        };
        let transaction = transaction.to_string();

        match kind {
            "m.key.verification.request" => {
                Ok(self.verification_request(&transaction, sender, our_device, content))
            }
            "m.key.verification.start" => {
                Ok(self.verification_start(&transaction, sender, content))
            }
            "m.key.verification.key" => {
                Ok(self.verification_key(&transaction, our_user, our_device, content))
            }
            "m.key.verification.mac" => {
                Ok(self.verification_mac(&transaction, our_user, our_device, content))
            }
            "m.key.verification.done" => Ok(self.verification_done(&transaction)),
            "m.key.verification.cancel" => Ok(self.verification_cancel(&transaction, content)),
            // m.key.verification.ready and m.key.verification.accept are what
            // an initiator receives; we never are one.
            _ => Ok(VerifyStep::default()),
        }
    }

    /// The user has looked at the emoji. `confirm` false means they did not
    /// match, which is the one outcome that must abort loudly.
    pub fn confirm_verification(
        &mut self,
        our_user: &str,
        our_device: &str,
        transaction: &str,
        confirm: bool,
    ) -> Result<VerifyStep> {
        let Some(entry) = self.verifications.get(transaction) else {
            // Expired, or already cancelled by the other side. Tell the UI so
            // it can take the emoji off the screen.
            return Ok(VerifyStep {
                cancelled: Some(format!(
                    "verification {transaction} is no longer in progress"
                )),
                ..VerifyStep::default()
            });
        };

        if !confirm {
            let device = entry.their_device.clone();
            return Ok(self.cancel(
                transaction,
                &device,
                "m.mismatched_sas",
                "the emoji did not match",
            ));
        }

        let Some(established) = entry.established.as_ref() else {
            let device = entry.their_device.clone();
            return Ok(self.cancel(
                transaction,
                &device,
                "m.unexpected_message",
                "confirmed before the key exchange finished",
            ));
        };

        // We only ever MAC our own device key. The master key belongs in a
        // cross-user MAC, and we have no cross-signing identity of our own.
        let info = mac_info(
            our_user,
            our_device,
            &entry.their_user,
            &entry.their_device,
            transaction,
        );
        let key_id = format!("ed25519:{our_device}");
        let our_ed = self.account.ed25519_key().to_base64();
        let key_mac = established
            .calculate_mac(&our_ed, &format!("{info}{key_id}"))
            .to_base64();
        let keys_mac = established
            .calculate_mac(&key_id, &format!("{info}KEY_IDS"))
            .to_base64();

        let their_device = entry.their_device.clone();
        let mut mac = Map::new();
        mac.insert(key_id, Value::String(key_mac));
        let mut mac_content = Map::new();
        mac_content.insert(
            "transaction_id".to_string(),
            Value::String(transaction.to_string()),
        );
        mac_content.insert("keys".to_string(), Value::String(keys_mac));
        mac_content.insert("mac".to_string(), Value::Object(mac));

        let mut done_content = Map::new();
        done_content.insert(
            "transaction_id".to_string(),
            Value::String(transaction.to_string()),
        );

        let mut step = VerifyStep {
            send: vec![
                (
                    "m.key.verification.mac".to_string(),
                    their_device.clone(),
                    Value::Object(mac_content),
                ),
                (
                    "m.key.verification.done".to_string(),
                    their_device.clone(),
                    Value::Object(done_content),
                ),
            ],
            ..VerifyStep::default()
        };

        if let Some(mut entry) = self.verifications.remove(transaction) {
            entry.we_sent_mac = true;
            entry.we_sent_done = true;
            if entry.complete() {
                step.done = Some(their_device);
            } else {
                self.verifications.insert(transaction.to_string(), entry);
            }
        }
        Ok(step)
    }

    // --------------------------------------------------------------- secrets

    /// Build an `m.secret.request` for `name`. The caller fans the content out
    /// to every device of our own user; the request id comes back so it can
    /// later be cancelled.
    pub fn secret_request(&mut self, our_device: &str, name: &str) -> (String, Value) {
        // 128 bits of request id: an attacker who cannot guess it cannot push
        // us a secret we never asked for.
        let high: u64 = rand::random();
        let low: u64 = rand::random();
        let request_id = format!("{high:016x}{low:016x}");
        self.secret_requests
            .insert(request_id.clone(), name.to_string());

        let mut content = Map::new();
        content.insert("action".to_string(), Value::String("request".to_string()));
        content.insert("name".to_string(), Value::String(name.to_string()));
        content.insert("request_id".to_string(), Value::String(request_id.clone()));
        content.insert(
            "requesting_device_id".to_string(),
            Value::String(our_device.to_string()),
        );
        (request_id, Value::Object(content))
    }

    /// Withdraw a request once one device has answered it. The request id
    /// stays known so that a second, in-flight answer is still accepted rather
    /// than logged as a forgery.
    pub fn secret_cancellation(&self, our_device: &str, request_id: &str) -> Value {
        let mut content = Map::new();
        content.insert(
            "action".to_string(),
            Value::String("request_cancellation".to_string()),
        );
        content.insert(
            "request_id".to_string(),
            Value::String(request_id.to_string()),
        );
        content.insert(
            "requesting_device_id".to_string(),
            Value::String(our_device.to_string()),
        );
        Value::Object(content)
    }

    // ---------------------------------------------------- verification steps

    fn verification_request(
        &mut self,
        transaction: &str,
        sender: &str,
        our_device: &str,
        content: &Value,
    ) -> VerifyStep {
        let Some(from_device) = content.get("from_device").and_then(Value::as_str) else {
            return VerifyStep::default();
        };
        let supported = content
            .get("methods")
            .and_then(Value::as_array)
            .is_some_and(|m| m.iter().any(|v| v.as_str() == Some(SAS_METHOD)));
        if !supported {
            return self.cancel(
                transaction,
                from_device,
                "m.unknown_method",
                "this device only speaks m.sas.v1",
            );
        }

        self.verifications.insert(
            transaction.to_string(),
            Verification::new(sender, from_device),
        );

        let mut ready = Map::new();
        ready.insert(
            "from_device".to_string(),
            Value::String(our_device.to_string()),
        );
        ready.insert(
            "methods".to_string(),
            Value::Array(vec![Value::String(SAS_METHOD.to_string())]),
        );
        ready.insert(
            "transaction_id".to_string(),
            Value::String(transaction.to_string()),
        );
        VerifyStep {
            send: vec![(
                "m.key.verification.ready".to_string(),
                from_device.to_string(),
                Value::Object(ready),
            )],
            ..VerifyStep::default()
        }
    }

    fn verification_start(
        &mut self,
        transaction: &str,
        sender: &str,
        content: &Value,
    ) -> VerifyStep {
        if !self.verifications.contains_key(transaction) {
            // A verification may begin with a bare `start`; the request and
            // ready round trip is optional. Answering one costs nothing until
            // the user confirms the emoji, so adopt it rather than go silent.
            let Some(from_device) = content.get("from_device").and_then(Value::as_str) else {
                return VerifyStep::default();
            };
            self.verifications.insert(
                transaction.to_string(),
                Verification::new(sender, from_device),
            );
        }
        let Some(entry) = self.verifications.get(transaction) else {
            return VerifyStep::default();
        };
        if entry.start.is_some() {
            // A duplicate start would move our ephemeral key out from under a
            // commitment the other side has already seen.
            return VerifyStep::default();
        }
        let their_device = entry.their_device.clone();

        if content.get("method").and_then(Value::as_str) != Some(SAS_METHOD) {
            return self.cancel(
                transaction,
                &their_device,
                "m.unknown_method",
                "this device only speaks m.sas.v1",
            );
        }

        let offers = |field: &str, wanted: &str| -> bool {
            content
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(|list| list.iter().any(|v| v.as_str() == Some(wanted)))
        };
        let negotiated = offers("key_agreement_protocols", KEY_AGREEMENT_PROTOCOL)
            && offers("hashes", SAS_HASH)
            && offers("message_authentication_codes", MAC_METHOD)
            && offers("short_authentication_string", SAS_EMOJI_STRING);
        if !negotiated {
            return self.cancel(
                transaction,
                &their_device,
                "m.unknown_method",
                "no shared key agreement, hash, MAC or SAS method",
            );
        }

        // The hash commitment: we are the accepting side, so we commit to the
        // ephemeral key we will only reveal after they have revealed theirs.
        let sas = Sas::new();
        let our_public_key = sas.public_key().to_base64();
        let mut committed = our_public_key.clone().into_bytes();
        committed.extend_from_slice(canonical_json_verbatim(content).as_bytes());
        let commitment = vodozemac::base64_encode(sha256(&committed));

        let mut accept = Map::new();
        accept.insert("commitment".to_string(), Value::String(commitment));
        accept.insert("hash".to_string(), Value::String(SAS_HASH.to_string()));
        accept.insert(
            "key_agreement_protocol".to_string(),
            Value::String(KEY_AGREEMENT_PROTOCOL.to_string()),
        );
        accept.insert(
            "message_authentication_code".to_string(),
            Value::String(MAC_METHOD.to_string()),
        );
        accept.insert("method".to_string(), Value::String(SAS_METHOD.to_string()));
        accept.insert(
            "short_authentication_string".to_string(),
            Value::Array(vec![Value::String(SAS_EMOJI_STRING.to_string())]),
        );
        accept.insert(
            "transaction_id".to_string(),
            Value::String(transaction.to_string()),
        );

        if let Some(entry) = self.verifications.get_mut(transaction) {
            entry.sas = Some(sas);
            entry.our_public_key = Some(our_public_key);
            entry.start = Some(content.clone());
        }

        VerifyStep {
            send: vec![(
                "m.key.verification.accept".to_string(),
                their_device,
                Value::Object(accept),
            )],
            ..VerifyStep::default()
        }
    }

    fn verification_key(
        &mut self,
        transaction: &str,
        our_user: &str,
        our_device: &str,
        content: &Value,
    ) -> VerifyStep {
        // Taken out of the map for the duration: the Diffie-Hellman consumes
        // our ephemeral key by value, and every failure path below ends the
        // transaction anyway.
        let Some(mut entry) = self.verifications.remove(transaction) else {
            return VerifyStep::default();
        };
        let their_device = entry.their_device.clone();
        let their_user = entry.their_user.clone();

        let Some(their_key) = content.get("key").and_then(Value::as_str) else {
            return self.cancel(
                transaction,
                &their_device,
                "m.invalid_message",
                "m.key.verification.key without a key",
            );
        };
        let their_key = their_key.to_string();

        let (Some(sas), Some(our_key)) = (entry.sas.take(), entry.our_public_key.clone()) else {
            return self.cancel(
                transaction,
                &their_device,
                "m.unexpected_message",
                "a key arrived before the start was accepted",
            );
        };

        let established = match sas.diffie_hellman_with_raw(&their_key) {
            Ok(established) => established,
            Err(e) => {
                return self.cancel(
                    transaction,
                    &their_device,
                    "m.invalid_message",
                    &format!("their SAS key is unusable: {e}"),
                )
            }
        };

        // They started, so their side of the info string comes first.
        let info = format!(
            "MATRIX_KEY_VERIFICATION_SAS|{their_user}|{their_device}|{their_key}\
             |{our_user}|{our_device}|{our_key}|{transaction}"
        );
        let indices = established.bytes(&info).emoji_indices();

        entry.their_public_key = Some(their_key);
        entry.established = Some(established);
        self.verifications.insert(transaction.to_string(), entry);

        let mut key = Map::new();
        key.insert("key".to_string(), Value::String(our_key));
        key.insert(
            "transaction_id".to_string(),
            Value::String(transaction.to_string()),
        );

        VerifyStep {
            send: vec![(
                "m.key.verification.key".to_string(),
                their_device.clone(),
                Value::Object(key),
            )],
            emoji: Some((transaction.to_string(), their_device, indices)),
            ..VerifyStep::default()
        }
    }

    fn verification_mac(
        &mut self,
        transaction: &str,
        our_user: &str,
        our_device: &str,
        content: &Value,
    ) -> VerifyStep {
        let Some(mut entry) = self.verifications.remove(transaction) else {
            return VerifyStep::default();
        };
        let their_device = entry.their_device.clone();
        let their_user = entry.their_user.clone();

        let Some(established) = entry.established.take() else {
            return self.cancel(
                transaction,
                &their_device,
                "m.unexpected_message",
                "a MAC arrived before the key exchange",
            );
        };
        let (Some(macs), Some(keys_mac)) = (
            content.get("mac").and_then(Value::as_object),
            content.get("keys").and_then(Value::as_str),
        ) else {
            return self.cancel(
                transaction,
                &their_device,
                "m.invalid_message",
                "m.key.verification.mac without mac and keys",
            );
        };

        // The MAC info string names the sender first, and they are the sender
        // of the MACs we are checking.
        let info = mac_info(
            &their_user,
            &their_device,
            our_user,
            our_device,
            transaction,
        );

        let mut key_ids: Vec<&str> = macs.keys().map(String::as_str).collect();
        key_ids.sort_unstable();
        let joined = key_ids.join(",");
        if verify_mac_b64(&established, &joined, &format!("{info}KEY_IDS"), keys_mac).is_err() {
            return self.cancel(
                transaction,
                &their_device,
                "m.key_mismatch",
                "the MAC over their key ids did not verify",
            );
        }

        for key_id in key_ids {
            let Some(mac) = macs.get(key_id).and_then(Value::as_str) else {
                return self.cancel(
                    transaction,
                    &their_device,
                    "m.invalid_message",
                    "a MAC entry was not a string",
                );
            };
            let Some(device_id) = key_id.strip_prefix("ed25519:") else {
                // Some other key algorithm. It was covered by the KEY_IDS MAC,
                // so it is not forged, only uninteresting.
                continue;
            };
            let Some(their_ed) = self
                .device_ed_keys
                .get(&(their_user.clone(), device_id.to_string()))
            else {
                eprintln!(
                    "kmatrixd: verification {transaction}: no ed25519 key known for \
                     {their_user}/{device_id}, skipping its MAC"
                );
                continue;
            };
            if verify_mac_b64(&established, their_ed, &format!("{info}{key_id}"), mac).is_err() {
                return self.cancel(
                    transaction,
                    &their_device,
                    "m.key_mismatch",
                    &format!("the MAC over {key_id} did not verify"),
                );
            }
        }

        entry.established = Some(established);
        entry.they_sent_mac = true;

        let mut step = VerifyStep::default();
        if entry.complete() {
            step.done = Some(their_device);
        } else {
            self.verifications.insert(transaction.to_string(), entry);
        }
        step
    }

    fn verification_done(&mut self, transaction: &str) -> VerifyStep {
        let mut step = VerifyStep::default();
        if let Some(mut entry) = self.verifications.remove(transaction) {
            entry.they_sent_done = true;
            if entry.complete() {
                step.done = Some(entry.their_device.clone());
            } else {
                self.verifications.insert(transaction.to_string(), entry);
            }
        }
        step
    }

    fn verification_cancel(&mut self, transaction: &str, content: &Value) -> VerifyStep {
        let Some(entry) = self.verifications.remove(transaction) else {
            return VerifyStep::default();
        };
        let reason = content
            .get("reason")
            .and_then(Value::as_str)
            .or_else(|| content.get("code").and_then(Value::as_str))
            .unwrap_or("the other device cancelled the verification");
        eprintln!(
            "kmatrixd: verification {transaction} with {} cancelled: {reason}",
            entry.their_device
        );
        VerifyStep {
            cancelled: Some(reason.to_string()),
            ..VerifyStep::default()
        }
    }

    /// Drop the transaction and emit the cancel the other side expects.
    fn cancel(
        &mut self,
        transaction: &str,
        their_device: &str,
        code: &str,
        reason: &str,
    ) -> VerifyStep {
        self.verifications.remove(transaction);
        let mut content = Map::new();
        content.insert("code".to_string(), Value::String(code.to_string()));
        content.insert("reason".to_string(), Value::String(reason.to_string()));
        content.insert(
            "transaction_id".to_string(),
            Value::String(transaction.to_string()),
        );
        VerifyStep {
            send: vec![(
                "m.key.verification.cancel".to_string(),
                their_device.to_string(),
                Value::Object(content),
            )],
            cancelled: Some(reason.to_string()),
            ..VerifyStep::default()
        }
    }

    fn expire_verifications(&mut self) {
        let now = Instant::now();
        self.verifications.retain(|transaction, entry| {
            let alive = now.duration_since(entry.created) < VERIFICATION_TIMEOUT;
            if !alive {
                eprintln!("kmatrixd: verification {transaction} expired");
            }
            alive
        });
    }

    // ------------------------------------------------------------- internals

    fn persist_account(&self, store: &Store) -> Result<()> {
        store.put_pickle(
            KIND_ACCOUNT,
            "self",
            "",
            &self.account.pickle().encrypt(&self.pickle_key),
        )
    }

    fn signed_device_keys(&self, user_id: &str, device_id: &str) -> Value {
        let mut keys = Map::new();
        keys.insert(
            format!("curve25519:{device_id}"),
            Value::String(self.account.curve25519_key().to_base64()),
        );
        keys.insert(
            format!("ed25519:{device_id}"),
            Value::String(self.account.ed25519_key().to_base64()),
        );

        let mut device_keys = Map::new();
        device_keys.insert(
            "algorithms".to_string(),
            Value::Array(vec![
                Value::String(OLM_ALGORITHM.to_string()),
                Value::String(MEGOLM_ALGORITHM.to_string()),
            ]),
        );
        device_keys.insert(
            "device_id".to_string(),
            Value::String(device_id.to_string()),
        );
        device_keys.insert("keys".to_string(), Value::Object(keys));
        device_keys.insert("user_id".to_string(), Value::String(user_id.to_string()));

        let signature = self
            .account
            .sign(canonical_json(&Value::Object(device_keys.clone())))
            .to_base64();
        device_keys.insert(
            "signatures".to_string(),
            signatures_for(user_id, device_id, &signature),
        );
        Value::Object(device_keys)
    }

    /// Try every olm session we hold for `sender_key`. On success the advanced
    /// session is written back, since its ratchet moved.
    fn decrypt_with_existing(
        &mut self,
        store: &Store,
        sender_key: &str,
        message: &OlmMessage,
    ) -> Option<Vec<u8>> {
        let pickle_key = self.pickle_key;
        let sessions = self.olm_sessions.get_mut(sender_key)?;
        for session in sessions.iter_mut() {
            if let Ok(plaintext) = session.decrypt(message) {
                if let Err(e) = store.put_pickle(
                    KIND_OLM,
                    &session.session_id(),
                    sender_key,
                    &session.pickle().encrypt(&pickle_key),
                ) {
                    eprintln!("kmatrixd: could not persist advanced olm session: {e:#}");
                }
                return Some(plaintext);
            }
        }
        None
    }

    fn olm_encrypt(
        &mut self,
        store: &Store,
        curve_key: &str,
        plaintext: &[u8],
    ) -> Result<(usize, String)> {
        let pickle_key = self.pickle_key;
        let session = self
            .olm_sessions
            .get_mut(curve_key)
            .and_then(|sessions| sessions.last_mut())
            .ok_or_else(|| anyhow!("no olm session for device key {curve_key}"))?;
        let message = session.encrypt(plaintext).context("olm encrypt")?;
        store.put_pickle(
            KIND_OLM,
            &session.session_id(),
            curve_key,
            &session.pickle().encrypt(&pickle_key),
        )?;
        let (message_type, ciphertext) = message.to_parts();
        Ok((message_type, vodozemac::base64_encode(ciphertext)))
    }

    /// The outbound session for a room, creating it on first use. A freshly
    /// created session is immediately registered as an inbound session too, so
    /// that our own messages echoed back by the server are decryptable.
    fn get_or_create_outbound(&mut self, store: &Store, room: &str) -> Result<&mut GroupSession> {
        if !self.outbound.contains_key(room) {
            let session = GroupSession::new(MegolmConfig::version_1());
            store.put_pickle(
                KIND_MEGOLM_OUT,
                room,
                "0",
                &session.pickle().encrypt(&self.pickle_key),
            )?;

            let inbound = InboundGroupSession::from(&session);
            let session_id = inbound.session_id();
            store.put_pickle(
                KIND_MEGOLM_IN,
                &session_id,
                room,
                &inbound.pickle().encrypt(&self.pickle_key),
            )?;
            self.inbound.insert(session_id, inbound);
            self.outbound.insert(room.to_string(), session);
        }
        self.outbound
            .get_mut(room)
            .ok_or_else(|| anyhow!("outbound megolm session for {room} disappeared"))
    }
}

// ------------------------------------------------------------------ helpers

fn load_pickle_key(store: &Store) -> Result<[u8; 32]> {
    let engine = base64::engine::general_purpose::STANDARD;
    if let Some(encoded) = store.get_meta(PICKLE_KEY_META)? {
        let raw = engine
            .decode(encoded.as_bytes())
            .context("decode pickle key")?;
        let key: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("stored pickle key is {} bytes, expected 32", raw.len()))?;
        return Ok(key);
    }
    let key: [u8; 32] = rand::random();
    store.set_meta(PICKLE_KEY_META, &engine.encode(key))?;
    Ok(key)
}

/// Decode the megolm backup private key as stored in `meta`.
fn decode_backup_key(encoded: &str) -> Result<Curve25519SecretKey> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .context("decode backup key")?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("stored backup key is {} bytes, expected 32", raw.len()))?;
    Ok(Curve25519SecretKey::from_slice(&bytes))
}

/// Decode a Matrix recovery key (the "security key" a client shows once): 35
/// base58 bytes made of a two byte prefix, the 32 byte Curve25519 backup
/// private key, and a parity byte chosen so that the XOR of all 35 bytes is 0.
///
/// Every failure mode gets its own message. The user typed this on an e-ink
/// keyboard, and "one character is mistyped" versus "a character is missing"
/// is the difference between re-reading one block and re-reading all thirteen.
fn decode_recovery_key(s: &str) -> Result<[u8; 32]> {
    // Clients display the key in blocks of four separated by spaces.
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err(anyhow!("recovery key is empty"));
    }
    let bytes = base58_decode(&compact)?;
    if bytes.len() != RECOVERY_KEY_LEN {
        return Err(anyhow!(
            "recovery key decodes to {} bytes, expected {RECOVERY_KEY_LEN}: \
             a character is missing or one too many",
            bytes.len()
        ));
    }
    if bytes[..2] != RECOVERY_KEY_PREFIX {
        return Err(anyhow!(
            "recovery key starts with {:02x}{:02x}, expected 8b01: this is not a Matrix \
             recovery key",
            bytes[0],
            bytes[1]
        ));
    }
    if bytes.iter().fold(0u8, |acc, b| acc ^ b) != 0 {
        return Err(anyhow!(
            "recovery key fails its parity check: at least one character is mistyped"
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[2..34]);
    Ok(key)
}

/// Base conversion from base58 to base256. The inner loop is quadratic in the
/// output length, which is fine for the 35 bytes this is ever asked to decode.
fn base58_decode(s: &str) -> Result<Vec<u8>> {
    // Little-endian while we do arithmetic, reversed on the way out.
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.chars() {
        let mut carry = u32::from(base58_digit(c)?);
        for byte in out.iter_mut() {
            let acc = u32::from(*byte) * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry != 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // '1' is the base58 zero digit; leading ones are leading zero bytes, which
    // the arithmetic above cannot express.
    let leading = s.bytes().take_while(|&c| c == b'1').count();
    out.resize(out.len() + leading, 0);
    out.reverse();
    Ok(out)
}

fn base58_digit(c: char) -> Result<u8> {
    if c.is_ascii() {
        if let Some(digit) = BASE58_ALPHABET.iter().position(|&a| a == c as u8) {
            return Ok(digit as u8);
        }
    }
    Err(anyhow!("'{c}' is not a valid base58 character"))
}

fn signatures_for(user_id: &str, device_id: &str, signature: &str) -> Value {
    let mut by_key = Map::new();
    by_key.insert(
        format!("ed25519:{device_id}"),
        Value::String(signature.to_string()),
    );
    let mut by_user = Map::new();
    by_user.insert(user_id.to_string(), Value::Object(by_key));
    Value::Object(by_user)
}

/// Pull the public key out of a `/keys/claim` entry. The value is a
/// `{"key": ..., "signatures": {...}}` object for `signed_curve25519`, but the
/// unsigned algorithm returns a bare string.
fn one_time_key_value(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => Some(s.as_str()),
        other => other.get("key").and_then(Value::as_str),
    }
}

fn room_key_envelope(
    content: &Value,
    our_user_id: &str,
    our_device_id: &str,
    our_ed_key: &str,
    device: &DeviceInfo,
) -> Value {
    let mut keys = Map::new();
    keys.insert("ed25519".to_string(), Value::String(our_ed_key.to_string()));
    let mut recipient_keys = Map::new();
    recipient_keys.insert("ed25519".to_string(), Value::String(device.ed_key.clone()));

    let mut envelope = Map::new();
    envelope.insert("content".to_string(), content.clone());
    envelope.insert("keys".to_string(), Value::Object(keys));
    envelope.insert(
        "recipient".to_string(),
        Value::String(device.user_id.clone()),
    );
    envelope.insert("recipient_keys".to_string(), Value::Object(recipient_keys));
    envelope.insert("sender".to_string(), Value::String(our_user_id.to_string()));
    envelope.insert(
        "sender_device".to_string(),
        Value::String(our_device_id.to_string()),
    );
    envelope.insert("type".to_string(), Value::String("m.room_key".to_string()));
    Value::Object(envelope)
}

fn olm_to_device_content(
    our_curve: &str,
    their_curve: &str,
    message_type: usize,
    body: &str,
) -> Value {
    let mut message = Map::new();
    message.insert("body".to_string(), Value::String(body.to_string()));
    message.insert("type".to_string(), Value::from(message_type as u64));

    let mut ciphertext = Map::new();
    ciphertext.insert(their_curve.to_string(), Value::Object(message));

    let mut content = Map::new();
    content.insert(
        "algorithm".to_string(),
        Value::String(OLM_ALGORITHM.to_string()),
    );
    content.insert("ciphertext".to_string(), Value::Object(ciphertext));
    content.insert(
        "sender_key".to_string(),
        Value::String(our_curve.to_string()),
    );
    Value::Object(content)
}

/// Matrix canonical JSON: keys sorted lexicographically, no insignificant
/// whitespace, `signatures` and `unsigned` removed from the top-level object.
///
/// `serde_json::Map` is a `BTreeMap` here (the `preserve_order` feature is not
/// enabled), so iteration is already in sorted key order; the writer below only
/// has to avoid whitespace and escape strings the same way the reference
/// implementation does.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Object(map) => {
            out.push('{');
            let mut first = true;
            for (key, entry) in map {
                if key == "signatures" || key == "unsigned" {
                    continue;
                }
                if !first {
                    out.push(',');
                }
                first = false;
                write_json_string(key, &mut out);
                out.push(':');
                write_canonical(entry, &mut out);
            }
            out.push('}');
        }
        other => write_canonical(other, &mut out),
    }
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (key, entry)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(entry, out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                for shift in [12u32, 8, 4, 0] {
                    let nibble = ((c as u32) >> shift) & 0xf;
                    out.push(char::from_digit(nibble, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------- SAS verification

/// Canonical JSON without the signing algorithm's redaction step.
///
/// [`canonical_json`] drops top-level `signatures` and `unsigned` because
/// everything it is used for is about to be signed. The SAS commitment is not:
/// it hashes the start event's content exactly as the other side serialised
/// it, so nothing may be removed.
fn canonical_json_verbatim(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

/// The info string a SAS MAC is keyed with. The MAC's sender comes first, then
/// the recipient, then the transaction, all run together without separators;
/// the caller appends either a key id or the literal `KEY_IDS`.
fn mac_info(
    sender_user: &str,
    sender_device: &str,
    other_user: &str,
    other_device: &str,
    transaction: &str,
) -> String {
    format!(
        "MATRIX_KEY_VERIFICATION_MAC{sender_user}{sender_device}\
         {other_user}{other_device}{transaction}"
    )
}

/// Check one base64 MAC. A MAC we cannot even decode is a failure, not an
/// error to bubble: either way the verification cannot continue.
fn verify_mac_b64(
    established: &EstablishedSas,
    input: &str,
    info: &str,
    mac_b64: &str,
) -> std::result::Result<(), ()> {
    let mac = Mac::from_base64(mac_b64).map_err(|_| ())?;
    established.verify_mac(input, info, &mac).map_err(|_| ())
}

/// FIPS 180-4 round constants.
#[rustfmt::skip]
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256, as the SAS commitment needs it.
///
/// This is hand-rolled on purpose. The daemon's dependency set is pinned, and
/// none of the eight crates it may name re-exports a hash: vodozemac keeps
/// `sha2` private (only HKDF/HMAC leak out, through `sas`), and `rusqlite` and
/// `ureq` pull `sha2`/`ring` in transitively, which Rust gives us no way to
/// name. Forty lines of FIPS 180-4 with the NIST vectors under test beats
/// widening the supply chain for one hash of about two hundred bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        sha256_block(&mut h, block);
    }

    // Padding: 0x80, zeroes, then the length in bits as a big-endian u64,
    // which needs one final block, or two when the remainder leaves no room.
    let rest = blocks.remainder();
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    let bit_len = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(64) {
        sha256_block(&mut h, block);
    }

    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// One 64 byte compression round. `block` is always exactly 64 bytes.
fn sha256_block(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for i in 16..64 {
        let x = w[i - 15];
        let y = w[i - 2];
        let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
        let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut i] = *h;
    for (round, k) in SHA256_K.iter().enumerate() {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = i
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(w[round]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        i = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, i]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct TempStore {
        path: std::path::PathBuf,
    }

    impl TempStore {
        fn new(tag: &str) -> TempStore {
            let nonce: u64 = rand::random();
            let path = std::env::temp_dir().join(format!("kmatrix-crypto-{tag}-{nonce:016x}.db"));
            TempStore { path }
        }

        fn open(&self) -> Store {
            match Store::open(&self.path) {
                Ok(s) => s,
                Err(e) => panic!("open test store: {e:#}"),
            }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn canonical_json_sorts_and_strips() {
        let value = json!({
            "user_id": "@a:x",
            "algorithms": ["b", "a"],
            "signatures": {"@a:x": {"ed25519:D": "sig"}},
            "unsigned": {"device_display_name": "kindle"},
            "device_id": "D",
        });
        assert_eq!(
            canonical_json(&value),
            r#"{"algorithms":["b","a"],"device_id":"D","user_id":"@a:x"}"#
        );

        // Nested objects sort too, and nested `signatures` is *not* stripped.
        let nested = json!({"b": 1, "a": {"z": 0, "signatures": 1}});
        assert_eq!(
            canonical_json(&nested),
            r#"{"a":{"signatures":1,"z":0},"b":1}"#
        );

        // Escaping matches the reference implementation.
        let escaped = json!({"k": "a\"b\n\u{1}"});
        assert_eq!(canonical_json(&escaped), "{\"k\":\"a\\\"b\\n\\u0001\"}");
    }

    #[test]
    fn megolm_round_trip() {
        let temp = TempStore::new("megolm");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };

        let room = "!room:example.org";
        assert!(!crypto.has_outbound(room));

        let envelope = json!({
            "type": "m.room.message",
            "room_id": room,
            "content": {"msgtype": "m.text", "body": "hello from the kindle"},
        });
        let encrypted = match crypto.encrypt(&store, room, &envelope, "@me:example.org", "DEV") {
            Ok(v) => v,
            Err(e) => panic!("encrypt: {e:#}"),
        };
        assert!(crypto.has_outbound(room));
        assert_eq!(encrypted["algorithm"], MEGOLM_ALGORITHM);
        assert_eq!(encrypted["device_id"], "DEV");
        assert_eq!(encrypted["sender_key"], crypto.curve25519_key().as_str());

        let session_id = match encrypted["session_id"].as_str() {
            Some(s) => s.to_string(),
            None => panic!("no session_id in encrypted content"),
        };
        let ciphertext = match encrypted["ciphertext"].as_str() {
            Some(s) => s.to_string(),
            None => panic!("no ciphertext in encrypted content"),
        };

        let plaintext = match crypto.decrypt(&session_id, &ciphertext) {
            Ok(p) => p,
            Err(e) => panic!("decrypt: {e:#}"),
        };
        let decoded: Value = match serde_json::from_str(&plaintext) {
            Ok(v) => v,
            Err(e) => panic!("parse plaintext: {e}"),
        };
        assert_eq!(decoded, envelope);

        let err = match crypto.decrypt("not-a-session", &ciphertext) {
            Ok(_) => panic!("decrypting with an unknown session must fail"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("unknown session"), "unexpected error: {err}");
    }

    #[test]
    fn account_survives_reload() {
        let temp = TempStore::new("account");

        let (curve, ed) = {
            let store = temp.open();
            let crypto = match Crypto::load_or_create(&store) {
                Ok(c) => c,
                Err(e) => panic!("create: {e:#}"),
            };
            (crypto.curve25519_key(), crypto.ed25519_key())
        };

        let store = temp.open();
        let crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("reload: {e:#}"),
        };
        assert_eq!(crypto.curve25519_key(), curve);
        assert_eq!(crypto.ed25519_key(), ed);
    }

    #[test]
    fn keys_upload_body_is_signed_and_tops_up() {
        let temp = TempStore::new("keys");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };

        let body = match crypto.keys_upload_body("@me:example.org", "DEV", 0, true) {
            Ok(Some(b)) => b,
            Ok(None) => panic!("expected an upload body"),
            Err(e) => panic!("keys_upload_body: {e:#}"),
        };

        let device_keys = &body["device_keys"];
        assert_eq!(
            device_keys["keys"]["curve25519:DEV"],
            crypto.curve25519_key()
        );

        let signature = match device_keys["signatures"]["@me:example.org"]["ed25519:DEV"].as_str() {
            Some(s) => s.to_string(),
            None => panic!("device keys are not signed"),
        };
        let signature = match vodozemac::Ed25519Signature::from_base64(&signature) {
            Ok(s) => s,
            Err(e) => panic!("bad signature encoding: {e}"),
        };
        let signed = canonical_json(device_keys);
        if let Err(e) = crypto
            .account
            .ed25519_key()
            .verify(signed.as_bytes(), &signature)
        {
            panic!("device key signature does not verify: {e}");
        }

        let otks = match body["one_time_keys"].as_object() {
            Some(m) => m,
            None => panic!("no one-time keys in upload body"),
        };
        assert_eq!(otks.len(), OTK_TARGET);
        for (id, key) in otks {
            assert!(id.starts_with("signed_curve25519:"), "bad key id {id}");
            assert!(key["key"].is_string());
            assert!(key["signatures"]["@me:example.org"]["ed25519:DEV"].is_string());
        }

        // Once the server has the target count and the device keys are known,
        // there is nothing left to upload.
        if let Err(e) = crypto.mark_published(&store) {
            panic!("mark_published: {e:#}");
        }
        match crypto.keys_upload_body("@me:example.org", "DEV", OTK_TARGET as u32, false) {
            Ok(None) => {}
            Ok(Some(b)) => panic!("expected no upload, got {b}"),
            Err(e) => panic!("keys_upload_body: {e:#}"),
        }
    }

    #[test]
    fn olm_key_sharing_round_trip() {
        // Two independent daemons, each with their own store: Alice shares a
        // room key with Bob over Olm and then sends him a Megolm message.
        let alice_temp = TempStore::new("alice");
        let bob_temp = TempStore::new("bob");
        let alice_store = alice_temp.open();
        let bob_store = bob_temp.open();

        let mut alice = match Crypto::load_or_create(&alice_store) {
            Ok(c) => c,
            Err(e) => panic!("alice: {e:#}"),
        };
        let mut bob = match Crypto::load_or_create(&bob_store) {
            Ok(c) => c,
            Err(e) => panic!("bob: {e:#}"),
        };

        // Bob publishes one-time keys; we feed one straight into a synthetic
        // /keys/claim response.
        let bob_upload = match bob.keys_upload_body("@bob:example.org", "BOB", 49, true) {
            Ok(Some(b)) => b,
            Ok(None) => panic!("bob had nothing to upload"),
            Err(e) => panic!("bob keys_upload_body: {e:#}"),
        };
        if let Err(e) = bob.mark_published(&bob_store) {
            panic!("bob mark_published: {e:#}");
        }
        let (otk_id, otk) = match bob_upload["one_time_keys"].as_object() {
            Some(m) => match m.iter().next() {
                Some((k, v)) => (k.clone(), v.clone()),
                None => panic!("bob uploaded no one-time keys"),
            },
            None => panic!("bob uploaded no one-time keys"),
        };
        assert!(otk_id.starts_with("signed_curve25519:"));

        let keys_query = json!({
            "device_keys": {
                "@bob:example.org": {
                    "BOB": bob_upload["device_keys"].clone(),
                },
            },
        });
        let devices = alice.parse_device_keys(&keys_query);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].curve_key, bob.curve25519_key());
        assert_eq!(devices[0].ed_key, bob.ed25519_key());

        let need = alice.devices_needing_session(&devices);
        assert_eq!(need.len(), 1);
        assert_eq!(
            Crypto::claim_body(&need),
            json!({"one_time_keys": {"@bob:example.org": {"BOB": "signed_curve25519"}}})
        );

        let claim = json!({
            "one_time_keys": {"@bob:example.org": {"BOB": {otk_id.clone(): otk}}},
        });
        if let Err(e) = alice.create_outbound_olm(&alice_store, &claim, &need) {
            panic!("create_outbound_olm: {e:#}");
        }
        assert!(alice.devices_needing_session(&devices).is_empty());

        let room = "!room:example.org";
        let messages = match alice.encrypt_room_key_to_devices(
            &alice_store,
            room,
            &devices,
            "@alice:example.org",
            "ALICE",
        ) {
            Ok(m) => m,
            Err(e) => panic!("encrypt_room_key_to_devices: {e:#}"),
        };
        let content = messages["@bob:example.org"]["BOB"].clone();
        assert_eq!(content["algorithm"], OLM_ALGORITHM);
        assert_eq!(content["sender_key"], alice.curve25519_key().as_str());
        assert_eq!(content["ciphertext"][bob.curve25519_key()]["type"], 0);

        let to_device = ToDeviceEvent {
            kind: "m.room.encrypted".to_string(),
            sender: "@alice:example.org".to_string(),
            content,
        };
        if let Err(e) = bob.handle_to_device(&bob_store, std::slice::from_ref(&to_device)) {
            panic!("handle_to_device: {e:#}");
        }

        let envelope = json!({
            "type": "m.room.message",
            "room_id": room,
            "content": {"msgtype": "m.text", "body": "over olm and megolm"},
        });
        let encrypted =
            match alice.encrypt(&alice_store, room, &envelope, "@alice:example.org", "ALICE") {
                Ok(v) => v,
                Err(e) => panic!("encrypt: {e:#}"),
            };
        let session_id = match encrypted["session_id"].as_str() {
            Some(s) => s.to_string(),
            None => panic!("no session id"),
        };
        let ciphertext = match encrypted["ciphertext"].as_str() {
            Some(s) => s.to_string(),
            None => panic!("no ciphertext"),
        };

        let plaintext = match bob.decrypt(&session_id, &ciphertext) {
            Ok(p) => p,
            Err(e) => panic!("bob could not decrypt: {e:#}"),
        };
        let decoded: Value = match serde_json::from_str(&plaintext) {
            Ok(v) => v,
            Err(e) => panic!("parse: {e}"),
        };
        assert_eq!(decoded, envelope);

        // Bob's inbound session survives a restart of his daemon.
        drop(bob);
        let bob_store = bob_temp.open();
        let mut bob = match Crypto::load_or_create(&bob_store) {
            Ok(c) => c,
            Err(e) => panic!("bob reload: {e:#}"),
        };
        let second =
            match alice.encrypt(&alice_store, room, &envelope, "@alice:example.org", "ALICE") {
                Ok(v) => v,
                Err(e) => panic!("second encrypt: {e:#}"),
            };
        let ciphertext = match second["ciphertext"].as_str() {
            Some(s) => s.to_string(),
            None => panic!("no ciphertext"),
        };
        if let Err(e) = bob.decrypt(&session_id, &ciphertext) {
            panic!("bob could not decrypt after reload: {e:#}");
        }
    }

    /// Base256 to base58, the inverse of [`base58_decode`]. Only the tests need
    /// this: the daemon never hands a recovery key back to anyone.
    fn base58_encode(bytes: &[u8]) -> String {
        let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            let mut carry = u32::from(byte);
            for digit in digits.iter_mut() {
                let acc = u32::from(*digit) * 256 + carry;
                *digit = (acc % 58) as u8;
                carry = acc / 58;
            }
            while carry != 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let mut out = String::with_capacity(digits.len() + 1);
        for _ in bytes.iter().take_while(|&&b| b == 0) {
            out.push('1');
        }
        for digit in digits.iter().rev() {
            match BASE58_ALPHABET.get(usize::from(*digit)) {
                Some(c) => out.push(char::from(*c)),
                None => panic!("base58 digit {digit} out of range"),
            }
        }
        out
    }

    /// The 35 byte recovery key blob for a private key: prefix, key, parity.
    fn recovery_blob(key: &[u8; 32]) -> [u8; RECOVERY_KEY_LEN] {
        let mut blob = [0u8; RECOVERY_KEY_LEN];
        blob[0] = RECOVERY_KEY_PREFIX[0];
        blob[1] = RECOVERY_KEY_PREFIX[1];
        blob[2..34].copy_from_slice(key);
        blob[34] = blob[..34].iter().fold(0u8, |acc, b| acc ^ b);
        blob
    }

    fn group_in_fours(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + s.len() / 4);
        for (i, c) in s.chars().enumerate() {
            if i != 0 && i % 4 == 0 {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }

    fn expect_recovery_error(encoded: &str) -> String {
        match decode_recovery_key(encoded) {
            Ok(_) => panic!("decode_recovery_key accepted {encoded}"),
            Err(e) => format!("{e:#}"),
        }
    }

    fn backup_public_key(key: &[u8; 32]) -> String {
        PkDecryption::from_key(Curve25519SecretKey::from_slice(key))
            .public_key()
            .to_base64()
    }

    /// Build the object a homeserver stores for one backed up session: the key
    /// JSON encrypted to the backup's public key with the same hybrid scheme
    /// the daemon has to undo.
    fn backup_entry(public_key: &str, plaintext: &Value, first_message_index: u64) -> Value {
        use vodozemac::pk_encryption::PkEncryption;

        let public = match Curve25519PublicKey::from_base64(public_key) {
            Ok(k) => k,
            Err(e) => panic!("bad backup public key: {e}"),
        };
        let raw = match serde_json::to_vec(plaintext) {
            Ok(v) => v,
            Err(e) => panic!("serialize backup plaintext: {e}"),
        };
        let message = match PkEncryption::from_key(public).encrypt(&raw) {
            Ok(m) => m,
            Err(e) => panic!("encrypt backup session: {e}"),
        };
        json!({
            "first_message_index": first_message_index,
            "forwarded_count": 0,
            "is_verified": true,
            "session_data": {
                "ciphertext": vodozemac::base64_encode(&message.ciphertext),
                "mac": vodozemac::base64_encode(&message.mac),
                "ephemeral": message.ephemeral_key.to_base64(),
            },
        })
    }

    /// The round-trip test below pairs our decoder with our own test encoder,
    /// so a shared misunderstanding would cancel out. These are the classic
    /// Bitcoin base58 vectors, which pin the encoding down from the outside.
    #[test]
    fn base58_matches_the_bitcoin_vectors() {
        let vectors: [(&[u8], &str); 5] = [
            (b"a", "2g"),
            (b"bbb", "a3gV"),
            (b"ccc", "aPEr"),
            (b"simply a long string", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
            (&[0x00, 0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd], "111233QC4"),
        ];
        for (bytes, encoded) in vectors {
            match base58_decode(encoded) {
                Ok(decoded) => assert_eq!(decoded, bytes, "decoding {encoded}"),
                Err(e) => panic!("base58_decode({encoded}): {e:#}"),
            }
            assert_eq!(base58_encode(bytes), encoded, "encoding {encoded}");
        }

        match base58_decode("1") {
            Ok(decoded) => assert_eq!(decoded, [0u8], "'1' is the zero digit"),
            Err(e) => panic!("base58_decode(1): {e:#}"),
        }
    }

    #[test]
    fn recovery_key_round_trip_and_rejections() {
        let key: [u8; 32] = rand::random();
        let encoded = base58_encode(&recovery_blob(&key));
        match decode_recovery_key(&encoded) {
            Ok(decoded) => assert_eq!(decoded, key),
            Err(e) => panic!("decode_recovery_key: {e:#}"),
        }

        // Wrong prefix, with the parity byte fixed up so that the prefix is
        // unambiguously what gets rejected.
        let mut blob = recovery_blob(&key);
        blob[0] = 0x8c;
        blob[34] ^= 0x8b ^ 0x8c;
        let err = expect_recovery_error(&base58_encode(&blob));
        assert!(err.contains("not a Matrix recovery key"), "{err}");

        // Bad parity: one bit off in the parity byte itself.
        let mut blob = recovery_blob(&key);
        blob[34] ^= 0x01;
        let err = expect_recovery_error(&base58_encode(&blob));
        assert!(err.contains("parity"), "{err}");

        // Wrong length: 34 bytes instead of 35.
        let blob = recovery_blob(&key);
        let err = expect_recovery_error(&base58_encode(&blob[..34]));
        assert!(err.contains("expected 35"), "{err}");

        // '0' is not in the base58 alphabet.
        let err = expect_recovery_error(&format!("0{encoded}"));
        assert!(err.contains("not a valid base58 character"), "{err}");

        let err = expect_recovery_error("   ");
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn recovery_key_ignores_grouping() {
        let key: [u8; 32] = rand::random();
        let encoded = base58_encode(&recovery_blob(&key));
        let grouped = group_in_fours(&encoded);
        assert!(grouped.contains(' '));
        assert_ne!(grouped, encoded);

        match decode_recovery_key(&grouped) {
            Ok(decoded) => assert_eq!(decoded, key),
            Err(e) => panic!("grouped recovery key rejected: {e:#}"),
        }
        match decode_recovery_key(&format!("\n {grouped} \t\n")) {
            Ok(decoded) => assert_eq!(decoded, key),
            Err(e) => panic!("surrounding whitespace rejected: {e:#}"),
        }
    }

    #[test]
    fn set_backup_key_checks_the_public_key() {
        let temp = TempStore::new("backup-key");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };
        assert!(!crypto.has_backup_key());

        let key: [u8; 32] = rand::random();
        let recovery = base58_encode(&recovery_blob(&key));
        let other: [u8; 32] = rand::random();

        // A valid recovery key for a *different* backup must not be accepted.
        let err = match crypto.set_backup_key(&store, &recovery, &backup_public_key(&other)) {
            Ok(()) => panic!("a recovery key for another backup was accepted"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("does not match this backup"), "{err}");
        assert!(!crypto.has_backup_key());

        // Padded base64 from the server is still the same key.
        let padded = format!("{}=", backup_public_key(&key));
        if let Err(e) = crypto.set_backup_key(&store, &recovery, &padded) {
            panic!("set_backup_key: {e:#}");
        }
        assert!(crypto.has_backup_key());

        // And it survives a restart of the daemon.
        drop(crypto);
        let store = temp.open();
        let crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("reload: {e:#}"),
        };
        assert!(crypto.has_backup_key());
    }

    #[test]
    fn backup_session_import_round_trip() {
        let temp = TempStore::new("backup-import");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };

        let key: [u8; 32] = rand::random();
        let public = backup_public_key(&key);
        let recovery = base58_encode(&recovery_blob(&key));
        if let Err(e) = crypto.set_backup_key(&store, &recovery, &public) {
            panic!("set_backup_key: {e:#}");
        }

        // A session from a device we have never talked to, of the kind that
        // predates this device entirely.
        let room = "!backup:example.org";
        let mut sender = GroupSession::new(MegolmConfig::version_1());
        let mut sender_inbound = InboundGroupSession::from(&sender);
        let session_id = sender_inbound.session_id();
        let exported = sender_inbound.export_at_first_known_index().to_base64();

        let first = sender.encrypt(b"{\"body\":\"first\"}").to_base64();
        let envelope = json!({
            "type": "m.room.message",
            "room_id": room,
            "content": {"msgtype": "m.text", "body": "from before this device existed"},
        });
        let raw = match serde_json::to_vec(&envelope) {
            Ok(v) => v,
            Err(e) => panic!("serialize envelope: {e}"),
        };
        let second = sender.encrypt(&raw).to_base64();

        // Before the import there is no session at all.
        let err = match crypto.decrypt(&session_id, &first) {
            Ok(_) => panic!("decrypted without the session"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("unknown session"), "{err}");

        let plaintext = json!({
            "algorithm": MEGOLM_ALGORITHM,
            "sender_key": crypto.curve25519_key(),
            "sender_claimed_keys": {"ed25519": crypto.ed25519_key()},
            "forwarding_curve25519_key_chain": [],
            "session_key": exported,
        });
        let entry = backup_entry(&public, &plaintext, 0);

        match crypto.import_backup_session(&store, room, &session_id, &entry) {
            Ok(true) => {}
            Ok(false) => panic!("a session we did not have was not imported"),
            Err(e) => panic!("import_backup_session: {e:#}"),
        }

        // The imported session decrypts from the very first message index.
        match crypto.decrypt(&session_id, &first) {
            Ok(p) => assert_eq!(p, "{\"body\":\"first\"}"),
            Err(e) => panic!("decrypt after import: {e:#}"),
        }

        // Re-importing the same entry changes nothing.
        match crypto.import_backup_session(&store, room, &session_id, &entry) {
            Ok(false) => {}
            Ok(true) => panic!("re-imported a session we already had"),
            Err(e) => panic!("second import: {e:#}"),
        }

        // A backup entry that starts at a later index must not replace the one
        // we hold: that would forget the messages in between.
        let late_key = match sender_inbound.export_at(2) {
            Some(k) => k.to_base64(),
            None => panic!("could not export at index 2"),
        };
        let mut late_plaintext = plaintext.clone();
        late_plaintext["session_key"] = Value::String(late_key);
        let late_entry = backup_entry(&public, &late_plaintext, 2);
        match crypto.import_backup_session(&store, room, &session_id, &late_entry) {
            Ok(false) => {}
            Ok(true) => panic!("a later-index session replaced an earlier one"),
            Err(e) => panic!("late import: {e:#}"),
        }
        let plain = match crypto.decrypt(&session_id, &second) {
            Ok(p) => p,
            Err(e) => panic!("decrypt at index 1 after the late entry: {e:#}"),
        };
        match serde_json::from_str::<Value>(&plain) {
            Ok(v) => assert_eq!(v, envelope),
            Err(e) => panic!("parse plaintext: {e}"),
        }

        // A non-Megolm backup entry is skipped, not an error.
        let mut other_algorithm = plaintext.clone();
        other_algorithm["algorithm"] = Value::String("m.something.else".to_string());
        let other_entry = backup_entry(&public, &other_algorithm, 0);
        match crypto.import_backup_session(&store, "!other:example.org", "other-id", &other_entry) {
            Ok(false) => {}
            Ok(true) => panic!("imported a non-megolm backup entry"),
            Err(e) => panic!("unexpected error for a foreign algorithm: {e:#}"),
        }

        // Without a recovery key there is nothing to try.
        let bare_temp = TempStore::new("backup-none");
        let bare_store = bare_temp.open();
        let mut bare = match Crypto::load_or_create(&bare_store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };
        assert!(!bare.has_backup_key());
        let err = match bare.import_backup_session(&bare_store, room, &session_id, &entry) {
            Ok(_) => panic!("imported without a backup key"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("no backup recovery key"), "{err}");

        // The imported session survives a restart.
        drop(crypto);
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("reload: {e:#}"),
        };
        let third = sender.encrypt(b"{\"body\":\"third\"}").to_base64();
        match crypto.decrypt(&session_id, &third) {
            Ok(p) => assert_eq!(p, "{\"body\":\"third\"}"),
            Err(e) => panic!("decrypt after reload: {e:#}"),
        }
    }

    // ----------------------------------------------------- SAS verification

    const OUR_USER: &str = "@me:example.org";
    const OUR_DEVICE: &str = "KINDLE";
    const THEIR_DEVICE: &str = "ELEMENT";

    /// The other end of a verification, driven by hand out of vodozemac.
    struct Initiator {
        account: Account,
        sas: Option<Sas>,
        established: Option<EstablishedSas>,
    }

    impl Initiator {
        fn new() -> Initiator {
            Initiator {
                account: Account::new(),
                sas: Some(Sas::new()),
                established: None,
            }
        }

        fn device(&self) -> DeviceInfo {
            DeviceInfo {
                user_id: OUR_USER.to_string(),
                device_id: THEIR_DEVICE.to_string(),
                curve_key: self.account.curve25519_key().to_base64(),
                ed_key: self.account.ed25519_key().to_base64(),
            }
        }

        fn public_key(&self) -> String {
            match &self.sas {
                Some(sas) => sas.public_key().to_base64(),
                None => match &self.established {
                    Some(e) => e.our_public_key().to_base64(),
                    None => panic!("initiator has no ephemeral key"),
                },
            }
        }

        fn dh(&mut self, our_key: &str) {
            let sas = match self.sas.take() {
                Some(sas) => sas,
                None => panic!("initiator already did the exchange"),
            };
            match sas.diffie_hellman_with_raw(our_key) {
                Ok(e) => self.established = Some(e),
                Err(e) => panic!("initiator diffie-hellman: {e}"),
            }
        }

        fn established(&self) -> &EstablishedSas {
            match &self.established {
                Some(e) => e,
                None => panic!("initiator has not done the exchange"),
            }
        }
    }

    fn start_content(transaction: &str) -> Value {
        json!({
            "from_device": THEIR_DEVICE,
            "method": SAS_METHOD,
            "transaction_id": transaction,
            "key_agreement_protocols": ["curve25519-hkdf-sha256"],
            "hashes": ["sha256"],
            "message_authentication_codes": ["hkdf-hmac-sha256", "hkdf-hmac-sha256.v2"],
            "short_authentication_string": ["decimal", "emoji"],
        })
    }

    fn feed(crypto: &mut Crypto, kind: &str, content: &Value) -> VerifyStep {
        match crypto.handle_verification(OUR_USER, OUR_DEVICE, OUR_USER, kind, content) {
            Ok(step) => step,
            Err(e) => panic!("handle_verification({kind}): {e:#}"),
        }
    }

    fn only_send<'a>(step: &'a VerifyStep, kind: &str) -> &'a Value {
        match step.send.as_slice() {
            [(sent_kind, device, content)] if sent_kind == kind && device == THEIR_DEVICE => {
                content
            }
            other => panic!("expected a single {kind}, got {} events", other.len()),
        }
    }

    /// Walk request -> ready -> start -> accept -> key -> key, and hand back
    /// the accept content plus the emoji we would show.
    fn run_to_emoji(
        crypto: &mut Crypto,
        initiator: &mut Initiator,
        transaction: &str,
    ) -> (Value, [u8; 7]) {
        let request = json!({
            "from_device": THEIR_DEVICE,
            "methods": [SAS_METHOD],
            "transaction_id": transaction,
            "timestamp": 1_700_000_000_000u64,
        });
        let ready = feed(crypto, "m.key.verification.request", &request);
        let content = only_send(&ready, "m.key.verification.ready");
        assert_eq!(content["from_device"], OUR_DEVICE);
        assert_eq!(content["methods"], json!([SAS_METHOD]));

        let start = start_content(transaction);
        let accepted = feed(crypto, "m.key.verification.start", &start);
        let accept = only_send(&accepted, "m.key.verification.accept").clone();
        assert_eq!(accept["key_agreement_protocol"], KEY_AGREEMENT_PROTOCOL);
        assert_eq!(accept["hash"], SAS_HASH);
        assert_eq!(accept["message_authentication_code"], MAC_METHOD);
        assert_eq!(accept["short_authentication_string"], json!(["emoji"]));

        let their_key = initiator.public_key();
        let keyed = feed(
            crypto,
            "m.key.verification.key",
            &json!({"transaction_id": transaction, "key": their_key}),
        );
        let our_key = match only_send(&keyed, "m.key.verification.key")["key"].as_str() {
            Some(k) => k.to_string(),
            None => panic!("our key event carries no key"),
        };
        let (txn, device, indices) = match keyed.emoji {
            Some(e) => e,
            None => panic!("no emoji after the key exchange"),
        };
        assert_eq!(txn, transaction);
        assert_eq!(device, THEIR_DEVICE);

        // The commitment we published must be the spec's hash of the key we
        // have only now revealed, over the start content byte for byte.
        let mut committed = our_key.clone().into_bytes();
        committed.extend_from_slice(canonical_json_verbatim(&start).as_bytes());
        assert_eq!(
            accept["commitment"],
            Value::String(vodozemac::base64_encode(sha256(&committed)))
        );

        initiator.dh(&our_key);
        let info = format!(
            "MATRIX_KEY_VERIFICATION_SAS|{OUR_USER}|{THEIR_DEVICE}|{their_key}\
             |{OUR_USER}|{OUR_DEVICE}|{our_key}|{transaction}"
        );
        assert_eq!(
            initiator.established().bytes(&info).emoji_indices(),
            indices
        );

        (accept, indices)
    }

    fn initiator_mac_content(initiator: &Initiator, transaction: &str) -> Value {
        let info = mac_info(OUR_USER, THEIR_DEVICE, OUR_USER, OUR_DEVICE, transaction);
        let key_id = format!("ed25519:{THEIR_DEVICE}");
        let their_ed = initiator.account.ed25519_key().to_base64();
        json!({
            "transaction_id": transaction,
            "keys": initiator
                .established()
                .calculate_mac(&key_id, &format!("{info}KEY_IDS"))
                .to_base64(),
            "mac": {
                key_id.clone(): initiator
                    .established()
                    .calculate_mac(&their_ed, &format!("{info}{key_id}"))
                    .to_base64(),
            },
        })
    }

    #[test]
    fn sas_verification_round_trip() {
        let temp = TempStore::new("sas");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };
        let mut initiator = Initiator::new();
        crypto.remember_devices(&[initiator.device()]);

        let transaction = "kmatrix-sas-1";
        let (_accept, indices) = run_to_emoji(&mut crypto, &mut initiator, transaction);
        assert!(indices.iter().all(|i| *i < 64));

        // Their MAC lands before the user has looked at the screen.
        let their_mac = initiator_mac_content(&initiator, transaction);
        let step = feed(&mut crypto, "m.key.verification.mac", &their_mac);
        assert!(step.send.is_empty(), "a valid MAC must not be answered yet");
        assert!(step.cancelled.is_none());
        assert!(step.done.is_none());

        // The user says the emoji match.
        let confirmed = match crypto.confirm_verification(OUR_USER, OUR_DEVICE, transaction, true) {
            Ok(step) => step,
            Err(e) => panic!("confirm_verification: {e:#}"),
        };
        assert!(confirmed.done.is_none(), "they have not said done yet");
        let kinds: Vec<&str> = confirmed
            .send
            .iter()
            .map(|(kind, _, _)| kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            vec!["m.key.verification.mac", "m.key.verification.done"]
        );

        // Our MAC must verify on the initiator's side.
        let our_mac = &confirmed.send[0].2;
        let info = mac_info(OUR_USER, OUR_DEVICE, OUR_USER, THEIR_DEVICE, transaction);
        let key_id = format!("ed25519:{OUR_DEVICE}");
        let our_ed = crypto.ed25519_key();
        let sent_mac = match our_mac["mac"][&key_id].as_str() {
            Some(m) => m.to_string(),
            None => panic!("our MAC event has no entry for {key_id}"),
        };
        let sent_keys = match our_mac["keys"].as_str() {
            Some(m) => m.to_string(),
            None => panic!("our MAC event has no keys MAC"),
        };
        if verify_mac_b64(
            initiator.established(),
            &our_ed,
            &format!("{info}{key_id}"),
            &sent_mac,
        )
        .is_err()
        {
            panic!("the initiator could not verify our device key MAC");
        }
        if verify_mac_b64(
            initiator.established(),
            &key_id,
            &format!("{info}KEY_IDS"),
            &sent_keys,
        )
        .is_err()
        {
            panic!("the initiator could not verify our key id MAC");
        }

        let finished = feed(
            &mut crypto,
            "m.key.verification.done",
            &json!({"transaction_id": transaction}),
        );
        assert_eq!(finished.done.as_deref(), Some(THEIR_DEVICE));
        assert!(crypto.verifications.is_empty());
    }

    #[test]
    fn sas_commitment_binds_our_key_and_the_start_content() {
        // We are always the responder, so we *publish* the commitment and
        // never receive one: `m.key.verification.accept` is the only event
        // that carries the field, and only an initiator is sent an accept.
        // What can go wrong on our side is a commitment that does not pin
        // down our ephemeral key or the exact start we answered, which is
        // what the initiator checks and what is asserted here.
        let temp = TempStore::new("sas-commit");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };
        let mut initiator = Initiator::new();
        crypto.remember_devices(&[initiator.device()]);

        let transaction = "kmatrix-sas-commit";
        let (accept, _) = run_to_emoji(&mut crypto, &mut initiator, transaction);
        let commitment = match accept["commitment"].as_str() {
            Some(c) => c.to_string(),
            None => panic!("the accept carries no commitment"),
        };

        // One extra field in the start, and the commitment no longer matches:
        // an initiator that saw a different start would reject us.
        let mut tampered = start_content(transaction);
        tampered["hashes"] = json!(["sha256", "sha3-256"]);
        let our_key = match crypto.verifications.get(transaction) {
            Some(entry) => match &entry.our_public_key {
                Some(k) => k.clone(),
                None => panic!("no ephemeral key recorded"),
            },
            None => panic!("the transaction disappeared"),
        };
        let mut committed = our_key.into_bytes();
        committed.extend_from_slice(canonical_json_verbatim(&tampered).as_bytes());
        assert_ne!(commitment, vodozemac::base64_encode(sha256(&committed)));

        // A different ephemeral key does not match either.
        let mut other = Sas::new().public_key().to_base64().into_bytes();
        other.extend_from_slice(canonical_json_verbatim(&start_content(transaction)).as_bytes());
        assert_ne!(commitment, vodozemac::base64_encode(sha256(&other)));
    }

    #[test]
    fn sas_rejects_an_unusable_start() {
        let temp = TempStore::new("sas-start");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };

        let transaction = "kmatrix-sas-bad-start";
        feed(
            &mut crypto,
            "m.key.verification.request",
            &json!({
                "from_device": THEIR_DEVICE,
                "methods": [SAS_METHOD],
                "transaction_id": transaction,
            }),
        );

        // Only the libolm-buggy MAC version on offer: nothing to negotiate.
        let mut start = start_content(transaction);
        start["message_authentication_codes"] = json!(["hkdf-hmac-sha256"]);
        let step = feed(&mut crypto, "m.key.verification.start", &start);
        let cancel = only_send(&step, "m.key.verification.cancel");
        assert_eq!(cancel["code"], "m.unknown_method");
        assert!(step.emoji.is_none());
        assert!(step.cancelled.is_some());
        assert!(crypto.verifications.is_empty());
    }

    #[test]
    fn sas_rejects_a_forged_mac() {
        let temp = TempStore::new("sas-mac");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };
        let mut initiator = Initiator::new();
        crypto.remember_devices(&[initiator.device()]);

        let transaction = "kmatrix-sas-mac";
        run_to_emoji(&mut crypto, &mut initiator, transaction);

        // A MAC taken over somebody else's ed25519 key.
        let info = mac_info(OUR_USER, THEIR_DEVICE, OUR_USER, OUR_DEVICE, transaction);
        let key_id = format!("ed25519:{THEIR_DEVICE}");
        let impostor = Account::new().ed25519_key().to_base64();
        let forged = json!({
            "transaction_id": transaction,
            "keys": initiator
                .established()
                .calculate_mac(&key_id, &format!("{info}KEY_IDS"))
                .to_base64(),
            "mac": {
                key_id.clone(): initiator
                    .established()
                    .calculate_mac(&impostor, &format!("{info}{key_id}"))
                    .to_base64(),
            },
        });

        let step = feed(&mut crypto, "m.key.verification.mac", &forged);
        let cancel = only_send(&step, "m.key.verification.cancel");
        assert_eq!(cancel["code"], "m.key_mismatch");
        assert!(step.done.is_none());
        assert!(crypto.verifications.is_empty());
    }

    #[test]
    fn refusing_the_emoji_cancels_without_a_mac() {
        let temp = TempStore::new("sas-refuse");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };
        let mut initiator = Initiator::new();
        crypto.remember_devices(&[initiator.device()]);

        let transaction = "kmatrix-sas-refuse";
        run_to_emoji(&mut crypto, &mut initiator, transaction);

        let step = match crypto.confirm_verification(OUR_USER, OUR_DEVICE, transaction, false) {
            Ok(step) => step,
            Err(e) => panic!("confirm_verification(false): {e:#}"),
        };
        let cancel = only_send(&step, "m.key.verification.cancel");
        assert_eq!(cancel["code"], "m.mismatched_sas");
        assert_eq!(cancel["transaction_id"], transaction);
        assert!(step.done.is_none());
        assert!(step.cancelled.is_some());
        assert!(crypto.verifications.is_empty());
    }

    #[test]
    fn unknown_transactions_are_ignored() {
        let temp = TempStore::new("sas-unknown");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };

        // Element sends its request to every device and cancels the losers, so
        // a transaction we never took part in must not provoke a reply.
        let stranger = "someone-elses-transaction";
        for (kind, content) in [
            (
                "m.key.verification.key",
                json!({"transaction_id": stranger, "key": Sas::new().public_key().to_base64()}),
            ),
            (
                "m.key.verification.mac",
                json!({"transaction_id": stranger, "keys": "AA", "mac": {}}),
            ),
            (
                "m.key.verification.done",
                json!({"transaction_id": stranger}),
            ),
            (
                "m.key.verification.cancel",
                json!({"transaction_id": stranger, "code": "m.accepted"}),
            ),
            (
                "m.key.verification.accept",
                json!({"transaction_id": stranger, "commitment": "AA"}),
            ),
        ] {
            let step = feed(&mut crypto, kind, &content);
            assert!(step.send.is_empty(), "{kind} produced a reply");
            assert!(step.emoji.is_none(), "{kind} produced emoji");
            assert!(step.done.is_none(), "{kind} completed something");
            assert!(step.cancelled.is_none(), "{kind} cancelled something");
        }
        assert!(crypto.verifications.is_empty());

        // Contents we cannot route anywhere are equally uninteresting: no
        // transaction id, or a start that names no device to answer.
        for content in [json!({}), json!({"transaction_id": stranger})] {
            let step = feed(&mut crypto, "m.key.verification.start", &content);
            assert!(step.send.is_empty());
            assert!(crypto.verifications.is_empty());
        }

        // A `start` that does name its device is a legal opening move even
        // without the request/ready round trip, so it is adopted.
        let step = feed(
            &mut crypto,
            "m.key.verification.start",
            &start_content(stranger),
        );
        let accept = only_send(&step, "m.key.verification.accept");
        assert_eq!(accept["transaction_id"], stranger);
        assert!(crypto.verifications.contains_key(stranger));
    }

    // ----------------------------------------------------------- secrets

    #[test]
    fn backup_key_from_a_shared_secret() {
        let temp = TempStore::new("secret-backup");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };

        let secret_bytes: [u8; 32] = rand::random();
        let decryption = PkDecryption::from_key(Curve25519SecretKey::from_slice(&secret_bytes));
        let public = decryption.public_key().to_base64();
        let padded = base64::engine::general_purpose::STANDARD.encode(secret_bytes);
        let unpadded = padded.trim_end_matches('=').to_string();

        assert!(!crypto.has_backup_key());
        match crypto.set_backup_key_base64(&store, &padded, Some(&public)) {
            Ok(()) => {}
            Err(e) => panic!("padded secret rejected: {e:#}"),
        }
        assert!(crypto.has_backup_key());

        // Both spellings land on the same `meta` row as the typed recovery
        // key, so a restart cannot tell the two entry points apart.
        match crypto.set_backup_key_base64(&store, &unpadded, Some(&public)) {
            Ok(()) => {}
            Err(e) => panic!("unpadded secret rejected: {e:#}"),
        }
        match store.get_meta(BACKUP_KEY_META) {
            Ok(Some(stored)) => assert_eq!(stored, padded),
            Ok(None) => panic!("the backup key was not persisted"),
            Err(e) => panic!("get_meta: {e:#}"),
        }

        let other: [u8; 32] = rand::random();
        let other_public = PkDecryption::from_key(Curve25519SecretKey::from_slice(&other))
            .public_key()
            .to_base64();
        let err = match crypto.set_backup_key_base64(
            &store,
            &base64::engine::general_purpose::STANDARD.encode(other),
            Some(&public),
        ) {
            Ok(()) => panic!("a secret for a different backup was accepted"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains(&other_public), "unexpected error: {err}");

        let err = match crypto.set_backup_key_base64(&store, "c2hvcnQ=", Some(&public)) {
            Ok(()) => panic!("a short secret was accepted"),
            Err(e) => format!("{e:#}"),
        };
        assert!(err.contains("expected 32"), "unexpected error: {err}");
    }

    #[test]
    fn secret_request_round_trip() {
        let temp = TempStore::new("secret-share");
        let store = temp.open();
        let mut crypto = match Crypto::load_or_create(&store) {
            Ok(c) => c,
            Err(e) => panic!("load_or_create: {e:#}"),
        };

        let (request_id, content) = crypto.secret_request(OUR_DEVICE, MEGOLM_BACKUP_SECRET);
        assert_eq!(content["action"], "request");
        assert_eq!(content["name"], MEGOLM_BACKUP_SECRET);
        assert_eq!(content["requesting_device_id"], OUR_DEVICE);
        assert_eq!(content["request_id"], request_id.as_str());

        let cancellation = crypto.secret_cancellation(OUR_DEVICE, &request_id);
        assert_eq!(cancellation["action"], "request_cancellation");
        assert_eq!(cancellation["request_id"], request_id.as_str());
        assert_eq!(cancellation["requesting_device_id"], OUR_DEVICE);

        // A real Olm channel from our "other device" back to us.
        let our_curve = crypto.curve25519_key();
        let otk = match crypto.keys_upload_body(OUR_USER, OUR_DEVICE, 0, false) {
            Ok(Some(body)) => match body["one_time_keys"].as_object() {
                Some(keys) => match keys.values().next().and_then(one_time_key_value) {
                    Some(k) => k.to_string(),
                    None => panic!("no one-time key in the upload body"),
                },
                None => panic!("no one_time_keys in the upload body"),
            },
            Ok(None) => panic!("expected an upload body"),
            Err(e) => panic!("keys_upload_body: {e:#}"),
        };

        let peer = Account::new();
        let identity = match Curve25519PublicKey::from_base64(&our_curve) {
            Ok(k) => k,
            Err(e) => panic!("our curve key: {e}"),
        };
        let one_time_key = match Curve25519PublicKey::from_base64(&otk) {
            Ok(k) => k,
            Err(e) => panic!("our one-time key: {e}"),
        };
        let mut session =
            match peer.create_outbound_session(OlmConfig::version_1(), identity, one_time_key) {
                Ok(s) => s,
                Err(e) => panic!("create_outbound_session: {e}"),
            };
        let peer_curve = peer.curve25519_key().to_base64();

        let secret = "cHJldGVuZC10aGlzLWlzLWEtYmFja3VwLWtleQ";
        let deliver = |session: &mut Session, plaintext: &Value| -> ToDeviceEvent {
            let raw = match serde_json::to_vec(plaintext) {
                Ok(v) => v,
                Err(e) => panic!("serialize: {e}"),
            };
            let message = match session.encrypt(&raw) {
                Ok(m) => m,
                Err(e) => panic!("olm encrypt: {e}"),
            };
            let (message_type, body) = message.to_parts();
            ToDeviceEvent {
                kind: "m.room.encrypted".to_string(),
                sender: OUR_USER.to_string(),
                content: olm_to_device_content(
                    &peer_curve,
                    &our_curve,
                    message_type,
                    &vodozemac::base64_encode(body),
                ),
            }
        };

        let event = deliver(
            &mut session,
            &json!({
                "type": "m.secret.send",
                "sender": OUR_USER,
                "content": {"request_id": request_id, "secret": secret},
            }),
        );
        let outcomes = match crypto.handle_to_device(&store, &[event]) {
            Ok(o) => o,
            Err(e) => panic!("handle_to_device: {e:#}"),
        };
        match outcomes.as_slice() {
            [ToDeviceOutcome::Secret {
                name,
                secret: got,
                request_id: got_id,
            }] => {
                assert_eq!(name, MEGOLM_BACKUP_SECRET);
                assert_eq!(got, secret);
                assert_eq!(got_id, &request_id);
            }
            other => panic!("expected one shared secret, got {}", other.len()),
        }

        // A secret answering a request id we never issued is dropped.
        let stray = deliver(
            &mut session,
            &json!({
                "type": "m.secret.send",
                "sender": OUR_USER,
                "content": {"request_id": "deadbeef", "secret": secret},
            }),
        );
        match crypto.handle_to_device(&store, &[stray]) {
            Ok(o) => assert!(o.is_empty(), "an unsolicited secret was accepted"),
            Err(e) => panic!("handle_to_device: {e:#}"),
        }
    }

    // ---------------------------------------------------------------- sha256

    #[test]
    fn sha256_matches_the_nist_vectors() {
        let hex = |bytes: [u8; 32]| -> String {
            let mut s = String::with_capacity(64);
            for byte in bytes {
                s.push_str(&format!("{byte:02x}"));
            }
            s
        };

        // Empty input, one block, and both padding shapes: 56 bytes needs a
        // second block for the length, 64 bytes leaves no remainder at all.
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(sha256(&[b'a'; 64])),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
        assert_eq!(
            hex(sha256(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                    .iter()
                    .copied()
                    .filter(|b| *b != b' ')
                    .collect::<Vec<u8>>()
                    .as_slice()
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }
}
