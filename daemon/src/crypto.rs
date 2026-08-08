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

/// One remote device, as far as we need to know it to send it a room key.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub user_id: String,
    pub device_id: String,
    pub curve_key: String,
    pub ed_key: String,
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
    pub fn handle_to_device(&mut self, store: &Store, events: &[ToDeviceEvent]) -> Result<()> {
        for event in events {
            if event.kind != "m.room.encrypted" {
                continue;
            }
            if let Err(e) = self.handle_olm_event(store, event) {
                eprintln!(
                    "kmatrixd: to-device event from {} dropped: {e:#}",
                    event.sender
                );
            }
        }
        Ok(())
    }

    fn handle_olm_event(&mut self, store: &Store, event: &ToDeviceEvent) -> Result<()> {
        let content = &event.content;
        if content.get("algorithm").and_then(Value::as_str) != Some(OLM_ALGORITHM) {
            return Ok(());
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
    ) -> Result<()> {
        let event: Value = serde_json::from_slice(plaintext).context("parse olm plaintext")?;
        if event.get("type").and_then(Value::as_str) != Some("m.room_key") {
            // m.dummy, m.forwarded_room_key, verification traffic: nothing we
            // act on, and nothing worth an error.
            return Ok(());
        }
        let content = event
            .get("content")
            .ok_or_else(|| anyhow!("m.room_key without content"))?;
        if content.get("algorithm").and_then(Value::as_str) != Some(MEGOLM_ALGORITHM) {
            return Ok(());
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
        Ok(())
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
}
