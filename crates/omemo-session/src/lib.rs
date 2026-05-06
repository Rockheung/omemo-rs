//! SQLite-backed persistence for OMEMO 2.
//!
//! Tables:
//! * `identity` — own JID + device id + 32-byte IK seed (single row).
//! * `signed_prekey` — id, priv, pub, sig, created_at, replaced_at.
//! * `prekey` — id, priv, pub, consumed (0/1), created_at.
//! * `device_list` — peer device IDs per JID.
//! * `session` — `TwomemoSessionSnapshot::encode()` BLOB per peer device.
//! * `message_keys_skipped` — for late delivery (Stage 5+, schema only here).
//!
//! Migration model: forward-only SQL files in `migrations/`. The `Store`
//! constructor runs any new migrations on connect. The current schema is
//! version 1 (`migrations/0001_init.sql`).
//!
//! WAL mode + foreign keys are enabled by `PRAGMA` in the migration.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

use omemo_doubleratchet::dh_ratchet::DhPrivProvider;
use omemo_oldmemo::{
    parse_key_exchange as parse_kex_old, peek_dh_pub as peek_dh_pub_old, OldmemoSession,
    OldmemoSessionSnapshot,
};
use omemo_twomemo::{parse_key_exchange, peek_dh_pub, TwomemoSession, TwomemoSessionSnapshot};
use omemo_x3dh::{
    get_shared_secret_passive, Header as X3dhHeader, IdentityKeyPair, PreKeyPair, SignedPreKeyPair,
    X3dhState,
};

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("twomemo: {0}")]
    Twomemo(#[from] omemo_twomemo::TwomemoError),
    #[error("oldmemo: {0}")]
    Oldmemo(#[from] omemo_oldmemo::OldmemoError),
    #[error("dh ratchet: {0}")]
    DhRatchet(#[from] omemo_doubleratchet::dh_ratchet::DhRatchetError),
    #[error("x3dh: {0}")]
    X3dh(#[from] omemo_x3dh::X3dhError),
    #[error("identity not initialised")]
    IdentityMissing,
    #[error("identity already initialised — call reset() first")]
    IdentityAlreadyExists,
    #[error("session not found for {jid}/{device_id}")]
    SessionNotFound { jid: String, device_id: u32 },
    #[error("kex references unknown spk_id {0}")]
    UnknownSpkId(u32),
    #[error("kex references unknown pk_id {0}")]
    UnknownPkId(u32),
    #[error("kex references already-consumed pk_id {0}")]
    PreKeyAlreadyConsumed(u32),
    #[error("schema migration failed at version {version}: {detail}")]
    Migration { version: u32, detail: String },
}

const SCHEMA_V1_SQL: &str = include_str!("../migrations/0001_init.sql");
const SCHEMA_V2_SQL: &str = include_str!("../migrations/0002_trust.sql");
const SCHEMA_V3_SQL: &str = include_str!("../migrations/0003_backend.sql");

/// OMEMO wire-format backend a session uses.
///
/// Stored as `INTEGER` in the `session.backend` /
/// `message_keys_skipped.backend` columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    /// `urn:xmpp:omemo:2` — XEP-0384 v0.9 (twomemo).
    Twomemo = 0,
    /// `eu.siacs.conversations.axolotl` — XEP-0384 v0.3 (oldmemo).
    Oldmemo = 1,
}

impl Backend {
    fn from_i64(v: i64) -> Result<Self, SessionStoreError> {
        Ok(match v {
            0 => Backend::Twomemo,
            1 => Backend::Oldmemo,
            _ => {
                return Err(SessionStoreError::Migration {
                    version: 3,
                    detail: format!("unknown backend value {v}"),
                })
            }
        })
    }

    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnIdentity {
    pub bare_jid: String,
    pub device_id: u32,
    pub ik_seed: [u8; 32],
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredSpk {
    pub id: u32,
    pub priv_key: [u8; 32],
    pub pub_key: [u8; 32],
    pub sig: [u8; 64],
    pub created_at: i64,
    pub replaced_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StoredOpk {
    pub id: u32,
    pub priv_key: [u8; 32],
    pub pub_key: [u8; 32],
    pub consumed: bool,
    pub created_at: i64,
}

/// Per-device trust verdict. Stored in `trusted_devices.trust_state`.
///
/// * `Pending` — the device has been seen but no policy decision has
///   been made yet. Outbound encryption to a Pending device is allowed
///   (lets messaging work) but UIs should surface the prompt.
/// * `Trusted` — explicitly approved, either by the user or by an
///   auto-approve TOFU policy on first sight.
/// * `Untrusted` — explicitly rejected. Outbound MUST refuse;
///   inbound from this device should be dropped or flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Pending = 0,
    Trusted = 1,
    Untrusted = 2,
}

impl TrustState {
    fn from_i64(v: i64) -> Result<Self, SessionStoreError> {
        Ok(match v {
            0 => TrustState::Pending,
            1 => TrustState::Trusted,
            2 => TrustState::Untrusted,
            _ => {
                return Err(SessionStoreError::Migration {
                    version: 2,
                    detail: format!("unknown trust_state value {v}"),
                })
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    pub bare_jid: String,
    pub device_id: u32,
    pub ik_pub: [u8; 32],
    pub state: TrustState,
    pub first_seen_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDevice {
    pub bare_jid: String,
    pub device_id: u32,
    pub label: Option<String>,
    pub last_seen_at: i64,
}

pub struct Store {
    conn: Connection,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn array_32(blob: &[u8]) -> Result<[u8; 32], SessionStoreError> {
    if blob.len() != 32 {
        return Err(SessionStoreError::Migration {
            version: 1,
            detail: format!("expected 32-byte blob, got {}", blob.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(blob);
    Ok(out)
}

fn array_64(blob: &[u8]) -> Result<[u8; 64], SessionStoreError> {
    if blob.len() != 64 {
        return Err(SessionStoreError::Migration {
            version: 1,
            detail: format!("expected 64-byte blob, got {}", blob.len()),
        });
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(blob);
    Ok(out)
}

impl Store {
    /// Open or create a store at the given filesystem path. Runs pending
    /// migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SessionStoreError> {
        let conn = Connection::open(path)?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory store (one per call). Useful for tests.
    pub fn open_in_memory() -> Result<Self, SessionStoreError> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn current_version(&self) -> Result<u32, SessionStoreError> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !exists {
            return Ok(0);
        }
        let v: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )?;
        Ok(v as u32)
    }

    fn migrate(&mut self) -> Result<(), SessionStoreError> {
        let v = self.current_version()?;
        if v < 1 {
            self.conn
                .execute_batch(SCHEMA_V1_SQL)
                .map_err(|e| SessionStoreError::Migration {
                    version: 1,
                    detail: e.to_string(),
                })?;
        }
        if v < 2 {
            self.conn
                .execute_batch(SCHEMA_V2_SQL)
                .map_err(|e| SessionStoreError::Migration {
                    version: 2,
                    detail: e.to_string(),
                })?;
        }
        if v < 3 {
            self.conn
                .execute_batch(SCHEMA_V3_SQL)
                .map_err(|e| SessionStoreError::Migration {
                    version: 3,
                    detail: e.to_string(),
                })?;
        }
        Ok(())
    }

    // ---- identity ---------------------------------------------------------

    pub fn put_identity(
        &mut self,
        bare_jid: &str,
        device_id: u32,
        ik_seed: &[u8; 32],
    ) -> Result<OwnIdentity, SessionStoreError> {
        if self.get_identity()?.is_some() {
            return Err(SessionStoreError::IdentityAlreadyExists);
        }
        let now = now_secs();
        self.conn.execute(
            "INSERT INTO identity (rowid, bare_jid, device_id, ik_seed, created_at)
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![bare_jid, device_id, &ik_seed[..], now],
        )?;
        Ok(OwnIdentity {
            bare_jid: bare_jid.to_string(),
            device_id,
            ik_seed: *ik_seed,
            created_at: now,
        })
    }

    pub fn get_identity(&self) -> Result<Option<OwnIdentity>, SessionStoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT bare_jid, device_id, ik_seed, created_at FROM identity WHERE rowid = 1",
                [],
                |r| {
                    let blob: Vec<u8> = r.get(2)?;
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        blob,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        Ok(match row {
            Some((bare_jid, device_id, blob, created_at)) => Some(OwnIdentity {
                bare_jid,
                device_id: device_id as u32,
                ik_seed: array_32(&blob)?,
                created_at,
            }),
            None => None,
        })
    }

    // ---- SPK --------------------------------------------------------------

    pub fn put_spk(&mut self, spk: &StoredSpk) -> Result<(), SessionStoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO signed_prekey
                 (id, priv, pub, sig, created_at, replaced_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                spk.id,
                &spk.priv_key[..],
                &spk.pub_key[..],
                &spk.sig[..],
                spk.created_at,
                spk.replaced_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_spk(&self, id: u32) -> Result<Option<StoredSpk>, SessionStoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, priv, pub, sig, created_at, replaced_at FROM signed_prekey WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?;
        Ok(match row {
            Some((id, priv_b, pub_b, sig_b, created, replaced)) => Some(StoredSpk {
                id: id as u32,
                priv_key: array_32(&priv_b)?,
                pub_key: array_32(&pub_b)?,
                sig: array_64(&sig_b)?,
                created_at: created,
                replaced_at: replaced,
            }),
            None => None,
        })
    }

    /// The most recently created SPK with `replaced_at IS NULL`.
    pub fn current_spk(&self) -> Result<Option<StoredSpk>, SessionStoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, priv, pub, sig, created_at, replaced_at
                   FROM signed_prekey
                  WHERE replaced_at IS NULL
                  ORDER BY created_at DESC LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .optional()?;
        Ok(match row {
            Some((id, priv_b, pub_b, sig_b, created, replaced)) => Some(StoredSpk {
                id: id as u32,
                priv_key: array_32(&priv_b)?,
                pub_key: array_32(&pub_b)?,
                sig: array_64(&sig_b)?,
                created_at: created,
                replaced_at: replaced,
            }),
            None => None,
        })
    }

    // ---- OPK --------------------------------------------------------------

    pub fn put_opk(&mut self, opk: &StoredOpk) -> Result<(), SessionStoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO prekey (id, priv, pub, consumed, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                opk.id,
                &opk.priv_key[..],
                &opk.pub_key[..],
                opk.consumed as i64,
                opk.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_opk(&self, id: u32) -> Result<Option<StoredOpk>, SessionStoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, priv, pub, consumed, created_at FROM prekey WHERE id = ?1",
                params![id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        Ok(match row {
            Some((id, priv_b, pub_b, consumed, created)) => Some(StoredOpk {
                id: id as u32,
                priv_key: array_32(&priv_b)?,
                pub_key: array_32(&pub_b)?,
                consumed: consumed != 0,
                created_at: created,
            }),
            None => None,
        })
    }

    /// Mark an OPK as consumed. Idempotent — safe to call on an already-
    /// consumed OPK, returns `Ok(false)` if no row matched.
    pub fn consume_opk(&mut self, id: u32) -> Result<bool, SessionStoreError> {
        let n = self.conn.execute(
            "UPDATE prekey SET consumed = 1 WHERE id = ?1 AND consumed = 0",
            params![id],
        )?;
        Ok(n > 0)
    }

    pub fn unconsumed_opks(&self) -> Result<Vec<StoredOpk>, SessionStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, priv, pub, consumed, created_at FROM prekey
              WHERE consumed = 0 ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, priv_b, pub_b, consumed, created) in rows {
            out.push(StoredOpk {
                id: id as u32,
                priv_key: array_32(&priv_b)?,
                pub_key: array_32(&pub_b)?,
                consumed: consumed != 0,
                created_at: created,
            });
        }
        Ok(out)
    }

    /// Number of unconsumed OPKs currently in the pool. Used by the
    /// refill helper in `omemo-pep::store` to decide whether to mint
    /// fresh ones.
    pub fn count_unconsumed_opks(&self) -> Result<u32, SessionStoreError> {
        let n: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM prekey WHERE consumed = 0", [], |r| {
                    r.get(0)
                })?;
        Ok(n as u32)
    }

    /// `MAX(id) + 1` over the entire `prekey` table — including
    /// already-consumed rows, so a refilled OPK never collides with
    /// a previously-published one (XEP-0384 §5.3.2 forbids id reuse).
    pub fn next_opk_id(&self) -> Result<u32, SessionStoreError> {
        let id: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM prekey", [], |r| {
                    r.get(0)
                })?;
        Ok(id as u32)
    }

    // ---- device list ------------------------------------------------------

    pub fn upsert_device(
        &mut self,
        bare_jid: &str,
        device_id: u32,
        label: Option<&str>,
    ) -> Result<(), SessionStoreError> {
        let now = now_secs();
        self.conn.execute(
            "INSERT INTO device_list (bare_jid, device_id, label, last_seen_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(bare_jid, device_id) DO UPDATE
                SET label = excluded.label,
                    last_seen_at = excluded.last_seen_at",
            params![bare_jid, device_id, label, now],
        )?;
        Ok(())
    }

    pub fn devices_for(&self, bare_jid: &str) -> Result<Vec<StoredDevice>, SessionStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT bare_jid, device_id, label, last_seen_at FROM device_list
              WHERE bare_jid = ?1 ORDER BY device_id",
        )?;
        let rows = stmt
            .query_map(params![bare_jid], |r| {
                Ok(StoredDevice {
                    bare_jid: r.get(0)?,
                    device_id: r.get::<_, i64>(1)? as u32,
                    label: r.get(2)?,
                    last_seen_at: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ---- trust (TOFU) -----------------------------------------------------

    /// Atomically record `(jid, device_id)` if absent, returning the
    /// resulting [`TrustedDevice`] row.
    ///
    /// On first sight, the row is inserted with `default_state` (TOFU
    /// callers pass `Trusted`; Manual callers pass `Pending`) and
    /// `first_seen_at = now`. On subsequent calls, the existing row is
    /// returned unchanged — including its IK and trust state — so the
    /// caller can detect IK drift (a different IK on a previously-seen
    /// `(jid, device_id)` is a critical security signal: the peer's
    /// device key changed without explicit re-trust).
    pub fn record_first_seen(
        &mut self,
        bare_jid: &str,
        device_id: u32,
        ik_pub: &[u8; 32],
        default_state: TrustState,
    ) -> Result<TrustedDevice, SessionStoreError> {
        let now = now_secs();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO trusted_devices
                 (bare_jid, device_id, ik_pub, trust_state, first_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![bare_jid, device_id, &ik_pub[..], default_state as i64, now,],
        )?;
        let row = tx.query_row(
            "SELECT bare_jid, device_id, ik_pub, trust_state, first_seen_at
               FROM trusted_devices WHERE bare_jid = ?1 AND device_id = ?2",
            params![bare_jid, device_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )?;
        tx.commit()?;
        let (bare_jid, device_id, ik_blob, state_i, first_seen_at) = row;
        Ok(TrustedDevice {
            bare_jid,
            device_id: device_id as u32,
            ik_pub: array_32(&ik_blob)?,
            state: TrustState::from_i64(state_i)?,
            first_seen_at,
        })
    }

    /// Look up the recorded trust state for `(jid, device_id)`.
    pub fn trusted_device(
        &self,
        bare_jid: &str,
        device_id: u32,
    ) -> Result<Option<TrustedDevice>, SessionStoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT bare_jid, device_id, ik_pub, trust_state, first_seen_at
                   FROM trusted_devices WHERE bare_jid = ?1 AND device_id = ?2",
                params![bare_jid, device_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        Ok(match row {
            Some((bare_jid, device_id, ik_blob, state_i, first_seen_at)) => Some(TrustedDevice {
                bare_jid,
                device_id: device_id as u32,
                ik_pub: array_32(&ik_blob)?,
                state: TrustState::from_i64(state_i)?,
                first_seen_at,
            }),
            None => None,
        })
    }

    /// Explicit policy decision: set the trust state for an already-
    /// seen device. Returns `Ok(false)` if no row matched (caller never
    /// recorded the device).
    pub fn set_trust(
        &mut self,
        bare_jid: &str,
        device_id: u32,
        state: TrustState,
    ) -> Result<bool, SessionStoreError> {
        let n = self.conn.execute(
            "UPDATE trusted_devices SET trust_state = ?3
              WHERE bare_jid = ?1 AND device_id = ?2",
            params![bare_jid, device_id, state as i64],
        )?;
        Ok(n > 0)
    }

    /// Force-overwrite the recorded identity key for a device,
    /// resetting its trust state at the same time. Used when the
    /// orchestrator has confirmed (out-of-band, via fingerprint
    /// comparison or a trusted side-channel) that a peer's
    /// device legitimately rotated its IK — e.g. the user
    /// reinstalled their client. Without this primitive, an
    /// IK-drift event leaves the bot permanently unable to
    /// decrypt that peer's traffic.
    ///
    /// If no row exists yet this inserts a fresh one (same
    /// shape as `record_first_seen`).
    pub fn force_set_ik(
        &mut self,
        bare_jid: &str,
        device_id: u32,
        new_ik_pub: &[u8; 32],
        state: TrustState,
    ) -> Result<(), SessionStoreError> {
        let now = now_secs();
        // INSERT-OR-REPLACE on the same (bare_jid, device_id) PK
        // keeps the schema's first_seen_at semantics simple — we
        // do reset it on a forced retrust, which is the right
        // behaviour: the operator is acknowledging this is a
        // brand-new key as far as the bot is concerned.
        self.conn.execute(
            "INSERT OR REPLACE INTO trusted_devices
                 (bare_jid, device_id, ik_pub, trust_state, first_seen_at)
              VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                bare_jid,
                device_id,
                &new_ik_pub[..],
                state as i64,
                now
            ],
        )?;
        Ok(())
    }

    /// Enumerate every device currently in `Pending` trust
    /// state. Used by the daemon's `pending_trusts` query so
    /// an operator can review + accept/reject queued first-
    /// sights under Manual trust policy.
    pub fn pending_devices(&self) -> Result<Vec<TrustedDevice>, SessionStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT bare_jid, device_id, ik_pub, trust_state, first_seen_at
               FROM trusted_devices
              WHERE trust_state = ?1
              ORDER BY first_seen_at",
        )?;
        let rows = stmt.query_map(params![TrustState::Pending as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u32,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (bare_jid, device_id, ik_blob, state, first_seen_at) = row?;
            out.push(TrustedDevice {
                bare_jid,
                device_id,
                ik_pub: array_32(&ik_blob)?,
                state: TrustState::from_i64(state)?,
                first_seen_at,
            });
        }
        Ok(out)
    }

    // ---- session ----------------------------------------------------------

    pub fn save_session(
        &mut self,
        bare_jid: &str,
        device_id: u32,
        session: &TwomemoSession,
    ) -> Result<(), SessionStoreError> {
        let blob = session.snapshot().encode();
        let now = now_secs();
        self.conn.execute(
            "INSERT INTO session (bare_jid, device_id, backend, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(bare_jid, device_id, backend) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![
                bare_jid,
                device_id,
                Backend::Twomemo.as_i64(),
                &blob[..],
                now
            ],
        )?;
        Ok(())
    }

    pub fn load_session_snapshot(
        &self,
        bare_jid: &str,
        device_id: u32,
    ) -> Result<Option<TwomemoSessionSnapshot>, SessionStoreError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT state FROM session WHERE bare_jid = ?1 AND device_id = ?2 AND backend = ?3",
                params![bare_jid, device_id, Backend::Twomemo.as_i64()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match blob {
            Some(b) => Some(TwomemoSessionSnapshot::decode(&b)?),
            None => None,
        })
    }

    pub fn delete_session(
        &mut self,
        bare_jid: &str,
        device_id: u32,
    ) -> Result<bool, SessionStoreError> {
        let n = self.conn.execute(
            "DELETE FROM session WHERE bare_jid = ?1 AND device_id = ?2 AND backend = ?3",
            params![bare_jid, device_id, Backend::Twomemo.as_i64()],
        )?;
        Ok(n > 0)
    }

    // ---- session (oldmemo) -----------------------------------------------

    pub fn save_oldmemo_session(
        &mut self,
        bare_jid: &str,
        device_id: u32,
        session: &OldmemoSession,
    ) -> Result<(), SessionStoreError> {
        let blob = session.snapshot().encode();
        let now = now_secs();
        self.conn.execute(
            "INSERT INTO session (bare_jid, device_id, backend, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(bare_jid, device_id, backend) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![
                bare_jid,
                device_id,
                Backend::Oldmemo.as_i64(),
                &blob[..],
                now
            ],
        )?;
        Ok(())
    }

    pub fn load_oldmemo_session_snapshot(
        &self,
        bare_jid: &str,
        device_id: u32,
    ) -> Result<Option<OldmemoSessionSnapshot>, SessionStoreError> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT state FROM session WHERE bare_jid = ?1 AND device_id = ?2 AND backend = ?3",
                params![bare_jid, device_id, Backend::Oldmemo.as_i64()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match blob {
            Some(b) => Some(OldmemoSessionSnapshot::decode(&b)?),
            None => None,
        })
    }

    pub fn delete_oldmemo_session(
        &mut self,
        bare_jid: &str,
        device_id: u32,
    ) -> Result<bool, SessionStoreError> {
        let n = self.conn.execute(
            "DELETE FROM session WHERE bare_jid = ?1 AND device_id = ?2 AND backend = ?3",
            params![bare_jid, device_id, Backend::Oldmemo.as_i64()],
        )?;
        Ok(n > 0)
    }

    /// Inspect which backends have a session row for a given peer
    /// device. Used by the dispatch layer to pick the best available
    /// backend at send time.
    pub fn session_backends(
        &self,
        bare_jid: &str,
        device_id: u32,
    ) -> Result<Vec<Backend>, SessionStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT backend FROM session WHERE bare_jid = ?1 AND device_id = ?2 ORDER BY backend",
        )?;
        let rows = stmt.query_map(params![bare_jid, device_id], |r| r.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(Backend::from_i64(row?)?);
        }
        Ok(out)
    }

    /// Enumerate every `device_id` we have a session with for
    /// `(bare_jid, backend)`. Sorted ascending. Empty when we
    /// haven't bootstrapped any sessions to this peer yet
    /// (caller's cue to fall back to `fetch_device_list` +
    /// per-device bootstrap).
    ///
    /// Used by the daemon's multi-device fan-out path so a
    /// single `Send { peer, body, device: None }` can encrypt
    /// to all of `bare_jid`'s already-bootstrapped devices in
    /// one go (XEP-0384 §4.6 multi-recipient fan-out).
    pub fn session_devices(
        &self,
        bare_jid: &str,
        backend: Backend,
    ) -> Result<Vec<u32>, SessionStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id FROM session WHERE bare_jid = ?1 AND backend = ?2 \
             ORDER BY device_id",
        )?;
        let rows =
            stmt.query_map(params![bare_jid, backend.as_i64()], |r| r.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row? as u32);
        }
        Ok(out)
    }

    /// Total number of `(bare_jid, device_id)` sessions we
    /// hold for `backend`, across all peers. Used by the
    /// daemon's `status` event to surface a cheap "how many
    /// peers am I talking to" gauge.
    pub fn session_count(&self, backend: Backend) -> Result<u64, SessionStoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM session WHERE backend = ?1",
            params![backend.as_i64()],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Atomically mark `opk_id` consumed and persist `session` for the
    /// given peer device. Used by the omemo-pep KEX-inbound flow when the
    /// caller has already produced the session via `decrypt_inbound_kex`
    /// (so it cannot reuse [`Self::receive_initial_message`]).
    pub fn commit_first_inbound(
        &mut self,
        peer_jid: &str,
        peer_device_id: u32,
        opk_id: u32,
        session: &TwomemoSession,
    ) -> Result<(), SessionStoreError> {
        let blob = session.snapshot().encode();
        let now = now_secs();
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE prekey SET consumed = 1 WHERE id = ?1 AND consumed = 0",
            params![opk_id],
        )?;
        tx.execute(
            "INSERT INTO session (bare_jid, device_id, backend, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(bare_jid, device_id, backend) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![
                peer_jid,
                peer_device_id,
                Backend::Twomemo.as_i64(),
                &blob[..],
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Atomic OPK-consume + oldmemo-session-save, mirror of
    /// [`Self::commit_first_inbound`] for the OMEMO 0.3 flow. The
    /// caller has already produced the [`OldmemoSession`] (e.g. via
    /// `decrypt_inbound_kex_oldmemo` in `omemo-pep`).
    pub fn commit_first_inbound_oldmemo(
        &mut self,
        peer_jid: &str,
        peer_device_id: u32,
        opk_id: u32,
        session: &OldmemoSession,
    ) -> Result<(), SessionStoreError> {
        let blob = session.snapshot().encode();
        let now = now_secs();
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE prekey SET consumed = 1 WHERE id = ?1 AND consumed = 0",
            params![opk_id],
        )?;
        tx.execute(
            "INSERT INTO session (bare_jid, device_id, backend, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(bare_jid, device_id, backend) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![
                peer_jid,
                peer_device_id,
                Backend::Oldmemo.as_i64(),
                &blob[..],
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    // ---- high-level helpers ----------------------------------------------

    /// Bootstrap a passive session from a received `OMEMOKeyExchange`.
    ///
    /// Looks up our SPK and OPK by the IDs in the KEX, runs X3DH passive,
    /// reconstructs the twomemo session, decrypts the embedded initial
    /// message, and atomically (single SQLite transaction) **marks the OPK
    /// consumed** + persists the session.
    ///
    /// This is the API to use in production; doing the same thing manually
    /// (`get_shared_secret_passive` → `consume_opk` → `save_session`) is
    /// allowed but easy to get wrong (e.g. consuming the OPK then crashing
    /// before saving the session). The transaction here closes that hole.
    ///
    /// Returns the decrypted M0 plaintext.
    pub fn receive_initial_message(
        &mut self,
        peer_jid: &str,
        peer_device_id: u32,
        kex_bytes: &[u8],
        priv_provider: Box<dyn DhPrivProvider>,
    ) -> Result<Vec<u8>, SessionStoreError> {
        // 1) Pure reads — find own keys and parse the KEX.
        let identity = self
            .get_identity()?
            .ok_or(SessionStoreError::IdentityMissing)?;
        let (pk_id, spk_id, peer_ik_pub_ed, peer_ek_pub, auth_msg_bytes) =
            parse_key_exchange(kex_bytes)?;
        let spk = self
            .get_spk(spk_id)?
            .ok_or(SessionStoreError::UnknownSpkId(spk_id))?;
        let opk = self
            .get_opk(pk_id)?
            .ok_or(SessionStoreError::UnknownPkId(pk_id))?;
        if opk.consumed {
            return Err(SessionStoreError::PreKeyAlreadyConsumed(pk_id));
        }

        // 2) Pure compute — build X3DH state, run passive, build session,
        //    decrypt M0. None of this writes to the DB yet.
        let own_state = X3dhState {
            identity_key: IdentityKeyPair::Seed(identity.ik_seed),
            signed_pre_key: SignedPreKeyPair {
                priv_key: spk.priv_key,
                sig: spk.sig,
                timestamp: spk.created_at as u64,
            },
            old_signed_pre_key: None,
            pre_keys: vec![PreKeyPair {
                priv_key: opk.priv_key,
            }],
        };
        let header = X3dhHeader {
            identity_key: peer_ik_pub_ed,
            ephemeral_key: peer_ek_pub,
            signed_pre_key: spk.pub_key,
            pre_key: Some(opk.pub_key),
        };
        let (x3dh_out, _used_spk) = get_shared_secret_passive(&own_state, &header, b"", true)?;

        let alice_first_dh_pub = peek_dh_pub(&auth_msg_bytes)?;
        let mut session = TwomemoSession::create_passive(
            x3dh_out.associated_data,
            x3dh_out.shared_secret.to_vec(),
            spk.priv_key,
            alice_first_dh_pub,
            priv_provider,
        )?;
        let plaintext = session.decrypt_message(&auth_msg_bytes)?;

        // 3) Atomic write — consume OPK + save session in one transaction.
        let blob = session.snapshot().encode();
        let now = now_secs();
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE prekey SET consumed = 1 WHERE id = ?1 AND consumed = 0",
            params![pk_id],
        )?;
        tx.execute(
            "INSERT INTO session (bare_jid, device_id, backend, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(bare_jid, device_id, backend) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![
                peer_jid,
                peer_device_id,
                Backend::Twomemo.as_i64(),
                &blob[..],
                now
            ],
        )?;
        tx.commit()?;

        Ok(plaintext)
    }

    /// OMEMO 0.3 (oldmemo) counterpart of
    /// [`Self::receive_initial_message`]. Same X3DH passive flow,
    /// but the KEX is parsed via `omemo_oldmemo` and the resulting
    /// session is an `OldmemoSession`. The IK in the OMEMO 0.3 KEX
    /// is the **Curve25519** form (32 bytes, 0x05 prefix already
    /// stripped by `parse_kex_old`); the X3DH state we build here
    /// expects the Ed25519 form, so the caller is responsible for
    /// performing the curve→ed conversion (with the correct sign
    /// bit drawn from the trusted devicelist) before calling.
    pub fn receive_initial_message_oldmemo(
        &mut self,
        peer_jid: &str,
        peer_device_id: u32,
        peer_ik_pub_ed: [u8; 32],
        kex_bytes: &[u8],
        priv_provider: Box<dyn DhPrivProvider>,
    ) -> Result<Vec<u8>, SessionStoreError> {
        let identity = self
            .get_identity()?
            .ok_or(SessionStoreError::IdentityMissing)?;
        let (pk_id, spk_id, _peer_ik_curve, peer_ek_pub, auth_msg_blob) =
            parse_kex_old(kex_bytes)?;
        let spk = self
            .get_spk(spk_id)?
            .ok_or(SessionStoreError::UnknownSpkId(spk_id))?;
        let opk = self
            .get_opk(pk_id)?
            .ok_or(SessionStoreError::UnknownPkId(pk_id))?;
        if opk.consumed {
            return Err(SessionStoreError::PreKeyAlreadyConsumed(pk_id));
        }

        let own_state = X3dhState {
            identity_key: IdentityKeyPair::Seed(identity.ik_seed),
            signed_pre_key: SignedPreKeyPair {
                priv_key: spk.priv_key,
                sig: spk.sig,
                timestamp: spk.created_at as u64,
            },
            old_signed_pre_key: None,
            pre_keys: vec![PreKeyPair {
                priv_key: opk.priv_key,
            }],
        };
        let header = X3dhHeader {
            identity_key: peer_ik_pub_ed,
            ephemeral_key: peer_ek_pub,
            signed_pre_key: spk.pub_key,
            pre_key: Some(opk.pub_key),
        };
        // OMEMO 0.3 X3DH: info "WhisperText", AD = enc(their)||enc(own)
        // — handled inside `get_shared_secret_passive_oldmemo`.
        let (x3dh_out, _used_spk) =
            omemo_x3dh::get_shared_secret_passive_oldmemo(&own_state, &header, b"", true)?;

        let alice_first_dh_pub = peek_dh_pub_old(&auth_msg_blob)?;
        let mut session = OldmemoSession::create_passive(
            x3dh_out.associated_data,
            x3dh_out.shared_secret.to_vec(),
            spk.priv_key,
            alice_first_dh_pub,
            priv_provider,
        )?;
        let plaintext = session.decrypt_message(&auth_msg_blob)?;

        let blob = session.snapshot().encode();
        let now = now_secs();
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE prekey SET consumed = 1 WHERE id = ?1 AND consumed = 0",
            params![pk_id],
        )?;
        tx.execute(
            "INSERT INTO session (bare_jid, device_id, backend, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(bare_jid, device_id, backend) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![
                peer_jid,
                peer_device_id,
                Backend::Oldmemo.as_i64(),
                &blob[..],
                now
            ],
        )?;
        tx.commit()?;

        Ok(plaintext)
    }
}
