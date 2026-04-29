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
            "INSERT INTO session (bare_jid, device_id, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(bare_jid, device_id) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![bare_jid, device_id, &blob[..], now],
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
                "SELECT state FROM session WHERE bare_jid = ?1 AND device_id = ?2",
                params![bare_jid, device_id],
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
            "DELETE FROM session WHERE bare_jid = ?1 AND device_id = ?2",
            params![bare_jid, device_id],
        )?;
        Ok(n > 0)
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
            "INSERT INTO session (bare_jid, device_id, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(bare_jid, device_id) DO UPDATE
                SET state = excluded.state,
                    updated_at = excluded.updated_at",
            params![peer_jid, peer_device_id, &blob[..], now],
        )?;
        tx.commit()?;

        Ok(plaintext)
    }
}
