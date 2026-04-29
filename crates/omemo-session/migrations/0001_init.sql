-- omemo-session schema, version 1.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- Single-row table for our local identity.
-- Using rowid pinned to 1 so UPSERTs are simple.
CREATE TABLE IF NOT EXISTS identity (
    rowid       INTEGER PRIMARY KEY CHECK (rowid = 1),
    bare_jid    TEXT    NOT NULL,
    device_id   INTEGER NOT NULL,
    ik_seed     BLOB    NOT NULL,                   -- 32 bytes
    created_at  INTEGER NOT NULL                    -- unix seconds
);

CREATE TABLE IF NOT EXISTS signed_prekey (
    id          INTEGER PRIMARY KEY,                -- spk id (uint32)
    priv        BLOB    NOT NULL,                   -- 32 bytes
    pub         BLOB    NOT NULL,                   -- 32 bytes (Curve25519)
    sig         BLOB    NOT NULL,                   -- 64 bytes (XEdDSA)
    created_at  INTEGER NOT NULL,
    replaced_at INTEGER                             -- nullable
);

CREATE TABLE IF NOT EXISTS prekey (
    id          INTEGER PRIMARY KEY,                -- opk id (uint32)
    priv        BLOB    NOT NULL,                   -- 32 bytes
    pub         BLOB    NOT NULL,                   -- 32 bytes (Curve25519)
    consumed    INTEGER NOT NULL DEFAULT 0,         -- 0/1
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_list (
    bare_jid    TEXT    NOT NULL,
    device_id   INTEGER NOT NULL,
    label       TEXT,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (bare_jid, device_id)
);

CREATE TABLE IF NOT EXISTS session (
    bare_jid    TEXT    NOT NULL,
    device_id   INTEGER NOT NULL,
    state       BLOB    NOT NULL,                   -- TwomemoSessionSnapshot::encode()
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (bare_jid, device_id)
);

CREATE TABLE IF NOT EXISTS message_keys_skipped (
    bare_jid    TEXT    NOT NULL,
    device_id   INTEGER NOT NULL,
    dh_pub      BLOB    NOT NULL,                   -- 32 bytes
    n           INTEGER NOT NULL,
    mk          BLOB    NOT NULL,                   -- 32 bytes
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (bare_jid, device_id, dh_pub, n)
);

INSERT OR REPLACE INTO schema_version (version) VALUES (1);
