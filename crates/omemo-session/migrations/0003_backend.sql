-- omemo-session schema, version 3.
--
-- Adds a `backend` discriminator (0 = twomemo / OMEMO 2,
-- 1 = oldmemo / OMEMO 0.3) to the per-peer-device tables so a
-- single peer can hold a twomemo *and* an oldmemo session
-- simultaneously. The identity / SPK / OPK / device-list / trust
-- tables are backend-agnostic and stay as they are.
--
-- SQLite cannot redefine a PRIMARY KEY in place, so we follow the
-- documented "create new, copy across, swap names" recipe:
-- https://www.sqlite.org/lang_altertable.html#otheralter

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

-- ---- session -------------------------------------------------

CREATE TABLE session_new (
    bare_jid    TEXT    NOT NULL,
    device_id   INTEGER NOT NULL,
    backend     INTEGER NOT NULL DEFAULT 0,         -- 0 twomemo, 1 oldmemo
    state       BLOB    NOT NULL,                   -- {Twomemo,Oldmemo}SessionSnapshot::encode()
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (bare_jid, device_id, backend)
);

INSERT INTO session_new (bare_jid, device_id, backend, state, created_at, updated_at)
SELECT bare_jid, device_id, 0, state, created_at, updated_at FROM session;

DROP TABLE session;
ALTER TABLE session_new RENAME TO session;

-- ---- message_keys_skipped ------------------------------------

CREATE TABLE message_keys_skipped_new (
    bare_jid    TEXT    NOT NULL,
    device_id   INTEGER NOT NULL,
    backend     INTEGER NOT NULL DEFAULT 0,
    dh_pub      BLOB    NOT NULL,                   -- 32 bytes
    n           INTEGER NOT NULL,
    mk          BLOB    NOT NULL,                   -- 32 bytes
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (bare_jid, device_id, backend, dh_pub, n)
);

INSERT INTO message_keys_skipped_new (bare_jid, device_id, backend, dh_pub, n, mk, expires_at)
SELECT bare_jid, device_id, 0, dh_pub, n, mk, expires_at FROM message_keys_skipped;

DROP TABLE message_keys_skipped;
ALTER TABLE message_keys_skipped_new RENAME TO message_keys_skipped;

INSERT OR REPLACE INTO schema_version (version) VALUES (3);

COMMIT;

PRAGMA foreign_keys = ON;
