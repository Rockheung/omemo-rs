-- omemo-session schema, version 2 — TOFU device-trust table.

CREATE TABLE IF NOT EXISTS trusted_devices (
    bare_jid     TEXT    NOT NULL,
    device_id    INTEGER NOT NULL,
    ik_pub       BLOB    NOT NULL,                   -- 32 bytes Ed25519
    trust_state  INTEGER NOT NULL,                   -- 0 Pending, 1 Trusted, 2 Untrusted
    first_seen_at INTEGER NOT NULL,                  -- unix seconds
    PRIMARY KEY (bare_jid, device_id)
);

INSERT OR REPLACE INTO schema_version (version) VALUES (2);
