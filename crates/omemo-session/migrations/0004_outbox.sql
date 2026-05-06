-- omemo-session schema, version 4.
--
-- In-flight command outbox (P3-3).
--
-- Survives a daemon SIGKILL between accepting a `Send` (or
-- `SendMuc`) command on stdin and emitting the matching
-- `sent` event. On next startup the daemon drains this table
-- back through the normal command path so the application
-- never silently loses a queued message just because the
-- daemon process crashed mid-encryption.
--
-- A row stays until the daemon emits success and calls
-- `dequeue_outbox(rowid)`. Rows that fail repeatedly stay
-- forever; the daemon may surface them via `list_outbox`
-- in a later release. For v1 we accept that.

BEGIN TRANSACTION;

CREATE TABLE outbox (
    rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 0 = direct (1:1 send), 1 = muc (group chat send).
    kind        INTEGER NOT NULL,
    peer        TEXT    NOT NULL,         -- bare JID for direct; room bare JID for muc
    -- Direct sends: NULL means fan-out to every session.
    -- MUC sends:    always NULL (fan-out across occupants).
    device_id   INTEGER,
    -- 0 = twomemo (OMEMO 2), 1 = oldmemo (OMEMO 0.3).
    backend     INTEGER NOT NULL,
    body        TEXT    NOT NULL,
    -- Optional opaque request id from the original command;
    -- echoed back in the replayed `sent`/`error` event so the
    -- orchestrator can still correlate.
    request_id  TEXT,
    queued_at   INTEGER NOT NULL
);

CREATE INDEX outbox_queued_at ON outbox(queued_at);

INSERT OR REPLACE INTO schema_version (version) VALUES (4);

COMMIT;
