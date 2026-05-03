-- Prosody configuration for omemo-rs integration tests.
--
-- Localhost-only. Two virtual users (alice, bob) are pre-registered by the
-- container entrypoint.
--
-- WARNING: c2s_require_encryption = false. Acceptable ONLY because the
-- container exposes 5222 on 127.0.0.1 and is meant for `cargo test` runs.
-- Do not lift this config to production.

admins = {}

modules_enabled = {
    -- Core
    "roster", "saslauth", "tls", "dialback", "disco",
    -- Bot/contact comfort
    "carbons", "private", "blocklist",
    "version", "uptime", "time", "ping",
    -- PEP/PubSub for OMEMO 2 device-list and bundle nodes.
    -- NOTE: do *not* also enable `pep_simple`. In Prosody 13 it
    -- intercepts publish requests and silently drops the XEP-0060
    -- `<publish-options>` data form, leaving the PEP node at its
    -- default `access_model = presence-required` — which makes
    -- `fetch_bundle` fail with `presence-subscription-required`
    -- the first time a peer (without an active subscription)
    -- tries to read it. The full `pep` module supports
    -- publish-options correctly.
    "pep",
    -- HTTP-binding modules so a browser-based client (Converse.js)
    -- can attach over BOSH (XEP-0124/0206) or WebSocket
    -- (RFC 7395). The `bosh` module backs `/http-bind/`, and
    -- `websocket` backs `/xmpp-websocket/`. Required for the
    -- multi-session E2E test setup under
    -- `test-vectors/integration/converse/`.
    "bosh", "websocket",
    -- Message Archive Management — production XMPP clients (incl.
    -- Converse.js) expect history to be retrievable across logins.
    "mam",
    -- HTTP file upload (XEP-0363) — Converse.js advertises it; the
    -- module is built-in to recent Prosody.
    "http_file_share",
}

modules_disabled = {
    -- Don't try to bind 5269; we don't federate in the tests.
    "s2s",
}

-- Localhost integration tests: cleartext SASL PLAIN is fine.
c2s_require_encryption = false
s2s_require_encryption = false
allow_registration = false

authentication = "internal_hashed"
storage = "internal"

pidfile = "/var/run/prosody/prosody.pid"

-- HTTP / BOSH / WebSocket for the Converse.js E2E setup
-- (`test-vectors/integration/converse/`). All HTTP services bind to
-- 0.0.0.0 inside the container; docker-compose.yml maps to
-- 127.0.0.1 on the host so it stays local-only.
http_interfaces = { "*" }
http_ports = { 5280 }
https_ports = { 5281 }
-- BOSH defaults to refusing SASL PLAIN unless the connection is
-- encrypted. For the localhost dev setup we attach over plain HTTP
-- (avoids the self-signed cert warning), so flip the flag.
consider_bosh_secure = true
consider_websocket_secure = true
-- Cross-origin allow-list. Converse.js is served from
-- http://localhost:8080 by the sibling nginx container; without
-- CORS the browser blocks the BOSH XHR.
http_cors_override = {
    bosh = {
        enabled = true;
        credentials = true;
    };
    websocket = {
        enabled = true;
        credentials = true;
    };
}

log = {
    { levels = {min = "info"}, to = "console" },
}

-- TLS cert + key. nginx terminates TLS for all browser-facing
-- traffic (Converse.js page on 8766, plus the same-origin
-- /http-bind/ and /xmpp-websocket reverse-proxies), so this only
-- backs Prosody's own HTTPS BOSH on 5281 (legacy / direct-attach
-- clients) plus StartTLS on the C2S socket. nginx → Prosody hops
-- stay on plain HTTP across the compose private network.
ssl = {
    certificate = "/etc/prosody/tls/cert.pem";
    key = "/etc/prosody/tls/key.pem";
}
-- Trust the X-Forwarded-* headers nginx sets so logs / rate
-- limiting see the real client IP, not the gateway's.
trusted_proxies = { "127.0.0.1", "::1", "172.16.0.0/12" }

VirtualHost "localhost"
    enabled = true

-- MUC component for Stage 5 (Group OMEMO) integration tests.
-- Rooms are created on first join (`restrict_room_creation = false`).
-- We don't gate on whitelisted creators because this is a localhost-only
-- test fixture; production deployments should restrict.
Component "conference.localhost" "muc"
    name = "omemo-rs test MUC"
    restrict_room_creation = false
    -- Newly-created rooms start unlocked (XEP-0045 §10.1.2): we don't
    -- want the integration tests to have to send a muc#owner instant-
    -- room IQ before a second occupant can join. Public, non-anonymous
    -- by default so MUC OMEMO can resolve real JIDs.
    muc_room_locking = false
    muc_room_default_public = true
    muc_room_default_members_only = false
    muc_room_default_public_jids = true
    modules_enabled = { "muc_mam" }
