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

log = {
    { levels = {min = "info"}, to = "console" },
}

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
