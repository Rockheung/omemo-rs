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
    -- PEP/PubSub for OMEMO 2 device-list and bundle nodes
    "pep",
    "pep_simple",
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
