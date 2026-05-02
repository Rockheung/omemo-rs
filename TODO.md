# omemo-rs — Active Task List

Live derivative of `docs/stages.md`. Tick items as they are completed.
When the box for a stage's gate test goes green, the whole stage is done.

Ordering reflects dependencies — do top to bottom.

---

## Status snapshot (2026-05-01)

| Stage | Status | Gate test |
|---|---|---|
| 0 — Workspace + pipeline | ✅ | `kdf_hkdf` |
| 1.1 — `omemo-xeddsa` | ✅ | `xeddsa` |
| 1.2 — `omemo-doubleratchet` | ✅ | `double_ratchet` |
| 1.3 — `omemo-x3dh` | ✅ | `x3dh` |
| 1.4 — `omemo-twomemo` | ✅ | `twomemo` (1 KEX + 3 messages, byte-equal protobuf) |
| 2 — `omemo-stanza` | ✅ | XEP-0384 §3+§5 round-trip + 3-recipient |
| 3 — `omemo-session` | ✅ | persist/restart 1:1 round-trip |
| 4 — `omemo-pep` | ✅ | alice ↔ bob 3-message exchange over real Prosody (`gate.rs`) |
| 5 — Group OMEMO | ✅ | `three_clients_groupchat_omemo2_round_trip` (3 omemo-rs in MUC) |
| 6.1 — python-omemo cross-impl | ✅ | `cargo test -p omemo-rs-cli --test python_interop -- --ignored` (both directions) |
| 6.2 — Conversations / Dino | ⏳ | manual; uses `omemo-rs-cli` against the same Prosody |

**Stages 1–5 + 4-FU.1..4 + 5-FU.1..4 + Stage 6.1 complete.**
Three `omemo-pep` clients exchange OMEMO 2 group-chat messages
end-to-end across a real Prosody MUC; the 1:1 path stays green from
Stage 4; **omemo-rs ↔ python-omemo (Syndace's reference Python
stack) cross-implementation interop passes in both directions** as
part of CI. The production hardening pass added OPK auto-refill,
RNG-based identity bootstrap, and the `omemo-rs-cli` binary; the
interop test suite spawns the binary alongside a slixmpp +
python-omemo client and asserts the body bytes round-trip. Bodies
are wrapped in XEP-0420 SCE envelopes (`<to>` verified on inbound —
peer bare for DM, room bare for groupchat); the trust layer records
every peer device on first sight under TOFU or Manual policy with
IK-drift detection. Production ships StartTLS via
`connect_starttls` (rustls + aws-lc-rs + native certs) alongside
the `connect_plaintext` helper used by localhost integration.
Crypto layer is byte-equal with the Syndace Python reference
(replay strategy, ADR-004); transport layer is MPL-2.0 xmpp-rs
(ADR-007). 64 self-contained tests + 10 Prosody-backed integration
tests all green (8 same-process + 2 cross-impl). CI runs fmt /
clippy / test / deny on every PR (`ci.yml`) and a
`cargo test -- --ignored` job spins up Prosody in Docker plus a
Python venv with python-omemo on push + weekly cron
(`integration.yml`).

---

## Stage 0 — Workspace + Test-Vector Pipeline ✅

- [x] Cargo workspace with 8 stub crates
- [x] Python venv with `doubleratchet 1.3`, `x3dh 1.3`, `xeddsa 1.2`,
      `twomemo 2.1`, `omemo 2.1`
- [x] Reference repos cloned to `test-vectors/reference/` (gitignored)
- [x] `omemo-test-harness` crate with `load_fixture` path resolver
- [x] First fixture/replay pair: HKDF (`scripts/gen_kdf_hkdf.py` +
      `tests/kdf_hkdf.rs`, 16 cases)
- [x] **Gate**: `cargo test -p omemo-test-harness --test kdf_hkdf` green

## Stage 1 — Crypto Layer

### 1.1 — `omemo-xeddsa` ✅

- [x] `gen_xeddsa.py` (8 cases × 13 primitives)
- [x] All 11 functions ported to Rust on curve25519-dalek + ed25519-dalek
- [x] Fixtures restricted to clamped priv (ADR-005)
- [x] **Gate**: `cargo test -p omemo-test-harness --test xeddsa` green

### 1.2 — `omemo-doubleratchet` ✅

In dependency order. Each item: generator script + Rust port + replay
test, all green together.

- [x] AEAD (AES-256-CBC + HMAC) — base recommended AEAD (full HMAC tail).
      The 16-byte truncation is a twomemo-layer override and lives in 1.4.
      - `gen_aead_aes_hmac.py` (20 cases), tamper tests, `src/aead.rs`
- [x] HKDF typed wrapper (`OmemoRootKdf`) — Stage 0 fixture covers correctness
- [x] Separate-HMACs message chain KDF (17 cases)
- [x] Generic `KDFChain` wrapper (6 multi-step cases: HKDF root + msg chain)
- [x] Symmetric key ratchet (3 cases × 19 ops, incl. send-chain rotation)
- [x] Curve25519 DH ratchet — Alice ↔ Bob 10-op scenario with mid-stream
      DH ratchet step (deterministic priv injection via `FixedDhPrivProvider`)
- [x] Top-level `DoubleRatchet` state machine
      - skipped-message-keys cap (`MAX_SKIP=1000`, FIFO)
      - header AD construction (configurable `BuildAdFn`; default
        `ad || ratchet_pub || pn(LE) || n(LE)`)
      - decrypt-on-clone semantics (clone DH ratchet, only commit on
        AEAD success)
      - **Gate**: 4-message round-trip with mid-conversation DH ratchet
        step + 1 skipped + 1 out-of-order delivery, byte-equal with
        Python ✅ (`tests/double_ratchet.rs`).

### 1.3 — `omemo-x3dh` ✅

- [x] Bundle generation (IK Ed25519 form / SPK Curve25519 + sig / OPK Curve25519)
- [x] Bundle verification (XEdDSA SPK sig over `_encode_public_key(spk_pub) = spk_pub`)
- [x] Active session (Alice initiates) — `get_shared_secret_active`
- [x] Passive session (Bob receives KEX) — `get_shared_secret_passive`
- [x] OPK lifecycle (consumed-once enforcement) — implemented in
      `Store::receive_initial_message` which atomically marks the OPK
      consumed + persists the new session in one SQLite transaction.
      Replay attempt fails with `PreKeyAlreadyConsumed`. Tests in
      `crates/omemo-session/tests/receive_initial.rs`.
- [x] **Gate**: full active/passive bundle exchange replays byte-equal with
      python-x3dh, 4 cases (3 with-OPK + 1 no-OPK), AD + SS byte-equal,
      bundle including SPK signature byte-equal. ✅
      `tests/x3dh.rs`

### 1.4 — `omemo-twomemo` ✅

- [x] `prost-build` codegen of `twomemo.proto` via `protoc-bin-vendored`
      (no system-wide `protoc` install required)
- [x] `OMEMOMessage` encode/decode
- [x] `OMEMOAuthenticatedMessage` encode/decode
- [x] `OMEMOKeyExchange` encode/decode
- [x] Glue: `TwomemoSession` (DH ratchet + skipped-keys FIFO) +
      `aead_encrypt`/`aead_decrypt` overrides (16-byte HMAC truncation,
      protobuf-aware AD parsing) + `build_key_exchange`/`parse_key_exchange`.
- [x] **Gate**: 1 KEX + 3 follow-up messages, byte-equal with python-twomemo
      at the protobuf wire-format level. Bob bootstraps from the KEX,
      decrypts M0 and the 3 follow-ups. ✅
      `tests/twomemo.rs`

## Stage 2 — `omemo-stanza` (XEP-0384 v0.9 stanza) ✅

- [x] `quick-xml 0.36` + `base64 0.22` (MIT)
- [x] `<encrypted>` envelope encode/decode (multi-recipient `<keys jid=>`,
      `<key rid=>` with optional `kex` flag, optional `<payload>`)
- [x] `<bundle>` encode/decode (`<spk id=>` / `<spks>` / `<ik>` / `<prekeys>`)
- [x] `<list>` (device list) encode/decode (with optional `label`)
- [x] **Gate**: 11 tests in `crates/omemo-stanza/tests/roundtrip.rs` —
      6 canonical round-trips (encrypted×3 incl. KEX/key-only/3-recipient,
      bundle, list, empty list), 3 tolerance tests (attribute reorder,
      self-closing root, XML decl + whitespace), 2 negative tests. ✅

## Stage 3 — `omemo-session` (SQLite store) ✅

- [x] Schema migration system (`migrations/0001_init.sql` —
      `schema_version` table + forward-only file-based migrator)
- [x] 6 tables: identity, signed_prekey, prekey, device_list, session,
      message_keys_skipped (last is schema-only until Stage 5+)
- [x] CRUD per table: identity, SPK (with `current_spk()`), OPK
      (with `consume_opk()` consumed-once enforcement), device list,
      session (BLOB), session-snapshot load/save
- [x] Ratchet-state BLOB serde — `TwomemoSessionSnapshot::encode/decode`
      (versioned, length-prefixed, deterministic). Lossless round-trip
      verified by `tests/twomemo.rs::session_snapshot_round_trip`.
- [x] WAL mode (`PRAGMA journal_mode=WAL` in migration), foreign keys ON
- [x] **Gate**: `tests/persist_round_trip.rs` — identity creation +
      bundle gen + 1:1 session round-trip + drop both stores + reopen
      + restore sessions + send M2 from restored state, decrypted
      successfully without re-keying. OPK consumed flag persisted. ✅

## Stage 4 — `omemo-pep` (XMPP integration) ✅

- [x] Pick XMPP library — `tokio-xmpp 5` + `xmpp-parsers 0.22` + `jid 0.12`
      (xmpp-rs family, MPL-2.0 — see ADR-007).
- [x] Localhost integration infra: `test-vectors/integration/prosody/` —
      Dockerfile (Debian + prosody.im apt repo, Prosody 13.x) +
      docker-compose with idempotent `alice`/`bob` registration.
- [x] First connect+auth integration test (`#[ignore]`'d so default
      `cargo test` stays self-contained):
      `omemo-pep::tests::connect::alice_authenticates_and_binds`.
- [x] Fix `omemo-stanza::DeviceList` element name — XEP-0384 v0.9 §5.3.1
      uses `<devices>` (plural), not `<list>`. Added `labelsig` attribute
      on `Device` for the XEdDSA signature over the label. All 11
      stanza round-trip tests still green.
- [x] PEP publish: own device list (`urn:xmpp:omemo:2:devices`) —
      `omemo_pep::publish_device_list`. Item id `"current"`.
- [x] PEP self-fetch: own device list — `omemo_pep::fetch_device_list`,
      with `peer: Option<BareJid>` so `None` means own account (works
      around Prosody self-PEP iq-tracker key mismatch — see
      `fetch_device_list` doc).
- [x] Integration test: `bob_publishes_and_fetches_own_device_list`
      round-trips a 3-device list via Prosody.
- [x] PEP publish: own bundle on `urn:xmpp:omemo:2:bundles`, item id =
      device id — `omemo_pep::publish_bundle`.
- [x] PEP self-fetch bundle — `omemo_pep::fetch_bundle(client, peer:
      Option<BareJid>, device_id)` (peer JID variant signed off too —
      same `Option<BareJid>` shape as device-list fetch).
- [x] Integration test: `charlie_publishes_and_fetches_own_bundle`
      round-trips a 3-prekey bundle via Prosody.
- [x] Integration: alice fetches bob's published bundle (cross-account
      peer fetch path) — exercised by the gate test.
- [x] publish-options compliance — `publish_device_list` ships
      `pubsub#access_model = open`, `publish_bundle` ships both
      `access_model = open` and `pubsub#max_items = max`. Verified
      against Prosody 13 (form is applied on auto-create).
- [x] SCE payload sym crypto in `omemo-twomemo::seal_payload` /
      `open_payload` (XEP-0384 v0.9 §4.4): random key + HKDF "OMEMO
      Payload" → AES-CBC body + 16-byte HMAC, key||hmac (48B) blob is
      what each recipient's session encrypts. Round-trip + tamper +
      bad-blob-length tests all green.
- [x] Compose `seal_payload` with per-device
      `TwomemoSession::encrypt_message` to produce the `<encrypted>`
      stanza — `omemo_pep::{encrypt_message, decrypt_message,
      Recipient}`. Single shared `<payload>`, one `<key rid=>` per
      recipient device. Tests: alice→bob single-device round-trip,
      alice→{bob_dev1, bob_dev2} multi-device round-trip, wrong-jid /
      wrong-device negative tests. `kex=false` for now (KEX wrapping
      lands with the X3DH-aware outbound interceptor).
- [x] X3DH active half of session bootstrap —
      `omemo_pep::bootstrap_active_session_from_bundle` consumes a
      stanza-level `Bundle`, picks an OPK id, runs X3DH active, and
      hands back a fresh `TwomemoSession` plus a `KexCarrier` (pk_id,
      spk_id, ik, ek) for wrapping the first outbound message.
- [x] `Recipient::kex: Option<KexCarrier>` triggers
      `OMEMOKeyExchange` wrapping (`kex=true`) on the per-device output
      bytes. KEX round-trip test: alice bootstraps active, encrypts,
      bob parses_key_exchange + X3DH passive + create_passive +
      decrypts → recovers plaintext byte-equal.
- [x] Stanza interceptor (outbound, with XMPP I/O): wired through the
      gate test — `omemo_pep::send_encrypted` wraps an `Encrypted` in
      a `<message type='chat'>` and sends via tokio-xmpp; the gate
      flows bundle fetch → `bootstrap_active_session_from_bundle` →
      `encrypt_message` → `send_encrypted` end-to-end. SQLite session
      persistence is intentionally separated into the `omemo-session
      integration` follow-up below.
- [x] Inbound API: `omemo_pep::{inbound_kind, decrypt_inbound_kex}`.
      `inbound_kind(...) -> InboundKind { Kex | Follow }` classifies
      an `<encrypted>` for our (jid, device_id);
      `decrypt_inbound_kex(...)` runs parse_key_exchange → X3DH passive
      → create_passive → decrypt → open_payload in one step, returning
      `(TwomemoSession, plaintext, consumed_opk_id)`. Caller-supplied
      `spk_pub_by_id` / `opk_pub_by_id` closures decouple the function
      from the SQLite store. `decrypt_message` remains the kex=false
      path.
- [x] Stanza interceptor (inbound, with XMPP I/O): wired through the
      gate test — `omemo_pep::wait_for_encrypted` drains the event
      stream until an OMEMO `<message>` arrives, then
      `inbound_kind` + `{decrypt_inbound_kex, decrypt_message}`
      yield `(TwomemoSession?, plaintext)`. Wiring SQLite session
      save + OPK consume is the `omemo-session integration` task
      below.
- [ ] SCE envelope (XEP-0420) wrap on the message-body path —
      `omemo-stanza::sce` already builds/parses
      `<envelope><content/><rpad/><time/><to/><from/></envelope>`,
      but the gate flow encrypts raw plaintext bytes. Production
      callers should serialise an SCE envelope into bytes,
      `seal_payload(envelope_bytes)`, then the receiver
      `open_payload` + parse the envelope back. Required for proper
      anti-tampering of the plaintext metadata (`to`/`from`/`time`)
      per XEP-0384 §4.4.
- [ ] Trust-on-first-use device acceptance (configurable) —
      currently the inbound flow trusts whatever device id appears
      in the `<encrypted>` header. Production needs a policy hook
      ("first-time devices: accept / reject / prompt") and a
      `trusted_devices` table in `omemo-session`.
- [x] publish-options compliance — both `publish_device_list` and
      `publish_bundle` now ship a `<publish-options>` data form per
      XEP-0384 v0.9: `pubsub#access_model = open` on both, plus
      `pubsub#max_items = max` on the bundle node. Verified green
      against Prosody 13 (server applies them on auto-create).
- [x] **Gate**: local Prosody integration test, two `omemo-pep`
      instances exchange 3 messages over real XMPP. ✅
      `omemo-pep::tests::gate::alice_to_bob_three_messages_over_real_xmpp`

## Stage 4 follow-ups (production hardening)

These don't gate Stage 4 — the gate is green — but they're prerequisites
before Stage 6 (real-client interop) can land. Roughly in dependency
order.

### 4-FU.1 — `omemo-session` SQLite integration ✅

- [x] Identity bootstrap helper (`omemo_pep::install_identity` +
      `IdentitySeed`) writes own IK seed, device id, SPK, and OPK pool
      into `omemo-session::Store`. `x3dh_state_from_store` /
      `bundle_from_store` reconstruct the in-memory `X3dhState` and
      stanza-level `Bundle` from that single source.
- [x] Outbound: `bootstrap_and_save_active` runs X3DH active and
      persists the freshly created session. `encrypt_to_peer` reloads
      the session via `TwomemoSession::from_snapshot`, runs one
      ratchet step, and saves the advanced state — no in-memory
      session state crosses the SQLite boundary.
- [x] Inbound KEX: `receive_first_message` looks up SPK/OPK pubs by
      id from the store, runs `decrypt_inbound_kex`, then
      atomically `consume_opk` + `save_session` via
      `Store::commit_first_inbound` (single SQLite tx).
- [x] Inbound follow-up: `receive_followup` loads the session,
      `decrypt_message`s the SCE envelope, persists the advanced
      session.
- [x] `crates/omemo-pep/tests/gate.rs` flows entirely through
      SQLite — no `X3dhState` or `TwomemoSession` lives in test
      locals across encrypt/decrypt boundaries.

### 4-FU.2 — StartTLS for production network use ✅

- [x] Re-enabled `tokio-xmpp/starttls` + `aws_lc_rs` +
      `rustls-native-certs` features (kept `insecure-tcp` alongside
      so localhost integration tests still work).
- [x] `connect_starttls(jid, password)` — wraps `Client::new` (SRV
      + StartTLS + native cert validation). Plus
      `connect_starttls_addr(jid, password, host_port)` for
      explicit-host deployments. `connect_plaintext` retained for
      localhost integration tests with a doc-comment pointer to
      `connect_starttls`.
- [x] `cargo deny`: added ISC + MIT-0 to allow-list (rustls + aws-lc-rs
      ecosystem). Added explicit ignores for RUSTSEC-2026-0118 and
      RUSTSEC-2026-0119 (hickory-proto 0.25 advisories — both
      DNSSEC/encoder paths we don't use; documented re-evaluation
      trigger when tokio-xmpp 6 lands).

### 4-FU.3 — XEP-0420 SCE envelope on the message body ✅

- [x] `omemo-stanza::sce::SceEnvelope` already round-trips canonically;
      added `body_text()` helper to extract the unescaped chat body
      from `<content>`.
- [x] Outbound (`omemo-pep::encrypt_to_peer`): wraps `body_text` in
      `<body xmlns='jabber:client'>...</body>`, builds an envelope with
      16 fresh random rpad bytes + an RFC 3339 UTC timestamp (hand-rolled
      Howard-Hinnant civil-from-days, no chrono dep), then encrypts the
      envelope XML.
- [x] Inbound (`receive_first_message` / `receive_followup`): parses
      the envelope, verifies `<to>` matches our JID (XEP-0384 §4.5),
      returns `InboundEnvelope { body, from_jid, timestamp }`. Drops
      with `StoreFlowError::WrongRecipient` on mismatch.
- [x] Gate test exchanges three real chat-text bodies through the
      envelope path.

### 4-FU.4 — TOFU device-trust policy ✅

- [x] `omemo-session` schema v2: `trusted_devices(jid, device_id,
      ik_pub, trust_state, first_seen_at)`. New types `TrustState`
      (`Pending` / `Trusted` / `Untrusted`) and `TrustedDevice`. New
      methods `record_first_seen` (atomic insert-if-absent, returns
      the resulting row so callers can detect IK drift), `set_trust`
      (UPDATE-only — explicit policy decision), `trusted_device`
      (lookup).
- [x] `omemo-pep::TrustPolicy` — `Tofu` (auto-Trusted on first sight)
      vs `Manual` (auto-Pending — the app prompts the user).
- [x] Inbound KEX (`receive_first_message`): records first-sight IK
      under the chosen policy *before* OPK consumption, so a
      rejected device does not burn a one-time prekey. On IK drift,
      returns `StoreFlowError::IkMismatch` (logs both stored and
      received fingerprints).
- [x] Outbound (`encrypt_to_peer`) and inbound follow-up
      (`receive_followup`) refuse `Untrusted` peers with
      `StoreFlowError::PeerUntrusted`. Pending and never-seen
      devices are allowed (KEX is the only path that can record an
      unseen IK on the wire).
- [x] Gate test asserts that alice's device is `Trusted` in bob's
      store after KEX. New unit tests cover Manual policy →
      Pending → set_trust → success, Untrusted blocking both
      directions, and IK-drift rejection without OPK consumption.

## Stage 5 — Group OMEMO (MUC) ✅

Algorithmically the same as Stage 4 (one shared `<payload>`, one
`<key rid=>` per recipient device, just across more recipient JIDs).
The Stage 5 work was XMPP-side: occupant discovery, real-JID mapping,
and groupchat fan-out.

### 5.1 — MUC join + occupant tracking ✅

- [x] `omemo-pep::muc` module: `MucRoom { jid, our_nick, occupants:
      HashMap<String, Occupant> }`, `Occupant { nick, real_jid,
      affiliation, role }`. `send_join` / `send_leave` send the
      directed presence; `handle_presence` parses
      `<x xmlns='muc#user'>` and updates the occupant table.
- [x] `accept_default_config` submits `muc#owner` form pinning
      `muc#roomconfig_whois = anyone` so the room is non-anonymous —
      required for OMEMO MUC since we need real JIDs to fetch each
      occupant's bundle.
- [x] Prosody MUC component (`conference.localhost`) registered with
      `muc_room_locking = false` and public-by-default flags.
- [x] 4 unit tests + integration test
      `two_clients_join_same_room_and_see_each_other`.

### 5.2 — Per-occupant device-list cache ✅

- [x] `MucRoom::refresh_device_lists(client, store)` walks every
      occupant with a real_jid, calls `pep::fetch_device_list`, and
      persists each result via `Store::upsert_device`. Self-PEP
      fetches are skipped (Prosody self-pubsub iq-result has no
      `from` and would hang the iq tracker).
- [x] Sequential by design — `tokio_xmpp::Client::send_iq` takes
      `&mut self`, so genuine in-flight concurrency would need a
      connection pool. Bot-sized rooms (≤ ~50 occupants) are RTT-
      bound; backpressure stays a follow-up if profiling motivates.
- [x] Integration test
      `refresh_pulls_each_occupants_device_list_into_store`.

### 5.3 — Outbound MUC message ✅

- [x] `omemo-pep::PeerSpec { jid, device_id, kex }` and
      `encrypt_to_peers(store, own_device_id, envelope_to,
      body_text, peers, providers)` seal one SCE envelope for the
      whole room and emit one `<key rid=>` per device.
      `envelope_to = room.jid` for groupchat (XEP-0384 §6.1).
- [x] `MucRoom::send_groupchat(client, &Encrypted)` wraps the
      `<encrypted>` in `<message type='groupchat' to='room@conf'>`.

### 5.4 — Inbound MUC message dispatch ✅

- [x] `MucRoom::resolve_sender_real_jid(&FullJid)` maps
      `from='room@conf/nick'` to the occupant's stored real bare JID
      so callers can route through the existing `inbound_kind` /
      `receive_first_message` / `receive_followup` pipeline.
- [x] `receive_first_message` / `receive_followup` got an
      `expected_envelope_to: &str` parameter — DM passes our_jid,
      groupchat passes room_jid. (XEP-0384 §4.5 envelope-`<to>`
      verification.)
- [x] Self-echo filtering is the caller's responsibility (compare
      resolved real JID vs `Store::get_identity()`).

### 5.5 — Gate ✅

- [x] `tests/muc.rs::three_clients_groupchat_omemo2_round_trip`:
      alice / bob / carol on `muc_e` / `muc_f` / `muc_g` exchange
      two OMEMO 2 group chat messages. Both are fan-out: alice runs
      X3DH active for bob+carol once, sends one `<message
      type='groupchat'>` carrying two `<key rid=>` entries, both
      bob and carol decrypt to the original body. Message #1 is
      KEX-wrapped (status 110 + IK record into TOFU trust store);
      message #2 is the follow-up.
- [x] `pump_three` helper drains all three streams concurrently
      (same reason as `pump_two`: Prosody broadcasts to whichever
      client is idling).
- [x] Cross-client interop with Conversations / Dino is Stage 6 —
      the original Stage 5 ambition was "3 omemo-rs + 1
      Conversations" but the Conversations leg requires a different
      gate environment and properly belongs to the external-client
      stage.

## Stage 5 follow-ups (production hardening)

These don't gate Stage 5 — the gate is green — but they tighten up
the ergonomics and durability of the production path. Roughly in
order of landing.

### 5-FU.1 — OPK auto-refill + bundle republish ✅

- [x] `Store::count_unconsumed_opks()`, `Store::next_opk_id()` —
      pool inspection helpers.
- [x] `omemo-pep::store::replenish_opks(store, target, rng)` —
      tops up the OPK pool to `target` unconsumed entries. Generic
      over `RngCore` so production can pass `OsRng` and tests can
      pass any seedable RNG.
- [x] `omemo-pep::store::publish_my_bundle(store, client, device_id)`
      — convenience wrapper that rebuilds the stanza-level bundle
      from the (refreshed) store and republishes via PEP. Pair with
      `replenish_opks` after every KEX-tagged inbound.
- [x] OPK ids are grow-only (`next_opk_id = MAX(id) + 1` over the
      whole `prekey` table, including consumed rows) so the spec's
      consume-once invariant is respected even across refills.

### 5-FU.2 — `install_identity_random` ✅

- [x] Production-side counterpart to `install_identity` /
      `IdentitySeed`. Draws every secret from `RngCore` (typical:
      `rand_core::OsRng`) and parameterises the OPK pool size so
      callers can match XEP-0384 §5.3.2's "≥ 100" recommendation.

### 5-FU.3 — `omemo-rs-cli` minimal client binary ✅

- [x] New workspace member `omemo-rs-cli` (path
      `crates/omemo-rs-cli/`, binary `omemo-rs-cli`). Three
      subcommands — `init` / `send --peer ... --peer-device ...
      --body ...` / `recv --timeout`. Defaults to `connect_starttls`;
      falls back to `--insecure-tcp <host:port>` for localhost.
- [x] First run: `install_identity_random(opk_count)` +
      `replenish_opks` + `publish_device_list` +
      `publish_my_bundle`.
- [x] Subsequent run: store reused; bundle republished on each
      connect (idempotent on PEP side).
- [x] `recv` refills + republishes after consuming an OPK so the
      bundle stays at target capacity.
- [x] Trust hard-coded to TOFU; production callers will eventually
      expose a flag and persist explicit user decisions.
- [x] End-to-end verified against the local Prosody fixture:
      muc_a → muc_b round-trip recovers the body bytes.

## Stage 6 — Real-Client Interop

### 6.1 — python-omemo (Syndace reference) ✅ automated

The interop pair we can drive ourselves end to end. Same library
the fixture pipeline already uses, so the test exercises **two
genuinely different OMEMO 2 codebases** against each other.

- [x] `test-vectors/integration/python-interop/interop_client.py`:
      slixmpp + python-omemo OMEMO 2 client (`send` / `recv`). Works
      around slixmpp-omemo 2.1's missing SCE plugin: the recv side
      catches `NotImplementedError` and parses the leaked
      plaintext envelope; the send side bypasses
      `xep_0384.encrypt_message` and goes straight to
      `SessionManager.encrypt` with a hand-built XEP-0420 envelope.
- [x] `crates/omemo-rs-cli/tests/python_interop.rs`: spawns the
      CLI binary + the python script and asserts both directions
      decrypt the same body bytes (`rust_send_python_recv` and
      `python_send_rust_recv`).
- [x] `.github/workflows/integration.yml` runs both interop tests
      after the existing Prosody-only suite. Stage 6 wire-format
      drift breaks CI on every PR.
- [x] `pyint_a` / `pyint_b` Prosody accounts (Dockerfile entrypoint).

### 6.2 — Conversations / Dino (manual)

External-client interop requires a phone or a desktop XMPP client
on the test bench, so it's not on the automated path. The
`omemo-rs-cli` binary is the right manual driver — point it at the
same Prosody account as Conversations / Dino and exchange chat
messages. Confirmed-working test for Stage 6.1 already proves the
wire format byte-equality with the spec authority's reference
stack, so a 6.2 failure would be a Conversations/Dino-specific
quirk rather than a spec violation on our side.

- [ ] DM: Conversations 2.x → omemo-rs
- [ ] DM: omemo-rs → Conversations
- [ ] DM: Dino → omemo-rs
- [ ] DM: omemo-rs → Dino
- [ ] MUC: same matrix
- [ ] Upgrade `nan-curunir` to use `omemo-rs` (separate repo, separate
      task list — out of scope for this project's TODO)
- [ ] Tag v0.1.0

---

## Cross-cutting / housekeeping

- [x] CI: GitHub Actions workflow `.github/workflows/ci.yml` —
      cargo fmt --check, clippy `-D warnings`, full workspace test
- [x] CI: weekly fixture-regen job (cron Mon 06:00 UTC) — installs
      pinned Syndace packages, regenerates fixtures, fails on drift
- [x] CI: `cargo deny` for licence check — `deny.toml` allow-list mode
      (MIT, Apache-2.0, BSD, Unicode-3.0), explicit deny on
      `libsignal-protocol{,-c}` + `openssl{,-sys}`, sources locked to
      crates.io. New `deny` job in CI via EmbarkStudios action. Verified
      local pass + AGPL negative test.
- [x] Benchmarks (`criterion`) for HKDF, AES-CBC, scalar mul +
      DH ratchet step + separate-HMACs KDF + OS RNG. Run via
      `cargo bench -p omemo-doubleratchet --bench crypto`.
- [x] Production `OsRngDhPrivProvider` in `omemo-doubleratchet` —
      OS-randomness-backed priv provider (uses `rand_core::OsRng`).
      Pairs with the existing test-only `FixedDhPrivProvider`.
- [x] `cargo fmt` + `cargo clippy --all-targets -D warnings` gated in CI —
      `RUSTFLAGS="-D warnings" cargo test --workspace` passes locally
- [x] `README.md` at repo root — project pitch, status table, license
      posture, quickstart, fixture regeneration recipe

### Stage 4 prep (no-server pieces)

- [x] XEP-0420 SCE envelope encode/decode in `omemo-stanza::sce`
      (6 round-trip + tolerance + negative tests)
