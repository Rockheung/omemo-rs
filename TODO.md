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
| 5 — Group OMEMO | ⏳ | 3 omemo-rs + 1 Conversations in MUC |
| 6 — Real-client interop | ⏳ | Conversations + Dino DM/MUC |

**Stages 1–4 complete.** alice and bob exchange three OMEMO 2 messages
end-to-end across a real Prosody — KEX bootstrap on M0, ratchet step on
M1/M2, byte-equal plaintext recovery on the receiving side. Crypto
layer is byte-equal with the Syndace Python reference (replay strategy,
ADR-004); transport layer is MPL-2.0 xmpp-rs (ADR-007). 51 self-
contained tests + 4 Prosody-backed integration tests all green.
`cargo fmt --all --check`, `cargo clippy --workspace --all-targets
-D warnings`, `cargo deny check licenses` all clean.

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

### 4-FU.1 — `omemo-session` SQLite integration

- [ ] Identity bootstrap helper: load own IK seed + device id + bundle
      pool from the `omemo-session::Store`, or generate them on first
      run. Single source of truth for `X3dhState` + the per-id SPK/OPK
      lookups our `decrypt_inbound_kex` callbacks need.
- [ ] Outbound: after `bootstrap_active_session_from_bundle`, persist
      the new `TwomemoSession` via
      `TwomemoSessionSnapshot::{encode,save_session}`. After every
      `encrypt_message`, save the advanced session state.
- [ ] Inbound: after `decrypt_inbound_kex`, persist the new session
      and call `Store::consume_opk(consumed_opk_id)` so the OPK
      cannot be reused. After every `decrypt_message`, save the
      advanced session state.
- [ ] Refactor `tests/gate.rs` to use the integrated path so the
      same flow round-trips through SQLite and survives a `Store`
      reopen.

### 4-FU.2 — StartTLS for production network use

- [ ] Re-enable `tokio-xmpp/starttls` + `aws_lc_rs` +
      `rustls-native-certs` features (turned off when we picked
      `insecure-tcp` for the localhost integration tests).
- [ ] Add `connect_starttls(jid, password)` — `Client::new` does SRV
      + StartTLS + native cert validation. Keep `connect_plaintext`
      for localhost integration tests.
- [ ] Document in `omemo-pep` README which entry point to use when.

### 4-FU.3 — XEP-0420 SCE envelope on the message body

- [ ] Wrap outbound plaintext in `omemo-stanza::sce::Envelope` with
      `<to>`, `<from>`, `<time>`, `<rpad>` (random 0–200 bytes) and
      then `seal_payload(envelope.encode())`.
- [ ] Inbound: `open_payload` → parse envelope → verify `to` matches
      our JID, drop messages with mismatched `to`/`from` per
      XEP-0384 §4.5 (anti-tampering).
- [ ] Update gate test to round-trip the envelope.

### 4-FU.4 — TOFU device-trust policy

- [ ] `omemo-session`: add `trusted_devices` table (`(jid, device_id,
      ik_pub, trust_state, first_seen_at)`).
- [ ] Inbound: on first `<encrypted>` from a previously unseen
      `(jid, device_id)`, consult policy hook (`PolicyTofu`,
      `PolicyManual`, ...).
- [ ] Outbound: warn / refuse if any peer device is in `Untrusted`
      state.

## Stage 5 — Group OMEMO (MUC)

Algorithmically the same as Stage 4 (one shared `<payload>`, one
`<key rid=>` per recipient device, just across more recipient JIDs).
The new work is XMPP-side: occupant discovery, real-JID mapping, and
bundle-fetch concurrency on join.

- [ ] MUC join + occupant tracking (XEP-0045 presence parsing,
      real-JID resolution from `<x xmlns='http://jabber.org/protocol/
      muc#user'><item jid='real@bare/res'/></x>`).
- [ ] Per-occupant device-list cache, refreshed on PEP `<event>` for
      each room member.
- [ ] Bundle-fetch backpressure on join — limit concurrent
      `fetch_bundle` to N (avoid stampeding a 50-occupant room).
- [ ] Outbound MUC message: encrypt for *every* device of *every*
      occupant (excluding our own); use `groupchat` message type,
      `to=room@conf` bare.
- [ ] Inbound MUC message: dispatch via `inbound_kind` exactly as
      Stage 4; the only new thing is the `from` JID is the room +
      occupant nick, real JID looked up via the cache.
- [ ] **Gate**: 3 omemo-rs clients + 1 Conversations client in a
      MUC, all four exchange and decrypt messages.

## Stage 6 — Real-Client Interop

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
