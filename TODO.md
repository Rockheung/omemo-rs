# omemo-rs — Active Task List

Live derivative of `docs/stages.md`. Tick items as they are completed.
When the box for a stage's gate test goes green, the whole stage is done.

Ordering reflects dependencies — do top to bottom.

---

## Status snapshot (2026-04-29)

| Stage | Status | Gate test |
|---|---|---|
| 0 — Workspace + pipeline | ✅ | `kdf_hkdf` |
| 1.1 — `omemo-xeddsa` | ✅ | `xeddsa` |
| 1.2 — `omemo-doubleratchet` | ✅ | `double_ratchet` |
| 1.3 — `omemo-x3dh` | ✅ | `x3dh` |
| 1.4 — `omemo-twomemo` | ✅ | `twomemo` (1 KEX + 3 messages, byte-equal protobuf) |
| 2 — `omemo-stanza` | ✅ | XEP-0384 §3+§5 round-trip + 3-recipient |
| 3 — `omemo-session` | ✅ | persist/restart 1:1 round-trip |
| 4 — `omemo-pep` | ⏳ | Prosody integration test |
| 5 — Group OMEMO | ⏳ | 3 omemo-rs + 1 Conversations in MUC |
| 6 — Real-client interop | ⏳ | Conversations + Dino DM/MUC |

**Stages 1–3 complete.** 29 test result groups green. Cross-cutting:
README, GitHub Actions CI (fmt + clippy + test + weekly fixture-drift),
XEP-0420 SCE envelope (Stage 4 prep) all in. `cargo fmt --all --check`
and `cargo clippy --workspace --all-targets -D warnings` both clean.

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
- [ ] OPK lifecycle (consumed-once enforcement) — currently the caller is
      responsible for deleting the consumed OPK; Stage 3 (omemo-session)
      will own this when sessions persist.
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

## Stage 4 — `omemo-pep` (XMPP integration)

- [ ] Pick XMPP library (probably `tokio-xmpp` from xmpp-rs)
- [ ] PEP publish: own device list and own bundle
- [ ] PEP fetch: peer device list, peer bundle on demand
- [ ] Stanza interceptor: encrypt outgoing `<message>` if recipient has
      device list
- [ ] Stanza interceptor: decrypt incoming `<message>` with `<encrypted>`
- [ ] SCE envelope wrapping (XEP-0420)
- [ ] Trust-on-first-use device acceptance (configurable)
- [ ] **Gate**: local Prosody integration test, two `omemo-pep` instances
      exchange 3 messages over real XMPP.

## Stage 5 — Group OMEMO (MUC)

- [ ] MUC occupant tracking (presence stanza parsing, real-JID resolution)
- [ ] Per-occupant device-list cache
- [ ] Bundle-fetch backpressure / parallelism control on join
- [ ] **Gate**: 3 omemo-rs clients + 1 Conversations client in a MUC,
      all four exchange and decrypt messages.

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
- [ ] Benchmarks (`criterion`) for HKDF, AES-CBC, scalar mul
- [x] `cargo fmt` + `cargo clippy --all-targets -D warnings` gated in CI —
      `RUSTFLAGS="-D warnings" cargo test --workspace` passes locally
- [x] `README.md` at repo root — project pitch, status table, license
      posture, quickstart, fixture regeneration recipe

### Stage 4 prep (no-server pieces)

- [x] XEP-0420 SCE envelope encode/decode in `omemo-stanza::sce`
      (6 round-trip + tolerance + negative tests)
