# omemo-rs — Active Task List

Live derivative of `docs/stages.md`. Tick items as they are completed.
When the box for a stage's gate test goes green, the whole stage is done.

Ordering reflects dependencies — do top to bottom.

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

### 1.2 — `omemo-doubleratchet` ⏳

In dependency order. Each item: generator script + Rust port + replay
test, all green together.

- [ ] AEAD (AES-256-CBC + HMAC-SHA-256, 16-byte tag)
      - `gen_aead_aes_hmac.py`, `tests/aead_aes_hmac.rs`,
        `crates/omemo-doubleratchet/src/aead.rs`
- [ ] HKDF wrapper (already covered by Stage 0; just expose typed wrapper)
- [ ] Separate-HMACs message chain KDF
      - `gen_kdf_separate_hmacs.py`, `tests/kdf_separate_hmacs.rs`
- [ ] Generic chain wrapper (`KDFChain`)
- [ ] Symmetric key ratchet (one chain)
      - `gen_symmetric_key_ratchet.py`, replay
- [ ] Curve25519 DH ratchet
      - `gen_dh_ratchet.py`, replay
- [ ] Top-level `DoubleRatchet` state machine
      - skipped-message-keys cap (`MAX_SKIP=1000`)
      - header AD construction
      - **Gate**: 4-message round-trip with mid-conversation DH ratchet
        step + 1 skipped + 1 out-of-order delivery, byte-equal with
        Python.

### 1.3 — `omemo-x3dh` ⏳

- [ ] Bundle generation (IK / SPK / OPKs)
- [ ] Bundle verification (SPK signature check via XEdDSA)
- [ ] Active session (Alice initiates)
- [ ] Passive session (Bob receives KEX, consumes OPK)
- [ ] OPK lifecycle (consumed-once enforcement)
- [ ] **Gate**: full active/passive bundle exchange replays byte-equal
      with python-x3dh including OPK consumption.

### 1.4 — `omemo-twomemo` ⏳

- [ ] `prost-build` codegen of `twomemo.proto` (already in
      `test-vectors/twomemo/twomemo.proto`)
- [ ] `OMEMOMessage` encode/decode
- [ ] `OMEMOAuthenticatedMessage` encode/decode
- [ ] `OMEMOKeyExchange` encode/decode
- [ ] Glue: take `omemo-doubleratchet` + `omemo-x3dh` outputs and emit
      protobuf bytes
- [ ] **Gate**: "Alice initiates with Bob, sends 1 KEX + 3 messages"
      end-to-end protobuf wire format byte-equal with python-twomemo.

## Stage 2 — `omemo-stanza` (XEP-0384 v0.9 stanza)

- [ ] Choose XML library (likely `quick-xml`, MIT)
- [ ] `<encrypted>` envelope encode/decode (with multiple `<keys jid=>`,
      `<key rid=>`, `kex` flag)
- [ ] `<bundle>` encode/decode (spk/spks/ik/prekeys)
- [ ] `<list>` (device list) encode/decode
- [ ] **Gate**: round-trip of every example stanza in XEP-0384 v0.9 §3
      and §5 + a custom 3-recipient message. Canonicalised attribute
      order.

## Stage 3 — `omemo-session` (SQLite store)

- [ ] Schema migration system (`migrations/0001_init.sql` etc.)
- [ ] Tables: identity, signed_prekey, prekey, device_list, session,
      message_keys_skipped
- [ ] CRUD for each table
- [ ] Ratchet-state BLOB serde (deterministic, length-prefixed)
- [ ] WAL mode, transaction wrappers
- [ ] **Gate**: identity creation → bundle gen → 1:1 session round-trip
      → process restart → session continues without rekeying.

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

- [ ] CI: GitHub Actions workflow for `cargo test --workspace`
- [ ] CI: weekly fixture-regen job to detect upstream drift
- [ ] CI: `cargo deny` for licence check (block AGPL re-introduction)
- [ ] Benchmarks (`criterion`) for HKDF, AES-CBC, scalar mul
- [ ] `cargo fmt` + `cargo clippy --all-targets --all-features -D warnings`
      gating in CI
- [ ] `README.md` at repo root (currently no README — public repo could
      use one once Stage 1 is complete enough to demo)
