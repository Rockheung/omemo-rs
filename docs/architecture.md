# omemo-rs Architecture

Pure-Rust implementation of **OMEMO 2** (XEP-0384 v0.9) for use as the E2EE
layer of an XMPP-based bot orchestrator (the planned successor to
[nan-curunir](https://github.com/Rockheung/nan-curunir)). This document is
intended to be detailed enough that the project can be rebuilt from scratch
with no other source than these docs.

## Big picture

The codebase is built bottom-up as two stacked layers, with external
interop on top. The stage plan in `docs/stages.md` follows this layering
exactly.

**Layer A — Crypto + data structures (Stages 0–3, ✅ complete)**

Pure functions and in-memory state machines. No network, no async, no
external services. Only compile-time deps are RustCrypto, prost,
quick-xml, rusqlite.

```
seed/priv → XEdDSA sign → X3DH agree → DoubleRatchet state
         → twomemo wire → XML stanza → SQLite persistence
```

Every step is byte-equal with the Syndace Python reference (replay
strategy, ADR-004), so Layer A can be checked from a single
`cargo test --workspace` with no servers or external accounts. License
chain is MIT throughout (ADR-002).

In principle Layer A is enough to handle OMEMO 2 end-to-end. The only
thing missing is *who delivers the bytes*.

**Layer B — XMPP transport (Stages 4–5)**

Glues Layer A onto a real XMPP stack (`tokio-xmpp`):
* Stage 4 — `omemo-pep`: PEP publish/fetch for own device list and
  bundle, plus stanza interceptors that wrap/unwrap `<encrypted>` on
  outbound/inbound `<message>`. SCE envelope (XEP-0420) is the plaintext
  format inside the wrapper (already implemented in `omemo-stanza::sce`
  as Stage 4 prep).
* Stage 5 — Group OMEMO: extends Stage 4 to MUC rooms (XEP-0384 §6).
  Adds occupant-JID resolution and bundle-fetch backpressure.

The cryptographic primitives do not change between Stages 4 and 5;
what's new is async orchestration and presence/PEP discovery flows.

**Layer C — External-client interop (Stage 6)**

Cross-implementation interop with Conversations (Android) and Dino
(Linux desktop), DM and MUC. Passing this layer unlocks v0.1.0 and the
nan-curunir migration off matrix-sdk (the original motivation, §1).

### Why this layering matters

If a bug appears in Stages 4–6, the byte-equal guarantee on Layer A
means the fault is almost certainly in transport / async timing / PEP
encoding — not in the crypto. This narrows debugging from "could be
anywhere in 6 crates" to "the integration glue and the wire framing".
This is the practical dividend of the replay-based test strategy
(ADR-004).

| Stage | Layer | Primary risk | Self-contained tests? |
|---|---|---|---|
| 0–3 | A | Algorithm porting | yes (`cargo test`) |
| 4   | B | Async glue, PEP semantics | requires Prosody |
| 5   | B | Membership, concurrency | requires Prosody |
| 6   | C | Spec-interpretation drift between clients | requires Conversations + Dino |

## 1. Why this project exists

`nan-curunir` is a Matrix-based AI bot manager. The team running it found
matrix-sdk (0.9, mid-2026) too unstable for production: cross-signing UIAA
edge cases, frequent crypto-store-loss recovery code, Continuwuity-specific
admin-room API quirks, and a generally heavy E2EE machinery.

XMPP is far simpler as a wire protocol (XML stanzas, well-defined XEPs), with
multiple battle-tested servers (Prosody, ejabberd, Snikket). The trade-off
is that XMPP's E2EE story (OMEMO) has weaker tooling in Rust: the official
reference is libsignal, which is **AGPL-3.0**, and would force the rewrite
onto AGPL.

This project produces a permissively-licensed (MIT) Rust OMEMO 2 stack so
the bot manager can be rewritten in Rust with the same licence as today.

## 2. Scope

* **OMEMO 2 only** (`urn:xmpp:omemo:2`, namespace from XEP-0384 v0.9).
* **No OMEMO 0.3.0** (`eu.siacs.conversations.axolotl`, "oldmemo"). 0.3 is
  axolotl-namespace and the only complete reference is `python-oldmemo`,
  which is AGPL-3.0 because it inherits from libsignal.
* **No MUC OMEMO support in v1** — direct messages only at first (XEP-0384
  §4 / §5). MUC support (XEP-0384 §6) is planned in Stage 5 once 1:1 is
  rock-solid.

## 3. License posture

| Layer | Licence |
|---|---|
| Our crates | MIT |
| `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `hmac`, `sha2`, `aes`, `cbc` | BSD/MIT/Apache (RustCrypto) |
| `prost` (protobuf) | Apache-2.0 |
| Python oracle (`doubleratchet`, `x3dh`, `xeddsa`, `twomemo`, `omemo`) | MIT — used only at build/test time |
| `libxeddsa` (C, via Python wheel) | MIT — also build/test only |
| **Avoided**: `libsignal` Rust crate | AGPL-3.0 |
| **Avoided**: `python-oldmemo` | AGPL-3.0 |

The runtime crate graph contains only MIT/Apache/BSD code.

## 4. Workspace layout

```
omemo-rs/
├── Cargo.toml                 # workspace, RustCrypto/prost/serde shared deps
├── crates/
│   ├── omemo-xeddsa/          # XEdDSA + Curve25519/Ed25519 ops
│   ├── omemo-doubleratchet/   # Double Ratchet algorithm
│   ├── omemo-x3dh/            # X3DH key agreement
│   ├── omemo-twomemo/         # OMEMO 2 backend (twomemo.proto encoding)
│   ├── omemo-stanza/          # XEP-0384 v0.9 stanza encode/parse
│   ├── omemo-session/         # SQLite-backed session store, multi-device
│   ├── omemo-pep/             # XEP-0163 PEP + tokio-xmpp integration
│   └── omemo-test-harness/    # Cross-language replay tests (no published crate)
├── docs/
│   ├── architecture.md        # this file
│   ├── pipeline.md            # test-vector replay pipeline
│   ├── stages.md              # phase-by-phase development plan
│   ├── crypto-spec.md         # algorithm choices & constants
│   └── decisions.md           # ADR-style decision log
├── test-vectors/
│   ├── .venv/                 # Python venv with reference packages (gitignored)
│   ├── reference/             # cloned upstream Python repos (gitignored)
│   ├── scripts/gen_*.py       # fixture generators
│   └── fixtures/*.json        # generated fixtures (committed)
└── TODO.md                    # active task list
```

## 5. Crate responsibilities

### `omemo-xeddsa` ✅
Curve25519 ↔ Ed25519 conversions, XEdDSA signing/verification, X25519 ECDH.
A direct port of `python-xeddsa`'s 11 public functions, which are themselves
CFFI bindings to `libxeddsa` (a libsodium-based C library). XEdDSA matches
the libxeddsa variant, not the Signal spec — see ADR-003.

### `omemo-doubleratchet` ✅
The Double Ratchet algorithm (Signal Foundation spec):
* `aead` — AES-256-CBC + HMAC AEAD (full HMAC tail; the 16-byte truncation
  is twomemo's override and lives in `omemo-twomemo`, see ADR-006).
* `kdf_hkdf` — HKDF wrapper, type-bound info string (e.g.
  `OmemoRootKdf` = HKDF-SHA-256 with `info = "OMEMO Root Chain"`).
* `kdf_separate_hmacs` — message-chain KDF; per-byte HMAC concat.
* `kdf_chain` — generic KDF chain wrapper (key + step counter).
* `symmetric_key_ratchet` — sending + receiving chains with rotation.
* `dh_ratchet` — Curve25519 DH ratchet over `x25519-dalek`. Pluggable
  priv generation (`DhPrivProvider`) for OS-RNG in production / fixed
  queue in tests.
* `double_ratchet` — top-level state machine. FIFO of skipped message
  keys (`MAX_SKIP=1000`), configurable `BuildAdFn`, decrypt-on-clone
  semantics matching python's `copy.deepcopy` of the DH ratchet (clone
  runs the tentative step; only commit on AEAD success).

### `omemo-x3dh` ✅
Triple-DH key agreement for session initiation (one-time prekey, signed
prekey, identity key). Port of `python-x3dh` configured for OMEMO 2:
`IdentityKeyFormat::Ed25519`, info = `"OMEMO X3DH"`, hash = SHA-256,
`_encode_public_key` is pass-through. SPK is signed with the raw IK priv
(not `priv_force_sign(...)`) since the bundle ships the IK in Ed25519
form — see the `project_spk_sig_format_dependent` memory.

### `omemo-twomemo` ✅
OMEMO 2 wire-format backend. `prost-build` codegens
`twomemo.proto` (committed in `test-vectors/twomemo/`) at compile time
via `protoc-bin-vendored` (no system `protoc` install needed):
* `aead_encrypt` / `aead_decrypt` — AEAD override. Truncates HMAC to
  16 bytes, wraps the AES-CBC ciphertext in `OMEMOMessage` (with header
  fields), HMACs over `(ad_x3dh) || OMEMOMessage_bytes`, returns a
  serialized `OMEMOAuthenticatedMessage`.
* `TwomemoSession` — DH ratchet + skipped-keys FIFO + X3DH-derived AD,
  with `encrypt_message` / `decrypt_message` returning/consuming wire
  bytes. Mirrors python-twomemo's `DoubleRatchetImpl` semantics.
* `build_key_exchange` / `parse_key_exchange` — wrap the first
  `OMEMOAuthenticatedMessage` in an `OMEMOKeyExchange` with `(pk_id,
  spk_id, ik, ek)` for the receiver to look up by id.

### `omemo-stanza` ✅
Encodes/parses the XEP-0384 v0.9 stanza tree on top of `quick-xml` (MIT):
* `<encrypted xmlns='urn:xmpp:omemo:2'>` envelope (multi-recipient
  `<header sid=...><keys jid=...><key rid=... kex=?>` + optional
  `<payload>` for SCE bytes)
* `<bundle xmlns='urn:xmpp:omemo:2'>` (`<spk id=>`, `<spks>`, `<ik>`,
  `<prekeys><pk id=>...</prekeys>`)
* `<list xmlns='urn:xmpp:omemo:2'>` (`<device id= label=?>`).

Decoder is tolerant (attribute order, XML decl, whitespace, self-closing
root). Encoder is canonical: `xmlns` first, then attributes in a fixed
order; `kex="true"` only emitted when set; key material always
RFC-4648 base64 (no line wrapping). 11 round-trip + tolerance + negative
tests gate it.

### `omemo-session` ✅
SQLite-backed persistence on top of `rusqlite` (bundled SQLite, no
system dep). Forward-only migrations under `migrations/0001_init.sql`,
WAL mode + foreign keys on, `schema_version` table for future bumps. Six
tables: `identity` (single row, IK seed + JID + device id),
`signed_prekey`, `prekey` (with `consumed` boolean — `consume_opk()`
enforces consumed-once), `device_list`, `session` (TwomemoSession state
as a length-prefixed BLOB), `message_keys_skipped` (schema-only until
Stage 5+).

Session BLOB format is decided by `omemo-twomemo::TwomemoSessionSnapshot`
(versioned, deterministic). Session save/load goes through `Store::
save_session` / `load_session_snapshot`; the priv provider is supplied
by the caller on restore (production: OS RNG; tests: `FixedDhPrivProvider`).

### `omemo-pep` ⏳
XEP-0163 PEP integration on top of `tokio-xmpp`: publishes our bundle and
device list, subscribes to peers' `urn:xmpp:omemo:2:devices` and fetches
`urn:xmpp:omemo:2:bundles:{deviceId}` on demand.

### `omemo-test-harness` ✅
Replays JSON fixtures generated by `test-vectors/scripts/gen_*.py` against
each Rust crate. Not a published crate — used only by `cargo test`.
Test inventory at completion of Stage 1 (10 replay tests, see
`docs/pipeline.md` §10):
`xeddsa`, `kdf_hkdf`, `aead_aes_hmac`, `kdf_separate_hmacs`, `kdf_chain`,
`symmetric_key_ratchet`, `dh_ratchet`, `double_ratchet`, `x3dh`, `twomemo`.

## 6. Cryptographic algorithms (OMEMO 2 normative)

| Layer | Algorithm | Constant / parameter |
|---|---|---|
| DH | Curve25519 (X25519) | clamping per RFC 7748 |
| Identity signature | XEdDSA (libxeddsa-compat) | 64-byte deterministic nonce (ADR-003) |
| X3DH KDF | HKDF-SHA-256 | info = `"OMEMO X3DH"`, salt = 0×32, IKM = `0xFF×32 ‖ DH1‖DH2‖DH3‖DH4?` |
| Root chain KDF | HKDF-SHA-256 | info = `"OMEMO Root Chain"` |
| Message chain KDF | Separate HMACs over SHA-256 | data = `b"\x02\x01"` (twomemo `MESSAGE_CHAIN_CONSTANT`) |
| AEAD HKDF | HKDF-SHA-256 | info = `"OMEMO Message Key Material"`, 80-byte split = 32 enc ‖ 32 auth ‖ 16 IV |
| AEAD encrypt | AES-256-CBC (PKCS#7) + HMAC-SHA-256 | full HMAC tail at the doubleratchet layer; **16-byte truncation** at the twomemo layer (ADR-006) |
| Stanza encryption | XEP-0420 SCE | inside `<envelope>` element |
| Padding | none (XEP-0420 SCE) | content + RPad element |
| Wire encoding | Protocol Buffers (proto2) | `twomemo.proto` (committed copy in test-vectors/twomemo/) |

See `docs/crypto-spec.md` for byte-level details, info strings, and the
exact KDF derivations.

## 7. Compatibility target

The Rust output must be byte-identical to the Syndace Python stack on every
test fixture (see `docs/pipeline.md`). Final acceptance is **a successful
round-trip with Conversations and Dino** over a real XMPP server (Stage 6).

## 8. Out of scope

* Old OMEMO (0.3.0 / oldmemo / siacs)
* MUC OMEMO before Stage 5
* Group encryption optimisations (Megolm-equivalent) — OMEMO 2 sends one
  encrypted key per recipient device per message and that is fine for the
  bot-sized rooms this project targets.
* Hardware token / smartcard backed keys.
* Web/JS / Wasm builds. (Library is `no_std`-friendly where reasonable but
  the storage layer assumes a real filesystem and SQLite.)
