# omemo-rs Architecture

Pure-Rust implementation of **OMEMO 2** (XEP-0384 v0.9) for use as the E2EE
layer of an XMPP-based bot orchestrator (the planned successor to
[nan-curunir](https://github.com/Rockheung/nan-curunir)). This document is
intended to be detailed enough that the project can be rebuilt from scratch
with no other source than these docs.

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

### `omemo-xeddsa`
Curve25519 ↔ Ed25519 conversions, XEdDSA signing/verification, X25519 ECDH.
A direct port of `python-xeddsa`'s 11 public functions, which are themselves
CFFI bindings to `libxeddsa` (a libsodium-based C library).

### `omemo-doubleratchet`
The Double Ratchet algorithm (Signal Foundation spec) using:
* HKDF-SHA-256 root chain
* Separate-HMACs message chain KDF
* AES-CBC + HMAC-SHA-256 (truncated to 16 bytes) AEAD
* Curve25519 DH ratchet
Port of `python-doubleratchet` (Syndace).

### `omemo-x3dh`
Triple-DH key agreement for session initiation (one-time prekey, signed
prekey, identity key). Port of `python-x3dh`.

### `omemo-twomemo`
OMEMO 2 backend: takes `omemo-doubleratchet` and `omemo-x3dh` outputs and
encodes them per `twomemo.proto` (3 protobuf messages: `OMEMOMessage`,
`OMEMOAuthenticatedMessage`, `OMEMOKeyExchange`). Port of `python-twomemo`.

### `omemo-stanza`
Encodes/parses the XEP-0384 v0.9 stanza tree:
* `<encrypted xmlns='urn:xmpp:omemo:2'>` envelope
* `<header sid=...><keys jid=...><key rid=...>` recipient routing
* `<payload>` element (base64 of SCE envelope)
* `<bundle xmlns='urn:xmpp:omemo:2'>` for PEP publishing

### `omemo-session`
SQLite-backed persistence: own identity key, signed-prekey rotations,
one-time prekeys (consumed once each), per-device session ratchet state,
device list per JID.

### `omemo-pep`
XEP-0163 PEP integration on top of `tokio-xmpp`: publishes our bundle and
device list, subscribes to peers' `urn:xmpp:omemo:2:devices` and fetches
`urn:xmpp:omemo:2:bundles:{deviceId}` on demand.

### `omemo-test-harness`
Replays JSON fixtures generated by `test-vectors/scripts/gen_*.py` against
each Rust crate. Not a published crate — used only by `cargo test`.

## 6. Cryptographic algorithms (OMEMO 2 normative)

| Layer | Algorithm | Constant / parameter |
|---|---|---|
| DH | Curve25519 (X25519) | clamping per RFC 7748 |
| Identity signature | XEdDSA (libxeddsa-compat) | 64-byte deterministic nonce |
| Root chain KDF | HKDF-SHA-256 | info = `"OMEMO Root Chain"` |
| Message chain KDF | Separate HMACs over SHA-256 | constant input bytes per branch |
| AEAD | AES-256-CBC + HMAC-SHA-256 | tag truncated to 16 bytes; info = `"OMEMO Message Key Material"` |
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
