# Development Stages

This is the master plan, with definition-of-done criteria ("gates") for each
stage. A stage is not done until its gate test is green. The TODO.md at the
repo root is the live, checkbox-style derivative of this document.

## Stage 0 — Workspace + Test-Vector Pipeline ✅

**Goal**: Establish the cross-language replay infrastructure before writing
any crypto code.

**Deliverables**:
* Cargo workspace with 8 stub crates (see `architecture.md` §4).
* Python venv with the 5 Syndace MIT packages installed.
* `omemo-test-harness` crate that loads JSON fixtures from
  `test-vectors/fixtures/` via a path-walking helper (`load_fixture`).
* One end-to-end fixture/replay pair as proof-of-life: HKDF
  (`scripts/gen_kdf_hkdf.py` + `tests/kdf_hkdf.rs`), 16 cases.

**Gate**: `cargo test -p omemo-test-harness --test kdf_hkdf` passes against
fixtures generated from `python-doubleratchet`.

## Stage 1 — Crypto Layer

The largest stage. Subdivided. Each sub-stage follows the same recipe:
generator script → JSON fixtures → Rust port → replay test → green.

### 1.1 — `omemo-xeddsa` ✅

**Scope**: 11 functions matching `python-xeddsa` (CFFI binding to libxeddsa).

* `seed_to_priv(seed)` — Ed25519 seed expansion + clamp
* `seed_to_ed25519_pub(seed)` — standard Ed25519 derive
* `priv_to_curve25519_pub(priv)` — clamp, scalar-mult, encode Montgomery
* `priv_to_ed25519_pub(priv)` — clamp, scalar-mult, encode Edwards
* `priv_force_sign(priv, set_sign_bit)` — clamp + negate scalar if needed
* `curve25519_pub_to_ed25519_pub(curve, sign)` — Mont→Edwards birational map
* `ed25519_pub_to_curve25519_pub(ed)` — Edwards→Mont
* `x25519(priv, curve_pub)` — ECDH with all-zero rejection
* `ed25519_seed_sign(seed, msg)` — standard RFC 8032 Ed25519 sign
* `ed25519_verify(sig, ed_pub, msg)` — RFC 8032 verify
* `ed25519_priv_sign(priv, msg, nonce)` — **libxeddsa-variant** XEdDSA
  sign (see ADR-003)

**Built on**: `curve25519-dalek` 4.x, `ed25519-dalek` 2.x, `sha2`.

**Gate**: 8 cases × 13 primitives = 104 assertions in
`tests/xeddsa.rs` all pass.

### 1.2 — `omemo-doubleratchet` ⏳

**Scope**: Port of `python-doubleratchet` 1.3.x.

Sub-modules to port (in dependency order):
1. `recommended/aead_aes_hmac.py` — AES-256-CBC + HMAC-SHA-256 (16-byte tag)
2. `recommended/kdf_hkdf.py` — HKDF wrapper (✅ fixture already exists)
3. `recommended/kdf_separate_hmacs.py` — HMAC chain KDF
4. `kdf_chain.py` — generic chain wrapper
5. `symmetric_key_ratchet.py` — message-key ratchet (one chain)
6. `recommended/diffie_hellman_ratchet_curve25519.py` — DH ratchet
7. `diffie_hellman_ratchet.py` — generic DH ratchet wrapper
8. `double_ratchet.py` — top-level state machine, header AD, skipped keys

**Each sub-module gets**:
* `scripts/gen_<module>.py` — emits JSON cases.
* `crates/omemo-test-harness/tests/<module>.rs` — replay.
* Implementation in `crates/omemo-doubleratchet/src/<module>.rs` (or one
  flat `lib.rs` if small enough).

**Gate**: A full DH-ratchet round-trip (Alice → Bob → Alice → Bob, with
one DH ratchet step in the middle, one skipped message, and one
out-of-order delivery) replays byte-equal across all messages.

### 1.3 — `omemo-x3dh` ⏳

**Scope**: Port of `python-x3dh` 1.3.x.

Implements X3DH key agreement:
* Identity Key (IK), Signed PreKey (SPK), one-time PreKeys (OPKs), Ephemeral
  Key (EK).
* Bundle = `IK_pub`, `SPK_pub` + sig, `OPK_pubs[]`.
* `KDF(F || DH1 || DH2 || DH3 || DH4?)` where `F = b"\xFF" * 32` for
  Curve25519 (see X3DH spec §3.3).
* Output: shared secret SK + associated data AD.

**Gate**: A full active/passive bundle exchange replays byte-equal,
including OPK consumption.

### 1.4 — `omemo-twomemo` ⏳

**Scope**: Port of `python-twomemo` 2.1.x.

Wraps `omemo-doubleratchet` and `omemo-x3dh` and emits the three protobuf
messages defined in `test-vectors/twomemo/twomemo.proto`:

```proto
message OMEMOMessage           { uint32 n; uint32 pn; bytes dh_pub; bytes ciphertext? }
message OMEMOAuthenticatedMessage { bytes mac; bytes message }
message OMEMOKeyExchange       { uint32 pk_id; uint32 spk_id; bytes ik; bytes ek; OMEMOAuthenticatedMessage message }
```

**Gate**: An end-to-end "Alice initiates session with Bob, sends 1 KEX +
3 messages" replays byte-equal at the protobuf wire-format level.

## Stage 2 — `omemo-stanza` (XEP-0384 v0.9)

**Scope**: XML stanza encode/parse for the OMEMO 2 wire format.

**Element tree to handle**:
```xml
<encrypted xmlns='urn:xmpp:omemo:2'>
  <header sid='27183'>
    <keys jid='juliet@capulet.lit'>
      <key rid='31415' kex='true'>b64</key>
      <key rid='31416'>b64</key>
    </keys>
    <keys jid='other@server'>...</keys>
  </header>
  <payload>b64-of-SCE-envelope</payload>
</encrypted>

<bundle xmlns='urn:xmpp:omemo:2'>
  <spk id='1'>b64</spk>
  <spks>b64-signature</spks>
  <ik>b64</ik>
  <prekeys>
    <pk id='1'>b64</pk>
    ...
  </prekeys>
</bundle>

<list xmlns='urn:xmpp:omemo:2'>   <!-- device list -->
  <device id='27183' label='Optional Display Label' />
</list>
```

**XML library**: `quick-xml` (MIT). No `tokio-xmpp` dep at this layer —
`omemo-stanza` only deals with element trees.

**Gate**: round-trip of every example stanza in XEP-0384 v0.9 §3 and §5
plus a hand-written sample with three recipients. Byte-equal serialisation
back to the original XML (modulo attribute ordering, which we will
canonicalise).

**Note**: XEP-0384 v0.9 §3.1 requires the payload to be a XEP-0420 SCE
envelope. We will handle the SCE envelope construction in Stage 4 (where
it integrates with PEP / tokio-xmpp); Stage 2 only validates the outer
OMEMO envelope.

## Stage 3 — `omemo-session`

**Scope**: SQLite-backed persistent storage. No protobuf, no XML — just
state.

Tables:
* `identity` (single row): own IK seed, device ID, JID.
* `signed_prekey`: id, priv, pub, sig, created_at, replaced_at?
* `prekey`: id, priv, pub, consumed (bool), created_at.
* `device_list`: jid, device_id, last_seen_at, our_subscription_state.
* `session`: jid, device_id, ratchet_state (BLOB, length-prefixed), created_at, updated_at.
* `message_keys_skipped`: jid, device_id, dh_pub, n, mk (BLOB), expires_at.

**Concurrency**: WAL mode, single-writer assumption, row-level locking via
SQLite transactions.

**Migration story**: schema_version table; migrations are forward-only
SQL files in `crates/omemo-session/migrations/`.

**Gate**: A test that creates an identity, generates a bundle, runs a
session round-trip, restarts (re-opens the DB), and continues the session
from persisted state without re-keying.

## Stage 4 — `omemo-pep` (XMPP integration)

**Scope**: Hook into `tokio-xmpp` and implement the PEP (XEP-0163) flows.

Outbound:
* On startup: publish own device list (`urn:xmpp:omemo:2:devices` PEP node).
* On startup: publish own bundle (`urn:xmpp:omemo:2:bundles:{deviceId}`)
  with `pubsub#access_model = open` and `pubsub#max_items = 1`.
* On message send: ensure session for each recipient device, encrypt key
  per device, wrap in `<encrypted>` stanza, send.

Inbound:
* On `<message>` with `<encrypted xmlns='urn:xmpp:omemo:2'>`: locate our
  device's encrypted key, decrypt, advance ratchet, deliver plaintext.
* On PEP `<event>` for a peer's device list: refresh our cache, fetch new
  bundles as needed.
* SCE envelope wrapping/unwrapping (XEP-0420).

**Gate**: A local Prosody-based integration test (started by the test
harness via `prosodyctl`) where two `omemo-pep` instances exchange three
messages.

## Stage 5 — Group OMEMO (MUC)

**Scope**: Extend Stage 4 to MUC rooms (XEP-0384 §6).

Per the spec, MUC OMEMO is "the same encrypted-key-per-device fanout but
the message body is one ciphertext for all recipients". Practical issues:
* Membership tracking: MUC presence stanzas tell us occupant JIDs; we have
  to map them to real JIDs to then resolve their device lists.
* Joins: bundle-fetch storm when a many-occupant room is joined.
* Leaves: stale device lists; eventual-consistency only.

**Gate**: Three `omemo-pep` clients + one Conversations client in a MUC,
all four exchange and decrypt messages.

## Stage 6 — Real-Client Interop

**Scope**: Cross-implementation interop with at least Conversations and
Dino, both DM and MUC.

**Gate**:
1. Conversations 2.x sends DM → omemo-rs client decrypts.
2. omemo-rs client sends DM → Conversations decrypts.
3. Same with Dino.
4. MUC variant of each.

After Stage 6 passes, the library is considered v0.1.0 candidate.
