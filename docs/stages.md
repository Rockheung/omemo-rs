# Development Stages

This is the master plan, with definition-of-done criteria ("gates") for each
stage. A stage is not done until its gate test is green. The TODO.md at the
repo root is the live, checkbox-style derivative of this document.

**Status (2026-05-02)**: Stages 0–5 complete; Stage 4 follow-ups
4-FU.1 through 4-FU.4 done. Crypto layer is byte-equal with the
Syndace Python stack, XEP-0384 v0.9 stanzas round-trip canonically,
SQLite-backed identity/SPK/OPK/session persistence is the system of
record on both sides of the gate, message bodies are wrapped in
XEP-0420 SCE envelopes with `<to>`-verification on inbound, peer
devices are tracked under a TOFU/Manual trust policy with IK-drift
detection, production deployments ship StartTLS via
`connect_starttls` (rustls + aws-lc-rs + native cert validation),
two `omemo-pep` instances exchange three OMEMO 2 chat messages over
a real Prosody (`tests/gate.rs`), and three `omemo-pep` instances
exchange OMEMO 2 group-chat messages over a real Prosody MUC
(`tests/muc.rs::three_clients_groupchat_omemo2_round_trip`). Stage 6
(Conversations + Dino interop) is the remaining track — it needs
external clients and so cannot be self-contained in this repo's
test suite.

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

### 1.2 — `omemo-doubleratchet` ✅

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

### 1.3 — `omemo-x3dh` ✅

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

### 1.4 — `omemo-twomemo` ✅

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

## Stage 2 — `omemo-stanza` (XEP-0384 v0.9) ✅

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

## Stage 3 — `omemo-session` ✅

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

## Stage 4 — `omemo-pep` (XMPP integration) ✅

**Scope**: Hook into `tokio-xmpp` (xmpp-rs 5, MPL-2.0 — ADR-007) and
implement the PEP (XEP-0163) + `<message>` flows. License chain stays
clean because MPL-2.0 is file-scoped weak copyleft, not infectious.

**Built**:
* Transport: `connect_plaintext(jid, password, addr)` (localhost
  integration only); production StartTLS queued.
* PEP publish/fetch:
    - `publish_device_list(client, &DeviceList)` — single item id
      `"current"`, with `<publish-options>` data form setting
      `pubsub#access_model = open`.
    - `publish_bundle(client, device_id, &Bundle)` — item id =
      device_id, with both `access_model = open` and
      `max_items = max`.
    - `fetch_device_list(client, peer: Option<BareJid>)` — `peer =
      None` for self-fetch (works around Prosody self-PEP iq tracker
      key mismatch when the response carries no `from`).
    - `fetch_bundle(client, peer: Option<BareJid>, device_id)`.
* Stanza-level encrypt/decrypt:
    - `encrypt_message(sid, recipients, plaintext)` produces an
      `omemo_stanza::Encrypted` (single shared `<payload>`, one
      `<key rid=>` per recipient device). Each recipient has an
      `Option<KexCarrier>` — `Some` triggers `kex=true` with
      `OMEMOKeyExchange` wrapping for the first message after X3DH
      active; `None` emits `kex=false` with a bare
      `OMEMOAuthenticatedMessage`.
    - `decrypt_message` is the kex=false (follow-up) path;
      `decrypt_inbound_kex` runs X3DH passive + create_passive +
      decrypt in one call and returns the fresh `TwomemoSession` +
      plaintext + the consumed OPK id.
    - `inbound_kind` classifies a received `<encrypted>` so callers
      dispatch to the right decryptor.
* X3DH-active bootstrap: `bootstrap_active_session_from_bundle`
  runs X3DH active against a stanza-level peer Bundle, returns
  `(TwomemoSession, KexCarrier)`.
* Wire bridge: `send_encrypted(client, to, &Encrypted)` wraps in
  `<message type='chat'>` and sends; `wait_for_encrypted(client)`
  drains the event stream until an OMEMO `<message>` arrives.

**Gate** (passed): `crates/omemo-pep/tests/gate.rs::
alice_to_bob_three_messages_over_real_xmpp` — alice and bob each
publish device list + bundle, alice fetches bob's data, bootstraps
active, sends three `<message>` stanzas (one KEX + two follow-ups),
bob recovers all three plaintexts byte-equal.

**Test infra**: `test-vectors/integration/prosody/` brings up a
Debian + prosody.im apt-repo Prosody 13 image with three
pre-registered accounts (alice / bob / charlie). All four
integration tests (`connect`, two `pep` round-trips, `gate`) run in
parallel against a single container.

**4-FU.1 — `omemo-session` integration** ✅: the gate flows through
SQLite end-to-end. `omemo-pep::store` adds: `install_identity` (write
IK seed + SPK + OPKs), `bundle_from_store` / `x3dh_state_from_store`
(build the published Bundle / in-memory `X3dhState` from store rows),
`bootstrap_and_save_active` (persist the freshly-bootstrapped session),
`encrypt_to_peer` (load → step → save), `receive_first_message`
(look up SPK/OPK pubs by id, run `decrypt_inbound_kex`, then
`Store::commit_first_inbound` for an atomic OPK consume + session
persist), `receive_followup` (load → step → save). No `X3dhState` or
`TwomemoSession` lives in test locals across encrypt/decrypt
boundaries.

**4-FU.2 — StartTLS for production** ✅: re-enabled
`tokio-xmpp/{starttls, aws_lc_rs, rustls-native-certs}` features
alongside `insecure-tcp`. New helpers `connect_starttls(jid, password)`
(SRV + StartTLS + native cert validation) and
`connect_starttls_addr(jid, password, "host:port")` (explicit host).
`connect_plaintext` retained for localhost integration tests, with a
doc-comment pointer to the production helper. `cargo deny` allow-list
extended for ISC + MIT-0 (rustls + aws-lc-rs ecosystem); two hickory-
proto 0.25 advisories ignored with documented rationale (DNSSEC and
encoder paths we don't use; re-evaluate when tokio-xmpp 6 lands).

**4-FU.3 — XEP-0420 SCE envelope** ✅: outbound `encrypt_to_peer`
wraps the chat body in `<body xmlns='jabber:client'>...</body>`
inside an `omemo_stanza::sce::SceEnvelope` (16 fresh random rpad
bytes, RFC 3339 UTC `<time stamp=>` from a hand-rolled
Howard-Hinnant civil-from-days), then encrypts the envelope XML.
Inbound returns `InboundEnvelope { body, from_jid, timestamp }` after
verifying `<to>` matches our JID — XEP-0384 §4.5's anti-tampering
gate. `omemo-stanza::sce` already had canonical encode/decode + 6
round-trip tests; this stage added a `body_text()` helper for chat
clients.

**4-FU.4 — TOFU device-trust policy** ✅: `omemo-session` schema v2
adds `trusted_devices(jid, device_id, ik_pub, trust_state,
first_seen_at)` with `TrustState::{Pending, Trusted, Untrusted}`.
`record_first_seen` is atomic insert-if-absent and returns the
existing row so callers can detect IK drift. `omemo-pep::TrustPolicy`
exposes `Tofu` (auto-Trusted on first sight) vs `Manual` (auto-
Pending — UI prompts user). Inbound KEX records first-sight IK
*before* OPK consumption, so a rejected device never burns a one-time
prekey; on IK mismatch with a previously-recorded `(jid, device_id)`,
returns `StoreFlowError::IkMismatch`. Outbound and inbound follow-up
refuse `Untrusted` peers. Three new unit tests + a gate assertion
that alice's device is `Trusted` in bob's store after KEX.

**Test infra change**: gate now uses dedicated XMPP accounts
(`gate_a@localhost` / `gate_b@localhost`) so it runs in parallel with
`tests/connect.rs` (uses `alice`) and `tests/pep.rs` (uses `bob` /
`charlie`) without same-JID reconnect collisions. Prosody Dockerfile
registers all five accounts on entrypoint.

## Stage 5 — Group OMEMO (MUC) ✅

**Scope**: Extended Stage 4 to MUC rooms (XEP-0384 §6).

Per the spec, MUC OMEMO is "the same encrypted-key-per-device fan-out
but the message body is one ciphertext for all recipients". Stage 5
landed it in five sub-stages:

* **5.1** — `omemo-pep::muc` module: `MucRoom`, `Occupant`, `MucEvent`.
  `send_join` / `send_leave` / `accept_default_config` (pins
  `muc#roomconfig_whois = anyone` so the room is non-anonymous and
  bundles can be addressed) / `handle_presence` (parses
  `<x xmlns='muc#user'>` and updates the occupant table).
* **5.2** — `MucRoom::refresh_device_lists(client, store)` walks every
  occupant with a known real JID and PEP-fetches their device list,
  persisting via `Store::upsert_device`. Self-PEP is skipped (Prosody
  iq tracker quirk).
* **5.3** — Multi-recipient `omemo-pep::encrypt_to_peers(store,
  own_device_id, envelope_to, body_text, peers, providers)` and
  `MucRoom::send_groupchat(client, &Encrypted)`. One SCE envelope,
  one `<key rid=>` per device, one `<message type='groupchat'>`.
* **5.4** — `MucRoom::resolve_sender_real_jid(&FullJid)` resolves
  `from='room/nick'` to the occupant's real bare JID so callers can
  route through the existing `inbound_kind` / `receive_first_message`
  / `receive_followup` pipeline. The same receive helpers gained an
  `expected_envelope_to: &str` parameter (DM passes our_jid;
  groupchat passes room_jid — XEP-0384 §4.5).
* **5.5** — Gate: `tests/muc.rs::three_clients_groupchat_omemo2_round_trip`.
  alice / bob / carol on `muc_e` / `muc_f` / `muc_g`. Alice runs
  X3DH active for both peers, sends one groupchat with a KEX-wrapped
  fan-out envelope; both receivers decrypt to the same body. Message
  #2 is the same fan-out with `kex=None`, decrypted via
  `receive_followup`.

Test infra: Prosody MUC component on `conference.localhost` with
`muc_room_locking = false`. Per-scenario account allocation
(`muc_a` / `muc_b` for 5.1, `muc_c` / `muc_d` for 5.2, `muc_e` /
`muc_f` / `muc_g` for 5.5) plus `serial_test::serial` to keep
binary-internal parallelism from racing the cold container.

**Out of scope (deferred to Stage 6)**: cross-client interop —
the original ambition was "3 omemo-rs + 1 Conversations" but the
Conversations leg properly belongs to the external-client stage.

## Stage 6 — Real-Client Interop

**Scope**: Cross-implementation interop with at least Conversations and
Dino, both DM and MUC.

**Gate**:
1. Conversations 2.x sends DM → omemo-rs client decrypts.
2. omemo-rs client sends DM → Conversations decrypts.
3. Same with Dino.
4. MUC variant of each.

After Stage 6 passes, the library is considered v0.1.0 candidate.
