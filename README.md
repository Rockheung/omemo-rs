# omemo-rs

A pure-Rust, MIT-licensed implementation of **OMEMO 2** (XEP-0384 v0.9) for
XMPP. Built to serve as the E2EE layer of an XMPP-based bot orchestrator
(the planned successor to [nan-curunir](https://github.com/Rockheung/nan-curunir)),
without pulling AGPL dependencies into the runtime graph.

Other languages: [한국어](README.ko.md)

## Why

The Rust ecosystem's reference for Signal-style E2EE is `signalapp/libsignal`,
which is **AGPL-3.0**. Implementations of OMEMO 0.3.0 (`oldmemo`) inherit that
licence transitively. This project sidesteps both by porting the
permissively-licensed [Syndace Python stack](https://github.com/Syndace) to
Rust on top of [RustCrypto](https://github.com/RustCrypto) primitives, and
implementing OMEMO 2 only.

See `docs/architecture.md` §3 for the full licence chain analysis and ADR-002.

## Status

| Stage | Crate | Status | Gate test |
|---|---|---|---|
| 0 | workspace + replay pipeline | ✅ | `kdf_hkdf` |
| 1.1 | `omemo-xeddsa` | ✅ | `xeddsa` (104 assertions) |
| 1.2 | `omemo-doubleratchet` | ✅ | 4-msg round-trip with DH step + skip + OOO |
| 1.3 | `omemo-x3dh` | ✅ | active+passive bundle exchange byte-equal |
| 1.4 | `omemo-twomemo` | ✅ | 1 KEX + 3 messages, byte-equal protobuf |
| 2 | `omemo-stanza` | ✅ | XEP-0384 §3+§5 round-trip + 3-recipient |
| 3 | `omemo-session` | ✅ | identity + bundle + persist + restart, no re-keying |
| 4 | `omemo-pep` | ✅ | alice ↔ bob 3 messages over real XMPP (`gate.rs`) |
| 5 | Group OMEMO (MUC) | ✅ | 3 omemo-pep clients groupchat round-trip on real XMPP MUC (`tests/muc.rs`) |
| 6.1 | python-omemo cross-impl | ✅ | omemo-rs ↔ Syndace python-omemo bidirectional via `tests/python_interop.rs` |
| 6.2 | Conversations / Dino | ⏳ | manual; drive `omemo-rs-cli` against same server |
| 7.1 | `omemo-oldmemo` scaffold | ✅ | 10 unit tests incl. full DR session round-trip |
| 7.2 | `gen_oldmemo.py` + replay | ✅ | byte-equal vs Syndace python-oldmemo (KEX + 3 messages) |
| 7.3 | `omemo-stanza` axolotl ns | ✅ | round-trip `eu.siacs.conversations.axolotl` + AES-128-GCM body |
| 7.4 | `omemo-pep` dual-backend | ✅ | parallel `*_oldmemo` flow + dual-namespace `wait_for_encrypted_any` |
| 7.5 | oldmemo cross-impl gate | ✅ | `python_interop --backend oldmemo` both directions on real XMPP |
| 8 | Converse.js E2E rig | ✅ | multi-session browser ↔ CLI E2E (`docs/converse-e2e.md`) |
| 9 | Stdio daemon (nan-curunir-shaped API) | ✅ | JSON Lines daemon with 1:1 + MUC OMEMO 2 (`docs/daemon-protocol.md`) |
| 10 | nan-curunir migration | ✅ | bot orchestrator on XMPP — full e2e gate green (downstream repo: `nan-curunir/docs/migration-xmpp.md`) |

The crypto layer is byte-equal with the Syndace Python stack on every
fixture. `cargo test --workspace` passes 64 unit/replay tests; an
additional 10 integration tests gate the XMPP path against a local
XMPP container (run with `-- --ignored`). Stages 4 + 5 + 6.1 +
the 4-FU.1..4 / 5-FU.1..4 follow-ups are done: alice ↔ bob 1:1 and
alice → bob+carol groupchat round-trip on a real XMPP MUC, plus
**omemo-rs ↔ Syndace's python-omemo cross-implementation interop in
both directions** (Stage 6.1 — `cargo test -p omemo-rs-cli --test
python_interop`). The gate flows entirely through `omemo-session`'s
SQLite store, message bodies are wrapped in XEP-0420 SCE envelopes
with `<to>`-verification on inbound (peer bare for DM, room bare
for groupchat), every peer device is recorded under TOFU or Manual
trust policy with IK-drift detection, and production deployments
ship StartTLS via `connect_starttls` (rustls + aws-lc-rs + native
cert validation). The `omemo-rs-cli` binary
(`crates/omemo-rs-cli/`) exercises the production API as a real
CLI client and is the manual driver for Stage 6.2 (Conversations /
Dino interop).

## Workspace layout

```
omemo-rs/
├── crates/
│   ├── omemo-xeddsa/          # XEdDSA + Curve25519/Ed25519 + X25519
│   ├── omemo-doubleratchet/   # Signal-spec Double Ratchet
│   ├── omemo-x3dh/            # X3DH key agreement
│   ├── omemo-twomemo/         # OMEMO 2 backend (twomemo.proto)
│   ├── omemo-stanza/          # XEP-0384 v0.9 stanza encode/parse
│   ├── omemo-session/         # SQLite-backed persistent storage
│   ├── omemo-pep/             # XEP-0163 PEP integration (Stage 4)
│   └── omemo-test-harness/    # cross-language fixture replay (cargo test only)
├── docs/                      # architecture, pipeline, ADRs, stages
├── test-vectors/
│   ├── fixtures/              # committed JSON fixtures (10 of them at Stage 3)
│   ├── scripts/gen_*.py       # regenerators
│   └── reference/             # cloned upstream Python repos (gitignored)
└── TODO.md                    # live task list (mirrors docs/stages.md)
```

## Test methodology

Every Rust crypto primitive must produce **byte-identical** output to its
Syndace Python counterpart. The Python implementations are used as
deterministic oracles: a generator script (`scripts/gen_*.py`) feeds
deterministic inputs into the Python reference and serialises (input,
expected output) pairs to `fixtures/<primitive>.json`. Rust replay tests
load the JSON, run our impl on the same inputs, and `assert_eq!` against
the recorded output.

Fixtures are committed; contributors without the Python venv can still run
`cargo test`. See `docs/pipeline.md` for full details and the fixture
inventory.

## Quickstart

```bash
git clone https://github.com/Rockheung/omemo-rs.git
cd omemo-rs
cargo test --workspace
```

To exchange a real OMEMO 2 message against a localhost XMPP server,
build the CLI:

```bash
docker compose -f test-vectors/integration/xmpp/docker-compose.yml up -d
cargo build -p omemo-rs-cli --release

# Initialise alice and bob (one-time per account):
./target/release/omemo-rs-cli --jid muc_a@localhost --password mucapass \
    --insecure-tcp 127.0.0.1:5222 init --device-id 1001 --opk-count 100
./target/release/omemo-rs-cli --jid muc_b@localhost --password mucbpass \
    --insecure-tcp 127.0.0.1:5222 init --device-id 1002 --opk-count 100

# In one shell: bob waits for one message.
./target/release/omemo-rs-cli --jid muc_b@localhost --password mucbpass \
    --insecure-tcp 127.0.0.1:5222 recv --timeout 60 &

# In another: alice sends.
./target/release/omemo-rs-cli --jid muc_a@localhost --password mucapass \
    --insecure-tcp 127.0.0.1:5222 send \
    --peer muc_b@localhost --peer-device 1002 --body "hello"
# bob prints: [<ts>] muc_a@localhost/1001: hello
```

Production deployments drop `--insecure-tcp`; the CLI defaults to
`connect_starttls` (SRV + StartTLS + native cert validation).

If you want to regenerate fixtures (after upstream Python package bumps):

```bash
cd test-vectors
git clone --depth 1 https://github.com/Syndace/python-doubleratchet.git reference/python-doubleratchet
git clone --depth 1 https://github.com/Syndace/python-x3dh.git           reference/python-x3dh
git clone --depth 1 https://github.com/Syndace/python-xeddsa.git         reference/python-xeddsa
git clone --depth 1 https://github.com/Syndace/python-twomemo.git        reference/python-twomemo
git clone --depth 1 https://github.com/Syndace/python-oldmemo.git        reference/python-oldmemo
git clone --depth 1 https://github.com/Syndace/python-omemo.git          reference/python-omemo

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install doubleratchet==1.3.0 x3dh==1.3.0 xeddsa==1.2.0 twomemo==2.1.0 oldmemo==2.1.0 'omemo>=2,<3' \
            cryptography pydantic

for s in scripts/gen_*.py; do python "$s"; done
git diff fixtures/   # should be empty if upstream hasn't drifted
```

## License

MIT (see `LICENSE` if present, else fall back to `Cargo.toml` `[workspace.package]`).

The runtime crate graph contains only MIT/Apache/BSD code:

* `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `hmac`,
  `sha2`, `aes`, `cbc` — RustCrypto, BSD/MIT/Apache
* `prost` — Apache-2.0
* `quick-xml` — MIT
* `rusqlite` (bundled SQLite) — MIT / public-domain SQLite source

Python reference packages are used **only at fixture-generation time** and
are not in the runtime crate graph. We deliberately do **not** depend on
`libsignal` (Rust) or `python-oldmemo`, both of which are AGPL-3.0.

## Documentation

* [`docs/architecture.md`](docs/architecture.md) — top-level design, crate
  responsibilities, OMEMO 2 algorithm choices.
* [`docs/pipeline.md`](docs/pipeline.md) — fixture replay infrastructure +
  per-primitive inventory.
* [`docs/stages.md`](docs/stages.md) — phase-by-phase development plan
  with gate criteria.
* [`docs/decisions.md`](docs/decisions.md) — architectural decision log
  (ADR-001 .. ADR-006).
* [`TODO.md`](TODO.md) — live checkbox-style task list.

## Out of scope

* Hardware-token / smartcard-backed identity keys.
* Wasm builds (storage layer assumes filesystem + SQLite).
* Megolm-style group encryption optimisations (OMEMO 2 fanout is fine for
  bot-sized rooms, which are our target).

OMEMO 0.3.0 (`oldmemo`/siacs axolotl namespace) was previously listed
here on the basis of a libsignal AGPL chain. ADR-009 (2026-05-02)
re-examined that premise — `python-oldmemo` does not depend on
libsignal at runtime; its AGPL is Syndace's own licensing choice.
OMEMO 0.3 is back in scope as Stage 7, implemented clean-room from
XEP-0384 v0.3 + the existing MIT primitives, with python-oldmemo
used **only** as an external fixture oracle (never linked, never
copied). See `docs/decisions.md` ADR-009.
