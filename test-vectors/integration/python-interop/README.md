# Stage 6 — cross-impl OMEMO 2 interop with python-omemo

This directory has the Python counterpart for the
`omemo-rs-cli` binary. It uses **slixmpp** + **Syndace's
`python-omemo` 2.x** (the same library the fixture pipeline already
uses), so the cross-implementation test exercises **two genuinely
different OMEMO 2 codebases** — Rust against Python.

## What's verified

* **Rust → Python** end-to-end: omemo-rs-cli encrypts a chat body,
  publishes its bundle, sends a `<message>` stanza. python-omemo
  parses the OMEMO 2 element, runs X3DH passive + DoubleRatchet
  decrypt, recovers the SCE envelope. The script unwraps the
  XEP-0420 envelope, prints the body to stdout. **Wire format,
  KEX bootstrap, ratchet decrypt, SCE envelope** all interoperate.

## Known limitation (Python side)

`slixmpp-omemo` 2.1.0 doesn't implement the XEP-0420 SCE plugin yet:

* On **decrypt**, it raises `NotImplementedError("SCE not supported
  yet. Plaintext: ...")` and leaks the plaintext bytes through the
  exception message. The interop client catches this and parses the
  envelope itself — that's enough for the rust→python check to
  pass.
* On **encrypt**, it explicitly skips the `urn:xmpp:omemo:2`
  namespace (xep_0384.py line 1049: `# Here I would prepare the
  plaintext for omemo:2 using my SCE plugin ... IF I HAD ONE!!!`).
  The Python side only emits messages on the legacy
  `eu.siacs.conversations.axolotl` namespace, which omemo-rs does
  not implement (we deliberately stay OMEMO-2-only — see ADR-002).

The python→rust direction therefore needs the SCE envelope to be
built explicitly in the interop client (calling
`SessionManager.encrypt` with an envelope-bytes plaintext +
`backend_priority_order=[twomemo.NAMESPACE]`). That work is
deferred — the wire-format byte-equality is already established by
both directions of the fixture replay tests in `omemo-test-harness`.

## Running it manually

```bash
# Bring up Prosody (registers `pyint_a` / `pyint_b` accounts).
docker compose -f test-vectors/integration/prosody/docker-compose.yml up -d

# Initialise the omemo-rs side once.
cargo build -p omemo-rs-cli
OMEMO_RS_STORE_DIR=/tmp/interop ./target/debug/omemo-rs-cli \
    --jid pyint_a@localhost --password pyintapass \
    --insecure-tcp 127.0.0.1:5222 \
    init --device-id 1001 --opk-count 10

# Start the Python receiver. It prints `READY <device_id>` to stdout
# once its identity has been published, then waits for one inbound
# encrypted message.
test-vectors/.venv/bin/python \
    test-vectors/integration/python-interop/interop_client.py \
    --jid pyint_b@localhost --password pyintbpass \
    --address 127.0.0.1:5222 \
    --data-dir /tmp/interop/python --timeout 30 -v recv > /tmp/py.log 2>&1 &

# Wait for the READY signal and pick up Python's randomly-generated
# device id.
until grep -q '^READY' /tmp/py.log; do sleep 1; done
PY_DEV=$(awk '/^READY/{print $2; exit}' /tmp/py.log)

# Send from Rust to Python.
OMEMO_RS_STORE_DIR=/tmp/interop ./target/debug/omemo-rs-cli \
    --jid pyint_a@localhost --password pyintapass \
    --insecure-tcp 127.0.0.1:5222 \
    send --peer pyint_b@localhost --peer-device "$PY_DEV" \
    --body "hello python from rust"

wait                 # Python prints `pyint_a@localhost/...: hello python from rust`
tail -5 /tmp/py.log
```

## Why the python venv is reused

`test-vectors/.venv` is the same virtualenv used to regenerate the
byte-equal fixtures (`scripts/gen_*.py`). It already has
`omemo`/`twomemo`/`oldmemo`/`x3dh`/`xeddsa` from the Syndace stack
installed pinned to known-good versions. Adding `slixmpp +
slixmpp-omemo` to it gives us cross-impl interop without a separate
toolchain.
