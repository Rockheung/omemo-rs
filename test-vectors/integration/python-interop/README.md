# Stage 6 — cross-impl OMEMO 2 interop with python-omemo

This directory has the Python counterpart for the
`omemo-rs-cli` binary. It uses **slixmpp** + **Syndace's
`python-omemo` 2.x** (the same library the fixture pipeline already
uses), so the cross-implementation test exercises **two genuinely
different OMEMO 2 codebases** — Rust against Python.

## What's verified — both directions ✅

* **Rust → Python**: omemo-rs-cli encrypts a chat body, publishes
  its bundle, sends a `<message>` stanza. python-omemo parses the
  OMEMO 2 element, runs X3DH passive + DoubleRatchet decrypt,
  recovers the SCE envelope. The script unwraps the XEP-0420
  envelope and prints the body to stdout.
* **Python → Rust**: the interop client builds the XEP-0420 SCE
  envelope itself (slixmpp-omemo's plugin doesn't), drives X3DH
  active + DoubleRatchet encrypt via `SessionManager.encrypt`, and
  hands the resulting `<encrypted xmlns='urn:xmpp:omemo:2'>` element
  to slixmpp's stanza writer. omemo-rs-cli's `recv` decrypts and
  prints the body. **Wire format, KEX bootstrap, ratchet step, SCE
  envelope, `<to>` verification** all interoperate in both
  directions.

## What we worked around in slixmpp-omemo 2.1.0

The plugin doesn't implement the XEP-0420 SCE side yet:

* On **decrypt**, it raises `NotImplementedError("SCE not supported
  yet. Plaintext: ...")` and leaks the plaintext bytes through the
  exception message. The interop client catches this and parses the
  envelope itself.
* On **encrypt**, the plugin explicitly skips the
  `urn:xmpp:omemo:2` namespace (xep_0384.py line 1049: `# Here I
  would prepare the plaintext for omemo:2 using my SCE plugin ...
  IF I HAD ONE!!!`). The interop client therefore bypasses
  `xep_0384.encrypt_message` and goes straight to
  `SessionManager.encrypt` with our hand-built envelope bytes +
  `backend_priority_order=[twomemo.twomemo.NAMESPACE]`, then
  `twomemo.etree.serialize_message` on each result, appended to a
  fresh `<message type='chat'>` and sent.

omemo-rs (our implementation) speaks XEP-0384 v0.9 + XEP-0420
correctly; the workarounds are entirely on the Python side.

## Running it manually (rust → python)

```bash
# Bring up the XMPP fixture (registers `pyint_a` / `pyint_b` accounts).
docker compose -f test-vectors/integration/xmpp/docker-compose.yml up -d

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

## Running it manually (python → rust)

```bash
# Bring up the XMPP fixture.
docker compose -f test-vectors/integration/xmpp/docker-compose.yml up -d

# Initialise the rust side (alice in this scenario receives).
cargo build -p omemo-rs-cli
OMEMO_RS_STORE_DIR=/tmp/interop ./target/debug/omemo-rs-cli \
    --jid pyint_b@localhost --password pyintbpass \
    --insecure-tcp 127.0.0.1:5222 \
    init --device-id 2002 --opk-count 10

# Start the rust receiver in the background.
OMEMO_RS_STORE_DIR=/tmp/interop ./target/debug/omemo-rs-cli \
    --jid pyint_b@localhost --password pyintbpass \
    --insecure-tcp 127.0.0.1:5222 \
    recv --timeout 60 > /tmp/rrecv.log 2>&1 &

# Send from Python. The interop client builds the SCE envelope
# itself (slixmpp-omemo doesn't), then encrypts via
# `SessionManager.encrypt` directly.
sleep 5  # let rust login + publish + start waiting
test-vectors/.venv/bin/python \
    test-vectors/integration/python-interop/interop_client.py \
    --jid pyint_a@localhost --password pyintapass \
    --address 127.0.0.1:5222 \
    --data-dir /tmp/interop/python --timeout 30 \
    send --peer pyint_b@localhost --body "hello rust from python"

wait
cat /tmp/rrecv.log
# [<ts>] pyint_a@localhost/<resource>: hello rust from python
```

## Why the python venv is reused

`test-vectors/.venv` is the same virtualenv used to regenerate the
byte-equal fixtures (`scripts/gen_*.py`). It already has
`omemo`/`twomemo`/`oldmemo`/`x3dh`/`xeddsa` from the Syndace stack
installed pinned to known-good versions. Adding `slixmpp +
slixmpp-omemo` to it gives us cross-impl interop without a separate
toolchain.
