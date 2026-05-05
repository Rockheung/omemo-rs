# omemo-rs-cli daemon JSON Lines protocol

A spec for the `omemo-rs-cli daemon` subcommand's stdio interface.
Designed to be the substrate the upcoming **nan-curunir** bot
orchestrator runs on top of, but useful for any tool that wants to
spawn an OMEMO-encrypted XMPP session as a child process.

## Streams

| stream | direction | content |
|---|---|---|
| `stdin`  | orchestrator → daemon | one [Command] per line, JSON object |
| `stdout` | daemon → orchestrator | one [Event] per line, JSON object |
| `stderr` | daemon → orchestrator | `tracing` structured logs (filtered by `RUST_LOG`) |

Each line ends with a single `\n`. Parsers should split on LF and
ignore empty lines. Each event is flushed to stdout immediately.

Closing stdin (EOF) is equivalent to sending `{"op":"shutdown"}`:
the daemon drains pending events, sends `</stream:stream>`, emits a
final `goodbye`, and exits 0.

## Lifecycle

```
                         orchestrator              daemon
                              │                      │
   spawn `omemo-rs-cli ...    │ ────────────────────▶│
        daemon`               │                      │
                              │                      │
                              │                      │── tracing logs to stderr
                              │ {"event":"connecting","jid":"..."}
                              │ {"event":"ready","jid":"...","device_id":N}
                              │
   {"op":"send",...}          │ ────────────────────▶│
                              │ {"event":"sent",...}
                              │ {"event":"message",...}
                              │ {"event":"message",...}
                              │
   {"op":"join_muc",...}      │ ────────────────────▶│
                              │ {"event":"muc_joined",...}
                              │ {"event":"muc_message",...}
                              │
   {"op":"shutdown"}          │ ────────────────────▶│
                              │ {"event":"goodbye"}
                              │            ↓ exit 0
```

## Commands

All commands are `{"op":"<op-name>", ...}` — `op` discriminates the
variant. Most accept an optional `"id"` field; whatever the
orchestrator passes is echoed back on the matching event so it can
correlate request/response pairs.

### `send` — one-to-one OMEMO message

```json
{
  "op": "send",
  "peer": "bob@example.org",
  "device": 1234,
  "backend": "twomemo",
  "body": "hello bob",
  "id": "msg-7"
}
```

* `peer` — bare JID of the recipient.
* `device` — device id (required in v1; multi-device fan-out is on
  the v3 list).
* `backend` — `"twomemo"` (default, OMEMO 2 = `urn:xmpp:omemo:2`)
  or `"oldmemo"` (OMEMO 0.3 = `eu.siacs.conversations.axolotl`).
* `body` — UTF-8 plaintext. The daemon wraps in XEP-0420 SCE for
  OMEMO 2 / hands raw bytes to AES-128-GCM for OMEMO 0.3.
* `id` — optional request id, echoed on `sent` / `error`.

If no session exists yet for the (peer, device) pair, the daemon
implicitly fetches the peer's PEP bundle and runs X3DH active —
the resulting `<key kex='true'>` rides along on this same
outbound. Subsequent sends to the same (peer, device) go fast-path.

### `discover` — list a peer's devices

```json
{"op":"discover","peer":"bob@example.org","backend":"twomemo","id":"d1"}
```

Returns a `device_list` event listing every device id the peer
currently advertises on PEP.

### `join_muc` — join a group chat

```json
{"op":"join_muc","room":"team@conference.localhost","nick":"alice","id":"j1"}
```

Sends presence to the room, then refreshes every occupant's
OMEMO 2 devicelist. Emits `muc_joined` once the snapshot is built.
The daemon stores the room state internally and routes subsequent
inbound presence + groupchat stanzas to it.

### `send_muc` — group-encrypted message

```json
{"op":"send_muc","room":"team@conference.localhost","body":"hi all","id":"g1"}
```

Encrypts once per occupant device (fan-out per XEP-0384 §6.1),
sends as a `<message type='groupchat'>`. v2 supports OMEMO 2 only;
OMEMO 0.3 MUC fan-out lands when Converse.js compatibility is
needed.

### `refresh_muc` — re-snapshot occupant devices

```json
{"op":"refresh_muc","room":"team@conference.localhost","id":"r1"}
```

Useful after observing `muc_occupant_joined` to pick up the new
arrival's devicelist before the next `send_muc`.

### `leave_muc`

```json
{"op":"leave_muc","room":"team@conference.localhost","id":"l1"}
```

### `status`

```json
{"op":"status","id":"s1"}
```

Liveness check. Emits `status` with the local JID + device id.

### `shutdown`

```json
{"op":"shutdown"}
```

Graceful close. Or close stdin.

## Events

All events are `{"event":"<event-name>", ...}`.

### `connecting` — fired immediately, before the C2S handshake

```json
{"event":"connecting","jid":"alice@example.org"}
```

### `ready` — login + identity-publish complete

```json
{"event":"ready","jid":"alice@example.org","device_id":1234}
```

The orchestrator MUST wait for `ready` before sending any other
command. Sends issued earlier are not racy in correctness terms
(the channel queues them), but they may fail with
`session/identity not yet bootstrapped` errors.

### `sent` — outbound 1:1 ack

```json
{"event":"sent","peer":"bob@example.org","device":1234,"backend":"twomemo","id":"msg-7"}
```

### `message` — inbound 1:1 OMEMO message decrypted

```json
{
  "event": "message",
  "from": "bob@example.org",
  "device": 5678,
  "backend": "twomemo",
  "body": "hi alice",
  "timestamp": "2026-05-05T18:07:16Z"
}
```

`timestamp` is from the OMEMO 2 SCE `<time>` envelope and is
omitted (empty) for OMEMO 0.3 since the spec carries no envelope.

### `muc_joined` — `join_muc` succeeded

```json
{
  "event":"muc_joined",
  "room":"team@conference.localhost",
  "occupants":[
    {"real_jid":"bob@example.org","nick":"bob","devices":[5678]},
    {"real_jid":"carol@example.org","nick":"carol","devices":[9101]}
  ],
  "id":"j1"
}
```

### `muc_message` — inbound OMEMO groupchat decrypted

```json
{
  "event":"muc_message",
  "room":"team@conference.localhost",
  "from_real_jid":"bob@example.org",
  "from_nick":"bob",
  "device":5678,
  "backend":"twomemo",
  "body":"hi alice"
}
```

### `muc_occupant_joined` / `muc_occupant_left`

Best-effort presence-derived events. The daemon doesn't auto-refresh
the occupant's bundle on join; orchestrators that want the new
arrival's devicelist before the next `send_muc` should issue a
`refresh_muc`.

### `device_list` — `discover` result

```json
{"event":"device_list","peer":"bob@example.org","backend":"twomemo","devices":[5678,9999],"id":"d1"}
```

### `status` — `status` result

```json
{"event":"status","jid":"alice@example.org","device_id":1234,"twomemo_sessions":18446744073709551615,"oldmemo_sessions":18446744073709551615,"id":"s1"}
```

The two session-count fields are `usize::MAX` sentinels in v1 —
their values aren't tracked yet (would need a `Store::list_sessions`
accessor that doesn't exist). They stay in the schema so v2 can
fill them in without breaking the protocol.

### `error` — command or runtime failure

```json
{"event":"error","kind":"command","detail":"...","id":"msg-7"}
```

`kind`:
* `parse` — bad JSON / unknown op on stdin
* `command` — command handler returned `Err`
* `inbound` — failed to process an incoming stanza
* `stdin` — stdin read failed

### `disconnected` — XMPP stream ended

```json
{"event":"disconnected","reason":"xmpp stream ended"}
```

Emitted right before `goodbye` when the daemon exits because the
stream died (not on a clean `shutdown`).

### `goodbye` — final event

```json
{"event":"goodbye"}
```

Always the last line on stdout before exit 0.

## Trust model

The daemon uses Trust-On-First-Use (`omemo-pep::TrustPolicy::Tofu`)
for inbound peer devices. New devices observed in a `<key kex>`
are auto-trusted and recorded with their identity key. If the
peer's IK ever changes for the same `(jid, device_id)`, decryption
fails with an `inbound` error event citing IK drift — the
orchestrator can then take action (alert the user, refuse the
peer, etc.).

This matches what the one-shot `init` / `send` / `recv`
subcommands have always done. Customising the policy (Manual
mode, explicit trust commands) is on the v3 list.

## Versioning

This protocol is currently **v2** (1:1 + MUC, OMEMO 2 + 0.3 for
1:1, OMEMO 2 only for MUC).

The protocol is forward-compatible: orchestrators MUST ignore
unknown `event` keys and MUST tolerate new optional fields on
existing events. New commands or fields will land additively;
breaking changes (rare) will be signalled via a new `--protocol-
version` flag.

## Examples

A complete end-to-end demo:

```bash
# Start daemon (alice's identity in $HOME/.omemo-rs-cli/)
omemo-rs-cli --jid alice@xmpp.example.org \
             --password "$ALICE_PW" \
             daemon --device-id 1001 --opk-count 100 \
  > daemon-events.log < daemon-commands.fifo &

DAEMON=$!

# Wait for ready, then send commands
exec 3>daemon-commands.fifo
echo '{"op":"send","peer":"bob@xmpp.example.org","device":2002,"body":"hi","id":"m1"}' >&3
echo '{"op":"join_muc","room":"team@conference.xmpp.example.org","nick":"alice","id":"j1"}' >&3
sleep 5
echo '{"op":"send_muc","room":"team@conference.xmpp.example.org","body":"hi all","id":"g1"}' >&3

# … process events from daemon-events.log …

echo '{"op":"shutdown"}' >&3
exec 3>&-
wait $DAEMON
```

For nan-curunir-style integration the orchestrator typically wraps
the daemon in a Rust child-process supervisor with `tokio::process::
Child` — see `docs/architecture.md` for the planned layout.
