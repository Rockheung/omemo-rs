# Integration test infrastructure

Stages 4–6 need a real XMPP server. This directory holds the docker-compose
recipes that bring the necessary pieces up.

## ejabberd (Stage 4 / 5)

```sh
cd test-vectors/integration/xmpp
docker compose up -d
docker compose ps         # wait for "healthy"
```

Pre-registered accounts (registered idempotently by the container
entrypoint):

| JID                  | Password       |
|----------------------|----------------|
| `alice@localhost`    | `alicepass`    |
| `bob@localhost`      | `bobpass`      |
| `charlie@localhost`  | `charliepass`  |

Stop and wipe all session state:

```sh
docker compose down -v
```

## Running tests against this XMPP fixture

Integration tests in the workspace are marked `#[ignore]` so the default
`cargo test --workspace` stays self-contained. To run the full integration
suite:

```sh
cargo test --workspace -- --ignored
```

## Notes

* `c2s_require_encryption = false` in the XMPP server config — cleartext SASL
  PLAIN is fine because the container only listens on `127.0.0.1:5222`.
  Do not borrow this config for anything other than local CI.
* The `prosody-data` volume persists the user database across `up`/`down`
  cycles. Add `-v` to `down` to wipe it.
* If integration tests start flaking with `login timed out`, the in-memory
  XMPP fixture state may have drifted (e.g. from killed test runs leaving
  half-open sessions). Restart with `docker compose restart prosody` —
  the user database in `prosody-data` is preserved.
* PEP integration tests use **bob** while connect tests use **alice**, so
  the two test binaries can run in parallel without two sessions for the
  same account colliding on the XMPP server.
