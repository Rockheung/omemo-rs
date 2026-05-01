# Integration test infrastructure

Stages 4–6 need a real XMPP server. This directory holds the docker-compose
recipes that bring the necessary pieces up.

## Prosody (Stage 4 / 5)

```sh
cd test-vectors/integration/prosody
docker compose up -d
docker compose ps         # wait for "healthy"
```

Pre-registered accounts (config: `prosody.cfg.lua`):

| JID                | Password    |
|--------------------|-------------|
| `alice@localhost`  | `alicepass` |
| `bob@localhost`    | `bobpass`   |

Stop and wipe all session state:

```sh
docker compose down -v
```

## Running tests against this Prosody

Integration tests in the workspace are marked `#[ignore]` so the default
`cargo test --workspace` stays self-contained. To run the full integration
suite:

```sh
cargo test --workspace -- --ignored
```

## Notes

* `c2s_require_encryption = false` in the Prosody config — cleartext SASL
  PLAIN is fine because the container only listens on `127.0.0.1:5222`.
  Do not borrow this config for anything other than local CI.
* The `prosody-data` volume persists the user database across `up`/`down`
  cycles. Add `-v` to `down` to wipe it.
