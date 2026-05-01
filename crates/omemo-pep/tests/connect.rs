//! Integration test: connect to a local Prosody and authenticate.
//!
//! Marked `#[ignore]`, so it does NOT run under `cargo test --workspace`.
//! Spin up the server first:
//!
//!     docker compose -f test-vectors/integration/prosody/docker-compose.yml up -d
//!
//! Then run:
//!
//!     cargo test -p omemo-pep --test connect -- --ignored

use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use omemo_pep::{connect_plaintext, BareJid, Event};

#[tokio::test]
#[ignore = "requires Prosody on 127.0.0.1:5222 (see test-vectors/integration/prosody/)"]
async fn alice_authenticates_and_binds() {
    let jid = BareJid::from_str("alice@localhost").expect("alice JID parses");
    let mut client = connect_plaintext(jid, "alicepass", "127.0.0.1:5222");

    let bound = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = client.next().await {
            if let Event::Online { bound_jid, resumed } = event {
                assert!(!resumed, "first connect should not be a resumption");
                return Some(bound_jid);
            }
        }
        None
    })
    .await
    .expect("login timed out (is Prosody running?)")
    .expect("client stream ended without an Online event");

    let bare = bound.to_bare().to_string();
    assert_eq!(bare, "alice@localhost", "bound JID is alice@localhost");

    client.send_end().await.expect("orderly shutdown");
}
