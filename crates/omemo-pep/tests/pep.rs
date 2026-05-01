//! Integration test: PEP publish + fetch round-trip on
//! `urn:xmpp:omemo:2:devices`.
//!
//! Marked `#[ignore]`. Bring up Prosody first:
//!
//!     docker compose -f test-vectors/integration/prosody/docker-compose.yml up -d
//!
//! Then run:
//!
//!     cargo test -p omemo-pep --test pep -- --ignored

use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use omemo_pep::{
    connect_plaintext, fetch_device_list, publish_device_list, BareJid, Device, DeviceList, Event,
};

async fn await_online(client: &mut omemo_pep::Client) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = client.next().await {
            if matches!(event, Event::Online { .. }) {
                return;
            }
        }
        panic!("client stream ended without Online event (is Prosody running?)");
    })
    .await
    .expect("login timed out");
}

#[tokio::test]
#[ignore = "requires Prosody on 127.0.0.1:5222 (see test-vectors/integration/prosody/)"]
async fn bob_publishes_and_fetches_own_device_list() {
    // Uses bob so this test can run in parallel with `connect.rs` (which
    // uses alice) without two sessions for the same account colliding on
    // Prosody.
    let bob_jid = BareJid::from_str("bob@localhost").expect("bob JID");
    let mut client = connect_plaintext(bob_jid, "bobpass", "127.0.0.1:5222");

    await_online(&mut client).await;

    let list = DeviceList {
        devices: vec![
            Device {
                id: 27183,
                label: Some("Phone".into()),
                labelsig: None,
            },
            Device {
                id: 27184,
                label: None,
                labelsig: None,
            },
            Device {
                id: 27185,
                label: Some("Desktop".into()),
                labelsig: Some(b"\x01\x02\x03\x04".to_vec()),
            },
        ],
    };

    publish_device_list(&mut client, &list)
        .await
        .expect("publish device list");

    let fetched =
        tokio::time::timeout(Duration::from_secs(5), fetch_device_list(&mut client, None))
            .await
            .expect("fetch timed out")
            .expect("fetch device list");

    assert_eq!(fetched, list, "round-trip device list mismatches");

    client.send_end().await.expect("orderly shutdown");
}
