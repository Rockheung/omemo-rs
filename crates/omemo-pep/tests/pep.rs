//! Integration tests: PEP publish + fetch round-trips on
//! `urn:xmpp:omemo:2:devices` and `urn:xmpp:omemo:2:bundles`.
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
    connect_plaintext, fetch_bundle, fetch_device_list, publish_bundle, publish_device_list,
    BareJid, Bundle, Device, DeviceList, Event, PreKey, SignedPreKey,
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

#[tokio::test]
#[ignore = "requires Prosody on 127.0.0.1:5222 (see test-vectors/integration/prosody/)"]
async fn charlie_publishes_and_fetches_own_bundle() {
    // Each test binary uses its own account to avoid the same-JID
    // reconnect timing flake we hit with two bob tests in sequence.
    let charlie_jid = BareJid::from_str("charlie@localhost").expect("charlie JID");
    let mut client = connect_plaintext(charlie_jid, "charliepass", "127.0.0.1:5222");

    await_online(&mut client).await;

    let device_id: u32 = 31415;
    // Stub bundle: opaque bytes only — the wire-format / PEP layer
    // doesn't care whether the bytes are a real Curve25519 key. Real
    // bundles are produced by `omemo-x3dh` / `omemo-twomemo` once we
    // wire up the integration end-to-end.
    let bundle = Bundle {
        spk: SignedPreKey {
            id: 1,
            pub_key: vec![0x11; 32],
        },
        spks: vec![0x22; 64],
        ik: vec![0x33; 32],
        prekeys: vec![
            PreKey {
                id: 1,
                pub_key: vec![0x44; 32],
            },
            PreKey {
                id: 2,
                pub_key: vec![0x55; 32],
            },
            PreKey {
                id: 3,
                pub_key: vec![0x66; 32],
            },
        ],
    };

    publish_bundle(&mut client, device_id, &bundle)
        .await
        .expect("publish bundle");

    let fetched = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_bundle(&mut client, None, device_id),
    )
    .await
    .expect("fetch timed out")
    .expect("fetch bundle");

    assert_eq!(fetched, bundle, "round-trip bundle mismatches");

    client.send_end().await.expect("orderly shutdown");
}
