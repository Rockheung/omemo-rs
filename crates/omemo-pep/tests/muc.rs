//! Stage 5 MUC integration tests:
//!
//! * `two_clients_join_same_room_and_see_each_other` — Stage 5.1 join
//!   + occupant tracking.
//! * `refresh_pulls_each_occupants_device_list_into_store` — Stage 5.2
//!   per-occupant device-list cache.
//!
//! ```sh
//! docker compose -f test-vectors/integration/prosody/docker-compose.yml up -d
//! cargo test -p omemo-pep --test muc -- --ignored
//! ```
//!
//! Each scenario claims its own pair of pre-registered Prosody
//! accounts (`muc_a` / `muc_b` for 5.1, `muc_c` / `muc_d` for 5.2) so
//! cargo can run them concurrently within the same test binary
//! without same-JID reconnect collisions.

use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use omemo_pep::{
    connect_plaintext, install_identity, publish_device_list, BareJid, Device, DeviceList, Event,
    IdentitySeed, MucRoom, Store,
};
use tokio_xmpp::Stanza;
use xmpp_parsers::presence::Presence;

async fn await_online(client: &mut omemo_pep::Client) {
    // 30s rather than 10s: Stage 5 puts up to ~7 clients on one Prosody
    // (4 in `tests/muc.rs` plus 3 in the Stage 5.5 gate), and login can
    // contend on shared state (auth backend, occupant-id mod, etc.) for
    // an extra few seconds during the cold cache.
    tokio::time::timeout(Duration::from_secs(30), async {
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

/// Drive `client` until `room.handle_presence` returns the matching
/// MucEvent, or until `Duration::from_secs(deadline_secs)` elapses.
/// Filters non-presence stanzas and `OutsideRoom` quietly. Returns the
/// matching event so callers can assert on its body.
/// Drain *both* streams concurrently into their respective rooms
/// until `done(alice_room, bob_room)` returns `true`. Polling both at
/// once is necessary because Prosody can broadcast bob's join to alice
/// at any point — if alice is idle inside a single-client pump, the
/// broadcast lands in tokio-xmpp's internal channel but our task is
/// not yielding to drain it.
async fn pump_two<F: Fn(&MucRoom, &MucRoom) -> bool>(
    alice: &mut omemo_pep::Client,
    alice_room: &mut MucRoom,
    bob: &mut omemo_pep::Client,
    bob_room: &mut MucRoom,
    deadline_secs: u64,
    done: F,
) {
    if done(alice_room, bob_room) {
        return;
    }
    tokio::time::timeout(Duration::from_secs(deadline_secs), async {
        loop {
            tokio::select! {
                ev = alice.next() => match ev {
                    Some(Event::Stanza(Stanza::Presence(p))) => {
                        let _ = alice_room.handle_presence(&p);
                    }
                    Some(_) => {}
                    None => panic!("alice stream ended"),
                },
                ev = bob.next() => match ev {
                    Some(Event::Stanza(Stanza::Presence(p))) => {
                        let _ = bob_room.handle_presence(&p);
                    }
                    Some(_) => {}
                    None => panic!("bob stream ended"),
                },
            }
            if done(alice_room, bob_room) {
                return;
            }
        }
    })
    .await
    .expect("pump_two: predicate not satisfied within deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
#[ignore = "Stage 5.1; requires Prosody on 127.0.0.1:5222 with conference.localhost MUC"]
async fn two_clients_join_same_room_and_see_each_other() {
    let alice_jid = BareJid::from_str("muc_a@localhost").unwrap();
    let bob_jid = BareJid::from_str("muc_b@localhost").unwrap();
    let room_jid = BareJid::from_str("muc_5_1@conference.localhost").unwrap();

    let mut alice = connect_plaintext(alice_jid.clone(), "mucapass", "127.0.0.1:5222");
    let mut bob = connect_plaintext(bob_jid.clone(), "mucbpass", "127.0.0.1:5222");
    await_online(&mut alice).await;
    await_online(&mut bob).await;

    // RFC 6121 §4.2: each session MUST send initial `<presence/>` before
    // any directed presence (like a MUC join) is considered routable.
    alice
        .send_stanza(Presence::available().into())
        .await
        .expect("alice initial presence");
    bob.send_stanza(Presence::available().into())
        .await
        .expect("bob initial presence");

    let mut alice_room = MucRoom::new(room_jid.clone(), "alice_nick");
    let mut bob_room = MucRoom::new(room_jid.clone(), "bob_nick");

    // Alice joins first; ensure her self-presence lands.
    alice_room.send_join(&mut alice).await.expect("alice join");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        10,
        |a, _| {
            a.occupants
                .get("alice_nick")
                .is_some_and(|o| o.real_jid.is_some())
        },
    )
    .await;
    assert_eq!(
        alice_room
            .occupants
            .get("alice_nick")
            .unwrap()
            .real_jid
            .as_ref()
            .map(|j| j.as_str()),
        Some("muc_a@localhost")
    );

    // Alice submits the muc#owner default-config form so the
    // freshly-created room unlocks for bob.
    alice_room
        .accept_default_config(&mut alice)
        .await
        .expect("alice accept default config");

    // Bob joins. We wait until BOTH rooms have BOTH occupants with
    // real JIDs — i.e. the broadcast has reached alice and the
    // history has reached bob.
    bob_room.send_join(&mut bob).await.expect("bob join");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        15,
        |a, b| {
            let want =
                |r: &MucRoom, n: &str| r.occupants.get(n).is_some_and(|o| o.real_jid.is_some());
            want(a, "alice_nick")
                && want(a, "bob_nick")
                && want(b, "alice_nick")
                && want(b, "bob_nick")
        },
    )
    .await;
    assert_eq!(
        bob_room
            .occupants
            .get("alice_nick")
            .unwrap()
            .real_jid
            .as_ref()
            .map(|j| j.as_str()),
        Some("muc_a@localhost")
    );
    assert_eq!(
        alice_room
            .occupants
            .get("bob_nick")
            .unwrap()
            .real_jid
            .as_ref()
            .map(|j| j.as_str()),
        Some("muc_b@localhost")
    );

    // Bob leaves; alice eventually observes the occupant disappear.
    bob_room.send_leave(&mut bob).await.expect("bob leave");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        10,
        |a, _| !a.occupants.contains_key("bob_nick"),
    )
    .await;
    assert!(alice_room.occupants.contains_key("alice_nick"));

    alice.send_end().await.expect("alice send_end");
    bob.send_end().await.expect("bob send_end");
}

/// Stage 5.2 — both clients publish their OMEMO device list to PEP,
/// then each one calls `MucRoom::refresh_device_lists` to pull the
/// other side's list into its local SQLite store. Verifies the per-
/// occupant device-list cache pipeline end-to-end (PEP fetch +
/// `Store::upsert_device`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
#[ignore = "Stage 5.2; requires Prosody on 127.0.0.1:5222 with conference.localhost MUC"]
async fn refresh_pulls_each_occupants_device_list_into_store() {
    const ALICE_DEVICE_ID: u32 = 27_001;
    const BOB_DEVICE_ID: u32 = 27_002;

    let alice_jid = BareJid::from_str("muc_c@localhost").unwrap();
    let bob_jid = BareJid::from_str("muc_d@localhost").unwrap();
    let room_jid = BareJid::from_str("muc_5_2@conference.localhost").unwrap();

    let mut alice_store = Store::open_in_memory().expect("alice store");
    let mut bob_store = Store::open_in_memory().expect("bob store");
    install_identity(
        &mut alice_store,
        &IdentitySeed {
            bare_jid: alice_jid.as_str(),
            device_id: ALICE_DEVICE_ID,
            ik_seed: [0xA1; 32],
            spk_id: 1,
            spk_priv: [0xA2; 32],
            spk_sig_nonce: [0xA3; 64],
            opks: &[(101, [0xA4; 32])],
        },
    )
    .expect("alice install_identity");
    install_identity(
        &mut bob_store,
        &IdentitySeed {
            bare_jid: bob_jid.as_str(),
            device_id: BOB_DEVICE_ID,
            ik_seed: [0xB1; 32],
            spk_id: 1,
            spk_priv: [0xB2; 32],
            spk_sig_nonce: [0xB3; 64],
            opks: &[(201, [0xB4; 32])],
        },
    )
    .expect("bob install_identity");

    let mut alice = connect_plaintext(alice_jid.clone(), "muccpass", "127.0.0.1:5222");
    let mut bob = connect_plaintext(bob_jid.clone(), "mucdpass", "127.0.0.1:5222");
    await_online(&mut alice).await;
    await_online(&mut bob).await;

    alice
        .send_stanza(Presence::available().into())
        .await
        .expect("alice initial presence");
    bob.send_stanza(Presence::available().into())
        .await
        .expect("bob initial presence");

    // Each side publishes its own OMEMO device list onto PEP. The MUC
    // layer doesn't drive PEP — that's the c2s plumbing from Stage 4.
    let alice_device_list = DeviceList {
        devices: vec![Device {
            id: ALICE_DEVICE_ID,
            label: Some("alice-laptop".into()),
            labelsig: None,
        }],
    };
    let bob_device_list = DeviceList {
        devices: vec![Device {
            id: BOB_DEVICE_ID,
            label: Some("bob-phone".into()),
            labelsig: None,
        }],
    };
    publish_device_list(&mut alice, &alice_device_list)
        .await
        .expect("alice publish device list");
    publish_device_list(&mut bob, &bob_device_list)
        .await
        .expect("bob publish device list");

    // Drive both sides into the same room. Same dance as Stage 5.1.
    let mut alice_room = MucRoom::new(room_jid.clone(), "alice_nick");
    let mut bob_room = MucRoom::new(room_jid.clone(), "bob_nick");

    alice_room.send_join(&mut alice).await.expect("alice join");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        10,
        |a, _| {
            a.occupants
                .get("alice_nick")
                .is_some_and(|o| o.real_jid.is_some())
        },
    )
    .await;
    alice_room
        .accept_default_config(&mut alice)
        .await
        .expect("alice accept default config");
    bob_room.send_join(&mut bob).await.expect("bob join");
    pump_two(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        15,
        |a, b| {
            let want =
                |r: &MucRoom, n: &str| r.occupants.get(n).is_some_and(|o| o.real_jid.is_some());
            want(a, "alice_nick")
                && want(a, "bob_nick")
                && want(b, "alice_nick")
                && want(b, "bob_nick")
        },
    )
    .await;

    // Alice pulls the room's device lists into her store. She should
    // see herself + bob; bob's row should carry his published label.
    let alice_pulled = alice_room
        .refresh_device_lists(&mut alice, &mut alice_store)
        .await
        .expect("alice refresh");
    let alice_pulled_map: std::collections::HashMap<&str, Vec<u32>> = alice_pulled
        .iter()
        .map(|(j, ids)| (j.as_str(), ids.clone()))
        .collect();
    assert_eq!(
        alice_pulled_map.get("muc_d@localhost"),
        Some(&vec![BOB_DEVICE_ID])
    );
    let bob_devices_in_alice_store = alice_store.devices_for("muc_d@localhost").unwrap();
    assert_eq!(bob_devices_in_alice_store.len(), 1);
    assert_eq!(bob_devices_in_alice_store[0].device_id, BOB_DEVICE_ID);
    assert_eq!(
        bob_devices_in_alice_store[0].label.as_deref(),
        Some("bob-phone")
    );

    // Bob does the same; alice's device should land in bob's store.
    let bob_pulled = bob_room
        .refresh_device_lists(&mut bob, &mut bob_store)
        .await
        .expect("bob refresh");
    let bob_pulled_map: std::collections::HashMap<&str, Vec<u32>> = bob_pulled
        .iter()
        .map(|(j, ids)| (j.as_str(), ids.clone()))
        .collect();
    assert_eq!(
        bob_pulled_map.get("muc_c@localhost"),
        Some(&vec![ALICE_DEVICE_ID])
    );
    let alice_devices_in_bob_store = bob_store.devices_for("muc_c@localhost").unwrap();
    assert_eq!(alice_devices_in_bob_store.len(), 1);
    assert_eq!(alice_devices_in_bob_store[0].device_id, ALICE_DEVICE_ID);
    assert_eq!(
        alice_devices_in_bob_store[0].label.as_deref(),
        Some("alice-laptop")
    );

    alice.send_end().await.expect("alice send_end");
    bob.send_end().await.expect("bob send_end");
}
