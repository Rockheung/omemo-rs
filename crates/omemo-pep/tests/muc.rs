//! Stage 5 MUC integration tests:
//!
//! * `two_clients_join_same_room_and_see_each_other` — Stage 5.1 join
//!   + occupant tracking.
//! * `refresh_pulls_each_occupants_device_list_into_store` — Stage 5.2
//!   per-occupant device-list cache.
//! * `three_clients_groupchat_omemo2_round_trip` — Stage 5.5 gate.
//!   alice / bob / carol exchange OMEMO 2 chat messages over a real
//!   XMPP MUC, with full encrypt/fan-out/decrypt round-trips.
//!
//! ```sh
//! docker compose -f test-vectors/integration/xmpp/docker-compose.yml up -d
//! cargo test -p omemo-pep --test muc -- --ignored
//! ```
//!
//! Each scenario claims its own group of pre-registered
//! accounts (`muc_a` / `muc_b` for 5.1, `muc_c` / `muc_d` for 5.2,
//! `muc_e` / `muc_f` / `muc_g` for 5.5) and `serial_test::serial`
//! pins the binary's tests to run one at a time so cargo's per-
//! binary parallelism doesn't race four-plus clients on a cold
//! the server.

use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use omemo_pep::{
    bootstrap_and_save_active, connect_plaintext, encrypt_to_peers, fetch_bundle, inbound_kind,
    install_identity, publish_bundle, publish_device_list, receive_first_message, receive_followup,
    wait_for_encrypted, BareJid, Bundle, Device, DeviceList, Event, IdentitySeed, InboundKind,
    MucRoom, PeerSpec, PreKey, SignedPreKey, Store, TrustPolicy,
};
use omemo_twomemo::fixed_priv_provider;
use omemo_x3dh::{IdentityKeyPair, PreKeyPair, SignedPreKeyPair, X3dhState};
use tokio_xmpp::Stanza;
use xmpp_parsers::presence::Presence;

async fn await_online(client: &mut omemo_pep::Client) {
    // 60s — Stage 5 puts up to ~7 clients on one server (4 in
    // `tests/muc.rs` plus 3 in the Stage 5.5 gate, all serialised by
    // `serial_test::serial`), and the OTHER test binaries
    // (`tests/gate.rs`, `tests/pep.rs`, `tests/connect.rs`) run in
    // parallel against the same container. Cold-cache login can take
    // more than the previous 30s ceiling.
    tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(event) = client.next().await {
            if matches!(event, Event::Online { .. }) {
                return;
            }
        }
        panic!("client stream ended without Online event (is the XMPP fixture running?)");
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
/// once is necessary because the server can broadcast bob's join to alice
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
#[ignore = "Stage 5.1; requires the XMPP fixture on 127.0.0.1:5222 with conference.localhost MUC"]
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
#[ignore = "Stage 5.2; requires the XMPP fixture on 127.0.0.1:5222 with conference.localhost MUC"]
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

// ============================================================
// Stage 5.5 — group OMEMO gate (3 clients in MUC)
// ============================================================

/// Three-stream variant of [`pump_two`].
#[allow(clippy::too_many_arguments)]
async fn pump_three<F: Fn(&MucRoom, &MucRoom, &MucRoom) -> bool>(
    a: &mut omemo_pep::Client,
    ar: &mut MucRoom,
    b: &mut omemo_pep::Client,
    br: &mut MucRoom,
    c: &mut omemo_pep::Client,
    cr: &mut MucRoom,
    deadline_secs: u64,
    done: F,
) {
    if done(ar, br, cr) {
        return;
    }
    tokio::time::timeout(Duration::from_secs(deadline_secs), async {
        loop {
            tokio::select! {
                ev = a.next() => match ev {
                    Some(Event::Stanza(Stanza::Presence(p))) => { let _ = ar.handle_presence(&p); }
                    Some(_) => {}
                    None => panic!("a stream ended"),
                },
                ev = b.next() => match ev {
                    Some(Event::Stanza(Stanza::Presence(p))) => { let _ = br.handle_presence(&p); }
                    Some(_) => {}
                    None => panic!("b stream ended"),
                },
                ev = c.next() => match ev {
                    Some(Event::Stanza(Stanza::Presence(p))) => { let _ = cr.handle_presence(&p); }
                    Some(_) => {}
                    None => panic!("c stream ended"),
                },
            }
            if done(ar, br, cr) {
                return;
            }
        }
    })
    .await
    .expect("pump_three: predicate not satisfied within deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[serial_test::serial]
#[ignore = "Stage 5.5 gate; requires the XMPP fixture on 127.0.0.1:5222 with conference.localhost MUC"]
async fn three_clients_groupchat_omemo2_round_trip() {
    // ------------------------------------------------------------
    // Identity material — deterministic seeds for replay; production
    // would draw these from the OS RNG inside `install_identity`.
    // ------------------------------------------------------------
    const ALICE_DEV: u32 = 51_001;
    const BOB_DEV: u32 = 51_002;
    const CAROL_DEV: u32 = 51_003;
    const ALICE_OPK: u32 = 101;
    const BOB_OPK: u32 = 201;
    const CAROL_OPK: u32 = 301;

    let alice_jid = BareJid::from_str("muc_e@localhost").unwrap();
    let bob_jid = BareJid::from_str("muc_f@localhost").unwrap();
    let carol_jid = BareJid::from_str("muc_g@localhost").unwrap();

    let mut alice_store = Store::open_in_memory().unwrap();
    let mut bob_store = Store::open_in_memory().unwrap();
    let mut carol_store = Store::open_in_memory().unwrap();

    install_identity(
        &mut alice_store,
        &IdentitySeed {
            bare_jid: alice_jid.as_str(),
            device_id: ALICE_DEV,
            ik_seed: [0xA1; 32],
            spk_id: 1,
            spk_priv: [0xA2; 32],
            spk_sig_nonce: [0xA3; 64],
            opks: &[(ALICE_OPK, [0xA4; 32])],
        },
    )
    .unwrap();
    install_identity(
        &mut bob_store,
        &IdentitySeed {
            bare_jid: bob_jid.as_str(),
            device_id: BOB_DEV,
            ik_seed: [0xB1; 32],
            spk_id: 1,
            spk_priv: [0xB2; 32],
            spk_sig_nonce: [0xB3; 64],
            opks: &[(BOB_OPK, [0xB4; 32])],
        },
    )
    .unwrap();
    install_identity(
        &mut carol_store,
        &IdentitySeed {
            bare_jid: carol_jid.as_str(),
            device_id: CAROL_DEV,
            ik_seed: [0xC1; 32],
            spk_id: 1,
            spk_priv: [0xC2; 32],
            spk_sig_nonce: [0xC3; 64],
            opks: &[(CAROL_OPK, [0xC4; 32])],
        },
    )
    .unwrap();

    // Build the publish-side X3dhState shadows so we can publish each
    // bundle to PEP. (`install_identity` writes into the store, but
    // it doesn't return the X3dhState; the receivers reconstruct theirs
    // via `x3dh_state_from_store` inside receive_first_message.)
    let bob_state = X3dhState {
        identity_key: IdentityKeyPair::Seed([0xB1; 32]),
        signed_pre_key: SignedPreKeyPair::create(
            &IdentityKeyPair::Seed([0xB1; 32]),
            [0xB2; 32],
            [0xB3; 64],
            0,
        ),
        old_signed_pre_key: None,
        pre_keys: vec![PreKeyPair {
            priv_key: [0xB4; 32],
        }],
    };
    let carol_state = X3dhState {
        identity_key: IdentityKeyPair::Seed([0xC1; 32]),
        signed_pre_key: SignedPreKeyPair::create(
            &IdentityKeyPair::Seed([0xC1; 32]),
            [0xC2; 32],
            [0xC3; 64],
            0,
        ),
        old_signed_pre_key: None,
        pre_keys: vec![PreKeyPair {
            priv_key: [0xC4; 32],
        }],
    };
    let bob_bundle_to_publish = Bundle {
        spk: SignedPreKey {
            id: 1,
            pub_key: bob_state.signed_pre_key.pub_key().to_vec(),
        },
        spks: bob_state.signed_pre_key.sig.to_vec(),
        ik: bob_state.identity_key.ed25519_pub().to_vec(),
        prekeys: vec![PreKey {
            id: BOB_OPK,
            pub_key: bob_state.pre_keys[0].pub_key().to_vec(),
        }],
    };
    let carol_bundle_to_publish = Bundle {
        spk: SignedPreKey {
            id: 1,
            pub_key: carol_state.signed_pre_key.pub_key().to_vec(),
        },
        spks: carol_state.signed_pre_key.sig.to_vec(),
        ik: carol_state.identity_key.ed25519_pub().to_vec(),
        prekeys: vec![PreKey {
            id: CAROL_OPK,
            pub_key: carol_state.pre_keys[0].pub_key().to_vec(),
        }],
    };

    // ------------------------------------------------------------
    // Connect, presence, publish.
    // ------------------------------------------------------------
    let mut alice = connect_plaintext(alice_jid.clone(), "mucepass", "127.0.0.1:5222");
    let mut bob = connect_plaintext(bob_jid.clone(), "mucfpass", "127.0.0.1:5222");
    let mut carol = connect_plaintext(carol_jid.clone(), "mucgpass", "127.0.0.1:5222");
    await_online(&mut alice).await;
    await_online(&mut bob).await;
    await_online(&mut carol).await;

    for client in [&mut alice, &mut bob, &mut carol] {
        client
            .send_stanza(Presence::available().into())
            .await
            .expect("initial presence");
    }

    // Each side publishes its OMEMO 2 device list and its bundle (so
    // alice's fetch_bundle below can locate them).
    publish_device_list(
        &mut alice,
        &DeviceList {
            devices: vec![Device {
                id: ALICE_DEV,
                label: None,
                labelsig: None,
            }],
        },
    )
    .await
    .expect("alice publish device list");
    publish_device_list(
        &mut bob,
        &DeviceList {
            devices: vec![Device {
                id: BOB_DEV,
                label: None,
                labelsig: None,
            }],
        },
    )
    .await
    .expect("bob publish device list");
    publish_device_list(
        &mut carol,
        &DeviceList {
            devices: vec![Device {
                id: CAROL_DEV,
                label: None,
                labelsig: None,
            }],
        },
    )
    .await
    .expect("carol publish device list");

    publish_bundle(&mut bob, BOB_DEV, &bob_bundle_to_publish)
        .await
        .expect("bob publish bundle");
    publish_bundle(&mut carol, CAROL_DEV, &carol_bundle_to_publish)
        .await
        .expect("carol publish bundle");

    // ------------------------------------------------------------
    // Join the room. Alice is creator + owner.
    // ------------------------------------------------------------
    let room_jid = BareJid::from_str("muc_5_5@conference.localhost").unwrap();
    let mut alice_room = MucRoom::new(room_jid.clone(), "alice");
    let mut bob_room = MucRoom::new(room_jid.clone(), "bob");
    let mut carol_room = MucRoom::new(room_jid.clone(), "carol");

    alice_room.send_join(&mut alice).await.expect("alice join");
    pump_three(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        &mut carol,
        &mut carol_room,
        15,
        |a, _, _| {
            a.occupants
                .get("alice")
                .is_some_and(|o| o.real_jid.is_some())
        },
    )
    .await;
    alice_room
        .accept_default_config(&mut alice)
        .await
        .expect("alice accept config");
    bob_room.send_join(&mut bob).await.expect("bob join");
    carol_room.send_join(&mut carol).await.expect("carol join");
    pump_three(
        &mut alice,
        &mut alice_room,
        &mut bob,
        &mut bob_room,
        &mut carol,
        &mut carol_room,
        20,
        |a, b, c| {
            let want =
                |r: &MucRoom, n: &str| r.occupants.get(n).is_some_and(|o| o.real_jid.is_some());
            want(a, "alice")
                && want(a, "bob")
                && want(a, "carol")
                && want(b, "alice")
                && want(b, "bob")
                && want(b, "carol")
                && want(c, "alice")
                && want(c, "bob")
                && want(c, "carol")
        },
    )
    .await;

    // ------------------------------------------------------------
    // Alice fetches bob + carol bundles, runs X3DH active for each,
    // persists the freshly-bootstrapped sessions in her store.
    // ------------------------------------------------------------
    let bob_bundle = fetch_bundle(&mut alice, Some(bob_jid.clone()), BOB_DEV)
        .await
        .expect("alice fetch bob bundle");
    let carol_bundle = fetch_bundle(&mut alice, Some(carol_jid.clone()), CAROL_DEV)
        .await
        .expect("alice fetch carol bundle");

    let alice_dr_to_bob: Vec<[u8; 32]> = (1..=8).map(|i| [(0x40 + i) as u8; 32]).collect();
    let alice_dr_to_carol: Vec<[u8; 32]> = (1..=8).map(|i| [(0x60 + i) as u8; 32]).collect();
    let kex_to_bob = bootstrap_and_save_active(
        &mut alice_store,
        bob_jid.as_str(),
        BOB_DEV,
        &bob_bundle,
        BOB_OPK,
        [0x42; 32],
        fixed_priv_provider(alice_dr_to_bob),
    )
    .expect("alice bootstrap to bob");
    let kex_to_carol = bootstrap_and_save_active(
        &mut alice_store,
        carol_jid.as_str(),
        CAROL_DEV,
        &carol_bundle,
        CAROL_OPK,
        [0x52; 32],
        fixed_priv_provider(alice_dr_to_carol),
    )
    .expect("alice bootstrap to carol");

    // ------------------------------------------------------------
    // Message #1: KEX fan-out groupchat. One <encrypted> with two
    // <key rid=>, one for bob_dev and one for carol_dev. Both wrap the
    // KEX (kex=true) so the receivers can run X3DH passive.
    // ------------------------------------------------------------
    let body_1 = "hello room (KEX)";
    let bob_jid_str = bob_jid.as_str().to_owned();
    let carol_jid_str = carol_jid.as_str().to_owned();
    let m1 = encrypt_to_peers(
        &mut alice_store,
        ALICE_DEV,
        room_jid.as_str(),
        body_1,
        vec![
            (
                PeerSpec {
                    jid: &bob_jid_str,
                    device_id: BOB_DEV,
                    kex: Some(kex_to_bob),
                },
                fixed_priv_provider(vec![]),
            ),
            (
                PeerSpec {
                    jid: &carol_jid_str,
                    device_id: CAROL_DEV,
                    kex: Some(kex_to_carol),
                },
                fixed_priv_provider(vec![]),
            ),
        ],
    )
    .expect("alice encrypt #1");
    alice_room
        .send_groupchat(&mut alice, &m1)
        .await
        .expect("alice send groupchat #1");

    let bob_dr: Vec<[u8; 32]> = (1..=8).map(|i| [(0x80 + i) as u8; 32]).collect();
    let (_from, m1_at_bob) =
        tokio::time::timeout(Duration::from_secs(15), wait_for_encrypted(&mut bob))
            .await
            .expect("bob receive #1 timeout")
            .expect("bob receive #1");
    assert_eq!(
        inbound_kind(&m1_at_bob, bob_jid.as_str(), BOB_DEV).unwrap(),
        InboundKind::Kex
    );
    let bob_recovered_1 = receive_first_message(
        &mut bob_store,
        &m1_at_bob,
        bob_jid.as_str(),
        BOB_DEV,
        room_jid.as_str(),
        alice_jid.as_str(),
        ALICE_DEV,
        TrustPolicy::Tofu,
        fixed_priv_provider(bob_dr),
    )
    .expect("bob decrypt #1");
    assert_eq!(bob_recovered_1.body, body_1);

    let carol_dr: Vec<[u8; 32]> = (1..=8).map(|i| [(0xA0 + i) as u8; 32]).collect();
    let (_from, m1_at_carol) =
        tokio::time::timeout(Duration::from_secs(15), wait_for_encrypted(&mut carol))
            .await
            .expect("carol receive #1 timeout")
            .expect("carol receive #1");
    assert_eq!(
        inbound_kind(&m1_at_carol, carol_jid.as_str(), CAROL_DEV).unwrap(),
        InboundKind::Kex
    );
    let carol_recovered_1 = receive_first_message(
        &mut carol_store,
        &m1_at_carol,
        carol_jid.as_str(),
        CAROL_DEV,
        room_jid.as_str(),
        alice_jid.as_str(),
        ALICE_DEV,
        TrustPolicy::Tofu,
        fixed_priv_provider(carol_dr),
    )
    .expect("carol decrypt #1");
    assert_eq!(carol_recovered_1.body, body_1);

    // ------------------------------------------------------------
    // Message #2: same fan-out, kex = None on both. Recovers via
    // receive_followup on each side.
    // ------------------------------------------------------------
    let body_2 = "second message, no KEX";
    let m2 = encrypt_to_peers(
        &mut alice_store,
        ALICE_DEV,
        room_jid.as_str(),
        body_2,
        vec![
            (
                PeerSpec {
                    jid: &bob_jid_str,
                    device_id: BOB_DEV,
                    kex: None,
                },
                fixed_priv_provider(vec![]),
            ),
            (
                PeerSpec {
                    jid: &carol_jid_str,
                    device_id: CAROL_DEV,
                    kex: None,
                },
                fixed_priv_provider(vec![]),
            ),
        ],
    )
    .expect("alice encrypt #2");
    alice_room
        .send_groupchat(&mut alice, &m2)
        .await
        .expect("alice send groupchat #2");

    let (_from, m2_at_bob) =
        tokio::time::timeout(Duration::from_secs(10), wait_for_encrypted(&mut bob))
            .await
            .expect("bob receive #2 timeout")
            .expect("bob receive #2");
    assert_eq!(
        inbound_kind(&m2_at_bob, bob_jid.as_str(), BOB_DEV).unwrap(),
        InboundKind::Follow
    );
    let bob_recovered_2 = receive_followup(
        &mut bob_store,
        &m2_at_bob,
        bob_jid.as_str(),
        BOB_DEV,
        room_jid.as_str(),
        alice_jid.as_str(),
        ALICE_DEV,
        fixed_priv_provider(vec![]),
    )
    .expect("bob followup");
    assert_eq!(bob_recovered_2.body, body_2);

    let (_from, m2_at_carol) =
        tokio::time::timeout(Duration::from_secs(10), wait_for_encrypted(&mut carol))
            .await
            .expect("carol receive #2 timeout")
            .expect("carol receive #2");
    assert_eq!(
        inbound_kind(&m2_at_carol, carol_jid.as_str(), CAROL_DEV).unwrap(),
        InboundKind::Follow
    );
    let carol_recovered_2 = receive_followup(
        &mut carol_store,
        &m2_at_carol,
        carol_jid.as_str(),
        CAROL_DEV,
        room_jid.as_str(),
        alice_jid.as_str(),
        ALICE_DEV,
        fixed_priv_provider(vec![]),
    )
    .expect("carol followup");
    assert_eq!(carol_recovered_2.body, body_2);

    // TOFU: alice's device should now be Trusted in both bob's and
    // carol's trust stores.
    let in_bob = bob_store
        .trusted_device(alice_jid.as_str(), ALICE_DEV)
        .unwrap()
        .unwrap();
    let in_carol = carol_store
        .trusted_device(alice_jid.as_str(), ALICE_DEV)
        .unwrap()
        .unwrap();
    assert_eq!(in_bob.state, omemo_pep::TrustState::Trusted);
    assert_eq!(in_carol.state, omemo_pep::TrustState::Trusted);

    alice.send_end().await.unwrap();
    bob.send_end().await.unwrap();
    carol.send_end().await.unwrap();
}
