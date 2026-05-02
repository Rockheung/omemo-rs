//! Stage 4 GATE TEST — two omemo-pep instances exchange three OMEMO 2
//! messages over a real XMPP server (Prosody on `127.0.0.1:5222`),
//! with `omemo-session`'s SQLite [`Store`] as the system of record on
//! both sides (4-FU.1).
//!
//! Bring Prosody up first:
//!
//!     docker compose -f test-vectors/integration/prosody/docker-compose.yml up -d
//!
//! Then:
//!
//!     cargo test -p omemo-pep --test gate -- --ignored
//!
//! Flow:
//! 1. alice and bob each open an in-memory `Store`, install identity +
//!    SPK + OPKs into it via `install_identity`, and derive their
//!    stanza-level [`Bundle`] from the store.
//! 2. Both connect to Prosody (alice@localhost / bob@localhost) and
//!    publish their device list and bundle to PEP.
//! 3. Alice fetches bob's published bundle, calls
//!    `bootstrap_and_save_active`, which runs X3DH active and
//!    persists the freshly created session under
//!    `(bob_jid, bob_device)` in alice's store.
//! 4. Alice sends "hello" via `encrypt_to_peer` (with KEX), which
//!    reloads the session, encrypts, and persists the advanced state.
//! 5. Bob receives, runs `receive_first_message` — that looks up
//!    SPK/OPK pubs from his store by id, runs X3DH passive + ratchet
//!    decrypt + SCE open, and atomically `consume_opk` + saves the new
//!    session.
//! 6. Two follow-up messages: alice `encrypt_to_peer(... kex: None)`,
//!    bob `receive_followup(...)`. Both sides reload the session from
//!    SQLite for each step and persist after.
//!
//! No state lives in Rust locals across encrypt/decrypt boundaries —
//! the store IS the state.

use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use omemo_pep::{
    bootstrap_and_save_active, bundle_from_store, connect_plaintext, encrypt_to_peer, fetch_bundle,
    fetch_device_list, inbound_kind, install_identity, publish_bundle, publish_device_list,
    receive_first_message, receive_followup, send_encrypted, wait_for_encrypted, BareJid, Device,
    DeviceList, Event, IdentitySeed, InboundKind, Store, TrustPolicy, TrustState,
};
use omemo_twomemo::fixed_priv_provider;

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

async fn announce_presence(client: &mut omemo_pep::Client) {
    use xmpp_parsers::presence::Presence;
    client
        .send_stanza(Presence::available().into())
        .await
        .expect("send presence");
}

#[tokio::test]
#[ignore = "Stage 4 gate; requires Prosody on 127.0.0.1:5222"]
async fn alice_to_bob_three_messages_over_real_xmpp() {
    // ------ Per-side SQLite stores. In-memory because the gate is a
    // one-shot test; production would use `Store::open(path)`.
    let mut alice_store = Store::open_in_memory().expect("alice store");
    let mut bob_store = Store::open_in_memory().expect("bob store");

    let alice_device_id: u32 = 1001;
    let bob_device_id: u32 = 2001;
    let bob_opk_ids: [u32; 2] = [201, 202];

    let alice_opks: &[(u32, [u8; 32])] = &[(101, [0xA4; 32]), (102, [0xA5; 32])];
    let bob_opks: &[(u32, [u8; 32])] =
        &[(bob_opk_ids[0], [0xB4; 32]), (bob_opk_ids[1], [0xB5; 32])];
    install_identity(
        &mut alice_store,
        &IdentitySeed {
            bare_jid: "gate_a@localhost",
            device_id: alice_device_id,
            ik_seed: [0xA1; 32],
            spk_id: 1,
            spk_priv: [0xA2; 32],
            spk_sig_nonce: [0xA3; 64],
            opks: alice_opks,
        },
    )
    .expect("alice install_identity");
    install_identity(
        &mut bob_store,
        &IdentitySeed {
            bare_jid: "gate_b@localhost",
            device_id: bob_device_id,
            ik_seed: [0xB1; 32],
            spk_id: 1,
            spk_priv: [0xB2; 32],
            spk_sig_nonce: [0xB3; 64],
            opks: bob_opks,
        },
    )
    .expect("bob install_identity");

    // ------ Connect both clients. The gate uses dedicated accounts
    // (`gate_a` / `gate_b`) so it can run in parallel with `connect.rs`
    // (uses `alice`) and `pep.rs` (uses `bob` and `charlie`) without two
    // sessions colliding on the same JID.
    let alice_jid = BareJid::from_str("gate_a@localhost").unwrap();
    let bob_jid = BareJid::from_str("gate_b@localhost").unwrap();
    let mut alice = connect_plaintext(alice_jid.clone(), "gateapass", "127.0.0.1:5222");
    let mut bob = connect_plaintext(bob_jid.clone(), "gatebpass", "127.0.0.1:5222");
    await_online(&mut alice).await;
    await_online(&mut bob).await;

    // Both clients announce availability so Prosody routes chat
    // messages to bob's bound resource.
    announce_presence(&mut alice).await;
    announce_presence(&mut bob).await;

    // ------ Each publishes device list + bundle (built from the store).
    let alice_device_list = DeviceList {
        devices: vec![Device {
            id: alice_device_id,
            label: None,
            labelsig: None,
        }],
    };
    let bob_device_list = DeviceList {
        devices: vec![Device {
            id: bob_device_id,
            label: None,
            labelsig: None,
        }],
    };
    let alice_bundle_stanza = bundle_from_store(&alice_store).expect("alice bundle_from_store");
    let bob_bundle_stanza = bundle_from_store(&bob_store).expect("bob bundle_from_store");

    publish_device_list(&mut alice, &alice_device_list)
        .await
        .expect("alice publish device list");
    publish_bundle(&mut alice, alice_device_id, &alice_bundle_stanza)
        .await
        .expect("alice publish bundle");
    publish_device_list(&mut bob, &bob_device_list)
        .await
        .expect("bob publish device list");
    publish_bundle(&mut bob, bob_device_id, &bob_bundle_stanza)
        .await
        .expect("bob publish bundle");

    // ------ Alice fetches bob's data.
    let bob_devices_fetched = fetch_device_list(&mut alice, Some(bob_jid.clone()))
        .await
        .expect("alice fetch bob device list");
    assert!(
        bob_devices_fetched
            .devices
            .iter()
            .any(|d| d.id == bob_device_id),
        "bob's device id present in fetched list"
    );
    let bob_bundle_fetched = fetch_bundle(&mut alice, Some(bob_jid.clone()), bob_device_id)
        .await
        .expect("alice fetch bob bundle");

    // ------ Alice bootstraps active session, persisted in her store.
    let chosen_opk_id = bob_opk_ids[0];
    let alice_ek_priv = [0x42; 32];
    let alice_dr_privs: Vec<[u8; 32]> = (1..=8).map(|i| [(0x50 + i) as u8; 32]).collect();
    let kex_carrier = bootstrap_and_save_active(
        &mut alice_store,
        bob_jid.as_str(),
        bob_device_id,
        &bob_bundle_fetched,
        chosen_opk_id,
        alice_ek_priv,
        fixed_priv_provider(alice_dr_privs),
    )
    .expect("alice bootstrap_and_save_active");

    // ------ Message #1: KEX (loaded from / saved to alice_store).
    let body_1 = "hello bob (kex)";
    let encrypted_1 = encrypt_to_peer(
        &mut alice_store,
        alice_device_id,
        bob_jid.as_str(),
        bob_device_id,
        body_1,
        Some(kex_carrier),
        fixed_priv_provider(vec![]),
    )
    .expect("alice encrypt_to_peer #1");
    send_encrypted(&mut alice, bob_jid.clone(), &encrypted_1)
        .await
        .expect("alice send #1");

    let (sender_jid, received_1) =
        tokio::time::timeout(Duration::from_secs(10), wait_for_encrypted(&mut bob))
            .await
            .expect("bob receive #1 timeout")
            .expect("bob receive #1");
    assert_eq!(sender_jid.as_ref(), Some(&alice_jid));
    assert_eq!(
        inbound_kind(&received_1, bob_jid.as_str(), bob_device_id).unwrap(),
        InboundKind::Kex
    );
    let bob_dr_privs: Vec<[u8; 32]> = (1..=8).map(|i| [(0x70 + i) as u8; 32]).collect();
    let recovered_1 = receive_first_message(
        &mut bob_store,
        &received_1,
        bob_jid.as_str(),
        bob_device_id,
        bob_jid.as_str(),
        alice_jid.as_str(),
        alice_device_id,
        TrustPolicy::Tofu,
        fixed_priv_provider(bob_dr_privs),
    )
    .expect("bob receive_first_message");
    assert_eq!(recovered_1.body, body_1);
    assert_eq!(recovered_1.from_jid, alice_jid.as_str());

    // The OPK we chose must be marked consumed on bob's side.
    let consumed_opk = bob_store
        .get_opk(chosen_opk_id)
        .unwrap()
        .expect("opk row exists");
    assert!(
        consumed_opk.consumed,
        "bob's OPK {chosen_opk_id} consumed after first inbound"
    );

    // Alice's device should now be Trusted in bob's store.
    let alice_trust = bob_store
        .trusted_device(alice_jid.as_str(), alice_device_id)
        .unwrap()
        .expect("alice device recorded under TOFU");
    assert_eq!(alice_trust.state, TrustState::Trusted);

    // ------ Messages #2 and #3: Follow.
    for (idx, body) in [(2u32, "second message"), (3u32, "third message")] {
        let encrypted = encrypt_to_peer(
            &mut alice_store,
            alice_device_id,
            bob_jid.as_str(),
            bob_device_id,
            body,
            None,
            fixed_priv_provider(vec![]),
        )
        .unwrap_or_else(|e| panic!("alice encrypt #{idx} failed: {e:?}"));
        send_encrypted(&mut alice, bob_jid.clone(), &encrypted)
            .await
            .unwrap_or_else(|e| panic!("alice send #{idx} failed: {e:?}"));

        let (_, received) =
            tokio::time::timeout(Duration::from_secs(10), wait_for_encrypted(&mut bob))
                .await
                .unwrap_or_else(|_| panic!("bob receive #{idx} timed out"))
                .unwrap_or_else(|e| panic!("bob receive #{idx} error: {e:?}"));
        assert_eq!(
            inbound_kind(&received, bob_jid.as_str(), bob_device_id).unwrap(),
            InboundKind::Follow
        );
        let recovered = receive_followup(
            &mut bob_store,
            &received,
            bob_jid.as_str(),
            bob_device_id,
            bob_jid.as_str(),
            alice_jid.as_str(),
            alice_device_id,
            fixed_priv_provider(vec![]),
        )
        .unwrap_or_else(|e| panic!("bob receive_followup #{idx} error: {e:?}"));
        assert_eq!(recovered.body, body, "message #{idx} body mismatch");
    }

    // ------ Clean shutdown.
    alice.send_end().await.expect("alice send_end");
    bob.send_end().await.expect("bob send_end");
}
