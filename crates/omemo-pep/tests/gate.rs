//! Stage 4 GATE TEST — two omemo-pep instances exchange three OMEMO 2
//! messages over a real XMPP server (Prosody on `127.0.0.1:5222`).
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
//! 1. alice and bob each generate an X3dhState, a stanza-level Bundle,
//!    and a single-device DeviceList.
//! 2. Both connect to Prosody (alice@localhost / bob@localhost) and
//!    publish their device list and bundle to PEP.
//! 3. Alice fetches bob's published bundle from PEP, runs X3DH active
//!    via `bootstrap_active_session_from_bundle`, encrypts a "hello"
//!    with `kex=true` and sends `<message><encrypted/></message>`.
//! 4. Bob receives, classifies via `inbound_kind`, decrypts via
//!    `decrypt_inbound_kex` — yields a passive session and the
//!    plaintext.
//! 5. Alice sends two follow-up messages (`kex=false`); bob decrypts
//!    each via `decrypt_message`.
//!
//! The test pre-shares the (spk_id, opk_ids) the publishing side
//! used. In production those IDs would be persisted alongside the
//! bundle in `omemo-session`'s SQLite store; here we just thread them
//! through test-local variables.

use std::str::FromStr;
use std::time::Duration;

use futures_util::StreamExt;
use omemo_pep::{
    bootstrap_active_session_from_bundle, connect_plaintext, decrypt_inbound_kex, decrypt_message,
    encrypt_message, fetch_bundle, fetch_device_list, inbound_kind, publish_bundle,
    publish_device_list, send_encrypted, wait_for_encrypted, BareJid, Bundle, Device, DeviceList,
    Event, InboundKind, PreKey, Recipient, SignedPreKey,
};
use omemo_twomemo::fixed_priv_provider;
use omemo_x3dh::{IdentityKeyPair, PreKeyPair, SignedPreKeyPair, X3dhState};

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

fn make_x3dh_state(
    ik_seed: [u8; 32],
    spk_priv: [u8; 32],
    spk_sig_nonce: [u8; 64],
    opk_privs: Vec<[u8; 32]>,
) -> X3dhState {
    let ik = IdentityKeyPair::Seed(ik_seed);
    let spk = SignedPreKeyPair::create(&ik, spk_priv, spk_sig_nonce, 0);
    let pre_keys = opk_privs
        .into_iter()
        .map(|p| PreKeyPair { priv_key: p })
        .collect();
    X3dhState {
        identity_key: ik,
        signed_pre_key: spk,
        old_signed_pre_key: None,
        pre_keys,
    }
}

fn bundle_stanza(state: &X3dhState, spk_id: u32, opk_ids: &[u32]) -> Bundle {
    Bundle {
        spk: SignedPreKey {
            id: spk_id,
            pub_key: state.signed_pre_key.pub_key().to_vec(),
        },
        spks: state.signed_pre_key.sig.to_vec(),
        ik: state.identity_key.ed25519_pub().to_vec(),
        prekeys: state
            .pre_keys
            .iter()
            .zip(opk_ids)
            .map(|(pk, &id)| PreKey {
                id,
                pub_key: pk.pub_key().to_vec(),
            })
            .collect(),
    }
}

#[tokio::test]
#[ignore = "Stage 4 gate; requires Prosody on 127.0.0.1:5222"]
async fn alice_to_bob_three_messages_over_real_xmpp() {
    // ------ X3DH state for both sides (deterministic for repeatability).
    let alice_state = make_x3dh_state(
        [0xA1; 32],
        [0xA2; 32],
        [0xA3; 64],
        vec![[0xA4; 32], [0xA5; 32]],
    );
    let bob_state = make_x3dh_state(
        [0xB1; 32],
        [0xB2; 32],
        [0xB3; 64],
        vec![[0xB4; 32], [0xB5; 32]],
    );
    let alice_device_id: u32 = 1001;
    let bob_device_id: u32 = 2001;
    let alice_spk_id: u32 = 1;
    let alice_opk_ids: [u32; 2] = [101, 102];
    let bob_spk_id: u32 = 1;
    let bob_opk_ids: [u32; 2] = [201, 202];
    let alice_bundle_stanza = bundle_stanza(&alice_state, alice_spk_id, &alice_opk_ids);
    let bob_bundle_stanza = bundle_stanza(&bob_state, bob_spk_id, &bob_opk_ids);

    // ------ Connect both clients.
    let alice_jid = BareJid::from_str("alice@localhost").unwrap();
    let bob_jid = BareJid::from_str("bob@localhost").unwrap();
    let mut alice = connect_plaintext(alice_jid.clone(), "alicepass", "127.0.0.1:5222");
    let mut bob = connect_plaintext(bob_jid.clone(), "bobpass", "127.0.0.1:5222");
    await_online(&mut alice).await;
    await_online(&mut bob).await;

    // Both clients announce availability so Prosody routes chat
    // messages to bob's bound resource.
    announce_presence(&mut alice).await;
    announce_presence(&mut bob).await;

    // ------ Each publishes device list + bundle.
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

    // ------ Alice bootstraps active session against bob's bundle.
    let chosen_opk_id = bob_opk_ids[0];
    let alice_ek_priv = [0x42; 32];
    let alice_dr_privs: Vec<[u8; 32]> = (1..=8).map(|i| [(0x50 + i) as u8; 32]).collect();
    let (mut alice_session, kex_carrier) = bootstrap_active_session_from_bundle(
        &alice_state,
        &bob_bundle_fetched,
        chosen_opk_id,
        alice_ek_priv,
        fixed_priv_provider(alice_dr_privs),
    )
    .expect("alice bootstrap active session");

    // ------ Message #1: KEX.
    let bob_jid_str = bob_jid.to_string();
    let plaintext_1 = b"hello bob (kex)";
    {
        let mut recipients = [Recipient {
            jid: &bob_jid_str,
            device_id: bob_device_id,
            session: &mut alice_session,
            kex: Some(kex_carrier),
        }];
        let encrypted = encrypt_message(alice_device_id, &mut recipients, plaintext_1)
            .expect("alice encrypt #1");
        send_encrypted(&mut alice, bob_jid.clone(), &encrypted)
            .await
            .expect("alice send #1");
    }

    let (sender_jid, received_1) =
        tokio::time::timeout(Duration::from_secs(10), wait_for_encrypted(&mut bob))
            .await
            .expect("bob receive #1 timeout")
            .expect("bob receive #1");
    assert_eq!(sender_jid.as_ref(), Some(&alice_jid));
    assert_eq!(
        inbound_kind(&received_1, &bob_jid_str, bob_device_id).unwrap(),
        InboundKind::Kex
    );
    let bob_dr_privs: Vec<[u8; 32]> = (1..=8).map(|i| [(0x70 + i) as u8; 32]).collect();
    let spk_pub_lookup = |id: u32| (id == bob_spk_id).then(|| bob_state.signed_pre_key.pub_key());
    let opk_pub_lookup = |id: u32| {
        bob_opk_ids
            .iter()
            .position(|&i| i == id)
            .map(|idx| bob_state.pre_keys[idx].pub_key())
    };
    let (mut bob_session, recovered_1, consumed_opk_id) = decrypt_inbound_kex(
        &received_1,
        &bob_jid_str,
        bob_device_id,
        &bob_state,
        spk_pub_lookup,
        opk_pub_lookup,
        fixed_priv_provider(bob_dr_privs),
    )
    .expect("bob decrypt_inbound_kex");
    assert_eq!(recovered_1, plaintext_1);
    assert_eq!(consumed_opk_id, chosen_opk_id);

    // ------ Messages #2 and #3: Follow.
    for (idx, plaintext) in [
        (2u32, b"second message" as &[u8]),
        (3u32, b"third message" as &[u8]),
    ] {
        {
            let mut recipients = [Recipient {
                jid: &bob_jid_str,
                device_id: bob_device_id,
                session: &mut alice_session,
                kex: None,
            }];
            let encrypted = encrypt_message(alice_device_id, &mut recipients, plaintext)
                .unwrap_or_else(|e| panic!("alice encrypt #{idx} failed: {e:?}"));
            send_encrypted(&mut alice, bob_jid.clone(), &encrypted)
                .await
                .unwrap_or_else(|e| panic!("alice send #{idx} failed: {e:?}"));
        }
        let (_, received) =
            tokio::time::timeout(Duration::from_secs(10), wait_for_encrypted(&mut bob))
                .await
                .unwrap_or_else(|_| panic!("bob receive #{idx} timed out"))
                .unwrap_or_else(|e| panic!("bob receive #{idx} error: {e:?}"));
        assert_eq!(
            inbound_kind(&received, &bob_jid_str, bob_device_id).unwrap(),
            InboundKind::Follow
        );
        let recovered = decrypt_message(&received, &bob_jid_str, bob_device_id, &mut bob_session)
            .unwrap_or_else(|e| panic!("bob decrypt #{idx} error: {e:?}"));
        assert_eq!(recovered, plaintext, "message #{idx} plaintext mismatch");
    }

    // ------ Clean shutdown.
    alice.send_end().await.expect("alice send_end");
    bob.send_end().await.expect("bob send_end");
}
