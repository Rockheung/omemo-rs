//! Verifies `Store::receive_initial_message` — the high-level passive-side
//! helper that atomically runs X3DH passive + consumes the OPK + persists
//! the session in one SQLite transaction.
//!
//! Two scenarios:
//! 1. happy path: Alice initiates, Bob receives via the helper, OPK is
//!    marked consumed and session is persisted.
//! 2. negative: feeding the same KEX twice fails on the second call with
//!    `PreKeyAlreadyConsumed`, demonstrating that the consume-once
//!    enforcement is wired in.

use omemo_doubleratchet::dh_ratchet::FixedDhPrivProvider;
use omemo_session::{SessionStoreError, Store, StoredOpk, StoredSpk};
use omemo_twomemo::{build_key_exchange, TwomemoSession};
use omemo_x3dh::{
    get_shared_secret_active, Bundle as X3dhBundle, IdentityKeyPair, PreKeyPair, SignedPreKeyPair,
    X3dhState,
};

fn det(label: &str, length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 0;
    while out.len() < length {
        let mut h = Sha512::new();
        h.update(b"recv-init-fixture");
        h.update(label.as_bytes());
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

fn det32(label: &str) -> [u8; 32] {
    let v = det(label, 32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn det64(label: &str) -> [u8; 64] {
    let v = det(label, 64);
    let mut a = [0u8; 64];
    a.copy_from_slice(&v);
    a
}

const ALICE_JID: &str = "alice@example.org";
const BOB_JID: &str = "bob@example.org";
const ALICE_DEVICE_ID: u32 = 1001;
const BOB_DEVICE_ID: u32 = 2002;
const SPK_ID: u32 = 1;
const OPK_ID: u32 = 100;

fn provision_bob(store: &mut Store) -> X3dhState {
    let ik_seed = det32("bob-ik");
    store
        .put_identity(BOB_JID, BOB_DEVICE_ID, &ik_seed)
        .unwrap();

    let ik = IdentityKeyPair::Seed(ik_seed);
    let spk_priv = det32("bob-spk-priv");
    let spk_nonce = det64("bob-spk-nonce");
    let spk = SignedPreKeyPair::create(&ik, spk_priv, spk_nonce, 1234567890);
    store
        .put_spk(&StoredSpk {
            id: SPK_ID,
            priv_key: spk.priv_key,
            pub_key: spk.pub_key(),
            sig: spk.sig,
            created_at: 1234567890,
            replaced_at: None,
        })
        .unwrap();

    let opk = PreKeyPair {
        priv_key: det32("bob-opk-priv"),
    };
    store
        .put_opk(&StoredOpk {
            id: OPK_ID,
            priv_key: opk.priv_key,
            pub_key: opk.pub_key(),
            consumed: false,
            created_at: 1234567890,
        })
        .unwrap();

    X3dhState {
        identity_key: ik,
        signed_pre_key: spk,
        old_signed_pre_key: None,
        pre_keys: vec![opk],
    }
}

fn alice_state() -> X3dhState {
    let ik = IdentityKeyPair::Seed(det32("alice-ik"));
    let spk = SignedPreKeyPair::create(&ik, det32("alice-spk-priv"), det64("alice-spk-nonce"), 1);
    X3dhState {
        identity_key: ik,
        signed_pre_key: spk,
        old_signed_pre_key: None,
        pre_keys: vec![],
    }
}

/// Build a (kex_bytes, expected_plaintext) for Bob to receive.
fn alice_initiates(bob_state: &X3dhState) -> Vec<u8> {
    let bob_bundle = X3dhBundle {
        identity_key: bob_state.identity_key.ed25519_pub(),
        signed_pre_key: bob_state.signed_pre_key.pub_key(),
        signed_pre_key_sig: bob_state.signed_pre_key.sig,
        pre_keys: vec![bob_state.pre_keys[0].pub_key()],
    };
    let alice = alice_state();
    let chosen_opk = bob_bundle.pre_keys[0];
    let (out, x3dh_header) = get_shared_secret_active(
        &alice,
        &bob_bundle,
        b"",
        det32("alice-ek"),
        Some(chosen_opk),
        true,
    )
    .unwrap();
    let mut session = TwomemoSession::create_active(
        out.associated_data,
        out.shared_secret.to_vec(),
        bob_bundle.signed_pre_key,
        Box::new(FixedDhPrivProvider::new(vec![det32("alice-dr-1")])),
    )
    .unwrap();
    let auth_m0 = session
        .encrypt_message(b"hello bob via the helper")
        .unwrap();
    let alice_ik_pub_ed = alice.identity_key.ed25519_pub();
    build_key_exchange(
        OPK_ID,
        SPK_ID,
        alice_ik_pub_ed,
        x3dh_header.ephemeral_key,
        &auth_m0,
    )
    .unwrap()
}

fn tempdir(prefix: &str) -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("{prefix}-{stamp}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn receive_initial_message_consumes_opk_and_persists_session() {
    let dir = tempdir("recv-init");
    let mut bob = Store::open(dir.join("bob.sqlite")).unwrap();
    let bob_state = provision_bob(&mut bob);

    let kex = alice_initiates(&bob_state);

    let pt = bob
        .receive_initial_message(
            ALICE_JID,
            ALICE_DEVICE_ID,
            &kex,
            Box::new(FixedDhPrivProvider::new(vec![det32("bob-dr-1")])),
        )
        .expect("receive");
    assert_eq!(pt, b"hello bob via the helper");

    // OPK is now consumed.
    let opk = bob.get_opk(OPK_ID).unwrap().unwrap();
    assert!(opk.consumed, "OPK was consumed by the helper");

    // Session is persisted.
    let snap = bob
        .load_session_snapshot(ALICE_JID, ALICE_DEVICE_ID)
        .unwrap();
    assert!(snap.is_some(), "session row written");
}

#[test]
fn receive_initial_message_rejects_replay() {
    let dir = tempdir("recv-init-replay");
    let mut bob = Store::open(dir.join("bob.sqlite")).unwrap();
    let bob_state = provision_bob(&mut bob);
    let kex = alice_initiates(&bob_state);

    bob.receive_initial_message(
        ALICE_JID,
        ALICE_DEVICE_ID,
        &kex,
        Box::new(FixedDhPrivProvider::new(vec![det32("bob-dr-1")])),
    )
    .expect("first receive");

    // Replaying the same KEX should fail because the OPK is consumed.
    let err = bob
        .receive_initial_message(
            ALICE_JID,
            ALICE_DEVICE_ID,
            &kex,
            Box::new(FixedDhPrivProvider::new(vec![det32("bob-dr-1")])),
        )
        .expect_err("second receive should fail");
    match err {
        SessionStoreError::PreKeyAlreadyConsumed(id) => assert_eq!(id, OPK_ID),
        other => panic!("wrong error: {other:?}"),
    }
}
