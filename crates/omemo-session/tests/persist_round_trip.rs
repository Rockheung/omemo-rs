//! Stage 3 GATE TEST: identity + bundle gen + 1:1 session round-trip +
//! reopen DB → session continues without re-keying.
//!
//! Scenario:
//! 1. Open a fresh on-disk SQLite store at a temp path.
//! 2. Persist Alice's identity + a generated SPK + 1 OPK.
//! 3. Bring up Bob's identity in a separate store.
//! 4. Run an active/passive X3DH between them.
//! 5. Alice creates a `TwomemoSession`, encrypts M0 + M1, persists the
//!    session BLOB after each, decrypts (Bob side) M0+M1, persists Bob.
//! 6. Drop both `Store` handles (simulating a process restart).
//! 7. Re-open both stores from the same paths.
//! 8. Restore both sessions from BLOB.
//! 9. Alice sends M2 from the restored session; Bob decrypts from his
//!    restored session — works without re-running X3DH.
//!
//! All keys deterministic via `omemo_xeddsa::seed_to_priv` etc.; the
//! priv-provider for the DH ratchet uses pre-staged queues so each
//! restart can hand a continuation queue.

use std::path::PathBuf;

use omemo_doubleratchet::dh_ratchet::FixedDhPrivProvider;
use omemo_session::{Store, StoredOpk, StoredSpk};
use omemo_twomemo::{parse_key_exchange, TwomemoSession, TwomemoSessionSnapshot};
use omemo_x3dh::{
    get_shared_secret_active, get_shared_secret_passive, Bundle as X3dhBundle,
    Header as X3dhHeader, IdentityKeyPair, PreKeyPair, SignedPreKeyPair, X3dhState,
};

fn det(label: &str, length: usize) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 0;
    while out.len() < length {
        let mut h = Sha512::new();
        h.update(b"stage3-fixture");
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
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn det64(label: &str) -> [u8; 64] {
    let v = det(label, 64);
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

const ALICE_JID: &str = "alice@example.org";
const BOB_JID: &str = "bob@example.org";
const ALICE_DEVICE_ID: u32 = 1001;
const BOB_DEVICE_ID: u32 = 2002;
const SPK_ID: u32 = 1;
const OPK_ID: u32 = 100;

/// Provision a Store with identity + 1 SPK + 1 OPK.
fn provision(store: &mut Store, jid: &str, device_id: u32, prefix: &str) -> X3dhState {
    let ik_seed = det32(&format!("{prefix}-ik"));
    store
        .put_identity(jid, device_id, &ik_seed)
        .expect("put_identity");

    let spk_priv = det32(&format!("{prefix}-spk-priv"));
    let spk_nonce = det64(&format!("{prefix}-spk-nonce"));
    let ik = IdentityKeyPair::Seed(ik_seed);
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
        .expect("put_spk");

    let opk_priv = det32(&format!("{prefix}-opk-priv"));
    let opk = PreKeyPair { priv_key: opk_priv };
    store
        .put_opk(&StoredOpk {
            id: OPK_ID,
            priv_key: opk.priv_key,
            pub_key: opk.pub_key(),
            consumed: false,
            created_at: 1234567890,
        })
        .expect("put_opk");

    X3dhState {
        identity_key: ik,
        signed_pre_key: spk,
        old_signed_pre_key: None,
        pre_keys: vec![opk],
    }
}

#[test]
fn gate_persist_and_continue_session() {
    let dir = tempdir_under_target("stage3");
    let alice_db = dir.join("alice.sqlite");
    let bob_db = dir.join("bob.sqlite");

    // Pre-stage DR priv queues so both sessions remain deterministic
    // across the restart. Alice generates 1 priv on active create + 1 on
    // first DH ratchet step on receive (which won't fire here since Alice
    // only sends in this scenario). Bob generates 1 priv inside passive
    // create + 1 on ratchet step from M2 (whose ratchet pub differs from
    // Alice's M0 pub iff she rotates — she doesn't here). Stage 3 worst
    // case is "long send-only with persist between each", so we stage
    // generously and rely on the priv provider being unused after init.
    let alice_dr_privs = vec![det32("alice-dr-1"), det32("alice-dr-2")];
    let bob_dr_privs = vec![det32("bob-dr-1"), det32("bob-dr-2")];

    // ============ Phase 1: provision + run active/passive X3DH ============
    let mut alice_store = Store::open(&alice_db).expect("open alice");
    let mut bob_store = Store::open(&bob_db).expect("open bob");
    let alice_state = provision(&mut alice_store, ALICE_JID, ALICE_DEVICE_ID, "alice");
    let bob_state = provision(&mut bob_store, BOB_JID, BOB_DEVICE_ID, "bob");

    // Alice fetches Bob's bundle (in real use this comes off PEP).
    let bob_bundle = X3dhBundle {
        identity_key: bob_state.identity_key.ed25519_pub(),
        signed_pre_key: bob_state.signed_pre_key.pub_key(),
        signed_pre_key_sig: bob_state.signed_pre_key.sig,
        pre_keys: vec![bob_state.pre_keys[0].pub_key()],
    };

    // Active X3DH (Alice).
    let ek_priv = det32("ek");
    let chosen_opk = bob_bundle.pre_keys[0];
    let (alice_x3dh, alice_x3dh_header) = get_shared_secret_active(
        &alice_state,
        &bob_bundle,
        b"",
        ek_priv,
        Some(chosen_opk),
        true,
    )
    .expect("active");

    // Passive X3DH (Bob).
    let (bob_x3dh, _used_spk) =
        get_shared_secret_passive(&bob_state, &alice_x3dh_header, b"", true).expect("passive");

    // Mark Bob's OPK consumed.
    assert!(
        bob_store.consume_opk(OPK_ID).expect("consume_opk"),
        "OPK was consumed"
    );

    assert_eq!(alice_x3dh.shared_secret, bob_x3dh.shared_secret);

    // ============ Phase 2: build + run + persist sessions ================
    let mut alice = TwomemoSession::create_active(
        alice_x3dh.associated_data.clone(),
        alice_x3dh.shared_secret.to_vec(),
        bob_bundle.signed_pre_key,
        Box::new(FixedDhPrivProvider::new(alice_dr_privs.clone())),
    )
    .expect("alice session");

    // Alice sends M0 (her first DH-rachet pub determines Bob's other_pub).
    let m0 = alice
        .encrypt_message(b"hello bob from alice")
        .expect("encrypt M0");
    alice_store
        .save_session(BOB_JID, BOB_DEVICE_ID, &alice)
        .expect("save alice session");

    // Bob bootstraps from M0 (peeks header to discover Alice's DH pub).
    let alice_first_dh_pub = peek_dh_pub(&m0);

    let mut bob = TwomemoSession::create_passive(
        bob_x3dh.associated_data.clone(),
        bob_x3dh.shared_secret.to_vec(),
        bob_state.signed_pre_key.priv_key,
        alice_first_dh_pub,
        Box::new(FixedDhPrivProvider::new(bob_dr_privs.clone())),
    )
    .expect("bob session");

    let pt0 = bob.decrypt_message(&m0).expect("bob M0");
    assert_eq!(pt0, b"hello bob from alice");
    bob_store
        .save_session(ALICE_JID, ALICE_DEVICE_ID, &bob)
        .expect("save bob session");

    // Alice → Bob M1.
    let m1 = alice.encrypt_message(b"second one").expect("M1");
    alice_store
        .save_session(BOB_JID, BOB_DEVICE_ID, &alice)
        .expect("alice save");
    let pt1 = bob.decrypt_message(&m1).expect("bob M1");
    assert_eq!(pt1, b"second one");
    bob_store
        .save_session(ALICE_JID, ALICE_DEVICE_ID, &bob)
        .expect("bob save");

    // ============ Phase 3: simulate restart ==============================
    drop(alice);
    drop(bob);
    drop(alice_store);
    drop(bob_store);

    let alice_store = Store::open(&alice_db).expect("reopen alice");
    let bob_store = Store::open(&bob_db).expect("reopen bob");

    // Identity + bundle facts persist.
    let alice_id = alice_store
        .get_identity()
        .expect("alice id")
        .expect("present");
    assert_eq!(alice_id.bare_jid, ALICE_JID);
    assert_eq!(alice_id.device_id, ALICE_DEVICE_ID);

    let alice_spk = alice_store
        .current_spk()
        .expect("alice spk")
        .expect("present");
    assert_eq!(alice_spk.id, SPK_ID);

    // OPK consumed-once flag persists.
    let bob_opk = bob_store.get_opk(OPK_ID).expect("opk").expect("present");
    assert!(
        bob_opk.consumed,
        "OPK consumed flag persisted across restart"
    );

    // ============ Phase 4: restore sessions + send M2 ====================
    // The DH priv queues for the restored sessions hand the *remaining*
    // privs (post-init both sessions consumed 1 priv).
    let alice_snap: TwomemoSessionSnapshot = alice_store
        .load_session_snapshot(BOB_JID, BOB_DEVICE_ID)
        .expect("load alice snap")
        .expect("alice session present");
    let bob_snap = bob_store
        .load_session_snapshot(ALICE_JID, ALICE_DEVICE_ID)
        .expect("load bob snap")
        .expect("bob session present");

    let mut alice = TwomemoSession::from_snapshot(
        alice_snap,
        Box::new(FixedDhPrivProvider::new(alice_dr_privs[1..].to_vec())),
    );
    let mut bob = TwomemoSession::from_snapshot(
        bob_snap,
        Box::new(FixedDhPrivProvider::new(bob_dr_privs[1..].to_vec())),
    );

    let m2 = alice
        .encrypt_message(b"after restart")
        .expect("M2 after restart");
    let pt2 = bob.decrypt_message(&m2).expect("bob M2 after restart");
    assert_eq!(
        pt2, b"after restart",
        "session continues across restart without re-keying"
    );
}

/// Tiny helper: read the `dh_pub` field from an OMEMOAuthenticatedMessage
/// → OMEMOMessage. Mirrors what `TwomemoSession::create_passive` needs to
/// be told.
fn peek_dh_pub(auth_msg_bytes: &[u8]) -> [u8; 32] {
    use prost::Message as _;
    let kex_or_auth =
        omemo_twomemo::OmemoAuthenticatedMessage::decode(auth_msg_bytes).expect("peek auth");
    let inner =
        omemo_twomemo::OmemoMessage::decode(kex_or_auth.message.as_slice()).expect("peek inner");
    let mut p = [0u8; 32];
    p.copy_from_slice(&inner.dh_pub);
    p
}

fn tempdir_under_target(prefix: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("{prefix}-{stamp}"));
    std::fs::create_dir_all(&p).expect("mkdir");
    p
}

// Workaround: parse_key_exchange isn't used here directly but we keep the
// import so the compiler doesn't strip the dependency. (No-op closure.)
#[allow(dead_code)]
fn _keep_imports() {
    let _ = parse_key_exchange;
    let _: X3dhHeader = X3dhHeader {
        identity_key: [0; 32],
        ephemeral_key: [0; 32],
        signed_pre_key: [0; 32],
        pre_key: None,
    };
}
