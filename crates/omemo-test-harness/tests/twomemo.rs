//! Stage 1.4 GATE TEST — Alice initiates a session and sends 1 KEX +
//! 3 follow-up messages, byte-equal with python-twomemo at the protobuf
//! wire-format level.

use omemo_twomemo::{
    aead_decrypt, aead_encrypt, build_associated_data, build_key_exchange,
    fixed_priv_provider, parse_key_exchange, OmemoAuthenticatedMessage, OmemoMessage,
    TwomemoSession,
};
use omemo_test_harness::{fixtures_dir, hex_decode};
use prost::Message as _;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AliceWire {
    #[allow(dead_code)]
    ik_seed_hex: String,
    #[allow(dead_code)]
    ik_pub_ed_hex: String,
    #[allow(dead_code)]
    ek_priv_hex: String,
    ek_pub_hex: String,
    dr_priv_queue_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BobWire {
    spk_priv_hex: String,
    #[allow(dead_code)]
    spk_pub_hex: String,
    #[allow(dead_code)]
    opk_priv_hex: String,
    #[allow(dead_code)]
    opk_pub_hex: String,
    dr_priv_queue_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WireBytes {
    kex0_hex: String,
    follow_up_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    shared_secret_hex: String,
    associated_data_hex: String,
    spk_id: u32,
    pk_id: u32,
    alice: AliceWire,
    bob: BobWire,
    wire: WireBytes,
    plaintexts_hex: Vec<String>,
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex_decode(s).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

#[test]
fn gate_twomemo_kex_plus_three() {
    // Stage-1.4 fixture is a single root-level object (no `cases` array),
    // so we read it directly rather than going through `load_fixture`.
    let raw = std::fs::read(fixtures_dir().join("twomemo.json")).expect("read fixture");
    let c: Case = serde_json::from_slice(&raw).expect("parse twomemo.json");

    // Derive bob's SPK pub for active.
    let bob_spk_priv = hex32(&c.bob.spk_priv_hex);
    let bob_spk_pub_local = omemo_xeddsa::priv_to_curve25519_pub(&bob_spk_priv);

    // ---- Alice (active).
    let alice_dr_privs: Vec<[u8; 32]> = c
        .alice
        .dr_priv_queue_hex
        .iter()
        .map(|h| hex32(h))
        .collect();
    let mut alice = TwomemoSession::create_active(
        hex_decode(&c.associated_data_hex).unwrap(),
        hex_decode(&c.shared_secret_hex).unwrap(),
        bob_spk_pub_local,
        fixed_priv_provider(alice_dr_privs),
    )
    .expect("alice create_active");

    let pt0 = hex_decode(&c.plaintexts_hex[0]).unwrap();
    let auth_m0 = alice.encrypt_message(&pt0).expect("alice M0");

    // Wrap into KEX. Alice's IK Ed25519 pub is recoverable from the seed.
    let alice_ik_pub_ed = omemo_xeddsa::seed_to_ed25519_pub(&hex32(&c.alice.ik_seed_hex));
    let alice_ek_pub = hex32(&c.alice.ek_pub_hex);
    let kex_bytes =
        build_key_exchange(c.pk_id, c.spk_id, alice_ik_pub_ed, alice_ek_pub, &auth_m0).expect("kex");

    // Byte-equal with python.
    let want_kex = hex_decode(&c.wire.kex0_hex).unwrap();
    assert_eq!(
        kex_bytes, want_kex,
        "KEX bytes byte-equal with python-twomemo"
    );

    // 3 follow-ups.
    let mut follow_ups = Vec::new();
    for i in 1..=3 {
        let pt = hex_decode(&c.plaintexts_hex[i]).unwrap();
        let auth = alice.encrypt_message(&pt).expect("alice follow-up");
        follow_ups.push(auth);
    }
    for (i, (got, want_hex)) in follow_ups
        .iter()
        .zip(c.wire.follow_up_hex.iter())
        .enumerate()
    {
        let want = hex_decode(want_hex).unwrap();
        assert_eq!(
            got, &want,
            "follow-up M{} bytes byte-equal with python",
            i + 1
        );
    }

    // ---- Bob receives. First parse KEX → auth_msg + needed ids.
    let (got_pk_id, got_spk_id, got_ik, got_ek, auth_m0_recovered) =
        parse_key_exchange(&kex_bytes).expect("parse kex");
    assert_eq!(got_pk_id, c.pk_id);
    assert_eq!(got_spk_id, c.spk_id);
    assert_eq!(got_ik, alice_ik_pub_ed);
    assert_eq!(got_ek, alice_ek_pub);
    assert_eq!(auth_m0_recovered, auth_m0, "auth msg from KEX matches");

    // Bob initiates passive session: derives DR root from shared secret
    // (same as alice's), uses his SPK priv as own_ratchet_priv, and uses
    // alice's first ratchet pub from the inner OMEMOMessage (auth_msg).
    let auth = OmemoAuthenticatedMessage::decode(auth_m0_recovered.as_slice())
        .expect("auth decode");
    let inner = OmemoMessage::decode(auth.message.as_slice()).expect("inner decode");
    let alice_first_dr_pub = {
        let mut p = [0u8; 32];
        p.copy_from_slice(&inner.dh_pub);
        p
    };

    let bob_dr_privs: Vec<[u8; 32]> = c
        .bob
        .dr_priv_queue_hex
        .iter()
        .map(|h| hex32(h))
        .collect();
    let mut bob = TwomemoSession::create_passive(
        hex_decode(&c.associated_data_hex).unwrap(),
        hex_decode(&c.shared_secret_hex).unwrap(),
        bob_spk_priv,
        alice_first_dr_pub,
        fixed_priv_provider(bob_dr_privs),
    )
    .expect("bob create_passive");

    let m0_pt = bob
        .decrypt_message(&auth_m0_recovered)
        .expect("bob decrypt M0");
    assert_eq!(m0_pt, pt0, "M0 plaintext recovered");

    for i in 0..3 {
        let want_pt = hex_decode(&c.plaintexts_hex[i + 1]).unwrap();
        let got = bob
            .decrypt_message(&follow_ups[i])
            .expect(&format!("bob decrypt follow-up M{}", i + 1));
        assert_eq!(got, want_pt, "follow-up M{} plaintext recovered", i + 1);
    }

    // Sanity: aead_encrypt / aead_decrypt round-trips against the same DR
    // header (covered by the higher-level path above; this is an extra sanity
    // pin that the helper functions are wired correctly).
    let bogus_ad = build_associated_data(
        &hex_decode(&c.associated_data_hex).unwrap(),
        &omemo_doubleratchet::dh_ratchet::Header {
            ratchet_pub: [0xAB; 32],
            previous_sending_chain_length: 1,
            sending_chain_length: 2,
        },
    );
    let mk = [0xCD; 32];
    let blob = aead_encrypt(&bogus_ad, &mk, b"smoke");
    let pt = aead_decrypt(&bogus_ad, &mk, &blob).expect("smoke decrypt");
    assert_eq!(pt, b"smoke");
}

#[test]
fn session_snapshot_round_trip() {
    use omemo_twomemo::TwomemoSessionSnapshot;

    let raw = std::fs::read(fixtures_dir().join("twomemo.json")).expect("read");
    let c: Case = serde_json::from_slice(&raw).expect("parse");

    let bob_spk_priv = hex32(&c.bob.spk_priv_hex);
    let bob_spk_pub = omemo_xeddsa::priv_to_curve25519_pub(&bob_spk_priv);

    let alice_dr_privs: Vec<[u8; 32]> = c
        .alice
        .dr_priv_queue_hex
        .iter()
        .map(|h| hex32(h))
        .collect();
    let mut alice = TwomemoSession::create_active(
        hex_decode(&c.associated_data_hex).unwrap(),
        hex_decode(&c.shared_secret_hex).unwrap(),
        bob_spk_pub,
        fixed_priv_provider(alice_dr_privs.clone()),
    )
    .expect("alice");

    // Send M0, snapshot the post-encrypt state.
    let pt0 = hex_decode(&c.plaintexts_hex[0]).unwrap();
    let m0 = alice.encrypt_message(&pt0).expect("M0");
    let snap = alice.snapshot();
    let bytes = snap.encode();
    let decoded = TwomemoSessionSnapshot::decode(&bytes).expect("decode");
    assert_eq!(snap, decoded, "snapshot encode/decode is lossless");

    // Restore. The remaining priv queue starts from where the original
    // session left off.
    let remaining_privs = alice_dr_privs[1..].to_vec();
    let mut restored = TwomemoSession::from_snapshot(
        decoded,
        fixed_priv_provider(remaining_privs.clone()),
    );

    // Continuation: encrypting M1 from the restored session must produce
    // the same wire bytes as encrypting M1 from the original session.
    let pt1 = hex_decode(&c.plaintexts_hex[1]).unwrap();
    let m1_orig = alice.encrypt_message(&pt1).expect("M1 orig");
    let m1_restored = restored.encrypt_message(&pt1).expect("M1 restored");
    assert_eq!(
        m1_orig, m1_restored,
        "restored session produces byte-identical M1"
    );

    // Also matches the python-recorded fixture bytes.
    assert_eq!(
        m1_restored,
        hex_decode(&c.wire.follow_up_hex[0]).unwrap(),
        "restored session matches python fixture"
    );

    // Drop M0 to silence the unused warning while making it clear this is
    // the same wire we'd recover from.
    drop(m0);
}
