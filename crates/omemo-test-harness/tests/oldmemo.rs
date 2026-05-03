//! Stage 7.2 GATE TEST — Alice initiates an OMEMO 0.3 session and
//! sends 1 KEX + 3 follow-up messages, byte-equal with python-oldmemo
//! at the wire-format level.

use omemo_oldmemo::{
    aead_decrypt, aead_encrypt, build_associated_data, build_key_exchange, fixed_priv_provider,
    parse_key_exchange, peek_dh_pub, OldmemoSession,
};
use omemo_test_harness::{fixtures_dir, hex_decode};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AliceWire {
    #[allow(dead_code)]
    ik_seed_hex: String,
    #[allow(dead_code)]
    ik_pub_ed_hex: String,
    ik_pub_curve_hex: String,
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
fn gate_oldmemo_kex_plus_three() {
    let raw = std::fs::read(fixtures_dir().join("oldmemo.json")).expect("read fixture");
    let c: Case = serde_json::from_slice(&raw).expect("parse oldmemo.json");

    // bob's SPK pub (Curve25519, raw 32B) is recoverable from his SPK priv.
    let bob_spk_priv = hex32(&c.bob.spk_priv_hex);
    let bob_spk_pub_local = omemo_xeddsa::priv_to_curve25519_pub(&bob_spk_priv);

    // ---- Alice (active).
    let alice_dr_privs: Vec<[u8; 32]> =
        c.alice.dr_priv_queue_hex.iter().map(|h| hex32(h)).collect();
    let mut alice = OldmemoSession::create_active(
        hex_decode(&c.associated_data_hex).unwrap(),
        hex_decode(&c.shared_secret_hex).unwrap(),
        bob_spk_pub_local,
        fixed_priv_provider(alice_dr_privs),
    )
    .expect("alice create_active");

    let pt0 = hex_decode(&c.plaintexts_hex[0]).unwrap();
    let auth_m0 = alice.encrypt_message(&pt0).expect("alice M0");

    // Wrap into KEX. Alice's IK is given to build_key_exchange in raw
    // 32-byte Curve25519 form (build_key_exchange applies the 0x05
    // prefix internally).
    let alice_ik_curve = hex32(&c.alice.ik_pub_curve_hex);
    let alice_ek_pub = hex32(&c.alice.ek_pub_hex);
    let kex_bytes = build_key_exchange(c.pk_id, c.spk_id, alice_ik_curve, alice_ek_pub, &auth_m0);

    let want_kex = hex_decode(&c.wire.kex0_hex).unwrap();
    assert_eq!(
        kex_bytes, want_kex,
        "KEX bytes byte-equal with python-oldmemo"
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
            got,
            &want,
            "follow-up M{} bytes byte-equal with python",
            i + 1
        );
    }

    // ---- Bob receives. Parse KEX → recover auth_msg + the X3DH ids.
    let (got_pk_id, got_spk_id, got_ik, got_ek, auth_m0_recovered) =
        parse_key_exchange(&kex_bytes).expect("parse kex");
    assert_eq!(got_pk_id, c.pk_id);
    assert_eq!(got_spk_id, c.spk_id);
    assert_eq!(got_ik, alice_ik_curve);
    assert_eq!(got_ek, alice_ek_pub);
    assert_eq!(auth_m0_recovered, auth_m0, "auth msg from KEX matches");

    // peek_dh_pub strips the 0x05 prefix from the inner OMEMOMessage.
    let alice_first_dr_pub = peek_dh_pub(&auth_m0_recovered).expect("peek dh_pub");

    let bob_dr_privs: Vec<[u8; 32]> = c.bob.dr_priv_queue_hex.iter().map(|h| hex32(h)).collect();
    let mut bob = OldmemoSession::create_passive(
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

    for (i, follow_up) in follow_ups.iter().enumerate() {
        let want_pt = hex_decode(&c.plaintexts_hex[i + 1]).unwrap();
        let got = bob
            .decrypt_message(follow_up)
            .unwrap_or_else(|_| panic!("bob decrypt follow-up M{}", i + 1));
        assert_eq!(got, want_pt, "follow-up M{} plaintext recovered", i + 1);
    }

    // Sanity: aead_encrypt / aead_decrypt round-trip with arbitrary
    // header. Pin the helper functions so accidental constant rename
    // (info string, MAC length, version byte) breaks here loudly.
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
    assert_eq!(blob[0], 0x33, "version byte present");
    let pt = aead_decrypt(&bogus_ad, &mk, &blob).expect("smoke decrypt");
    assert_eq!(pt, b"smoke");
}

#[test]
fn session_snapshot_round_trip() {
    use omemo_oldmemo::OldmemoSessionSnapshot;

    let raw = std::fs::read(fixtures_dir().join("oldmemo.json")).expect("read");
    let c: Case = serde_json::from_slice(&raw).expect("parse");

    let bob_spk_priv = hex32(&c.bob.spk_priv_hex);
    let bob_spk_pub = omemo_xeddsa::priv_to_curve25519_pub(&bob_spk_priv);

    let alice_dr_privs: Vec<[u8; 32]> =
        c.alice.dr_priv_queue_hex.iter().map(|h| hex32(h)).collect();
    let mut alice = OldmemoSession::create_active(
        hex_decode(&c.associated_data_hex).unwrap(),
        hex_decode(&c.shared_secret_hex).unwrap(),
        bob_spk_pub,
        fixed_priv_provider(alice_dr_privs.clone()),
    )
    .expect("alice");

    let pt0 = hex_decode(&c.plaintexts_hex[0]).unwrap();
    let _m0 = alice.encrypt_message(&pt0).expect("M0");
    let snap = alice.snapshot();
    let bytes = snap.encode();
    let decoded = OldmemoSessionSnapshot::decode(&bytes).expect("decode");
    assert_eq!(snap, decoded, "snapshot encode/decode is lossless");

    let remaining_privs = alice_dr_privs[1..].to_vec();
    let mut restored =
        OldmemoSession::from_snapshot(decoded, fixed_priv_provider(remaining_privs.clone()));

    let pt1 = hex_decode(&c.plaintexts_hex[1]).unwrap();
    let m1_orig = alice.encrypt_message(&pt1).expect("M1 orig");
    let m1_restored = restored.encrypt_message(&pt1).expect("M1 restored");
    assert_eq!(
        m1_orig, m1_restored,
        "restored session produces byte-identical M1"
    );

    assert_eq!(
        m1_restored,
        hex_decode(&c.wire.follow_up_hex[0]).unwrap(),
        "restored session matches python fixture"
    );
}
