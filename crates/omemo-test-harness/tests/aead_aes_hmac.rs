//! Replay AEAD (AES-256-CBC + HMAC) fixtures from python-doubleratchet's
//! `recommended.aead_aes_hmac` against `omemo-doubleratchet::aead`.

use omemo_doubleratchet::aead::{decrypt, encrypt, AeadError, HashFunction};
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    hash: String,
    info_hex: String,
    key_hex: String,
    ad_hex: String,
    plaintext_hex: String,
    ciphertext_hex: String,
}

fn pick_hash(name: &str) -> HashFunction {
    match name {
        "sha256" => HashFunction::Sha256,
        "sha512" => HashFunction::Sha512,
        other => panic!("unsupported hash: {other}"),
    }
}

#[test]
fn replay_aead_aes_hmac_fixtures() {
    let fixture = load_fixture::<Case>("aead_aes_hmac.json").expect("load");
    assert!(!fixture.cases.is_empty(), "fixture has no cases");

    for (i, c) in fixture.cases.iter().enumerate() {
        let hash = pick_hash(&c.hash);
        let info = hex_decode(&c.info_hex).unwrap();
        let key = hex_decode(&c.key_hex).unwrap();
        let ad = hex_decode(&c.ad_hex).unwrap();
        let pt = hex_decode(&c.plaintext_hex).unwrap();
        let expected = hex_decode(&c.ciphertext_hex).unwrap();

        let got = encrypt(hash, &info, &key, &ad, &pt);
        assert_eq!(
            got,
            expected,
            "case {i} ({}): encrypt mismatch\n  expected: {}\n  got:      {}",
            c.label,
            hex::encode(&expected),
            hex::encode(&got)
        );

        let recovered = decrypt(hash, &info, &key, &ad, &expected)
            .unwrap_or_else(|e| panic!("case {i} ({}): decrypt failed: {e}", c.label));
        assert_eq!(
            recovered, pt,
            "case {i} ({}): decrypt did not recover plaintext",
            c.label
        );
    }
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let fixture = load_fixture::<Case>("aead_aes_hmac.json").expect("load");
    // Pick the first case that has a non-empty plaintext so flipping a CT byte
    // is meaningful (an empty-PT case still has an HMAC tail to flip).
    let c = fixture
        .cases
        .iter()
        .find(|c| !c.plaintext_hex.is_empty())
        .expect("at least one non-empty plaintext case");

    let hash = pick_hash(&c.hash);
    let info = hex_decode(&c.info_hex).unwrap();
    let key = hex_decode(&c.key_hex).unwrap();
    let ad = hex_decode(&c.ad_hex).unwrap();
    let mut ct = hex_decode(&c.ciphertext_hex).unwrap();
    ct[0] ^= 0x01;

    match decrypt(hash, &info, &key, &ad, &ct) {
        Err(AeadError::AuthenticationFailed) => {}
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    }
}

#[test]
fn decrypt_rejects_tampered_associated_data() {
    let fixture = load_fixture::<Case>("aead_aes_hmac.json").expect("load");
    let c = fixture.cases.first().expect("at least one case");

    let hash = pick_hash(&c.hash);
    let info = hex_decode(&c.info_hex).unwrap();
    let key = hex_decode(&c.key_hex).unwrap();
    let mut ad = hex_decode(&c.ad_hex).unwrap();
    let ct = hex_decode(&c.ciphertext_hex).unwrap();
    if ad.is_empty() {
        ad.push(0x42);
    } else {
        ad[0] ^= 0x01;
    }

    match decrypt(hash, &info, &key, &ad, &ct) {
        Err(AeadError::AuthenticationFailed) => {}
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    }
}
