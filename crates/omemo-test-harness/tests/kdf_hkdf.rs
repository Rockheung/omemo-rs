//! Replay HKDF fixtures from python-doubleratchet against the Rust `hkdf` crate.
//! Mapping: case.key → HKDF salt, case.data → HKDF IKM, case.info → HKDF info.

use hkdf::Hkdf;
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;
use sha2::{Sha256, Sha512};

#[derive(Debug, Deserialize)]
struct Case {
    hash: String,
    info_hex: String,
    key_hex: String,
    data_hex: String,
    out_len: usize,
    expected_hex: String,
}

fn derive(hash: &str, salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    match hash {
        "sha256" => {
            Hkdf::<Sha256>::new(Some(salt), ikm)
                .expand(info, &mut out)
                .expect("expand sha256");
        }
        "sha512" => {
            Hkdf::<Sha512>::new(Some(salt), ikm)
                .expand(info, &mut out)
                .expect("expand sha512");
        }
        other => panic!("unsupported hash: {other}"),
    }
    out
}

#[test]
fn replay_kdf_hkdf_fixtures() {
    let fixture = load_fixture::<Case>("kdf_hkdf.json").expect("load");
    assert!(!fixture.cases.is_empty(), "fixture has no cases");
    for (i, c) in fixture.cases.iter().enumerate() {
        let info = hex_decode(&c.info_hex).unwrap();
        let salt = hex_decode(&c.key_hex).unwrap();
        let ikm = hex_decode(&c.data_hex).unwrap();
        let expected = hex_decode(&c.expected_hex).unwrap();
        let got = derive(&c.hash, &salt, &ikm, &info, c.out_len);
        assert_eq!(
            got, expected,
            "case {i} ({}): mismatch\n  expected: {}\n  got:      {}",
            c.hash,
            hex::encode(&expected),
            hex::encode(&got)
        );
    }
}
