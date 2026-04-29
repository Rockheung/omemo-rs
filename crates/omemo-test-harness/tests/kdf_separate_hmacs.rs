//! Replay separate-HMACs KDF fixtures against `omemo-doubleratchet::kdf_separate_hmacs`.

use omemo_doubleratchet::aead::HashFunction;
use omemo_doubleratchet::kdf::Kdf;
use omemo_doubleratchet::kdf_separate_hmacs::{SeparateHmacsKdf, SeparateHmacsParams};
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    hash: String,
    key_hex: String,
    data_hex: String,
    out_len: usize,
    expected_hex: String,
}

struct Sha256Params;
impl SeparateHmacsParams for Sha256Params {
    const HASH: HashFunction = HashFunction::Sha256;
}
struct Sha512Params;
impl SeparateHmacsParams for Sha512Params {
    const HASH: HashFunction = HashFunction::Sha512;
}

fn derive(hash: &str, key: &[u8], data: &[u8], len: usize) -> Vec<u8> {
    match hash {
        "sha256" => SeparateHmacsKdf::<Sha256Params>::derive(key, data, len),
        "sha512" => SeparateHmacsKdf::<Sha512Params>::derive(key, data, len),
        other => panic!("unsupported hash: {other}"),
    }
}

#[test]
fn replay_kdf_separate_hmacs_fixtures() {
    let fixture = load_fixture::<Case>("kdf_separate_hmacs.json").expect("load");
    assert!(!fixture.cases.is_empty(), "fixture has no cases");
    for (i, c) in fixture.cases.iter().enumerate() {
        let key = hex_decode(&c.key_hex).unwrap();
        let data = hex_decode(&c.data_hex).unwrap();
        let expected = hex_decode(&c.expected_hex).unwrap();
        let got = derive(&c.hash, &key, &data, c.out_len);
        assert_eq!(
            got, expected,
            "case {i} ({}): mismatch\n  expected: {}\n  got:      {}",
            c.label,
            hex::encode(&expected),
            hex::encode(&got)
        );
    }
}
