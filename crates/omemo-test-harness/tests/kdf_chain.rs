//! Replay KDFChain fixtures from python-doubleratchet against Rust port.

use omemo_doubleratchet::aead::HashFunction;
use omemo_doubleratchet::kdf_chain::KdfChain;
use omemo_doubleratchet::kdf_hkdf::{HkdfKdf, HkdfParams};
use omemo_doubleratchet::kdf_separate_hmacs::{SeparateHmacsKdf, SeparateHmacsParams};
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Step {
    data_hex: String,
    length: usize,
    out_hex: String,
    key_after_hex: String,
    length_after: u64,
}

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    kind: String,
    #[serde(default)]
    info_hex: String,
    hash: String,
    key_hex: String,
    steps: Vec<Step>,
}

struct OmemoRoot;
impl HkdfParams for OmemoRoot {
    const HASH: HashFunction = HashFunction::Sha256;
    const INFO: &'static [u8] = b"OMEMO Root Chain";
}
struct OmemoMsg;
impl SeparateHmacsParams for OmemoMsg {
    const HASH: HashFunction = HashFunction::Sha256;
}

fn run_case(case: &Case) {
    assert_eq!(
        case.hash, "sha256",
        "case {}: only sha256 covered",
        case.label
    );
    let initial = hex_decode(&case.key_hex).unwrap();
    match case.kind.as_str() {
        "hkdf-root" => {
            assert_eq!(
                hex_decode(&case.info_hex).unwrap(),
                b"OMEMO Root Chain".to_vec(),
                "case {}: info mismatch — only OMEMO Root Chain covered",
                case.label
            );
            let mut chain: KdfChain<HkdfKdf<OmemoRoot>> = KdfChain::new(initial);
            replay_steps(
                &case.label,
                &mut chain,
                &case.steps,
                |c| c.key().to_vec(),
                |c| c.length(),
            );
        }
        "separate-hmacs-msg" => {
            let mut chain: KdfChain<SeparateHmacsKdf<OmemoMsg>> = KdfChain::new(initial);
            replay_steps(
                &case.label,
                &mut chain,
                &case.steps,
                |c| c.key().to_vec(),
                |c| c.length(),
            );
        }
        other => panic!("unknown kind: {other}"),
    }
}

fn replay_steps<C>(
    label: &str,
    chain: &mut C,
    steps: &[Step],
    key_of: impl Fn(&C) -> Vec<u8>,
    len_of: impl Fn(&C) -> u64,
) where
    C: StepChain,
{
    for (i, s) in steps.iter().enumerate() {
        let data = hex_decode(&s.data_hex).unwrap();
        let want_out = hex_decode(&s.out_hex).unwrap();
        let want_key = hex_decode(&s.key_after_hex).unwrap();
        let got = chain.step(&data, s.length);
        assert_eq!(
            got,
            want_out,
            "case {label} step {i}: out mismatch\n  want: {}\n  got:  {}",
            hex::encode(&want_out),
            hex::encode(&got)
        );
        assert_eq!(
            key_of(chain),
            want_key,
            "case {label} step {i}: key-after mismatch"
        );
        assert_eq!(
            len_of(chain),
            s.length_after,
            "case {label} step {i}: length-after mismatch"
        );
    }
}

trait StepChain {
    fn step(&mut self, data: &[u8], length: usize) -> Vec<u8>;
}

impl<K: omemo_doubleratchet::kdf::Kdf> StepChain for KdfChain<K> {
    fn step(&mut self, data: &[u8], length: usize) -> Vec<u8> {
        KdfChain::step(self, data, length)
    }
}

#[test]
fn replay_kdf_chain_fixtures() {
    let fixture = load_fixture::<Case>("kdf_chain.json").expect("load");
    assert!(!fixture.cases.is_empty());
    for c in &fixture.cases {
        run_case(c);
    }
}
