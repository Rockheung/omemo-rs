//! Replay SymmetricKeyRatchet fixtures.

use omemo_doubleratchet::aead::HashFunction;
use omemo_doubleratchet::kdf_separate_hmacs::{SeparateHmacsKdf, SeparateHmacsParams};
use omemo_doubleratchet::symmetric_key_ratchet::{Chain, SymmetricKeyRatchet};
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
enum Op {
    #[serde(rename = "replace_send")]
    ReplaceSend {
        key_hex: String,
        send_len_after: Option<u64>,
        recv_len_after: Option<u64>,
        prev_send_len_after: Option<u64>,
    },
    #[serde(rename = "replace_recv")]
    ReplaceRecv {
        key_hex: String,
        send_len_after: Option<u64>,
        recv_len_after: Option<u64>,
        prev_send_len_after: Option<u64>,
    },
    #[serde(rename = "enc")]
    Enc {
        out_hex: String,
        send_len_after: Option<u64>,
        recv_len_after: Option<u64>,
        prev_send_len_after: Option<u64>,
    },
    #[serde(rename = "dec")]
    Dec {
        out_hex: String,
        send_len_after: Option<u64>,
        recv_len_after: Option<u64>,
        prev_send_len_after: Option<u64>,
    },
}

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    constant_hex: String,
    ops: Vec<Op>,
}

struct Sha256Params;
impl SeparateHmacsParams for Sha256Params {
    const HASH: HashFunction = HashFunction::Sha256;
}
type Kdf = SeparateHmacsKdf<Sha256Params>;

fn assert_state(
    label: &str,
    i: usize,
    skr: &SymmetricKeyRatchet<Kdf>,
    s: Option<u64>,
    r: Option<u64>,
    p: Option<u64>,
) {
    assert_eq!(skr.sending_chain_length(), s, "case {label} op {i}: send_len");
    assert_eq!(skr.receiving_chain_length(), r, "case {label} op {i}: recv_len");
    assert_eq!(
        skr.previous_sending_chain_length(),
        p,
        "case {label} op {i}: prev_send_len"
    );
}

#[test]
fn replay_symmetric_key_ratchet_fixtures() {
    let fixture = load_fixture::<Case>("symmetric_key_ratchet.json").expect("load");
    assert!(!fixture.cases.is_empty());
    for c in &fixture.cases {
        let constant = hex_decode(&c.constant_hex).unwrap();
        let mut skr: SymmetricKeyRatchet<Kdf> = SymmetricKeyRatchet::new(constant);
        for (i, op) in c.ops.iter().enumerate() {
            match op {
                Op::ReplaceSend {
                    key_hex,
                    send_len_after: s,
                    recv_len_after: r,
                    prev_send_len_after: p,
                } => {
                    let key = hex_decode(key_hex).unwrap();
                    skr.replace_chain(Chain::Sending, key).unwrap();
                    assert_state(&c.label, i, &skr, *s, *r, *p);
                }
                Op::ReplaceRecv {
                    key_hex,
                    send_len_after: s,
                    recv_len_after: r,
                    prev_send_len_after: p,
                } => {
                    let key = hex_decode(key_hex).unwrap();
                    skr.replace_chain(Chain::Receiving, key).unwrap();
                    assert_state(&c.label, i, &skr, *s, *r, *p);
                }
                Op::Enc {
                    out_hex,
                    send_len_after: s,
                    recv_len_after: r,
                    prev_send_len_after: p,
                } => {
                    let want = hex_decode(out_hex).unwrap();
                    let got = skr.next_encryption_key().unwrap();
                    assert_eq!(got, want, "case {} op {i}: enc out", c.label);
                    assert_state(&c.label, i, &skr, *s, *r, *p);
                }
                Op::Dec {
                    out_hex,
                    send_len_after: s,
                    recv_len_after: r,
                    prev_send_len_after: p,
                } => {
                    let want = hex_decode(out_hex).unwrap();
                    let got = skr.next_decryption_key().unwrap();
                    assert_eq!(got, want, "case {} op {i}: dec out", c.label);
                    assert_state(&c.label, i, &skr, *s, *r, *p);
                }
            }
        }
    }
}
