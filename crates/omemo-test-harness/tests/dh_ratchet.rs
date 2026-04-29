//! Replay DH ratchet fixtures end-to-end against the Rust port.

use omemo_doubleratchet::aead::HashFunction;
use omemo_doubleratchet::dh_ratchet::{
    DhPrivProvider, DiffieHellmanRatchet, FixedDhPrivProvider, Header,
};
use omemo_doubleratchet::kdf_hkdf::{HkdfKdf, HkdfParams};
use omemo_doubleratchet::kdf_separate_hmacs::{SeparateHmacsKdf, SeparateHmacsParams};
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct WireHeader {
    ratchet_pub_hex: String,
    pn: u64,
    n: u64,
}

#[derive(Debug, Deserialize)]
struct WireSkipped {
    pub_hex: String,
    n: u64,
    mk_hex: String,
}

#[derive(Debug, Deserialize)]
struct WireOp {
    op: String,
    mk_hex: String,
    header: WireHeader,
    skipped: Vec<WireSkipped>,
}

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    constant_hex: String,
    root_chain_key_hex: String,
    alice_priv_queue_hex: Vec<String>,
    bob_init_priv_hex: String,
    bob_init_other_pub_hex: String,
    bob_priv_queue_hex: Vec<String>,
    bob_initial_other_pub_for_alice_hex: String,
    ops: Vec<WireOp>,
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
type RootKdf = HkdfKdf<OmemoRoot>;
type MsgKdf = SeparateHmacsKdf<OmemoMsg>;
type DR = DiffieHellmanRatchet<RootKdf, MsgKdf>;

fn hex32(s: &str) -> [u8; 32] {
    let v = hex_decode(s).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn make_provider(queue: &[String]) -> Box<dyn DhPrivProvider> {
    let privs = queue.iter().map(|h| hex32(h)).collect::<Vec<_>>();
    Box::new(FixedDhPrivProvider::new(privs))
}

fn run_case(c: &Case) {
    let constant = hex_decode(&c.constant_hex).unwrap();
    let root_key = hex_decode(&c.root_chain_key_hex).unwrap();

    let mut alice: DR = DR::create_active(
        hex32(&c.bob_initial_other_pub_for_alice_hex),
        root_key.clone(),
        constant.clone(),
        1000,
        make_provider(&c.alice_priv_queue_hex),
    )
    .expect("alice create_active");

    let mut bob: DR = DR::create_passive(
        hex32(&c.bob_init_priv_hex),
        hex32(&c.bob_init_other_pub_hex),
        root_key.clone(),
        constant.clone(),
        1000,
        make_provider(&c.bob_priv_queue_hex),
    )
    .expect("bob create_passive");

    for (i, op) in c.ops.iter().enumerate() {
        let want_mk = hex_decode(&op.mk_hex).unwrap();
        let want_pub = hex_decode(&op.header.ratchet_pub_hex).unwrap();

        let (mk, header, skipped) = match op.op.as_str() {
            "alice_enc" => {
                let (mk, h) = alice.next_encryption_key().expect("alice enc");
                (mk, h, vec![])
            }
            "bob_enc" => {
                let (mk, h) = bob.next_encryption_key().expect("bob enc");
                (mk, h, vec![])
            }
            "alice_dec" => {
                let h = Header {
                    ratchet_pub: hex32(&op.header.ratchet_pub_hex),
                    previous_sending_chain_length: op.header.pn,
                    sending_chain_length: op.header.n,
                };
                let (mk, sk) = alice.next_decryption_key(&h).expect("alice dec");
                (mk, h, sk)
            }
            "bob_dec" => {
                let h = Header {
                    ratchet_pub: hex32(&op.header.ratchet_pub_hex),
                    previous_sending_chain_length: op.header.pn,
                    sending_chain_length: op.header.n,
                };
                let (mk, sk) = bob.next_decryption_key(&h).expect("bob dec");
                (mk, h, sk)
            }
            other => panic!("unknown op: {other}"),
        };

        assert_eq!(
            mk, want_mk,
            "case {} op {i} ({}): mk mismatch",
            c.label, op.op
        );
        assert_eq!(
            header.ratchet_pub.to_vec(),
            want_pub,
            "case {} op {i} ({}): ratchet_pub mismatch",
            c.label,
            op.op
        );
        assert_eq!(
            header.previous_sending_chain_length, op.header.pn,
            "case {} op {i} ({}): pn mismatch",
            c.label, op.op
        );
        assert_eq!(
            header.sending_chain_length, op.header.n,
            "case {} op {i} ({}): n mismatch",
            c.label, op.op
        );

        // Skipped keys: order-preserving compare against fixture.
        assert_eq!(
            skipped.len(),
            op.skipped.len(),
            "case {} op {i} ({}): skipped length mismatch",
            c.label,
            op.op
        );
        for (j, (got, want)) in skipped.iter().zip(op.skipped.iter()).enumerate() {
            let want_mk = hex_decode(&want.mk_hex).unwrap();
            let want_pub = hex_decode(&want.pub_hex).unwrap();
            assert_eq!(got.0 .0.to_vec(), want_pub, "skipped[{j}] pub");
            assert_eq!(got.0 .1, want.n, "skipped[{j}] n");
            assert_eq!(got.1, want_mk, "skipped[{j}] mk");
        }
    }
}

#[test]
fn replay_dh_ratchet_fixtures() {
    let fixture = load_fixture::<Case>("dh_ratchet.json").expect("load");
    assert!(!fixture.cases.is_empty());
    for c in &fixture.cases {
        run_case(c);
    }
}
