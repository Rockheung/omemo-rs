//! Replay XEdDSA fixtures from python-xeddsa against the Rust port.

use omemo_test_harness::{hex_decode, load_fixture};
use omemo_xeddsa as xed;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    ed_seed_hex: String,
    priv_hex: String,
    msg_hex: String,
    nonce_hex: String,

    seed_to_priv_hex: String,
    seed_to_ed_pub_hex: String,
    priv_to_curve_pub_hex: String,
    priv_to_ed_pub_hex: String,
    priv_force_sign_false_hex: String,
    priv_force_sign_true_hex: String,
    curve_pub_hex: String,
    curve_to_ed_sign0_hex: String,
    curve_to_ed_sign1_hex: String,
    ed_to_curve_hex: String,
    ed25519_seed_sig_hex: String,
    xeddsa_priv_sig_hex: String,
    peer_priv_hex: String,
    peer_curve_pub_hex: String,
    x25519_shared_hex: String,
}

fn arr32(s: &str) -> [u8; 32] {
    let v = hex_decode(s).unwrap();
    v.try_into().expect("32 bytes")
}
fn arr64(s: &str) -> [u8; 64] {
    let v = hex_decode(s).unwrap();
    v.try_into().expect("64 bytes")
}

#[derive(Default)]
struct Failures(Vec<String>);
impl Failures {
    fn check(&mut self, label: &str, name: &str, got: Vec<u8>, expected_hex: &str) {
        let exp = hex_decode(expected_hex).unwrap();
        if got != exp {
            self.0.push(format!(
                "[{label}] {name}: mismatch\n  expected: {}\n  got:      {}",
                expected_hex,
                hex::encode(&got)
            ));
        }
    }
}

#[test]
fn replay_xeddsa_fixtures() {
    let fixture = load_fixture::<Case>("xeddsa.json").expect("load");
    assert!(!fixture.cases.is_empty());
    let mut f = Failures::default();

    for c in &fixture.cases {
        let ed_seed = arr32(&c.ed_seed_hex);
        let priv_ = arr32(&c.priv_hex);
        let msg = hex_decode(&c.msg_hex).unwrap();
        let nonce = arr64(&c.nonce_hex);
        let peer_priv = arr32(&c.peer_priv_hex);
        let peer_curve_pub = arr32(&c.peer_curve_pub_hex);

        f.check(&c.label, "seed_to_priv",
            xed::seed_to_priv(&ed_seed).to_vec(), &c.seed_to_priv_hex);
        f.check(&c.label, "seed_to_ed25519_pub",
            xed::seed_to_ed25519_pub(&ed_seed).to_vec(), &c.seed_to_ed_pub_hex);
        f.check(&c.label, "priv_to_curve25519_pub",
            xed::priv_to_curve25519_pub(&priv_).to_vec(), &c.priv_to_curve_pub_hex);
        f.check(&c.label, "priv_to_ed25519_pub",
            xed::priv_to_ed25519_pub(&priv_).to_vec(), &c.priv_to_ed_pub_hex);
        f.check(&c.label, "priv_force_sign(false)",
            xed::priv_force_sign(&priv_, false).to_vec(), &c.priv_force_sign_false_hex);
        f.check(&c.label, "priv_force_sign(true)",
            xed::priv_force_sign(&priv_, true).to_vec(), &c.priv_force_sign_true_hex);

        let curve_pub = arr32(&c.curve_pub_hex);
        f.check(&c.label, "curve→ed (sign=0)",
            xed::curve25519_pub_to_ed25519_pub(&curve_pub, false).to_vec(), &c.curve_to_ed_sign0_hex);
        f.check(&c.label, "curve→ed (sign=1)",
            xed::curve25519_pub_to_ed25519_pub(&curve_pub, true).to_vec(), &c.curve_to_ed_sign1_hex);

        let ed_pub = arr32(&c.priv_to_ed_pub_hex);
        let ed_to_curve = xed::ed25519_pub_to_curve25519_pub(&ed_pub).expect("decompress");
        f.check(&c.label, "ed→curve",
            ed_to_curve.to_vec(), &c.ed_to_curve_hex);

        f.check(&c.label, "ed25519_seed_sign",
            xed::ed25519_seed_sign(&ed_seed, &msg).to_vec(), &c.ed25519_seed_sig_hex);

        f.check(&c.label, "ed25519_priv_sign (XEdDSA)",
            xed::ed25519_priv_sign(&priv_, &msg, &nonce).to_vec(), &c.xeddsa_priv_sig_hex);

        let x25519 = xed::x25519(&priv_, &peer_curve_pub).expect("x25519");
        f.check(&c.label, "x25519",
            x25519.to_vec(), &c.x25519_shared_hex);

        // Sanity: both parties derive same shared secret
        let priv_curve_pub = xed::priv_to_curve25519_pub(&priv_);
        let alt = xed::x25519(&peer_priv, &priv_curve_pub).expect("x25519 reverse");
        assert_eq!(alt, x25519, "[{}] DH symmetry", c.label);
    }

    if !f.0.is_empty() {
        panic!("xeddsa replay failures ({} of {} primitives × {} cases):\n{}",
               f.0.len(), 13, fixture.cases.len(), f.0.join("\n"));
    }
}
