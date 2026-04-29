//! Replay X3DH fixtures against `omemo-x3dh`. Stage 1.3 GATE TEST.
//!
//! Each case independently builds Alice's and Bob's deterministic states,
//! runs `get_shared_secret_active` on Alice's side, then `get_shared_secret_passive`
//! on Bob's side, asserting both produce the same shared secret + AD that
//! python-x3dh produced.

use omemo_x3dh::{
    get_shared_secret_active, get_shared_secret_passive, Bundle, Header, IdentityKeyPair,
    PreKeyPair, SignedPreKeyPair, X3dhState,
};
use omemo_test_harness::{hex_decode, load_fixture};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AliceFixture {
    ik_seed_hex: String,
    spk_priv_hex: String,
    spk_nonce_hex: String,
    #[allow(dead_code)]
    ik_pub_ed_hex: String,
}

#[derive(Debug, Deserialize)]
struct BobBundleFixture {
    ik_pub_hex: String,
    spk_pub_hex: String,
    spk_sig_hex: String,
    opks_pub_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BobFixture {
    ik_seed_hex: String,
    spk_priv_hex: String,
    spk_nonce_hex: String,
    opk_privs_hex: Vec<String>,
    bundle: BobBundleFixture,
}

#[derive(Debug, Deserialize)]
struct HeaderFixture {
    ik_hex: String,
    ek_hex: String,
    spk_hex: String,
    opk_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    associated_data_appendix_hex: String,
    ephemeral_priv_hex: String,
    use_pre_key: bool,
    require_pre_key: bool,
    alice: AliceFixture,
    bob: BobFixture,
    header: HeaderFixture,
    shared_secret_hex: String,
    associated_data_hex: String,
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex_decode(s).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hex64(s: &str) -> [u8; 64] {
    let v = hex_decode(s).unwrap();
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

fn build_state(ik_seed_hex: &str, spk_priv_hex: &str, spk_nonce_hex: &str, opk_privs_hex: &[String]) -> X3dhState {
    let ik = IdentityKeyPair::Seed(hex32(ik_seed_hex));
    let spk = SignedPreKeyPair::create(&ik, hex32(spk_priv_hex), hex64(spk_nonce_hex), 1234567890);
    let opks = opk_privs_hex
        .iter()
        .map(|h| PreKeyPair {
            priv_key: hex32(h),
        })
        .collect();
    X3dhState {
        identity_key: ik,
        signed_pre_key: spk,
        old_signed_pre_key: None,
        pre_keys: opks,
    }
}

fn run_case(c: &Case) {
    let alice = build_state(&c.alice.ik_seed_hex, &c.alice.spk_priv_hex, &c.alice.spk_nonce_hex, &[]);
    let bob = build_state(
        &c.bob.ik_seed_hex,
        &c.bob.spk_priv_hex,
        &c.bob.spk_nonce_hex,
        &c.bob.opk_privs_hex,
    );

    let bob_bundle_actual = bob.bundle();

    // Sanity: the bundle we built equals the one python published (same
    // sort by OPK pub hex).
    let mut opks_sorted = bob_bundle_actual.pre_keys.clone();
    opks_sorted.sort_by_key(|p| hex::encode(p));
    let want_opks: Vec<[u8; 32]> = c
        .bob
        .bundle
        .opks_pub_hex
        .iter()
        .map(|h| hex32(h))
        .collect();
    assert_eq!(opks_sorted, want_opks, "case {}: OPK set mismatch", c.label);
    assert_eq!(
        bob_bundle_actual.identity_key,
        hex32(&c.bob.bundle.ik_pub_hex),
        "case {}: IK pub mismatch",
        c.label
    );
    assert_eq!(
        bob_bundle_actual.signed_pre_key,
        hex32(&c.bob.bundle.spk_pub_hex),
        "case {}: SPK pub mismatch",
        c.label
    );
    assert_eq!(
        bob_bundle_actual.signed_pre_key_sig.to_vec(),
        hex_decode(&c.bob.bundle.spk_sig_hex).unwrap(),
        "case {}: SPK sig mismatch",
        c.label
    );

    let appendix = hex_decode(&c.associated_data_appendix_hex).unwrap();
    let ek = hex32(&c.ephemeral_priv_hex);
    let chosen_opk = if c.use_pre_key {
        Some(hex32(&c.bob.bundle.opks_pub_hex[0]))
    } else {
        None
    };

    let bundle = Bundle {
        identity_key: hex32(&c.bob.bundle.ik_pub_hex),
        signed_pre_key: hex32(&c.bob.bundle.spk_pub_hex),
        signed_pre_key_sig: {
            let v = hex_decode(&c.bob.bundle.spk_sig_hex).unwrap();
            let mut out = [0u8; 64];
            out.copy_from_slice(&v);
            out
        },
        pre_keys: opks_sorted,
    };

    let (active_out, header) =
        get_shared_secret_active(&alice, &bundle, &appendix, ek, chosen_opk, c.require_pre_key)
            .expect("active");

    let want_ss = hex_decode(&c.shared_secret_hex).unwrap();
    let want_ad = hex_decode(&c.associated_data_hex).unwrap();
    assert_eq!(active_out.shared_secret.to_vec(), want_ss, "case {}: active SS mismatch", c.label);
    assert_eq!(active_out.associated_data, want_ad, "case {}: active AD mismatch", c.label);

    // Verify header matches.
    assert_eq!(header.identity_key, hex32(&c.header.ik_hex), "case {}: header.ik", c.label);
    assert_eq!(header.ephemeral_key, hex32(&c.header.ek_hex), "case {}: header.ek", c.label);
    assert_eq!(header.signed_pre_key, hex32(&c.header.spk_hex), "case {}: header.spk", c.label);
    match (&header.pre_key, &c.header.opk_hex) {
        (Some(p), Some(h)) => assert_eq!(*p, hex32(h), "case {}: header.opk", c.label),
        (None, None) => {}
        _ => panic!("case {}: header.opk presence mismatch", c.label),
    }

    // Bob's passive side.
    let h_native = Header {
        identity_key: hex32(&c.header.ik_hex),
        ephemeral_key: hex32(&c.header.ek_hex),
        signed_pre_key: hex32(&c.header.spk_hex),
        pre_key: c.header.opk_hex.as_deref().map(hex32),
    };
    let (passive_out, _spk_used) =
        get_shared_secret_passive(&bob, &h_native, &appendix, c.require_pre_key).expect("passive");

    assert_eq!(
        passive_out.shared_secret, active_out.shared_secret,
        "case {}: SS active vs passive mismatch",
        c.label
    );
    assert_eq!(
        passive_out.associated_data, active_out.associated_data,
        "case {}: AD active vs passive mismatch",
        c.label
    );
}

#[test]
fn replay_x3dh_fixtures() {
    let fixture = load_fixture::<Case>("x3dh.json").expect("load");
    assert!(!fixture.cases.is_empty());
    for c in &fixture.cases {
        run_case(c);
    }
}
