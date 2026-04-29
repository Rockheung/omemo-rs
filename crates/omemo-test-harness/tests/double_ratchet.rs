//! Stage 1.2 GATE TEST — top-level DoubleRatchet 4-message round-trip with
//! mid-conversation DH ratchet step + 1 skipped + 1 out-of-order delivery,
//! byte-equal with python-doubleratchet.

use omemo_doubleratchet::aead::HashFunction;
use omemo_doubleratchet::dh_ratchet::{
    DhPrivProvider, DiffieHellmanRatchet, FixedDhPrivProvider, Header,
};
use omemo_doubleratchet::double_ratchet::{
    build_ad_default, AeadParams, DoubleRatchet, EncryptedMessage,
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
struct WireEncrypted {
    header: WireHeader,
    ciphertext_hex: String,
}

#[derive(Debug, Deserialize)]
struct WireMessage {
    #[allow(dead_code)] // human-readable label, present in JSON only
    label: String,
    plaintext_hex: String,
    encrypted: WireEncrypted,
}

#[derive(Debug, Deserialize)]
struct Case {
    label: String,
    shared_secret_hex: String,
    associated_data_hex: String,
    constant_hex: String,
    max_skip: usize,
    dos_threshold: u64,
    alice_priv_queue_hex: Vec<String>,
    bob_spk_priv_hex: String,
    bob_spk_pub_hex: String,
    bob_priv_queue_hex: Vec<String>,
    messages: Vec<WireMessage>,
    expected_bob_skipped_after_m3: usize,
    expected_bob_skipped_after_m2: usize,
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
type DR = DoubleRatchet<RootKdf, MsgKdf>;

const AEAD: AeadParams = AeadParams {
    hash: HashFunction::Sha256,
    info: b"OMEMO Message Key Material",
};

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

fn from_wire(w: &WireEncrypted) -> EncryptedMessage {
    EncryptedMessage {
        header: Header {
            ratchet_pub: hex32(&w.header.ratchet_pub_hex),
            previous_sending_chain_length: w.header.pn,
            sending_chain_length: w.header.n,
        },
        ciphertext: hex_decode(&w.ciphertext_hex).unwrap(),
    }
}

#[test]
fn gate_double_ratchet_round_trip() {
    let fixture = load_fixture::<Case>("double_ratchet.json").expect("load");
    let c = &fixture.cases[0];

    let shared = hex_decode(&c.shared_secret_hex).unwrap();
    let ad = hex_decode(&c.associated_data_hex).unwrap();
    let constant = hex_decode(&c.constant_hex).unwrap();

    // ---- Alice: active. Build her DH ratchet directly (rather than through
    // a separate `encrypt_initial_message` helper); the underlying state is
    // identical.
    let alice_dh: DiffieHellmanRatchet<RootKdf, MsgKdf> = DiffieHellmanRatchet::create_active(
        hex32(&c.bob_spk_pub_hex),
        shared.clone(),
        constant.clone(),
        c.dos_threshold,
        make_provider(&c.alice_priv_queue_hex),
    )
    .expect("alice DH create");
    let mut alice = DR::from_dh_ratchet(alice_dh, c.max_skip, AEAD, build_ad_default);

    // M0: Alice → Bob (initial).
    let m0_pt = hex_decode(&c.messages[0].plaintext_hex).unwrap();
    let m0_ct = alice
        .encrypt_message(&m0_pt, &ad)
        .expect("alice encrypt M0");
    let want_m0 = from_wire(&c.messages[0].encrypted);
    assert_eq!(m0_ct, want_m0, "M0 ciphertext byte-equal with python");

    // ---- Bob: passive, bootstrapped from M0's header.
    let bob_dh: DiffieHellmanRatchet<RootKdf, MsgKdf> = DiffieHellmanRatchet::create_passive(
        hex32(&c.bob_spk_priv_hex),
        m0_ct.header.ratchet_pub,
        shared.clone(),
        constant.clone(),
        c.dos_threshold,
        make_provider(&c.bob_priv_queue_hex),
    )
    .expect("bob DH create");
    let mut bob = DR::from_dh_ratchet(bob_dh, c.max_skip, AEAD, build_ad_default);

    let m0_recovered = bob.decrypt_message(&m0_ct, &ad).expect("bob decrypt M0");
    assert_eq!(m0_recovered, m0_pt, "M0 plaintext recovered");

    // M1: Bob → Alice.
    let m1_pt = hex_decode(&c.messages[1].plaintext_hex).unwrap();
    let m1_ct = bob.encrypt_message(&m1_pt, &ad).expect("bob encrypt M1");
    let want_m1 = from_wire(&c.messages[1].encrypted);
    assert_eq!(m1_ct, want_m1, "M1 ciphertext byte-equal with python");

    let m1_recovered = alice
        .decrypt_message(&m1_ct, &ad)
        .expect("alice decrypt M1");
    assert_eq!(m1_recovered, m1_pt, "M1 plaintext recovered");

    // M2, M3: Alice → Bob (encrypt both before either is delivered).
    let m2_pt = hex_decode(&c.messages[2].plaintext_hex).unwrap();
    let m3_pt = hex_decode(&c.messages[3].plaintext_hex).unwrap();
    let m2_ct = alice
        .encrypt_message(&m2_pt, &ad)
        .expect("alice encrypt M2");
    let m3_ct = alice
        .encrypt_message(&m3_pt, &ad)
        .expect("alice encrypt M3");

    assert_eq!(
        m2_ct,
        from_wire(&c.messages[2].encrypted),
        "M2 ciphertext byte-equal with python"
    );
    assert_eq!(
        m3_ct,
        from_wire(&c.messages[3].encrypted),
        "M3 ciphertext byte-equal with python"
    );

    // Out-of-order: M3 arrives first → triggers Bob's DH ratchet step AND
    // adds 1 skipped key for M2's slot.
    let m3_recovered = bob.decrypt_message(&m3_ct, &ad).expect("bob decrypt M3");
    assert_eq!(m3_recovered, m3_pt, "M3 plaintext recovered");
    assert_eq!(
        bob.skipped_count(),
        c.expected_bob_skipped_after_m3,
        "case {}: skipped after M3",
        c.label
    );

    // M2 arrives — pulled from skipped-keys cache.
    let m2_recovered = bob.decrypt_message(&m2_ct, &ad).expect("bob decrypt M2");
    assert_eq!(m2_recovered, m2_pt, "M2 plaintext recovered");
    assert_eq!(
        bob.skipped_count(),
        c.expected_bob_skipped_after_m2,
        "case {}: skipped after M2",
        c.label
    );
}
