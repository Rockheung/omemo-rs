//! Mirrors `westron-spec/tests/test_identity.py`.
use omemo_westron::{derive_curve25519, Identity, IdentityError};

#[test]
fn ed25519_to_curve25519_deterministic() {
    let id = Identity::generate();
    let pk = id.ik_ed_pub();
    let c1 = derive_curve25519(&pk).unwrap();
    let c2 = derive_curve25519(&pk).unwrap();
    assert_eq!(c1, c2);
    assert_eq!(c1.len(), 32);
}

#[test]
fn two_different_ed25519_yield_different_curve25519() {
    let a = Identity::generate();
    let b = Identity::generate();
    assert_ne!(
        derive_curve25519(&a.ik_ed_pub()).unwrap(),
        derive_curve25519(&b.ik_ed_pub()).unwrap()
    );
}

#[test]
fn dual_bundle_consistent_accepted() {
    let id = Identity::generate();
    let ik_ed = id.ik_ed_pub();
    let ik_curve = derive_curve25519(&ik_ed).unwrap();
    Identity::verify_dual_bundle(&ik_ed, &ik_curve).unwrap();
}

#[test]
fn dual_bundle_inconsistent_rejected() {
    let a = Identity::generate();
    let b = Identity::generate();
    let bad_curve = derive_curve25519(&b.ik_ed_pub()).unwrap();
    match Identity::verify_dual_bundle(&a.ik_ed_pub(), &bad_curve) {
        Err(IdentityError::IkConflict) => {}
        other => panic!("expected IkConflict, got {other:?}"),
    }
}

#[test]
fn spk_signature_roundtrip() {
    let a = Identity::generate();
    let spk_pub = [0x42u8; 32];
    let sig = a.sign_spk(&spk_pub);
    Identity::verify_spk_signature(&a.ik_ed_pub(), &spk_pub, &sig).unwrap();
}

#[test]
fn spk_signature_wrong_signer_rejected() {
    let a = Identity::generate();
    let b = Identity::generate();
    let spk_pub = [0x42u8; 32];
    let sig_by_b = b.sign_spk(&spk_pub);
    match Identity::verify_spk_signature(&a.ik_ed_pub(), &spk_pub, &sig_by_b) {
        Err(IdentityError::BundleInvalid) => {}
        other => panic!("expected BundleInvalid, got {other:?}"),
    }
}

#[test]
fn spk_signature_tampered_spk_rejected() {
    let a = Identity::generate();
    let spk_pub = [0x42u8; 32];
    let sig = a.sign_spk(&spk_pub);
    let tampered = [0x43u8; 32];
    match Identity::verify_spk_signature(&a.ik_ed_pub(), &tampered, &sig) {
        Err(IdentityError::BundleInvalid) => {}
        other => panic!("expected BundleInvalid, got {other:?}"),
    }
}

#[test]
fn spk_signature_zero_bytes_rejected() {
    let a = Identity::generate();
    let spk_pub = [0x42u8; 32];
    let zero_sig = [0u8; 64];
    assert!(Identity::verify_spk_signature(&a.ik_ed_pub(), &spk_pub, &zero_sig).is_err());
}
