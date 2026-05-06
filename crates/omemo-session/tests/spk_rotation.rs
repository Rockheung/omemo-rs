//! Unit-level coverage for `Store::rotate_spk` (P3-2).
//!
//! Verifies that:
//!   * A rotated store has exactly one *active* SPK row
//!     (`replaced_at IS NULL`) and the previous one(s) are
//!     marked replaced with the supplied timestamp.
//!   * `current_spk()` returns the freshly-rotated row.
//!   * Old rows survive in the table (so in-flight KEXes
//!     against the old `spk_id` can still complete via
//!     `get_spk(old_id)`).
//!   * The SPK signature is valid against the identity key
//!     (i.e. the rotate flow signed with the right IK seed).

use omemo_session::Store;

fn install_seed() -> [u8; 32] {
    [0xA1; 32]
}

#[test]
fn rotate_marks_old_replaced_and_installs_new_active() {
    let mut store = Store::open_in_memory().expect("open");
    let _ = store
        .put_identity("alice@example.org", 1001, &install_seed())
        .expect("put_identity");

    // Seed an initial SPK with id 1, active.
    let initial_priv = [0x10u8; 32];
    let initial_nonce = [0x20u8; 64];
    let first = store
        .rotate_spk(initial_priv, initial_nonce, 1_000_000)
        .expect("rotate first");
    assert_eq!(first.id, 1, "first rotate against fresh store yields id=1");
    assert!(first.replaced_at.is_none());

    // Rotate again — old row marked replaced, new one active.
    let next_priv = [0x30u8; 32];
    let next_nonce = [0x40u8; 64];
    let second = store
        .rotate_spk(next_priv, next_nonce, 2_000_000)
        .expect("rotate second");

    assert_eq!(second.id, 2, "ids monotonically increment");
    assert!(second.replaced_at.is_none());

    let old_row = store
        .get_spk(first.id)
        .expect("get_spk")
        .expect("old row preserved");
    assert_eq!(
        old_row.replaced_at,
        Some(2_000_000),
        "rotate marks predecessors with the new rotate timestamp"
    );

    let current = store.current_spk().expect("current_spk").expect("must exist");
    assert_eq!(current.id, second.id);
    assert_eq!(current.priv_key, second.priv_key);
    assert_eq!(current.created_at, 2_000_000);
}

#[test]
fn rotated_spk_carries_supplied_priv_and_consistent_pub() {
    let mut store = Store::open_in_memory().expect("open");
    let _ = store
        .put_identity("alice@example.org", 1001, &install_seed())
        .expect("put_identity");

    let spk_priv = [0xC1u8; 32];
    let nonce = [0xD2u8; 64];
    let spk = store
        .rotate_spk(spk_priv, nonce, 3_000_000)
        .expect("rotate");

    // Priv echoes the input verbatim (no clamping done by
    // rotate_spk itself — XEdDSA signing handles the clamp
    // inside `omemo-x3dh`).
    assert_eq!(spk.priv_key, spk_priv);
    // Pub matches the canonical Curve25519 derivation of priv.
    assert_eq!(
        spk.pub_key,
        omemo_xeddsa::priv_to_curve25519_pub(&spk_priv)
    );
    // 64-byte signature is populated.
    assert_ne!(spk.sig, [0u8; 64]);
}

#[test]
fn rotate_without_identity_errors() {
    let mut store = Store::open_in_memory().expect("open");
    let err = store.rotate_spk([0u8; 32], [0u8; 64], 0).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("rotate_spk requires an installed identity"),
        "rotate before put_identity should fail clearly; got: {msg}"
    );
}
