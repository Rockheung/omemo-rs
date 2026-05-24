//! Mirrors `westron-spec/tests/test_caps.py` + test_transcode.py + test_signed_caps.py.
use omemo_westron::{
    detect_downgrade, negotiate_best_spec, select_wire_for_recipients, Caps, Identity,
    NegotiationError, Recipient, SignedCaps, Spec, CAPS_MAX_SKEW_SECS,
};

// ---- negotiate_best_spec --------------------------------------------------

#[test]
fn select_westron_when_both_support() {
    let s = Caps::new([Spec::Omemo03, Spec::Omemo2, Spec::Westron]);
    let p = Caps::new([Spec::Omemo2, Spec::Westron]);
    assert_eq!(negotiate_best_spec(&s, &p).unwrap(), Spec::Westron);
}

#[test]
fn select_omemo2_when_westron_unavailable() {
    let s = Caps::new([Spec::Omemo2, Spec::Westron]);
    let p = Caps::new([Spec::Omemo03, Spec::Omemo2]);
    assert_eq!(negotiate_best_spec(&s, &p).unwrap(), Spec::Omemo2);
}

#[test]
fn select_omemo03_only_when_legacy_peer() {
    let s = Caps::new([Spec::Omemo03, Spec::Omemo2, Spec::Westron]);
    let p = Caps::new([Spec::Omemo03]);
    assert_eq!(negotiate_best_spec(&s, &p).unwrap(), Spec::Omemo03);
}

#[test]
fn no_common_spec_errors() {
    let s = Caps::new([Spec::Westron]);
    let p = Caps::new([Spec::Omemo03]);
    assert!(matches!(
        negotiate_best_spec(&s, &p),
        Err(NegotiationError::NoCommon)
    ));
}

#[test]
fn priority_order_is_westron_2_03() {
    let full = Caps::new([Spec::Omemo03, Spec::Omemo2, Spec::Westron]);
    assert_eq!(negotiate_best_spec(&full, &full).unwrap(), Spec::Westron);
}

// ---- downgrade detection -------------------------------------------------

#[test]
fn downgrade_detected_when_higher_spec_lost() {
    let prev = Caps::new([Spec::Westron, Spec::Omemo2]);
    let now = Caps::new([Spec::Omemo03]);
    assert!(detect_downgrade(&prev, &now));
}

#[test]
fn equal_caps_not_downgrade() {
    let c = Caps::new([Spec::Omemo2]);
    assert!(!detect_downgrade(&c, &c));
}

#[test]
fn upgrade_not_downgrade() {
    let prev = Caps::new([Spec::Omemo2]);
    let now = Caps::new([Spec::Westron, Spec::Omemo2]);
    assert!(!detect_downgrade(&prev, &now));
}

// ---- transcode -----------------------------------------------------------

#[test]
fn mixed_devices_split_by_best_spec() {
    let self_caps = Caps::new([Spec::Omemo03, Spec::Omemo2, Spec::Westron]);
    let devs = vec![
        Recipient {
            jid: "bob@x".into(),
            device_id: 1,
            caps: Caps::new([Spec::Westron, Spec::Omemo2]),
        },
        Recipient {
            jid: "bob@x".into(),
            device_id: 2,
            caps: Caps::new([Spec::Omemo2]),
        },
        Recipient {
            jid: "bob@x".into(),
            device_id: 3,
            caps: Caps::new([Spec::Omemo03]),
        },
    ];
    let plan = select_wire_for_recipients(&self_caps, &devs);
    assert_eq!(plan.groups.len(), 3);
    assert_eq!(plan.groups[&Spec::Westron][0].device_id, 1);
    assert_eq!(plan.groups[&Spec::Omemo2][0].device_id, 2);
    assert_eq!(plan.groups[&Spec::Omemo03][0].device_id, 3);
    assert!(plan.unreachable.is_empty());
}

#[test]
fn unreachable_device_surfaced() {
    let self_caps = Caps::new([Spec::Westron, Spec::Omemo2]);
    let devs = vec![Recipient {
        jid: "bob@x".into(),
        device_id: 1,
        caps: Caps::new([Spec::Omemo03]),
    }];
    let plan = select_wire_for_recipients(&self_caps, &devs);
    assert!(plan.groups.is_empty());
    assert_eq!(plan.unreachable.len(), 1);
}

// ---- signed caps ---------------------------------------------------------

#[test]
fn signed_caps_happy_path() {
    let a = Identity::generate();
    let caps = SignedCaps::sign(&a, true, false, 42, 1_731_000_000);
    caps.verify(42, &a.ik_ed_pub(), Some(1_731_000_000), CAPS_MAX_SKEW_SECS)
        .unwrap();
}

#[test]
fn unsigned_caps_rejected() {
    let a = Identity::generate();
    let caps = SignedCaps {
        also_speaks_omemo_2: true,
        also_speaks_omemo_03: true,
        sid: 42,
        ts: 1_731_000_000,
        sig: [0u8; 64],
    };
    assert!(caps
        .verify(42, &a.ik_ed_pub(), None, CAPS_MAX_SKEW_SECS)
        .is_err());
}

#[test]
fn caps_signed_by_other_identity_rejected() {
    let a = Identity::generate();
    let forger = Identity::generate();
    let caps = SignedCaps::sign(&forger, true, false, 42, 1_731_000_000);
    assert!(caps
        .verify(42, &a.ik_ed_pub(), None, CAPS_MAX_SKEW_SECS)
        .is_err());
}

#[test]
fn caps_sid_mismatch_rejected() {
    let a = Identity::generate();
    let caps = SignedCaps::sign(&a, true, false, 42, 1_731_000_000);
    assert!(caps
        .verify(99, &a.ik_ed_pub(), None, CAPS_MAX_SKEW_SECS)
        .is_err());
}

#[test]
fn caps_tampered_attribute_rejected() {
    let a = Identity::generate();
    let mut caps = SignedCaps::sign(&a, true, false, 42, 1_731_000_000);
    caps.also_speaks_omemo_2 = false; // attacker flips bool
    assert!(caps
        .verify(42, &a.ik_ed_pub(), None, CAPS_MAX_SKEW_SECS)
        .is_err());
}

#[test]
fn caps_stale_ts_rejected() {
    let a = Identity::generate();
    let caps = SignedCaps::sign(&a, true, false, 42, 1000);
    assert!(caps
        .verify(42, &a.ik_ed_pub(), Some(1000 + 100_000), CAPS_MAX_SKEW_SECS)
        .is_err());
}

#[test]
fn caps_within_skew_accepted() {
    let a = Identity::generate();
    let caps = SignedCaps::sign(&a, true, false, 42, 1000);
    caps.verify(42, &a.ik_ed_pub(), Some(1000 + 3600), CAPS_MAX_SKEW_SECS)
        .unwrap();
}

// ---- canonical signed string interop with Python spec -------------------

#[test]
fn canonical_signed_string_matches_python_format() {
    // SPEC §4.3: "speaks-omemo-2={a};speaks-omemo-03={b};sid={sid};ts={ts}"
    let caps = SignedCaps {
        also_speaks_omemo_2: true,
        also_speaks_omemo_03: false,
        sid: 12345,
        ts: 1_731_000_000,
        sig: [0u8; 64],
    };
    assert_eq!(
        caps.canonical_signed_string(),
        b"speaks-omemo-2=true;speaks-omemo-03=false;sid=12345;ts=1731000000"
    );
}
