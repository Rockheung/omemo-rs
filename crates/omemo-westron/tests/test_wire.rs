//! Mirrors `westron-spec/tests/test_wire_westron.py` — Westron canonical wire.
use omemo_westron::signed_caps::SignedCaps;
use omemo_westron::wire::{
    decode, encode, WestronKey, WestronKeysGroup, WestronStanza, WireError,
};
use omemo_westron::Identity;

fn sample(caps: SignedCaps) -> WestronStanza {
    WestronStanza {
        sid: 12345,
        groups: vec![WestronKeysGroup {
            jid: "bob@example".into(),
            keys: vec![WestronKey {
                rid: 70000,
                kex: false,
                data: vec![0xaa; 64],
            }],
        }],
        payload: vec![0xbb; 64],
        caps,
    }
}

#[test]
fn westron_wire_roundtrip_with_unsigned_caps() {
    let s = sample(SignedCaps {
        also_speaks_omemo_2: true,
        also_speaks_omemo_03: false,
        sid: 12345,
        ts: 0,
        sig: [0u8; 64],
    });
    let xml = encode(&s).unwrap();
    assert!(std::str::from_utf8(&xml)
        .unwrap()
        .contains("xmlns=\"urn:xmpp:omemo:westron:1\""));
    let d = decode(&xml).unwrap();
    assert_eq!(d.sid, s.sid);
    assert_eq!(d.payload, s.payload);
    assert_eq!(d.caps.also_speaks_omemo_2, s.caps.also_speaks_omemo_2);
}

#[test]
fn westron_wire_roundtrip_with_signed_caps_verifies() {
    let a = Identity::generate();
    let caps = SignedCaps::sign(&a, true, false, 12345, 1_731_000_000);
    let s = sample(caps);
    let xml = encode(&s).unwrap();
    let d = decode(&xml).unwrap();
    assert_eq!(d.caps.sig, s.caps.sig);
    d.caps.verify(12345, &a.ik_ed_pub(), Some(1_731_000_000), 86400)
        .unwrap();
}

#[test]
fn westron_namespace_strict_rejected() {
    let not_westron = b"<encrypted xmlns=\"urn:xmpp:omemo:2\"><header sid=\"1\"/></encrypted>";
    assert!(matches!(decode(not_westron), Err(WireError::Namespace(_))));
}
