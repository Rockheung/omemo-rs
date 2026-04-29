//! Stage 2 GATE TEST — round-trip canonical XEP-0384 v0.9 stanza examples.
//!
//! For each canonical XML string we:
//! 1. Parse it into the typed model.
//! 2. Re-emit XML.
//! 3. Assert the re-emitted XML is byte-equal with the canonical form.
//! 4. Parse the re-emitted XML again — assert the model is identical.
//!
//! The canonical forms here follow XEP-0384 v0.9 §3 (Encrypted Message)
//! and §5 (Bundle, Device List), with attribute order normalised:
//!
//! * Root element: `xmlns` first.
//! * `<header>`:    `sid`.
//! * `<keys>`:      `jid`.
//! * `<key>`:       `rid`, then `kex` (only present if true).
//! * `<spk>` / `<pk>`: `id`.
//! * `<device>`:    `id`, then `label` (only if present).

use omemo_stanza::{Bundle, DeviceList, Encrypted};

// XEP-0384 §3.1 — single-recipient encrypted message with payload, kex=true.
const ENCRYPTED_KEX: &str = "\
<encrypted xmlns=\"urn:xmpp:omemo:2\">\
<header sid=\"27183\">\
<keys jid=\"juliet@capulet.lit\">\
<key rid=\"31415\" kex=\"true\">SGVsbG8gd29ybGQh</key>\
</keys>\
</header>\
<payload>U0NFLWVudmVsb3BlLWJ5dGVz</payload>\
</encrypted>";

// XEP-0384 §3.1 follow-up — same recipient, no kex flag, key-only message
// (no <payload>, e.g. heartbeat/empty key transport).
const ENCRYPTED_KEY_ONLY: &str = "\
<encrypted xmlns=\"urn:xmpp:omemo:2\">\
<header sid=\"27183\">\
<keys jid=\"juliet@capulet.lit\">\
<key rid=\"31415\">a2V5LW9ubHk=</key>\
</keys>\
</header>\
</encrypted>";

// Custom 3-recipient case (per stages.md gate requirement). One recipient
// has two devices; another only the kex flag.
const ENCRYPTED_3_RECIPIENTS: &str = "\
<encrypted xmlns=\"urn:xmpp:omemo:2\">\
<header sid=\"27183\">\
<keys jid=\"alice@example.org\">\
<key rid=\"100\">a2V5LWZvci1hbGljZS0xMDA=</key>\
<key rid=\"101\">a2V5LWZvci1hbGljZS0xMDE=</key>\
</keys>\
<keys jid=\"bob@example.org\">\
<key rid=\"200\" kex=\"true\">a2V4LWtleS1mb3ItYm9i</key>\
</keys>\
<keys jid=\"carol@example.com\">\
<key rid=\"300\">a2V5LWZvci1jYXJvbA==</key>\
</keys>\
</header>\
<payload>VGhyZWUtcmVjaXBpZW50LXBheWxvYWQ=</payload>\
</encrypted>";

// XEP-0384 §5.1 — bundle.
const BUNDLE: &str = "\
<bundle xmlns=\"urn:xmpp:omemo:2\">\
<spk id=\"1\">U1BLLXB1Yi1ieXRlcw==</spk>\
<spks>U1BLLXNpZ25hdHVyZS1ieXRlcw==</spks>\
<ik>SUstcHViLWJ5dGVz</ik>\
<prekeys>\
<pk id=\"1\">UEstMQ==</pk>\
<pk id=\"2\">UEstMg==</pk>\
<pk id=\"3\">UEstMw==</pk>\
</prekeys>\
</bundle>";

// XEP-0384 §5.2 — device list with mix of labelled and unlabelled devices.
const DEVICE_LIST: &str = "\
<list xmlns=\"urn:xmpp:omemo:2\">\
<device id=\"27183\" label=\"Phone\"/>\
<device id=\"27184\"/>\
<device id=\"27185\" label=\"Desktop\"/>\
</list>";

// Empty device list (just-removed-all-devices state).
const EMPTY_DEVICE_LIST: &str = "<list xmlns=\"urn:xmpp:omemo:2\"></list>";

fn roundtrip_encrypted(canonical: &str) {
    let parsed = Encrypted::parse(canonical).expect("parse");
    let emitted = parsed.encode().expect("encode");
    assert_eq!(
        emitted, canonical,
        "encode mismatch\n want: {canonical}\n got:  {emitted}"
    );
    let reparsed = Encrypted::parse(&emitted).expect("reparse");
    assert_eq!(parsed, reparsed, "model not stable across round-trip");
}

fn roundtrip_bundle(canonical: &str) {
    let parsed = Bundle::parse(canonical).expect("parse");
    let emitted = parsed.encode().expect("encode");
    assert_eq!(emitted, canonical, "encode mismatch");
    let reparsed = Bundle::parse(&emitted).expect("reparse");
    assert_eq!(parsed, reparsed);
}

fn roundtrip_device_list(canonical: &str) {
    let parsed = DeviceList::parse(canonical).expect("parse");
    let emitted = parsed.encode().expect("encode");
    assert_eq!(emitted, canonical, "encode mismatch");
    let reparsed = DeviceList::parse(&emitted).expect("reparse");
    assert_eq!(parsed, reparsed);
}

#[test]
fn encrypted_kex() {
    roundtrip_encrypted(ENCRYPTED_KEX);
}

#[test]
fn encrypted_key_only() {
    roundtrip_encrypted(ENCRYPTED_KEY_ONLY);
}

#[test]
fn encrypted_three_recipients() {
    roundtrip_encrypted(ENCRYPTED_3_RECIPIENTS);
}

#[test]
fn bundle_round_trip() {
    roundtrip_bundle(BUNDLE);
}

#[test]
fn device_list_round_trip() {
    roundtrip_device_list(DEVICE_LIST);
}

#[test]
fn empty_device_list() {
    // Empty open-tag form differs from the self-closing `<list .../>`. We
    // accept either on parse and emit the explicit-close form.
    let parsed = DeviceList::parse(EMPTY_DEVICE_LIST).expect("parse");
    assert!(parsed.devices.is_empty());
    let emitted = parsed.encode().expect("encode");
    assert_eq!(emitted, EMPTY_DEVICE_LIST);
}

// --- Tolerance tests: parsing accepts non-canonical input. ---

#[test]
fn parse_accepts_attribute_reordering() {
    let alt = "\
<encrypted xmlns=\"urn:xmpp:omemo:2\">\
<header sid=\"27183\">\
<keys jid=\"alice@example.org\">\
<key kex=\"true\" rid=\"100\">a2V4LWZvci1hbGljZQ==</key>\
</keys>\
</header>\
</encrypted>";
    let parsed = Encrypted::parse(alt).expect("parse");
    assert_eq!(parsed.sid, 27183);
    assert_eq!(parsed.keys.len(), 1);
    assert_eq!(parsed.keys[0].keys[0].rid, 100);
    assert!(parsed.keys[0].keys[0].kex);
}

#[test]
fn parse_accepts_self_closing_list() {
    let alt = "<list xmlns=\"urn:xmpp:omemo:2\"/>";
    let parsed = DeviceList::parse(alt).expect("parse");
    assert!(parsed.devices.is_empty());
}

#[test]
fn parse_accepts_xml_decl_and_whitespace() {
    let alt = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<list xmlns=\"urn:xmpp:omemo:2\">
  <device id=\"42\" label=\"Phone\"/>
  <device id=\"43\"/>
</list>";
    let parsed = DeviceList::parse(alt).expect("parse");
    assert_eq!(parsed.devices.len(), 2);
    assert_eq!(parsed.devices[0].id, 42);
    assert_eq!(parsed.devices[0].label.as_deref(), Some("Phone"));
    assert_eq!(parsed.devices[1].label, None);
}

// --- Negative tests. ---

#[test]
fn missing_sid_is_error() {
    let bad =
        "<encrypted xmlns=\"urn:xmpp:omemo:2\"><header><keys jid=\"x\"/></header></encrypted>";
    assert!(Encrypted::parse(bad).is_err());
}

#[test]
fn wrong_root_is_error() {
    let bad = "<bundle xmlns=\"urn:xmpp:omemo:2\"><spk id=\"1\">YQ==</spk><spks>Yg==</spks><ik>Yw==</ik><prekeys/></bundle>";
    assert!(Encrypted::parse(bad).is_err());
}
