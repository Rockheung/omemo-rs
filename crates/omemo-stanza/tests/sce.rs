//! XEP-0420 SCE envelope round-trip tests.

use omemo_stanza::sce::SceEnvelope;

const CANONICAL_BODY_ENVELOPE: &str = "\
<envelope xmlns=\"urn:xmpp:sce:1\">\
<content><body xmlns=\"jabber:client\">Hello, world.</body></content>\
<rpad>cmFuZG9tLXBhZGRpbmctYnl0ZXM=</rpad>\
<time stamp=\"2026-04-29T12:34:56Z\"/>\
<to jid=\"bob@example.org\"/>\
<from jid=\"alice@example.org/desktop\"/>\
</envelope>";

const CANONICAL_EMPTY_PAD: &str = "\
<envelope xmlns=\"urn:xmpp:sce:1\">\
<content><body xmlns=\"jabber:client\">no padding</body></content>\
<rpad/>\
<time stamp=\"2026-04-29T00:00:00Z\"/>\
<to jid=\"a@b\"/>\
<from jid=\"c@d\"/>\
</envelope>";

#[test]
fn body_envelope_round_trip() {
    let parsed = SceEnvelope::parse(CANONICAL_BODY_ENVELOPE).expect("parse");
    assert_eq!(parsed.to, "bob@example.org");
    assert_eq!(parsed.from, "alice@example.org/desktop");
    assert_eq!(parsed.timestamp, "2026-04-29T12:34:56Z");
    assert_eq!(parsed.rpad.len(), b"random-padding-bytes".len());
    assert!(parsed.content.contains("Hello, world."));

    let emitted = parsed.encode().expect("encode");
    assert_eq!(emitted, CANONICAL_BODY_ENVELOPE);

    let reparsed = SceEnvelope::parse(&emitted).expect("reparse");
    assert_eq!(parsed, reparsed, "model stable across round-trip");
}

#[test]
fn empty_rpad_uses_self_close() {
    let parsed = SceEnvelope::parse(CANONICAL_EMPTY_PAD).expect("parse");
    assert!(parsed.rpad.is_empty());

    let emitted = parsed.encode().expect("encode");
    assert_eq!(emitted, CANONICAL_EMPTY_PAD);
}

#[test]
fn parse_accepts_attribute_reordering_and_whitespace() {
    let alt = "\
<?xml version=\"1.0\"?>
<envelope xmlns=\"urn:xmpp:sce:1\">
  <content><body xmlns=\"jabber:client\">hi</body></content>
  <rpad>YQ==</rpad>
  <to jid=\"recipient@x\"/>
  <from jid=\"sender@y/r\"/>
  <time stamp=\"2026-04-29T00:00:00Z\"/>
</envelope>";
    let parsed = SceEnvelope::parse(alt).expect("parse");
    assert_eq!(parsed.to, "recipient@x");
    assert_eq!(parsed.from, "sender@y/r");
    assert_eq!(parsed.rpad, b"a");
}

#[test]
fn parse_rejects_missing_required_elements() {
    // Missing <time>.
    let bad = "\
<envelope xmlns=\"urn:xmpp:sce:1\">\
<content><body xmlns=\"jabber:client\">x</body></content>\
<rpad/>\
<to jid=\"a@b\"/>\
<from jid=\"c@d\"/>\
</envelope>";
    assert!(SceEnvelope::parse(bad).is_err());
}

#[test]
fn parse_rejects_wrong_root() {
    let bad = "<bundle xmlns=\"urn:xmpp:omemo:2\"/>";
    assert!(SceEnvelope::parse(bad).is_err());
}

#[test]
fn empty_content_round_trip() {
    // Some clients send an envelope with an empty <content/> as a
    // chat-state-only / typing-indicator carrier.
    let canonical = "\
<envelope xmlns=\"urn:xmpp:sce:1\">\
<content></content>\
<rpad>YWJj</rpad>\
<time stamp=\"2026-04-29T00:00:00Z\"/>\
<to jid=\"a@b\"/>\
<from jid=\"c@d\"/>\
</envelope>";
    let parsed = SceEnvelope::parse(canonical).expect("parse");
    assert_eq!(parsed.content, "");
    let emitted = parsed.encode().expect("encode");
    assert_eq!(emitted, canonical);
}
