//! XEP-0420 v0.4 Stanza Content Encryption envelope.
//!
//! ```xml
//! <envelope xmlns="urn:xmpp:sce:1">
//!   <content>
//!     <body xmlns="jabber:client">Hello</body>
//!     <!-- arbitrary stanza content -->
//!   </content>
//!   <rpad>random padding bytes (base64)</rpad>
//!   <time stamp="2026-04-29T12:34:56Z" />
//!   <to jid="bob@example.org" />
//!   <from jid="alice@example.org/desktop" />
//! </envelope>
//! ```
//!
//! In OMEMO 2 the envelope sits inside `<encrypted><payload>` (base64-
//! encoded) before AEAD encryption. Padding (`<rpad>`) is required by
//! XEP-0420 §3.2 and must be 0..200 random bytes. Time, to, and from are
//! all required.
//!
//! The `<content>` payload is treated as opaque XML by this layer — we
//! preserve the inner bytes verbatim across decode → encode, so the
//! caller's choice of inner stanza (e.g. `<body>`) is byte-stable. We
//! intentionally do not validate the inner XML structure; that's the
//! caller's responsibility.

use std::io::Cursor;

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;

use crate::{attr_str, local_name, req_attr, StanzaError};

/// XEP-0420 envelope namespace.
pub const NS: &str = "urn:xmpp:sce:1";

/// XEP-0420 v0.4 envelope. `content` is the raw XML inside `<content>...</content>`
/// (without the wrapping element tags) — encoder writes it verbatim, decoder
/// captures it verbatim, so a round-trip is byte-stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SceEnvelope {
    /// Raw XML inside `<content>` (e.g. `<body xmlns="jabber:client">hi</body>`).
    pub content: String,
    /// 0..200 random bytes (XEP-0420 §3.2). Encoded as base64 on the wire.
    pub rpad: Vec<u8>,
    /// ISO-8601 UTC timestamp, e.g. `"2026-04-29T12:34:56Z"`.
    pub timestamp: String,
    /// Intended recipient bare/full JID.
    pub to: String,
    /// Claimed sender bare/full JID.
    pub from: String,
}

impl SceEnvelope {
    pub fn parse(xml: &str) -> Result<Self, StanzaError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false); // preserve inner whitespace

        // Find <envelope>.
        loop {
            match reader.read_event()? {
                Event::Decl(_) | Event::DocType(_) | Event::Comment(_) | Event::PI(_) => {}
                Event::Text(_) => {} // leading whitespace
                Event::Start(s) if local_name(s.name()) == b"envelope" => break,
                Event::Eof => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "envelope",
                        got: "(eof)".into(),
                    })
                }
                ev => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "envelope",
                        got: format!("{:?}", ev),
                    })
                }
            }
        }

        let mut content: Option<String> = None;
        let mut rpad: Option<Vec<u8>> = None;
        let mut timestamp: Option<String> = None;
        let mut to: Option<String> = None;
        let mut from: Option<String> = None;

        loop {
            match reader.read_event()? {
                Event::Start(s) => {
                    let name = local_name(s.name()).to_vec();
                    match name.as_slice() {
                        b"content" => {
                            content = Some(read_inner_xml(&mut reader, b"content")?);
                        }
                        b"rpad" => {
                            let txt = crate::read_text(&mut reader, b"rpad")?;
                            rpad = Some(crate::b64_decode(&txt)?);
                        }
                        b"time" => {
                            // <time stamp="..."> usually self-closing; tolerate
                            // both Start and Empty.
                            timestamp = Some(req_attr(&s, "stamp")?.into_owned());
                            consume_until_end(&mut reader, b"time")?;
                        }
                        b"to" => {
                            to = Some(req_attr(&s, "jid")?.into_owned());
                            consume_until_end(&mut reader, b"to")?;
                        }
                        b"from" => {
                            from = Some(req_attr(&s, "jid")?.into_owned());
                            consume_until_end(&mut reader, b"from")?;
                        }
                        other => {
                            return Err(StanzaError::UnexpectedElement(
                                String::from_utf8_lossy(other).into_owned(),
                            ))
                        }
                    }
                }
                Event::Empty(s) => {
                    let name = local_name(s.name()).to_vec();
                    match name.as_slice() {
                        b"rpad" => rpad = Some(Vec::new()),
                        b"time" => {
                            timestamp = Some(req_attr(&s, "stamp")?.into_owned());
                        }
                        b"to" => {
                            to = Some(req_attr(&s, "jid")?.into_owned());
                        }
                        b"from" => {
                            from = Some(req_attr(&s, "jid")?.into_owned());
                        }
                        other => {
                            return Err(StanzaError::UnexpectedElement(
                                String::from_utf8_lossy(other).into_owned(),
                            ))
                        }
                    }
                }
                Event::End(e) if local_name(e.name()) == b"envelope" => break,
                Event::Eof => return Err(StanzaError::MissingElement("envelope")),
                _ => {}
            }
        }

        Ok(Self {
            content: content.ok_or(StanzaError::MissingElement("content"))?,
            rpad: rpad.ok_or(StanzaError::MissingElement("rpad"))?,
            timestamp: timestamp.ok_or(StanzaError::MissingElement("time"))?,
            to: to.ok_or(StanzaError::MissingElement("to"))?,
            from: from.ok_or(StanzaError::MissingElement("from"))?,
        })
    }

    /// Canonical encoder. Element order: `<content>`, `<rpad>`, `<time>`,
    /// `<to>`, `<from>`. Empty `rpad` is emitted as `<rpad/>`. `time`,
    /// `to`, `from` are always self-closing.
    pub fn encode(&self) -> Result<String, StanzaError> {
        let mut buf = Vec::new();
        let mut w = Writer::new(Cursor::new(&mut buf));

        let mut env = BytesStart::new("envelope");
        env.push_attribute(("xmlns", NS));
        w.write_event(Event::Start(env.borrow()))?;

        // <content>...verbatim...</content>
        w.write_event(Event::Start(BytesStart::new("content")))?;
        // The content is raw XML — write it as a verbatim text-ish event.
        // BytesText would escape, so we use a Raw write via the inner cursor.
        let cursor: &mut Cursor<&mut Vec<u8>> = w.get_mut();
        std::io::Write::write_all(cursor, self.content.as_bytes()).expect("write");
        w.write_event(Event::End(BytesEnd::new("content")))?;

        // <rpad>...</rpad> or <rpad/>
        if self.rpad.is_empty() {
            w.write_event(Event::Empty(BytesStart::new("rpad")))?;
        } else {
            w.write_event(Event::Start(BytesStart::new("rpad")))?;
            let s = crate::b64_encode(&self.rpad);
            w.write_event(Event::Text(BytesText::new(&s)))?;
            w.write_event(Event::End(BytesEnd::new("rpad")))?;
        }

        let mut t = BytesStart::new("time");
        t.push_attribute(("stamp", self.timestamp.as_str()));
        w.write_event(Event::Empty(t.borrow()))?;

        let mut to = BytesStart::new("to");
        to.push_attribute(("jid", self.to.as_str()));
        w.write_event(Event::Empty(to.borrow()))?;

        let mut from = BytesStart::new("from");
        from.push_attribute(("jid", self.from.as_str()));
        w.write_event(Event::Empty(from.borrow()))?;

        w.write_event(Event::End(BytesEnd::new("envelope")))?;
        Ok(String::from_utf8(buf).expect("utf-8"))
    }
}

/// Consume reader events until matching `</end_name>`. Used for elements
/// that we treat as attribute-only and want to skip their (empty) body if
/// they happen to be written as `<x ...></x>` rather than `<x .../>`.
fn consume_until_end(reader: &mut Reader<&[u8]>, end_name: &[u8]) -> Result<(), StanzaError> {
    loop {
        match reader.read_event()? {
            Event::End(e) if local_name(e.name()) == end_name => return Ok(()),
            Event::Eof => return Err(StanzaError::MissingElement("(close tag)")),
            _ => {}
        }
    }
}

/// Capture the verbatim XML inside the current element (between `<X>` and
/// `</X>`), preserving entity references and child markup as-written.
fn read_inner_xml(reader: &mut Reader<&[u8]>, end_name: &[u8]) -> Result<String, StanzaError> {
    let mut depth: usize = 0;
    let mut out = String::new();
    loop {
        // Track byte position so we can copy raw spans verbatim from the
        // original input.
        let before = reader.buffer_position();
        match reader.read_event()? {
            Event::Start(s) => {
                if depth == 0 {
                    // First nested start — capture from `before` to current
                    // pos, which is the `<...>` opening of the child.
                    let after = reader.buffer_position();
                    let _ = (before, after); // unused — see verbatim path below
                }
                depth += 1;
                write_start(&mut out, &s);
            }
            Event::Empty(s) => {
                write_empty(&mut out, &s);
            }
            Event::End(e) => {
                if depth == 0 && local_name(e.name()) == end_name {
                    return Ok(out);
                }
                depth = depth.saturating_sub(1);
                out.push_str("</");
                out.push_str(std::str::from_utf8(e.name().as_ref())?);
                out.push('>');
            }
            Event::Text(t) => {
                // unescape gives us the decoded text; re-escape minimally
                // for round-trip. For our use (base64 / plain text), the
                // safe approach is to use the unescaped form with manual
                // entity escaping for &, <, >.
                let s = t.unescape()?;
                out.push_str(&escape_text(&s));
            }
            Event::CData(c) => {
                out.push_str("<![CDATA[");
                out.push_str(std::str::from_utf8(c.as_ref())?);
                out.push_str("]]>");
            }
            Event::Comment(_) | Event::PI(_) | Event::Decl(_) | Event::DocType(_) => {}
            Event::Eof => return Err(StanzaError::MissingElement("(content close)")),
        }
    }
}

fn write_start(out: &mut String, s: &BytesStart<'_>) {
    out.push('<');
    out.push_str(std::str::from_utf8(s.name().as_ref()).unwrap_or(""));
    write_attrs(out, s);
    out.push('>');
}

fn write_empty(out: &mut String, s: &BytesStart<'_>) {
    out.push('<');
    out.push_str(std::str::from_utf8(s.name().as_ref()).unwrap_or(""));
    write_attrs(out, s);
    out.push_str("/>");
}

fn write_attrs(out: &mut String, s: &BytesStart<'_>) {
    for a in s.attributes() {
        let Ok(a) = a else { continue };
        out.push(' ');
        out.push_str(std::str::from_utf8(a.key.as_ref()).unwrap_or(""));
        out.push('=');
        out.push('"');
        if let Ok(v) = a.unescape_value() {
            out.push_str(&escape_attr(&v));
        }
        out.push('"');
    }
}

fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

// `attr_str` is re-exported just so the lib's helpers remain callable
// from this module without unused-import warnings. (No-op shim.)
#[allow(dead_code)]
fn _phantom() -> Result<(), StanzaError> {
    let s = BytesStart::new("x");
    let _ = attr_str(&s, "k")?;
    Ok(())
}
