//! Westron canonical wire format (`urn:xmpp:omemo:westron:1`).
//!
//! Strict superset of the OMEMO 2 stanza shape with a signed `<caps>` element.
//! See SPEC §4.3.
//!
//!   <encrypted xmlns="urn:xmpp:omemo:westron:1">
//!     <header sid="...">
//!       <keys jid="...">
//!         <key rid="..." [kex="true"]>BASE64</key>
//!       </keys>
//!       <caps speaks-omemo-2="..." speaks-omemo-03="..." ts="..." sig="BASE64"/>
//!     </header>
//!     <payload>BASE64</payload>
//!   </encrypted>
use crate::signed_caps::SignedCaps;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;
use std::io::Cursor;
use thiserror::Error;

pub const NS: &str = "urn:xmpp:omemo:westron:1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WestronKey {
    pub rid: u32,
    pub kex: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WestronKeysGroup {
    pub jid: String,
    pub keys: Vec<WestronKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WestronStanza {
    pub sid: u32,
    pub groups: Vec<WestronKeysGroup>,
    pub payload: Vec<u8>,
    pub caps: SignedCaps,
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("XML parse error: {0}")]
    Xml(String),
    #[error("namespace mismatch: expected {NS}, got {0}")]
    Namespace(String),
    #[error("missing required element: {0}")]
    Missing(&'static str),
    #[error("malformed integer: {0}")]
    BadInt(&'static str),
    #[error("base64 decode error")]
    Base64,
}

impl From<quick_xml::Error> for WireError {
    fn from(e: quick_xml::Error) -> Self {
        WireError::Xml(e.to_string())
    }
}
impl From<base64::DecodeError> for WireError {
    fn from(_: base64::DecodeError) -> Self {
        WireError::Base64
    }
}

pub fn encode(stanza: &WestronStanza) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new(Cursor::new(Vec::new()));

    let mut root = BytesStart::new("encrypted");
    root.push_attribute(("xmlns", NS));
    w.write_event(Event::Start(root))?;

    let sid = stanza.sid.to_string();
    let mut header = BytesStart::new("header");
    header.push_attribute(("sid", sid.as_str()));
    w.write_event(Event::Start(header))?;

    for g in &stanza.groups {
        let mut ks = BytesStart::new("keys");
        ks.push_attribute(("jid", g.jid.as_str()));
        w.write_event(Event::Start(ks))?;
        for k in &g.keys {
            let rid = k.rid.to_string();
            let mut key = BytesStart::new("key");
            key.push_attribute(("rid", rid.as_str()));
            if k.kex {
                key.push_attribute(("kex", "true"));
            }
            let data_b64 = B64.encode(&k.data);
            w.write_event(Event::Start(key))?;
            w.write_event(Event::Text(BytesText::new(&data_b64)))?;
            w.write_event(Event::End(BytesEnd::new("key")))?;
        }
        w.write_event(Event::End(BytesEnd::new("keys")))?;
    }

    let ts = stanza.caps.ts.to_string();
    let sig_b64 = B64.encode(stanza.caps.sig);
    let mut caps_el = BytesStart::new("caps");
    caps_el.push_attribute((
        "speaks-omemo-2",
        if stanza.caps.also_speaks_omemo_2 { "true" } else { "false" },
    ));
    caps_el.push_attribute((
        "speaks-omemo-03",
        if stanza.caps.also_speaks_omemo_03 { "true" } else { "false" },
    ));
    caps_el.push_attribute(("ts", ts.as_str()));
    caps_el.push_attribute(("sig", sig_b64.as_str()));
    w.write_event(Event::Empty(caps_el))?;

    w.write_event(Event::End(BytesEnd::new("header")))?;

    let payload_b64 = B64.encode(&stanza.payload);
    w.write_event(Event::Start(BytesStart::new("payload")))?;
    w.write_event(Event::Text(BytesText::new(&payload_b64)))?;
    w.write_event(Event::End(BytesEnd::new("payload")))?;

    w.write_event(Event::End(BytesEnd::new("encrypted")))?;
    Ok(w.into_inner().into_inner())
}

pub fn decode(xml: &[u8]) -> Result<WestronStanza, WireError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    // State machine — light implementation focused on the spec's schema.
    let mut sid: Option<u32> = None;
    let mut groups: Vec<WestronKeysGroup> = Vec::new();
    let mut current_group: Option<WestronKeysGroup> = None;
    let mut current_key: Option<WestronKey> = None;
    let mut payload: Option<Vec<u8>> = None;
    let mut caps: Option<SignedCaps> = None;

    // Track text buffer for the current element
    let mut text_buf = String::new();
    let mut in_key_text = false;
    let mut in_payload_text = false;

    let mut buf = Vec::new();
    let mut root_seen = false;
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) | Event::Empty(e) => {
                let name = e.name().0.to_vec();
                let name_str = std::str::from_utf8(&name).map_err(|_| WireError::Missing("name"))?;
                match name_str {
                    "encrypted" => {
                        if !root_seen {
                            let mut ns = String::new();
                            for a in e.attributes() {
                                let a = a.map_err(|e| WireError::Xml(e.to_string()))?;
                                if a.key.0 == b"xmlns" {
                                    ns = std::str::from_utf8(&a.value)
                                        .map_err(|_| WireError::Namespace("".into()))?
                                        .to_string();
                                }
                            }
                            if ns != NS {
                                return Err(WireError::Namespace(ns));
                            }
                            root_seen = true;
                        }
                    }
                    "header" => {
                        for a in e.attributes() {
                            let a = a.map_err(|e| WireError::Xml(e.to_string()))?;
                            if a.key.0 == b"sid" {
                                let s = std::str::from_utf8(&a.value).map_err(|_| WireError::BadInt("sid"))?;
                                sid = Some(s.parse().map_err(|_| WireError::BadInt("sid"))?);
                            }
                        }
                    }
                    "keys" => {
                        let mut jid = String::new();
                        for a in e.attributes() {
                            let a = a.map_err(|e| WireError::Xml(e.to_string()))?;
                            if a.key.0 == b"jid" {
                                jid = std::str::from_utf8(&a.value)
                                    .map_err(|_| WireError::Missing("jid"))?
                                    .to_string();
                            }
                        }
                        current_group = Some(WestronKeysGroup { jid, keys: vec![] });
                    }
                    "key" => {
                        let mut rid = 0u32;
                        let mut kex = false;
                        for a in e.attributes() {
                            let a = a.map_err(|e| WireError::Xml(e.to_string()))?;
                            match a.key.0 {
                                b"rid" => {
                                    let s = std::str::from_utf8(&a.value).map_err(|_| WireError::BadInt("rid"))?;
                                    rid = s.parse().map_err(|_| WireError::BadInt("rid"))?;
                                }
                                b"kex" => {
                                    kex = a.value.as_ref() == b"true";
                                }
                                _ => {}
                            }
                        }
                        current_key = Some(WestronKey { rid, kex, data: vec![] });
                        in_key_text = true;
                        text_buf.clear();
                    }
                    "caps" => {
                        let mut sp2 = false;
                        let mut sp03 = false;
                        let mut ts = 0i64;
                        let mut sig = [0u8; 64];
                        let mut sid_for_caps = sid.unwrap_or(0);
                        let _ = &mut sid_for_caps;
                        for a in e.attributes() {
                            let a = a.map_err(|e| WireError::Xml(e.to_string()))?;
                            match a.key.0 {
                                b"speaks-omemo-2" => sp2 = a.value.as_ref() == b"true",
                                b"speaks-omemo-03" => sp03 = a.value.as_ref() == b"true",
                                b"ts" => {
                                    let s = std::str::from_utf8(&a.value).map_err(|_| WireError::BadInt("ts"))?;
                                    ts = s.parse().unwrap_or(0);
                                }
                                b"sig" => {
                                    let s = std::str::from_utf8(&a.value).map_err(|_| WireError::Base64)?;
                                    let raw = B64.decode(s).map_err(|_| WireError::Base64)?;
                                    if raw.len() == 64 {
                                        sig.copy_from_slice(&raw);
                                    }
                                }
                                _ => {}
                            }
                        }
                        caps = Some(SignedCaps {
                            also_speaks_omemo_2: sp2,
                            also_speaks_omemo_03: sp03,
                            sid: sid.unwrap_or(0),
                            ts,
                            sig,
                        });
                    }
                    "payload" => {
                        in_payload_text = true;
                        text_buf.clear();
                    }
                    _ => {}
                }
            }
            Event::Text(t) => {
                if in_key_text || in_payload_text {
                    text_buf.push_str(&t.unescape().map_err(|e| WireError::Xml(e.to_string()))?);
                }
            }
            Event::End(e) => {
                let name = e.name().0.to_vec();
                match std::str::from_utf8(&name).map_err(|_| WireError::Missing("name"))? {
                    "key" => {
                        if in_key_text {
                            if let Some(mut k) = current_key.take() {
                                k.data = B64.decode(text_buf.as_bytes()).map_err(|_| WireError::Base64)?;
                                if let Some(g) = current_group.as_mut() {
                                    g.keys.push(k);
                                }
                            }
                            in_key_text = false;
                        }
                    }
                    "keys" => {
                        if let Some(g) = current_group.take() {
                            groups.push(g);
                        }
                    }
                    "payload" => {
                        if in_payload_text {
                            payload = Some(B64.decode(text_buf.as_bytes()).map_err(|_| WireError::Base64)?);
                            in_payload_text = false;
                        }
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    let sid = sid.ok_or(WireError::Missing("sid"))?;
    let payload = payload.unwrap_or_default();
    let caps = caps.unwrap_or(SignedCaps {
        also_speaks_omemo_2: false,
        also_speaks_omemo_03: false,
        sid,
        ts: 0,
        sig: [0u8; 64],
    });
    Ok(WestronStanza {
        sid,
        groups,
        payload,
        caps,
    })
}
