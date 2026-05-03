//! XEP-0384 v0.9 stanza encoder/decoder for OMEMO 2 + XEP-0420 SCE envelope.
//!
//! Element trees:
//!
//! 1. `<encrypted xmlns='urn:xmpp:omemo:2'>` — the message envelope
//!    containing per-recipient encrypted keys + an optional SCE payload.
//! 2. `<bundle xmlns='urn:xmpp:omemo:2'>` — published per device on PEP.
//! 3. `<devices xmlns='urn:xmpp:omemo:2'>` — per-account device list on PEP.
//! 4. `<envelope xmlns='urn:xmpp:sce:1'>` — XEP-0420 Stanza Content
//!    Encryption envelope. See [`sce`].
//!
//! Decoding tolerates any attribute order; encoding emits attributes in a
//! canonical order so that round-trip output is byte-stable. Element key
//! material is base64-encoded on the wire (RFC 4648, no line wrapping).

pub mod axolotl_aead;
pub mod axolotl_stanza;
pub mod sce;

use std::borrow::Cow;
use std::io::Cursor;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::name::QName;
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;
use thiserror::Error;

pub const NS: &str = "urn:xmpp:omemo:2";

#[derive(Debug, Error)]
pub enum StanzaError {
    #[error("xml read error: {0}")]
    XmlRead(#[from] quick_xml::Error),
    #[error("xml attribute error: {0}")]
    XmlAttr(#[from] quick_xml::events::attributes::AttrError),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("expected u32 attribute {attr:?}, got {got:?}")]
    NotU32 { attr: String, got: String },
    #[error("missing required attribute {0:?}")]
    MissingAttr(&'static str),
    #[error("missing required element <{0}>")]
    MissingElement(&'static str),
    #[error("expected root <{expected}>, got <{got}>")]
    UnexpectedRoot { expected: &'static str, got: String },
    #[error("unexpected element <{0}>")]
    UnexpectedElement(String),
    #[error("xml utf-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("expected 33-byte 0x05-prefixed Curve25519 pubkey on the wire; got {0} bytes")]
    BadEncodedPubkeyLength(usize),
    #[error("expected 0x05 Curve25519 pubkey prefix; got 0x{0:02x}")]
    BadPubkeyPrefix(u8),
    #[error("signedPreKeySignature must be 64 bytes; got {0}")]
    MalformedSignedPreKeySignature(usize),
    #[error("xeddsa: {0}")]
    XEdDsa(omemo_xeddsa::XEdDsaError),
}

impl From<omemo_xeddsa::XEdDsaError> for StanzaError {
    fn from(e: omemo_xeddsa::XEdDsaError) -> Self {
        StanzaError::XEdDsa(e)
    }
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    /// Sender device ID.
    pub sid: u32,
    pub keys: Vec<KeysGroup>,
    /// Optional SCE-encrypted payload. `None` means "key-only" message.
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysGroup {
    pub jid: String,
    pub keys: Vec<Key>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub rid: u32,
    /// True only on the very first message of a session (KEX).
    pub kex: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub spk: SignedPreKey,
    /// SPK signature.
    pub spks: Vec<u8>,
    /// Identity key (Ed25519 form for OMEMO 2).
    pub ik: Vec<u8>,
    pub prekeys: Vec<PreKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPreKey {
    pub id: u32,
    pub pub_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreKey {
    pub id: u32,
    pub pub_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceList {
    pub devices: Vec<Device>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: u32,
    pub label: Option<String>,
    /// XEdDSA signature over `label`, base64 on the wire. Only present
    /// when `label` is set; the spec requires a present `label` to be
    /// signed (XEP-0384 v0.9 §5.3.1) so other devices can detect
    /// tampering.
    pub labelsig: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

pub(crate) fn attr_str<'a>(
    start: &'a BytesStart<'a>,
    name: &str,
) -> Result<Option<Cow<'a, str>>, StanzaError> {
    for a in start.attributes() {
        let a = a?;
        if a.key == QName(name.as_bytes()) {
            return Ok(Some(a.unescape_value()?));
        }
    }
    Ok(None)
}

pub(crate) fn req_attr<'a>(
    start: &'a BytesStart<'a>,
    name: &'static str,
) -> Result<Cow<'a, str>, StanzaError> {
    attr_str(start, name)?.ok_or(StanzaError::MissingAttr(name))
}

pub(crate) fn parse_u32(name: &'static str, value: &str) -> Result<u32, StanzaError> {
    value.parse::<u32>().map_err(|_| StanzaError::NotU32 {
        attr: name.to_string(),
        got: value.to_string(),
    })
}

pub(crate) fn req_u32_attr<'a>(
    start: &'a BytesStart<'a>,
    name: &'static str,
) -> Result<u32, StanzaError> {
    parse_u32(name, &req_attr(start, name)?)
}

/// Read text content of the current element until its end tag.
pub(crate) fn read_text(
    reader: &mut Reader<&[u8]>,
    end_name: &[u8],
) -> Result<String, StanzaError> {
    let mut buf = String::new();
    loop {
        match reader.read_event()? {
            Event::Text(t) => buf.push_str(&t.unescape()?),
            Event::CData(c) => buf.push_str(std::str::from_utf8(c.as_ref())?),
            Event::End(e) if local_name(e.name()) == end_name => return Ok(buf),
            Event::Eof => return Err(StanzaError::MissingElement("(text close)")),
            _ => {}
        }
    }
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, StanzaError> {
    Ok(B64.decode(s.trim().as_bytes())?)
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub(crate) fn local_name<'a>(qname: QName<'a>) -> &'a [u8] {
    let full: &'a [u8] = qname.0;
    if let Some(idx) = full.iter().position(|&b| b == b':') {
        &full[idx + 1..]
    } else {
        full
    }
}

// ---------------------------------------------------------------------------
// Encrypted
// ---------------------------------------------------------------------------

impl Encrypted {
    pub fn parse(xml: &str) -> Result<Self, StanzaError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        loop {
            match reader.read_event()? {
                Event::Decl(_) | Event::DocType(_) | Event::Comment(_) | Event::PI(_) => {}
                Event::Start(s) if local_name(s.name()) == b"encrypted" => break,
                Event::Eof => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "encrypted",
                        got: "(eof)".into(),
                    })
                }
                ev => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "encrypted",
                        got: format!("{:?}", ev),
                    })
                }
            }
        }

        let mut sid: Option<u32> = None;
        let mut keys: Vec<KeysGroup> = Vec::new();
        let mut payload: Option<Vec<u8>> = None;

        loop {
            match reader.read_event()? {
                Event::Start(s) => {
                    let n = local_name(s.name()).to_vec();
                    match n.as_slice() {
                        b"header" => {
                            sid = Some(req_u32_attr(&s, "sid")?);
                            loop {
                                match reader.read_event()? {
                                    Event::Start(ks) if local_name(ks.name()) == b"keys" => {
                                        let jid = req_attr(&ks, "jid")?.into_owned();
                                        let mut group_keys: Vec<Key> = Vec::new();
                                        loop {
                                            match reader.read_event()? {
                                                Event::Start(ke)
                                                    if local_name(ke.name()) == b"key" =>
                                                {
                                                    let rid = req_u32_attr(&ke, "rid")?;
                                                    let kex = match attr_str(&ke, "kex")? {
                                                        Some(v) => {
                                                            matches!(v.as_ref(), "true" | "1")
                                                        }
                                                        None => false,
                                                    };
                                                    let txt = read_text(&mut reader, b"key")?;
                                                    group_keys.push(Key {
                                                        rid,
                                                        kex,
                                                        data: b64_decode(&txt)?,
                                                    });
                                                }
                                                Event::Empty(ke)
                                                    if local_name(ke.name()) == b"key" =>
                                                {
                                                    let rid = req_u32_attr(&ke, "rid")?;
                                                    let kex = match attr_str(&ke, "kex")? {
                                                        Some(v) => {
                                                            matches!(v.as_ref(), "true" | "1")
                                                        }
                                                        None => false,
                                                    };
                                                    group_keys.push(Key {
                                                        rid,
                                                        kex,
                                                        data: vec![],
                                                    });
                                                }
                                                Event::End(e)
                                                    if local_name(e.name()) == b"keys" =>
                                                {
                                                    break;
                                                }
                                                Event::Eof => {
                                                    return Err(StanzaError::MissingElement("keys"))
                                                }
                                                _ => {}
                                            }
                                        }
                                        keys.push(KeysGroup {
                                            jid,
                                            keys: group_keys,
                                        });
                                    }
                                    Event::End(e) if local_name(e.name()) == b"header" => {
                                        break;
                                    }
                                    Event::Eof => {
                                        return Err(StanzaError::MissingElement("header"))
                                    }
                                    _ => {}
                                }
                            }
                        }
                        b"payload" => {
                            let txt = read_text(&mut reader, b"payload")?;
                            payload = Some(b64_decode(&txt)?);
                        }
                        other => {
                            return Err(StanzaError::UnexpectedElement(
                                String::from_utf8_lossy(other).into_owned(),
                            ))
                        }
                    }
                }
                Event::End(e) if local_name(e.name()) == b"encrypted" => break,
                Event::Eof => return Err(StanzaError::MissingElement("encrypted")),
                _ => {}
            }
        }

        Ok(Self {
            sid: sid.ok_or(StanzaError::MissingAttr("sid"))?,
            keys,
            payload,
        })
    }

    pub fn encode(&self) -> Result<String, StanzaError> {
        let mut buf = Vec::new();
        let mut w = Writer::new(Cursor::new(&mut buf));

        let mut enc = BytesStart::new("encrypted");
        enc.push_attribute(("xmlns", NS));
        w.write_event(Event::Start(enc.borrow()))?;

        let mut hdr = BytesStart::new("header");
        let sid_str = self.sid.to_string();
        hdr.push_attribute(("sid", sid_str.as_str()));
        w.write_event(Event::Start(hdr.borrow()))?;

        for kg in &self.keys {
            let mut keys_el = BytesStart::new("keys");
            keys_el.push_attribute(("jid", kg.jid.as_str()));
            w.write_event(Event::Start(keys_el.borrow()))?;
            for k in &kg.keys {
                let rid_str = k.rid.to_string();
                let mut key_el = BytesStart::new("key");
                key_el.push_attribute(("rid", rid_str.as_str()));
                if k.kex {
                    key_el.push_attribute(("kex", "true"));
                }
                w.write_event(Event::Start(key_el.borrow()))?;
                let txt = b64_encode(&k.data);
                w.write_event(Event::Text(BytesText::new(&txt)))?;
                w.write_event(Event::End(BytesEnd::new("key")))?;
            }
            w.write_event(Event::End(BytesEnd::new("keys")))?;
        }
        w.write_event(Event::End(BytesEnd::new("header")))?;

        if let Some(payload) = &self.payload {
            w.write_event(Event::Start(BytesStart::new("payload")))?;
            let txt = b64_encode(payload);
            w.write_event(Event::Text(BytesText::new(&txt)))?;
            w.write_event(Event::End(BytesEnd::new("payload")))?;
        }

        w.write_event(Event::End(BytesEnd::new("encrypted")))?;

        Ok(String::from_utf8(buf).expect("quick-xml emits valid utf-8"))
    }
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

impl Bundle {
    pub fn parse(xml: &str) -> Result<Self, StanzaError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        loop {
            match reader.read_event()? {
                Event::Decl(_) | Event::DocType(_) | Event::Comment(_) | Event::PI(_) => {}
                Event::Start(s) if local_name(s.name()) == b"bundle" => break,
                Event::Eof => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "bundle",
                        got: "(eof)".into(),
                    })
                }
                ev => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "bundle",
                        got: format!("{:?}", ev),
                    })
                }
            }
        }

        let mut spk: Option<SignedPreKey> = None;
        let mut spks: Option<Vec<u8>> = None;
        let mut ik: Option<Vec<u8>> = None;
        let mut prekeys: Vec<PreKey> = Vec::new();

        loop {
            match reader.read_event()? {
                Event::Start(s) => {
                    let n = local_name(s.name()).to_vec();
                    match n.as_slice() {
                        b"spk" => {
                            let id = req_u32_attr(&s, "id")?;
                            let txt = read_text(&mut reader, b"spk")?;
                            spk = Some(SignedPreKey {
                                id,
                                pub_key: b64_decode(&txt)?,
                            });
                        }
                        b"spks" => {
                            let txt = read_text(&mut reader, b"spks")?;
                            spks = Some(b64_decode(&txt)?);
                        }
                        b"ik" => {
                            let txt = read_text(&mut reader, b"ik")?;
                            ik = Some(b64_decode(&txt)?);
                        }
                        b"prekeys" => loop {
                            match reader.read_event()? {
                                Event::Start(pk) if local_name(pk.name()) == b"pk" => {
                                    let id = req_u32_attr(&pk, "id")?;
                                    let txt = read_text(&mut reader, b"pk")?;
                                    prekeys.push(PreKey {
                                        id,
                                        pub_key: b64_decode(&txt)?,
                                    });
                                }
                                Event::End(e) if local_name(e.name()) == b"prekeys" => break,
                                Event::Eof => return Err(StanzaError::MissingElement("prekeys")),
                                _ => {}
                            }
                        },
                        other => {
                            return Err(StanzaError::UnexpectedElement(
                                String::from_utf8_lossy(other).into_owned(),
                            ))
                        }
                    }
                }
                Event::End(e) if local_name(e.name()) == b"bundle" => break,
                Event::Eof => return Err(StanzaError::MissingElement("bundle")),
                _ => {}
            }
        }

        Ok(Self {
            spk: spk.ok_or(StanzaError::MissingElement("spk"))?,
            spks: spks.ok_or(StanzaError::MissingElement("spks"))?,
            ik: ik.ok_or(StanzaError::MissingElement("ik"))?,
            prekeys,
        })
    }

    pub fn encode(&self) -> Result<String, StanzaError> {
        let mut buf = Vec::new();
        let mut w = Writer::new(Cursor::new(&mut buf));

        let mut bundle_el = BytesStart::new("bundle");
        bundle_el.push_attribute(("xmlns", NS));
        w.write_event(Event::Start(bundle_el.borrow()))?;

        let spk_id = self.spk.id.to_string();
        let mut spk_el = BytesStart::new("spk");
        spk_el.push_attribute(("id", spk_id.as_str()));
        w.write_event(Event::Start(spk_el.borrow()))?;
        let spk_b64 = b64_encode(&self.spk.pub_key);
        w.write_event(Event::Text(BytesText::new(&spk_b64)))?;
        w.write_event(Event::End(BytesEnd::new("spk")))?;

        w.write_event(Event::Start(BytesStart::new("spks")))?;
        let spks_b64 = b64_encode(&self.spks);
        w.write_event(Event::Text(BytesText::new(&spks_b64)))?;
        w.write_event(Event::End(BytesEnd::new("spks")))?;

        w.write_event(Event::Start(BytesStart::new("ik")))?;
        let ik_b64 = b64_encode(&self.ik);
        w.write_event(Event::Text(BytesText::new(&ik_b64)))?;
        w.write_event(Event::End(BytesEnd::new("ik")))?;

        w.write_event(Event::Start(BytesStart::new("prekeys")))?;
        for pk in &self.prekeys {
            let id_str = pk.id.to_string();
            let mut pk_el = BytesStart::new("pk");
            pk_el.push_attribute(("id", id_str.as_str()));
            w.write_event(Event::Start(pk_el.borrow()))?;
            let pk_b64 = b64_encode(&pk.pub_key);
            w.write_event(Event::Text(BytesText::new(&pk_b64)))?;
            w.write_event(Event::End(BytesEnd::new("pk")))?;
        }
        w.write_event(Event::End(BytesEnd::new("prekeys")))?;

        w.write_event(Event::End(BytesEnd::new("bundle")))?;
        Ok(String::from_utf8(buf).expect("utf-8"))
    }
}

// ---------------------------------------------------------------------------
// DeviceList
// ---------------------------------------------------------------------------

impl DeviceList {
    pub fn parse(xml: &str) -> Result<Self, StanzaError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        loop {
            match reader.read_event()? {
                Event::Decl(_) | Event::DocType(_) | Event::Comment(_) | Event::PI(_) => {}
                Event::Start(s) if local_name(s.name()) == b"devices" => break,
                Event::Empty(s) if local_name(s.name()) == b"devices" => {
                    let _ = s;
                    return Ok(DeviceList { devices: vec![] });
                }
                Event::Eof => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "devices",
                        got: "(eof)".into(),
                    })
                }
                ev => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "devices",
                        got: format!("{:?}", ev),
                    })
                }
            }
        }

        let mut devices: Vec<Device> = Vec::new();
        loop {
            match reader.read_event()? {
                Event::Start(s) | Event::Empty(s) if local_name(s.name()) == b"device" => {
                    let id = req_u32_attr(&s, "id")?;
                    let label = attr_str(&s, "label")?.map(|c| c.into_owned());
                    let labelsig = match attr_str(&s, "labelsig")? {
                        Some(v) => Some(b64_decode(v.as_ref())?),
                        None => None,
                    };
                    devices.push(Device {
                        id,
                        label,
                        labelsig,
                    });
                }
                Event::End(e) if local_name(e.name()) == b"devices" => break,
                Event::Eof => return Err(StanzaError::MissingElement("devices")),
                _ => {}
            }
        }

        Ok(Self { devices })
    }

    pub fn encode(&self) -> Result<String, StanzaError> {
        let mut buf = Vec::new();
        let mut w = Writer::new(Cursor::new(&mut buf));

        let mut list_el = BytesStart::new("devices");
        list_el.push_attribute(("xmlns", NS));
        w.write_event(Event::Start(list_el.borrow()))?;

        for d in &self.devices {
            let id_str = d.id.to_string();
            let mut dev = BytesStart::new("device");
            dev.push_attribute(("id", id_str.as_str()));
            if let Some(label) = &d.label {
                dev.push_attribute(("label", label.as_str()));
            }
            let sig_b64 = d.labelsig.as_ref().map(|s| b64_encode(s));
            if let Some(sig) = &sig_b64 {
                dev.push_attribute(("labelsig", sig.as_str()));
            }
            w.write_event(Event::Empty(dev.borrow()))?;
        }

        w.write_event(Event::End(BytesEnd::new("devices")))?;
        Ok(String::from_utf8(buf).expect("utf-8"))
    }
}
