//! XEP-0384 v0.3 (`eu.siacs.conversations.axolotl`) stanza encoder
//! and parser — the OMEMO 0.3 wire shape.
//!
//! Authored from the public XEP and from the schemas embedded in
//! python-oldmemo's `etree.py` (the schemas are functional facts
//! identical to the wire spec; comments and Rust structure are our
//! own — see ADR-009).
//!
//! Element trees, in canonical encoder order:
//!
//! 1. `<encrypted xmlns='eu.siacs.conversations.axolotl'>` — message
//!    envelope; carries `<header sid='X'>` (multiple `<key rid='Y'
//!    [prekey='true']>BASE64</key>` flat children, then one
//!    `<iv>BASE64</iv>` for the AES-128-GCM IV) plus an optional
//!    `<payload>BASE64</payload>`. There is no per-JID grouping —
//!    OMEMO 0.3 fans out at the device level.
//! 2. `<bundle xmlns='eu.siacs.conversations.axolotl'>` —
//!    `<signedPreKeyPublic signedPreKeyId='1'>`,
//!    `<signedPreKeySignature>` (64 bytes; bit 7 of byte 63 is
//!    stuffed with the IK sign bit — see [`Bundle`] docs),
//!    `<identityKey>` (33 bytes: `0x05 || curve25519(ed25519_pub)`),
//!    `<prekeys>` containing N `<preKeyPublic preKeyId='K'>`.
//! 3. `<list xmlns='eu.siacs.conversations.axolotl'>` — flat list
//!    of `<device id='K'/>`.
//!
//! All public-key fields on the wire are 33-byte 0x05-prefixed
//! Curve25519 (matching `omemo_oldmemo::serialize_public_key`).

use std::io::Cursor;

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;

use crate::{
    attr_str, b64_decode, b64_encode, local_name, read_text, req_u32_attr, StanzaError,
};

pub const NS: &str = "eu.siacs.conversations.axolotl";

// ---------------------------------------------------------------------------
// Encrypted (`<encrypted>` message body)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    /// Sender device ID.
    pub sid: u32,
    /// Per-recipient-device encrypted key blobs. OMEMO 0.3 has no
    /// per-JID grouping (`<keys jid=...>`); `<key>` elements are
    /// flat children of `<header>`.
    pub keys: Vec<KeyEntry>,
    /// Per-message AES-128-GCM IV (typically 12 bytes; the spec
    /// allows other lengths, but real implementations always use
    /// 12 — see [`crate::axolotl_aead::IV_LEN`]).
    pub iv: Vec<u8>,
    /// AES-128-GCM ciphertext over the body. `None` when this is a
    /// key-only message (no body).
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub rid: u32,
    /// `prekey='true'` on the very first message of a session — the
    /// blob is then a serialised `OMEMOKeyExchange` instead of a
    /// bare `OMEMOAuthenticatedMessage`. (Matches OMEMO 2's `kex`
    /// flag, just under a different attribute name.)
    pub prekey: bool,
    pub data: Vec<u8>,
}

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
        let mut keys: Vec<KeyEntry> = Vec::new();
        let mut iv: Option<Vec<u8>> = None;
        let mut payload: Option<Vec<u8>> = None;

        loop {
            match reader.read_event()? {
                Event::Start(s) => match local_name(s.name()) {
                    b"header" => {
                        sid = Some(req_u32_attr(&s, "sid")?);
                        loop {
                            match reader.read_event()? {
                                Event::Start(ke) if local_name(ke.name()) == b"key" => {
                                    let rid = req_u32_attr(&ke, "rid")?;
                                    let prekey = parse_bool_attr(&ke, "prekey")?;
                                    let txt = read_text(&mut reader, b"key")?;
                                    keys.push(KeyEntry {
                                        rid,
                                        prekey,
                                        data: b64_decode(&txt)?,
                                    });
                                }
                                Event::Empty(ke) if local_name(ke.name()) == b"key" => {
                                    let rid = req_u32_attr(&ke, "rid")?;
                                    let prekey = parse_bool_attr(&ke, "prekey")?;
                                    keys.push(KeyEntry {
                                        rid,
                                        prekey,
                                        data: vec![],
                                    });
                                }
                                Event::Start(ie) if local_name(ie.name()) == b"iv" => {
                                    let txt = read_text(&mut reader, b"iv")?;
                                    iv = Some(b64_decode(&txt)?);
                                }
                                Event::End(e) if local_name(e.name()) == b"header" => break,
                                Event::Eof => return Err(StanzaError::MissingElement("header")),
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
                },
                Event::End(e) if local_name(e.name()) == b"encrypted" => break,
                Event::Eof => return Err(StanzaError::MissingElement("encrypted")),
                _ => {}
            }
        }

        Ok(Self {
            sid: sid.ok_or(StanzaError::MissingAttr("sid"))?,
            keys,
            iv: iv.ok_or(StanzaError::MissingElement("iv"))?,
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

        for k in &self.keys {
            let rid_str = k.rid.to_string();
            let mut key_el = BytesStart::new("key");
            key_el.push_attribute(("rid", rid_str.as_str()));
            if k.prekey {
                key_el.push_attribute(("prekey", "true"));
            }
            w.write_event(Event::Start(key_el.borrow()))?;
            let txt = b64_encode(&k.data);
            w.write_event(Event::Text(BytesText::new(&txt)))?;
            w.write_event(Event::End(BytesEnd::new("key")))?;
        }

        // <iv> goes after all keys (matches python-oldmemo's
        // serialize_message order).
        w.write_event(Event::Start(BytesStart::new("iv")))?;
        let iv_b64 = b64_encode(&self.iv);
        w.write_event(Event::Text(BytesText::new(&iv_b64)))?;
        w.write_event(Event::End(BytesEnd::new("iv")))?;

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

fn parse_bool_attr<'a>(start: &'a BytesStart<'a>, name: &str) -> Result<bool, StanzaError> {
    Ok(match attr_str(start, name)? {
        Some(v) => matches!(v.as_ref(), "true" | "1"),
        None => false,
    })
}

// ---------------------------------------------------------------------------
// Bundle (`<bundle>` published via PEP)
// ---------------------------------------------------------------------------

/// OMEMO 0.3 bundle, in the canonical Ed25519-identity-key view.
///
/// On the wire, the identity key is transported as Curve25519 (no
/// sign bit). To recover the original Ed25519 key, python-oldmemo
/// stuffs the IK's sign bit into bit 7 of byte 63 of the SPK
/// signature (which is otherwise always 0 for a valid Ed25519 sig:
/// `s < q` and `q < 2^253`, so the top bits of the bottom half are
/// reserved). On parse, we extract that bit, clear it, and use it to
/// disambiguate the Ed25519 IK via the Curve→Ed birational map.
///
/// This struct stores the Ed25519 form (32 bytes) for the IK so
/// callers don't have to think about the stuffing; encode/parse
/// move bits around at the wire boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub signed_prekey_id: u32,
    /// 32-byte raw Curve25519 X25519 SPK pub. Encoder applies the
    /// `0x05` prefix on the wire.
    pub signed_prekey_pub: [u8; 32],
    /// 64-byte Ed25519 / XEdDSA signature over `0x05 || spk_pub`
    /// **before** sign-bit-stuffing. The encoder stuffs the IK sign
    /// bit on the way out; the parser unstuffs on the way in.
    pub signed_prekey_sig: [u8; 64],
    /// 32-byte Ed25519 identity-key pub. Encoder converts to
    /// Curve25519 and prefixes `0x05` for the wire.
    pub identity_key_ed: [u8; 32],
    pub prekeys: Vec<PreKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreKey {
    pub id: u32,
    /// 32-byte raw Curve25519 X25519 prekey pub. Encoder applies
    /// the `0x05` prefix on the wire.
    pub pub_key: [u8; 32],
}

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

        let mut spk_id: Option<u32> = None;
        let mut spk_pub_curve_prefixed: Option<Vec<u8>> = None;
        let mut spk_sig_stuffed: Option<Vec<u8>> = None;
        let mut ik_curve_prefixed: Option<Vec<u8>> = None;
        let mut prekeys: Vec<PreKey> = Vec::new();

        loop {
            match reader.read_event()? {
                Event::Start(s) => match local_name(s.name()) {
                    b"signedPreKeyPublic" => {
                        spk_id = Some(req_u32_attr(&s, "signedPreKeyId")?);
                        let txt = read_text(&mut reader, b"signedPreKeyPublic")?;
                        spk_pub_curve_prefixed = Some(b64_decode(&txt)?);
                    }
                    b"signedPreKeySignature" => {
                        let txt = read_text(&mut reader, b"signedPreKeySignature")?;
                        spk_sig_stuffed = Some(b64_decode(&txt)?);
                    }
                    b"identityKey" => {
                        let txt = read_text(&mut reader, b"identityKey")?;
                        ik_curve_prefixed = Some(b64_decode(&txt)?);
                    }
                    b"prekeys" => loop {
                        match reader.read_event()? {
                            Event::Start(pk) if local_name(pk.name()) == b"preKeyPublic" => {
                                let id = req_u32_attr(&pk, "preKeyId")?;
                                let txt = read_text(&mut reader, b"preKeyPublic")?;
                                let raw = strip_curve_prefix(&b64_decode(&txt)?)?;
                                prekeys.push(PreKey { id, pub_key: raw });
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
                },
                Event::End(e) if local_name(e.name()) == b"bundle" => break,
                Event::Eof => return Err(StanzaError::MissingElement("bundle")),
                _ => {}
            }
        }

        let spk_pub_raw =
            strip_curve_prefix(&spk_pub_curve_prefixed.ok_or(StanzaError::MissingElement("signedPreKeyPublic"))?)?;
        let mut sig_stuffed = spk_sig_stuffed.ok_or(StanzaError::MissingElement("signedPreKeySignature"))?;
        if sig_stuffed.len() != 64 {
            return Err(StanzaError::MalformedSignedPreKeySignature(sig_stuffed.len()));
        }
        // Pull the stuffed sign bit off byte 63's bit 7, clear it.
        let set_sign_bit = (sig_stuffed[63] >> 7) & 1 == 1;
        sig_stuffed[63] &= 0x7F;
        let spk_sig: [u8; 64] = sig_stuffed.try_into().expect("len checked");

        let ik_raw =
            strip_curve_prefix(&ik_curve_prefixed.ok_or(StanzaError::MissingElement("identityKey"))?)?;
        let identity_key_ed = omemo_xeddsa::curve25519_pub_to_ed25519_pub(&ik_raw, set_sign_bit);

        Ok(Self {
            signed_prekey_id: spk_id.ok_or(StanzaError::MissingAttr("signedPreKeyId"))?,
            signed_prekey_pub: spk_pub_raw,
            signed_prekey_sig: spk_sig,
            identity_key_ed,
            prekeys,
        })
    }

    pub fn encode(&self) -> Result<String, StanzaError> {
        let mut buf = Vec::new();
        let mut w = Writer::new(Cursor::new(&mut buf));

        let mut bundle_el = BytesStart::new("bundle");
        bundle_el.push_attribute(("xmlns", NS));
        w.write_event(Event::Start(bundle_el.borrow()))?;

        // <signedPreKeyPublic signedPreKeyId='...'>BASE64(0x05||spk_pub)
        let spk_id = self.signed_prekey_id.to_string();
        let mut spk_el = BytesStart::new("signedPreKeyPublic");
        spk_el.push_attribute(("signedPreKeyId", spk_id.as_str()));
        w.write_event(Event::Start(spk_el.borrow()))?;
        let spk_b64 = b64_encode(&prepend_curve_prefix(&self.signed_prekey_pub));
        w.write_event(Event::Text(BytesText::new(&spk_b64)))?;
        w.write_event(Event::End(BytesEnd::new("signedPreKeyPublic")))?;

        // <signedPreKeySignature>BASE64(stuffed sig)</signedPreKeySignature>
        // Stuff the IK sign bit into byte-63 bit-7.
        let mut sig_with_stuffed = self.signed_prekey_sig;
        let ik_sign_bit = (self.identity_key_ed[31] >> 7) & 1;
        // Clear bit 7 first to defend against a bad caller that
        // already set it; it's reserved-zero in a valid Ed25519 sig.
        sig_with_stuffed[63] = (sig_with_stuffed[63] & 0x7F) | (ik_sign_bit << 7);
        w.write_event(Event::Start(BytesStart::new("signedPreKeySignature")))?;
        let sig_b64 = b64_encode(&sig_with_stuffed);
        w.write_event(Event::Text(BytesText::new(&sig_b64)))?;
        w.write_event(Event::End(BytesEnd::new("signedPreKeySignature")))?;

        // <identityKey>BASE64(0x05 || curve25519(ed25519_pub))</identityKey>
        let ik_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(&self.identity_key_ed)?;
        w.write_event(Event::Start(BytesStart::new("identityKey")))?;
        let ik_b64 = b64_encode(&prepend_curve_prefix(&ik_curve));
        w.write_event(Event::Text(BytesText::new(&ik_b64)))?;
        w.write_event(Event::End(BytesEnd::new("identityKey")))?;

        // <prekeys>...</prekeys>
        w.write_event(Event::Start(BytesStart::new("prekeys")))?;
        for pk in &self.prekeys {
            let id_str = pk.id.to_string();
            let mut pk_el = BytesStart::new("preKeyPublic");
            pk_el.push_attribute(("preKeyId", id_str.as_str()));
            w.write_event(Event::Start(pk_el.borrow()))?;
            let pk_b64 = b64_encode(&prepend_curve_prefix(&pk.pub_key));
            w.write_event(Event::Text(BytesText::new(&pk_b64)))?;
            w.write_event(Event::End(BytesEnd::new("preKeyPublic")))?;
        }
        w.write_event(Event::End(BytesEnd::new("prekeys")))?;

        w.write_event(Event::End(BytesEnd::new("bundle")))?;
        Ok(String::from_utf8(buf).expect("utf-8"))
    }
}

fn prepend_curve_prefix(raw: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x05;
    out[1..].copy_from_slice(raw);
    out
}

fn strip_curve_prefix(prefixed: &[u8]) -> Result<[u8; 32], StanzaError> {
    if prefixed.len() != 33 {
        return Err(StanzaError::BadEncodedPubkeyLength(prefixed.len()));
    }
    if prefixed[0] != 0x05 {
        return Err(StanzaError::BadPubkeyPrefix(prefixed[0]));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&prefixed[1..]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// DeviceList (`<list>` published via PEP).
// ---------------------------------------------------------------------------

/// OMEMO 0.3 device list — a flat set of device IDs. The 0.3 spec
/// has no device-label support (python-oldmemo silently drops
/// labels on serialisation), so we don't carry one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceList {
    pub devices: Vec<u32>,
}

impl DeviceList {
    pub fn parse(xml: &str) -> Result<Self, StanzaError> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        loop {
            match reader.read_event()? {
                Event::Decl(_) | Event::DocType(_) | Event::Comment(_) | Event::PI(_) => {}
                Event::Start(s) if local_name(s.name()) == b"list" => break,
                Event::Empty(s) if local_name(s.name()) == b"list" => {
                    let _ = s;
                    return Ok(DeviceList::default());
                }
                Event::Eof => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "list",
                        got: "(eof)".into(),
                    })
                }
                ev => {
                    return Err(StanzaError::UnexpectedRoot {
                        expected: "list",
                        got: format!("{:?}", ev),
                    })
                }
            }
        }

        let mut devices: Vec<u32> = Vec::new();
        loop {
            match reader.read_event()? {
                Event::Start(s) | Event::Empty(s) if local_name(s.name()) == b"device" => {
                    devices.push(req_u32_attr(&s, "id")?);
                    // For Event::Start we also need to consume the
                    // closing tag, but quick-xml will produce that as
                    // a separate Event::End on the next iteration; we
                    // ignore it via the catch-all branch below.
                }
                Event::End(e) if local_name(e.name()) == b"list" => break,
                Event::Eof => return Err(StanzaError::MissingElement("list")),
                _ => {}
            }
        }
        Ok(Self { devices })
    }

    pub fn encode(&self) -> Result<String, StanzaError> {
        let mut buf = Vec::new();
        let mut w = Writer::new(Cursor::new(&mut buf));

        let mut list_el = BytesStart::new("list");
        list_el.push_attribute(("xmlns", NS));
        w.write_event(Event::Start(list_el.borrow()))?;

        for id in &self.devices {
            let id_str = id.to_string();
            let mut dev = BytesStart::new("device");
            dev.push_attribute(("id", id_str.as_str()));
            w.write_event(Event::Empty(dev.borrow()))?;
        }

        w.write_event(Event::End(BytesEnd::new("list")))?;
        Ok(String::from_utf8(buf).expect("utf-8"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_round_trip_with_payload() {
        let e = Encrypted {
            sid: 1001,
            keys: vec![
                KeyEntry {
                    rid: 2002,
                    prekey: true,
                    data: vec![1, 2, 3, 4],
                },
                KeyEntry {
                    rid: 2003,
                    prekey: false,
                    data: vec![5, 6, 7, 8, 9, 10],
                },
            ],
            iv: vec![0xA0; 12],
            payload: Some(vec![0xB0; 24]),
        };
        let xml = e.encode().unwrap();
        // Spot-check shape: namespace, sid, prekey attribute,
        // canonical iv-after-keys ordering.
        assert!(xml.contains("xmlns=\"eu.siacs.conversations.axolotl\""));
        assert!(xml.contains("sid=\"1001\""));
        assert!(xml.contains("rid=\"2002\""));
        assert!(xml.contains("prekey=\"true\""));
        let ki = xml.find("<key").unwrap();
        let ii = xml.find("<iv>").unwrap();
        assert!(ki < ii, "<iv> must come after <key>s");

        let parsed = Encrypted::parse(&xml).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn encrypted_key_only_message() {
        let e = Encrypted {
            sid: 7,
            keys: vec![KeyEntry {
                rid: 8,
                prekey: false,
                data: vec![1; 16],
            }],
            iv: vec![0xCC; 12],
            payload: None,
        };
        let xml = e.encode().unwrap();
        assert!(!xml.contains("<payload"));
        let parsed = Encrypted::parse(&xml).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn encrypted_three_recipients_round_trip() {
        let e = Encrypted {
            sid: 1,
            keys: (10..13)
                .map(|rid| KeyEntry {
                    rid,
                    prekey: rid == 10,
                    data: vec![rid as u8; 8],
                })
                .collect(),
            iv: vec![0u8; 12],
            payload: Some(vec![0xEEu8; 32]),
        };
        let xml = e.encode().unwrap();
        let parsed = Encrypted::parse(&xml).unwrap();
        assert_eq!(parsed.keys.len(), 3);
        assert_eq!(parsed, e);
    }

    #[test]
    fn encrypted_parse_tolerates_iv_before_keys() {
        // python-oldmemo's schema declares <xs:all> for <header>'s
        // children, which means any order is valid. Make sure our
        // parser handles iv-first too even though we always emit
        // iv-last.
        let xml = "\
            <encrypted xmlns=\"eu.siacs.conversations.axolotl\">\
              <header sid=\"5\">\
                <iv>YWFhYWFhYWFhYWFh</iv>\
                <key rid=\"6\">AQID</key>\
              </header>\
            </encrypted>";
        let parsed = Encrypted::parse(xml).unwrap();
        assert_eq!(parsed.sid, 5);
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].rid, 6);
        assert_eq!(parsed.iv, b"aaaaaaaaaaaa");
    }

    #[test]
    fn bundle_round_trip_with_sign_bit_stuffing() {
        // Use a real Ed25519 key so the curve→ed conversion has
        // something to disambiguate. The seed ensures determinism.
        let seed = [0x42u8; 32];
        let ik_priv = omemo_xeddsa::seed_to_priv(&seed);
        let ik_ed = omemo_xeddsa::priv_to_ed25519_pub(&ik_priv);

        // Plausible 64-byte sig with bit-7 of byte 63 left clear (as
        // a valid Ed25519 sig would have it).
        let mut sig = [0u8; 64];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        sig[63] &= 0x7F;

        let b = Bundle {
            signed_prekey_id: 99,
            signed_prekey_pub: [0xABu8; 32],
            signed_prekey_sig: sig,
            identity_key_ed: ik_ed,
            prekeys: vec![
                PreKey {
                    id: 1,
                    pub_key: [0x10u8; 32],
                },
                PreKey {
                    id: 2,
                    pub_key: [0x20u8; 32],
                },
            ],
        };
        let xml = b.encode().unwrap();
        // The wire <identityKey> is Curve25519 + 0x05 prefix, NOT
        // the raw Ed25519. After base64-decode the byte before that
        // has different content than ik_ed.
        assert!(xml.contains("xmlns=\"eu.siacs.conversations.axolotl\""));
        let parsed = Bundle::parse(&xml).unwrap();
        assert_eq!(parsed, b, "round-trip recovers the Ed25519 IK");
    }

    #[test]
    fn bundle_parse_rejects_wrong_pubkey_prefix() {
        // Replace the 0x05 byte at start of identityKey base64 with
        // 0x06 by hand-building an XML.
        let bad_b64 = b64_encode(&[0x06u8; 33]);
        let xml = format!(
            "<bundle xmlns=\"eu.siacs.conversations.axolotl\">\
               <signedPreKeyPublic signedPreKeyId=\"1\">{}</signedPreKeyPublic>\
               <signedPreKeySignature>{}</signedPreKeySignature>\
               <identityKey>{}</identityKey>\
               <prekeys></prekeys>\
             </bundle>",
            b64_encode(&prepend_curve_prefix(&[1u8; 32])),
            b64_encode(&[0u8; 64]),
            bad_b64
        );
        match Bundle::parse(&xml) {
            Err(StanzaError::BadPubkeyPrefix(0x06)) => {}
            other => panic!("expected BadPubkeyPrefix, got {other:?}"),
        }
    }

    #[test]
    fn device_list_round_trip() {
        let dl = DeviceList {
            devices: vec![1, 4711, 0xDEAD_BEEF],
        };
        let xml = dl.encode().unwrap();
        assert!(xml.contains("<list xmlns=\"eu.siacs.conversations.axolotl\">"));
        let parsed = DeviceList::parse(&xml).unwrap();
        assert_eq!(parsed, dl);
    }

    #[test]
    fn device_list_empty() {
        let dl = DeviceList::default();
        let xml = dl.encode().unwrap();
        let parsed = DeviceList::parse(&xml).unwrap();
        assert_eq!(parsed.devices, Vec::<u32>::new());
    }
}
