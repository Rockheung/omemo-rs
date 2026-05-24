//! tokio-xmpp `<message>` send / receive glue for the OMEMO 2
//! `<encrypted>` payload.
//!
//! Composes [`omemo_stanza::Encrypted`] with `xmpp_parsers::message::Message`
//! so callers don't have to learn both XML serialisations. Network
//! errors are bubbled up via [`WireError`].

use std::str::FromStr;

use futures_util::StreamExt;
use jid::{BareJid, Jid};
use omemo_stanza::axolotl_stanza::{Encrypted as OldEncrypted, NS as OMEMO_OLD_NS};
use omemo_stanza::Encrypted;
use omemo_westron::SignedCaps;
use thiserror::Error;
use tokio_xmpp::{Client, Event, Stanza};
use xmpp_parsers::message::Message as XmppMessage;
use xmpp_parsers::minidom::Element;

use crate::westron::{encode_signed_caps_payload, parse_signed_caps_payload, SIGNED_CAPS_NS};

const OMEMO2_NS: &str = "urn:xmpp:omemo:2";
const ENCRYPTED_ELEM: &str = "encrypted";

/// Either-flavour incoming `<encrypted>` payload.
///
/// Returned by [`wait_for_encrypted_any`] so a caller running both
/// backends in parallel doesn't have to know in advance which one a
/// given message will use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedAny {
    Twomemo(Encrypted),
    Oldmemo(OldEncrypted),
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not encode <encrypted>: {0}")]
    Encode(omemo_stanza::StanzaError),
    #[error("could not parse incoming <encrypted>: {0}")]
    Parse(omemo_stanza::StanzaError),
    #[error("could not parse minidom element: {0}")]
    Minidom(String),
    #[error("client stream ended before an <encrypted> message arrived")]
    StreamEnded,
}

/// Send a `<message type="chat" to=peer>` carrying `encrypted` as its
/// `<encrypted xmlns='urn:xmpp:omemo:2'>` payload.
pub async fn send_encrypted(
    client: &mut Client,
    to: BareJid,
    encrypted: &Encrypted,
) -> Result<(), WireError> {
    let xml = encrypted.encode().map_err(WireError::Encode)?;
    let elem = Element::from_str(&xml).map_err(|e| WireError::Minidom(e.to_string()))?;
    let msg = XmppMessage::chat(Some(Jid::from(to))).with_payloads(vec![elem]);
    client.send_stanza(msg.into()).await?;
    Ok(())
}

/// Send a `<message type="chat" to=peer>` carrying an OMEMO 0.3
/// `<encrypted xmlns='eu.siacs.conversations.axolotl'>` payload.
pub async fn send_encrypted_old(
    client: &mut Client,
    to: BareJid,
    encrypted: &OldEncrypted,
) -> Result<(), WireError> {
    let xml = encrypted.encode().map_err(WireError::Encode)?;
    let elem = Element::from_str(&xml).map_err(|e| WireError::Minidom(e.to_string()))?;
    let msg = XmppMessage::chat(Some(Jid::from(to))).with_payloads(vec![elem]);
    client.send_stanza(msg.into()).await?;
    Ok(())
}

/// Variant of [`send_encrypted`] that rides a Westron signed-caps
/// element alongside the OMEMO 2 `<encrypted>` payload. SPEC §4.3 — a
/// Westron-aware peer can use this to drive
/// [`crate::InboundSpecLocks::renegotiate`] without waiting for the
/// peer's own publish cycle.
///
/// `caps.sid` should equal `encrypted.sid` (the receiver verifies sid
/// rebinding); call [`crate::caps_for_self`] to produce the caps with
/// the correct sid for the bot's own identity.
pub async fn send_encrypted_with_caps(
    client: &mut Client,
    to: BareJid,
    encrypted: &Encrypted,
    caps: &SignedCaps,
) -> Result<(), WireError> {
    let xml_enc = encrypted.encode().map_err(WireError::Encode)?;
    let elem_enc = Element::from_str(&xml_enc).map_err(|e| WireError::Minidom(e.to_string()))?;
    let xml_caps = encode_signed_caps_payload(caps);
    let elem_caps =
        Element::from_str(&xml_caps).map_err(|e| WireError::Minidom(e.to_string()))?;
    let msg = XmppMessage::chat(Some(Jid::from(to))).with_payloads(vec![elem_enc, elem_caps]);
    client.send_stanza(msg.into()).await?;
    Ok(())
}

/// OMEMO 0.3 mirror of [`send_encrypted_with_caps`]. Legacy 0.3-only
/// clients drop the unknown `<caps>` payload silently; Westron-aware
/// clients can use it to upgrade the session.
pub async fn send_encrypted_old_with_caps(
    client: &mut Client,
    to: BareJid,
    encrypted: &OldEncrypted,
    caps: &SignedCaps,
) -> Result<(), WireError> {
    let xml_enc = encrypted.encode().map_err(WireError::Encode)?;
    let elem_enc = Element::from_str(&xml_enc).map_err(|e| WireError::Minidom(e.to_string()))?;
    let xml_caps = encode_signed_caps_payload(caps);
    let elem_caps =
        Element::from_str(&xml_caps).map_err(|e| WireError::Minidom(e.to_string()))?;
    let msg = XmppMessage::chat(Some(Jid::from(to))).with_payloads(vec![elem_enc, elem_caps]);
    client.send_stanza(msg.into()).await?;
    Ok(())
}

/// Pluck a signed-caps sibling payload out of `msg` if present.
/// Returns the *unverified* `SignedCaps`; the caller MUST call
/// [`SignedCaps::verify`] under the peer's `IK_ed` before honoring it.
///
/// Mirror of [`parse_encrypted_message`] — both look for siblings of
/// `<message>` payloads, neither consumes a stanza off the stream.
pub fn parse_signed_caps_sibling(msg: &XmppMessage) -> Result<Option<SignedCaps>, WireError> {
    for p in &msg.payloads {
        if p.name() == "caps" && p.ns() == SIGNED_CAPS_NS {
            let xml = String::from(p);
            let caps =
                parse_signed_caps_payload(&xml).map_err(|e| WireError::Minidom(e.to_string()))?;
            return Ok(Some(caps));
        }
    }
    Ok(None)
}

/// Drive `client` until a `<message>` with an `<encrypted xmlns=
/// 'urn:xmpp:omemo:2'>` payload arrives. Returns `(sender_bare_jid,
/// Encrypted)`. Other stanzas (PEP `<event>` notifications, presence,
/// etc.) are silently consumed and skipped.
pub async fn wait_for_encrypted(
    client: &mut Client,
) -> Result<(Option<BareJid>, Encrypted), WireError> {
    while let Some(event) = client.next().await {
        let Event::Stanza(Stanza::Message(msg)) = event else {
            continue;
        };
        let Some(payload) = msg
            .payloads
            .iter()
            .find(|p| p.name() == ENCRYPTED_ELEM && p.ns() == OMEMO2_NS)
        else {
            continue;
        };
        let xml = String::from(payload);
        let parsed = Encrypted::parse(&xml).map_err(WireError::Parse)?;
        let from = msg.from.as_ref().map(|j| j.to_bare());
        return Ok((from, parsed));
    }
    Err(WireError::StreamEnded)
}

/// Inspect an already-popped `<message>` and, if it carries an
/// `<encrypted>` payload (OMEMO 2 or OMEMO 0.3), return the parsed
/// payload + sender bare JID.
///
/// Use this from a daemon-style outer event loop where you've
/// already pulled the stanza off `client.next()` for routing
/// purposes — calling [`wait_for_encrypted_any`] in that situation
/// would lose the stanza you just popped (it goes back to polling
/// the stream, missing the message in hand).
pub fn parse_encrypted_message(
    msg: &XmppMessage,
) -> Result<Option<(Option<BareJid>, EncryptedAny)>, WireError> {
    let from = msg.from.as_ref().map(|j| j.to_bare());
    for p in &msg.payloads {
        if p.name() != ENCRYPTED_ELEM {
            continue;
        }
        match p.ns().as_str() {
            OMEMO2_NS => {
                let xml = String::from(p);
                let parsed = Encrypted::parse(&xml).map_err(WireError::Parse)?;
                return Ok(Some((from, EncryptedAny::Twomemo(parsed))));
            }
            OMEMO_OLD_NS => {
                let xml = String::from(p);
                let parsed = OldEncrypted::parse(&xml).map_err(WireError::Parse)?;
                return Ok(Some((from, EncryptedAny::Oldmemo(parsed))));
            }
            _ => {}
        }
    }
    Ok(None)
}

/// Dual-backend variant of [`wait_for_encrypted`]. Returns the first
/// `<encrypted>` payload arriving in *either* the OMEMO 2 namespace or
/// the OMEMO 0.3 (`eu.siacs.conversations.axolotl`) namespace, wrapped
/// in [`EncryptedAny`] so the caller can dispatch by protocol.
pub async fn wait_for_encrypted_any(
    client: &mut Client,
) -> Result<(Option<BareJid>, EncryptedAny), WireError> {
    while let Some(event) = client.next().await {
        let Event::Stanza(Stanza::Message(msg)) = event else {
            continue;
        };
        if let Some(parsed) = parse_encrypted_message(&msg)? {
            return Ok(parsed);
        }
    }
    Err(WireError::StreamEnded)
}
