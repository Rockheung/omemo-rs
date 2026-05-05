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
use thiserror::Error;
use tokio_xmpp::{Client, Event, Stanza};
use xmpp_parsers::message::Message as XmppMessage;
use xmpp_parsers::minidom::Element;

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
