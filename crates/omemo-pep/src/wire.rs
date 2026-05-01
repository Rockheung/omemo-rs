//! tokio-xmpp `<message>` send / receive glue for the OMEMO 2
//! `<encrypted>` payload.
//!
//! Composes [`omemo_stanza::Encrypted`] with `xmpp_parsers::message::Message`
//! so callers don't have to learn both XML serialisations. Network
//! errors are bubbled up via [`WireError`].

use std::str::FromStr;

use futures_util::StreamExt;
use jid::{BareJid, Jid};
use omemo_stanza::Encrypted;
use thiserror::Error;
use tokio_xmpp::{Client, Event, Stanza};
use xmpp_parsers::message::Message as XmppMessage;
use xmpp_parsers::minidom::Element;

const OMEMO2_NS: &str = "urn:xmpp:omemo:2";
const ENCRYPTED_ELEM: &str = "encrypted";

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
