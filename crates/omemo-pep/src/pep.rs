//! PEP (XEP-0163) publish/fetch for OMEMO 2 device-list and bundle nodes.
//!
//! XEP-0384 v0.9 §5.3 requires every device to publish itself onto the
//! `urn:xmpp:omemo:2:devices` PEP node so peers can discover it. This
//! module gives the thin `publish_device_list` / `fetch_device_list`
//! helpers that wrap the iq + pubsub plumbing.

use futures_util::StreamExt;
use jid::{BareJid, Jid};
use std::str::FromStr;
use thiserror::Error;
use xmpp_parsers::minidom::Element;
use xmpp_parsers::pubsub::pubsub::{Item, Items, PubSub, Publish};
use xmpp_parsers::pubsub::{ItemId, NodeName};
use xmpp_parsers::stanza_error::StanzaError;

use omemo_stanza::DeviceList;
use tokio_xmpp::{Client, IqFailure, IqRequest, IqResponse, IqResponseToken};

/// PEP node holding the OMEMO 2 device list.
pub const DEVICES_NODE: &str = "urn:xmpp:omemo:2:devices";
/// PEP item id for the (single) device-list payload.
pub const ITEM_ID_CURRENT: &str = "current";
/// XML namespace of the OMEMO 2 device-list payload elements.
const OMEMO2_NS: &str = "urn:xmpp:omemo:2";

#[derive(Debug, Error)]
pub enum PepError {
    #[error("iq transport failure: {0}")]
    Iq(IqFailure),
    /// Boxed because `xmpp_parsers::stanza_error::StanzaError` is ~200B,
    /// which would inflate `Result<_, PepError>` for every helper.
    #[error("server returned an error stanza: {0:?}")]
    ServerError(Box<StanzaError>),
    #[error("response payload missing")]
    NoPayload,
    #[error("unexpected pubsub response shape")]
    UnexpectedResponse,
    #[error("device list payload missing in pubsub item")]
    NoDeviceList,
    #[error("could not parse pubsub response: {0}")]
    Parse(String),
    #[error("stream ended while awaiting iq response")]
    StreamEnded,
}

/// Render a `DeviceList` as the `<devices xmlns='urn:xmpp:omemo:2'>`
/// element XEP-0384 §5.3.1 expects inside a `<pubsub>` `<item>`.
///
/// Routes through `omemo_stanza::DeviceList::encode` so the canonical
/// attribute order lives in exactly one place.
fn devices_to_element(list: &DeviceList) -> Result<Element, PepError> {
    let xml = list
        .encode()
        .map_err(|e| PepError::Parse(format!("DeviceList encode: {e}")))?;
    Element::from_str(&xml).map_err(|e| PepError::Parse(format!("minidom parse: {e}")))
}

/// Inverse of [`devices_to_element`]. Routes back through
/// `omemo_stanza::DeviceList::parse` so the parsing rules live in one
/// place too.
fn element_to_device_list(elem: &Element) -> Result<DeviceList, PepError> {
    if elem.name() != "devices" || elem.ns() != OMEMO2_NS {
        return Err(PepError::Parse(format!(
            "expected <devices xmlns='{OMEMO2_NS}'>, got <{}>",
            elem.name()
        )));
    }
    let xml = String::from(elem);
    DeviceList::parse(&xml).map_err(|e| PepError::Parse(format!("DeviceList parse: {e}")))
}

/// Drive the client stream until either the iq response is delivered or
/// the stream ends. tokio-xmpp delivers iq responses via the
/// `IqResponseToken`, but the response only arrives if `Client::next` is
/// being polled — see the `send_iq` doc on tokio-xmpp's `Client`.
async fn await_iq_response(
    client: &mut Client,
    token: IqResponseToken,
) -> Result<IqResponse, PepError> {
    let mut token = Box::pin(token);
    loop {
        tokio::select! {
            biased;
            response = &mut token => return response.map_err(PepError::Iq),
            event = client.next() => match event {
                Some(_) => continue,
                None => return Err(PepError::StreamEnded),
            },
        }
    }
}

/// Publish a device list onto the user's own `urn:xmpp:omemo:2:devices`
/// PEP node.
///
/// Item id is `"current"` per XEP-0384 §5.3.1.
pub async fn publish_device_list(client: &mut Client, list: &DeviceList) -> Result<(), PepError> {
    let payload = devices_to_element(list)?;
    let pubsub = PubSub::Publish {
        publish: Publish {
            node: NodeName(DEVICES_NODE.to_owned()),
            items: vec![Item {
                id: Some(ItemId(ITEM_ID_CURRENT.to_owned())),
                publisher: None,
                payload: Some(payload),
            }],
        },
        publish_options: None,
    };
    let token = client
        .send_iq(None, IqRequest::Set(Element::from(pubsub)))
        .await;
    match await_iq_response(client, token).await? {
        IqResponse::Result(_) => Ok(()),
        IqResponse::Error(e) => Err(PepError::ServerError(Box::new(e))),
    }
}

/// Fetch the device list published at `peer`'s
/// `urn:xmpp:omemo:2:devices` PEP node.
///
/// Pass `None` for `peer` to query the caller's own account — required
/// because Prosody (and other servers) reply to self-PEP iq's with no
/// `from` attribute, and the iq response tracker keys outbound requests
/// by the request's `to`. Sending `to=Some(self_jid)` would key the
/// request differently from how the response's normalised `from` is
/// keyed, so the response would surface as a stanza event rather than
/// resolve the token. Sending `to=None` matches the publish path
/// exactly and works.
pub async fn fetch_device_list(
    client: &mut Client,
    peer: Option<BareJid>,
) -> Result<DeviceList, PepError> {
    let request = PubSub::Items(Items {
        max_items: None,
        node: NodeName(DEVICES_NODE.to_owned()),
        subid: None,
        items: vec![],
    });
    let to = peer.map(Jid::from);
    let token = client
        .send_iq(to, IqRequest::Get(Element::from(request)))
        .await;
    let result_payload = match await_iq_response(client, token).await? {
        IqResponse::Result(p) => p.ok_or(PepError::NoPayload)?,
        IqResponse::Error(e) => return Err(PepError::ServerError(Box::new(e))),
    };
    let pubsub_response = PubSub::try_from(result_payload)
        .map_err(|e| PepError::Parse(format!("pubsub response: {e:?}")))?;
    match pubsub_response {
        PubSub::Items(items) => {
            let item = items.items.first().ok_or(PepError::NoDeviceList)?;
            let payload = item.payload.as_ref().ok_or(PepError::NoDeviceList)?;
            element_to_device_list(payload)
        }
        _ => Err(PepError::UnexpectedResponse),
    }
}

#[cfg(test)]
mod unit {
    use super::*;
    use omemo_stanza::Device;

    #[test]
    fn devices_round_trip_via_minidom() {
        let original = DeviceList {
            devices: vec![
                Device {
                    id: 27183,
                    label: Some("Phone".into()),
                    labelsig: Some(b"sig".to_vec()),
                },
                Device {
                    id: 27184,
                    label: None,
                    labelsig: None,
                },
            ],
        };
        let element = devices_to_element(&original).expect("encode");
        assert_eq!(element.name(), "devices");
        assert_eq!(element.ns(), OMEMO2_NS);
        let parsed = element_to_device_list(&element).expect("parse back");
        assert_eq!(parsed, original);
    }
}
