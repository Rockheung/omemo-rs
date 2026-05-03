//! PEP (XEP-0163) publish/fetch for OMEMO 2 device-list and bundle nodes.
//!
//! XEP-0384 v0.9 §5.3 requires every device to publish itself onto the
//! `urn:xmpp:omemo:2:devices` PEP node so peers can discover it, and
//! to publish its key bundle onto `urn:xmpp:omemo:2:bundles` (one item
//! per device, item id = device id). This module gives the thin
//! `publish_*` / `fetch_*` helpers that wrap the iq + pubsub plumbing.

use futures_util::StreamExt;
use jid::{BareJid, Jid};
use std::str::FromStr;
use thiserror::Error;
use xmpp_parsers::data_forms::{DataForm, DataFormType, Field};
use xmpp_parsers::minidom::Element;
use xmpp_parsers::pubsub::pubsub::{Item, Items, PubSub, Publish, PublishOptions};
use xmpp_parsers::pubsub::{ItemId, NodeName};
use xmpp_parsers::stanza_error::StanzaError;

use omemo_stanza::axolotl_stanza::{
    Bundle as OldBundle, DeviceList as OldDeviceList, NS as OMEMO_OLD_NS,
};
use omemo_stanza::{Bundle, DeviceList};
use tokio_xmpp::{Client, IqFailure, IqRequest, IqResponse, IqResponseToken};

/// PEP node holding the OMEMO 2 device list (XEP-0384 §5.3.1).
pub const DEVICES_NODE: &str = "urn:xmpp:omemo:2:devices";
/// PEP item id for the (single) device-list payload.
pub const ITEM_ID_CURRENT: &str = "current";
/// PEP node holding OMEMO 2 bundles (XEP-0384 §5.3.2). One item per
/// device, with item id equal to the device id (as a decimal string).
pub const BUNDLES_NODE: &str = "urn:xmpp:omemo:2:bundles";
/// XML namespace of the OMEMO 2 device-list and bundle payloads.
const OMEMO2_NS: &str = "urn:xmpp:omemo:2";

/// PEP node holding the OMEMO 0.3 device list. Note the single
/// "devicelist" word (vs the OMEMO 2 plural "devices" node) and the
/// distinct namespace string per XEP-0384 v0.3 §4.3.
pub const OLD_DEVICES_NODE: &str = "eu.siacs.conversations.axolotl.devicelist";
/// PEP node prefix for OMEMO 0.3 bundles. Each device has its **own**
/// node `<prefix><device_id>`, in contrast to OMEMO 2 which puts every
/// device's bundle as an item under the single bundles node.
pub const OLD_BUNDLES_NODE_PREFIX: &str = "eu.siacs.conversations.axolotl.bundles:";

fn old_bundles_node(device_id: u32) -> String {
    format!("{}{}", OLD_BUNDLES_NODE_PREFIX, device_id)
}

/// Build `<publish-options>` carrying a `pubsub#publish-options` data form.
///
/// XEP-0384 v0.9 mandates `pubsub#access_model = open` on both PEP nodes
/// (so peers without presence subscription can fetch — common on first
/// contact and in MUCs), plus `pubsub#max_items = max` on the bundles
/// node (so each device's bundle item survives the next device's
/// publish).
fn publish_options_form(fields: Vec<(&str, &str)>) -> PublishOptions {
    let form = DataForm::new(
        DataFormType::Submit,
        "http://jabber.org/protocol/pubsub#publish-options",
        fields
            .into_iter()
            .map(|(k, v)| Field::text_single(k, v))
            .collect(),
    );
    PublishOptions { form: Some(form) }
}

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
    #[error("bundle payload missing in pubsub item")]
    NoBundle,
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
        publish_options: Some(publish_options_form(vec![("pubsub#access_model", "open")])),
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

// ---------------------------------------------------------------------------
// Bundles (XEP-0384 §5.3.2)
// ---------------------------------------------------------------------------

fn bundle_to_element(bundle: &Bundle) -> Result<Element, PepError> {
    let xml = bundle
        .encode()
        .map_err(|e| PepError::Parse(format!("Bundle encode: {e}")))?;
    Element::from_str(&xml).map_err(|e| PepError::Parse(format!("minidom parse: {e}")))
}

fn element_to_bundle(elem: &Element) -> Result<Bundle, PepError> {
    if elem.name() != "bundle" || elem.ns() != OMEMO2_NS {
        return Err(PepError::Parse(format!(
            "expected <bundle xmlns='{OMEMO2_NS}'>, got <{}>",
            elem.name()
        )));
    }
    let xml = String::from(elem);
    Bundle::parse(&xml).map_err(|e| PepError::Parse(format!("Bundle parse: {e}")))
}

/// Publish `bundle` onto `urn:xmpp:omemo:2:bundles` with item id =
/// `device_id` (decimal). XEP-0384 §5.3.2 mandates that the item id
/// equals the publishing device's id.
pub async fn publish_bundle(
    client: &mut Client,
    device_id: u32,
    bundle: &Bundle,
) -> Result<(), PepError> {
    let payload = bundle_to_element(bundle)?;
    let pubsub = PubSub::Publish {
        publish: Publish {
            node: NodeName(BUNDLES_NODE.to_owned()),
            items: vec![Item {
                id: Some(ItemId(device_id.to_string())),
                publisher: None,
                payload: Some(payload),
            }],
        },
        publish_options: Some(publish_options_form(vec![
            ("pubsub#access_model", "open"),
            ("pubsub#max_items", "max"),
        ])),
    };
    let token = client
        .send_iq(None, IqRequest::Set(Element::from(pubsub)))
        .await;
    match await_iq_response(client, token).await? {
        IqResponse::Result(_) => Ok(()),
        IqResponse::Error(e) => Err(PepError::ServerError(Box::new(e))),
    }
}

/// Fetch the bundle for `device_id` from `peer`'s bundles node.
///
/// `peer = None` means own account (same Prosody-self-PEP iq-tracker
/// rationale as [`fetch_device_list`]).
pub async fn fetch_bundle(
    client: &mut Client,
    peer: Option<BareJid>,
    device_id: u32,
) -> Result<Bundle, PepError> {
    let request = PubSub::Items(Items {
        max_items: None,
        node: NodeName(BUNDLES_NODE.to_owned()),
        subid: None,
        items: vec![Item {
            id: Some(ItemId(device_id.to_string())),
            publisher: None,
            payload: None,
        }],
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
            // Server returns a single Item with our requested id; reach
            // into its payload to get <bundle/>.
            let item = items.items.first().ok_or(PepError::NoBundle)?;
            let payload = item.payload.as_ref().ok_or(PepError::NoBundle)?;
            element_to_bundle(payload)
        }
        _ => Err(PepError::UnexpectedResponse),
    }
}

// ---------------------------------------------------------------------------
// OMEMO 0.3 (eu.siacs.conversations.axolotl) PEP nodes
// ---------------------------------------------------------------------------
//
// Three deltas from OMEMO 2:
//
// * Distinct node names (`OLD_DEVICES_NODE`, `OLD_BUNDLES_NODE_PREFIX`).
// * The bundles node is **per-device** — `prefix:<device_id>` — so the
//   item id collapses to "current". This contrasts with OMEMO 2's
//   single-node-many-items model where item id == device id.
// * The encoded XML is the axolotl-namespace shape from
//   `omemo_stanza::axolotl_stanza` (different element layout from
//   `omemo_stanza::Bundle` etc.; sign-bit-stuffing on the SPK sig).

fn old_devices_to_element(list: &OldDeviceList) -> Result<Element, PepError> {
    let xml = list
        .encode()
        .map_err(|e| PepError::Parse(format!("OldDeviceList encode: {e}")))?;
    Element::from_str(&xml).map_err(|e| PepError::Parse(format!("minidom parse: {e}")))
}

fn element_to_old_device_list(elem: &Element) -> Result<OldDeviceList, PepError> {
    if elem.name() != "list" || elem.ns() != OMEMO_OLD_NS {
        return Err(PepError::Parse(format!(
            "expected <list xmlns='{OMEMO_OLD_NS}'>, got <{}>",
            elem.name()
        )));
    }
    let xml = String::from(elem);
    OldDeviceList::parse(&xml)
        .map_err(|e| PepError::Parse(format!("OldDeviceList parse: {e}")))
}

fn old_bundle_to_element(bundle: &OldBundle) -> Result<Element, PepError> {
    let xml = bundle
        .encode()
        .map_err(|e| PepError::Parse(format!("OldBundle encode: {e}")))?;
    Element::from_str(&xml).map_err(|e| PepError::Parse(format!("minidom parse: {e}")))
}

fn element_to_old_bundle(elem: &Element) -> Result<OldBundle, PepError> {
    if elem.name() != "bundle" || elem.ns() != OMEMO_OLD_NS {
        return Err(PepError::Parse(format!(
            "expected <bundle xmlns='{OMEMO_OLD_NS}'>, got <{}>",
            elem.name()
        )));
    }
    let xml = String::from(elem);
    OldBundle::parse(&xml).map_err(|e| PepError::Parse(format!("OldBundle parse: {e}")))
}

/// Publish an OMEMO 0.3 device list onto the user's
/// `eu.siacs.conversations.axolotl.devicelist` PEP node.
pub async fn publish_old_device_list(
    client: &mut Client,
    list: &OldDeviceList,
) -> Result<(), PepError> {
    let payload = old_devices_to_element(list)?;
    let pubsub = PubSub::Publish {
        publish: Publish {
            node: NodeName(OLD_DEVICES_NODE.to_owned()),
            items: vec![Item {
                id: Some(ItemId(ITEM_ID_CURRENT.to_owned())),
                publisher: None,
                payload: Some(payload),
            }],
        },
        publish_options: Some(publish_options_form(vec![("pubsub#access_model", "open")])),
    };
    let token = client
        .send_iq(None, IqRequest::Set(Element::from(pubsub)))
        .await;
    match await_iq_response(client, token).await? {
        IqResponse::Result(_) => Ok(()),
        IqResponse::Error(e) => Err(PepError::ServerError(Box::new(e))),
    }
}

/// Fetch the OMEMO 0.3 device list from `peer`'s
/// `eu.siacs.conversations.axolotl.devicelist` PEP node.
pub async fn fetch_old_device_list(
    client: &mut Client,
    peer: Option<BareJid>,
) -> Result<OldDeviceList, PepError> {
    let request = PubSub::Items(Items {
        max_items: None,
        node: NodeName(OLD_DEVICES_NODE.to_owned()),
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
            element_to_old_device_list(payload)
        }
        _ => Err(PepError::UnexpectedResponse),
    }
}

/// Publish `bundle` onto our own
/// `eu.siacs.conversations.axolotl.bundles:<device_id>` PEP node.
/// Each device gets its own node — there is no single shared
/// "bundles" node like OMEMO 2 has.
pub async fn publish_old_bundle(
    client: &mut Client,
    device_id: u32,
    bundle: &OldBundle,
) -> Result<(), PepError> {
    let payload = old_bundle_to_element(bundle)?;
    let pubsub = PubSub::Publish {
        publish: Publish {
            node: NodeName(old_bundles_node(device_id)),
            items: vec![Item {
                id: Some(ItemId(ITEM_ID_CURRENT.to_owned())),
                publisher: None,
                payload: Some(payload),
            }],
        },
        publish_options: Some(publish_options_form(vec![
            ("pubsub#access_model", "open"),
            ("pubsub#max_items", "1"),
        ])),
    };
    let token = client
        .send_iq(None, IqRequest::Set(Element::from(pubsub)))
        .await;
    match await_iq_response(client, token).await? {
        IqResponse::Result(_) => Ok(()),
        IqResponse::Error(e) => Err(PepError::ServerError(Box::new(e))),
    }
}

/// Fetch the OMEMO 0.3 bundle for `device_id` from `peer`'s
/// per-device bundles node.
pub async fn fetch_old_bundle(
    client: &mut Client,
    peer: Option<BareJid>,
    device_id: u32,
) -> Result<OldBundle, PepError> {
    let request = PubSub::Items(Items {
        max_items: None,
        node: NodeName(old_bundles_node(device_id)),
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
            let item = items.items.first().ok_or(PepError::NoBundle)?;
            let payload = item.payload.as_ref().ok_or(PepError::NoBundle)?;
            element_to_old_bundle(payload)
        }
        _ => Err(PepError::UnexpectedResponse),
    }
}

#[cfg(test)]
mod unit {
    use super::*;
    use omemo_stanza::{Device, PreKey, SignedPreKey};

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

    #[test]
    fn bundle_round_trip_via_minidom() {
        let original = Bundle {
            spk: SignedPreKey {
                id: 1,
                pub_key: b"spk-pub-bytes".to_vec(),
            },
            spks: b"spk-signature-bytes".to_vec(),
            ik: b"identity-key-bytes".to_vec(),
            prekeys: vec![
                PreKey {
                    id: 1,
                    pub_key: b"pk1".to_vec(),
                },
                PreKey {
                    id: 2,
                    pub_key: b"pk2".to_vec(),
                },
            ],
        };
        let element = bundle_to_element(&original).expect("encode");
        assert_eq!(element.name(), "bundle");
        assert_eq!(element.ns(), OMEMO2_NS);
        let parsed = element_to_bundle(&element).expect("parse back");
        assert_eq!(parsed, original);
    }

    #[test]
    fn old_devices_round_trip_via_minidom() {
        let original = OldDeviceList {
            devices: vec![1234, 5678],
        };
        let element = old_devices_to_element(&original).expect("encode");
        assert_eq!(element.name(), "list");
        assert_eq!(element.ns(), OMEMO_OLD_NS);
        let parsed = element_to_old_device_list(&element).expect("parse back");
        assert_eq!(parsed, original);
    }

    #[test]
    fn old_bundle_round_trip_via_minidom() {
        // Use a deterministic Ed25519 key so the curve↔ed
        // round-trip via the sign-bit-stuffing trick is valid.
        let seed = [0xA5u8; 32];
        let ik_priv = omemo_xeddsa::seed_to_priv(&seed);
        let ik_ed = omemo_xeddsa::priv_to_ed25519_pub(&ik_priv);
        let mut sig = [0u8; 64];
        for (i, b) in sig.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11);
        }
        sig[63] &= 0x7F;
        let original = OldBundle {
            signed_prekey_id: 7,
            signed_prekey_pub: [0x33u8; 32],
            signed_prekey_sig: sig,
            identity_key_ed: ik_ed,
            prekeys: vec![omemo_stanza::axolotl_stanza::PreKey {
                id: 1,
                pub_key: [0x44u8; 32],
            }],
        };
        let element = old_bundle_to_element(&original).expect("encode");
        assert_eq!(element.name(), "bundle");
        assert_eq!(element.ns(), OMEMO_OLD_NS);
        let parsed = element_to_old_bundle(&element).expect("parse back");
        assert_eq!(parsed, original);
    }

    #[test]
    fn old_bundles_node_format() {
        assert_eq!(old_bundles_node(0), "eu.siacs.conversations.axolotl.bundles:0");
        assert_eq!(old_bundles_node(2002), "eu.siacs.conversations.axolotl.bundles:2002");
    }
}
