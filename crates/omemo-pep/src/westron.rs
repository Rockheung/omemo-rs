//! Westron identity unification glue — sits above [`crate::store`] and
//! [`crate::store_old`] so a single Ed25519 master identity drives both
//! spec stacks.
//!
//! Westron's premise (SPEC §3): one `Identity` Ed25519 keypair, one
//! deterministically-derived Curve25519 form, two on-wire bundle shapes
//! (OMEMO 2 over Ed25519, OMEMO 0.3 over Curve25519). The omemo-session
//! store already holds the master seed; this module is the small typed
//! lens that hands an [`omemo_westron::Identity`] to callers that need
//! to sign over the master key (signed caps, future Westron canonical
//! wire) without re-deriving from raw bytes at every call site.
//!
//! Day 1-2 of the D-full plan in `/home/rock/projects/westron-spec/STATUS.md`.

use std::time::{SystemTime, UNIX_EPOCH};

use omemo_session::Store;
use omemo_westron::caps::{Caps, Spec};
use omemo_westron::transcode::{select_wire_for_recipients, Recipient as WestronRecipient, SendPlan};
use omemo_westron::{Identity, IdentityError, SignedCaps};

use crate::pep::{publish_bundle, publish_old_bundle};
use crate::store::{bundle_from_store, StoreFlowError};
use crate::store_old::old_bundle_from_store;

/// Standalone signed-caps XML namespace — same as the Westron canonical
/// wire format. A `<caps xmlns="urn:xmpp:omemo:westron:1" .../>` element
/// rides alongside `<encrypted>` so a Westron-aware peer can renegotiate
/// the spec lock, while legacy 0.3 / 2 clients silently ignore it.
pub const SIGNED_CAPS_NS: &str = "urn:xmpp:omemo:westron:1";

/// Construct an [`omemo_westron::Identity`] from the store's master
/// `ik_seed`. Errors if the identity row is missing (call
/// [`crate::install_identity`] / [`crate::install_identity_random`]
/// first).
pub fn westron_identity(store: &Store) -> Result<Identity, StoreFlowError> {
    let id = store
        .get_identity()?
        .ok_or(StoreFlowError::IdentityMissing)?;
    Ok(Identity::from_seed(id.ik_seed))
}

/// SPEC C-3.3 — verify that a peer's OMEMO 2 (Ed25519) and OMEMO 0.3
/// (Curve25519) bundle identity keys are consistent: deriving X25519
/// from the Ed25519 form must equal the published Curve25519 form.
///
/// Thin wrapper that lifts [`omemo_westron::Identity::verify_dual_bundle`]
/// into [`StoreFlowError`] so wire-layer callers can use a single error
/// channel.
pub fn verify_peer_dual_bundle(
    ik_ed_pub: &[u8; 32],
    ik_curve_pub: &[u8; 32],
) -> Result<(), StoreFlowError> {
    Identity::verify_dual_bundle(ik_ed_pub, ik_curve_pub)
        .map_err(|e| StoreFlowError::Pep(format!("dual-bundle: {e}")))
}

impl From<IdentityError> for StoreFlowError {
    fn from(e: IdentityError) -> Self {
        StoreFlowError::Pep(format!("westron identity: {e}"))
    }
}

/// Publish BOTH our OMEMO 2 bundle (`urn:xmpp:omemo:2:bundles`) and
/// our OMEMO 0.3 bundle (`eu.siacs.conversations.axolotl.bundles:N`)
/// from the same store, under the same `own_device_id`.
///
/// Both bundles share the master Ed25519 seed (`OwnIdentity.ik_seed`),
/// the same SPK, and the same OPK pool — the wire encoders apply the
/// per-spec transformations (Curve25519 derivation, sign-bit stuffing,
/// 33-byte SPK signature re-derivation). After this call, a peer
/// running OMEMO 2 *or* OMEMO 0.3 can boot a session against us using
/// the same logical identity.
///
/// XEP-0384 §5.3 atomicity: publishing both bundles in sequence is not
/// strictly atomic from the perspective of a peer that fetches mid-way.
/// P4-B operational test (still open) will cover the transactional
/// case. For now, "publish OMEMO 2 first, then OMEMO 0.3" is the
/// conventional ordering — peers prefer the newer spec when both are
/// available, so a peer that sees only 0.3 after our 2-publish will
/// degrade gracefully (cap-negotiation handles this).
/// What a Westron-aware bot built on this crate speaks. SPEC §7.1 —
/// Westron > OMEMO 2 > OMEMO 0.3, all three supported.
pub fn default_self_caps() -> Caps {
    Caps::new([Spec::Westron, Spec::Omemo2, Spec::Omemo03])
}

/// SPEC §4.3 — sign caps for the bot's own identity at `ts` (unix
/// seconds). `sid` MUST be our XEP-0384 device id; the verifier rebinds
/// the signature to the carrying `<encrypted sid=>`. `also_speaks_*`
/// flags advertise legacy-spec interop so a Westron peer can decide to
/// stay on the legacy wire if our other devices are stuck there.
pub fn sign_caps(
    store: &Store,
    sid: u32,
    ts: i64,
    also_speaks_omemo_2: bool,
    also_speaks_omemo_03: bool,
) -> Result<SignedCaps, StoreFlowError> {
    let id = westron_identity(store)?;
    Ok(SignedCaps::sign(
        &id,
        also_speaks_omemo_2,
        also_speaks_omemo_03,
        sid,
        ts,
    ))
}

/// `sign_caps` with the conventional bot defaults: advertises OMEMO 2
/// *and* OMEMO 0.3 interop, `ts = SystemTime::now()`. `sid` is the bot's
/// own device id (taken from the store identity for safety — the caller
/// passes it explicitly to make stanza-binding mistakes obvious).
pub fn caps_for_self(store: &Store, sid: u32) -> Result<SignedCaps, StoreFlowError> {
    let id = store
        .get_identity()?
        .ok_or(StoreFlowError::IdentityMissing)?;
    if id.device_id != sid {
        return Err(StoreFlowError::Pep(format!(
            "caps sid mismatch: store has device_id={}, caller passed sid={sid}",
            id.device_id
        )));
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    sign_caps(store, sid, ts, true, true)
}

/// Encode `caps` as a standalone XML element ready to ride alongside an
/// `<encrypted>` payload in an outbound `<message>`. Schema:
///
/// ```xml
/// <caps xmlns="urn:xmpp:omemo:westron:1"
///       sid="..." speaks-omemo-2="..." speaks-omemo-03="..."
///       ts="..." sig="BASE64"/>
/// ```
///
/// Sibling-payload position lets legacy clients ignore it without
/// disturbing the underlying OMEMO 2 / 0.3 stanza.
pub fn encode_signed_caps_payload(caps: &SignedCaps) -> String {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let sig_b64 = B64.encode(caps.sig);
    format!(
        concat!(
            "<caps xmlns=\"{ns}\" sid=\"{sid}\" ",
            "speaks-omemo-2=\"{s2}\" speaks-omemo-03=\"{s03}\" ",
            "ts=\"{ts}\" sig=\"{sig}\"/>"
        ),
        ns = SIGNED_CAPS_NS,
        sid = caps.sid,
        s2 = caps.also_speaks_omemo_2,
        s03 = caps.also_speaks_omemo_03,
        ts = caps.ts,
        sig = sig_b64,
    )
}

/// Parse a standalone signed-caps payload (produced by
/// [`encode_signed_caps_payload`] or by a peer Westron stanza). Returns
/// the unverified `SignedCaps` — call [`SignedCaps::verify`] before
/// honoring its content (SPEC §7.3, prevent unauthenticated downgrade).
///
/// Errors are returned via [`StoreFlowError::Pep`] with a diagnostic
/// prefix so callers see them in the same error channel as the rest of
/// the wire path.
pub fn parse_signed_caps_payload(xml: &str) -> Result<SignedCaps, StoreFlowError> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use xmpp_parsers::minidom::Element;

    let elem: Element = xml
        .parse()
        .map_err(|e: xmpp_parsers::minidom::Error| {
            StoreFlowError::Pep(format!("caps parse: {e}"))
        })?;
    if elem.name() != "caps" || elem.ns() != SIGNED_CAPS_NS {
        return Err(StoreFlowError::Pep(format!(
            "caps parse: expected <caps xmlns=\"{SIGNED_CAPS_NS}\">, got <{} xmlns=\"{}\">",
            elem.name(),
            elem.ns()
        )));
    }
    let sid: u32 = elem
        .attr("sid")
        .ok_or_else(|| StoreFlowError::Pep("caps parse: missing sid".into()))?
        .parse()
        .map_err(|e| StoreFlowError::Pep(format!("caps parse sid: {e}")))?;
    let ts: i64 = elem
        .attr("ts")
        .ok_or_else(|| StoreFlowError::Pep("caps parse: missing ts".into()))?
        .parse()
        .map_err(|e| StoreFlowError::Pep(format!("caps parse ts: {e}")))?;
    let s2 = parse_bool_attr(&elem, "speaks-omemo-2")?;
    let s03 = parse_bool_attr(&elem, "speaks-omemo-03")?;
    let sig_b64 = elem
        .attr("sig")
        .ok_or_else(|| StoreFlowError::Pep("caps parse: missing sig".into()))?;
    let raw = B64
        .decode(sig_b64)
        .map_err(|e| StoreFlowError::Pep(format!("caps parse sig base64: {e}")))?;
    if raw.len() != 64 {
        return Err(StoreFlowError::Pep(format!(
            "caps parse: sig is {} bytes, expected 64",
            raw.len()
        )));
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&raw);
    Ok(SignedCaps {
        also_speaks_omemo_2: s2,
        also_speaks_omemo_03: s03,
        sid,
        ts,
        sig,
    })
}

fn parse_bool_attr(
    elem: &xmpp_parsers::minidom::Element,
    name: &str,
) -> Result<bool, StoreFlowError> {
    let raw = elem
        .attr(name)
        .ok_or_else(|| StoreFlowError::Pep(format!("caps parse: missing {name}")))?;
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(StoreFlowError::Pep(format!(
            "caps parse {name}: expected true|false, got {other}"
        ))),
    }
}

/// SPEC §7.2 — group recipient devices by best-shared wire spec.
/// One stanza per group; per-group encoders are spec-specific (OMEMO 2 /
/// OMEMO 0.3 / Westron canonical). Re-export of
/// [`omemo_westron::transcode::select_wire_for_recipients`] for callers
/// who only depend on `omemo-pep`.
pub fn plan_outbound_wire(self_caps: &Caps, recipients: &[WestronRecipient]) -> SendPlan {
    select_wire_for_recipients(self_caps, recipients)
}

pub async fn publish_my_dual_bundles(
    store: &Store,
    client: &mut tokio_xmpp::Client,
    own_device_id: u32,
) -> Result<(), StoreFlowError> {
    let bundle2 = bundle_from_store(store)?;
    publish_bundle(client, own_device_id, &bundle2)
        .await
        .map_err(|e| StoreFlowError::Pep(format!("omemo:2 bundle: {e}")))?;
    let bundle03 = old_bundle_from_store(store)?;
    publish_old_bundle(client, own_device_id, &bundle03)
        .await
        .map_err(|e| StoreFlowError::Pep(format!("omemo:0.3 bundle: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omemo_session::Store;
    use omemo_x3dh::IdentityKeyPair;

    use crate::store::{install_identity, IdentitySeed};

    fn seeded_store() -> Store {
        let mut store = Store::open_in_memory().expect("in-memory store");
        const OPKS: &[(u32, [u8; 32])] = &[(101, [0xA4; 32]), (102, [0xA5; 32])];
        install_identity(
            &mut store,
            &IdentitySeed {
                bare_jid: "alice@example.org",
                device_id: 1001,
                ik_seed: [0xA1; 32],
                spk_id: 1,
                spk_priv: [0xA2; 32],
                spk_sig_nonce: [0xA3; 64],
                opks: OPKS,
            },
        )
        .expect("install");
        store
    }

    #[test]
    fn westron_identity_matches_stored_ed25519() {
        let store = seeded_store();
        let id = westron_identity(&store).expect("identity");
        let from_seed = IdentityKeyPair::Seed([0xA1; 32]).ed25519_pub();
        assert_eq!(
            id.ik_ed_pub(),
            from_seed,
            "westron::Identity Ed25519 pub must match x3dh derivation"
        );
    }

    #[test]
    fn westron_identity_matches_omemo2_bundle_ik() {
        let store = seeded_store();
        let id = westron_identity(&store).expect("identity");
        let bundle = bundle_from_store(&store).expect("bundle");
        let mut bundle_ik = [0u8; 32];
        bundle_ik.copy_from_slice(&bundle.ik);
        assert_eq!(
            id.ik_ed_pub(),
            bundle_ik,
            "OMEMO 2 bundle.ik must equal westron Ed25519 pub"
        );
    }

    #[test]
    fn westron_identity_curve_matches_omemo03_bundle_curve_derivation() {
        let store = seeded_store();
        let id = westron_identity(&store).expect("identity");
        let bundle = old_bundle_from_store(&store).expect("old bundle");
        let derived = omemo_westron::derive_curve25519(&bundle.identity_key_ed)
            .expect("derive curve from old bundle ed");
        assert_eq!(
            id.ik_curve_pub().expect("curve from westron id"),
            derived,
            "westron Curve25519 pub must match the form an OMEMO 0.3 peer derives from our bundle's Ed25519"
        );
    }

    #[test]
    fn verify_dual_bundle_accepts_consistent_pair() {
        let store = seeded_store();
        let id = westron_identity(&store).expect("identity");
        let ed = id.ik_ed_pub();
        let curve = id.ik_curve_pub().expect("curve");
        verify_peer_dual_bundle(&ed, &curve).expect("consistent pair accepted");
    }

    #[test]
    fn verify_dual_bundle_rejects_mismatched_pair() {
        let store = seeded_store();
        let id = westron_identity(&store).expect("identity");
        let ed = id.ik_ed_pub();
        let mut wrong_curve = id.ik_curve_pub().expect("curve");
        wrong_curve[0] ^= 0x01; // flip a bit so it can't be a valid X25519 point for `ed`
        let err = verify_peer_dual_bundle(&ed, &wrong_curve)
            .expect_err("mismatched pair must reject");
        match err {
            StoreFlowError::Pep(msg) => assert!(
                msg.contains("dual-bundle"),
                "expected dual-bundle rejection, got {msg}"
            ),
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn westron_identity_signature_verifies_under_published_ed25519() {
        let store = seeded_store();
        let id = westron_identity(&store).expect("identity");
        let msg = b"caps assertion test";
        let sig = id.sign(msg);
        Identity::verify(&id.ik_ed_pub(), msg, &sig)
            .expect("signature must verify under the same Ed25519 we publish");
    }

    #[test]
    fn missing_identity_errs() {
        let store = Store::open_in_memory().expect("store");
        match westron_identity(&store) {
            Ok(_) => panic!("expected error, got identity"),
            Err(StoreFlowError::IdentityMissing) => {}
            Err(other) => panic!("expected IdentityMissing, got {other}"),
        }
    }

    // ---- Day 5: signed caps + send plan ----

    const CAPS_FRESH_SKEW: i64 = 86_400;

    #[test]
    fn sign_caps_verifies_under_published_ed25519() {
        let store = seeded_store();
        let caps = sign_caps(&store, 1001, 1_700_000_000, true, true).expect("sign");
        let id = westron_identity(&store).expect("id");
        caps.verify(1001, &id.ik_ed_pub(), Some(1_700_000_000), CAPS_FRESH_SKEW)
            .expect("our caps verify under our own Ed25519");
    }

    #[test]
    fn sign_caps_distinct_ts_yields_distinct_sig() {
        let store = seeded_store();
        let a = sign_caps(&store, 1001, 1_700_000_000, true, true).unwrap();
        let b = sign_caps(&store, 1001, 1_700_000_001, true, true).unwrap();
        assert_ne!(a.sig, b.sig, "ts contributes to the signing string");
    }

    #[test]
    fn sign_caps_distinct_sid_yields_distinct_sig() {
        let store = seeded_store();
        let a = sign_caps(&store, 1001, 1_700_000_000, true, true).unwrap();
        let b = sign_caps(&store, 1002, 1_700_000_000, true, true).unwrap();
        assert_ne!(a.sig, b.sig, "sid contributes to the signing string");
    }

    #[test]
    fn caps_for_self_rejects_mismatched_sid() {
        let store = seeded_store(); // device_id = 1001
        match caps_for_self(&store, 9999) {
            Ok(_) => panic!("expected error on sid mismatch"),
            Err(StoreFlowError::Pep(msg)) => assert!(
                msg.contains("caps sid mismatch"),
                "expected sid-mismatch error, got {msg}"
            ),
            Err(other) => panic!("unexpected variant: {other}"),
        }
    }

    #[test]
    fn caps_for_self_uses_store_device_id() {
        let store = seeded_store();
        let caps = caps_for_self(&store, 1001).expect("caps");
        assert_eq!(caps.sid, 1001);
        assert!(caps.also_speaks_omemo_2);
        assert!(caps.also_speaks_omemo_03);
    }

    #[test]
    fn signed_caps_payload_round_trips() {
        let store = seeded_store();
        let original = sign_caps(&store, 1001, 1_700_000_000, true, false).unwrap();
        let xml = encode_signed_caps_payload(&original);
        let parsed = parse_signed_caps_payload(&xml).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn signed_caps_payload_xml_shape() {
        let store = seeded_store();
        let caps = sign_caps(&store, 1001, 1_700_000_000, true, true).unwrap();
        let xml = encode_signed_caps_payload(&caps);
        assert!(xml.starts_with("<caps "));
        assert!(xml.contains("xmlns=\"urn:xmpp:omemo:westron:1\""));
        assert!(xml.contains("sid=\"1001\""));
        assert!(xml.contains("speaks-omemo-2=\"true\""));
        assert!(xml.contains("speaks-omemo-03=\"true\""));
        assert!(xml.contains("ts=\"1700000000\""));
        assert!(xml.ends_with("/>"));
    }

    #[test]
    fn parse_signed_caps_rejects_wrong_namespace() {
        let xml = "<caps xmlns=\"some-other-ns\" sid=\"1\" speaks-omemo-2=\"true\" \
                   speaks-omemo-03=\"true\" ts=\"0\" sig=\"AAAA\"/>";
        match parse_signed_caps_payload(xml) {
            Ok(_) => panic!("wrong namespace must reject"),
            Err(StoreFlowError::Pep(msg)) => assert!(
                msg.contains("expected <caps"),
                "expected namespace rejection, got {msg}"
            ),
            Err(other) => panic!("unexpected variant: {other}"),
        }
    }

    #[test]
    fn parse_signed_caps_rejects_short_sig() {
        let xml = "<caps xmlns=\"urn:xmpp:omemo:westron:1\" sid=\"1\" \
                   speaks-omemo-2=\"true\" speaks-omemo-03=\"true\" \
                   ts=\"0\" sig=\"AAAA\"/>";
        match parse_signed_caps_payload(xml) {
            Ok(_) => panic!("short sig must reject"),
            Err(StoreFlowError::Pep(msg)) => assert!(
                msg.contains("expected 64"),
                "expected length rejection, got {msg}"
            ),
            Err(other) => panic!("unexpected variant: {other}"),
        }
    }

    #[test]
    fn parse_signed_caps_rejects_missing_attr() {
        // No `sig` attribute.
        let xml = "<caps xmlns=\"urn:xmpp:omemo:westron:1\" sid=\"1\" \
                   speaks-omemo-2=\"true\" speaks-omemo-03=\"true\" ts=\"0\"/>";
        match parse_signed_caps_payload(xml) {
            Ok(_) => panic!("missing sig must reject"),
            Err(StoreFlowError::Pep(msg)) => assert!(
                msg.contains("missing sig"),
                "expected missing-attr rejection, got {msg}"
            ),
            Err(other) => panic!("unexpected variant: {other}"),
        }
    }

    #[test]
    fn parse_signed_caps_rejects_bad_bool() {
        let xml = "<caps xmlns=\"urn:xmpp:omemo:westron:1\" sid=\"1\" \
                   speaks-omemo-2=\"yes\" speaks-omemo-03=\"true\" \
                   ts=\"0\" sig=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"/>";
        match parse_signed_caps_payload(xml) {
            Ok(_) => panic!("bad bool must reject"),
            Err(StoreFlowError::Pep(msg)) => assert!(
                msg.contains("speaks-omemo-2") && msg.contains("expected true|false"),
                "expected bool rejection, got {msg}"
            ),
            Err(other) => panic!("unexpected variant: {other}"),
        }
    }

    #[test]
    fn default_self_caps_contains_all_three_specs() {
        let caps = default_self_caps();
        assert!(caps.specs.contains(&Spec::Westron));
        assert!(caps.specs.contains(&Spec::Omemo2));
        assert!(caps.specs.contains(&Spec::Omemo03));
        assert_eq!(caps.specs.len(), 3);
    }

    #[test]
    fn plan_outbound_wire_groups_recipients_by_best_spec() {
        let self_caps = default_self_caps();
        let recipients = vec![
            WestronRecipient {
                jid: "alice@example.org".into(),
                device_id: 1,
                caps: Caps::new([Spec::Westron, Spec::Omemo2]),
            },
            WestronRecipient {
                jid: "bob@example.org".into(),
                device_id: 2,
                caps: Caps::new([Spec::Omemo2, Spec::Omemo03]),
            },
            WestronRecipient {
                jid: "carol@example.org".into(),
                device_id: 3,
                caps: Caps::new([Spec::Omemo03]),
            },
        ];
        let plan = plan_outbound_wire(&self_caps, &recipients);
        assert_eq!(plan.unreachable.len(), 0);
        // alice → Westron (highest common w/ self_caps), bob → 2, carol → 0.3
        assert_eq!(plan.groups.get(&Spec::Westron).map(Vec::len), Some(1));
        assert_eq!(plan.groups.get(&Spec::Omemo2).map(Vec::len), Some(1));
        assert_eq!(plan.groups.get(&Spec::Omemo03).map(Vec::len), Some(1));
        assert_eq!(plan.groups[&Spec::Westron][0].jid, "alice@example.org");
        assert_eq!(plan.groups[&Spec::Omemo2][0].jid, "bob@example.org");
        assert_eq!(plan.groups[&Spec::Omemo03][0].jid, "carol@example.org");
    }

    #[test]
    fn plan_outbound_wire_flags_unreachable_when_no_common_spec() {
        // We only speak OMEMO 2; peer only speaks 0.3 → unreachable.
        let self_caps = Caps::new([Spec::Omemo2]);
        let recipients = vec![WestronRecipient {
            jid: "legacy@example.org".into(),
            device_id: 7,
            caps: Caps::new([Spec::Omemo03]),
        }];
        let plan = plan_outbound_wire(&self_caps, &recipients);
        assert_eq!(plan.groups.len(), 0);
        assert_eq!(plan.unreachable.len(), 1);
        assert_eq!(plan.unreachable[0].jid, "legacy@example.org");
    }

    #[test]
    fn signed_caps_payload_can_be_parsed_by_minidom_as_element() {
        // Sanity check that the wire helper's `Element::from_str` step
        // (used by `send_encrypted_with_caps`) will accept our output.
        let store = seeded_store();
        let caps = sign_caps(&store, 1001, 1_700_000_000, true, true).unwrap();
        let xml = encode_signed_caps_payload(&caps);
        let elem: xmpp_parsers::minidom::Element = xml.parse().expect("minidom accepts");
        assert_eq!(elem.name(), "caps");
        assert_eq!(elem.ns(), SIGNED_CAPS_NS);
    }
}
