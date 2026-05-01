//! Stanza-level OMEMO 2 message encryption / decryption (XEP-0384 v0.9
//! §3 + §4.4) plus the X3DH-active half of session bootstrap.
//!
//! Composes [`omemo_twomemo::seal_payload`] (the body encryption) with
//! per-recipient [`omemo_twomemo::TwomemoSession::encrypt_message`] (the
//! ratcheted key blob distribution) to build the
//! [`omemo_stanza::Encrypted`] envelope, and the inverse for the
//! receiving side.
//!
//! No XMPP I/O: this module produces / consumes the data model that
//! `omemo-stanza` serialises to / parses from XML. Wiring this into
//! actual `<message>` interception is the next sub-task.
//!
//! ## Session bootstrap
//! The very first message after X3DH active bootstrap MUST be wrapped
//! in an `OMEMOKeyExchange` so the peer can run X3DH passive. Use
//! [`bootstrap_active_session_from_bundle`] to derive a fresh session
//! from a peer bundle, then attach the returned [`KexCarrier`] on the
//! [`Recipient`] for that *first* outbound — [`encrypt_message`] will
//! then emit `kex=true`. Subsequent messages on the same session pass
//! `kex: None` and emit `kex=false`.

use omemo_doubleratchet::dh_ratchet::DhPrivProvider;
use omemo_stanza::{Encrypted, Key, KeysGroup};
use omemo_twomemo::{
    build_key_exchange, open_payload, seal_payload, SceError, TwomemoError, TwomemoSession,
};
use omemo_x3dh::{get_shared_secret_active, X3dhError, X3dhState};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("ratchet encrypt error: {0:?}")]
    RatchetEncrypt(omemo_doubleratchet::dh_ratchet::DhRatchetError),
    #[error("twomemo decrypt error: {0}")]
    TwomemoDecrypt(TwomemoError),
    #[error("SCE payload error: {0}")]
    Sce(#[from] SceError),
    #[error("our JID `{0}` not in recipient list")]
    OurJidNotInRecipients(String),
    #[error("our device id {0} not present in our recipient group")]
    OurDeviceNotInRecipients(u32),
    #[error("encrypted stanza has no <payload> (key-only message)")]
    PayloadMissing,
    #[error("twomemo wire-format error: {0}")]
    Twomemo(TwomemoError),
    #[error("X3DH error: {0}")]
    X3dh(X3dhError),
    #[error("invalid bundle field length (field={field}, expected={expected}, got={got})")]
    InvalidBundleField {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("OPK id {0} not present in peer bundle")]
    OpkNotFound(u32),
}

/// Material needed to wrap the very first message of a session in an
/// `OMEMOKeyExchange` so the peer can run X3DH passive.
///
/// Produced by [`bootstrap_active_session_from_bundle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexCarrier {
    /// `<pk id=...>` of the peer's OPK we consumed.
    pub pk_id: u32,
    /// `<spk id=...>` of the peer's signed pre-key.
    pub spk_id: u32,
    /// Our IK in Ed25519 form (32 bytes).
    pub ik: [u8; 32],
    /// Our ephemeral public key (32 bytes Curve25519).
    pub ek: [u8; 32],
}

/// Where to send one copy of the encrypted message body.
///
/// Several recipients with the same `jid` are grouped into one
/// `<keys jid=...>` element on the wire.
pub struct Recipient<'a> {
    /// The recipient's bare JID (string form).
    pub jid: &'a str,
    /// The recipient's device id.
    pub device_id: u32,
    /// The session we use to encrypt the per-message key blob for this
    /// device. Each session is mutated forward by exactly one
    /// `encrypt_message` step.
    pub session: &'a mut TwomemoSession,
    /// `Some` only on the first outbound message of a freshly bootstrapped
    /// session (see [`bootstrap_active_session_from_bundle`]). Triggers
    /// `kex=true` and `OMEMOKeyExchange` wrapping for this device.
    pub kex: Option<KexCarrier>,
}

/// Run X3DH active against `peer_bundle` (the recipient's published
/// bundle) and bootstrap a fresh [`TwomemoSession`] in the active role.
///
/// Returns the live session plus the [`KexCarrier`] callers attach to
/// their first outbound [`Recipient`] for that device.
///
/// `chosen_opk_id` selects which OPK to consume from the bundle —
/// callers MUST track which OPKs they've seen and avoid re-using one
/// (XEP-0384 §5.3.2; the receiver enforces consume-once on their side).
///
/// `ephemeral_priv` should be 32 fresh random bytes in production; tests
/// pass a fixture value for byte-equal replay.
pub fn bootstrap_active_session_from_bundle(
    own_state: &X3dhState,
    peer_bundle: &omemo_stanza::Bundle,
    chosen_opk_id: u32,
    ephemeral_priv: [u8; 32],
    priv_provider: Box<dyn DhPrivProvider>,
) -> Result<(TwomemoSession, KexCarrier), MessageError> {
    let x3dh_bundle = stanza_bundle_to_x3dh(peer_bundle)?;
    let chosen_opk_pub = peer_bundle
        .prekeys
        .iter()
        .find(|pk| pk.id == chosen_opk_id)
        .ok_or(MessageError::OpkNotFound(chosen_opk_id))?;
    let chosen_opk_pub_bytes = bundle_field_32(&chosen_opk_pub.pub_key, "prekey")?;

    let (output, _header) = get_shared_secret_active(
        own_state,
        &x3dh_bundle,
        &[],
        ephemeral_priv,
        Some(chosen_opk_pub_bytes),
        true,
    )
    .map_err(MessageError::X3dh)?;

    let session = TwomemoSession::create_active(
        output.associated_data,
        output.shared_secret.to_vec(),
        x3dh_bundle.signed_pre_key,
        priv_provider,
    )
    .map_err(MessageError::RatchetEncrypt)?;

    let ek_pub = omemo_xeddsa::priv_to_curve25519_pub(&ephemeral_priv);
    let kex = KexCarrier {
        pk_id: chosen_opk_id,
        spk_id: peer_bundle.spk.id,
        ik: own_state.identity_key.ed25519_pub(),
        ek: ek_pub,
    };
    Ok((session, kex))
}

fn bundle_field_32(field: &[u8], name: &'static str) -> Result<[u8; 32], MessageError> {
    if field.len() != 32 {
        return Err(MessageError::InvalidBundleField {
            field: name,
            expected: 32,
            got: field.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(field);
    Ok(out)
}

fn stanza_bundle_to_x3dh(b: &omemo_stanza::Bundle) -> Result<omemo_x3dh::Bundle, MessageError> {
    let identity_key = bundle_field_32(&b.ik, "ik")?;
    let signed_pre_key = bundle_field_32(&b.spk.pub_key, "spk")?;
    if b.spks.len() != 64 {
        return Err(MessageError::InvalidBundleField {
            field: "spks",
            expected: 64,
            got: b.spks.len(),
        });
    }
    let mut signed_pre_key_sig = [0u8; 64];
    signed_pre_key_sig.copy_from_slice(&b.spks);
    let pre_keys: Result<Vec<[u8; 32]>, _> = b
        .prekeys
        .iter()
        .map(|pk| bundle_field_32(&pk.pub_key, "prekey"))
        .collect();
    Ok(omemo_x3dh::Bundle {
        identity_key,
        signed_pre_key,
        signed_pre_key_sig,
        pre_keys: pre_keys?,
    })
}

/// Encrypt `plaintext` for one or more recipient devices, returning
/// the [`Encrypted`] envelope ready for serialisation by `omemo-stanza`.
///
/// The body is sealed once via [`seal_payload`] (single shared
/// `<payload>`); the resulting 48-byte `key || hmac` blob is then
/// encrypted *per device* through that device's session. Each
/// recipient's per-device output goes into its `<key rid=...>` element,
/// wrapped in `OMEMOKeyExchange` (`kex=true`) when [`Recipient::kex`]
/// is `Some`, otherwise as a bare `OMEMOAuthenticatedMessage`.
pub fn encrypt_message(
    sid: u32,
    recipients: &mut [Recipient<'_>],
    plaintext: &[u8],
) -> Result<Encrypted, MessageError> {
    let (payload_ct, key_blob) = seal_payload(plaintext);

    // Group recipients by JID, preserving insertion order so the wire
    // format is deterministic.
    let mut groups: Vec<KeysGroup> = Vec::new();
    for r in recipients.iter_mut() {
        let auth_bytes = r
            .session
            .encrypt_message(&key_blob)
            .map_err(MessageError::RatchetEncrypt)?;
        let (data, kex_flag) = if let Some(k) = &r.kex {
            let kex_bytes = build_key_exchange(k.pk_id, k.spk_id, k.ik, k.ek, &auth_bytes)
                .map_err(MessageError::Twomemo)?;
            (kex_bytes, true)
        } else {
            (auth_bytes, false)
        };
        let key_entry = Key {
            rid: r.device_id,
            kex: kex_flag,
            data,
        };
        if let Some(group) = groups.iter_mut().find(|g| g.jid == r.jid) {
            group.keys.push(key_entry);
        } else {
            groups.push(KeysGroup {
                jid: r.jid.to_owned(),
                keys: vec![key_entry],
            });
        }
    }

    Ok(Encrypted {
        sid,
        keys: groups,
        payload: Some(payload_ct),
    })
}

/// Inverse of [`encrypt_message`].
///
/// Locates our `<key rid=our_device_id>` inside the `<keys jid=our_jid>`
/// group, advances `our_session` to recover the 48-byte key blob, then
/// uses it to [`open_payload`] the shared `<payload>`.
pub fn decrypt_message(
    encrypted: &Encrypted,
    our_jid: &str,
    our_device_id: u32,
    our_session: &mut TwomemoSession,
) -> Result<Vec<u8>, MessageError> {
    let group = encrypted
        .keys
        .iter()
        .find(|g| g.jid == our_jid)
        .ok_or_else(|| MessageError::OurJidNotInRecipients(our_jid.to_owned()))?;
    let key = group
        .keys
        .iter()
        .find(|k| k.rid == our_device_id)
        .ok_or(MessageError::OurDeviceNotInRecipients(our_device_id))?;
    let key_blob = our_session
        .decrypt_message(&key.data)
        .map_err(MessageError::TwomemoDecrypt)?;
    let payload = encrypted
        .payload
        .as_ref()
        .ok_or(MessageError::PayloadMissing)?;
    Ok(open_payload(payload, &key_blob)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use omemo_twomemo::{fixed_priv_provider, peek_dh_pub};

    /// Build a (alice_active, bob_passive) session pair for one device,
    /// in lockstep. Both sides share the same X3DH-derived `ad` and
    /// `root_chain_key` — for the test we just hand them fixed bytes.
    /// Returns `(alice, bob)` where each side has decrypted alice's
    /// initial "warm-up" message so the ratchets are aligned.
    fn make_session_pair(
        ad: Vec<u8>,
        root: Vec<u8>,
        bob_spk_priv: [u8; 32],
        alice_dr_privs: Vec<[u8; 32]>,
        bob_dr_privs: Vec<[u8; 32]>,
    ) -> (TwomemoSession, TwomemoSession) {
        let bob_spk_pub = omemo_xeddsa::priv_to_curve25519_pub(&bob_spk_priv);
        let mut alice = TwomemoSession::create_active(
            ad.clone(),
            root.clone(),
            bob_spk_pub,
            fixed_priv_provider(alice_dr_privs),
        )
        .expect("alice create_active");

        // alice encrypts a warm-up so we can extract her first ratchet pub
        // for bob's passive bootstrap. The warm-up message itself is
        // discarded; subsequent messages build on top of the now-aligned
        // ratchets.
        let warmup = alice.encrypt_message(b"warmup").expect("alice warmup");
        let alice_first_pub = peek_dh_pub(&warmup).expect("peek dh pub");

        let mut bob = TwomemoSession::create_passive(
            ad,
            root,
            bob_spk_priv,
            alice_first_pub,
            fixed_priv_provider(bob_dr_privs),
        )
        .expect("bob create_passive");

        let _ = bob.decrypt_message(&warmup).expect("bob decrypts warmup");
        (alice, bob)
    }

    #[test]
    fn alice_to_bob_single_device_round_trip() {
        let ad = vec![0xAA; 64];
        let root = vec![0xBB; 32];
        let (mut alice_to_bob, mut bob_recv) = make_session_pair(
            ad,
            root,
            [0x11; 32],
            (1..=4).map(|i| [i as u8; 32]).collect(),
            (1..=4).map(|i| [(i + 16) as u8; 32]).collect(),
        );

        const ALICE_DEV: u32 = 27_183;
        const BOB_DEV: u32 = 31_415;
        const BOB_JID: &str = "bob@example.org";
        let plaintext = b"hello SCE bob";

        let mut recipients = [Recipient {
            jid: BOB_JID,
            device_id: BOB_DEV,
            session: &mut alice_to_bob,
            kex: None,
        }];
        let encrypted =
            encrypt_message(ALICE_DEV, &mut recipients, plaintext).expect("alice encrypt");
        assert_eq!(encrypted.sid, ALICE_DEV);
        assert_eq!(encrypted.keys.len(), 1, "single recipient JID group");
        assert_eq!(encrypted.keys[0].jid, BOB_JID);
        assert_eq!(encrypted.keys[0].keys.len(), 1, "single recipient device");
        assert!(!encrypted.keys[0].keys[0].kex, "kex flag false (no X3DH)");
        assert!(encrypted.payload.is_some(), "<payload> present");

        let recovered =
            decrypt_message(&encrypted, BOB_JID, BOB_DEV, &mut bob_recv).expect("bob decrypt");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn alice_to_two_bob_devices_round_trip() {
        let plaintext = b"single payload, two recipients";
        const ALICE_DEV: u32 = 27_183;
        const BOB_DEV1: u32 = 31_415;
        const BOB_DEV2: u32 = 27_182;
        const BOB_JID: &str = "bob@example.org";

        let (mut alice_to_dev1, mut bob_dev1) = make_session_pair(
            vec![0xAA; 64],
            vec![0xBB; 32],
            [0x11; 32],
            (1..=4).map(|i| [i as u8; 32]).collect(),
            (1..=4).map(|i| [(i + 16) as u8; 32]).collect(),
        );
        let (mut alice_to_dev2, mut bob_dev2) = make_session_pair(
            vec![0xCC; 64],
            vec![0xDD; 32],
            [0x22; 32],
            (1..=4).map(|i| [(i + 32) as u8; 32]).collect(),
            (1..=4).map(|i| [(i + 48) as u8; 32]).collect(),
        );

        let mut recipients = [
            Recipient {
                jid: BOB_JID,
                device_id: BOB_DEV1,
                session: &mut alice_to_dev1,
                kex: None,
            },
            Recipient {
                jid: BOB_JID,
                device_id: BOB_DEV2,
                session: &mut alice_to_dev2,
                kex: None,
            },
        ];
        let encrypted =
            encrypt_message(ALICE_DEV, &mut recipients, plaintext).expect("alice encrypt");

        assert_eq!(encrypted.keys.len(), 1, "same JID → single group");
        assert_eq!(encrypted.keys[0].keys.len(), 2, "two device entries");
        let payload = encrypted
            .payload
            .clone()
            .expect("payload present in multi-recipient");
        assert!(!payload.is_empty());

        let r1 = decrypt_message(&encrypted, BOB_JID, BOB_DEV1, &mut bob_dev1)
            .expect("bob dev1 decrypt");
        let r2 = decrypt_message(&encrypted, BOB_JID, BOB_DEV2, &mut bob_dev2)
            .expect("bob dev2 decrypt");
        assert_eq!(r1, plaintext);
        assert_eq!(r2, plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_jid() {
        let (mut alice, mut bob) = make_session_pair(
            vec![1; 64],
            vec![2; 32],
            [3; 32],
            (1..=4).map(|i| [i as u8; 32]).collect(),
            (1..=4).map(|i| [(i + 8) as u8; 32]).collect(),
        );
        let mut recipients = [Recipient {
            jid: "bob@example.org",
            device_id: 100,
            session: &mut alice,
            kex: None,
        }];
        let encrypted = encrypt_message(1, &mut recipients, b"data").unwrap();

        match decrypt_message(&encrypted, "carol@example.org", 100, &mut bob) {
            Err(MessageError::OurJidNotInRecipients(j)) => assert_eq!(j, "carol@example.org"),
            other => panic!("expected OurJidNotInRecipients, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_rejects_wrong_device() {
        let (mut alice, mut bob) = make_session_pair(
            vec![1; 64],
            vec![2; 32],
            [3; 32],
            (1..=4).map(|i| [i as u8; 32]).collect(),
            (1..=4).map(|i| [(i + 8) as u8; 32]).collect(),
        );
        let mut recipients = [Recipient {
            jid: "bob@example.org",
            device_id: 100,
            session: &mut alice,
            kex: None,
        }];
        let encrypted = encrypt_message(1, &mut recipients, b"data").unwrap();

        match decrypt_message(&encrypted, "bob@example.org", 999, &mut bob) {
            Err(MessageError::OurDeviceNotInRecipients(d)) => assert_eq!(d, 999),
            other => panic!("expected OurDeviceNotInRecipients, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // X3DH active bootstrap + KEX round-trip
    // -----------------------------------------------------------------

    use omemo_twomemo::parse_key_exchange;
    use omemo_x3dh::{
        get_shared_secret_passive, Header as X3dhHeader, IdentityKeyPair, PreKeyPair,
        SignedPreKeyPair, X3dhState,
    };

    fn make_x3dh_state(
        ik_seed: [u8; 32],
        spk_priv: [u8; 32],
        spk_sig_nonce: [u8; 64],
        opk_privs: Vec<[u8; 32]>,
    ) -> X3dhState {
        let ik = IdentityKeyPair::Seed(ik_seed);
        let spk = SignedPreKeyPair::create(&ik, spk_priv, spk_sig_nonce, 0);
        let pre_keys = opk_privs
            .into_iter()
            .map(|p| PreKeyPair { priv_key: p })
            .collect();
        X3dhState {
            identity_key: ik,
            signed_pre_key: spk,
            old_signed_pre_key: None,
            pre_keys,
        }
    }

    fn bundle_stanza_from_state(
        state: &X3dhState,
        spk_id: u32,
        opk_ids: &[u32],
    ) -> omemo_stanza::Bundle {
        omemo_stanza::Bundle {
            spk: omemo_stanza::SignedPreKey {
                id: spk_id,
                pub_key: state.signed_pre_key.pub_key().to_vec(),
            },
            spks: state.signed_pre_key.sig.to_vec(),
            ik: state.identity_key.ed25519_pub().to_vec(),
            prekeys: state
                .pre_keys
                .iter()
                .zip(opk_ids)
                .map(|(pk, &id)| omemo_stanza::PreKey {
                    id,
                    pub_key: pk.pub_key().to_vec(),
                })
                .collect(),
        }
    }

    #[test]
    fn alice_bootstraps_active_session_and_kex_round_trips_to_bob() {
        // Alice's full state.
        let alice_state = make_x3dh_state([0xAA; 32], [0x11; 32], [0xCC; 64], vec![[0x21; 32]]);
        // Bob's state with two OPKs (ids 10, 11).
        let bob_state = make_x3dh_state(
            [0xBB; 32],
            [0x22; 32],
            [0xDD; 64],
            vec![[0x31; 32], [0x32; 32]],
        );
        let bob_spk_id: u32 = 1;
        let bob_opk_ids: [u32; 2] = [10, 11];
        let bob_bundle_stanza = bundle_stanza_from_state(&bob_state, bob_spk_id, &bob_opk_ids);

        // Alice bootstraps active session against bob's bundle, picking OPK 10.
        let chosen_opk_id = bob_opk_ids[0];
        let alice_ek_priv = [0x42; 32];
        let alice_dr_privs: Vec<[u8; 32]> = (1..=4).map(|i| [(0x50 + i) as u8; 32]).collect();
        let (mut alice_session, kex) = bootstrap_active_session_from_bundle(
            &alice_state,
            &bob_bundle_stanza,
            chosen_opk_id,
            alice_ek_priv,
            fixed_priv_provider(alice_dr_privs),
        )
        .expect("alice bootstrap");

        assert_eq!(kex.pk_id, chosen_opk_id);
        assert_eq!(kex.spk_id, bob_spk_id);
        assert_eq!(kex.ik, alice_state.identity_key.ed25519_pub());
        assert_eq!(kex.ek, omemo_xeddsa::priv_to_curve25519_pub(&alice_ek_priv));

        const ALICE_DEV: u32 = 1;
        const BOB_DEV: u32 = 2;
        const BOB_JID: &str = "bob@example.org";
        let plaintext = b"first message after X3DH active";

        let mut recipients = [Recipient {
            jid: BOB_JID,
            device_id: BOB_DEV,
            session: &mut alice_session,
            kex: Some(kex.clone()),
        }];
        let encrypted =
            encrypt_message(ALICE_DEV, &mut recipients, plaintext).expect("alice encrypt");
        assert!(
            encrypted.keys[0].keys[0].kex,
            "kex=true on first message after X3DH active"
        );

        // ---- Bob's side: parse KEX, run X3DH passive, build session, decrypt.
        let key = &encrypted.keys[0].keys[0];
        let (got_pk_id, got_spk_id, got_ik, got_ek, auth_bytes) =
            parse_key_exchange(&key.data).expect("parse_key_exchange");
        assert_eq!(got_pk_id, chosen_opk_id);
        assert_eq!(got_spk_id, bob_spk_id);
        assert_eq!(got_ik, alice_state.identity_key.ed25519_pub());

        // Bob looks up the actual SPK / OPK pub bytes from his state via
        // the IDs the receiver carried. (In production these IDs index
        // into the SQLite store; here we just hand-thread them from the
        // arrays we constructed above.)
        let bob_spk_pub = bob_state.signed_pre_key.pub_key();
        let bob_opk_pub = bob_state.pre_keys[0].pub_key();
        let header = X3dhHeader {
            identity_key: got_ik,
            ephemeral_key: got_ek,
            signed_pre_key: bob_spk_pub,
            pre_key: Some(bob_opk_pub),
        };
        let (bob_x3dh_out, _spk) =
            get_shared_secret_passive(&bob_state, &header, &[], true).expect("bob X3DH passive");

        let alice_first_pub = peek_dh_pub(&auth_bytes).expect("peek dh");
        let bob_dr_privs: Vec<[u8; 32]> = (1..=4).map(|i| [(0x70 + i) as u8; 32]).collect();
        let mut bob_session = TwomemoSession::create_passive(
            bob_x3dh_out.associated_data,
            bob_x3dh_out.shared_secret.to_vec(),
            bob_state.signed_pre_key.priv_key,
            alice_first_pub,
            fixed_priv_provider(bob_dr_privs),
        )
        .expect("bob create_passive");

        // The auth_msg inside the KEX is M0; bob decrypts it directly.
        let key_blob = bob_session
            .decrypt_message(&auth_bytes)
            .expect("bob decrypt M0");
        let payload = encrypted.payload.as_ref().expect("payload");
        let recovered = omemo_twomemo::open_payload(payload, &key_blob).expect("open_payload");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn bootstrap_rejects_unknown_opk_id() {
        let alice_state = make_x3dh_state([0xAA; 32], [0x11; 32], [0xCC; 64], vec![[0x21; 32]]);
        let bob_state = make_x3dh_state([0xBB; 32], [0x22; 32], [0xDD; 64], vec![[0x31; 32]]);
        let bundle = bundle_stanza_from_state(&bob_state, 1, &[10]);

        let result = bootstrap_active_session_from_bundle(
            &alice_state,
            &bundle,
            999,
            [0x42; 32],
            fixed_priv_provider(vec![[1; 32]]),
        );
        match result {
            Err(MessageError::OpkNotFound(id)) => assert_eq!(id, 999),
            Err(other) => panic!("expected OpkNotFound(999), got error {other:?}"),
            Ok(_) => panic!("expected OpkNotFound(999), got Ok"),
        }
    }
}
