//! Stanza-level OMEMO 0.3 (`eu.siacs.conversations.axolotl`) message
//! encryption / decryption — the OMEMO-0.3 mirror of [`crate::message`].
//!
//! Three notable deltas from the OMEMO 2 path:
//!
//! 1. Body AEAD is AES-128-GCM (`omemo_stanza::axolotl_aead`) instead
//!    of OMEMO 2's HMAC-SHA-256-truncated-to-16 SCE envelope. The IV
//!    rides along plaintext in the `<iv>` element.
//! 2. The body is **raw plaintext** — there is no XEP-0420 SCE
//!    envelope wrapping. Inbound returns the body bytes directly;
//!    callers do their own verification.
//! 3. The wire format is the axolotl stanza shape — flat
//!    `<key rid='...'>` children directly inside `<header>`, no
//!    per-JID grouping.

use omemo_doubleratchet::dh_ratchet::DhPrivProvider;
use omemo_oldmemo::{
    build_key_exchange as build_kex_old, parse_key_exchange as parse_kex_old, peek_dh_pub as peek_dh_pub_old,
    OldmemoError, OldmemoSession,
};
use omemo_stanza::axolotl_aead::{open_payload as open_old_payload, seal_payload as seal_old_payload, AxolotlAeadError};
use omemo_stanza::axolotl_stanza::{Encrypted as OldEncrypted, KeyEntry as OldKeyEntry};
use omemo_x3dh::{
    get_shared_secret_active_oldmemo, get_shared_secret_passive_oldmemo, Header as X3dhHeader, X3dhError,
    X3dhState,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageOldError {
    #[error("ratchet error: {0:?}")]
    Ratchet(omemo_doubleratchet::dh_ratchet::DhRatchetError),
    #[error("oldmemo wire-format error: {0}")]
    Oldmemo(OldmemoError),
    #[error("axolotl AEAD error: {0}")]
    Aead(#[from] AxolotlAeadError),
    #[error("our device id {0} not present in inbound key list")]
    OurDeviceNotInRecipients(u32),
    #[error("encrypted stanza has no <payload>")]
    PayloadMissing,
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
    #[error("inbound key entry was prekey=false; route to decrypt_message_oldmemo")]
    KexExpected,
    #[error("inbound key entry was prekey=true; route to decrypt_inbound_kex_oldmemo")]
    FollowExpected,
    #[error("our SPK id {0} not found in caller's lookup")]
    SpkIdNotFound(u32),
    #[error("our OPK id {0} not found in caller's lookup")]
    OpkIdNotFound(u32),
    #[error("SPK signature verification failed (bundle was tampered)")]
    BundleSpkVerifyFailed,
}

/// OMEMO-0.3 counterpart of [`crate::message::KexCarrier`]. Same
/// fields; but `ik` is the raw 32-byte X25519 (Curve25519) form, not
/// Ed25519 — the OMEMO 0.3 KEX wire format only carries Curve25519.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexCarrierOld {
    pub pk_id: u32,
    pub spk_id: u32,
    /// Our IK in raw 32-byte Curve25519 form. The encoder applies
    /// the `0x05` prefix on the wire.
    pub ik_curve: [u8; 32],
    /// Our ephemeral public (32 bytes Curve25519).
    pub ek: [u8; 32],
}

/// One recipient device for an OMEMO 0.3 fan-out. Mirrors
/// [`crate::message::Recipient`] but does not group by JID — the
/// 0.3 wire shape has no per-JID `<keys>` element.
pub struct RecipientOld<'a> {
    pub device_id: u32,
    pub session: &'a mut OldmemoSession,
    pub kex: Option<KexCarrierOld>,
}

/// Run X3DH active (oldmemo flavour) against `peer_bundle` and
/// bootstrap a fresh [`OldmemoSession`] in the active role. Mirrors
/// [`crate::message::bootstrap_active_session_from_bundle`].
///
/// The peer's bundle in OMEMO 0.3 form carries the IK as Ed25519
/// (in `identity_key_ed`), so we hand that to `omemo_x3dh` as-is —
/// the X3DH oldmemo entry point performs its own Ed25519→Curve25519
/// conversion internally.
pub fn bootstrap_active_session_oldmemo_from_bundle(
    own_state: &X3dhState,
    peer_bundle: &omemo_stanza::axolotl_stanza::Bundle,
    chosen_opk_id: u32,
    ephemeral_priv: [u8; 32],
    priv_provider: Box<dyn DhPrivProvider>,
) -> Result<(OldmemoSession, KexCarrierOld), MessageOldError> {
    // Convert the axolotl-shape bundle to an X3DH bundle. SPK / IK /
    // OPKs are all 32-byte raw values; the wire prefix has already
    // been stripped by the stanza parser.
    let chosen_opk = peer_bundle
        .prekeys
        .iter()
        .find(|pk| pk.id == chosen_opk_id)
        .ok_or(MessageOldError::OpkNotFound(chosen_opk_id))?;

    let x3dh_bundle = omemo_x3dh::Bundle {
        identity_key: peer_bundle.identity_key_ed,
        signed_pre_key: peer_bundle.signed_prekey_pub,
        signed_pre_key_sig: peer_bundle.signed_prekey_sig,
        pre_keys: peer_bundle
            .prekeys
            .iter()
            .map(|pk| pk.pub_key)
            .collect(),
    };

    let (output, _header) = get_shared_secret_active_oldmemo(
        own_state,
        &x3dh_bundle,
        &[],
        ephemeral_priv,
        Some(chosen_opk.pub_key),
        true,
    )
    .map_err(MessageOldError::X3dh)?;

    let session = OldmemoSession::create_active(
        output.associated_data,
        output.shared_secret.to_vec(),
        x3dh_bundle.signed_pre_key,
        priv_provider,
    )
    .map_err(MessageOldError::Ratchet)?;

    let ek_pub = omemo_xeddsa::priv_to_curve25519_pub(&ephemeral_priv);
    let own_ik_curve =
        omemo_xeddsa::ed25519_pub_to_curve25519_pub(&own_state.identity_key.ed25519_pub())
            .map_err(|e| MessageOldError::X3dh(X3dhError::XEdDsa(e)))?;
    let kex = KexCarrierOld {
        pk_id: chosen_opk_id,
        spk_id: peer_bundle.signed_prekey_id,
        ik_curve: own_ik_curve,
        ek: ek_pub,
    };
    Ok((session, kex))
}

/// Encrypt `plaintext` for one or more OMEMO 0.3 recipient devices.
/// Returns the [`OldEncrypted`] envelope ready for serialisation by
/// `omemo-stanza::axolotl_stanza`.
///
/// The body is sealed once via [`omemo_stanza::axolotl_aead::seal_payload`]
/// (single shared `<payload>` + per-message `<iv>`); the resulting
/// 32-byte `aes_key || gcm_tag` blob is then encrypted *per device*
/// through that device's `OldmemoSession`. Each recipient's per-device
/// output goes into its `<key rid=...>` element (with `prekey="true"`
/// when the recipient has a [`KexCarrierOld`]).
pub fn encrypt_message_oldmemo(
    sid: u32,
    recipients: &mut [RecipientOld<'_>],
    plaintext: &[u8],
) -> Result<OldEncrypted, MessageOldError> {
    let (payload_ct, iv, key_blob) = seal_old_payload(plaintext);

    let mut keys: Vec<OldKeyEntry> = Vec::with_capacity(recipients.len());
    for r in recipients.iter_mut() {
        let auth_blob = r
            .session
            .encrypt_message(&key_blob)
            .map_err(MessageOldError::Ratchet)?;
        let (data, prekey_flag) = if let Some(k) = &r.kex {
            let kex_bytes = build_kex_old(k.pk_id, k.spk_id, k.ik_curve, k.ek, &auth_blob);
            (kex_bytes, true)
        } else {
            (auth_blob, false)
        };
        keys.push(OldKeyEntry {
            rid: r.device_id,
            prekey: prekey_flag,
            data,
        });
    }

    Ok(OldEncrypted {
        sid,
        keys,
        iv: iv.to_vec(),
        payload: Some(payload_ct),
    })
}

fn locate_our_old_key(
    encrypted: &OldEncrypted,
    our_device_id: u32,
) -> Result<&OldKeyEntry, MessageOldError> {
    encrypted
        .keys
        .iter()
        .find(|k| k.rid == our_device_id)
        .ok_or(MessageOldError::OurDeviceNotInRecipients(our_device_id))
}

/// Whether an inbound OMEMO 0.3 `<encrypted>` carries a session-bootstrap
/// KEX (`prekey="true"`) or is a follow-up message on an existing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundOldKind {
    /// `prekey="true"` — the `<key>` carries an OMEMO 0.3
    /// `OMEMOKeyExchange`. Decrypt via [`decrypt_inbound_kex_oldmemo`].
    Kex,
    /// Bare `OMEMOAuthenticatedMessage`. Decrypt via [`decrypt_message_oldmemo`].
    Follow,
}

pub fn inbound_kind_oldmemo(
    encrypted: &OldEncrypted,
    our_device_id: u32,
) -> Result<InboundOldKind, MessageOldError> {
    let key = locate_our_old_key(encrypted, our_device_id)?;
    Ok(if key.prekey {
        InboundOldKind::Kex
    } else {
        InboundOldKind::Follow
    })
}

/// Inverse of [`encrypt_message_oldmemo`] for the follow-up path.
/// Locates our key entry, advances `our_session` to recover the
/// 32-byte AES-128 key blob, then opens the AES-128-GCM `<payload>`
/// against `<iv>`.
pub fn decrypt_message_oldmemo(
    encrypted: &OldEncrypted,
    our_device_id: u32,
    our_session: &mut OldmemoSession,
) -> Result<Vec<u8>, MessageOldError> {
    let key = locate_our_old_key(encrypted, our_device_id)?;
    if key.prekey {
        return Err(MessageOldError::KexExpected);
    }
    let key_blob = our_session
        .decrypt_message(&key.data)
        .map_err(MessageOldError::Oldmemo)?;
    let payload = encrypted
        .payload
        .as_ref()
        .ok_or(MessageOldError::PayloadMissing)?;
    Ok(open_old_payload(payload, &encrypted.iv, &key_blob)?)
}

/// Bootstrap a passive [`OldmemoSession`] from an inbound `<encrypted>`
/// whose key entry carries `prekey="true"`, decrypt the embedded first
/// message, return the new session + the body plaintext + the consumed
/// OPK id.
///
/// The peer's IK in the OMEMO 0.3 KEX is the **Curve25519** form (the
/// `parse_key_exchange` already strips the 0x05 prefix). The caller
/// must supply `peer_ik_pub_ed` — the Ed25519 form recovered either
/// from the peer's bundle (we already know the sign bit there from
/// the SPK signature byte 63 stuffing) or from a previously-trusted
/// device record. We cannot recover the Ed25519 form from the
/// Curve25519 form alone — the sign bit is missing.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_inbound_kex_oldmemo<S, P>(
    encrypted: &OldEncrypted,
    our_device_id: u32,
    own_state: &X3dhState,
    peer_ik_pub_ed: [u8; 32],
    spk_pub_by_id: S,
    opk_pub_by_id: P,
    priv_provider: Box<dyn DhPrivProvider>,
) -> Result<(OldmemoSession, Vec<u8>, u32), MessageOldError>
where
    S: FnOnce(u32) -> Option<[u8; 32]>,
    P: FnOnce(u32) -> Option<[u8; 32]>,
{
    let key = locate_our_old_key(encrypted, our_device_id)?;
    if !key.prekey {
        return Err(MessageOldError::FollowExpected);
    }
    let (pk_id, spk_id, _peer_ik_curve, peer_ek_pub, auth_blob) =
        parse_kex_old(&key.data).map_err(MessageOldError::Oldmemo)?;

    let spk_pub = spk_pub_by_id(spk_id).ok_or(MessageOldError::SpkIdNotFound(spk_id))?;
    let opk_pub = opk_pub_by_id(pk_id).ok_or(MessageOldError::OpkIdNotFound(pk_id))?;

    let header = X3dhHeader {
        identity_key: peer_ik_pub_ed,
        ephemeral_key: peer_ek_pub,
        signed_pre_key: spk_pub,
        pre_key: Some(opk_pub),
    };
    let (out, spk_pair) = get_shared_secret_passive_oldmemo(own_state, &header, &[], true)
        .map_err(MessageOldError::X3dh)?;

    let alice_first_pub = peek_dh_pub_old(&auth_blob).map_err(MessageOldError::Oldmemo)?;

    let mut session = OldmemoSession::create_passive(
        out.associated_data,
        out.shared_secret.to_vec(),
        spk_pair.priv_key,
        alice_first_pub,
        priv_provider,
    )
    .map_err(MessageOldError::Ratchet)?;

    let key_blob = session
        .decrypt_message(&auth_blob)
        .map_err(MessageOldError::Oldmemo)?;
    let payload = encrypted
        .payload
        .as_ref()
        .ok_or(MessageOldError::PayloadMissing)?;
    let plaintext = open_old_payload(payload, &encrypted.iv, &key_blob)?;

    Ok((session, plaintext, pk_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use omemo_oldmemo::fixed_priv_provider;

    fn make_pair(
        ad: Vec<u8>,
        root: Vec<u8>,
        bob_spk_priv: [u8; 32],
        alice_dr_privs: Vec<[u8; 32]>,
        bob_dr_privs: Vec<[u8; 32]>,
    ) -> (OldmemoSession, OldmemoSession) {
        let bob_spk_pub = omemo_xeddsa::priv_to_curve25519_pub(&bob_spk_priv);
        let mut alice = OldmemoSession::create_active(
            ad.clone(),
            root.clone(),
            bob_spk_pub,
            fixed_priv_provider(alice_dr_privs),
        )
        .unwrap();
        let warmup = alice.encrypt_message(b"warmup").unwrap();
        let alice_first_pub = peek_dh_pub_old(&warmup).unwrap();
        let mut bob = OldmemoSession::create_passive(
            ad,
            root,
            bob_spk_priv,
            alice_first_pub,
            fixed_priv_provider(bob_dr_privs),
        )
        .unwrap();
        let _ = bob.decrypt_message(&warmup).unwrap();
        (alice, bob)
    }

    #[test]
    fn round_trip_single_recipient() {
        // 66-byte AD (= IDENTITY_KEY_ENCODING_LENGTH * 2) matching
        // the oldmemo wire format AssociatedData shape.
        let ad = vec![0xAA; 66];
        let root = vec![0xBB; 32];
        let (mut alice, mut bob) = make_pair(
            ad,
            root,
            [0x11; 32],
            (1..=4).map(|i| [i as u8; 32]).collect(),
            (1..=4).map(|i| [(i + 16) as u8; 32]).collect(),
        );

        let body = b"hello bob (0.3)";
        let mut alice_recipients = [RecipientOld {
            device_id: 2002,
            session: &mut alice,
            kex: None,
        }];
        let encrypted = encrypt_message_oldmemo(1001, &mut alice_recipients, body).unwrap();
        assert_eq!(encrypted.sid, 1001);
        assert_eq!(encrypted.keys.len(), 1);
        assert!(!encrypted.keys[0].prekey);
        assert_eq!(encrypted.iv.len(), 12);

        let pt = decrypt_message_oldmemo(&encrypted, 2002, &mut bob).unwrap();
        assert_eq!(pt, body);
    }

    #[test]
    fn locate_rejects_wrong_device() {
        let ad = vec![0xAA; 66];
        let root = vec![0xBB; 32];
        let (mut alice, _) = make_pair(
            ad,
            root,
            [0x11; 32],
            (1..=2).map(|i| [i as u8; 32]).collect(),
            (1..=2).map(|i| [(i + 16) as u8; 32]).collect(),
        );
        let mut alice_recipients = [RecipientOld {
            device_id: 2002,
            session: &mut alice,
            kex: None,
        }];
        let encrypted = encrypt_message_oldmemo(1001, &mut alice_recipients, b"x").unwrap();
        match inbound_kind_oldmemo(&encrypted, 9999) {
            Err(MessageOldError::OurDeviceNotInRecipients(9999)) => {}
            other => panic!("expected OurDeviceNotInRecipients, got {other:?}"),
        }
    }
}
