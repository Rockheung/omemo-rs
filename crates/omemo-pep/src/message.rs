//! Stanza-level OMEMO 2 message encryption / decryption (XEP-0384 v0.9
//! §3 + §4.4).
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
//! Sessions are assumed already bootstrapped (active + matching
//! passive). Building OMEMOKeyExchange wrappers for the very first
//! message of a session is queued for the X3DH-aware outbound
//! interceptor (see TODO.md Stage 4). This means [`encrypt_message`]
//! emits `kex=false` for every recipient — fine for the second message
//! onwards, plus for tests that pre-bootstrap both sides.

use omemo_stanza::{Encrypted, Key, KeysGroup};
use omemo_twomemo::{open_payload, seal_payload, SceError, TwomemoError, TwomemoSession};
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
}

/// Encrypt `plaintext` for one or more recipient devices, returning
/// the [`Encrypted`] envelope ready for serialisation by `omemo-stanza`.
///
/// The body is sealed once via [`seal_payload`] (single shared
/// `<payload>`); the resulting 48-byte `key || hmac` blob is then
/// encrypted *per device* through that device's session, producing one
/// `<key rid=...>` per device.
///
/// All `kex` flags emitted are `false`. Rationale in the module-level
/// doc.
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
        let key_entry = Key {
            rid: r.device_id,
            kex: false,
            data: auth_bytes,
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
            },
            Recipient {
                jid: BOB_JID,
                device_id: BOB_DEV2,
                session: &mut alice_to_dev2,
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
        }];
        let encrypted = encrypt_message(1, &mut recipients, b"data").unwrap();

        match decrypt_message(&encrypted, "bob@example.org", 999, &mut bob) {
            Err(MessageError::OurDeviceNotInRecipients(d)) => assert_eq!(d, 999),
            other => panic!("expected OurDeviceNotInRecipients, got {other:?}"),
        }
    }
}
