//! XEP-0384 v0.3 (`eu.siacs.conversations.axolotl`) message-body
//! AEAD: AES-128-GCM.
//!
//! Distinct from the OMEMO 2 SCE envelope ([`crate::sce`]). The
//! 0.3 spec encrypts the body once with a fresh AES-128 key + IV,
//! then distributes `key || gcm_tag` (32 bytes) per recipient
//! device through the ratchet. The IV is carried as plaintext in
//! the `<iv>` element of the message header.
//!
//! Key blob layout (matches python-oldmemo's
//! `EncryptedKeyMaterialImpl` for the over-the-wire-with-MAC form):
//!
//! ```text
//! key_blob[0..16]  = AES-128 key
//! key_blob[16..32] = GCM authentication tag
//! ```
//!
//! Both halves are 16 bytes. Total blob length is
//! [`PAYLOAD_KEY_BLOB_LEN`] = 32. The IV is an out-of-band 12-byte
//! value transported in the `<iv>` element next to the ciphertext.
//!
//! Note that, unlike OMEMO 2's SCE, OMEMO 0.3 never wraps the
//! plaintext in an extra envelope element. The plaintext fed in
//! here is the raw message body bytes.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit};
use rand_core::RngCore as _;
use thiserror::Error;
use zeroize::Zeroize as _;

/// AES-128-GCM IV length used by every OMEMO-0.3 implementation in
/// the wild.
pub const IV_LEN: usize = 12;
/// AES-128 key length.
pub const KEY_LEN: usize = 16;
/// GCM tag length (truncation is not used).
pub const TAG_LEN: usize = 16;
/// Length of the per-message blob distributed via the ratchet:
/// `key (16) || tag (16)` = 32 bytes.
pub const PAYLOAD_KEY_BLOB_LEN: usize = KEY_LEN + TAG_LEN;

#[derive(Debug, Error)]
pub enum AxolotlAeadError {
    #[error("GCM authentication tag mismatch (tampered or wrong key)")]
    AuthFailed,
    #[error("invalid key_blob length: expected {PAYLOAD_KEY_BLOB_LEN}, got {0}")]
    InvalidKeyBlobLength(usize),
    #[error("invalid iv length: expected {IV_LEN}, got {0}")]
    InvalidIvLength(usize),
}

/// Seal `plaintext` for multi-recipient distribution per OMEMO 0.3.
/// Returns `(payload_ciphertext, iv, key_blob)`.
///
/// * `payload_ciphertext` goes into the `<payload>` element (single
///   copy, identical for every recipient).
/// * `iv` (12 bytes) goes into the `<iv>` element. Random per
///   message — never reuse with the same `key`.
/// * `key_blob` (32 bytes: `aes_key || gcm_tag`) is encrypted once
///   per recipient device via that device's ratchet session,
///   yielding the per-`<key rid>` blob.
pub fn seal_payload(plaintext: &[u8]) -> (Vec<u8>, [u8; IV_LEN], [u8; PAYLOAD_KEY_BLOB_LEN]) {
    let mut key = [0u8; KEY_LEN];
    rand_core::OsRng.fill_bytes(&mut key);
    let mut iv = [0u8; IV_LEN];
    rand_core::OsRng.fill_bytes(&mut iv);
    let result = seal_payload_with_key_iv(&key, &iv, plaintext);
    key.zeroize();
    let (ct, blob) = result;
    (ct, iv, blob)
}

/// Deterministic counterpart of [`seal_payload`] for replay tests.
/// `key` and `iv` should be uniformly random in production.
pub fn seal_payload_with_key_iv(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; PAYLOAD_KEY_BLOB_LEN]) {
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(iv), b"", &mut buf)
        .expect("AES-128-GCM encrypt in-place");

    let mut blob = [0u8; PAYLOAD_KEY_BLOB_LEN];
    blob[..KEY_LEN].copy_from_slice(key);
    blob[KEY_LEN..].copy_from_slice(tag.as_slice());
    (buf, blob)
}

/// Inverse of [`seal_payload`]. Returns the decrypted plaintext.
pub fn open_payload(
    ciphertext: &[u8],
    iv: &[u8],
    key_blob: &[u8],
) -> Result<Vec<u8>, AxolotlAeadError> {
    if iv.len() != IV_LEN {
        return Err(AxolotlAeadError::InvalidIvLength(iv.len()));
    }
    if key_blob.len() != PAYLOAD_KEY_BLOB_LEN {
        return Err(AxolotlAeadError::InvalidKeyBlobLength(key_blob.len()));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&key_blob[..KEY_LEN]);
    let tag = GenericArray::from_slice(&key_blob[KEY_LEN..]);

    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    let mut buf = ciphertext.to_vec();
    let ok = cipher
        .decrypt_in_place_detached(GenericArray::from_slice(iv), b"", &mut buf, tag)
        .is_ok();
    key.zeroize();
    if !ok {
        return Err(AxolotlAeadError::AuthFailed);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_random_key_iv() {
        let pt = b"the quick brown fox jumps over the lazy dog";
        let (ct, iv, blob) = seal_payload(pt);
        assert_ne!(ct, pt, "ciphertext differs from plaintext");
        assert_eq!(iv.len(), IV_LEN);
        assert_eq!(blob.len(), PAYLOAD_KEY_BLOB_LEN);
        let recovered = open_payload(&ct, &iv, &blob).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn round_trip_deterministic() {
        let key = [0xAAu8; KEY_LEN];
        let iv = [0xBBu8; IV_LEN];
        let pt = b"hello axolotl";
        let (ct1, blob1) = seal_payload_with_key_iv(&key, &iv, pt);
        let (ct2, blob2) = seal_payload_with_key_iv(&key, &iv, pt);
        assert_eq!(ct1, ct2);
        assert_eq!(blob1, blob2);
        let recovered = open_payload(&ct1, &iv, &blob1).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn tampered_payload_rejected() {
        let pt = b"important secret";
        let (mut ct, iv, blob) = seal_payload(pt);
        ct[3] ^= 0x40;
        match open_payload(&ct, &iv, &blob) {
            Err(AxolotlAeadError::AuthFailed) => {}
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[test]
    fn tampered_tag_rejected() {
        let pt = b"important secret";
        let (ct, iv, mut blob) = seal_payload(pt);
        // Flip a tag byte (bytes 16..32 of the blob).
        blob[20] ^= 0x80;
        match open_payload(&ct, &iv, &blob) {
            Err(AxolotlAeadError::AuthFailed) => {}
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_blob_length_rejected() {
        let (ct, iv, _blob) = seal_payload(b"x");
        let bad = vec![0u8; PAYLOAD_KEY_BLOB_LEN - 1];
        match open_payload(&ct, &iv, &bad) {
            Err(AxolotlAeadError::InvalidKeyBlobLength(got)) => {
                assert_eq!(got, PAYLOAD_KEY_BLOB_LEN - 1)
            }
            other => panic!("expected InvalidKeyBlobLength, got {other:?}"),
        }
    }

    #[test]
    fn wrong_iv_length_rejected() {
        let (ct, _iv, blob) = seal_payload(b"x");
        let bad_iv = [0u8; IV_LEN - 1];
        match open_payload(&ct, &bad_iv, &blob) {
            Err(AxolotlAeadError::InvalidIvLength(got)) => assert_eq!(got, IV_LEN - 1),
            other => panic!("expected InvalidIvLength, got {other:?}"),
        }
    }

    #[test]
    fn iv_changes_per_random_call() {
        // Two seal_payload calls on the same plaintext should pick
        // two different random ivs. Vanishingly small chance of
        // collision in a healthy OS RNG.
        let (_ct1, iv1, _b1) = seal_payload(b"same plaintext");
        let (_ct2, iv2, _b2) = seal_payload(b"same plaintext");
        assert_ne!(iv1, iv2, "OS RNG produces fresh IVs");
    }
}
