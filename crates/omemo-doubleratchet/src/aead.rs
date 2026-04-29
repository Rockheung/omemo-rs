//! AES-256-CBC + HMAC AEAD — port of `python-doubleratchet`'s
//! `recommended/aead_aes_hmac.py`.
//!
//! Wire layout produced by [`encrypt`]:
//!
//! ```text
//! ciphertext = AES-256-CBC(PKCS#7 pad(plaintext))
//! tag        = HMAC-<hash>(auth_key, associated_data || ciphertext)   // full digest
//! output     = ciphertext || tag
//! ```
//!
//! Key/IV/auth_key are all derived from the AEAD key via HKDF with a zero salt
//! of `hash.size()` bytes:
//!
//! ```text
//! hkdf_out      = HKDF-<hash>(salt = 0^hash_size, ikm = key, info = info, len = 80)
//! enc_key       = hkdf_out[ 0..32]
//! auth_key      = hkdf_out[32..64]
//! iv            = hkdf_out[64..80]
//! ```
//!
//! Note: this is the *base* AEAD. OMEMO 2 over the wire (twomemo) wraps the
//! ciphertext in a protobuf and uses a 16-byte HMAC tail; that override
//! lives in `omemo-twomemo`, not here.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroize;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Hash function selector for the AEAD's HKDF and HMAC. Matches the variants
/// of `python-doubleratchet`'s `HashFunction` that this AEAD supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    Sha256,
    Sha512,
}

impl HashFunction {
    pub fn size(self) -> usize {
        match self {
            HashFunction::Sha256 => 32,
            HashFunction::Sha512 => 64,
        }
    }
}

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("authentication tags do not match")]
    AuthenticationFailed,
    #[error("ciphertext shorter than authentication tag")]
    CiphertextTooShort,
    #[error("invalid PKCS#7 padding")]
    InvalidPadding,
}

const HKDF_OUT_LEN: usize = 80;

fn derive(hash: HashFunction, key: &[u8], info: &[u8]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let mut out = [0u8; HKDF_OUT_LEN];
    match hash {
        HashFunction::Sha256 => {
            let salt = [0u8; 32];
            Hkdf::<Sha256>::new(Some(&salt), key)
                .expand(info, &mut out)
                .expect("HKDF-SHA256 expand of 80 bytes is well within the limit");
        }
        HashFunction::Sha512 => {
            let salt = [0u8; 64];
            Hkdf::<Sha512>::new(Some(&salt), key)
                .expand(info, &mut out)
                .expect("HKDF-SHA512 expand of 80 bytes is well within the limit");
        }
    }
    let mut enc = [0u8; 32];
    let mut auth = [0u8; 32];
    let mut iv = [0u8; 16];
    enc.copy_from_slice(&out[..32]);
    auth.copy_from_slice(&out[32..64]);
    iv.copy_from_slice(&out[64..80]);
    out.zeroize();
    (enc, auth, iv)
}

fn hmac(hash: HashFunction, key: &[u8], data: &[u8]) -> Vec<u8> {
    match hash {
        HashFunction::Sha256 => {
            let mut m =
                <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        HashFunction::Sha512 => {
            let mut m =
                <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

pub fn encrypt(
    hash: HashFunction,
    info: &[u8],
    key: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let (mut enc_key, mut auth_key, iv) = derive(hash, key, info);

    let ciphertext =
        Aes256CbcEnc::new(&enc_key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut mac_input = Vec::with_capacity(associated_data.len() + ciphertext.len());
    mac_input.extend_from_slice(associated_data);
    mac_input.extend_from_slice(&ciphertext);
    let tag = hmac(hash, &auth_key, &mac_input);

    enc_key.zeroize();
    auth_key.zeroize();

    let mut out = ciphertext;
    out.extend_from_slice(&tag);
    out
}

pub fn decrypt(
    hash: HashFunction,
    info: &[u8],
    key: &[u8],
    associated_data: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let tag_len = hash.size();
    if ciphertext_with_tag.len() < tag_len {
        return Err(AeadError::CiphertextTooShort);
    }
    let split = ciphertext_with_tag.len() - tag_len;
    let (ciphertext, tag) = ciphertext_with_tag.split_at(split);

    let (mut enc_key, mut auth_key, iv) = derive(hash, key, info);

    let mut mac_input = Vec::with_capacity(associated_data.len() + ciphertext.len());
    mac_input.extend_from_slice(associated_data);
    mac_input.extend_from_slice(ciphertext);
    let expected = hmac(hash, &auth_key, &mac_input);

    if !constant_time_eq(&expected, tag) {
        enc_key.zeroize();
        auth_key.zeroize();
        return Err(AeadError::AuthenticationFailed);
    }

    let plaintext = Aes256CbcDec::new(&enc_key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| AeadError::InvalidPadding)?;

    enc_key.zeroize();
    auth_key.zeroize();
    Ok(plaintext)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
