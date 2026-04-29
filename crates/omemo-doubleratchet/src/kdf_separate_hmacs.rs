//! Separate-HMACs KDF — port of `python-doubleratchet/recommended/kdf_separate_hmacs.py`.
//!
//! For each byte `b` in `data`, compute `HMAC-<hash>(key, b)` and concatenate.
//! `length` must equal `data.len() * hash.size()`.
//!
//! OMEMO 2 / twomemo uses this with `data = b"\x02\x01"` and SHA-256 as the
//! per-step message-chain KDF, yielding 64 bytes split into
//! (new_chain_key, message_key).

use core::marker::PhantomData;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::aead::HashFunction;
use crate::kdf::Kdf;

pub trait SeparateHmacsParams {
    const HASH: HashFunction;
}

pub struct SeparateHmacsKdf<P: SeparateHmacsParams>(PhantomData<P>);

impl<P: SeparateHmacsParams> Kdf for SeparateHmacsKdf<P> {
    fn derive(key: &[u8], data: &[u8], length: usize) -> Vec<u8> {
        assert_eq!(
            length,
            data.len() * P::HASH.size(),
            "separate-HMACs KDF: length must equal data.len() * hash_size",
        );
        let mut out = Vec::with_capacity(length);
        for b in data {
            match P::HASH {
                HashFunction::Sha256 => {
                    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key)
                        .expect("HMAC accepts any key length");
                    m.update(&[*b]);
                    out.extend_from_slice(&m.finalize().into_bytes());
                }
                HashFunction::Sha512 => {
                    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key)
                        .expect("HMAC accepts any key length");
                    m.update(&[*b]);
                    out.extend_from_slice(&m.finalize().into_bytes());
                }
            }
        }
        out
    }
}

/// OMEMO 2 message chain: SHA-256.
pub struct OmemoMessageChain;
impl SeparateHmacsParams for OmemoMessageChain {
    const HASH: HashFunction = HashFunction::Sha256;
}
pub type OmemoMessageChainKdf = SeparateHmacsKdf<OmemoMessageChain>;
