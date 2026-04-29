//! HKDF-based KDF — port of `python-doubleratchet/recommended/kdf_hkdf.py`.
//!
//! Mapping (matches python `recommended.kdf_hkdf.KDF.derive`):
//!
//! * KDF `key` → HKDF `salt`
//! * KDF `data` → HKDF `IKM`
//! * impl-bound constant `info`
//!
//! The hash function and info string are bound at the type level via the
//! [`HkdfParams`] trait, mirroring how python uses abstract `_get_hash_function`
//! / `_get_info` classmethods.

use core::marker::PhantomData;

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

use crate::aead::HashFunction;
use crate::kdf::Kdf;

pub trait HkdfParams {
    const HASH: HashFunction;
    const INFO: &'static [u8];
}

pub struct HkdfKdf<P: HkdfParams>(PhantomData<P>);

impl<P: HkdfParams> Kdf for HkdfKdf<P> {
    fn derive(key: &[u8], data: &[u8], length: usize) -> Vec<u8> {
        let mut out = vec![0u8; length];
        match P::HASH {
            HashFunction::Sha256 => {
                Hkdf::<Sha256>::new(Some(key), data)
                    .expand(P::INFO, &mut out)
                    .expect("HKDF-SHA256 expand respects max length 255*32");
            }
            HashFunction::Sha512 => {
                Hkdf::<Sha512>::new(Some(key), data)
                    .expand(P::INFO, &mut out)
                    .expect("HKDF-SHA512 expand respects max length 255*64");
            }
        }
        out
    }
}

/// OMEMO 2 root chain: HKDF-SHA-256 with `info = "OMEMO Root Chain"`.
pub struct OmemoRootChain;
impl HkdfParams for OmemoRootChain {
    const HASH: HashFunction = HashFunction::Sha256;
    const INFO: &'static [u8] = b"OMEMO Root Chain";
}
pub type OmemoRootKdf = HkdfKdf<OmemoRootChain>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omemo_root_kdf_smoke() {
        // Sanity check: 64-byte derive on fixed inputs is stable & non-trivial.
        let salt = [0x11u8; 32];
        let ikm = [0x22u8; 32];
        let out = OmemoRootKdf::derive(&salt, &ikm, 64);
        assert_eq!(out.len(), 64);
        assert_ne!(out, vec![0u8; 64]);
    }
}
