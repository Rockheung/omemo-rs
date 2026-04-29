//! XEdDSA: Ed25519-compatible signing using Curve25519 keys.
//!
//! Port of `python-xeddsa` (CFFI binding to libxeddsa). Behaviour is validated
//! byte-for-byte against fixtures generated from the reference impl. See
//! `crates/omemo-test-harness/tests/xeddsa.rs`.
//!
//! Reference: <https://signal.org/docs/specifications/xeddsa/>

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
use thiserror::Error;
use zeroize::Zeroize as _;

pub const PRIV_SIZE: usize = 32;
pub const SEED_SIZE: usize = 32;
pub const CURVE_25519_PUB_SIZE: usize = 32;
pub const ED_25519_PUB_SIZE: usize = 32;
pub const ED_25519_SIGNATURE_SIZE: usize = 64;
pub const NONCE_SIZE: usize = 64;
pub const SHARED_SECRET_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum XEdDsaError {
    #[error("public key rejected: suboptimal security properties (low-order or zero)")]
    BadPublicKey,
    #[error("X25519 produced all-zero shared secret")]
    AllZeroSharedSecret,
    #[error("invalid input length")]
    InvalidLength,
    #[error("signature verification failed")]
    VerifyFailed,
}

/// Apply X25519/Ed25519 clamping to a 32-byte scalar.
fn clamp(b: &mut [u8; 32]) {
    b[0] &= 0xF8;
    b[31] &= 0x7F;
    b[31] |= 0x40;
}

/// `seed_to_priv`: SHA-512(seed)[:32] then clamp. (Ed25519 expansion of seed.)
pub fn seed_to_priv(seed: &[u8; SEED_SIZE]) -> [u8; PRIV_SIZE] {
    let h = Sha512::digest(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    clamp(&mut out);
    out
}

/// `seed_to_ed25519_pub`: standard Ed25519 public from seed.
pub fn seed_to_ed25519_pub(seed: &[u8; SEED_SIZE]) -> [u8; ED_25519_PUB_SIZE] {
    let sk = SigningKey::from_bytes(seed);
    sk.verifying_key().to_bytes()
}

/// `priv_to_ed25519_pub`: scalar mult basepoint, encode as Edwards. Input is
/// clamped first to mirror libxeddsa behaviour (which clamps internally).
pub fn priv_to_ed25519_pub(priv_in: &[u8; PRIV_SIZE]) -> [u8; ED_25519_PUB_SIZE] {
    let mut bytes = *priv_in;
    clamp(&mut bytes);
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let point = EdwardsPoint::mul_base(&scalar);
    point.compress().to_bytes()
}

/// `priv_to_curve25519_pub`: scalar mult basepoint, encode as Montgomery.
pub fn priv_to_curve25519_pub(priv_in: &[u8; PRIV_SIZE]) -> [u8; CURVE_25519_PUB_SIZE] {
    let mut bytes = *priv_in;
    clamp(&mut bytes);
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let edwards = EdwardsPoint::mul_base(&scalar);
    edwards.to_montgomery().to_bytes()
}

/// `priv_force_sign`: clamp `priv`, derive Ed25519 pub, and if its sign bit
/// (bit 7 of byte 31 of compressed form) does not match `set_sign_bit`,
/// negate the scalar so it does.
pub fn priv_force_sign(priv_in: &[u8; PRIV_SIZE], set_sign_bit: bool) -> [u8; PRIV_SIZE] {
    let mut bytes = *priv_in;
    clamp(&mut bytes);
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let edwards = EdwardsPoint::mul_base(&scalar);
    let pub_bytes = edwards.compress().to_bytes();
    let current_sign = (pub_bytes[31] >> 7) & 1 == 1;
    if current_sign == set_sign_bit {
        bytes
    } else {
        (-scalar).to_bytes()
    }
}

/// `curve25519_pub_to_ed25519_pub`: Montgomery → Edwards via birational map.
/// `set_sign_bit` controls the sign of the resulting Edwards y-coordinate.
pub fn curve25519_pub_to_ed25519_pub(
    curve_pub: &[u8; CURVE_25519_PUB_SIZE],
    set_sign_bit: bool,
) -> [u8; ED_25519_PUB_SIZE] {
    let m = MontgomeryPoint(*curve_pub);
    // to_edwards takes a sign byte (0 or 1)
    let edwards = m
        .to_edwards(set_sign_bit as u8)
        .expect("non-canonical Mont u");
    let mut compressed = edwards.compress().to_bytes();
    // Force sign bit per request (defensive — to_edwards already does this)
    if set_sign_bit {
        compressed[31] |= 0x80;
    } else {
        compressed[31] &= 0x7F;
    }
    compressed
}

/// `ed25519_pub_to_curve25519_pub`: Edwards → Montgomery.
pub fn ed25519_pub_to_curve25519_pub(
    ed_pub: &[u8; ED_25519_PUB_SIZE],
) -> Result<[u8; CURVE_25519_PUB_SIZE], XEdDsaError> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards = compressed.decompress().ok_or(XEdDsaError::BadPublicKey)?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// X25519 ECDH. Errors if the result is all zeros.
pub fn x25519(
    priv_in: &[u8; PRIV_SIZE],
    curve_pub: &[u8; CURVE_25519_PUB_SIZE],
) -> Result<[u8; SHARED_SECRET_SIZE], XEdDsaError> {
    let mut bytes = *priv_in;
    clamp(&mut bytes);
    let scalar = Scalar::from_bytes_mod_order(bytes);
    let result = MontgomeryPoint(*curve_pub) * scalar;
    let out = result.to_bytes();
    if out.iter().all(|&b| b == 0) {
        return Err(XEdDsaError::AllZeroSharedSecret);
    }
    bytes.zeroize();
    Ok(out)
}

/// Standard Ed25519 sign from seed (deterministic per RFC 8032).
pub fn ed25519_seed_sign(seed: &[u8; SEED_SIZE], msg: &[u8]) -> [u8; ED_25519_SIGNATURE_SIZE] {
    use ed25519_dalek::Signer;
    let sk = SigningKey::from_bytes(seed);
    sk.sign(msg).to_bytes()
}

/// Ed25519 verify.
pub fn ed25519_verify(
    sig: &[u8; ED_25519_SIGNATURE_SIZE],
    ed_pub: &[u8; ED_25519_PUB_SIZE],
    msg: &[u8],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(ed_pub) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify(msg, &signature).is_ok()
}

/// XEdDSA sign with deterministic 64-byte nonce — libxeddsa variant.
///
/// libxeddsa simplifies the Signal XEdDSA spec: it skips `calculate_key_pair`
/// (no sign-bit normalisation, no scalar negation) and uses `priv` as a raw
/// 32-byte scalar directly. Caller is responsible for passing an
/// already-prepared private (e.g. clamped + sign-forced via `priv_force_sign`).
///
/// Algorithm (matching libxeddsa/ref10):
/// ```text
/// A = priv·B   (Edwards point, compressed with its natural sign bit)
/// r = SHA-512(0xFE || 0xFF·31 || priv || M || Z)  (mod q)
/// R = rB
/// h = SHA-512(R || A || M) (mod q)
/// s = h·priv + r (mod q)
/// signature = R || s
/// ```
pub fn ed25519_priv_sign(
    priv_in: &[u8; PRIV_SIZE],
    msg: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> [u8; ED_25519_SIGNATURE_SIZE] {
    // No clamp: libxeddsa uses priv as a raw scalar.
    let k = Scalar::from_bytes_mod_order(*priv_in);
    let big_a = EdwardsPoint::mul_base(&k).compress().to_bytes();

    let mut prefix = [0xFFu8; 32];
    prefix[0] = 0xFE;

    let mut h = Sha512::new();
    h.update(prefix);
    h.update(priv_in);
    h.update(msg);
    h.update(nonce);
    let r_hash: [u8; 64] = h.finalize().into();
    let r = Scalar::from_bytes_mod_order_wide(&r_hash);

    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();

    let mut h2 = Sha512::new();
    h2.update(big_r);
    h2.update(big_a);
    h2.update(msg);
    let h_hash: [u8; 64] = h2.finalize().into();
    let h_scalar = Scalar::from_bytes_mod_order_wide(&h_hash);

    let s = h_scalar * k + r;

    let mut sig = [0u8; ED_25519_SIGNATURE_SIZE];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_idempotent() {
        let mut a = [0xFFu8; 32];
        clamp(&mut a);
        let mut b = a;
        clamp(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn ed25519_self_round_trip() {
        let seed = [7u8; 32];
        let pk = seed_to_ed25519_pub(&seed);
        let sig = ed25519_seed_sign(&seed, b"hello");
        assert!(ed25519_verify(&sig, &pk, b"hello"));
        assert!(!ed25519_verify(&sig, &pk, b"world"));
    }
}
