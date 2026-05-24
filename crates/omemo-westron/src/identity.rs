//! Identity unification — Ed25519 canonical, Curve25519 derived for OMEMO 0.3.
//!
//! SPEC §3 (westron-spec/SPEC.md): a Westron endpoint has exactly ONE master
//! identity, an Ed25519 keypair `IK_ed`. The Curve25519 form used by OMEMO 0.3
//! is derived deterministically via Edwards→Montgomery point conversion.
//! The reverse (Curve→Ed) is non-unique (sign bit lost), so a 0.3-only client
//! cannot upgrade to Westron without minting a fresh identity.
//!
//! `derive_curve25519` is byte-for-byte compatible with the Python reference
//! implementation in `westron-spec` AND with libsodium's
//! `crypto_sign_ed25519_pk_to_curve25519` (RFC 7748 §4.1).
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use omemo_xeddsa::ed25519_pub_to_curve25519_pub;
use rand_core::OsRng;
use thiserror::Error;

/// Edwards (Ed25519 pub) → Montgomery (X25519 pub) conversion, delegating to
/// the workspace's vetted XEdDSA implementation (`omemo-xeddsa`).
///
/// Byte-for-byte compatible with libsodium's
/// `crypto_sign_ed25519_pk_to_curve25519` and the Python reference impl in
/// `westron-spec/westron/identity.py`.
pub fn derive_curve25519(ik_ed_pub: &[u8; 32]) -> Result<[u8; 32], IdentityError> {
    ed25519_pub_to_curve25519_pub(ik_ed_pub).map_err(|_| IdentityError::BundleInvalid)
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("dual-bundle IK conflict: derive(IK_ed) != IK_curve")]
    IkConflict,
    #[error("SPK signature does not verify under IK_ed")]
    BundleInvalid,
    #[error("cannot lift Curve25519 IK to Ed25519: sign bit not recoverable")]
    LiftUnsupported,
}

/// Westron canonical identity. Holds an Ed25519 keypair.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn ik_ed_pub(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn ik_curve_pub(&self) -> Result<[u8; 32], IdentityError> {
        derive_curve25519(&self.ik_ed_pub())
    }

    /// SPEC §3.4 — sign an SPK public key with our IK_ed.
    pub fn sign_spk(&self, spk_pub: &[u8]) -> [u8; 64] {
        self.signing.sign(spk_pub).to_bytes()
    }

    /// Sign arbitrary bytes (used by signed-caps and other identity-bound proofs).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Verify an SPK signature under a given IK_ed public key.
    /// SPEC C-3.4: this MUST be called BEFORE any X3DH operation that uses spk_pub.
    pub fn verify_spk_signature(
        ik_ed_pub: &[u8; 32],
        spk_pub: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let pk = VerifyingKey::from_bytes(ik_ed_pub).map_err(|_| IdentityError::BundleInvalid)?;
        let sig = Signature::from_bytes(signature);
        pk.verify(spk_pub, &sig).map_err(|_| IdentityError::BundleInvalid)
    }

    /// Generic Ed25519 verify (for signed caps, etc.).
    pub fn verify(
        ik_ed_pub: &[u8; 32],
        msg: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let pk = VerifyingKey::from_bytes(ik_ed_pub).map_err(|_| IdentityError::BundleInvalid)?;
        let sig = Signature::from_bytes(signature);
        pk.verify(msg, &sig).map_err(|_| IdentityError::BundleInvalid)
    }

    /// SPEC C-3.3 — a peer publishing both 0.3 and 2 bundles MUST be consistent:
    /// derive(IK_ed_in_2_bundle) == IK_curve_in_03_bundle.
    pub fn verify_dual_bundle(
        ik_ed_pub: &[u8; 32],
        ik_curve_pub: &[u8; 32],
    ) -> Result<(), IdentityError> {
        let derived = derive_curve25519(ik_ed_pub)?;
        if derived != *ik_curve_pub {
            return Err(IdentityError::IkConflict);
        }
        Ok(())
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // SigningKey already zeroizes on drop via zeroize feature
    }
}
