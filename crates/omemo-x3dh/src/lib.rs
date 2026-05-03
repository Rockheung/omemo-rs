//! X3DH key agreement — port of `python-x3dh` 1.3.x configured for OMEMO 2
//! (`urn:xmpp:omemo:2`, twomemo backend).
//!
//! # Configuration matched against `twomemo.StateImpl`
//!
//! * `IdentityKeyFormat::Ed25519` — bundles carry the IK as a 32-byte Ed25519
//!   public key (Edwards y || sign bit). Internally for DH operations the
//!   peer's IK is converted to Curve25519 via the birational map; the
//!   own clamped 32-byte priv is used directly as the Curve25519 scalar.
//! * Hash: SHA-256.
//! * `info`: `b"OMEMO X3DH"`.
//! * `_encode_public_key(_, pub) = pub` (pass-through).
//!
//! # Determinism
//!
//! python-x3dh's `get_shared_secret_active` calls `secrets.token_bytes` for
//! the ephemeral key and `secrets.choice` for the OPK pick. To enable
//! byte-equal fixture replay this Rust API takes `ephemeral_priv` and
//! `chosen_opk_pub` as explicit parameters. Production code passes freshly
//! generated values; tests pass values from the fixture.

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize as _;

pub const PUB_SIZE: usize = 32;
pub const PRIV_SIZE: usize = 32;
pub const SIG_SIZE: usize = 64;
pub const SHARED_SECRET_SIZE: usize = 32;

/// OMEMO 2 X3DH info string. Matches `twomemo.StateImpl.INFO`.
pub const OMEMO_X3DH_INFO: &[u8] = b"OMEMO X3DH";

/// OMEMO 0.3 X3DH info string. Matches `oldmemo.StateImpl.INFO`.
pub const OMEMO_OLD_X3DH_INFO: &[u8] = b"WhisperText";

/// 0x05 prefix byte used by OMEMO 0.3's `_encode_public_key` —
/// every public key on the wire (and inside AssociatedData) is
/// encoded as `0x05 || curve25519_pub` (33 bytes).
pub const OLDMEMO_PUBKEY_PREFIX: u8 = 0x05;

#[derive(Debug, Error)]
pub enum X3dhError {
    #[error("signed pre key signature did not verify")]
    BadSpkSignature,
    #[error("bundle has no pre keys but require_pre_key=true")]
    NoPreKeyAvailable,
    #[error("chosen pre key is not in the bundle")]
    UnknownChosenPreKey,
    #[error("header references unavailable signed pre key")]
    SpkUnavailable,
    #[error("header references unavailable pre key")]
    OpkUnavailable,
    #[error("require_pre_key set but header has no pre key")]
    HeaderHasNoPreKey,
    #[error("xeddsa: {0}")]
    XEdDsa(#[from] omemo_xeddsa::XEdDsaError),
}

/// Bundle carries the public information published per device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// Ed25519 form (32 bytes — Edwards y || sign bit). For OMEMO 2.
    pub identity_key: [u8; PUB_SIZE],
    /// Curve25519 form (32 bytes).
    pub signed_pre_key: [u8; PUB_SIZE],
    pub signed_pre_key_sig: [u8; SIG_SIZE],
    pub pre_keys: Vec<[u8; PUB_SIZE]>,
}

/// X3DH header — sent by the active party with the first message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Active party's IK (Ed25519 form for OMEMO 2).
    pub identity_key: [u8; PUB_SIZE],
    /// Curve25519 ephemeral pub.
    pub ephemeral_key: [u8; PUB_SIZE],
    /// Curve25519. Reference to which SPK on the passive party was used.
    pub signed_pre_key: [u8; PUB_SIZE],
    /// Curve25519. Reference to which OPK was consumed (if any).
    pub pre_key: Option<[u8; PUB_SIZE]>,
}

/// Identity key pair. Matches python's `IdentityKeyPair{Seed,Priv}` —
/// either a 32-byte seed (preferred, allows Ed25519 SHA-512 signing nonce
/// derivation) or a 32-byte clamped Curve25519/Ed25519 priv.
#[derive(Debug, Clone)]
pub enum IdentityKeyPair {
    Seed([u8; 32]),
    Priv([u8; 32]),
}

impl IdentityKeyPair {
    pub fn priv_bytes(&self) -> [u8; 32] {
        match self {
            Self::Seed(s) => omemo_xeddsa::seed_to_priv(s),
            Self::Priv(p) => *p,
        }
    }

    /// Derive the Ed25519 public key form for use as the OMEMO 2 identity key.
    pub fn ed25519_pub(&self) -> [u8; 32] {
        match self {
            Self::Seed(s) => omemo_xeddsa::seed_to_ed25519_pub(s),
            Self::Priv(p) => omemo_xeddsa::priv_to_ed25519_pub(p),
        }
    }

    pub fn curve25519_pub(&self) -> [u8; 32] {
        omemo_xeddsa::priv_to_curve25519_pub(&self.priv_bytes())
    }
}

/// Signed pre-key pair: the priv, the signature over its Curve25519 pub,
/// and an opaque timestamp (seconds since epoch).
#[derive(Debug, Clone)]
pub struct SignedPreKeyPair {
    pub priv_key: [u8; PRIV_SIZE],
    pub sig: [u8; SIG_SIZE],
    pub timestamp: u64,
}

impl SignedPreKeyPair {
    pub fn pub_key(&self) -> [u8; PUB_SIZE] {
        omemo_xeddsa::priv_to_curve25519_pub(&self.priv_key)
    }

    /// Sign a freshly generated SPK priv with the IK priv. For OMEMO 2's
    /// `IdentityKeyFormat::Ed25519`, the bundle's identity key is
    /// `priv_to_ed25519_pub(ik_priv)` (natural sign bit preserved), so we
    /// must sign with `ik_priv` directly — not with `priv_force_sign(ik, false)`,
    /// which is only correct when the bundle ships the IK in Curve25519
    /// form (sign bit lost in encoding, so the signer must clear it on the
    /// signing key first).
    ///
    /// `nonce` is the 64-byte XEdDSA deterministic nonce — production code
    /// supplies a freshly random one; fixtures supply a recorded nonce.
    pub fn create(
        ik: &IdentityKeyPair,
        spk_priv: [u8; PRIV_SIZE],
        nonce: [u8; 64],
        timestamp: u64,
    ) -> Self {
        let spk_pub = omemo_xeddsa::priv_to_curve25519_pub(&spk_priv);
        let sig = omemo_xeddsa::ed25519_priv_sign(&ik.priv_bytes(), &spk_pub, &nonce);
        Self {
            priv_key: spk_priv,
            sig,
            timestamp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreKeyPair {
    pub priv_key: [u8; PRIV_SIZE],
}

impl PreKeyPair {
    pub fn pub_key(&self) -> [u8; PUB_SIZE] {
        omemo_xeddsa::priv_to_curve25519_pub(&self.priv_key)
    }
}

/// Local X3DH state. Holds enough to generate bundles and to perform passive
/// key agreements when peers initiate.
pub struct X3dhState {
    pub identity_key: IdentityKeyPair,
    pub signed_pre_key: SignedPreKeyPair,
    pub old_signed_pre_key: Option<SignedPreKeyPair>,
    pub pre_keys: Vec<PreKeyPair>,
}

impl X3dhState {
    pub fn bundle(&self) -> Bundle {
        Bundle {
            identity_key: self.identity_key.ed25519_pub(),
            signed_pre_key: self.signed_pre_key.pub_key(),
            signed_pre_key_sig: self.signed_pre_key.sig,
            pre_keys: self.pre_keys.iter().map(|pk| pk.pub_key()).collect(),
        }
    }
}

/// Verify the signed pre key signature using the bundle's IK. Always
/// performed first by `get_shared_secret_active`.
pub fn verify_bundle(bundle: &Bundle) -> Result<(), X3dhError> {
    if !omemo_xeddsa::ed25519_verify(
        &bundle.signed_pre_key_sig,
        &bundle.identity_key,
        &bundle.signed_pre_key,
    ) {
        return Err(X3dhError::BadSpkSignature);
    }
    Ok(())
}

/// OMEMO 0.3 SPK signature verifier. The signature is over the
/// **encoded** SPK pub (`0x05 || curve25519_spk_pub`, 33 bytes), not
/// the raw 32 bytes that OMEMO 2 signs.
pub fn verify_bundle_oldmemo(bundle: &Bundle) -> Result<(), X3dhError> {
    let mut encoded_spk = [0u8; 33];
    encoded_spk[0] = OLDMEMO_PUBKEY_PREFIX;
    encoded_spk[1..].copy_from_slice(&bundle.signed_pre_key);
    if !omemo_xeddsa::ed25519_verify(
        &bundle.signed_pre_key_sig,
        &bundle.identity_key,
        &encoded_spk,
    ) {
        return Err(X3dhError::BadSpkSignature);
    }
    Ok(())
}

fn hkdf_sha256_derive(ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let salt = [0u8; 32];
    let mut out = vec![0u8; length];
    Hkdf::<Sha256>::new(Some(&salt), ikm)
        .expand(info, &mut out)
        .expect("HKDF-SHA-256 expand within limits");
    out
}

/// Output of an X3DH key agreement.
#[derive(Debug, Clone)]
pub struct X3dhAgreementOutput {
    pub shared_secret: [u8; SHARED_SECRET_SIZE],
    pub associated_data: Vec<u8>,
}

/// Active key agreement (Alice). Caller supplies the ephemeral priv key
/// (production: random; tests: from fixture) and optionally chooses which
/// OPK from `bundle.pre_keys` to consume. If `chosen_opk_pub` is `None`
/// and `require_pre_key` is true, an error is returned.
pub fn get_shared_secret_active(
    own_state: &X3dhState,
    bundle: &Bundle,
    associated_data_appendix: &[u8],
    ephemeral_priv: [u8; 32],
    chosen_opk_pub: Option<[u8; PUB_SIZE]>,
    require_pre_key: bool,
) -> Result<(X3dhAgreementOutput, Header), X3dhError> {
    if bundle.pre_keys.is_empty() && require_pre_key {
        return Err(X3dhError::NoPreKeyAvailable);
    }

    verify_bundle(bundle)?;

    let opk_pub = match chosen_opk_pub {
        Some(p) => {
            if !bundle.pre_keys.contains(&p) {
                return Err(X3dhError::UnknownChosenPreKey);
            }
            Some(p)
        }
        None => {
            if require_pre_key {
                return Err(X3dhError::NoPreKeyAvailable);
            }
            None
        }
    };

    let own_ik_priv = own_state.identity_key.priv_bytes();
    let own_ik_pub_ed = own_state.identity_key.ed25519_pub();
    let other_ik_pub_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(&bundle.identity_key)?;

    let dh1 = omemo_xeddsa::x25519(&own_ik_priv, &bundle.signed_pre_key)?;
    let dh2 = omemo_xeddsa::x25519(&ephemeral_priv, &other_ik_pub_curve)?;
    let dh3 = omemo_xeddsa::x25519(&ephemeral_priv, &bundle.signed_pre_key)?;
    let dh4 = match opk_pub {
        Some(p) => Some(omemo_xeddsa::x25519(&ephemeral_priv, &p)?),
        None => None,
    };

    let mut ikm = Vec::with_capacity(32 + 32 * 4);
    ikm.extend_from_slice(&[0xFFu8; 32]); // F
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(d) = dh4.as_ref() {
        ikm.extend_from_slice(d);
    }

    let ss_vec = hkdf_sha256_derive(&ikm, OMEMO_X3DH_INFO, SHARED_SECRET_SIZE);
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss_vec);

    let mut ad = Vec::with_capacity(64 + associated_data_appendix.len());
    ad.extend_from_slice(&own_ik_pub_ed);
    ad.extend_from_slice(&bundle.identity_key);
    ad.extend_from_slice(associated_data_appendix);

    let ek_pub = omemo_xeddsa::priv_to_curve25519_pub(&ephemeral_priv);
    let header = Header {
        identity_key: own_ik_pub_ed,
        ephemeral_key: ek_pub,
        signed_pre_key: bundle.signed_pre_key,
        pre_key: opk_pub,
    };

    let mut ikm_clear = ikm;
    ikm_clear.zeroize();

    Ok((
        X3dhAgreementOutput {
            shared_secret,
            associated_data: ad,
        },
        header,
    ))
}

/// Passive key agreement (Bob). Resolves the SPK and OPK referenced in the
/// header against `own_state`, computes the same shared secret. Returns the
/// resolved `SignedPreKeyPair` for the caller to attach to subsequent
/// double-ratchet state. Does not delete the consumed OPK — that is left to
/// the caller (matches python's `BaseState` separation).
pub fn get_shared_secret_passive(
    own_state: &X3dhState,
    header: &Header,
    associated_data_appendix: &[u8],
    require_pre_key: bool,
) -> Result<(X3dhAgreementOutput, SignedPreKeyPair), X3dhError> {
    // Find SPK.
    let spk = if header.signed_pre_key == own_state.signed_pre_key.pub_key() {
        own_state.signed_pre_key.clone()
    } else if let Some(old) = own_state
        .old_signed_pre_key
        .as_ref()
        .filter(|s| s.pub_key() == header.signed_pre_key)
    {
        old.clone()
    } else {
        return Err(X3dhError::SpkUnavailable);
    };

    // Find OPK if header references one.
    let opk_priv = match header.pre_key {
        Some(opk_pub) => own_state
            .pre_keys
            .iter()
            .find(|pk| pk.pub_key() == opk_pub)
            .map(|pk| pk.priv_key)
            .ok_or(X3dhError::OpkUnavailable)?,
        None => {
            if require_pre_key {
                return Err(X3dhError::HeaderHasNoPreKey);
            }
            [0u8; 32] // sentinel; not used since dh4 is then skipped
        }
    };

    let own_ik_priv = own_state.identity_key.priv_bytes();
    let own_ik_pub_ed = own_state.identity_key.ed25519_pub();
    let other_ik_pub_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(&header.identity_key)?;

    let dh1 = omemo_xeddsa::x25519(&spk.priv_key, &other_ik_pub_curve)?;
    let dh2 = omemo_xeddsa::x25519(&own_ik_priv, &header.ephemeral_key)?;
    let dh3 = omemo_xeddsa::x25519(&spk.priv_key, &header.ephemeral_key)?;
    let dh4 = match header.pre_key {
        Some(_) => Some(omemo_xeddsa::x25519(&opk_priv, &header.ephemeral_key)?),
        None => None,
    };

    let mut ikm = Vec::with_capacity(32 + 32 * 4);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(d) = dh4.as_ref() {
        ikm.extend_from_slice(d);
    }

    let ss_vec = hkdf_sha256_derive(&ikm, OMEMO_X3DH_INFO, SHARED_SECRET_SIZE);
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss_vec);

    let mut ad = Vec::with_capacity(64 + associated_data_appendix.len());
    ad.extend_from_slice(&header.identity_key);
    ad.extend_from_slice(&own_ik_pub_ed);
    ad.extend_from_slice(associated_data_appendix);

    let mut ikm_clear = ikm;
    ikm_clear.zeroize();

    Ok((
        X3dhAgreementOutput {
            shared_secret,
            associated_data: ad,
        },
        spk,
    ))
}

/// Encode a 32-byte Curve25519 (or Ed25519-then-converted) pubkey
/// in OMEMO 0.3's `_encode_public_key` format: `0x05 || pub`.
fn enc_old_pub(pub_key: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = OLDMEMO_PUBKEY_PREFIX;
    out[1..].copy_from_slice(pub_key);
    out
}

/// Build the AssociatedData for OMEMO 0.3: the two identity keys
/// (each as 33-byte 0x05-prefixed Curve25519) concatenated, then
/// the appendix. Matches python-oldmemo's StateImpl + the AD shape
/// our `omemo_oldmemo::build_associated_data` parses (66 bytes
/// before the trailing OMEMOMessage header).
fn ad_old(their_ik_ed: &[u8; 32], own_ik_ed: &[u8; 32], appendix: &[u8]) -> Result<Vec<u8>, X3dhError> {
    let their_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(their_ik_ed)?;
    let own_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(own_ik_ed)?;
    let mut ad = Vec::with_capacity(33 + 33 + appendix.len());
    // Note ordering: passive AD is (their || own); active AD is
    // (own || their). Caller hands us their_ik_ed first.
    ad.extend_from_slice(&enc_old_pub(&their_curve));
    ad.extend_from_slice(&enc_old_pub(&own_curve));
    ad.extend_from_slice(appendix);
    Ok(ad)
}

/// Active key agreement (Alice), OMEMO 0.3 flavour. Same DH steps
/// as [`get_shared_secret_active`], with two deltas:
///
/// * HKDF info is `b"WhisperText"` instead of `b"OMEMO X3DH"`.
/// * AssociatedData is `enc(own_ik) || enc(their_ik) || appendix`
///   (each enc(.) is `0x05 || curve25519_pub`, 33 bytes; total
///   pre-appendix = 66 bytes).
pub fn get_shared_secret_active_oldmemo(
    own_state: &X3dhState,
    bundle: &Bundle,
    associated_data_appendix: &[u8],
    ephemeral_priv: [u8; 32],
    chosen_opk_pub: Option<[u8; PUB_SIZE]>,
    require_pre_key: bool,
) -> Result<(X3dhAgreementOutput, Header), X3dhError> {
    if bundle.pre_keys.is_empty() && require_pre_key {
        return Err(X3dhError::NoPreKeyAvailable);
    }
    verify_bundle_oldmemo(bundle)?;
    let opk_pub = match chosen_opk_pub {
        Some(p) => {
            if !bundle.pre_keys.contains(&p) {
                return Err(X3dhError::UnknownChosenPreKey);
            }
            Some(p)
        }
        None => {
            if require_pre_key {
                return Err(X3dhError::NoPreKeyAvailable);
            }
            None
        }
    };

    let own_ik_priv = own_state.identity_key.priv_bytes();
    let own_ik_pub_ed = own_state.identity_key.ed25519_pub();
    let other_ik_pub_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(&bundle.identity_key)?;

    let dh1 = omemo_xeddsa::x25519(&own_ik_priv, &bundle.signed_pre_key)?;
    let dh2 = omemo_xeddsa::x25519(&ephemeral_priv, &other_ik_pub_curve)?;
    let dh3 = omemo_xeddsa::x25519(&ephemeral_priv, &bundle.signed_pre_key)?;
    let dh4 = match opk_pub {
        Some(p) => Some(omemo_xeddsa::x25519(&ephemeral_priv, &p)?),
        None => None,
    };

    let mut ikm = Vec::with_capacity(32 + 32 * 4);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(d) = dh4.as_ref() {
        ikm.extend_from_slice(d);
    }

    let ss_vec = hkdf_sha256_derive(&ikm, OMEMO_OLD_X3DH_INFO, SHARED_SECRET_SIZE);
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss_vec);

    // Active AD: enc(own_ik) || enc(their_ik) || appendix
    // (mirrors get_shared_secret_active's ordering).
    let own_ik_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(&own_ik_pub_ed)?;
    let mut ad = Vec::with_capacity(33 + 33 + associated_data_appendix.len());
    ad.extend_from_slice(&enc_old_pub(&own_ik_curve));
    ad.extend_from_slice(&enc_old_pub(&other_ik_pub_curve));
    ad.extend_from_slice(associated_data_appendix);

    let ek_pub = omemo_xeddsa::priv_to_curve25519_pub(&ephemeral_priv);
    let header = Header {
        identity_key: own_ik_pub_ed,
        ephemeral_key: ek_pub,
        signed_pre_key: bundle.signed_pre_key,
        pre_key: opk_pub,
    };

    let mut ikm_clear = ikm;
    ikm_clear.zeroize();

    Ok((
        X3dhAgreementOutput {
            shared_secret,
            associated_data: ad,
        },
        header,
    ))
}

/// Passive key agreement (Bob), OMEMO 0.3 flavour. Mirror of
/// [`get_shared_secret_passive`] with the OMEMO-0.3 info/AD.
pub fn get_shared_secret_passive_oldmemo(
    own_state: &X3dhState,
    header: &Header,
    associated_data_appendix: &[u8],
    require_pre_key: bool,
) -> Result<(X3dhAgreementOutput, SignedPreKeyPair), X3dhError> {
    let spk = if header.signed_pre_key == own_state.signed_pre_key.pub_key() {
        own_state.signed_pre_key.clone()
    } else if let Some(old) = own_state
        .old_signed_pre_key
        .as_ref()
        .filter(|s| s.pub_key() == header.signed_pre_key)
    {
        old.clone()
    } else {
        return Err(X3dhError::SpkUnavailable);
    };

    let opk_priv = match header.pre_key {
        Some(opk_pub) => own_state
            .pre_keys
            .iter()
            .find(|pk| pk.pub_key() == opk_pub)
            .map(|pk| pk.priv_key)
            .ok_or(X3dhError::OpkUnavailable)?,
        None => {
            if require_pre_key {
                return Err(X3dhError::HeaderHasNoPreKey);
            }
            [0u8; 32]
        }
    };

    let own_ik_priv = own_state.identity_key.priv_bytes();
    let own_ik_pub_ed = own_state.identity_key.ed25519_pub();
    let other_ik_pub_curve = omemo_xeddsa::ed25519_pub_to_curve25519_pub(&header.identity_key)?;

    let dh1 = omemo_xeddsa::x25519(&spk.priv_key, &other_ik_pub_curve)?;
    let dh2 = omemo_xeddsa::x25519(&own_ik_priv, &header.ephemeral_key)?;
    let dh3 = omemo_xeddsa::x25519(&spk.priv_key, &header.ephemeral_key)?;
    let dh4 = match header.pre_key {
        Some(_) => Some(omemo_xeddsa::x25519(&opk_priv, &header.ephemeral_key)?),
        None => None,
    };

    let mut ikm = Vec::with_capacity(32 + 32 * 4);
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    if let Some(d) = dh4.as_ref() {
        ikm.extend_from_slice(d);
    }

    let ss_vec = hkdf_sha256_derive(&ikm, OMEMO_OLD_X3DH_INFO, SHARED_SECRET_SIZE);
    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&ss_vec);

    // Passive AD: their || own.
    let ad = ad_old(&header.identity_key, &own_ik_pub_ed, associated_data_appendix)?;

    let mut ikm_clear = ikm;
    ikm_clear.zeroize();

    Ok((
        X3dhAgreementOutput {
            shared_secret,
            associated_data: ad,
        },
        spk,
    ))
}
