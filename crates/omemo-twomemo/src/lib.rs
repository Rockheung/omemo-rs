//! OMEMO 2 (twomemo) wire-format backend.
//!
//! Glues `omemo-doubleratchet` + `omemo-x3dh` + the protobuf shapes from
//! `test-vectors/twomemo/twomemo.proto` into the on-the-wire bytes that
//! `<encrypted>` stanzas carry.
//!
//! # AEAD override
//!
//! python-twomemo's `AEADImpl` derives from `aead_aes_hmac.AEAD` but
//! overrides `encrypt`/`decrypt` entirely (the docstring literally says it
//! "doesn't use any of its code"). The overrides:
//!
//! * Wrap the AES-CBC ciphertext in an `OMEMOMessage` protobuf (with the
//!   header fields from the DR), serialize it, then HMAC over
//!   `(ad_minus_header) || omemo_message_bytes` and **truncate to 16 bytes**.
//! * Output: serialized `OMEMOAuthenticatedMessage{mac, message}`.
//!
//! See `docs/decisions.md` ADR-006 and the `project_aead_layering` memory
//! for the rationale; do not implement by chopping the base AEAD's output.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message as _;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize as _;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use omemo_doubleratchet::dh_ratchet::Header as DrHeader;

/// Generated protobuf bindings.
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/twomemo.rs"));
}

pub use proto::{OmemoAuthenticatedMessage, OmemoKeyExchange, OmemoMessage};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub const AEAD_INFO: &[u8] = b"OMEMO Message Key Material";
pub const MAC_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum TwomemoError {
    #[error("authentication tag mismatch")]
    AuthFailed,
    #[error("invalid PKCS#7 padding")]
    InvalidPadding,
    #[error("protobuf decode: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("OMEMOMessage header does not match the DR header")]
    HeaderMismatch,
    #[error("OMEMOMessage missing ciphertext field")]
    MissingCiphertext,
}

/// Build the AD that twomemo's DoubleRatchet uses internally. Matches
/// `python-twomemo.DoubleRatchetImpl._build_associated_data`:
///
/// `ad_omemo_x3dh || OMEMOMessage(n, pn, dh_pub).SerializeToString()`
///
/// The AEAD then strips the trailing OMEMOMessage off before HMAC-ing.
pub fn build_associated_data(ad_x3dh: &[u8], h: &DrHeader) -> Vec<u8> {
    let header_msg = OmemoMessage {
        n: h.sending_chain_length as u32,
        pn: h.previous_sending_chain_length as u32,
        dh_pub: h.ratchet_pub.to_vec(),
        ciphertext: None,
    };
    let mut out = Vec::with_capacity(ad_x3dh.len() + header_msg.encoded_len());
    out.extend_from_slice(ad_x3dh);
    header_msg.encode(&mut out).expect("encode in-memory");
    out
}

fn derive(key: &[u8]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let salt = [0u8; 32];
    let mut out = [0u8; 80];
    Hkdf::<Sha256>::new(Some(&salt), key)
        .expand(AEAD_INFO, &mut out)
        .expect("HKDF-SHA-256 expand within limits");
    let mut enc = [0u8; 32];
    let mut auth = [0u8; 32];
    let mut iv = [0u8; 16];
    enc.copy_from_slice(&out[..32]);
    auth.copy_from_slice(&out[32..64]);
    iv.copy_from_slice(&out[64..80]);
    out.zeroize();
    (enc, auth, iv)
}

fn truncated_hmac(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    let full = m.finalize().into_bytes();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&full[..MAC_LEN]);
    tag
}

/// `AEADImpl::encrypt` (twomemo). Returns the serialized
/// `OMEMOAuthenticatedMessage`.
///
/// `associated_data` is what `omemo-doubleratchet::DoubleRatchet` passes
/// in: it equals `ad_x3dh || OMEMOMessage(header).SerializeToString()`. We
/// re-split it back into `(ad_x3dh, header_msg)` here.
pub fn aead_encrypt(associated_data: &[u8], msg_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // Split AD: first IDENTITY_KEY_ENCODING_LENGTH * 2 bytes are the X3DH
    // associated data; the rest is the OMEMOMessage header (which we re-
    // parse so we can rebuild the message with the ciphertext).
    let (ad_x3dh, header_bytes) = associated_data.split_at(IDENTITY_KEY_ENCODING_LENGTH * 2);
    let header =
        OmemoMessage::decode(header_bytes).expect("DR layer always feeds well-formed OMEMOMessage");

    let (mut enc_key, mut auth_key, iv) = derive(msg_key);

    let ciphertext =
        Aes256CbcEnc::new(&enc_key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let omemo_msg = OmemoMessage {
        n: header.n,
        pn: header.pn,
        dh_pub: header.dh_pub,
        ciphertext: Some(ciphertext),
    };
    let mut omemo_msg_bytes = Vec::with_capacity(omemo_msg.encoded_len());
    omemo_msg
        .encode(&mut omemo_msg_bytes)
        .expect("encode in-memory");

    let mut mac_input = Vec::with_capacity(ad_x3dh.len() + omemo_msg_bytes.len());
    mac_input.extend_from_slice(ad_x3dh);
    mac_input.extend_from_slice(&omemo_msg_bytes);
    let mac = truncated_hmac(&auth_key, &mac_input);

    enc_key.zeroize();
    auth_key.zeroize();

    let auth_msg = OmemoAuthenticatedMessage {
        mac: mac.to_vec(),
        message: omemo_msg_bytes,
    };
    let mut out = Vec::with_capacity(auth_msg.encoded_len());
    auth_msg.encode(&mut out).expect("encode in-memory");
    out
}

/// `AEADImpl::decrypt` (twomemo). Input is the serialized
/// `OMEMOAuthenticatedMessage`. Returns the plaintext.
pub fn aead_decrypt(
    associated_data: &[u8],
    msg_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TwomemoError> {
    let (ad_x3dh, header_bytes) = associated_data.split_at(IDENTITY_KEY_ENCODING_LENGTH * 2);
    let dr_header = OmemoMessage::decode(header_bytes)?;

    let auth_msg = OmemoAuthenticatedMessage::decode(ciphertext)?;

    let (mut enc_key, mut auth_key, iv) = derive(msg_key);

    let mut mac_input = Vec::with_capacity(ad_x3dh.len() + auth_msg.message.len());
    mac_input.extend_from_slice(ad_x3dh);
    mac_input.extend_from_slice(&auth_msg.message);
    let computed = truncated_hmac(&auth_key, &mac_input);

    if !constant_time_eq(&computed, &auth_msg.mac) {
        enc_key.zeroize();
        auth_key.zeroize();
        return Err(TwomemoError::AuthFailed);
    }

    let inner = OmemoMessage::decode(auth_msg.message.as_slice())?;
    if inner.n != dr_header.n || inner.pn != dr_header.pn || inner.dh_pub != dr_header.dh_pub {
        enc_key.zeroize();
        auth_key.zeroize();
        return Err(TwomemoError::HeaderMismatch);
    }
    let ct = inner
        .ciphertext
        .as_deref()
        .ok_or(TwomemoError::MissingCiphertext)?;

    let pt = Aes256CbcDec::new(&enc_key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| TwomemoError::InvalidPadding)?;

    enc_key.zeroize();
    auth_key.zeroize();
    Ok(pt)
}

const IDENTITY_KEY_ENCODING_LENGTH: usize = 32;

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

// ---------------------------------------------------------------------------
// Session: Double-Ratchet + twomemo wire format glue.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;

use omemo_doubleratchet::aead::HashFunction;
use omemo_doubleratchet::dh_ratchet::{
    DhPrivProvider, DiffieHellmanRatchet, FixedDhPrivProvider, Header,
};
use omemo_doubleratchet::kdf_hkdf::{HkdfKdf, HkdfParams};
use omemo_doubleratchet::kdf_separate_hmacs::{SeparateHmacsKdf, SeparateHmacsParams};

/// OMEMO 2 root chain KDF type binding (HKDF-SHA-256, info "OMEMO Root Chain").
pub struct OmemoRoot;
impl HkdfParams for OmemoRoot {
    const HASH: HashFunction = HashFunction::Sha256;
    const INFO: &'static [u8] = b"OMEMO Root Chain";
}
pub type RootKdf = HkdfKdf<OmemoRoot>;

/// OMEMO 2 message chain KDF type binding (separate-HMACs SHA-256).
pub struct OmemoMsg;
impl SeparateHmacsParams for OmemoMsg {
    const HASH: HashFunction = HashFunction::Sha256;
}
pub type MsgKdf = SeparateHmacsKdf<OmemoMsg>;

pub const MESSAGE_CHAIN_CONSTANT: &[u8] = b"\x02\x01";
pub const DEFAULT_MAX_SKIPPED: usize = 1000;
pub const DEFAULT_DOS_THRESHOLD: u64 = 1000;

type SkippedKey = ([u8; 32], u64);

/// twomemo-flavoured Double Ratchet session. Owns the underlying
/// [`DiffieHellmanRatchet`], an X3DH-derived AD that gets pre-pended to
/// every AEAD HMAC, and a FIFO of skipped message keys.
pub struct TwomemoSession {
    dh: DiffieHellmanRatchet<RootKdf, MsgKdf>,
    ad_x3dh: Vec<u8>,
    skipped: VecDeque<(SkippedKey, Vec<u8>)>,
    max_skipped: usize,
}

impl TwomemoSession {
    /// Active session bootstrap (Alice). Caller passes the X3DH-derived
    /// shared secret as `root_chain_key` and X3DH-derived AD as `ad_x3dh`,
    /// plus Bob's SPK pub as the initial DH ratchet pub, and a priv provider
    /// (production: OS RNG; tests: fixed queue) so the ratchet can grab a
    /// fresh own_ratchet_priv.
    pub fn create_active(
        ad_x3dh: Vec<u8>,
        root_chain_key: Vec<u8>,
        bob_spk_pub: [u8; 32],
        priv_provider: Box<dyn DhPrivProvider>,
    ) -> Result<Self, omemo_doubleratchet::dh_ratchet::DhRatchetError> {
        let dh = DiffieHellmanRatchet::create_active(
            bob_spk_pub,
            root_chain_key,
            MESSAGE_CHAIN_CONSTANT.to_vec(),
            DEFAULT_DOS_THRESHOLD,
            priv_provider,
        )?;
        Ok(Self {
            dh,
            ad_x3dh,
            skipped: VecDeque::new(),
            max_skipped: DEFAULT_MAX_SKIPPED,
        })
    }

    /// Passive session bootstrap (Bob). `own_ratchet_priv` is Bob's SPK
    /// priv. `alice_ratchet_pub` is taken from the inner OMEMOMessage's
    /// `dh_pub` field (carried inside the KEX). The fresh DR priv comes
    /// from `priv_provider`.
    pub fn create_passive(
        ad_x3dh: Vec<u8>,
        root_chain_key: Vec<u8>,
        own_ratchet_priv: [u8; 32],
        alice_ratchet_pub: [u8; 32],
        priv_provider: Box<dyn DhPrivProvider>,
    ) -> Result<Self, omemo_doubleratchet::dh_ratchet::DhRatchetError> {
        let dh = DiffieHellmanRatchet::create_passive(
            own_ratchet_priv,
            alice_ratchet_pub,
            root_chain_key,
            MESSAGE_CHAIN_CONSTANT.to_vec(),
            DEFAULT_DOS_THRESHOLD,
            priv_provider,
        )?;
        Ok(Self {
            dh,
            ad_x3dh,
            skipped: VecDeque::new(),
            max_skipped: DEFAULT_MAX_SKIPPED,
        })
    }

    /// Encrypt one message. Returns the serialized
    /// `OMEMOAuthenticatedMessage` bytes ready for the wire.
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, omemo_doubleratchet::dh_ratchet::DhRatchetError> {
        let (msg_key, dr_header) = self.dh.next_encryption_key()?;
        let ad = build_associated_data(&self.ad_x3dh, &dr_header);
        Ok(aead_encrypt(&ad, &msg_key, plaintext))
    }

    /// Decrypt an `OMEMOAuthenticatedMessage` (raw bytes from the wire).
    pub fn decrypt_message(&mut self, auth_msg_bytes: &[u8]) -> Result<Vec<u8>, TwomemoError> {
        // Peek the inner OmemoMessage to discover (dh_pub, n, pn) without
        // touching ratchet state.
        let auth = OmemoAuthenticatedMessage::decode(auth_msg_bytes)?;
        let inner = OmemoMessage::decode(auth.message.as_slice())?;
        let header = Header {
            ratchet_pub: {
                let mut p = [0u8; 32];
                if inner.dh_pub.len() != 32 {
                    return Err(TwomemoError::HeaderMismatch);
                }
                p.copy_from_slice(&inner.dh_pub);
                p
            },
            previous_sending_chain_length: inner.pn as u64,
            sending_chain_length: inner.n as u64,
        };

        // Skipped-keys cache lookup.
        let key_idx = (header.ratchet_pub, header.sending_chain_length);
        if let Some(pos) = self.skipped.iter().position(|(k, _)| *k == key_idx) {
            let mk = self.skipped[pos].1.clone();
            let ad = build_associated_data(&self.ad_x3dh, &header);
            let pt = aead_decrypt(&ad, &mk, auth_msg_bytes)?;
            self.skipped.remove(pos);
            return Ok(pt);
        }

        // Tentative step on a clone, only commit on AEAD success.
        let mut dh_clone = self.dh.clone();
        let (mk, new_skipped) = dh_clone
            .next_decryption_key(&header)
            .map_err(|_| TwomemoError::AuthFailed)?;
        let ad = build_associated_data(&self.ad_x3dh, &header);
        let pt = aead_decrypt(&ad, &mk, auth_msg_bytes)?;

        self.dh = dh_clone;
        for ((p, n), mk) in new_skipped {
            self.skipped.push_back(((p, n), mk));
        }
        while self.skipped.len() > self.max_skipped {
            self.skipped.pop_front();
        }
        Ok(pt)
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Capture the full session state as a plain-data snapshot. Pair with
    /// [`Self::from_snapshot`] to round-trip through SQLite.
    pub fn snapshot(&self) -> TwomemoSessionSnapshot {
        TwomemoSessionSnapshot {
            dh: self.dh.snapshot(),
            ad_x3dh: self.ad_x3dh.clone(),
            max_skipped: self.max_skipped,
            skipped: self.skipped.iter().cloned().collect(),
        }
    }

    /// Restore a session from a snapshot. The caller supplies a fresh
    /// priv provider (production: OS RNG; tests: fixed queue).
    pub fn from_snapshot(
        s: TwomemoSessionSnapshot,
        priv_provider: Box<dyn DhPrivProvider>,
    ) -> Self {
        Self {
            dh: DiffieHellmanRatchet::from_snapshot(s.dh, priv_provider),
            ad_x3dh: s.ad_x3dh,
            skipped: s.skipped.into_iter().collect(),
            max_skipped: s.max_skipped,
        }
    }
}

/// Plain-data snapshot of a [`TwomemoSession`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwomemoSessionSnapshot {
    pub dh: omemo_doubleratchet::dh_ratchet::DhRatchetSnapshot,
    pub ad_x3dh: Vec<u8>,
    pub max_skipped: usize,
    pub skipped: Vec<(SkippedKey, Vec<u8>)>,
}

const SNAPSHOT_VERSION: u8 = 1;

impl TwomemoSessionSnapshot {
    /// Length-prefixed deterministic encoding. Suitable for SQLite BLOB
    /// columns. Format (versioned for future migration):
    ///
    /// ```text
    /// [u8] version = 0x01
    /// [32] own_ratchet_priv
    /// [32] other_ratchet_pub
    /// [u32 LE] root_chain_key.len, [bytes]
    /// [u64 LE] root_chain_length
    /// [u32 LE] message_chain_constant.len, [bytes]
    /// [u8] has_sending; if 1: u32 LE key.len + bytes, u64 LE length
    /// [u8] has_receiving; if 1: same
    /// [u8] has_prev_send_len; if 1: u64 LE
    /// [u64 LE] dos_threshold
    /// [u32 LE] ad_x3dh.len, [bytes]
    /// [u32 LE] max_skipped
    /// [u32 LE] skipped.len
    ///   per entry: [32] pub, [u64 LE] n, [u32 LE] mk.len, [bytes]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&self.dh.own_ratchet_priv);
        out.extend_from_slice(&self.dh.other_ratchet_pub);
        write_bytes(&mut out, &self.dh.root_chain_key);
        out.extend_from_slice(&self.dh.root_chain_length.to_le_bytes());
        write_bytes(&mut out, &self.dh.message_chain_constant);
        write_chain(&mut out, &self.dh.sending_chain);
        write_chain(&mut out, &self.dh.receiving_chain);
        match self.dh.previous_sending_chain_length {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.dh.dos_threshold.to_le_bytes());
        write_bytes(&mut out, &self.ad_x3dh);
        out.extend_from_slice(&(self.max_skipped as u32).to_le_bytes());
        out.extend_from_slice(&(self.skipped.len() as u32).to_le_bytes());
        for ((p, n), mk) in &self.skipped {
            out.extend_from_slice(p);
            out.extend_from_slice(&n.to_le_bytes());
            write_bytes(&mut out, mk);
        }
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, TwomemoError> {
        let mut r = ByteReader::new(input);
        let version = r.read_u8()?;
        if version != SNAPSHOT_VERSION {
            return Err(TwomemoError::HeaderMismatch);
        }
        let own_ratchet_priv = r.read_array_32()?;
        let other_ratchet_pub = r.read_array_32()?;
        let root_chain_key = r.read_bytes()?;
        let root_chain_length = r.read_u64()?;
        let message_chain_constant = r.read_bytes()?;
        let sending_chain = r.read_chain()?;
        let receiving_chain = r.read_chain()?;
        let previous_sending_chain_length = match r.read_u8()? {
            0 => None,
            1 => Some(r.read_u64()?),
            _ => return Err(TwomemoError::HeaderMismatch),
        };
        let dos_threshold = r.read_u64()?;
        let ad_x3dh = r.read_bytes()?;
        let max_skipped = r.read_u32()? as usize;
        let skipped_count = r.read_u32()? as usize;
        let mut skipped = Vec::with_capacity(skipped_count);
        for _ in 0..skipped_count {
            let p = r.read_array_32()?;
            let n = r.read_u64()?;
            let mk = r.read_bytes()?;
            skipped.push(((p, n), mk));
        }
        if !r.is_empty() {
            return Err(TwomemoError::HeaderMismatch);
        }
        Ok(Self {
            dh: omemo_doubleratchet::dh_ratchet::DhRatchetSnapshot {
                own_ratchet_priv,
                other_ratchet_pub,
                root_chain_key,
                root_chain_length,
                message_chain_constant,
                sending_chain,
                receiving_chain,
                previous_sending_chain_length,
                dos_threshold,
            },
            ad_x3dh,
            max_skipped,
            skipped,
        })
    }
}

fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn write_chain(out: &mut Vec<u8>, chain: &Option<(Vec<u8>, u64)>) {
    match chain {
        Some((key, length)) => {
            out.push(1);
            write_bytes(out, key);
            out.extend_from_slice(&length.to_le_bytes());
        }
        None => out.push(0),
    }
}

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], TwomemoError> {
        if self.pos + n > self.data.len() {
            return Err(TwomemoError::HeaderMismatch);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u8(&mut self) -> Result<u8, TwomemoError> {
        Ok(self.take(1)?[0])
    }
    fn read_u32(&mut self) -> Result<u32, TwomemoError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn read_u64(&mut self) -> Result<u64, TwomemoError> {
        let s = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(s);
        Ok(u64::from_le_bytes(buf))
    }
    fn read_array_32(&mut self) -> Result<[u8; 32], TwomemoError> {
        let s = self.take(32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(s);
        Ok(buf)
    }
    fn read_bytes(&mut self) -> Result<Vec<u8>, TwomemoError> {
        let len = self.read_u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
    fn read_chain(&mut self) -> Result<Option<(Vec<u8>, u64)>, TwomemoError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => {
                let key = self.read_bytes()?;
                let length = self.read_u64()?;
                Ok(Some((key, length)))
            }
            _ => Err(TwomemoError::HeaderMismatch),
        }
    }
}

/// Wrap an `OMEMOAuthenticatedMessage` (serialized) inside an
/// `OMEMOKeyExchange`. Used for the very first message of a session.
///
/// `ik` and `ek` are taken from the X3DH active header; `pk_id` and
/// `spk_id` are the IDs of the consumed OPK and SPK respectively (the
/// receiver looks them up by ID to recover the full public keys).
pub fn build_key_exchange(
    pk_id: u32,
    spk_id: u32,
    ik: [u8; 32],
    ek: [u8; 32],
    auth_msg_bytes: &[u8],
) -> Result<Vec<u8>, TwomemoError> {
    let auth = OmemoAuthenticatedMessage::decode(auth_msg_bytes)?;
    let kex = OmemoKeyExchange {
        pk_id,
        spk_id,
        ik: ik.to_vec(),
        ek: ek.to_vec(),
        message: auth,
    };
    let mut out = Vec::with_capacity(kex.encoded_len());
    kex.encode(&mut out).expect("encode in-memory");
    Ok(out)
}

/// `(pk_id, spk_id, ik_pub, ek_pub, auth_msg_bytes)` extracted from a parsed
/// OMEMOKeyExchange.
pub type ParsedKeyExchange = (u32, u32, [u8; 32], [u8; 32], Vec<u8>);

/// Parse an `OMEMOKeyExchange`, returning the extracted fields. The receiver
/// pairs `(pk_id, spk_id)` with their stored public keys, runs X3DH passive,
/// and feeds `auth_msg_bytes` to [`TwomemoSession::decrypt_message`].
pub fn parse_key_exchange(kex_bytes: &[u8]) -> Result<ParsedKeyExchange, TwomemoError> {
    let kex = OmemoKeyExchange::decode(kex_bytes)?;
    if kex.ik.len() != 32 || kex.ek.len() != 32 {
        return Err(TwomemoError::HeaderMismatch);
    }
    let mut ik = [0u8; 32];
    let mut ek = [0u8; 32];
    ik.copy_from_slice(&kex.ik);
    ek.copy_from_slice(&kex.ek);
    let mut auth_bytes = Vec::with_capacity(kex.message.encoded_len());
    kex.message
        .encode(&mut auth_bytes)
        .expect("encode in-memory");
    Ok((kex.pk_id, kex.spk_id, ik, ek, auth_bytes))
}

/// Helper for tests — re-export so the harness doesn't need to depend on
/// `omemo-doubleratchet` for the FixedDhPrivProvider type.
pub fn fixed_priv_provider(privs: Vec<[u8; 32]>) -> Box<dyn DhPrivProvider> {
    Box::new(FixedDhPrivProvider::new(privs))
}

/// Read the inner `OMEMOMessage.dh_pub` from a serialized
/// `OMEMOAuthenticatedMessage` without otherwise touching ratchet state.
/// Used when bootstrapping a passive `TwomemoSession` from a KEX so that
/// the receiver knows the sender's first DH ratchet pub.
pub fn peek_dh_pub(auth_msg_bytes: &[u8]) -> Result<[u8; 32], TwomemoError> {
    let auth = OmemoAuthenticatedMessage::decode(auth_msg_bytes)?;
    let inner = OmemoMessage::decode(auth.message.as_slice())?;
    if inner.dh_pub.len() != 32 {
        return Err(TwomemoError::HeaderMismatch);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&inner.dh_pub);
    Ok(out)
}
