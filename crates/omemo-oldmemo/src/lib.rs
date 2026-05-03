//! OMEMO 0.3.0 (`oldmemo`, `eu.siacs.conversations.axolotl`) wire-format
//! backend.
//!
//! Authored clean-room from XEP-0384 v0.3 plus interop fixtures (see
//! ADR-009). The Rust crypto primitives are reused unchanged from
//! `omemo-doubleratchet` / `omemo-x3dh` / `omemo-xeddsa`; only the
//! OMEMO-0.3-specific deltas live here:
//!
//! | aspect              | twomemo (urn:xmpp:omemo:2)            | oldmemo (eu.siacs...axolotl)            |
//! |---------------------|---------------------------------------|-----------------------------------------|
//! | OMEMOAuthenticatedMessage | protobuf wrapper                | bare concat: `0x33 || OMEMOMessage || mac` |
//! | MAC truncation      | 16 bytes                              | 8 bytes                                 |
//! | AEAD info           | `b"OMEMO Message Key Material"`       | `b"WhisperMessageKeys"`                 |
//! | Root chain info     | `b"OMEMO Root Chain"`                 | `b"WhisperRatchet"`                     |
//! | X3DH info           | `b"OMEMO X3DH"`                       | `b"WhisperText"`                        |
//! | Ratchet pub on wire | raw 32 bytes                          | 33 bytes (`0x05 \|\| pub`)              |
//! | Identity key format | Ed25519                               | Curve25519 (33-byte 0x05-prefixed)      |
//! | AssociatedData      | `ik_a(32) \|\| ik_b(32)` = 64 bytes   | `enc(ik_a)(33) \|\| enc(ik_b)(33)` = 66 |

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message as _;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize as _;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use omemo_doubleratchet::dh_ratchet::Header as DrHeader;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/oldmemo.rs"));
}

pub use proto::{OmemoKeyExchange, OmemoMessage};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Per-message AEAD HKDF info string (`b"WhisperMessageKeys"` per
/// XEP-0384 v0.3 / Signal `WhisperTextProtocol`).
pub const AEAD_INFO: &[u8] = b"WhisperMessageKeys";
/// Truncated HMAC length on the per-message tag (8 bytes — half of
/// twomemo's 16, matching libsignal-protocol-java's `SignalMessage`).
pub const MAC_LEN: usize = 8;
/// Single byte that prefixes a serialised `OMEMOMessage` inside the
/// `OMEMOAuthenticatedMessage` blob. Encodes the protocol version (3
/// for OMEMO 0.3); receivers reject any other value.
pub const VERSION_BYTE: u8 = 0x33;
/// Curve25519 public-key network prefix (`0x05`). Total encoded length
/// is `IDENTITY_KEY_ENCODING_LENGTH = 33`.
pub const PUBKEY_PREFIX: u8 = 0x05;
/// Encoded length of a Curve25519 public key in OMEMO 0.3's network
/// format (one prefix byte + 32 bytes of key).
pub const IDENTITY_KEY_ENCODING_LENGTH: usize = 33;

#[derive(Debug, Error)]
pub enum OldmemoError {
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
    #[error("expected version byte 0x33, got 0x{0:02x}")]
    BadVersionByte(u8),
    #[error("expected 0x05 public-key prefix; got 0x{0:02x}")]
    BadPubkeyPrefix(u8),
    #[error("authenticated message blob shorter than {MAC_LEN} bytes")]
    AuthMsgTooShort,
    #[error("expected {IDENTITY_KEY_ENCODING_LENGTH}-byte encoded pubkey; got {0}")]
    BadEncodedPubkeyLength(usize),
}

/// Encode a 32-byte Curve25519 public key in OMEMO 0.3's network
/// format: `0x05 || pub` (33 bytes total).
pub fn serialize_public_key(pub_key: &[u8; 32]) -> [u8; IDENTITY_KEY_ENCODING_LENGTH] {
    let mut out = [0u8; IDENTITY_KEY_ENCODING_LENGTH];
    out[0] = PUBKEY_PREFIX;
    out[1..].copy_from_slice(pub_key);
    out
}

/// Inverse of [`serialize_public_key`]. Validates the prefix byte and
/// the total length.
pub fn parse_public_key(serialized: &[u8]) -> Result<[u8; 32], OldmemoError> {
    if serialized.len() != IDENTITY_KEY_ENCODING_LENGTH {
        return Err(OldmemoError::BadEncodedPubkeyLength(serialized.len()));
    }
    if serialized[0] != PUBKEY_PREFIX {
        return Err(OldmemoError::BadPubkeyPrefix(serialized[0]));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&serialized[1..]);
    Ok(out)
}

/// Build the AD that oldmemo's DoubleRatchet uses internally.
///
/// `ad_x3dh` is the X3DH-derived `enc(ik_a) || enc(ik_b)` (66 bytes,
/// using [`serialize_public_key`] for each identity key). The trailing
/// `OMEMOMessage(n, pn, dh_pub).SerializeToString()` is appended; the
/// AEAD strips it back off before HMAC-ing.
pub fn build_associated_data(ad_x3dh: &[u8], h: &DrHeader) -> Vec<u8> {
    let header_msg = OmemoMessage {
        n: h.sending_chain_length as u32,
        pn: h.previous_sending_chain_length as u32,
        dh_pub: serialize_public_key(&h.ratchet_pub).to_vec(),
        ciphertext: None,
    };
    let mut out = Vec::with_capacity(ad_x3dh.len() + header_msg.encoded_len());
    out.extend_from_slice(ad_x3dh);
    header_msg.encode(&mut out).expect("encode in-memory");
    out
}

fn derive_with_info(key: &[u8], info: &[u8]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let salt = [0u8; 32];
    let mut out = [0u8; 80];
    Hkdf::<Sha256>::new(Some(&salt), key)
        .expand(info, &mut out)
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

fn derive(key: &[u8]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    derive_with_info(key, AEAD_INFO)
}

fn truncated_hmac(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    let full = m.finalize().into_bytes();
    let mut tag = [0u8; MAC_LEN];
    tag.copy_from_slice(&full[..MAC_LEN]);
    tag
}

/// Serialise an OMEMO 0.3 `OMEMOAuthenticatedMessage`: bare concat of
/// `0x33 || OmemoMessage::encode() || mac(8B)`.
fn serialize_auth_msg(omemo_msg_bytes: &[u8], mac: &[u8; MAC_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + omemo_msg_bytes.len() + MAC_LEN);
    out.push(VERSION_BYTE);
    out.extend_from_slice(omemo_msg_bytes);
    out.extend_from_slice(mac);
    out
}

/// Inverse of [`serialize_auth_msg`]. Returns `(omemo_msg_bytes,
/// mac)`. The first byte must be `0x33`.
fn parse_auth_msg(blob: &[u8]) -> Result<(&[u8], [u8; MAC_LEN]), OldmemoError> {
    if blob.len() < 1 + MAC_LEN {
        return Err(OldmemoError::AuthMsgTooShort);
    }
    if blob[0] != VERSION_BYTE {
        return Err(OldmemoError::BadVersionByte(blob[0]));
    }
    let split = blob.len() - MAC_LEN;
    let omemo_msg_bytes = &blob[1..split];
    let mut mac = [0u8; MAC_LEN];
    mac.copy_from_slice(&blob[split..]);
    Ok((omemo_msg_bytes, mac))
}

/// `AEADImpl::encrypt` (oldmemo). Returns the bare-concat
/// `OMEMOAuthenticatedMessage` bytes ready for the wire (or for
/// wrapping in an `OMEMOKeyExchange` for the very first message).
pub fn aead_encrypt(associated_data: &[u8], msg_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (ad_x3dh, header_bytes) = associated_data.split_at(IDENTITY_KEY_ENCODING_LENGTH * 2);
    let header = OmemoMessage::decode(header_bytes)
        .expect("DR layer always feeds well-formed OMEMOMessage");

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

    // HMAC input matches python-oldmemo: ad_x3dh || (0x33 ||
    // omemo_msg_bytes). Note the version byte is included in the MAC
    // input.
    let mut mac_input = Vec::with_capacity(ad_x3dh.len() + 1 + omemo_msg_bytes.len());
    mac_input.extend_from_slice(ad_x3dh);
    mac_input.push(VERSION_BYTE);
    mac_input.extend_from_slice(&omemo_msg_bytes);
    let mac = truncated_hmac(&auth_key, &mac_input);

    enc_key.zeroize();
    auth_key.zeroize();

    serialize_auth_msg(&omemo_msg_bytes, &mac)
}

/// `AEADImpl::decrypt` (oldmemo). Input is the bare-concat
/// `OMEMOAuthenticatedMessage` bytes. Returns the plaintext.
pub fn aead_decrypt(
    associated_data: &[u8],
    msg_key: &[u8],
    auth_msg_blob: &[u8],
) -> Result<Vec<u8>, OldmemoError> {
    let (ad_x3dh, header_bytes) = associated_data.split_at(IDENTITY_KEY_ENCODING_LENGTH * 2);
    let dr_header = OmemoMessage::decode(header_bytes)?;

    let (omemo_msg_bytes, mac) = parse_auth_msg(auth_msg_blob)?;

    let (mut enc_key, mut auth_key, iv) = derive(msg_key);

    let mut mac_input = Vec::with_capacity(ad_x3dh.len() + 1 + omemo_msg_bytes.len());
    mac_input.extend_from_slice(ad_x3dh);
    mac_input.push(VERSION_BYTE);
    mac_input.extend_from_slice(omemo_msg_bytes);
    let computed = truncated_hmac(&auth_key, &mac_input);

    if !constant_time_eq(&computed, &mac) {
        enc_key.zeroize();
        auth_key.zeroize();
        return Err(OldmemoError::AuthFailed);
    }

    let inner = OmemoMessage::decode(omemo_msg_bytes)?;
    if inner.n != dr_header.n || inner.pn != dr_header.pn || inner.dh_pub != dr_header.dh_pub {
        enc_key.zeroize();
        auth_key.zeroize();
        return Err(OldmemoError::HeaderMismatch);
    }
    let ct = inner
        .ciphertext
        .as_deref()
        .ok_or(OldmemoError::MissingCiphertext)?;

    let pt = Aes256CbcDec::new(&enc_key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| OldmemoError::InvalidPadding)?;

    enc_key.zeroize();
    auth_key.zeroize();
    Ok(pt)
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

// ---------------------------------------------------------------------------
// Session: Double-Ratchet + oldmemo wire format glue.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;

use omemo_doubleratchet::aead::HashFunction;
use omemo_doubleratchet::dh_ratchet::{
    DhPrivProvider, DiffieHellmanRatchet, FixedDhPrivProvider, Header,
};
use omemo_doubleratchet::kdf_hkdf::{HkdfKdf, HkdfParams};
use omemo_doubleratchet::kdf_separate_hmacs::{SeparateHmacsKdf, SeparateHmacsParams};

/// OMEMO 0.3 root chain KDF (HKDF-SHA-256, info `"WhisperRatchet"`).
pub struct OldmemoRoot;
impl HkdfParams for OldmemoRoot {
    const HASH: HashFunction = HashFunction::Sha256;
    const INFO: &'static [u8] = b"WhisperRatchet";
}
pub type RootKdf = HkdfKdf<OldmemoRoot>;

/// OMEMO 0.3 message chain KDF (separate-HMACs SHA-256). Constant
/// `b"\x02\x01"` matches libsignal-protocol-java's `ChainKey.java`
/// (`MESSAGE_KEY_SEED`/`CHAIN_KEY_SEED` distinguishers concatenated).
pub struct OldmemoMsg;
impl SeparateHmacsParams for OldmemoMsg {
    const HASH: HashFunction = HashFunction::Sha256;
}
pub type MsgKdf = SeparateHmacsKdf<OldmemoMsg>;

pub const MESSAGE_CHAIN_CONSTANT: &[u8] = b"\x02\x01";
pub const DEFAULT_MAX_SKIPPED: usize = 1000;
pub const DEFAULT_DOS_THRESHOLD: u64 = 1000;

type SkippedKey = ([u8; 32], u64);

/// oldmemo-flavoured Double Ratchet session.
pub struct OldmemoSession {
    dh: DiffieHellmanRatchet<RootKdf, MsgKdf>,
    ad_x3dh: Vec<u8>,
    skipped: VecDeque<(SkippedKey, Vec<u8>)>,
    max_skipped: usize,
}

impl OldmemoSession {
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

    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, omemo_doubleratchet::dh_ratchet::DhRatchetError> {
        let (msg_key, dr_header) = self.dh.next_encryption_key()?;
        let ad = build_associated_data(&self.ad_x3dh, &dr_header);
        Ok(aead_encrypt(&ad, &msg_key, plaintext))
    }

    pub fn decrypt_message(&mut self, auth_msg_blob: &[u8]) -> Result<Vec<u8>, OldmemoError> {
        // Peek inner OMEMOMessage to discover (dh_pub, n, pn) without
        // touching ratchet state.
        let (omemo_msg_bytes, _mac) = parse_auth_msg(auth_msg_blob)?;
        let inner = OmemoMessage::decode(omemo_msg_bytes)?;
        let dh_pub = parse_public_key(&inner.dh_pub)?;
        let header = Header {
            ratchet_pub: dh_pub,
            previous_sending_chain_length: inner.pn as u64,
            sending_chain_length: inner.n as u64,
        };

        let key_idx = (header.ratchet_pub, header.sending_chain_length);
        if let Some(pos) = self.skipped.iter().position(|(k, _)| *k == key_idx) {
            let mk = self.skipped[pos].1.clone();
            let ad = build_associated_data(&self.ad_x3dh, &header);
            let pt = aead_decrypt(&ad, &mk, auth_msg_blob)?;
            self.skipped.remove(pos);
            return Ok(pt);
        }

        let mut dh_clone = self.dh.clone();
        let (mk, new_skipped) = dh_clone
            .next_decryption_key(&header)
            .map_err(|_| OldmemoError::AuthFailed)?;
        let ad = build_associated_data(&self.ad_x3dh, &header);
        let pt = aead_decrypt(&ad, &mk, auth_msg_blob)?;

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

    pub fn snapshot(&self) -> OldmemoSessionSnapshot {
        OldmemoSessionSnapshot {
            dh: self.dh.snapshot(),
            ad_x3dh: self.ad_x3dh.clone(),
            max_skipped: self.max_skipped,
            skipped: self.skipped.iter().cloned().collect(),
        }
    }

    pub fn from_snapshot(
        s: OldmemoSessionSnapshot,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldmemoSessionSnapshot {
    pub dh: omemo_doubleratchet::dh_ratchet::DhRatchetSnapshot,
    pub ad_x3dh: Vec<u8>,
    pub max_skipped: usize,
    pub skipped: Vec<(SkippedKey, Vec<u8>)>,
}

const SNAPSHOT_VERSION: u8 = 1;

impl OldmemoSessionSnapshot {
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

    pub fn decode(input: &[u8]) -> Result<Self, OldmemoError> {
        let mut r = ByteReader::new(input);
        let version = r.read_u8()?;
        if version != SNAPSHOT_VERSION {
            return Err(OldmemoError::HeaderMismatch);
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
            _ => return Err(OldmemoError::HeaderMismatch),
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
            return Err(OldmemoError::HeaderMismatch);
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
    fn take(&mut self, n: usize) -> Result<&'a [u8], OldmemoError> {
        if self.pos + n > self.data.len() {
            return Err(OldmemoError::HeaderMismatch);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn read_u8(&mut self) -> Result<u8, OldmemoError> {
        Ok(self.take(1)?[0])
    }
    fn read_u32(&mut self) -> Result<u32, OldmemoError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn read_u64(&mut self) -> Result<u64, OldmemoError> {
        let s = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(s);
        Ok(u64::from_le_bytes(buf))
    }
    fn read_array_32(&mut self) -> Result<[u8; 32], OldmemoError> {
        let s = self.take(32)?;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(s);
        Ok(buf)
    }
    fn read_bytes(&mut self) -> Result<Vec<u8>, OldmemoError> {
        let len = self.read_u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
    fn read_chain(&mut self) -> Result<Option<(Vec<u8>, u64)>, OldmemoError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => {
                let key = self.read_bytes()?;
                let length = self.read_u64()?;
                Ok(Some((key, length)))
            }
            _ => Err(OldmemoError::HeaderMismatch),
        }
    }
}

/// Wrap an `OMEMOAuthenticatedMessage` (bare concat blob) inside an
/// `OMEMOKeyExchange`. Used for the very first message of a session.
///
/// `ik`/`ek` here are the **raw 32-byte X25519** public keys; this
/// function applies the `0x05` network prefix for you. `pk_id`/`spk_id`
/// are the IDs of the consumed OPK and SPK respectively.
///
/// The wire form is `0x33 || OMEMOKeyExchange.SerializeToString()` —
/// the same `[VERSION_BYTE]` prefix that wraps follow-up
/// `OMEMOAuthenticatedMessage`s. python-oldmemo's
/// `KeyExchangeImpl.serialize` does the same.
pub fn build_key_exchange(
    pk_id: u32,
    spk_id: u32,
    ik: [u8; 32],
    ek: [u8; 32],
    auth_msg_blob: &[u8],
) -> Vec<u8> {
    let kex = OmemoKeyExchange {
        pk_id,
        spk_id,
        ik: serialize_public_key(&ik).to_vec(),
        ek: serialize_public_key(&ek).to_vec(),
        message: auth_msg_blob.to_vec(),
        unused: None,
    };
    let mut out = Vec::with_capacity(1 + kex.encoded_len());
    out.push(VERSION_BYTE);
    kex.encode(&mut out).expect("encode in-memory");
    out
}

/// `(pk_id, spk_id, ik_pub, ek_pub, auth_msg_blob)` extracted from a
/// parsed `OMEMOKeyExchange`. `ik_pub`/`ek_pub` come back as raw
/// 32-byte X25519 keys (the `0x05` prefix is stripped).
pub type ParsedKeyExchange = (u32, u32, [u8; 32], [u8; 32], Vec<u8>);

pub fn parse_key_exchange(kex_bytes: &[u8]) -> Result<ParsedKeyExchange, OldmemoError> {
    if kex_bytes.is_empty() || kex_bytes[0] != VERSION_BYTE {
        return Err(OldmemoError::BadVersionByte(
            kex_bytes.first().copied().unwrap_or(0),
        ));
    }
    let kex = OmemoKeyExchange::decode(&kex_bytes[1..])?;
    let ik = parse_public_key(&kex.ik)?;
    let ek = parse_public_key(&kex.ek)?;
    Ok((kex.pk_id, kex.spk_id, ik, ek, kex.message))
}

/// Read the inner `OMEMOMessage.dh_pub` (raw 32 bytes, prefix
/// stripped) from an `OMEMOAuthenticatedMessage` blob without
/// touching ratchet state.
pub fn peek_dh_pub(auth_msg_blob: &[u8]) -> Result<[u8; 32], OldmemoError> {
    let (omemo_msg_bytes, _mac) = parse_auth_msg(auth_msg_blob)?;
    let inner = OmemoMessage::decode(omemo_msg_bytes)?;
    parse_public_key(&inner.dh_pub)
}

pub fn fixed_priv_provider(privs: Vec<[u8; 32]>) -> Box<dyn DhPrivProvider> {
    Box::new(FixedDhPrivProvider::new(privs))
}

// Test-only re-export of x25519-dalek under a stable alias so the
// session test below can build a real X25519 base-point key without
// adding x25519-dalek to the runtime dependency set.
#[cfg(test)]
extern crate x25519_dalek as x25519_dalek_v2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_serde_round_trip() {
        let pk = [0x42u8; 32];
        let enc = serialize_public_key(&pk);
        assert_eq!(enc[0], 0x05);
        assert_eq!(&enc[1..], &pk);
        let dec = parse_public_key(&enc).unwrap();
        assert_eq!(dec, pk);
    }

    #[test]
    fn pubkey_parse_rejects_bad_prefix() {
        let mut bad = [0u8; IDENTITY_KEY_ENCODING_LENGTH];
        bad[0] = 0x06;
        match parse_public_key(&bad) {
            Err(OldmemoError::BadPubkeyPrefix(0x06)) => {}
            other => panic!("expected BadPubkeyPrefix, got {other:?}"),
        }
    }

    #[test]
    fn pubkey_parse_rejects_short() {
        let bad = [0x05u8; 32];
        match parse_public_key(&bad) {
            Err(OldmemoError::BadEncodedPubkeyLength(32)) => {}
            other => panic!("expected BadEncodedPubkeyLength, got {other:?}"),
        }
    }

    #[test]
    fn auth_msg_serde_round_trip() {
        let inner = b"\x08\x01\x10\x02".to_vec(); // not a real OMEMOMessage; just a blob
        let mac = [0xAAu8; MAC_LEN];
        let blob = serialize_auth_msg(&inner, &mac);
        assert_eq!(blob[0], VERSION_BYTE);
        assert_eq!(blob.len(), 1 + inner.len() + MAC_LEN);
        let (got_inner, got_mac) = parse_auth_msg(&blob).unwrap();
        assert_eq!(got_inner, &inner[..]);
        assert_eq!(got_mac, mac);
    }

    #[test]
    fn auth_msg_parse_rejects_bad_version() {
        let mut blob = vec![0x32]; // wrong version
        blob.extend_from_slice(&[0u8; 16 + MAC_LEN]);
        match parse_auth_msg(&blob) {
            Err(OldmemoError::BadVersionByte(0x32)) => {}
            other => panic!("expected BadVersionByte, got {other:?}"),
        }
    }

    #[test]
    fn auth_msg_parse_rejects_too_short() {
        let blob = [VERSION_BYTE; MAC_LEN]; // exactly 8 bytes — no room for any inner content
        // Note: blob.len() = MAC_LEN, and the threshold is `1 + MAC_LEN`, so
        // this is rejected because parse_auth_msg requires len >= 1 + MAC_LEN.
        match parse_auth_msg(&blob) {
            Err(OldmemoError::AuthMsgTooShort) => {}
            other => panic!("expected AuthMsgTooShort, got {other:?}"),
        }
    }

    #[test]
    fn aead_round_trip() {
        // Simulate an AD: 66 zero bytes (encoded ik_a || ik_b) + a
        // serialised header OMEMOMessage.
        let ad_x3dh = vec![0u8; IDENTITY_KEY_ENCODING_LENGTH * 2];
        let header = DrHeader {
            ratchet_pub: [0x77u8; 32],
            previous_sending_chain_length: 0,
            sending_chain_length: 0,
        };
        let ad = build_associated_data(&ad_x3dh, &header);

        let msg_key = [0xC3u8; 32];
        let pt = b"hello oldmemo round trip";
        let blob = aead_encrypt(&ad, &msg_key, pt);

        // Verify shape: starts with 0x33, ends with 8-byte MAC.
        assert_eq!(blob[0], VERSION_BYTE);

        let recovered = aead_decrypt(&ad, &msg_key, &blob).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aead_rejects_bad_mac() {
        let ad_x3dh = vec![0u8; IDENTITY_KEY_ENCODING_LENGTH * 2];
        let header = DrHeader {
            ratchet_pub: [0x77u8; 32],
            previous_sending_chain_length: 0,
            sending_chain_length: 0,
        };
        let ad = build_associated_data(&ad_x3dh, &header);
        let msg_key = [0xC3u8; 32];
        let mut blob = aead_encrypt(&ad, &msg_key, b"x");
        // Flip last byte (MAC tail).
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        match aead_decrypt(&ad, &msg_key, &blob) {
            Err(OldmemoError::AuthFailed) => {}
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[test]
    fn key_exchange_serde() {
        let auth_blob = {
            let mut v = vec![VERSION_BYTE];
            v.extend_from_slice(&[0xAA; 30]);
            v.extend_from_slice(&[0xBB; MAC_LEN]);
            v
        };
        let kex_bytes = build_key_exchange(7, 13, [0x11u8; 32], [0x22u8; 32], &auth_blob);
        let (pk_id, spk_id, ik, ek, msg) = parse_key_exchange(&kex_bytes).unwrap();
        assert_eq!(pk_id, 7);
        assert_eq!(spk_id, 13);
        assert_eq!(ik, [0x11u8; 32]);
        assert_eq!(ek, [0x22u8; 32]);
        assert_eq!(msg, auth_blob);
    }

    #[test]
    fn session_round_trip_via_doubleratchet() {
        // Drive a real DR session through OldmemoSession with a fixed
        // priv provider, exercising encrypt -> decrypt across a DH
        // step.

        // 32-byte deterministic seeds; not real X25519 priv keys, but
        // the DR ratchet treats them opaquely for the test path.
        let alice_seeds: Vec<[u8; 32]> = (0..4).map(|i| [0x10 | i as u8; 32]).collect();
        let bob_seeds: Vec<[u8; 32]> = (0..4).map(|i| [0x20 | i as u8; 32]).collect();

        let bob_spk_priv = [0x33u8; 32];
        // bob's spk pub == X25519 pubkey of priv (use x25519_dalek for
        // a real point). Avoid pulling x25519 in here; use an
        // arbitrary 32-byte buffer as a stand-in. The DR treats it
        // opaquely except as a DH input; we verify only encrypt/
        // decrypt symmetry.
        let bob_spk_pub = {
            let sk = x25519_dalek_v2::StaticSecret::from(bob_spk_priv);
            let pk: x25519_dalek_v2::PublicKey = (&sk).into();
            pk.to_bytes()
        };

        let ad_x3dh = vec![0u8; IDENTITY_KEY_ENCODING_LENGTH * 2];
        let root_key = vec![0x55u8; 32];

        let mut alice = OldmemoSession::create_active(
            ad_x3dh.clone(),
            root_key.clone(),
            bob_spk_pub,
            fixed_priv_provider(alice_seeds.clone()),
        )
        .unwrap();
        let m1 = alice.encrypt_message(b"hello bob").unwrap();
        let alice_dh_pub_1 = peek_dh_pub(&m1).unwrap();

        let mut bob = OldmemoSession::create_passive(
            ad_x3dh,
            root_key,
            bob_spk_priv,
            alice_dh_pub_1,
            fixed_priv_provider(bob_seeds),
        )
        .unwrap();
        let pt = bob.decrypt_message(&m1).unwrap();
        assert_eq!(pt, b"hello bob");

        let m2 = bob.encrypt_message(b"hi alice").unwrap();
        let pt2 = alice.decrypt_message(&m2).unwrap();
        assert_eq!(pt2, b"hi alice");
    }
}

