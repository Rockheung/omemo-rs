//! Diffie-Hellman ratchet — port of `python-doubleratchet/diffie_hellman_ratchet.py`
//! parameterised on Curve25519 (X25519) per `recommended/diffie_hellman_ratchet_curve25519.py`.
//!
//! Owns the root chain (KDF chain, e.g. HKDF-SHA-256) and the symmetric-key
//! ratchet. Each `next_encryption_key` advances the sending chain; each
//! `next_decryption_key(header)` may trigger a full DH ratchet step (replace
//! receiving + generate fresh priv + replace sending) when the header's
//! `ratchet_pub` differs from the cached peer pub.
//!
//! Fresh ratchet privs are obtained from a [`DhPrivProvider`] supplied at
//! construction time. Production code uses [`OsRandDhPrivProvider`]; tests
//! pre-stage privs via [`FixedDhPrivProvider`] for byte-equal replay.

use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::kdf::Kdf;
use crate::kdf_chain::KdfChain;
use crate::symmetric_key_ratchet::{Chain, SymmetricKeyRatchet, SymmetricKeyRatchetError};

/// Header carried with each ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub ratchet_pub: [u8; 32],
    pub previous_sending_chain_length: u64,
    pub sending_chain_length: u64,
}

#[derive(Debug, Error)]
pub enum DhRatchetError {
    #[error("symmetric-key ratchet error: {0}")]
    Skr(#[from] SymmetricKeyRatchetError),
    #[error("DoS protection: more than {threshold} skipped message keys requested")]
    DosProtection { threshold: u64 },
    #[error("duplicate message — header.n {header_n} < receiving_chain_length {recv_len}")]
    DuplicateMessage { header_n: u64, recv_len: u64 },
    #[error("root chain key must be 32 bytes")]
    InvalidRootKey,
}

/// Skipped message keys: list of `(peer_ratchet_pub, n, msg_key)`. Insertion
/// order matches python's `OrderedDict` behaviour.
pub type SkippedMessageKeys = Vec<(([u8; 32], u64), Vec<u8>)>;

pub trait DhPrivProvider {
    fn generate_priv(&mut self) -> [u8; 32];
    /// Required for the DoubleRatchet decrypt-on-clone pattern; both the
    /// ratchet state *and* its priv provider need to be deep-copied.
    fn clone_box(&self) -> Box<dyn DhPrivProvider>;
}

/// Test-only: priv keys popped from the front of a queue. Panics if exhausted.
#[derive(Clone)]
pub struct FixedDhPrivProvider {
    pub queue: std::collections::VecDeque<[u8; 32]>,
}

impl FixedDhPrivProvider {
    pub fn new(privs: Vec<[u8; 32]>) -> Self {
        Self {
            queue: privs.into_iter().collect(),
        }
    }
}

impl DhPrivProvider for FixedDhPrivProvider {
    fn generate_priv(&mut self) -> [u8; 32] {
        self.queue
            .pop_front()
            .expect("FixedDhPrivProvider exhausted")
    }

    fn clone_box(&self) -> Box<dyn DhPrivProvider> {
        Box::new(self.clone())
    }
}

fn x25519(own_priv: &[u8; 32], other_pub: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*own_priv);
    let p = PublicKey::from(*other_pub);
    *s.diffie_hellman(&p).as_bytes()
}

fn derive_pub(priv_bytes: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*priv_bytes)).as_bytes()
}

pub struct DiffieHellmanRatchet<R: Kdf, M: Kdf> {
    own_ratchet_priv: [u8; 32],
    other_ratchet_pub: [u8; 32],
    root_chain: KdfChain<R>,
    skr: SymmetricKeyRatchet<M>,
    priv_provider: Box<dyn DhPrivProvider>,
    dos_threshold: u64,
}

impl<R: Kdf, M: Kdf> Clone for DiffieHellmanRatchet<R, M> {
    fn clone(&self) -> Self {
        Self {
            own_ratchet_priv: self.own_ratchet_priv,
            other_ratchet_pub: self.other_ratchet_pub,
            root_chain: self.root_chain.clone(),
            skr: self.skr.clone(),
            priv_provider: self.priv_provider.clone_box(),
            dos_threshold: self.dos_threshold,
        }
    }
}

/// Plain-data snapshot of a [`DiffieHellmanRatchet`]'s state, suitable for
/// persistence (SQLite BLOB) or transport between processes. Excludes the
/// priv provider — the caller must supply one when restoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhRatchetSnapshot {
    pub own_ratchet_priv: [u8; 32],
    pub other_ratchet_pub: [u8; 32],
    pub root_chain_key: Vec<u8>,
    pub root_chain_length: u64,
    pub message_chain_constant: Vec<u8>,
    pub sending_chain: Option<(Vec<u8>, u64)>,
    pub receiving_chain: Option<(Vec<u8>, u64)>,
    pub previous_sending_chain_length: Option<u64>,
    pub dos_threshold: u64,
}

impl<R: Kdf, M: Kdf> DiffieHellmanRatchet<R, M> {
    /// Active initialisation (Alice). Generates a fresh own priv, performs
    /// one root-chain step, sets the sending chain.
    pub fn create_active(
        other_ratchet_pub: [u8; 32],
        root_chain_key: Vec<u8>,
        message_chain_constant: Vec<u8>,
        dos_threshold: u64,
        mut priv_provider: Box<dyn DhPrivProvider>,
    ) -> Result<Self, DhRatchetError> {
        if root_chain_key.len() != 32 {
            return Err(DhRatchetError::InvalidRootKey);
        }
        let own_priv = priv_provider.generate_priv();
        let mut this = Self {
            own_ratchet_priv: own_priv,
            other_ratchet_pub,
            root_chain: KdfChain::new(root_chain_key),
            skr: SymmetricKeyRatchet::new(message_chain_constant),
            priv_provider,
            dos_threshold,
        };
        this.replace_chain(Chain::Sending)?;
        Ok(this)
    }

    /// Passive initialisation (Bob). Uses a given own priv (e.g. SPK from
    /// X3DH) for the receiving chain, then generates a fresh priv for the
    /// sending chain.
    pub fn create_passive(
        own_ratchet_priv: [u8; 32],
        other_ratchet_pub: [u8; 32],
        root_chain_key: Vec<u8>,
        message_chain_constant: Vec<u8>,
        dos_threshold: u64,
        priv_provider: Box<dyn DhPrivProvider>,
    ) -> Result<Self, DhRatchetError> {
        if root_chain_key.len() != 32 {
            return Err(DhRatchetError::InvalidRootKey);
        }
        let mut this = Self {
            own_ratchet_priv,
            other_ratchet_pub,
            root_chain: KdfChain::new(root_chain_key),
            skr: SymmetricKeyRatchet::new(message_chain_constant),
            priv_provider,
            dos_threshold,
        };
        this.replace_chain(Chain::Receiving)?;
        let new_priv = this.priv_provider.generate_priv();
        this.own_ratchet_priv = new_priv;
        this.replace_chain(Chain::Sending)?;
        Ok(this)
    }

    fn replace_chain(&mut self, chain: Chain) -> Result<(), DhRatchetError> {
        let dh = x25519(&self.own_ratchet_priv, &self.other_ratchet_pub);
        let chain_key = self.root_chain.step(&dh, 32);
        self.skr.replace_chain(chain, chain_key)?;
        Ok(())
    }

    /// Capture the full ratchet state as a plain-data snapshot. Pair with
    /// [`from_snapshot`] to round-trip through persistent storage.
    pub fn snapshot(&self) -> DhRatchetSnapshot {
        DhRatchetSnapshot {
            own_ratchet_priv: self.own_ratchet_priv,
            other_ratchet_pub: self.other_ratchet_pub,
            root_chain_key: self.root_chain.key().to_vec(),
            root_chain_length: self.root_chain.length(),
            message_chain_constant: self.skr.constant().to_vec(),
            sending_chain: self.skr.sending_chain_parts(),
            receiving_chain: self.skr.receiving_chain_parts(),
            previous_sending_chain_length: self.skr.previous_sending_chain_length(),
            dos_threshold: self.dos_threshold,
        }
    }

    /// Restore a ratchet from a snapshot. The caller supplies a fresh priv
    /// provider — production code uses an OS-RNG-backed provider, tests
    /// use [`FixedDhPrivProvider`].
    pub fn from_snapshot(s: DhRatchetSnapshot, priv_provider: Box<dyn DhPrivProvider>) -> Self {
        Self {
            own_ratchet_priv: s.own_ratchet_priv,
            other_ratchet_pub: s.other_ratchet_pub,
            root_chain: KdfChain::from_parts(s.root_chain_key, s.root_chain_length),
            skr: SymmetricKeyRatchet::from_parts(
                s.message_chain_constant,
                s.sending_chain,
                s.receiving_chain,
                s.previous_sending_chain_length,
            ),
            priv_provider,
            dos_threshold: s.dos_threshold,
        }
    }

    pub fn sending_chain_length(&self) -> u64 {
        self.skr
            .sending_chain_length()
            .expect("sending chain always exists post-init")
    }

    pub fn receiving_chain_length(&self) -> Option<u64> {
        self.skr.receiving_chain_length()
    }

    pub fn own_ratchet_pub(&self) -> [u8; 32] {
        derive_pub(&self.own_ratchet_priv)
    }

    pub fn next_encryption_key(&mut self) -> Result<(Vec<u8>, Header), DhRatchetError> {
        let send_n = self.sending_chain_length();
        let prev_n = self.skr.previous_sending_chain_length().unwrap_or(0);
        let header = Header {
            ratchet_pub: self.own_ratchet_pub(),
            previous_sending_chain_length: prev_n,
            sending_chain_length: send_n,
        };
        let mk = self.skr.next_encryption_key()?;
        Ok((mk, header))
    }

    pub fn next_decryption_key(
        &mut self,
        header: &Header,
    ) -> Result<(Vec<u8>, SkippedMessageKeys), DhRatchetError> {
        let mut skipped: SkippedMessageKeys = Vec::new();

        if header.ratchet_pub != self.other_ratchet_pub {
            // Step ratchet. First, drain skipped keys from the *current* receiving
            // chain (only if a receiving chain exists).
            if let Some(mut recv_len) = self.receiving_chain_length() {
                let num_skipped = header
                    .previous_sending_chain_length
                    .saturating_sub(recv_len);
                if num_skipped > self.dos_threshold {
                    // python-doubleratchet emits a warning here and skips drain,
                    // continuing the ratchet step. We mirror that — skipping
                    // recovery is preferred over total stall under heavy loss.
                } else {
                    let prev_pub = self.other_ratchet_pub;
                    for _ in 0..num_skipped {
                        let mk = self.skr.next_decryption_key()?;
                        skipped.push(((prev_pub, recv_len), mk));
                        recv_len += 1;
                    }
                }
            }
            self.other_ratchet_pub = header.ratchet_pub;
            self.replace_chain(Chain::Receiving)?;
            self.own_ratchet_priv = self.priv_provider.generate_priv();
            self.replace_chain(Chain::Sending)?;
        }

        let mut recv_len = self
            .receiving_chain_length()
            .expect("receiving chain present after possible step");

        let num_skipped = header.sending_chain_length.saturating_sub(recv_len);
        if num_skipped > self.dos_threshold {
            return Err(DhRatchetError::DosProtection {
                threshold: self.dos_threshold,
            });
        }
        for _ in 0..num_skipped {
            let mk = self.skr.next_decryption_key()?;
            skipped.push(((self.other_ratchet_pub, recv_len), mk));
            recv_len += 1;
        }

        if header.sending_chain_length < recv_len {
            return Err(DhRatchetError::DuplicateMessage {
                header_n: header.sending_chain_length,
                recv_len,
            });
        }

        let mk = self.skr.next_decryption_key()?;
        Ok((mk, skipped))
    }
}
