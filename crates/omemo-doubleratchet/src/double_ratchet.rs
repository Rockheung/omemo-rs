//! Top-level DoubleRatchet — port of `python-doubleratchet/double_ratchet.py`.
//!
//! Wraps a [`DiffieHellmanRatchet`], an AEAD, and a FIFO of skipped message
//! keys. Provides `encrypt_message` / `decrypt_message`. Decrypt uses the
//! deep-copy-on-failure pattern: a clone of the DH ratchet runs the
//! tentative step; the clone is only committed back to `self` after AEAD
//! success.
//!
//! Skipped-key cap: `max_skipped_message_keys` (FIFO eviction of oldest).
//! For the gate test we use 1000.
//!
//! `build_ad` is a function pointer `(ad, header) -> Vec<u8>` — the python
//! ABC's `_build_associated_data` callback. The default [`build_ad_default`]
//! is a deterministic encoding used by the gate test; OMEMO 2/twomemo will
//! substitute a protobuf-based header serialiser later.

use std::collections::VecDeque;

use thiserror::Error;

use crate::aead::{self as aead_mod, AeadError, HashFunction};
use crate::dh_ratchet::{DhRatchetError, DiffieHellmanRatchet, Header};
use crate::kdf::Kdf;

#[derive(Debug, Error)]
pub enum DoubleRatchetError {
    #[error("aead: {0}")]
    Aead(#[from] AeadError),
    #[error("dh ratchet: {0}")]
    DhRatchet(#[from] DhRatchetError),
    #[error("dos_threshold ({dos}) > max_skipped_message_keys ({max})")]
    InvalidThresholds { dos: u64, max: u64 },
    #[error("shared secret must be 32 bytes")]
    InvalidSharedSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

pub type BuildAdFn = fn(associated_data: &[u8], header: &Header) -> Vec<u8>;

/// Default associated-data encoding for the gate test:
/// `ad || ratchet_pub(32) || pn(8 LE) || n(8 LE)`.
pub fn build_ad_default(ad: &[u8], h: &Header) -> Vec<u8> {
    let mut out = Vec::with_capacity(ad.len() + 32 + 8 + 8);
    out.extend_from_slice(ad);
    out.extend_from_slice(&h.ratchet_pub);
    out.extend_from_slice(&h.previous_sending_chain_length.to_le_bytes());
    out.extend_from_slice(&h.sending_chain_length.to_le_bytes());
    out
}

#[derive(Debug, Clone, Copy)]
pub struct AeadParams {
    pub hash: HashFunction,
    pub info: &'static [u8],
}

type SkippedKey = ([u8; 32], u64);

pub struct DoubleRatchet<R: Kdf, M: Kdf> {
    dh: DiffieHellmanRatchet<R, M>,
    /// FIFO of skipped message keys. Order matches python's `OrderedDict`
    /// insertion order so the truncation semantics line up.
    skipped: VecDeque<(SkippedKey, Vec<u8>)>,
    max_skipped: usize,
    aead_params: AeadParams,
    build_ad: BuildAdFn,
}

impl<R: Kdf, M: Kdf> DoubleRatchet<R, M> {
    /// Construct from a pre-initialised DH ratchet (active or passive).
    pub fn from_dh_ratchet(
        dh: DiffieHellmanRatchet<R, M>,
        max_skipped_message_keys: usize,
        aead_params: AeadParams,
        build_ad: BuildAdFn,
    ) -> Self {
        Self {
            dh,
            skipped: VecDeque::new(),
            max_skipped: max_skipped_message_keys,
            aead_params,
            build_ad,
        }
    }

    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedMessage, DoubleRatchetError> {
        let (mk, header) = self.dh.next_encryption_key()?;
        let ad = (self.build_ad)(associated_data, &header);
        let ct = aead_mod::encrypt(self.aead_params.hash, self.aead_params.info, &mk, &ad, plaintext);
        Ok(EncryptedMessage {
            header,
            ciphertext: ct,
        })
    }

    pub fn decrypt_message(
        &mut self,
        message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, DoubleRatchetError> {
        let key = (
            message.header.ratchet_pub,
            message.header.sending_chain_length,
        );

        // Try the skipped-keys cache first.
        if let Some(pos) = self.skipped.iter().position(|(k, _)| *k == key) {
            let (_, mk) = self.skipped[pos].clone();
            let ad = (self.build_ad)(associated_data, &message.header);
            let pt = aead_mod::decrypt(
                self.aead_params.hash,
                self.aead_params.info,
                &mk,
                &ad,
                &message.ciphertext,
            )?;
            // Commit: drop the used skipped key.
            self.skipped.remove(pos);
            return Ok(pt);
        }

        // Tentative step on a clone — only committed if AEAD succeeds.
        let mut dh_clone = self.dh.clone();
        let (mk, new_skipped) = dh_clone.next_decryption_key(&message.header)?;
        let ad = (self.build_ad)(associated_data, &message.header);
        let pt = aead_mod::decrypt(
            self.aead_params.hash,
            self.aead_params.info,
            &mk,
            &ad,
            &message.ciphertext,
        )?;

        // Commit. Append new skipped keys, then truncate from the front.
        self.dh = dh_clone;
        for ((pub_, n), mk) in new_skipped {
            self.skipped.push_back(((pub_, n), mk));
        }
        while self.skipped.len() > self.max_skipped {
            self.skipped.pop_front();
        }
        Ok(pt)
    }

    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }
}
