//! Symmetric-key ratchet — port of `python-doubleratchet/symmetric_key_ratchet.py`.
//!
//! Holds two KDF chains (sending, receiving). On each `next_encryption_key`
//! / `next_decryption_key` it advances one chain by `constant` and yields a
//! 32-byte message key.
//!
//! The `replace_chain(SENDING, key)` operation snapshots the current sending
//! chain's length into `previous_sending_chain_length` before swapping in the
//! new chain — that snapshot is what populates `OMEMOMessage.pn` on the wire.

use thiserror::Error;

use crate::kdf::Kdf;
use crate::kdf_chain::KdfChain;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Sending,
    Receiving,
}

#[derive(Debug, Error)]
pub enum SymmetricKeyRatchetError {
    #[error("the {0:?} chain has not been initialized")]
    ChainNotAvailable(Chain),
    #[error("chain key must be exactly 32 bytes")]
    InvalidChainKeyLength,
}

pub struct SymmetricKeyRatchet<K: Kdf> {
    constant: Vec<u8>,
    sending_chain: Option<KdfChain<K>>,
    receiving_chain: Option<KdfChain<K>>,
    previous_sending_chain_length: Option<u64>,
}

impl<K: Kdf> Clone for SymmetricKeyRatchet<K> {
    fn clone(&self) -> Self {
        Self {
            constant: self.constant.clone(),
            sending_chain: self.sending_chain.clone(),
            receiving_chain: self.receiving_chain.clone(),
            previous_sending_chain_length: self.previous_sending_chain_length,
        }
    }
}

impl<K: Kdf> SymmetricKeyRatchet<K> {
    pub fn new(constant: Vec<u8>) -> Self {
        Self {
            constant,
            sending_chain: None,
            receiving_chain: None,
            previous_sending_chain_length: None,
        }
    }

    /// Restore an SKR from snapshotted parts. Used by the SQLite session
    /// store. The chain `Option`s carry a `(key, length)` pair each.
    pub fn from_parts(
        constant: Vec<u8>,
        sending_chain: Option<(Vec<u8>, u64)>,
        receiving_chain: Option<(Vec<u8>, u64)>,
        previous_sending_chain_length: Option<u64>,
    ) -> Self {
        Self {
            constant,
            sending_chain: sending_chain.map(|(k, l)| KdfChain::from_parts(k, l)),
            receiving_chain: receiving_chain.map(|(k, l)| KdfChain::from_parts(k, l)),
            previous_sending_chain_length,
        }
    }

    pub fn constant(&self) -> &[u8] {
        &self.constant
    }

    pub fn sending_chain_parts(&self) -> Option<(Vec<u8>, u64)> {
        self.sending_chain
            .as_ref()
            .map(|c| (c.key().to_vec(), c.length()))
    }

    pub fn receiving_chain_parts(&self) -> Option<(Vec<u8>, u64)> {
        self.receiving_chain
            .as_ref()
            .map(|c| (c.key().to_vec(), c.length()))
    }

    pub fn replace_chain(
        &mut self,
        chain: Chain,
        key: Vec<u8>,
    ) -> Result<(), SymmetricKeyRatchetError> {
        if key.len() != 32 {
            return Err(SymmetricKeyRatchetError::InvalidChainKeyLength);
        }
        match chain {
            Chain::Sending => {
                self.previous_sending_chain_length = self.sending_chain_length();
                self.sending_chain = Some(KdfChain::new(key));
            }
            Chain::Receiving => {
                self.receiving_chain = Some(KdfChain::new(key));
            }
        }
        Ok(())
    }

    pub fn sending_chain_length(&self) -> Option<u64> {
        self.sending_chain.as_ref().map(|c| c.length())
    }

    pub fn receiving_chain_length(&self) -> Option<u64> {
        self.receiving_chain.as_ref().map(|c| c.length())
    }

    pub fn previous_sending_chain_length(&self) -> Option<u64> {
        self.previous_sending_chain_length
    }

    pub fn next_encryption_key(&mut self) -> Result<Vec<u8>, SymmetricKeyRatchetError> {
        let chain = self
            .sending_chain
            .as_mut()
            .ok_or(SymmetricKeyRatchetError::ChainNotAvailable(Chain::Sending))?;
        Ok(chain.step(&self.constant, 32))
    }

    pub fn next_decryption_key(&mut self) -> Result<Vec<u8>, SymmetricKeyRatchetError> {
        let chain = self
            .receiving_chain
            .as_mut()
            .ok_or(SymmetricKeyRatchetError::ChainNotAvailable(Chain::Receiving))?;
        Ok(chain.step(&self.constant, 32))
    }
}
