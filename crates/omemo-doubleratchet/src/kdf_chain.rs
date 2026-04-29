//! Generic KDF chain — port of `python-doubleratchet/kdf_chain.py`.
//!
//! Wraps a [`Kdf`] and a chain key. Each `step(data, length)` derives
//! `key.len() + length` bytes from the chain, replaces the chain key with the
//! first `key.len()` bytes, and returns the last `length` bytes.

use core::marker::PhantomData;

use zeroize::Zeroize;

use crate::kdf::Kdf;

pub struct KdfChain<K: Kdf> {
    key: Vec<u8>,
    length: u64,
    _kdf: PhantomData<K>,
}

impl<K: Kdf> Clone for KdfChain<K> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            length: self.length,
            _kdf: PhantomData,
        }
    }
}

impl<K: Kdf> KdfChain<K> {
    pub fn new(initial_key: Vec<u8>) -> Self {
        Self {
            key: initial_key,
            length: 0,
            _kdf: PhantomData,
        }
    }

    /// Restore a chain from a previously snapshotted (key, length) pair.
    /// Used by the SQLite session store; do not call from production
    /// session-init paths (use [`new`] there).
    pub fn from_parts(key: Vec<u8>, length: u64) -> Self {
        Self {
            key,
            length,
            _kdf: PhantomData,
        }
    }

    pub fn step(&mut self, data: &[u8], length: usize) -> Vec<u8> {
        let key_len = self.key.len();
        let mut out = K::derive(&self.key, data, key_len + length);

        let mut new_key = out[..key_len].to_vec();
        let result = out[key_len..].to_vec();

        out.zeroize();

        // Replace key in place (zeroizes the old one).
        self.key.zeroize();
        core::mem::swap(&mut self.key, &mut new_key);
        self.length += 1;

        result
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl<K: Kdf> Drop for KdfChain<K> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
