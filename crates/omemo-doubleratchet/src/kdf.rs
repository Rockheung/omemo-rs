//! Generic KDF trait — port of `python-doubleratchet/kdf.py`.
//!
//! A KDF takes a `key` and `data` (each opaque bytes) and produces `length`
//! bytes of pseudo-random output.

pub trait Kdf {
    fn derive(key: &[u8], data: &[u8], length: usize) -> Vec<u8>;
}
