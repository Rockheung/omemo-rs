//! # omemo-westron
//!
//! Westron — unified spec layer that lets a single Rust endpoint speak
//! OMEMO 0.3, OMEMO 2, and the Westron canonical wire (`urn:xmpp:omemo:westron:1`)
//! with one Ed25519 master identity.
//!
//! See `/home/rock/projects/westron-spec/SPEC.md` for the full specification.
//!
//! This crate sits on top of `omemo-twomemo` (OMEMO 2 wire), `omemo-oldmemo`
//! (OMEMO 0.3 wire), and the workspace's shared `omemo-x3dh` / `omemo-doubleratchet`
//! crates. It does NOT reimplement the inner crypto — only the unification
//! layer: identity, capability negotiation, signed caps, per-recipient wire
//! selection, and (planned) the Westron canonical wire format.

pub mod caps;
pub mod identity;
pub mod signed_caps;
pub mod transcode;
pub mod wire;

pub use caps::{detect_downgrade, negotiate_best_spec, Caps, NegotiationError, Spec};
pub use identity::{derive_curve25519, Identity, IdentityError};
pub use signed_caps::{CapsError, SignedCaps, CAPS_MAX_SKEW_SECS};
pub use transcode::{select_wire_for_recipients, Recipient, SendPlan};
