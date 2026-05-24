//! Capability negotiation — SPEC §7.
//!
//! A device publishes which OMEMO specs it can speak; the sender picks the
//! highest-priority spec in the intersection. Westron > OMEMO 2 > OMEMO 0.3.
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Spec {
    /// `urn:xmpp:omemo:westron:1`
    Westron,
    /// `urn:xmpp:omemo:2`
    Omemo2,
    /// `eu.siacs.conversations.axolotl`
    Omemo03,
}

impl Spec {
    pub fn namespace(self) -> &'static str {
        match self {
            Spec::Westron => "urn:xmpp:omemo:westron:1",
            Spec::Omemo2 => "urn:xmpp:omemo:2",
            Spec::Omemo03 => "eu.siacs.conversations.axolotl",
        }
    }

    /// Priority order: Westron > 2 > 0.3.
    pub fn priority(self) -> u8 {
        match self {
            Spec::Westron => 0,
            Spec::Omemo2 => 1,
            Spec::Omemo03 => 2,
        }
    }

    /// SPEC C-5.1 — X3DH HKDF info string per-spec.
    pub fn x3dh_info(self) -> &'static [u8] {
        match self {
            Spec::Westron => b"OMEMO Westron",
            Spec::Omemo2 => b"OMEMO X3DH",
            Spec::Omemo03 => b"WhisperText",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caps {
    pub specs: BTreeSet<Spec>,
}

impl Caps {
    pub fn new<I: IntoIterator<Item = Spec>>(specs: I) -> Self {
        Self {
            specs: specs.into_iter().collect(),
        }
    }
}

#[derive(Debug, Error)]
pub enum NegotiationError {
    #[error("no common OMEMO spec between self and peer")]
    NoCommon,
}

/// SPEC §7.2 — pick the highest-priority spec both sides support.
pub fn negotiate_best_spec(self_caps: &Caps, peer_caps: &Caps) -> Result<Spec, NegotiationError> {
    const PRIORITY_ORDER: &[Spec] = &[Spec::Westron, Spec::Omemo2, Spec::Omemo03];
    for &s in PRIORITY_ORDER {
        if self_caps.specs.contains(&s) && peer_caps.specs.contains(&s) {
            return Ok(s);
        }
    }
    Err(NegotiationError::NoCommon)
}

/// SPEC §7.3 — detect a peer dropping a higher-priority spec they previously had.
pub fn detect_downgrade(prev: &Caps, now: &Caps) -> bool {
    const PRIORITY_ORDER: &[Spec] = &[Spec::Westron, Spec::Omemo2, Spec::Omemo03];
    for &s in PRIORITY_ORDER {
        let in_prev = prev.specs.contains(&s);
        let in_now = now.specs.contains(&s);
        if in_prev && !in_now {
            return true;
        }
        if in_prev && in_now {
            return false;
        }
    }
    false
}
