//! Signed caps assertion — SPEC §4.3, C-7.3 (P2-C/D).
//!
//! Receiver MUST verify the Ed25519 signature on the `<caps>` element before
//! honoring its content, otherwise an active attacker (A2) can mount a
//! downgrade by stripping or forging caps fields.
//!
//! Canonical signed string (UTF-8):
//!   speaks-omemo-2={a};speaks-omemo-03={b};sid={sid};ts={ts}
use crate::identity::Identity;
use thiserror::Error;

/// SPEC §4.3 — caps freshness window. Receiver rejects caps older than this.
pub const CAPS_MAX_SKEW_SECS: i64 = 86_400;

#[derive(Debug, Error)]
pub enum CapsError {
    #[error("caps signature does not verify under IK_ed")]
    BadSignature,
    #[error("caps sid={got} ≠ stanza sid={expected}")]
    SidMismatch { expected: u32, got: u32 },
    #[error("caps stale: |now - ts| = {skew}s exceeds limit")]
    Stale { skew: i64 },
    #[error("caps missing signature")]
    Unsigned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCaps {
    pub also_speaks_omemo_2: bool,
    pub also_speaks_omemo_03: bool,
    pub sid: u32,
    pub ts: i64,
    pub sig: [u8; 64],
}

impl SignedCaps {
    /// SPEC §4.3 — canonical UTF-8 string the signature covers.
    pub fn canonical_signed_string(&self) -> Vec<u8> {
        format!(
            "speaks-omemo-2={};speaks-omemo-03={};sid={};ts={}",
            self.also_speaks_omemo_2, self.also_speaks_omemo_03, self.sid, self.ts
        )
        .into_bytes()
    }

    /// Producer side — sign caps with our IK.
    pub fn sign(
        identity: &Identity,
        also_speaks_omemo_2: bool,
        also_speaks_omemo_03: bool,
        sid: u32,
        ts: i64,
    ) -> Self {
        let mut caps = Self {
            also_speaks_omemo_2,
            also_speaks_omemo_03,
            sid,
            ts,
            sig: [0u8; 64],
        };
        let msg = caps.canonical_signed_string();
        caps.sig = identity.sign(&msg);
        caps
    }

    /// Verifier side — checks signature, sid binding, and freshness window.
    pub fn verify(
        &self,
        expected_sid: u32,
        ik_ed_pub: &[u8; 32],
        now: Option<i64>,
        max_skew: i64,
    ) -> Result<(), CapsError> {
        if self.sid != expected_sid {
            return Err(CapsError::SidMismatch {
                expected: expected_sid,
                got: self.sid,
            });
        }
        if let Some(now) = now {
            let skew = (now - self.ts).abs();
            if skew > max_skew {
                return Err(CapsError::Stale { skew });
            }
        }
        if self.sig == [0u8; 64] {
            return Err(CapsError::Unsigned);
        }
        Identity::verify(ik_ed_pub, &self.canonical_signed_string(), &self.sig)
            .map_err(|_| CapsError::BadSignature)?;
        Ok(())
    }
}
