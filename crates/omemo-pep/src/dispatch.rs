//! Inbound spec-lock dispatcher — SPEC §7.2/§7.3.
//!
//! When a peer-device sends us an `<encrypted>` payload, the namespace
//! tells us which spec they spoke (OMEMO 2 vs OMEMO 0.3 vs Westron).
//! The dispatcher remembers the highest-priority spec each peer-device
//! has spoken and rejects active downgrade attempts:
//!
//! * **First sight**: record observed spec, accept.
//! * **Same spec**: accept.
//! * **Upgrade** (peer moves to a higher-priority spec — e.g. 0.3 → 2 or
//!   2 → Westron): accept and bump the lock.
//! * **Downgrade** (peer drops to a lower-priority spec): reject with
//!   [`DispatchError::Downgrade`]. Per SPEC §7.3, a peer that has proven
//!   support for spec X cannot silently fall back; if they really need
//!   to (e.g. lost a device that held the higher-spec key material),
//!   they must republish caps via the signed-caps element and the
//!   caller calls [`InboundSpecLocks::renegotiate`].
//!
//! Locks live in process memory for now — persistence is Day 7 of the
//! D-full plan. A bot restart resets locks to first-sight which means
//! one missed downgrade per restart; the wire-level downgrade gate in
//! Westron signed caps closes the same hole at higher cost.
//!
//! Day 4 of the D-full plan in `/home/rock/projects/westron-spec/STATUS.md`.

use std::collections::HashMap;

use jid::BareJid;
use omemo_westron::caps::{negotiate_best_spec, Caps, NegotiationError, Spec};
use thiserror::Error;

use crate::wire::EncryptedAny;

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("peer {jid}/{device_id} downgrade: locked={locked:?}, observed={observed:?}")]
    Downgrade {
        jid: String,
        device_id: u32,
        locked: Spec,
        observed: Spec,
    },
    #[error("capability negotiation: {0}")]
    Negotiation(#[from] NegotiationError),
}

/// In-memory per-peer-device spec lock.
///
/// Construct once per bot run with `self_caps` describing the specs
/// *we* speak. Feed every inbound `<encrypted>` to
/// [`InboundSpecLocks::observe`] before routing to the spec-specific
/// decrypt path — a `Downgrade` return value means the dispatcher
/// should drop the stanza without attempting decryption.
pub struct InboundSpecLocks {
    self_caps: Caps,
    locks: HashMap<(String, u32), Spec>,
}

impl InboundSpecLocks {
    pub fn new(self_caps: Caps) -> Self {
        Self {
            self_caps,
            locks: HashMap::new(),
        }
    }

    /// What we ourselves support — exposed so callers can sanity-check
    /// against caps they've received and so renegotiation against a
    /// peer Caps element can intersect.
    pub fn self_caps(&self) -> &Caps {
        &self.self_caps
    }

    /// Currently-locked spec for `(jid, device_id)` if observed before.
    pub fn locked(&self, jid: &BareJid, device_id: u32) -> Option<Spec> {
        self.locks.get(&(jid.to_string(), device_id)).copied()
    }

    /// Best (highest-priority) spec previously observed for any device
    /// under `jid`. Used by outbound dispatch to pick a backend before
    /// the recipient device is resolved: in the single-spec-per-peer
    /// case this matches every device; if a peer mixes specs across
    /// devices the higher-priority one wins (Westron > OMEMO 2 > 0.3).
    pub fn lookup_peer(&self, jid: &BareJid) -> Option<Spec> {
        let prefix = jid.to_string();
        self.locks
            .iter()
            .filter_map(|((j, _), s)| (j == &prefix).then_some(*s))
            .min_by_key(|s| s.priority())
    }

    /// Observe the spec implied by `payload`. Returns the spec we are
    /// going to route to, or [`DispatchError::Downgrade`] if `payload`
    /// is in a lower-priority spec than the previously-locked one.
    ///
    /// `Spec::priority` is *lower-is-better* (Westron=0, 2=1, 0.3=2),
    /// so a downgrade is "observed.priority() > locked.priority()".
    pub fn observe(
        &mut self,
        jid: &BareJid,
        device_id: u32,
        payload: &EncryptedAny,
    ) -> Result<Spec, DispatchError> {
        let observed = spec_of(payload);
        self.observe_spec(jid, device_id, observed)
    }

    /// Lower-level variant: observe a `Spec` directly. Useful when the
    /// caller has parsed the namespace from a foreign source (e.g. a
    /// Westron-canonical stanza that the wire layer didn't classify as
    /// `EncryptedAny`).
    pub fn observe_spec(
        &mut self,
        jid: &BareJid,
        device_id: u32,
        observed: Spec,
    ) -> Result<Spec, DispatchError> {
        let key = (jid.to_string(), device_id);
        match self.locks.get(&key).copied() {
            None => {
                self.locks.insert(key, observed);
                Ok(observed)
            }
            Some(locked) => {
                if observed == locked {
                    Ok(observed)
                } else if observed.priority() < locked.priority() {
                    self.locks.insert(key, observed);
                    Ok(observed)
                } else {
                    Err(DispatchError::Downgrade {
                        jid: jid.to_string(),
                        device_id,
                        locked,
                        observed,
                    })
                }
            }
        }
    }

    /// SPEC §7.2 — given a freshly-verified peer Caps element (typically
    /// from a signed-caps inbound), intersect with our own caps to pick
    /// the highest-priority common spec, and *replace* the per-peer-device
    /// lock with that spec.
    ///
    /// Use this only after the caps element has been signature-verified
    /// under the peer's IK_ed — otherwise a MITM could renegotiate us
    /// down to a spec they prefer. (D-full Day 5 will produce signed
    /// caps; this function is the consumer.)
    pub fn renegotiate(
        &mut self,
        jid: &BareJid,
        device_id: u32,
        peer_caps: &Caps,
    ) -> Result<Spec, DispatchError> {
        let spec = negotiate_best_spec(&self.self_caps, peer_caps)?;
        self.locks.insert((jid.to_string(), device_id), spec);
        Ok(spec)
    }

    /// Forget any lock for `(jid, device_id)`. Useful when the peer
    /// rotates its device or the user explicitly resets trust.
    pub fn forget(&mut self, jid: &BareJid, device_id: u32) {
        self.locks.remove(&(jid.to_string(), device_id));
    }
}

/// Map an `EncryptedAny` variant to the on-wire spec it represents.
pub fn spec_of(payload: &EncryptedAny) -> Spec {
    match payload {
        EncryptedAny::Twomemo(_) => Spec::Omemo2,
        EncryptedAny::Oldmemo(_) => Spec::Omemo03,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omemo_stanza::axolotl_stanza::{Encrypted as OldEncrypted, KeyEntry as OldKeyEntry};
    use omemo_stanza::{Encrypted, Key, KeysGroup};
    use std::str::FromStr;

    fn alice() -> BareJid {
        BareJid::from_str("alice@example.org").unwrap()
    }

    fn bob() -> BareJid {
        BareJid::from_str("bob@example.org").unwrap()
    }

    fn full_caps() -> Caps {
        Caps::new([Spec::Westron, Spec::Omemo2, Spec::Omemo03])
    }

    fn caps_2_only() -> Caps {
        Caps::new([Spec::Omemo2])
    }

    fn caps_03_only() -> Caps {
        Caps::new([Spec::Omemo03])
    }

    fn caps_2_and_03() -> Caps {
        Caps::new([Spec::Omemo2, Spec::Omemo03])
    }

    /// Minimal valid OMEMO 2 `<encrypted>` payload — only structure
    /// matters for the dispatcher; nothing here is decrypted.
    fn omemo2_payload() -> EncryptedAny {
        EncryptedAny::Twomemo(Encrypted {
            sid: 1001,
            keys: vec![KeysGroup {
                jid: "bob@example.org".into(),
                keys: vec![Key {
                    rid: 2001,
                    kex: false,
                    data: vec![0u8; 16],
                }],
            }],
            payload: Some(vec![0u8; 8]),
        })
    }

    fn omemo03_payload() -> EncryptedAny {
        EncryptedAny::Oldmemo(OldEncrypted {
            sid: 1001,
            iv: vec![0u8; 12],
            keys: vec![OldKeyEntry {
                rid: 2001,
                prekey: false,
                data: vec![0u8; 16],
            }],
            payload: Some(vec![0u8; 8]),
        })
    }

    #[test]
    fn first_sight_records_and_accepts() {
        let mut locks = InboundSpecLocks::new(full_caps());
        let spec = locks.observe(&bob(), 2001, &omemo2_payload()).expect("ok");
        assert_eq!(spec, Spec::Omemo2);
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Omemo2));
    }

    #[test]
    fn same_spec_accepted_no_change() {
        let mut locks = InboundSpecLocks::new(full_caps());
        locks.observe(&bob(), 2001, &omemo2_payload()).unwrap();
        let spec = locks.observe(&bob(), 2001, &omemo2_payload()).expect("ok");
        assert_eq!(spec, Spec::Omemo2);
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Omemo2));
    }

    #[test]
    fn upgrade_03_to_2_accepted() {
        let mut locks = InboundSpecLocks::new(full_caps());
        locks
            .observe(&bob(), 2001, &omemo03_payload())
            .expect("first sight 0.3");
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Omemo03));
        let spec = locks
            .observe(&bob(), 2001, &omemo2_payload())
            .expect("upgrade to 2");
        assert_eq!(spec, Spec::Omemo2);
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Omemo2));
    }

    #[test]
    fn upgrade_via_renegotiate_to_westron() {
        let mut locks = InboundSpecLocks::new(full_caps());
        locks.observe(&bob(), 2001, &omemo2_payload()).unwrap();
        let spec = locks
            .renegotiate(&bob(), 2001, &full_caps())
            .expect("renegotiate to westron");
        assert_eq!(spec, Spec::Westron);
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Westron));
    }

    #[test]
    fn downgrade_2_to_03_rejected() {
        let mut locks = InboundSpecLocks::new(full_caps());
        locks.observe(&bob(), 2001, &omemo2_payload()).unwrap();
        let err = locks
            .observe(&bob(), 2001, &omemo03_payload())
            .expect_err("downgrade rejected");
        match err {
            DispatchError::Downgrade {
                jid,
                device_id,
                locked,
                observed,
            } => {
                assert_eq!(jid, "bob@example.org");
                assert_eq!(device_id, 2001);
                assert_eq!(locked, Spec::Omemo2);
                assert_eq!(observed, Spec::Omemo03);
            }
            other => panic!("expected Downgrade, got {other}"),
        }
        // Lock unchanged after rejection.
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Omemo2));
    }

    #[test]
    fn downgrade_westron_to_2_rejected() {
        let mut locks = InboundSpecLocks::new(full_caps());
        locks
            .observe_spec(&bob(), 2001, Spec::Westron)
            .expect("first sight westron");
        let err = locks
            .observe(&bob(), 2001, &omemo2_payload())
            .expect_err("westron→2 rejected");
        assert!(matches!(err, DispatchError::Downgrade { .. }));
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Westron));
    }

    #[test]
    fn renegotiate_intersects_caps() {
        let mut locks = InboundSpecLocks::new(caps_2_and_03());
        let spec = locks
            .renegotiate(&bob(), 2001, &caps_03_only())
            .expect("intersect");
        assert_eq!(spec, Spec::Omemo03);
    }

    #[test]
    fn renegotiate_no_common_errs() {
        let mut locks = InboundSpecLocks::new(caps_2_only());
        let err = locks
            .renegotiate(&bob(), 2001, &caps_03_only())
            .expect_err("no overlap");
        assert!(matches!(err, DispatchError::Negotiation(_)));
        // No lock recorded on failure.
        assert_eq!(locks.locked(&bob(), 2001), None);
    }

    #[test]
    fn lock_is_per_peer_device() {
        let mut locks = InboundSpecLocks::new(full_caps());
        locks.observe(&alice(), 1001, &omemo2_payload()).unwrap();
        locks.observe(&bob(), 2001, &omemo03_payload()).unwrap();
        // alice/1001 stays on 2, bob/2001 stays on 0.3 — independent.
        assert_eq!(locks.locked(&alice(), 1001), Some(Spec::Omemo2));
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Omemo03));
        // Same JID, different device_id: independent again.
        locks.observe(&bob(), 2002, &omemo2_payload()).unwrap();
        assert_eq!(locks.locked(&bob(), 2002), Some(Spec::Omemo2));
        assert_eq!(locks.locked(&bob(), 2001), Some(Spec::Omemo03));
    }

    #[test]
    fn forget_clears_lock_for_first_sight_on_next_observe() {
        let mut locks = InboundSpecLocks::new(full_caps());
        locks.observe(&bob(), 2001, &omemo2_payload()).unwrap();
        locks.forget(&bob(), 2001);
        assert_eq!(locks.locked(&bob(), 2001), None);
        // After forget, an 0.3 payload from the same peer is first-sight again.
        let spec = locks
            .observe(&bob(), 2001, &omemo03_payload())
            .expect("first sight again");
        assert_eq!(spec, Spec::Omemo03);
    }

    #[test]
    fn spec_of_classifies_correctly() {
        assert_eq!(spec_of(&omemo2_payload()), Spec::Omemo2);
        assert_eq!(spec_of(&omemo03_payload()), Spec::Omemo03);
    }
}
