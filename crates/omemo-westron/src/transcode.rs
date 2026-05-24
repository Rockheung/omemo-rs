//! Sender-side per-recipient wire selection — SPEC §7.2.
//!
//! Given a list of recipient devices with caps, group them by best-shared spec
//! and emit one stanza per group.
use crate::caps::{negotiate_best_spec, Caps, Spec};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Recipient {
    pub jid: String,
    pub device_id: u32,
    pub caps: Caps,
}

#[derive(Debug, Default)]
pub struct SendPlan {
    pub groups: BTreeMap<Spec, Vec<Recipient>>,
    pub unreachable: Vec<Recipient>,
}

pub fn select_wire_for_recipients(self_caps: &Caps, recipients: &[Recipient]) -> SendPlan {
    let mut plan = SendPlan::default();
    for r in recipients {
        match negotiate_best_spec(self_caps, &r.caps) {
            Ok(spec) => plan.groups.entry(spec).or_default().push(r.clone()),
            Err(_) => plan.unreachable.push(r.clone()),
        }
    }
    plan
}
