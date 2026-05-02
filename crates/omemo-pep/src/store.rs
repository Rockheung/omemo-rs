//! Glue between [`omemo_session::Store`] and the in-memory crypto types
//! ([`X3dhState`], [`TwomemoSession`]).
//!
//! The Store is the system of record for own identity, SPK, OPK pool,
//! and per-peer-device sessions. This module exposes the small set of
//! operations the wire layer needs:
//!
//! * `install_identity` — bootstrap own identity + SPK + OPKs into the
//!   store (test/replay path; production will gain a randomised variant).
//! * `x3dh_state_from_store` / `bundle_from_store` — reconstruct the
//!   in-memory `X3dhState` and the stanza-level `Bundle`.
//! * `bootstrap_and_save_active` — run X3DH active against a peer
//!   bundle, persist the freshly created session, return the carrier
//!   that the first outbound message must wrap in `OMEMOKeyExchange`.
//! * `encrypt_to_peer` — load session, encrypt one message (optionally
//!   with KEX), persist the advanced session.
//! * `receive_first_message` — KEX-tagged inbound: look up SPK/OPK pubs
//!   from the store by id, run X3DH passive + ratchet decrypt, open SCE
//!   payload, then atomically `consume_opk` + `save_session`.
//! * `receive_followup` — non-KEX inbound: load session, decrypt SCE,
//!   persist updated session.
//!
//! Single-device peers only; group fanout is Stage 5.

use std::time::{SystemTime, UNIX_EPOCH};

use omemo_doubleratchet::dh_ratchet::DhPrivProvider;
use omemo_session::{
    OwnIdentity, SessionStoreError, Store, StoredOpk, StoredSpk, TrustState, TrustedDevice,
};
use omemo_stanza::{
    sce::SceEnvelope, Bundle, Encrypted, PreKey as StanzaPreKey,
    SignedPreKey as StanzaSignedPreKey, StanzaError,
};
use omemo_twomemo::{parse_key_exchange, TwomemoSession};
use omemo_x3dh::{IdentityKeyPair, PreKeyPair, SignedPreKeyPair, X3dhState};
use rand_core::{OsRng, RngCore};
use thiserror::Error;

use crate::message::{
    bootstrap_active_session_from_bundle, decrypt_inbound_kex, decrypt_message, encrypt_message,
    KexCarrier, MessageError, Recipient,
};

#[derive(Debug, Error)]
pub enum StoreFlowError {
    #[error("session store: {0}")]
    Store(#[from] SessionStoreError),
    #[error("message: {0}")]
    Message(#[from] MessageError),
    #[error("identity not initialised in store")]
    IdentityMissing,
    #[error("no current SPK in store")]
    SpkMissing,
    #[error("session not found for {jid}/{device_id}")]
    SessionMissing { jid: String, device_id: u32 },
    #[error("our key entry missing for {jid}/{device_id}")]
    OurKeyMissing { jid: String, device_id: u32 },
    #[error("inbound was kex=false; route to receive_followup")]
    KexExpected,
    #[error("inbound was kex=true; route to receive_first_message")]
    FollowExpected,
    #[error("twomemo: {0}")]
    Twomemo(#[from] omemo_twomemo::TwomemoError),
    #[error("envelope: {0}")]
    Envelope(#[from] StanzaError),
    #[error("SCE envelope is not valid UTF-8 XML")]
    EnvelopeNotUtf8,
    #[error("SCE envelope <to> is {got:?}, expected {expected:?}")]
    WrongRecipient { expected: String, got: String },
    #[error("SCE envelope has no <body>")]
    BodyMissing,
    #[error("peer device {jid}/{device_id} is Untrusted — refusing to encrypt")]
    PeerUntrusted { jid: String, device_id: u32 },
    #[error("peer device {jid}/{device_id} not yet approved (Pending) under Manual policy")]
    PeerPending { jid: String, device_id: u32 },
    #[error("peer device {jid}/{device_id} IK changed: stored {stored_hex}, KEX {got_hex}")]
    IkMismatch {
        jid: String,
        device_id: u32,
        stored_hex: String,
        got_hex: String,
    },
    #[error("PEP transport: {0}")]
    Pep(String),
}

/// Caller-supplied policy for incorporating new peer devices into the
/// trust store.
///
/// * `Tofu` — Trust-On-First-Use: any unseen device's IK is accepted
///   immediately and persisted as `TrustState::Trusted`. Subsequent
///   sights must match that IK or the receive call rejects with
///   [`StoreFlowError::IkMismatch`].
/// * `Manual` — first sight inserts the device as
///   `TrustState::Pending`; the application is expected to render an
///   approval prompt and call `Store::set_trust(...,Trusted)` (or
///   `Untrusted`) before encryption / decryption proceeds. While
///   Pending, encrypt/decrypt return [`StoreFlowError::PeerPending`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustPolicy {
    Tofu,
    Manual,
}

impl TrustPolicy {
    fn default_state(self) -> TrustState {
        match self {
            TrustPolicy::Tofu => TrustState::Trusted,
            TrustPolicy::Manual => TrustState::Pending,
        }
    }
}

/// Parsed inbound SCE envelope after decryption + `<to>` verification.
/// `body` is the unescaped text content of `<body xmlns='jabber:client'>`;
/// `from_jid` and `timestamp` are XEP-0420 fields, exposed for callers
/// that want to surface "Received from X at T" hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundEnvelope {
    pub body: String,
    pub from_jid: String,
    pub timestamp: String,
}

/// Caller-supplied material for [`install_identity`]. All fields are
/// deterministic seeds so tests and fixtures can replay byte-for-byte;
/// production code will derive each from the OS RNG.
pub struct IdentitySeed<'a> {
    pub bare_jid: &'a str,
    pub device_id: u32,
    pub ik_seed: [u8; 32],
    pub spk_id: u32,
    pub spk_priv: [u8; 32],
    pub spk_sig_nonce: [u8; 64],
    pub opks: &'a [(u32, [u8; 32])],
}

/// Bootstrap own identity + initial SPK + OPK pool into the store.
pub fn install_identity(
    store: &mut Store,
    seed: &IdentitySeed<'_>,
) -> Result<OwnIdentity, StoreFlowError> {
    let identity = store.put_identity(seed.bare_jid, seed.device_id, &seed.ik_seed)?;
    let ik = IdentityKeyPair::Seed(seed.ik_seed);
    let spk_pair = SignedPreKeyPair::create(&ik, seed.spk_priv, seed.spk_sig_nonce, 0);
    store.put_spk(&StoredSpk {
        id: seed.spk_id,
        priv_key: seed.spk_priv,
        pub_key: spk_pair.pub_key(),
        sig: spk_pair.sig,
        created_at: identity.created_at,
        replaced_at: None,
    })?;
    for (id, priv_key) in seed.opks {
        let pk = PreKeyPair {
            priv_key: *priv_key,
        };
        store.put_opk(&StoredOpk {
            id: *id,
            priv_key: *priv_key,
            pub_key: pk.pub_key(),
            consumed: false,
            created_at: identity.created_at,
        })?;
    }
    Ok(identity)
}

/// Reconstruct the in-memory `X3dhState` from the current SPK and the
/// unconsumed OPK pool.
pub fn x3dh_state_from_store(store: &Store) -> Result<X3dhState, StoreFlowError> {
    let identity = store
        .get_identity()?
        .ok_or(StoreFlowError::IdentityMissing)?;
    let spk = store.current_spk()?.ok_or(StoreFlowError::SpkMissing)?;
    let opks = store.unconsumed_opks()?;
    Ok(X3dhState {
        identity_key: IdentityKeyPair::Seed(identity.ik_seed),
        signed_pre_key: SignedPreKeyPair {
            priv_key: spk.priv_key,
            sig: spk.sig,
            timestamp: spk.created_at as u64,
        },
        old_signed_pre_key: None,
        pre_keys: opks
            .into_iter()
            .map(|o| PreKeyPair {
                priv_key: o.priv_key,
            })
            .collect(),
    })
}

/// Build the stanza-level [`Bundle`] from the store. Includes all
/// unconsumed OPKs.
pub fn bundle_from_store(store: &Store) -> Result<Bundle, StoreFlowError> {
    let identity = store
        .get_identity()?
        .ok_or(StoreFlowError::IdentityMissing)?;
    let spk = store.current_spk()?.ok_or(StoreFlowError::SpkMissing)?;
    let opks = store.unconsumed_opks()?;
    let ik_pub_ed = IdentityKeyPair::Seed(identity.ik_seed).ed25519_pub();
    Ok(Bundle {
        spk: StanzaSignedPreKey {
            id: spk.id,
            pub_key: spk.pub_key.to_vec(),
        },
        spks: spk.sig.to_vec(),
        ik: ik_pub_ed.to_vec(),
        prekeys: opks
            .iter()
            .map(|o| StanzaPreKey {
                id: o.id,
                pub_key: o.pub_key.to_vec(),
            })
            .collect(),
    })
}

/// Run X3DH active against `peer_bundle`, persist the freshly created
/// session under `(peer_jid, peer_device_id)`, and return the
/// [`KexCarrier`] the caller must attach to the first outbound message.
pub fn bootstrap_and_save_active(
    store: &mut Store,
    peer_jid: &str,
    peer_device_id: u32,
    peer_bundle: &Bundle,
    chosen_opk_id: u32,
    ephemeral_priv: [u8; 32],
    priv_provider: Box<dyn DhPrivProvider>,
) -> Result<KexCarrier, StoreFlowError> {
    let state = x3dh_state_from_store(store)?;
    let (session, kex) = bootstrap_active_session_from_bundle(
        &state,
        peer_bundle,
        chosen_opk_id,
        ephemeral_priv,
        priv_provider,
    )?;
    store.save_session(peer_jid, peer_device_id, &session)?;
    Ok(kex)
}

/// Top up the OPK pool to at least `target_unconsumed` unconsumed
/// entries. Each OPK consumes XEP-0384 §5.3.2's "consume-once"
/// invariant, so a finite pool drains over time as peers run X3DH
/// active against the published bundle. Production callers should run
/// this on a schedule (e.g. on every PEP item-deletion notification
/// for our own bundles, or simply periodically) and then call
/// [`publish_my_bundle`] so the freshly-minted public halves reach
/// peers via the PEP node.
///
/// `rng` provides 32 fresh bytes per new OPK priv. A
/// CSPRNG-equivalent RNG is required — passing `OsRng` from `rand`
/// is the typical production choice; tests can pass any
/// deterministic seed-able RNG.
///
/// Returns the number of OPKs actually inserted (`0` if the pool was
/// already at or above target).
pub fn replenish_opks<R: rand_core::RngCore>(
    store: &mut Store,
    target_unconsumed: u32,
    rng: &mut R,
) -> Result<u32, StoreFlowError> {
    let current = store.count_unconsumed_opks()?;
    if current >= target_unconsumed {
        return Ok(0);
    }
    let to_add = target_unconsumed - current;
    let first_id = store.next_opk_id()?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    for next_id in first_id..first_id + to_add {
        let mut priv_key = [0u8; 32];
        rng.fill_bytes(&mut priv_key);
        let pk = PreKeyPair { priv_key };
        store.put_opk(&StoredOpk {
            id: next_id,
            priv_key,
            pub_key: pk.pub_key(),
            consumed: false,
            created_at: now_secs,
        })?;
    }
    Ok(to_add)
}

/// Build the stanza-level [`Bundle`] from the store and publish it to
/// our own `urn:xmpp:omemo:2:bundles` PEP node under the given device
/// id. Convenience wrapper for the typical "after refilling OPKs,
/// republish the bundle" flow — `bundle_from_store` always reflects
/// the current pool, so this picks up the freshly-minted entries.
pub async fn publish_my_bundle(
    store: &Store,
    client: &mut tokio_xmpp::Client,
    own_device_id: u32,
) -> Result<(), StoreFlowError> {
    let bundle = bundle_from_store(store)?;
    crate::pep::publish_bundle(client, own_device_id, &bundle)
        .await
        .map_err(|e| StoreFlowError::Pep(e.to_string()))?;
    Ok(())
}

/// Refuse encrypt / decrypt to a device the user has explicitly marked
/// `Untrusted`. Pending devices and never-seen devices are allowed —
/// the receive path is what records and gates first sight.
fn refuse_if_untrusted(
    store: &Store,
    jid: &str,
    device_id: u32,
) -> Result<Option<TrustedDevice>, StoreFlowError> {
    let row = store.trusted_device(jid, device_id)?;
    if let Some(t) = &row {
        if t.state == TrustState::Untrusted {
            return Err(StoreFlowError::PeerUntrusted {
                jid: jid.to_owned(),
                device_id,
            });
        }
    }
    Ok(row)
}

fn hex32(b: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for x in b {
        out.push_str(&format!("{x:02x}"));
    }
    out
}

/// Build the SCE envelope (XEP-0420 §3) for one outbound message.
///
/// `body_text` is wrapped in `<body xmlns='jabber:client'>...</body>`
/// (XML-escaped). 16 fresh random bytes are placed in `<rpad>` to
/// resist size-based traffic analysis. The current wall clock is
/// formatted as RFC 3339 UTC for `<time stamp=>`.
fn build_envelope(
    body_text: &str,
    our_jid: &str,
    peer_jid: &str,
) -> Result<String, StoreFlowError> {
    let mut rpad = vec![0u8; 16];
    OsRng.fill_bytes(&mut rpad);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let env = SceEnvelope {
        content: build_body_xml(body_text),
        rpad,
        timestamp: format_iso8601_utc(now_secs),
        to: peer_jid.to_owned(),
        from: our_jid.to_owned(),
    };
    Ok(env.encode()?)
}

fn build_body_xml(text: &str) -> String {
    let mut s = String::from("<body xmlns=\"jabber:client\">");
    for c in text.chars() {
        match c {
            '<' => s.push_str("&lt;"),
            '>' => s.push_str("&gt;"),
            '&' => s.push_str("&amp;"),
            other => s.push(other),
        }
    }
    s.push_str("</body>");
    s
}

/// Civil-from-days algorithm (Howard Hinnant) — converts unix seconds
/// to `YYYY-MM-DDTHH:MM:SSZ`. Pure-arithmetic so no chrono/time
/// dependency is needed for the one timestamp field XEP-0420 mandates.
fn format_iso8601_utc(secs: i64) -> String {
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    let secs_today = secs.rem_euclid(86400);
    let h = secs_today / 3600;
    let mn = (secs_today / 60) % 60;
    let s = secs_today % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mn:02}:{s:02}Z")
}

/// Verify and unwrap a decrypted SCE envelope.
///
/// XEP-0384 §4.5 mandates `<to>` checking — a peer that sees an
/// envelope with the wrong `<to>` MUST drop it. (This blocks an
/// attacker who knows our session-derived key from re-routing a
/// captured ciphertext to a different recipient.)
fn parse_envelope_inbound(
    xml: &[u8],
    expected_to: &str,
) -> Result<InboundEnvelope, StoreFlowError> {
    let xml_str = std::str::from_utf8(xml).map_err(|_| StoreFlowError::EnvelopeNotUtf8)?;
    let env = SceEnvelope::parse(xml_str)?;
    if env.to != expected_to {
        return Err(StoreFlowError::WrongRecipient {
            expected: expected_to.to_owned(),
            got: env.to,
        });
    }
    let body = env.body_text()?.ok_or(StoreFlowError::BodyMissing)?;
    Ok(InboundEnvelope {
        body,
        from_jid: env.from,
        timestamp: env.timestamp,
    })
}

/// Load the session for `(peer_jid, peer_device_id)`, wrap `body_text`
/// in an SCE envelope (XEP-0420 — `<to>`/`<from>`/`<time>`/`<rpad>`),
/// encrypt for that single device (optionally wrapping the first
/// message in `OMEMOKeyExchange` via `kex`), and persist the advanced
/// session.
pub fn encrypt_to_peer(
    store: &mut Store,
    own_device_id: u32,
    peer_jid: &str,
    peer_device_id: u32,
    body_text: &str,
    kex: Option<KexCarrier>,
    priv_provider: Box<dyn DhPrivProvider>,
) -> Result<Encrypted, StoreFlowError> {
    refuse_if_untrusted(store, peer_jid, peer_device_id)?;
    let our_jid = store
        .get_identity()?
        .ok_or(StoreFlowError::IdentityMissing)?
        .bare_jid;
    let envelope_xml = build_envelope(body_text, &our_jid, peer_jid)?;

    let snapshot = store
        .load_session_snapshot(peer_jid, peer_device_id)?
        .ok_or_else(|| StoreFlowError::SessionMissing {
            jid: peer_jid.to_owned(),
            device_id: peer_device_id,
        })?;
    let mut session = TwomemoSession::from_snapshot(snapshot, priv_provider);
    let mut recipients = [Recipient {
        jid: peer_jid,
        device_id: peer_device_id,
        session: &mut session,
        kex,
    }];
    let encrypted = encrypt_message(own_device_id, &mut recipients, envelope_xml.as_bytes())?;
    store.save_session(peer_jid, peer_device_id, &session)?;
    Ok(encrypted)
}

/// One recipient device for a multi-recipient `encrypt_to_peers` call.
///
/// `kex` is `Some` only on the first message of a freshly bootstrapped
/// session for that device; the carrier wraps that key entry in
/// `OMEMOKeyExchange` so the peer can run X3DH passive. Subsequent
/// messages on the same session pass `None`.
pub struct PeerSpec<'a> {
    pub jid: &'a str,
    pub device_id: u32,
    pub kex: Option<KexCarrier>,
}

/// Encrypt `body_text` for *every* peer device in `peers`, sealing the
/// SCE envelope **once** and emitting one `<key rid=>` per device.
///
/// `envelope_to` is the address that lands in the envelope's `<to>`
/// element — for a 1:1 chat that's the peer's bare JID; for MUC group
/// chat it's the room's bare JID (XEP-0384 §6.1).
///
/// Each peer comes with its own `Box<dyn DhPrivProvider>` so per-device
/// ratchet steps can pull from independent priv sources (production:
/// OS RNG; tests: fixed queues).
///
/// Refuses any `Untrusted` peer device — the same gate as
/// [`encrypt_to_peer`].
#[allow(clippy::too_many_arguments)]
pub fn encrypt_to_peers(
    store: &mut Store,
    own_device_id: u32,
    envelope_to: &str,
    body_text: &str,
    peers: Vec<(PeerSpec<'_>, Box<dyn DhPrivProvider>)>,
) -> Result<Encrypted, StoreFlowError> {
    let our_jid = store
        .get_identity()?
        .ok_or(StoreFlowError::IdentityMissing)?
        .bare_jid;
    let envelope_xml = build_envelope(body_text, &our_jid, envelope_to)?;

    for (peer, _) in &peers {
        refuse_if_untrusted(store, peer.jid, peer.device_id)?;
    }

    // Load all sessions before borrowing them mutably for `Recipient`.
    let mut sessions: Vec<TwomemoSession> = Vec::with_capacity(peers.len());
    let mut peer_keys: Vec<(String, u32, Option<KexCarrier>)> = Vec::with_capacity(peers.len());
    for (peer, provider) in peers {
        let snap = store
            .load_session_snapshot(peer.jid, peer.device_id)?
            .ok_or_else(|| StoreFlowError::SessionMissing {
                jid: peer.jid.to_owned(),
                device_id: peer.device_id,
            })?;
        sessions.push(TwomemoSession::from_snapshot(snap, provider));
        peer_keys.push((peer.jid.to_owned(), peer.device_id, peer.kex));
    }

    let encrypted = {
        let mut recipients: Vec<Recipient> = peer_keys
            .iter()
            .zip(sessions.iter_mut())
            .map(|((jid, device_id, kex), s)| Recipient {
                jid: jid.as_str(),
                device_id: *device_id,
                session: s,
                kex: kex.clone(),
            })
            .collect();
        encrypt_message(own_device_id, &mut recipients, envelope_xml.as_bytes())?
    };

    // Persist the advanced sessions. Order doesn't matter — each
    // (jid, device_id) row is independent.
    for ((jid, device_id, _), sess) in peer_keys.iter().zip(sessions.iter()) {
        store.save_session(jid, *device_id, sess)?;
    }

    Ok(encrypted)
}

fn locate_our_key<'a>(
    encrypted: &'a Encrypted,
    our_jid: &str,
    our_device_id: u32,
) -> Result<&'a omemo_stanza::Key, StoreFlowError> {
    encrypted
        .keys
        .iter()
        .find(|g| g.jid == our_jid)
        .and_then(|g| g.keys.iter().find(|k| k.rid == our_device_id))
        .ok_or_else(|| StoreFlowError::OurKeyMissing {
            jid: our_jid.to_owned(),
            device_id: our_device_id,
        })
}

/// KEX-tagged inbound (`<key kex="true">`): peek the KEX to find which
/// SPK/OPK ids it references, look those up in the store, run X3DH
/// passive + ratchet decrypt + SCE open, parse and verify the
/// XEP-0420 envelope (`<to>` must match `expected_envelope_to`), then
/// atomically consume the OPK and persist the new session.
///
/// `expected_envelope_to` is what the envelope's `<to>` field has to
/// say. For a 1:1 chat that's our own bare JID; for a MUC group chat
/// it's the room's bare JID (XEP-0384 §6.1 + §4.5).
///
/// `policy` decides what to do on first sight of a peer device: TOFU
/// records it as `Trusted`, Manual records it as `Pending` and the
/// caller's UI is expected to prompt the user before accepting more
/// traffic. Either way, an explicitly `Untrusted` device is refused.
/// If the peer's IK in the KEX disagrees with a previously-recorded
/// IK for the same `(jid, device_id)`, the call fails with
/// [`StoreFlowError::IkMismatch`] — the OPK is *not* consumed and the
/// session is *not* saved.
#[allow(clippy::too_many_arguments)]
pub fn receive_first_message(
    store: &mut Store,
    encrypted: &Encrypted,
    our_jid: &str,
    our_device_id: u32,
    expected_envelope_to: &str,
    sender_jid: &str,
    sender_device_id: u32,
    policy: TrustPolicy,
    priv_provider: Box<dyn DhPrivProvider>,
) -> Result<InboundEnvelope, StoreFlowError> {
    let key = locate_our_key(encrypted, our_jid, our_device_id)?;
    if !key.kex {
        return Err(StoreFlowError::FollowExpected);
    }
    let (pk_id, spk_id, peer_ik_ed, _peer_ek, _auth_bytes) = parse_key_exchange(&key.data)?;

    // Trust gate happens *before* OPK consumption, so a rejected KEX
    // does not burn a one-time prekey.
    let trust = store.record_first_seen(
        sender_jid,
        sender_device_id,
        &peer_ik_ed,
        policy.default_state(),
    )?;
    if trust.state == TrustState::Untrusted {
        return Err(StoreFlowError::PeerUntrusted {
            jid: sender_jid.to_owned(),
            device_id: sender_device_id,
        });
    }
    if trust.ik_pub != peer_ik_ed {
        return Err(StoreFlowError::IkMismatch {
            jid: sender_jid.to_owned(),
            device_id: sender_device_id,
            stored_hex: hex32(&trust.ik_pub),
            got_hex: hex32(&peer_ik_ed),
        });
    }

    let spk_pub = store
        .get_spk(spk_id)?
        .ok_or(StoreFlowError::Message(MessageError::SpkIdNotFound(spk_id)))?
        .pub_key;
    let opk_pub = store
        .get_opk(pk_id)?
        .ok_or(StoreFlowError::Message(MessageError::OpkIdNotFound(pk_id)))?
        .pub_key;

    let state = x3dh_state_from_store(store)?;
    let (session, envelope_bytes, consumed_opk_id) = decrypt_inbound_kex(
        encrypted,
        our_jid,
        our_device_id,
        &state,
        |id| (id == spk_id).then_some(spk_pub),
        |id| (id == pk_id).then_some(opk_pub),
        priv_provider,
    )?;

    let envelope = parse_envelope_inbound(&envelope_bytes, expected_envelope_to)?;
    store.commit_first_inbound(sender_jid, sender_device_id, consumed_opk_id, &session)?;
    Ok(envelope)
}

/// Non-KEX inbound (`<key kex="false">`): load the session for
/// `(sender_jid, sender_device_id)`, decrypt the SCE payload, parse
/// and verify the XEP-0420 envelope (`<to>` must match
/// `expected_envelope_to`), persist the advanced session.
///
/// Refuses `(jid, device_id)` rows in `Untrusted` state. Pending and
/// never-seen devices are allowed (KEX inbound is the only path that
/// could record a new device, since it is the only path that carries
/// the peer's IK on the wire).
#[allow(clippy::too_many_arguments)]
pub fn receive_followup(
    store: &mut Store,
    encrypted: &Encrypted,
    our_jid: &str,
    our_device_id: u32,
    expected_envelope_to: &str,
    sender_jid: &str,
    sender_device_id: u32,
    priv_provider: Box<dyn DhPrivProvider>,
) -> Result<InboundEnvelope, StoreFlowError> {
    let key = locate_our_key(encrypted, our_jid, our_device_id)?;
    if key.kex {
        return Err(StoreFlowError::KexExpected);
    }
    refuse_if_untrusted(store, sender_jid, sender_device_id)?;
    let snapshot = store
        .load_session_snapshot(sender_jid, sender_device_id)?
        .ok_or(StoreFlowError::SessionMissing {
            jid: sender_jid.to_owned(),
            device_id: sender_device_id,
        })?;
    let mut session = TwomemoSession::from_snapshot(snapshot, priv_provider);
    let envelope_bytes = decrypt_message(encrypted, our_jid, our_device_id, &mut session)?;
    let envelope = parse_envelope_inbound(&envelope_bytes, expected_envelope_to)?;
    store.save_session(sender_jid, sender_device_id, &session)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use omemo_session::Store;
    use omemo_twomemo::fixed_priv_provider;

    fn fresh_store() -> Store {
        Store::open_in_memory().expect("in-memory store")
    }

    fn alice_seed() -> IdentitySeed<'static> {
        const ALICE_OPKS: &[(u32, [u8; 32])] = &[(101, [0xA4; 32]), (102, [0xA5; 32])];
        IdentitySeed {
            bare_jid: "alice@example.org",
            device_id: 1001,
            ik_seed: [0xA1; 32],
            spk_id: 1,
            spk_priv: [0xA2; 32],
            spk_sig_nonce: [0xA3; 64],
            opks: ALICE_OPKS,
        }
    }

    fn bob_seed() -> IdentitySeed<'static> {
        const BOB_OPKS: &[(u32, [u8; 32])] = &[(201, [0xB4; 32])];
        IdentitySeed {
            bare_jid: "bob@example.org",
            device_id: 2001,
            ik_seed: [0xB1; 32],
            spk_id: 1,
            spk_priv: [0xB2; 32],
            spk_sig_nonce: [0xB3; 64],
            opks: BOB_OPKS,
        }
    }

    #[test]
    fn install_then_read_back_state_and_bundle() {
        let mut store = fresh_store();
        install_identity(&mut store, &alice_seed()).expect("install");

        let state = x3dh_state_from_store(&store).expect("state");
        assert_eq!(state.pre_keys.len(), 2);

        let bundle = bundle_from_store(&store).expect("bundle");
        assert_eq!(bundle.spk.id, 1);
        assert_eq!(bundle.prekeys.len(), 2);
        assert_eq!(bundle.spk.pub_key.len(), 32);
        assert_eq!(bundle.ik.len(), 32);
        assert_eq!(bundle.spks.len(), 64);
    }

    #[test]
    fn bootstrap_active_persists_session() {
        let mut alice = fresh_store();
        install_identity(&mut alice, &alice_seed()).unwrap();
        let mut bob = fresh_store();
        install_identity(&mut bob, &bob_seed()).unwrap();

        let bob_bundle = bundle_from_store(&bob).unwrap();
        let kex = bootstrap_and_save_active(
            &mut alice,
            "bob@example.org",
            2001,
            &bob_bundle,
            201,
            [0x42; 32],
            fixed_priv_provider((1..=4).map(|i| [(0x50 + i) as u8; 32]).collect()),
        )
        .expect("bootstrap");
        assert_eq!(kex.pk_id, 201);
        assert_eq!(kex.spk_id, 1);

        // Session should now be loadable from the store.
        let snap = alice
            .load_session_snapshot("bob@example.org", 2001)
            .unwrap();
        assert!(snap.is_some(), "session persisted");
    }

    #[test]
    fn alice_to_bob_first_then_followup_through_stores() {
        let mut alice = fresh_store();
        install_identity(&mut alice, &alice_seed()).unwrap();
        let mut bob = fresh_store();
        install_identity(&mut bob, &bob_seed()).unwrap();

        let bob_bundle = bundle_from_store(&bob).unwrap();
        let kex = bootstrap_and_save_active(
            &mut alice,
            "bob@example.org",
            2001,
            &bob_bundle,
            201,
            [0x42; 32],
            fixed_priv_provider((1..=8).map(|i| [(0x50 + i) as u8; 32]).collect()),
        )
        .unwrap();

        // Message #1: KEX
        let m1 = encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "hello bob",
            Some(kex),
            fixed_priv_provider(vec![]), // session already persisted; reload uses fresh provider
        )
        .expect("encrypt #1");
        let recovered_1 = receive_first_message(
            &mut bob,
            &m1,
            "bob@example.org",
            2001,
            "bob@example.org",
            "alice@example.org",
            1001,
            TrustPolicy::Tofu,
            fixed_priv_provider((1..=8).map(|i| [(0x70 + i) as u8; 32]).collect()),
        )
        .expect("bob receive #1");
        assert_eq!(recovered_1.body, "hello bob");
        assert_eq!(recovered_1.from_jid, "alice@example.org");

        // Bob's OPK 201 must now be marked consumed.
        let opk = bob.get_opk(201).unwrap().unwrap();
        assert!(opk.consumed, "opk consumed after first inbound");

        // Alice's device should be recorded as Trusted under Tofu.
        let trust = bob
            .trusted_device("alice@example.org", 1001)
            .unwrap()
            .unwrap();
        assert_eq!(trust.state, TrustState::Trusted);

        // Message #2: Follow
        let m2 = encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "second",
            None,
            fixed_priv_provider(vec![]),
        )
        .expect("encrypt #2");
        let recovered_2 = receive_followup(
            &mut bob,
            &m2,
            "bob@example.org",
            2001,
            "bob@example.org",
            "alice@example.org",
            1001,
            fixed_priv_provider(vec![]),
        )
        .expect("bob receive #2");
        assert_eq!(recovered_2.body, "second");
    }

    #[test]
    fn manual_policy_records_pending_then_set_trust_lets_followup_through() {
        let mut alice = fresh_store();
        install_identity(&mut alice, &alice_seed()).unwrap();
        let mut bob = fresh_store();
        install_identity(&mut bob, &bob_seed()).unwrap();

        let bob_bundle = bundle_from_store(&bob).unwrap();
        let kex = bootstrap_and_save_active(
            &mut alice,
            "bob@example.org",
            2001,
            &bob_bundle,
            201,
            [0x42; 32],
            fixed_priv_provider((1..=8).map(|i| [(0x50 + i) as u8; 32]).collect()),
        )
        .unwrap();

        let m1 = encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "hi under manual policy",
            Some(kex),
            fixed_priv_provider(vec![]),
        )
        .unwrap();
        let recovered = receive_first_message(
            &mut bob,
            &m1,
            "bob@example.org",
            2001,
            "bob@example.org",
            "alice@example.org",
            1001,
            TrustPolicy::Manual,
            fixed_priv_provider((1..=8).map(|i| [(0x70 + i) as u8; 32]).collect()),
        )
        .expect("manual: receive_first_message still decrypts");
        assert_eq!(recovered.body, "hi under manual policy");
        let trust = bob
            .trusted_device("alice@example.org", 1001)
            .unwrap()
            .unwrap();
        assert_eq!(
            trust.state,
            TrustState::Pending,
            "manual policy records new device as Pending"
        );

        // User explicitly approves; follow-ups now succeed.
        bob.set_trust("alice@example.org", 1001, TrustState::Trusted)
            .unwrap();
        let m2 = encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "follow-up",
            None,
            fixed_priv_provider(vec![]),
        )
        .unwrap();
        let recovered_2 = receive_followup(
            &mut bob,
            &m2,
            "bob@example.org",
            2001,
            "bob@example.org",
            "alice@example.org",
            1001,
            fixed_priv_provider(vec![]),
        )
        .unwrap();
        assert_eq!(recovered_2.body, "follow-up");
    }

    #[test]
    fn untrusted_device_blocks_outbound_and_followup_inbound() {
        let mut alice = fresh_store();
        install_identity(&mut alice, &alice_seed()).unwrap();
        let mut bob = fresh_store();
        install_identity(&mut bob, &bob_seed()).unwrap();

        let bob_bundle = bundle_from_store(&bob).unwrap();
        let kex = bootstrap_and_save_active(
            &mut alice,
            "bob@example.org",
            2001,
            &bob_bundle,
            201,
            [0x42; 32],
            fixed_priv_provider((1..=8).map(|i| [(0x50 + i) as u8; 32]).collect()),
        )
        .unwrap();
        let m1 = encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "hello",
            Some(kex),
            fixed_priv_provider(vec![]),
        )
        .unwrap();
        receive_first_message(
            &mut bob,
            &m1,
            "bob@example.org",
            2001,
            "bob@example.org",
            "alice@example.org",
            1001,
            TrustPolicy::Tofu,
            fixed_priv_provider((1..=8).map(|i| [(0x70 + i) as u8; 32]).collect()),
        )
        .unwrap();

        // Bob now decides alice's device is Untrusted.
        bob.set_trust("alice@example.org", 1001, TrustState::Untrusted)
            .unwrap();

        // Alice is unaware; she sends a follow-up. Bob's receive_followup
        // refuses.
        let m2 = encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "follow-up",
            None,
            fixed_priv_provider(vec![]),
        )
        .unwrap();
        match receive_followup(
            &mut bob,
            &m2,
            "bob@example.org",
            2001,
            "bob@example.org",
            "alice@example.org",
            1001,
            fixed_priv_provider(vec![]),
        ) {
            Err(StoreFlowError::PeerUntrusted { jid, device_id }) => {
                assert_eq!(jid, "alice@example.org");
                assert_eq!(device_id, 1001);
            }
            other => panic!("expected PeerUntrusted, got {other:?}"),
        }

        // Symmetrically, if alice marks bob's device Untrusted in *her*
        // store, her encrypt_to_peer refuses. Alice has bob's IK
        // available from his bundle, which she records before changing
        // the state — set_trust is UPDATE-only.
        let bob_ik_pub = bundle_from_store(&bob).unwrap().ik;
        let mut bob_ik_arr = [0u8; 32];
        bob_ik_arr.copy_from_slice(&bob_ik_pub);
        alice
            .record_first_seen("bob@example.org", 2001, &bob_ik_arr, TrustState::Trusted)
            .unwrap();
        alice
            .set_trust("bob@example.org", 2001, TrustState::Untrusted)
            .unwrap();
        match encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "another",
            None,
            fixed_priv_provider(vec![]),
        ) {
            Err(StoreFlowError::PeerUntrusted { jid, device_id }) => {
                assert_eq!(jid, "bob@example.org");
                assert_eq!(device_id, 2001);
            }
            other => panic!("expected PeerUntrusted, got {other:?}"),
        }
    }

    #[test]
    fn ik_drift_rejects_kex_without_consuming_opk() {
        let mut alice = fresh_store();
        install_identity(&mut alice, &alice_seed()).unwrap();
        let mut bob = fresh_store();
        install_identity(&mut bob, &bob_seed()).unwrap();

        // Plant a *different* IK for alice in bob's trust store first.
        bob.record_first_seen("alice@example.org", 1001, &[0xFF; 32], TrustState::Trusted)
            .unwrap();

        let bob_bundle = bundle_from_store(&bob).unwrap();
        let kex = bootstrap_and_save_active(
            &mut alice,
            "bob@example.org",
            2001,
            &bob_bundle,
            201,
            [0x42; 32],
            fixed_priv_provider((1..=8).map(|i| [(0x50 + i) as u8; 32]).collect()),
        )
        .unwrap();
        let m1 = encrypt_to_peer(
            &mut alice,
            1001,
            "bob@example.org",
            2001,
            "hi",
            Some(kex),
            fixed_priv_provider(vec![]),
        )
        .unwrap();
        match receive_first_message(
            &mut bob,
            &m1,
            "bob@example.org",
            2001,
            "bob@example.org",
            "alice@example.org",
            1001,
            TrustPolicy::Tofu,
            fixed_priv_provider((1..=8).map(|i| [(0x70 + i) as u8; 32]).collect()),
        ) {
            Err(StoreFlowError::IkMismatch { jid, device_id, .. }) => {
                assert_eq!(jid, "alice@example.org");
                assert_eq!(device_id, 1001);
            }
            other => panic!("expected IkMismatch, got {other:?}"),
        }

        // OPK 201 must NOT have been consumed — IK check fires before
        // commit_first_inbound.
        let opk = bob.get_opk(201).unwrap().unwrap();
        assert!(!opk.consumed, "IK-mismatch must not burn the OPK");
    }

    #[test]
    fn replenish_opks_tops_up_to_target_and_skips_when_already_above() {
        use rand_core::OsRng;

        let mut store = fresh_store();
        install_identity(&mut store, &alice_seed()).unwrap();
        // alice_seed installs 2 OPKs.
        assert_eq!(store.count_unconsumed_opks().unwrap(), 2);
        assert_eq!(store.next_opk_id().unwrap(), 103, "next id is max(102) + 1");

        // Refill to 5 — should add exactly 3.
        let added = replenish_opks(&mut store, 5, &mut OsRng).unwrap();
        assert_eq!(added, 3);
        assert_eq!(store.count_unconsumed_opks().unwrap(), 5);
        assert_eq!(store.next_opk_id().unwrap(), 106);

        // Refill again with the same target — should add 0.
        let added = replenish_opks(&mut store, 5, &mut OsRng).unwrap();
        assert_eq!(added, 0);

        // Consume one, refill to 5 — should add 1, and next_opk_id keeps
        // climbing (consumed rows count toward MAX(id), so a new id is
        // not reused).
        store.consume_opk(101).unwrap();
        assert_eq!(store.count_unconsumed_opks().unwrap(), 4);
        let added = replenish_opks(&mut store, 5, &mut OsRng).unwrap();
        assert_eq!(added, 1);
        assert_eq!(store.count_unconsumed_opks().unwrap(), 5);
        assert_eq!(store.next_opk_id().unwrap(), 107);

        // The replenished OPKs round-trip into the bundle that
        // `bundle_from_store` produces, so a subsequent
        // `publish_my_bundle` exposes them on PEP.
        let bundle = bundle_from_store(&store).unwrap();
        assert_eq!(bundle.prekeys.len(), 5);
    }
}
