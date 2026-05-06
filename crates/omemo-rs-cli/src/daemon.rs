//! Long-running JSON Lines stdio daemon.
//!
//! An orchestrator (nan-curunir, an LLM bot, anything that wants to
//! drive an OMEMO-encrypted XMPP session as a child process) spawns
//! `omemo-rs-cli daemon` and communicates with it line-by-line:
//!
//! * **stdin** — one JSON object per line, each a [`Command`].
//! * **stdout** — one JSON object per line, each an [`Event`].
//!   Events are line-buffered and flushed on every emit.
//! * **stderr** — `tracing` structured logs (filtered by
//!   `RUST_LOG`). Not part of the protocol; the orchestrator can
//!   log it for diagnostics.
//!
//! ## Lifecycle
//!
//!     stdin                              stdout
//!     ─────                              ──────
//!                                        {"event":"connecting", ...}
//!                                        {"event":"ready", "jid":"...", "device_id": ...}
//!     {"op":"send","peer":"bob@x", ...}  →
//!                                        {"event":"sent","id":"...","peer":"bob@x"}
//!                                        {"event":"message","from":"bob@x", ...}
//!     {"op":"shutdown"}                  →
//!                                        {"event":"goodbye"}
//!
//! Closing stdin (EOF) is equivalent to `{"op":"shutdown"}`.
//!
//! ## Phase 1 limitations (these go away in later phases)
//!
//! * **1:1 only** — MUC commands (`join_muc`, `send_muc`) are
//!   accepted but currently emit `error` events. Phase 2.
//! * **Sessions must already exist for fast-path send** — to
//!   bootstrap a brand new peer session, the orchestrator must
//!   issue `{"op":"bootstrap","peer":"...","device":N}` first.
//!   That command DOES drive a PEP bundle fetch which (per the
//!   tokio-xmpp single-consumer stream model) briefly blocks
//!   inbound stanza dispatch — a few inbound messages from other
//!   peers may be delayed for the duration of the fetch but are
//!   not lost (the underlying TCP buffer holds them).
//!
//! Stream Management resumption (XEP-0198) for transparent
//! reconnect on network blips is Phase 3 (production polish).

use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Daemon-wide start instant — set once on `Event::Ready`,
/// read by `Command::Status` to compute uptime. OnceLock so
/// the value is available from anywhere in the file without
/// threading it through every handler signature.
static STARTED_AT: OnceLock<Instant> = OnceLock::new();

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use omemo_doubleratchet::dh_ratchet::DhPrivProvider;
use omemo_pep::{
    bootstrap_and_save_active, bootstrap_and_save_active_oldmemo, encrypt_to_peer,
    encrypt_to_peer_oldmemo, encrypt_to_peers, fetch_bundle, fetch_device_list, fetch_old_bundle,
    fetch_old_device_list, inbound_kind, inbound_kind_oldmemo, install_identity_random,
    parse_encrypted_message, publish_device_list, publish_my_bundle, publish_old_bundle,
    publish_old_device_list, receive_first_message, receive_first_message_oldmemo,
    receive_followup, receive_followup_oldmemo, replenish_opks, send_encrypted,
    send_encrypted_old, BareJid, Client, Device, DeviceList, EncryptedAny, Event as XmppEvent,
    InboundKind, InboundOldKind, MucRoom, OldDeviceList, PeerSpec, Stanza, Store, TrustPolicy,
};
use std::collections::HashMap;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const REPLENISH_TARGET: u32 = 100;

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

/// Inbound JSON command from stdin.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Command {
    /// Encrypt and send a UTF-8 chat body to a peer.
    ///
    /// `device` semantics:
    ///   * `Some(N)` → encrypt for device id N specifically. If
    ///     no session exists yet for `(peer, N)` the daemon
    ///     implicitly bootstraps via `fetch_bundle` + X3DH active
    ///     and attaches the resulting `KexCarrier` so the
    ///     receiver can run X3DH passive.
    ///   * `None` → multi-device fan-out: encrypt for **every**
    ///     device id we already have a session with for this
    ///     peer (XEP-0384 §4.6). If we have zero sessions yet,
    ///     fall back to `fetch_device_list` + bootstrap each
    ///     advertised device. The single emitted `<encrypted>`
    ///     stanza carries one `<key rid=N>` per device, so all
    ///     of alice's phones / laptops decrypt the same body.
    Send {
        /// Bare JID of the recipient.
        peer: String,
        /// Recipient device id. `None` (omitted on the wire) =
        /// fan out across all sessions.
        #[serde(default)]
        device: Option<u32>,
        /// Wire-format backend. Default `twomemo`.
        #[serde(default)]
        backend: BackendArg,
        /// Plaintext body (UTF-8). The daemon wraps this in an
        /// XEP-0420 SCE envelope for OMEMO 2 / hands raw bytes to
        /// the AEAD for OMEMO 0.3 — caller doesn't have to know.
        body: String,
        /// Optional opaque request id; echoed in the matching
        /// `sent` / `error` event so the orchestrator can correlate.
        #[serde(default)]
        id: Option<String>,
    },
    /// Join a MUC room as `nick`. The daemon sends presence,
    /// fetches each occupant's OMEMO devicelist (so subsequent
    /// `send_muc` knows which devices to encrypt for), and emits
    /// `muc_joined` with the resolved occupant→devices map.
    /// Currently OMEMO 2 only — Converse.js compatibility for
    /// OMEMO 0.3 MUC fan-out is on the v3 list.
    JoinMuc {
        /// `room@conference.localhost`-style bare JID of the room.
        room: String,
        /// Our nickname inside the room.
        nick: String,
        #[serde(default)]
        id: Option<String>,
    },
    /// Send an OMEMO-encrypted groupchat message to a previously
    /// `join_muc`-ed room. Encrypts once and fans out per device
    /// across every occupant's known devicelist.
    SendMuc {
        room: String,
        body: String,
        #[serde(default)]
        id: Option<String>,
    },
    /// Re-fetch every occupant's devicelist for a room (e.g. after
    /// you've seen new occupants join). The MVP `join_muc` only
    /// snapshots once at join time.
    RefreshMuc {
        room: String,
        #[serde(default)]
        id: Option<String>,
    },
    /// Leave a MUC room.
    LeaveMuc {
        room: String,
        #[serde(default)]
        id: Option<String>,
    },
    /// Discover a peer's device list. Emits `device_list` event
    /// listing every device id the peer currently advertises on
    /// PEP. Useful for the orchestrator to know which devices to
    /// `bootstrap` against.
    Discover {
        peer: String,
        #[serde(default)]
        backend: BackendArg,
        #[serde(default)]
        id: Option<String>,
    },
    /// Get a one-shot status snapshot. Currently mostly just for
    /// liveness checking — emits a `status` event with the local
    /// JID, device id, and how many active sessions are stored.
    Status {
        #[serde(default)]
        id: Option<String>,
    },
    /// Set the trust state for a (peer, device). The
    /// orchestrator drives this in response to a `pending_trust`
    /// event (Manual policy) or any application-level "block
    /// this device" decision.
    SetTrust {
        peer: String,
        device: u32,
        state: TrustStateArg,
        #[serde(default)]
        id: Option<String>,
    },
    /// Force-replace the recorded IK for a device after an
    /// `ik_drift` event. The orchestrator must have verified
    /// the new fingerprint out-of-band. `new_ik_hex` is the
    /// 64-char hex of the new 32-byte Ed25519 IK pub — usually
    /// echoed from the drift event's `observed_fingerprint`
    /// field. The trust state goes back to `Trusted` (or the
    /// supplied `state`, if specified).
    ForceRetrust {
        peer: String,
        device: u32,
        new_ik_hex: String,
        #[serde(default = "default_trusted")]
        state: TrustStateArg,
        #[serde(default)]
        id: Option<String>,
    },
    /// Enumerate every device currently in Pending state — the
    /// queue an admin works through under Manual policy. Reply
    /// via `pending_trusts` event.
    ListPending {
        #[serde(default)]
        id: Option<String>,
    },
    /// Graceful shutdown: send `</stream:stream>`, drain pending
    /// events, exit. Closing stdin (EOF) has the same effect.
    Shutdown,
}

fn default_trusted() -> TrustStateArg {
    TrustStateArg::Trusted
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustStateArg {
    Pending,
    Trusted,
    Untrusted,
}

impl TrustStateArg {
    fn as_state(self) -> omemo_pep::TrustState {
        match self {
            TrustStateArg::Pending => omemo_pep::TrustState::Pending,
            TrustStateArg::Trusted => omemo_pep::TrustState::Trusted,
            TrustStateArg::Untrusted => omemo_pep::TrustState::Untrusted,
        }
    }
    #[allow(dead_code)] // wired when --trust-policy manual lands
    fn from_state(s: omemo_pep::TrustState) -> Self {
        match s {
            omemo_pep::TrustState::Pending => TrustStateArg::Pending,
            omemo_pep::TrustState::Trusted => TrustStateArg::Trusted,
            omemo_pep::TrustState::Untrusted => TrustStateArg::Untrusted,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendArg {
    /// OMEMO 2 (`urn:xmpp:omemo:2`). Default.
    #[default]
    Twomemo,
    /// OMEMO 0.3 (`eu.siacs.conversations.axolotl`).
    Oldmemo,
}

/// One occupant + their OMEMO 2 devicelist as known to the daemon
/// at this point in time. Embedded in `muc_joined` /
/// `muc_refreshed` events.
#[derive(Debug, Clone, Serialize)]
pub struct MucOccupantInfo {
    /// Real bare JID (NOT the in-room nickname) — required for
    /// OMEMO since encryption keys are bound to the user's identity.
    pub real_jid: String,
    /// In-room nickname.
    pub nick: String,
    /// OMEMO 2 device ids advertised on the occupant's PEP node.
    pub devices: Vec<u32>,
}

/// Outbound JSON event emitted on stdout.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Daemon has parsed args and started the connection attempt.
    Connecting { jid: String },
    /// Login + identity publish succeeded; daemon is now ready for
    /// commands. The orchestrator should wait for this before
    /// sending its first command.
    Ready { jid: String, device_id: u32 },
    /// An OMEMO message was successfully encrypted and sent to a
    /// peer. The `id` echoes the request id from the matching
    /// `send` command (if any).
    Sent {
        peer: String,
        device: u32,
        backend: BackendArg,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// An incoming OMEMO message was decrypted successfully.
    Message {
        from: String,
        device: u32,
        backend: BackendArg,
        body: String,
        /// ISO-8601 server timestamp from the SCE `<time>` envelope
        /// (OMEMO 2 only — empty for OMEMO 0.3 which has no
        /// envelope wrapping).
        #[serde(skip_serializing_if = "String::is_empty")]
        timestamp: String,
    },
    /// `join_muc` succeeded. `occupants` is the resolved
    /// `(real_jid, device_id)` list the daemon will encrypt to
    /// on subsequent `send_muc` (modulo new joins reflected via
    /// `muc_occupant_joined`).
    MucJoined {
        room: String,
        occupants: Vec<MucOccupantInfo>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// A new occupant entered the room. The daemon has refreshed
    /// their devicelist (best-effort) and will include them on
    /// subsequent `send_muc`.
    MucOccupantJoined {
        room: String,
        nick: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        real_jid: Option<String>,
    },
    /// An occupant left the room.
    MucOccupantLeft { room: String, nick: String },
    /// An OMEMO-encrypted groupchat message was decrypted.
    MucMessage {
        room: String,
        from_real_jid: String,
        from_nick: String,
        device: u32,
        backend: BackendArg,
        body: String,
    },
    /// `leave_muc` completed.
    MucLeft {
        room: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// `refresh_muc` completed.
    MucRefreshed {
        room: String,
        occupants: Vec<MucOccupantInfo>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Result of a `discover` command.
    DeviceList {
        peer: String,
        backend: BackendArg,
        devices: Vec<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Result of a `status` command. Beefed up in v3 with
    /// fields useful for orchestrator health probes.
    Status {
        jid: String,
        device_id: u32,
        /// Total session rows by backend.
        twomemo_sessions: u64,
        oldmemo_sessions: u64,
        /// Number of unconsumed OPKs in the local pool. The
        /// daemon's bundle-health timer auto-refills below
        /// `OPK_REFILL_THRESHOLD` (50), but this lets the
        /// orchestrator alert proactively if e.g. it's been
        /// 0 for several status calls.
        opk_pool_size: u32,
        /// Number of MUC rooms the daemon is currently joined
        /// in (`join_muc` issued, no `leave_muc`).
        joined_muc_count: usize,
        /// Daemon process uptime in seconds since `Ready`.
        uptime_secs: u64,
        /// Coarse connection state. Today the daemon is in the
        /// `main_loop` for the entire lifetime between Ready
        /// and Goodbye, so this is always `"online"` whenever
        /// a Status event fires; future `--reconnect` work
        /// (XEP-0198 stream resumption) will populate the
        /// `"reconnecting"` variant too.
        connection_state: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// A command failed. `id` echoes the request id of the failing
    /// command (when one was provided).
    Error {
        kind: String,
        detail: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// A peer device's identity key changed. Decryption of the
    /// inbound message that triggered this event was aborted
    /// (the OPK was NOT consumed; the session was NOT updated).
    /// Orchestrator must verify the new fingerprint out-of-band
    /// and either issue `force_retrust` to accept the new key
    /// or `set_trust` with `Untrusted` to permanently refuse.
    IkDrift {
        peer: String,
        device: u32,
        /// 64-char hex of the IK pub we previously recorded
        /// for this device.
        stored_fingerprint: String,
        /// 64-char hex of the IK pub the inbound `<key kex>`
        /// claims now. Echo this back as `new_ik_hex` in
        /// `force_retrust` to accept.
        observed_fingerprint: String,
    },
    /// First-sight of a peer device under Manual trust policy.
    /// The new device is recorded as `Pending`; subsequent
    /// inbound from it is decrypted normally (the consume-once
    /// OPK was already burned by the bootstrap KEX) but the
    /// orchestrator should prompt an operator to accept or
    /// reject before this device is allowed to receive
    /// outbound traffic from us.
    PendingTrust {
        peer: String,
        device: u32,
        ik_fingerprint: String,
    },
    /// Ack of a `set_trust` command.
    TrustSet {
        peer: String,
        device: u32,
        state: TrustStateArg,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Ack of a `force_retrust` command.
    Retrusted {
        peer: String,
        device: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Result of a `list_pending` query.
    PendingTrusts {
        entries: Vec<PendingTrustEntry>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// XMPP stream ended (server side closed, network error, etc.).
    /// The daemon will exit shortly after this.
    Disconnected { reason: String },
    /// Final event before exit. Always emitted last.
    Goodbye,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingTrustEntry {
    pub peer: String,
    pub device: u32,
    pub ik_fingerprint: String,
    /// Unix epoch seconds.
    pub first_seen_at: i64,
}

// ---------------------------------------------------------------------------
// Daemon entry point
// ---------------------------------------------------------------------------

/// Configuration carved out of the top-level CLI args. Keeping
/// daemon-specific knobs in one struct so the function signature
/// stays manageable.
pub struct DaemonConfig {
    pub bare_jid: BareJid,
    pub password: String,
    pub store_path: std::path::PathBuf,
    pub insecure_tcp: Option<String>,
    pub starttls_addr: Option<String>,
    pub device_id_hint: Option<u32>,
    pub opk_count: u32,
}

pub async fn run(cfg: DaemonConfig) -> Result<()> {
    // stderr-side structured logging. Stdout is reserved for the
    // JSON event stream — DO NOT add a stdout-bound subscriber.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    emit(&Event::Connecting {
        jid: cfg.bare_jid.to_string(),
    })
    .await?;

    let mut store = open_store(&cfg.store_path)?;
    let device_id =
        ensure_local_identity(&cfg.bare_jid, &mut store, cfg.device_id_hint, cfg.opk_count)?;

    let mut client = connect(&cfg).await;
    await_online(&mut client).await?;
    announce_presence(&mut client).await?;
    publish_identity(&mut client, &store, device_id).await?;

    let _ = STARTED_AT.set(Instant::now());
    emit(&Event::Ready {
        jid: cfg.bare_jid.to_string(),
        device_id,
    })
    .await?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
    tokio::spawn(stdin_reader(cmd_tx.clone()));

    // Signal-driven shutdown — orchestrators send SIGTERM (kill,
    // systemd, container stop) to terminate cleanly; an
    // interactive shell sends SIGINT (Ctrl-C). Both translate
    // into the same `Command::Shutdown` the JSON Lines protocol
    // already handles, so the cleanup path stays singular.
    #[cfg(unix)]
    tokio::spawn(signal_listener(cmd_tx));
    #[cfg(not(unix))]
    {
        let _ = cmd_tx; // Windows path: stdin EOF is the only shutdown trigger.
    }

    let mut rooms: HashMap<BareJid, MucRoom> = HashMap::new();
    let mut occupants_cache: HashMap<BareJid, Vec<(BareJid, Vec<u32>)>> = HashMap::new();
    let exit_reason = main_loop(
        &cfg.bare_jid,
        &mut client,
        &mut store,
        device_id,
        cmd_rx,
        &mut rooms,
        &mut occupants_cache,
    )
    .await;

    // Try to close cleanly. send_end is best-effort.
    let _ = client.send_end().await;

    match exit_reason {
        ExitReason::Shutdown => {}
        ExitReason::StdinClosed => {}
        ExitReason::StreamEnded => {
            emit(&Event::Disconnected {
                reason: "xmpp stream ended".into(),
            })
            .await?;
        }
        ExitReason::Error(e) => {
            emit(&Event::Disconnected {
                reason: e.to_string(),
            })
            .await?;
        }
    }
    emit(&Event::Goodbye).await?;
    Ok(())
}

#[derive(Debug)]
enum ExitReason {
    Shutdown,
    StdinClosed,
    StreamEnded,
    #[allow(dead_code)]
    Error(anyhow::Error),
}

// ---------------------------------------------------------------------------
// Main event loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
/// How often the daemon checks bundle health. Cheap — counts
/// rows in the OPKs table, no network unless something needs
/// fixing. Production deployments can sit at 60s; under load
/// (lots of incoming KEXes) this might tick more often
/// reactively too.
const BUNDLE_HEALTH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Threshold below which the daemon proactively replenishes the
/// OPK pool. XEP-0384 §5.3.2 says ≥ 100 is normal; we trigger
/// refill at the half-life so a noisy bot can't deplete the
/// pool faster than the timer ticks.
const OPK_REFILL_THRESHOLD: u32 = 50;

async fn main_loop(
    own_jid: &BareJid,
    client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
    mut cmd_rx: mpsc::Receiver<Command>,
    rooms: &mut HashMap<BareJid, MucRoom>,
    occupants_cache: &mut HashMap<BareJid, Vec<(BareJid, Vec<u32>)>>,
) -> ExitReason {
    let mut bundle_health = tokio::time::interval(BUNDLE_HEALTH_INTERVAL);
    // The first tick fires immediately; we don't need a check
    // right after spawn because identity-publish already wrote
    // a fresh bundle.
    bundle_health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let _ = bundle_health.tick().await;

    loop {
        tokio::select! {
            _ = bundle_health.tick() => {
                if let Err(e) = check_bundle_health(client, store, own_device_id).await {
                    let _ = emit(&Event::Error {
                        kind: "bundle_health".into(),
                        detail: e.to_string(),
                        id: None,
                    }).await;
                }
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(Command::Shutdown) => return ExitReason::Shutdown,
                Some(cmd) => {
                    if let Err(e) = handle_command(own_jid, client, store, own_device_id, rooms, occupants_cache, cmd).await {
                        let _ = emit(&Event::Error {
                            kind: "command".into(),
                            detail: e.to_string(),
                            id: None,
                        }).await;
                    }
                }
                None => return ExitReason::StdinClosed,
            },
            event = client.next() => match event {
                Some(XmppEvent::Stanza(Stanza::Presence(presence))) => {
                    handle_presence(rooms, &presence).await;
                }
                Some(XmppEvent::Stanza(Stanza::Message(msg))) => {
                    // Inspect the *already-popped* `<message>` for an
                    // `<encrypted>` payload (OMEMO 2 or 0.3). If it
                    // doesn't carry one, drop. We must NOT call
                    // wait_for_encrypted_any here — that would loop
                    // back into client.next() and miss the message
                    // we just took off the queue.
                    let is_groupchat = matches!(msg.type_, xmpp_parsers::message::MessageType::Groupchat);
                    let parsed = match parse_encrypted_message(&msg) {
                        Ok(p) => p,
                        Err(e) => {
                            let _ = emit(&Event::Error {
                                kind: "parse".into(),
                                detail: format!("parse_encrypted_message: {e}"),
                                id: None,
                            }).await;
                            continue;
                        }
                    };
                    let Some((sender_opt, encrypted_any)) = parsed else { continue };
                    let result = if is_groupchat {
                        handle_inbound_muc(own_jid, client, store, own_device_id, rooms, &msg, sender_opt.as_ref(), encrypted_any).await
                    } else {
                        handle_inbound(own_jid, client, store, own_device_id, sender_opt, encrypted_any).await
                    };
                    if let Err(e) = result {
                        // Distinguish IK-drift from other inbound
                        // failures so the orchestrator can route
                        // it to a re-trust workflow rather than
                        // generic error noise.
                        let downcast = e.downcast_ref::<omemo_pep::StoreFlowError>();
                        match downcast {
                            Some(omemo_pep::StoreFlowError::IkMismatch {
                                jid, device_id, stored_hex, got_hex,
                            }) => {
                                let _ = emit(&Event::IkDrift {
                                    peer: jid.clone(),
                                    device: *device_id,
                                    stored_fingerprint: stored_hex.clone(),
                                    observed_fingerprint: got_hex.clone(),
                                }).await;
                            }
                            _ => {
                                let _ = emit(&Event::Error {
                                    kind: "inbound".into(),
                                    detail: e.to_string(),
                                    id: None,
                                }).await;
                            }
                        }
                    }
                }
                Some(_) => continue,
                None => return ExitReason::StreamEnded,
            }
        }
    }
}

/// Proactive bundle maintenance — invoked on a timer.
///
/// Reads the unconsumed-OPK count from the store. If we're below
/// `OPK_REFILL_THRESHOLD`, top up to 100 (matches the default
/// install pool size) and republish the bundle so peers see the
/// new public halves. No-op when the pool is healthy.
///
/// Why this exists: the reactive refill paths (one per inbound
/// KEX) only fire AFTER an OPK has been consumed. Under
/// peer-fanout load (e.g. a fresh group of users all bootstrap
/// against this bot in the same minute) the pool could drain
/// faster than the publish-republish RTT. Then the next peer's
/// bundle fetch hits an empty `<prekeys>` and X3DH passive
/// fails. The 60s timer caps the worst-case window.
async fn check_bundle_health(
    client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
) -> anyhow::Result<()> {
    let unconsumed = store
        .count_unconsumed_opks()
        .map_err(|e| anyhow::anyhow!("count_unconsumed_opks: {e}"))?;
    if unconsumed >= OPK_REFILL_THRESHOLD {
        return Ok(());
    }
    tracing::info!(
        unconsumed,
        threshold = OPK_REFILL_THRESHOLD,
        "OPK pool below threshold; replenishing"
    );
    let added = replenish_opks(store, REPLENISH_TARGET, &mut OsRng)
        .map_err(|e| anyhow::anyhow!("replenish_opks: {e}"))?;
    tracing::info!(added, "OPKs replenished");
    publish_my_bundle(store, client, own_device_id)
        .await
        .map_err(|e| anyhow::anyhow!("publish_my_bundle: {e}"))?;
    // Also republish the OMEMO 0.3 bundle so dual-namespace
    // peers see the refilled pool too.
    let old_bundle = omemo_pep::old_bundle_from_store(store)
        .map_err(|e| anyhow::anyhow!("old_bundle_from_store: {e}"))?;
    publish_old_bundle(client, own_device_id, &old_bundle)
        .await
        .map_err(|e| anyhow::anyhow!("publish_old_bundle: {e}"))?;
    Ok(())
}

async fn handle_inbound(
    own_jid: &BareJid,
    client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
    sender_jid_opt: Option<BareJid>,
    encrypted_any: EncryptedAny,
) -> Result<()> {
    let sender_jid =
        sender_jid_opt.ok_or_else(|| anyhow!("inbound message has no `from` JID"))?;

    match encrypted_any {
        EncryptedAny::Twomemo(encrypted) => {
            let sender_device = encrypted.sid;
            let kind = inbound_kind(&encrypted, own_jid.as_str(), own_device_id)
                .context("classify inbound (twomemo)")?;
            let recovered = match kind {
                InboundKind::Kex => receive_first_message(
                    store,
                    &encrypted,
                    own_jid.as_str(),
                    own_device_id,
                    own_jid.as_str(),
                    sender_jid.as_str(),
                    sender_device,
                    TrustPolicy::Tofu,
                    random_priv_provider(16),
                )?,
                InboundKind::Follow => receive_followup(
                    store,
                    &encrypted,
                    own_jid.as_str(),
                    own_device_id,
                    own_jid.as_str(),
                    sender_jid.as_str(),
                    sender_device,
                    random_priv_provider(16),
                )?,
            };
            // Refill OPKs if a KEX consumed one.
            let _ = replenish_opks(store, REPLENISH_TARGET, &mut OsRng);
            emit(&Event::Message {
                from: sender_jid.to_string(),
                device: sender_device,
                backend: BackendArg::Twomemo,
                body: recovered.body,
                timestamp: recovered.timestamp,
            })
            .await?;
        }
        EncryptedAny::Oldmemo(encrypted) => {
            let sender_device = encrypted.sid;
            let kind = inbound_kind_oldmemo(&encrypted, own_device_id)
                .context("classify inbound (oldmemo)")?;
            let body_bytes = match kind {
                InboundOldKind::Kex => {
                    // Need sender's IK in Ed25519 form — fetch the
                    // sender's bundle. (PEP fetch caveat in
                    // module docstring.)
                    let bundle = fetch_old_bundle(client, Some(sender_jid.clone()), sender_device)
                        .await
                        .context("fetch sender oldmemo bundle for IK")?;
                    receive_first_message_oldmemo(
                        store,
                        &encrypted,
                        own_device_id,
                        sender_jid.as_str(),
                        sender_device,
                        bundle.identity_key_ed,
                        TrustPolicy::Tofu,
                        random_priv_provider(16),
                    )?
                }
                InboundOldKind::Follow => receive_followup_oldmemo(
                    store,
                    &encrypted,
                    own_device_id,
                    sender_jid.as_str(),
                    sender_device,
                    random_priv_provider(16),
                )?,
            };
            let _ = replenish_opks(store, REPLENISH_TARGET, &mut OsRng);
            let body = String::from_utf8(body_bytes)
                .map_err(|e| anyhow!("oldmemo body not UTF-8: {e}"))?;
            emit(&Event::Message {
                from: sender_jid.to_string(),
                device: sender_device,
                backend: BackendArg::Oldmemo,
                body,
                timestamp: String::new(),
            })
            .await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    own_jid: &BareJid,
    client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
    rooms: &mut HashMap<BareJid, MucRoom>,
    occupants_cache: &mut HashMap<BareJid, Vec<(BareJid, Vec<u32>)>>,
    cmd: Command,
) -> Result<()> {
    match cmd {
        Command::Send {
            peer,
            device,
            backend,
            body,
            id,
        } => {
            tracing::info!(peer = %peer, ?device, ?backend, body_len = body.len(), "send");
            let peer_jid = BareJid::from_str_strict(&peer)?;
            // Resolve the target device set:
            //   Some(d)    → just that one
            //   None + sessions exist → all (peer, *) sessions
            //   None + no sessions    → discover + bootstrap each
            //                           advertised device
            let target_devices: Vec<u32> = match device {
                Some(d) => vec![d],
                None => {
                    let store_backend = match backend {
                        BackendArg::Twomemo => omemo_pep::Backend::Twomemo,
                        BackendArg::Oldmemo => omemo_pep::Backend::Oldmemo,
                    };
                    let mut existing = store
                        .session_devices(peer_jid.as_str(), store_backend)
                        .map_err(|e| anyhow!("session_devices: {e}"))?;
                    if existing.is_empty() {
                        // No sessions yet → discover the peer's
                        // devicelist and let `send_one` bootstrap
                        // each one as it goes. We don't need a
                        // separate bootstrap here — `send_one`'s
                        // existing implicit-bootstrap path handles
                        // it for each device id we hand it.
                        let advertised = match backend {
                            BackendArg::Twomemo => fetch_device_list(client, Some(peer_jid.clone()))
                                .await
                                .map_err(|e| anyhow!("fetch_device_list: {e}"))?
                                .devices
                                .into_iter()
                                .map(|d| d.id)
                                .collect::<Vec<_>>(),
                            BackendArg::Oldmemo => fetch_old_device_list(client, Some(peer_jid.clone()))
                                .await
                                .map_err(|e| anyhow!("fetch_old_device_list: {e}"))?
                                .devices,
                        };
                        if advertised.is_empty() {
                            return Err(anyhow!(
                                "peer {peer} advertises no devices in `{:?}` namespace",
                                backend
                            ));
                        }
                        existing = advertised;
                    }
                    existing
                }
            };
            // Fan-out: send_one is per-device — call it once per
            // target. v1 doesn't share the SCE envelope across
            // devices (each call re-seals it), which costs a few
            // extra AES blocks per device but keeps the simple
            // single-device API. A future optimisation could
            // batch via `encrypt_to_peers` (already used for MUC).
            for d in &target_devices {
                send_one(client, store, own_device_id, &peer_jid, *d, backend, &body)
                    .await
                    .with_context(|| format!("send to {peer}/{d}"))?;
            }
            for d in &target_devices {
                emit(&Event::Sent {
                    peer: peer.clone(),
                    device: *d,
                    backend,
                    id: id.clone(),
                })
                .await?;
            }
        }
        Command::Discover { peer, backend, id } => {
            let peer_jid = BareJid::from_str_strict(&peer)?;
            let devices = match backend {
                BackendArg::Twomemo => fetch_device_list(client, Some(peer_jid))
                    .await
                    .map_err(|e| anyhow!("fetch_device_list: {e}"))?
                    .devices
                    .into_iter()
                    .map(|d| d.id)
                    .collect(),
                BackendArg::Oldmemo => fetch_old_device_list(client, Some(peer_jid))
                    .await
                    .map_err(|e| anyhow!("fetch_old_device_list: {e}"))?
                    .devices,
            };
            emit(&Event::DeviceList {
                peer,
                backend,
                devices,
                id,
            })
            .await?;
        }
        Command::JoinMuc { room, nick, id } => {
            // MVP architecture decision: `join_muc` only sends the
            // presence. It does NOT block to fetch occupant
            // devicelists — the daemon's command handler runs
            // inside `tokio::select!`, so any code that awaits
            // here (sleep, IQ fetch, etc.) prevents the inbound
            // arm from dispatching the presence stanzas the
            // server is sending us right now. Without those
            // dispatches the room state stays empty and the
            // refresh sees nobody.
            //
            // Instead, the daemon emits `muc_joined` immediately
            // with an empty occupant list, then streams
            // `muc_occupant_joined` events as presences arrive.
            // The orchestrator decides when the room is "settled"
            // (typical: after seeing every expected nick or after
            // a small idle period) and issues `refresh_muc` to
            // snapshot the OMEMO devicelists in one shot. Splitting
            // these phases keeps the daemon cooperative.
            let room_jid = BareJid::from_str_strict(&room)?;
            let muc = MucRoom::new(room_jid.clone(), nick.clone());
            muc.send_join(client)
                .await
                .map_err(|e| anyhow!("send_join: {e}"))?;
            rooms.insert(room_jid.clone(), muc);
            occupants_cache.insert(room_jid, Vec::new());
            emit(&Event::MucJoined {
                room,
                occupants: Vec::new(),
                id,
            })
            .await?;
        }
        Command::SendMuc { room, body, id } => {
            let room_jid = BareJid::from_str_strict(&room)?;
            let muc = rooms
                .get(&room_jid)
                .ok_or_else(|| anyhow!("not in MUC {room} (run join_muc first)"))?;
            let occupant_devs = occupants_cache
                .get(&room_jid)
                .ok_or_else(|| anyhow!("no devicelist cache for {room} (run refresh_muc)"))?
                .clone();
            // Refuse to fan out to zero recipients — the resulting
            // `<encrypted>` would be a no-op for everyone (no
            // <key> children) but ejabberd still routes it,
            // making peers see a malformed message. Better to
            // surface the misconfig.
            if occupant_devs.iter().all(|(_, devs)| devs.is_empty()) {
                return Err(anyhow!(
                    "send_muc: no occupant devicelists cached for {room} — \
                     issue `refresh_muc` after seeing `muc_occupant_joined` events"
                ));
            }

            // For each (peer, device): bootstrap if needed and
            // collect the resulting KexCarrier so the first send
            // to a brand-new device emits `<key kex='true'>`.
            // This MVP path is OMEMO 2 only — OMEMO 0.3 MUC
            // fan-out (Converse.js compat) is on the v3 list.
            //
            // PeerSpec borrows the `jid` field as `&str`, so we
            // stash the JID strings in a stable Vec first and
            // then immutably borrow into the spec list. This
            // keeps the borrow checker happy without any unsafe.
            struct PreSpec {
                peer_jid: String,
                device: u32,
                kex: Option<omemo_pep::KexCarrier>,
            }
            let mut prespecs: Vec<PreSpec> = Vec::new();
            for (peer_jid, device_ids) in &occupant_devs {
                for &device in device_ids {
                    let kex = if store
                        .load_session_snapshot(peer_jid.as_str(), device)
                        .map_err(|e| anyhow!("load_session: {e}"))?
                        .is_none()
                    {
                        let mut ephemeral_priv = [0u8; 32];
                        OsRng.fill_bytes(&mut ephemeral_priv);
                        let bundle = fetch_bundle(client, Some(peer_jid.clone()), device)
                            .await
                            .map_err(|e| anyhow!("fetch_bundle({peer_jid}/{device}): {e}"))?;
                        let opk_id = bundle
                            .prekeys
                            .first()
                            .ok_or_else(|| anyhow!("peer {peer_jid}/{device} bundle has no OPKs"))?
                            .id;
                        Some(bootstrap_and_save_active(
                            store,
                            peer_jid.as_str(),
                            device,
                            &bundle,
                            opk_id,
                            ephemeral_priv,
                            random_priv_provider(32),
                        )?)
                    } else {
                        None
                    };
                    prespecs.push(PreSpec {
                        peer_jid: peer_jid.as_str().to_owned(),
                        device,
                        kex,
                    });
                }
            }
            let specs: Vec<(PeerSpec<'_>, Box<dyn omemo_doubleratchet::dh_ratchet::DhPrivProvider>)> =
                prespecs
                    .iter()
                    .map(|p| {
                        (
                            PeerSpec {
                                jid: p.peer_jid.as_str(),
                                device_id: p.device,
                                kex: p.kex.clone(),
                            },
                            random_priv_provider(16),
                        )
                    })
                    .collect();
            let encrypted = encrypt_to_peers(
                store,
                own_device_id,
                room_jid.as_str(),
                &body,
                specs,
            )
            .map_err(|e| anyhow!("encrypt_to_peers: {e}"))?;
            muc.send_groupchat(client, &encrypted)
                .await
                .map_err(|e| anyhow!("send_groupchat: {e}"))?;
            emit(&Event::Sent {
                peer: room.clone(),
                device: 0,
                backend: BackendArg::Twomemo,
                id,
            })
            .await?;
            // Note: emitting `sent` with peer=room and device=0 is
            // a slight overload of the 1:1 event shape — could be
            // a separate `muc_sent` event. Kept compact for now.
            let _ = room;
        }
        Command::RefreshMuc { room, id } => {
            let room_jid = BareJid::from_str_strict(&room)?;
            let muc = rooms
                .get(&room_jid)
                .ok_or_else(|| anyhow!("not in MUC {room}"))?;
            let occupant_devs = muc
                .refresh_device_lists(client, store)
                .await
                .map_err(|e| anyhow!("refresh_device_lists: {e}"))?;
            let infos = occupant_infos(muc, &occupant_devs);
            occupants_cache.insert(room_jid, occupant_devs);
            emit(&Event::MucRefreshed {
                room,
                occupants: infos,
                id,
            })
            .await?;
        }
        Command::LeaveMuc { room, id } => {
            let room_jid = BareJid::from_str_strict(&room)?;
            if let Some(muc) = rooms.remove(&room_jid) {
                let _ = muc.send_leave(client).await;
            }
            occupants_cache.remove(&room_jid);
            emit(&Event::MucLeft { room, id }).await?;
        }
        Command::Status { id } => {
            let twomemo_sessions = store
                .session_count(omemo_pep::Backend::Twomemo)
                .map_err(|e| anyhow!("session_count(twomemo): {e}"))?;
            let oldmemo_sessions = store
                .session_count(omemo_pep::Backend::Oldmemo)
                .map_err(|e| anyhow!("session_count(oldmemo): {e}"))?;
            let opk_pool_size = store
                .count_unconsumed_opks()
                .map_err(|e| anyhow!("count_unconsumed_opks: {e}"))?;
            let uptime_secs = STARTED_AT
                .get()
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0);
            emit(&Event::Status {
                jid: own_jid.to_string(),
                device_id: own_device_id,
                twomemo_sessions,
                oldmemo_sessions,
                opk_pool_size,
                joined_muc_count: rooms.len(),
                uptime_secs,
                connection_state: "online",
                id,
            })
            .await?;
        }
        Command::SetTrust {
            peer,
            device,
            state,
            id,
        } => {
            let updated = store
                .set_trust(&peer, device, state.as_state())
                .map_err(|e| anyhow!("set_trust: {e}"))?;
            if !updated {
                return Err(anyhow!(
                    "set_trust: no recorded device for {peer}/{device}"
                ));
            }
            emit(&Event::TrustSet {
                peer,
                device,
                state,
                id,
            })
            .await?;
        }
        Command::ForceRetrust {
            peer,
            device,
            new_ik_hex,
            state,
            id,
        } => {
            let new_ik = parse_hex32(&new_ik_hex)
                .ok_or_else(|| anyhow!("force_retrust: new_ik_hex must be 64 hex chars"))?;
            store
                .force_set_ik(&peer, device, &new_ik, state.as_state())
                .map_err(|e| anyhow!("force_set_ik: {e}"))?;
            emit(&Event::Retrusted { peer, device, id }).await?;
        }
        Command::ListPending { id } => {
            let entries = store
                .pending_devices()
                .map_err(|e| anyhow!("pending_devices: {e}"))?
                .into_iter()
                .map(|d| PendingTrustEntry {
                    peer: d.bare_jid,
                    device: d.device_id,
                    ik_fingerprint: hex_encode(&d.ik_pub),
                    first_seen_at: d.first_seen_at,
                })
                .collect();
            emit(&Event::PendingTrusts { entries, id }).await?;
        }
        Command::Shutdown => unreachable!("shutdown is handled at main_loop top-level"),
    }
    Ok(())
}

/// Lowercase-hex encode a 32-byte buffer (64 chars). Fingerprint
/// representation in the daemon protocol.
fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Parse a 64-char lowercase-hex string back into a 32-byte
/// buffer. Returns `None` on length / non-hex char errors.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// MUC helpers
// ---------------------------------------------------------------------------

/// Resolve `(real_jid, devices)` pairs back to the room's
/// `(real_jid, nick, devices)` triples for the wire event shape.
fn occupant_infos(
    muc: &MucRoom,
    devs: &[(BareJid, Vec<u32>)],
) -> Vec<MucOccupantInfo> {
    let mut out = Vec::with_capacity(devs.len());
    for (jid, devices) in devs {
        // Find the in-room nick for this real_jid (best-effort).
        let nick = muc
            .occupants
            .values()
            .find(|o| o.real_jid.as_ref() == Some(jid))
            .map(|o| o.nick.clone())
            .unwrap_or_default();
        out.push(MucOccupantInfo {
            real_jid: jid.to_string(),
            nick,
            devices: devices.clone(),
        });
    }
    out
}

async fn handle_presence(
    rooms: &mut HashMap<BareJid, MucRoom>,
    presence: &xmpp_parsers::presence::Presence,
) {
    use omemo_pep::MucEvent;
    let Some(from) = presence.from.as_ref() else {
        return;
    };
    let from_bare = from.to_bare();
    let Some(muc) = rooms.get_mut(&from_bare) else {
        return;
    };
    let event = match muc.handle_presence(presence) {
        Ok(e) => e,
        Err(_) => return,
    };
    match event {
        MucEvent::OccupantJoined { occupant } => {
            let _ = emit(&Event::MucOccupantJoined {
                room: from_bare.to_string(),
                nick: occupant.nick.clone(),
                real_jid: occupant.real_jid.as_ref().map(|j| j.to_string()),
            })
            .await;
        }
        MucEvent::OccupantLeft { nick } => {
            let _ = emit(&Event::MucOccupantLeft {
                room: from_bare.to_string(),
                nick,
            })
            .await;
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound_muc(
    own_jid: &BareJid,
    _client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
    rooms: &HashMap<BareJid, MucRoom>,
    msg: &xmpp_parsers::message::Message,
    sender_opt: Option<&BareJid>,
    encrypted_any: EncryptedAny,
) -> Result<()> {
    let from_full = msg
        .from
        .as_ref()
        .and_then(|j| j.try_as_full().ok().cloned())
        .ok_or_else(|| anyhow!("groupchat <message> has no full from-JID"))?;
    let _ = sender_opt; // sender_opt is bare-of-room; we want the occupant's real bare below
    let room_bare = from_full.to_bare();
    let muc = rooms
        .get(&room_bare)
        .ok_or_else(|| anyhow!("groupchat from unknown room: {room_bare}"))?;
    let real_bare = muc
        .resolve_sender_real_jid(&from_full)
        .ok_or_else(|| anyhow!("can't resolve real JID for {from_full}"))?
        .clone();
    let nick = from_full.resource().to_string();

    // Skip our own MUC echo: alice sends to room → ejabberd reflects
    // back to alice. Alice's device id isn't in `<keys>` (we don't
    // encrypt to ourselves) so `inbound_kind` would error. Drop it.
    if &real_bare == own_jid {
        return Ok(());
    }

    match encrypted_any {
        EncryptedAny::Twomemo(encrypted) => {
            let sender_device = encrypted.sid;
            let kind = inbound_kind(&encrypted, own_jid.as_str(), own_device_id)
                .context("classify groupchat inbound (twomemo)")?;
            let recovered = match kind {
                InboundKind::Kex => receive_first_message(
                    store,
                    &encrypted,
                    own_jid.as_str(),
                    own_device_id,
                    room_bare.as_str(),
                    real_bare.as_str(),
                    sender_device,
                    TrustPolicy::Tofu,
                    random_priv_provider(16),
                )?,
                InboundKind::Follow => receive_followup(
                    store,
                    &encrypted,
                    own_jid.as_str(),
                    own_device_id,
                    room_bare.as_str(),
                    real_bare.as_str(),
                    sender_device,
                    random_priv_provider(16),
                )?,
            };
            let _ = replenish_opks(store, REPLENISH_TARGET, &mut OsRng);
            emit(&Event::MucMessage {
                room: room_bare.to_string(),
                from_real_jid: real_bare.to_string(),
                from_nick: nick,
                device: sender_device,
                backend: BackendArg::Twomemo,
                body: recovered.body,
            })
            .await?;
        }
        EncryptedAny::Oldmemo(_) => {
            return Err(anyhow!("groupchat OMEMO 0.3 inbound not supported in v2"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Listen for SIGTERM and SIGINT and synthesise a `Shutdown`
/// command on the same channel stdin uses. The main loop already
/// knows how to handle `Shutdown` cleanly (drain pending events,
/// send `</stream:stream>`, emit `goodbye`, exit 0); reusing it
/// keeps shutdown semantics consistent regardless of trigger.
#[cfg(unix)]
async fn signal_listener(tx: mpsc::Sender<Command>) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let signal_name = tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = sigint.recv()  => "SIGINT",
    };
    tracing::info!(signal = signal_name, "shutdown signal received");
    let _ = tx.send(Command::Shutdown).await;
}

/// Read JSON Lines from stdin into the command channel. Stdin EOF
/// closes the channel so the main loop exits cleanly.
async fn stdin_reader(tx: mpsc::Sender<Command>) {
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Command>(line) {
                    Ok(cmd) => {
                        if tx.send(cmd).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = emit(&Event::Error {
                            kind: "parse".into(),
                            detail: format!("bad command line: {e}"),
                            id: None,
                        })
                        .await;
                    }
                }
            }
            Ok(None) => return, // EOF
            Err(e) => {
                let _ = emit(&Event::Error {
                    kind: "stdin".into(),
                    detail: e.to_string(),
                    id: None,
                })
                .await;
                return;
            }
        }
    }
}

/// Serialise + write one event to stdout. Each event is exactly
/// one line (LF-terminated) so the consumer can use line-based
/// parsing.
async fn emit(event: &Event) -> Result<()> {
    let mut line = serde_json::to_string(event)?;
    line.push('\n');
    let mut stdout = tokio::io::stdout();
    stdout.write_all(line.as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

enum FreshKex {
    Twomemo(omemo_pep::KexCarrier),
    Oldmemo(omemo_pep::KexCarrierOld),
}

async fn bootstrap_session(
    client: &mut Client,
    store: &mut Store,
    peer_jid: &BareJid,
    device: u32,
    backend: BackendArg,
) -> Result<FreshKex> {
    let mut ephemeral_priv = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_priv);
    match backend {
        BackendArg::Twomemo => {
            let bundle = fetch_bundle(client, Some(peer_jid.clone()), device)
                .await
                .map_err(|e| anyhow!("fetch_bundle: {e}"))?;
            let chosen_opk_id = bundle
                .prekeys
                .first()
                .ok_or_else(|| anyhow!("peer twomemo bundle has no OPKs left"))?
                .id;
            let kex = bootstrap_and_save_active(
                store,
                peer_jid.as_str(),
                device,
                &bundle,
                chosen_opk_id,
                ephemeral_priv,
                random_priv_provider(32),
            )?;
            Ok(FreshKex::Twomemo(kex))
        }
        BackendArg::Oldmemo => {
            let bundle = fetch_old_bundle(client, Some(peer_jid.clone()), device)
                .await
                .map_err(|e| anyhow!("fetch_old_bundle: {e}"))?;
            let chosen_opk_id = bundle
                .prekeys
                .first()
                .ok_or_else(|| anyhow!("peer oldmemo bundle has no OPKs left"))?
                .id;
            let kex = bootstrap_and_save_active_oldmemo(
                store,
                peer_jid.as_str(),
                device,
                &bundle,
                chosen_opk_id,
                ephemeral_priv,
                random_priv_provider(32),
            )?;
            Ok(FreshKex::Oldmemo(kex))
        }
    }
}

async fn send_one(
    client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
    peer_jid: &BareJid,
    device: u32,
    backend: BackendArg,
    body: &str,
) -> Result<()> {
    match backend {
        BackendArg::Twomemo => {
            // First send to a brand-new (peer, device) → bootstrap
            // implicitly and attach the resulting `KexCarrier` to
            // this outbound so it goes out as `<key kex='true'>`.
            // The peer's receive_first_message can then run X3DH
            // passive. Subsequent sends use the persisted session
            // and emit `kex='false'`.
            let kex = if store
                .load_session_snapshot(peer_jid.as_str(), device)
                .map_err(|e| anyhow!("load_session: {e}"))?
                .is_none()
            {
                match bootstrap_session(client, store, peer_jid, device, backend).await? {
                    FreshKex::Twomemo(k) => Some(k),
                    FreshKex::Oldmemo(_) => unreachable!("backend mismatch"),
                }
            } else {
                None
            };
            let encrypted = encrypt_to_peer(
                store,
                own_device_id,
                peer_jid.as_str(),
                device,
                body,
                kex,
                random_priv_provider(16),
            )?;
            send_encrypted(client, peer_jid.clone(), &encrypted)
                .await
                .map_err(|e| anyhow!("send_encrypted: {e}"))?;
        }
        BackendArg::Oldmemo => {
            let kex = if store
                .load_oldmemo_session_snapshot(peer_jid.as_str(), device)
                .map_err(|e| anyhow!("load_oldmemo_session: {e}"))?
                .is_none()
            {
                match bootstrap_session(client, store, peer_jid, device, backend).await? {
                    FreshKex::Oldmemo(k) => Some(k),
                    FreshKex::Twomemo(_) => unreachable!("backend mismatch"),
                }
            } else {
                None
            };
            let encrypted = encrypt_to_peer_oldmemo(
                store,
                own_device_id,
                peer_jid.as_str(),
                device,
                body,
                kex,
                random_priv_provider(16),
            )?;
            send_encrypted_old(client, peer_jid.clone(), &encrypted)
                .await
                .map_err(|e| anyhow!("send_encrypted_old: {e}"))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Connect / identity (mirror of main.rs helpers, kept here so the
// daemon is self-contained and easy to evolve independently)
// ---------------------------------------------------------------------------

fn open_store(store_path: &Path) -> Result<Store> {
    Store::open(store_path).with_context(|| format!("open store {store_path:?}"))
}

fn ensure_local_identity(
    bare_jid: &BareJid,
    store: &mut Store,
    device_id_hint: Option<u32>,
    opk_count: u32,
) -> Result<u32> {
    let identity = if let Some(id) = store.get_identity()? {
        id
    } else {
        let device_id = device_id_hint.unwrap_or_else(|| OsRng.next_u32());
        install_identity_random(store, bare_jid.as_str(), device_id, opk_count, &mut OsRng)
            .context("install_identity_random")?
    };
    let _added = replenish_opks(store, REPLENISH_TARGET, &mut OsRng)?;
    Ok(identity.device_id)
}

async fn connect(cfg: &DaemonConfig) -> Client {
    if let Some(addr) = &cfg.insecure_tcp {
        omemo_pep::connect_plaintext(cfg.bare_jid.clone(), cfg.password.clone(), addr.clone())
    } else if let Some(addr) = &cfg.starttls_addr {
        omemo_pep::connect_starttls_addr(
            cfg.bare_jid.clone(),
            cfg.password.clone(),
            addr.clone(),
        )
    } else {
        omemo_pep::connect_starttls(cfg.bare_jid.clone(), cfg.password.clone())
    }
}

async fn await_online(client: &mut Client) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(event) = client.next().await {
            if matches!(event, XmppEvent::Online { .. }) {
                return Ok(());
            }
        }
        Err(anyhow!("client stream ended before Online event"))
    })
    .await
    .map_err(|_| anyhow!("login timed out"))?
}

async fn announce_presence(client: &mut Client) -> Result<()> {
    use xmpp_parsers::presence::Presence;
    client
        .send_stanza(Presence::available().into())
        .await
        .context("send initial presence")?;
    Ok(())
}

async fn publish_identity(client: &mut Client, store: &Store, device_id: u32) -> Result<()> {
    let device_list = DeviceList {
        devices: vec![Device {
            id: device_id,
            label: None,
            labelsig: None,
        }],
    };
    publish_device_list(client, &device_list)
        .await
        .map_err(|e| anyhow!("publish OMEMO 2 device list: {e}"))?;
    publish_my_bundle(store, client, device_id)
        .await
        .map_err(|e| anyhow!("publish OMEMO 2 bundle: {e}"))?;

    let old_list = OldDeviceList {
        devices: vec![device_id],
    };
    publish_old_device_list(client, &old_list)
        .await
        .map_err(|e| anyhow!("publish OMEMO 0.3 device list: {e}"))?;
    let old_bundle =
        omemo_pep::old_bundle_from_store(store).map_err(|e| anyhow!("old_bundle: {e}"))?;
    publish_old_bundle(client, device_id, &old_bundle)
        .await
        .map_err(|e| anyhow!("publish OMEMO 0.3 bundle: {e}"))?;
    Ok(())
}

fn random_priv_provider(count: usize) -> Box<dyn DhPrivProvider> {
    let privs: Vec<[u8; 32]> = (0..count)
        .map(|_| {
            let mut p = [0u8; 32];
            OsRng.fill_bytes(&mut p);
            p
        })
        .collect();
    omemo_twomemo::fixed_priv_provider(privs)
}

trait BareJidExt {
    fn from_str_strict(s: &str) -> Result<BareJid>;
}
impl BareJidExt for BareJid {
    fn from_str_strict(s: &str) -> Result<BareJid> {
        use std::str::FromStr;
        BareJid::from_str(s).map_err(|e| anyhow!("invalid bare JID `{s}`: {e}"))
    }
}

