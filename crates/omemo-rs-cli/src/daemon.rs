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
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use omemo_doubleratchet::dh_ratchet::DhPrivProvider;
use omemo_pep::{
    bootstrap_and_save_active, bootstrap_and_save_active_oldmemo, encrypt_to_peer,
    encrypt_to_peer_oldmemo, fetch_bundle, fetch_device_list, fetch_old_bundle,
    fetch_old_device_list, inbound_kind, inbound_kind_oldmemo, install_identity_random,
    parse_encrypted_message, publish_device_list, publish_my_bundle, publish_old_bundle,
    publish_old_device_list, receive_first_message, receive_first_message_oldmemo,
    receive_followup, receive_followup_oldmemo, replenish_opks, send_encrypted,
    send_encrypted_old, BareJid, Client, Device, DeviceList, EncryptedAny, Event as XmppEvent,
    InboundKind, InboundOldKind, OldDeviceList, Stanza, Store, TrustPolicy,
};
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
    /// Encrypt and send a UTF-8 chat body to one peer device.
    /// If no session exists yet, the daemon will implicitly run
    /// `bootstrap` first (so the orchestrator doesn't have to
    /// chain commands manually).
    Send {
        /// Bare JID of the recipient.
        peer: String,
        /// Recipient device id. Required in v1 — multi-device
        /// fan-out (`device` omitted → all devices) is on the
        /// roadmap and needs a `Store::list_sessions` accessor
        /// that doesn't exist yet.
        device: u32,
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
    /// Graceful shutdown: send `</stream:stream>`, drain pending
    /// events, exit. Closing stdin (EOF) has the same effect.
    Shutdown,
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
    /// Result of a `discover` command.
    DeviceList {
        peer: String,
        backend: BackendArg,
        devices: Vec<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    /// Result of a `status` command.
    Status {
        jid: String,
        device_id: u32,
        twomemo_sessions: usize,
        oldmemo_sessions: usize,
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
    /// XMPP stream ended (server side closed, network error, etc.).
    /// The daemon will exit shortly after this.
    Disconnected { reason: String },
    /// Final event before exit. Always emitted last.
    Goodbye,
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

    emit(&Event::Ready {
        jid: cfg.bare_jid.to_string(),
        device_id,
    })
    .await?;

    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
    tokio::spawn(stdin_reader(cmd_tx));

    let exit_reason = main_loop(&cfg.bare_jid, &mut client, &mut store, device_id, cmd_rx).await;

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

async fn main_loop(
    own_jid: &BareJid,
    client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
    mut cmd_rx: mpsc::Receiver<Command>,
) -> ExitReason {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(Command::Shutdown) => return ExitReason::Shutdown,
                Some(cmd) => {
                    if let Err(e) = handle_command(own_jid, client, store, own_device_id, cmd).await {
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
                Some(XmppEvent::Stanza(Stanza::Message(msg))) => {
                    // Inspect the *already-popped* `<message>` for an
                    // `<encrypted>` payload (OMEMO 2 or 0.3). If it
                    // doesn't carry one, drop. We must NOT call
                    // wait_for_encrypted_any here — that would loop
                    // back into client.next() and miss the message
                    // we just took off the queue.
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
                    if let Err(e) = handle_inbound(own_jid, client, store, own_device_id, sender_opt, encrypted_any).await {
                        let _ = emit(&Event::Error {
                            kind: "inbound".into(),
                            detail: e.to_string(),
                            id: None,
                        }).await;
                    }
                }
                Some(_) => continue,
                None => return ExitReason::StreamEnded,
            }
        }
    }
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

async fn handle_command(
    own_jid: &BareJid,
    client: &mut Client,
    store: &mut Store,
    own_device_id: u32,
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
            let peer_jid = BareJid::from_str_strict(&peer)?;
            send_one(client, store, own_device_id, &peer_jid, device, backend, &body)
                .await
                .with_context(|| format!("send to {peer}/{device}"))?;
            emit(&Event::Sent {
                peer,
                device,
                backend,
                id,
            })
            .await?;
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
        Command::Status { id } => {
            // Session counts would need a `Store::list_sessions`
            // accessor that doesn't exist yet — return -1 sentinels
            // for the v1 protocol so the field shape stays stable
            // for orchestrators that already parse them.
            emit(&Event::Status {
                jid: own_jid.to_string(),
                device_id: own_device_id,
                twomemo_sessions: usize::MAX,
                oldmemo_sessions: usize::MAX,
                id,
            })
            .await?;
        }
        Command::Shutdown => unreachable!("shutdown is handled at main_loop top-level"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

