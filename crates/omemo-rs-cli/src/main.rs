//! `omemo-rs-cli` — minimal 1:1 OMEMO 2 chat client.
//!
//! Three subcommands:
//!
//! * `init` — open / create the SQLite store, generate identity if
//!   absent, publish device list + bundle to PEP.
//! * `send` — encrypt + send one chat body to a peer device. Auto-runs
//!   `init` on first invocation against a fresh store.
//! * `recv` — wait for one inbound encrypted `<message>`, decrypt,
//!   print body to stdout, then exit.
//!
//! Store is `$OMEMO_RS_STORE_DIR/<bare-jid>.db`, where
//! `OMEMO_RS_STORE_DIR` defaults to `$HOME/.omemo-rs-cli`.
//!
//! Connection: defaults to `connect_starttls` (XMPP SRV + StartTLS +
//! native cert validation). Pass `--insecure-tcp <host:port>` to use
//! the localhost-friendly `connect_plaintext` instead.
//!
//! Trust policy: hard-coded TOFU on the receive side. Production use
//! would expose this as a flag and persist explicit user decisions.

use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use futures_util::StreamExt;
use omemo_pep::{
    bootstrap_and_save_active, bootstrap_and_save_active_oldmemo, connect_plaintext,
    connect_starttls, connect_starttls_addr, encrypt_to_peer, encrypt_to_peer_oldmemo,
    fetch_bundle, fetch_device_list, fetch_old_bundle, fetch_old_device_list, inbound_kind,
    inbound_kind_oldmemo, install_identity_random, old_bundle_from_store, publish_device_list,
    publish_my_bundle, publish_old_bundle, publish_old_device_list, receive_first_message,
    receive_first_message_oldmemo, receive_followup, receive_followup_oldmemo, replenish_opks,
    send_encrypted, send_encrypted_old, wait_for_encrypted_any, BareJid, Client, Device,
    DeviceList, EncryptedAny, Event, InboundKind, InboundOldKind, OldDeviceList, Store,
    TrustPolicy,
};
use rand_core::{OsRng, RngCore};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BackendArg {
    /// OMEMO 2 (urn:xmpp:omemo:2). Default.
    Twomemo,
    /// OMEMO 0.3 (eu.siacs.conversations.axolotl).
    Oldmemo,
}

const DEFAULT_OPK_COUNT: u32 = 100;
const REPLENISH_TARGET: u32 = 100;

#[derive(Debug, Parser)]
#[command(version, about = "Minimal 1:1 OMEMO 2 chat client")]
struct Cli {
    /// Bare JID for the local account (e.g. `alice@example.org`).
    #[arg(long, value_name = "JID")]
    jid: String,

    /// SASL PLAIN password.
    #[arg(long, env = "OMEMO_RS_PASSWORD")]
    password: String,

    /// Override the SRV-resolved server with an explicit `host:port`
    /// and use a *plaintext* connection (no StartTLS). Localhost
    /// integration only.
    #[arg(long, value_name = "HOST:PORT")]
    insecure_tcp: Option<String>,

    /// Override the StartTLS endpoint with an explicit `host:port`.
    /// Useful for staging deployments without SRV records.
    #[arg(long, value_name = "HOST:PORT", conflicts_with = "insecure_tcp")]
    starttls_addr: Option<String>,

    /// Override the store directory. Default:
    /// `$OMEMO_RS_STORE_DIR` or `$HOME/.omemo-rs-cli`.
    #[arg(long, value_name = "DIR", env = "OMEMO_RS_STORE_DIR")]
    store_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Bootstrap the store (if absent), publish device list + bundle.
    Init {
        /// Local device id. Default: random `u32`.
        #[arg(long)]
        device_id: Option<u32>,
        /// OPK pool size. XEP-0384 §5.3.2 recommends ≥ 100.
        #[arg(long, default_value_t = DEFAULT_OPK_COUNT)]
        opk_count: u32,
    },
    /// Send one encrypted message to a peer device.
    Send {
        #[arg(long, value_name = "BARE_JID")]
        peer: String,
        /// Peer device id. If omitted, the first device in the
        /// peer's published devicelist (matching `--backend`) is
        /// used.
        #[arg(long, value_name = "u32")]
        peer_device: Option<u32>,
        /// Message body (UTF-8).
        #[arg(long)]
        body: String,
        /// Wire-format backend: OMEMO 2 (`twomemo`, default) or
        /// OMEMO 0.3 (`oldmemo`).
        #[arg(long, value_enum, default_value_t = BackendArg::Twomemo)]
        backend: BackendArg,
    },
    /// Wait for one inbound encrypted message, decrypt, print body.
    Recv {
        /// Wall-clock seconds to wait before giving up.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let bare_jid = BareJid::from_str(&cli.jid).context("parse --jid as a bare JID")?;
    let store_path = resolve_store_path(&cli, &bare_jid)?;

    match &cli.cmd {
        Cmd::Init {
            device_id,
            opk_count,
        } => run_init(&cli, &bare_jid, &store_path, *device_id, *opk_count).await,
        Cmd::Send {
            peer,
            peer_device,
            body,
            backend,
        } => run_send(&cli, &bare_jid, &store_path, peer, *peer_device, body, *backend).await,
        Cmd::Recv { timeout } => run_recv(&cli, &bare_jid, &store_path, *timeout).await,
    }
}

fn resolve_store_path(cli: &Cli, jid: &BareJid) -> Result<PathBuf> {
    let dir = match &cli.store_dir {
        Some(d) => d.clone(),
        None => {
            let home = std::env::var_os("HOME").ok_or_else(|| {
                anyhow!("$HOME is not set; pass --store-dir or set OMEMO_RS_STORE_DIR")
            })?;
            PathBuf::from(home).join(".omemo-rs-cli")
        }
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("create store dir {dir:?}"))?;
    Ok(dir.join(format!("{}.db", jid.as_str())))
}

fn open_store(store_path: &std::path::Path) -> Result<Store> {
    Store::open(store_path).with_context(|| format!("open store {store_path:?}"))
}

async fn connect(cli: &Cli, jid: BareJid) -> Result<Client> {
    if let Some(addr) = &cli.insecure_tcp {
        Ok(connect_plaintext(jid, cli.password.clone(), addr.clone()))
    } else if let Some(addr) = &cli.starttls_addr {
        Ok(connect_starttls_addr(
            jid,
            cli.password.clone(),
            addr.clone(),
        ))
    } else {
        Ok(connect_starttls(jid, cli.password.clone()))
    }
}

async fn await_online(client: &mut Client) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(event) = client.next().await {
            if matches!(event, Event::Online { .. }) {
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

/// Open the store, install identity on first run, then refill OPKs
/// to `REPLENISH_TARGET`. Pure-store work — no network. Returns the
/// device id.
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
        let id =
            install_identity_random(store, bare_jid.as_str(), device_id, opk_count, &mut OsRng)
                .context("install_identity_random")?;
        eprintln!("Initialised identity (device id {})", id.device_id);
        id
    };
    let _added = replenish_opks(store, REPLENISH_TARGET, &mut OsRng)?;
    Ok(identity.device_id)
}

/// Publish our device list + bundle to PEP under **both** OMEMO 2
/// and OMEMO 0.3 namespaces, so peers running either backend can
/// discover us. Idempotent.
async fn publish_identity(client: &mut Client, store: &Store, device_id: u32) -> Result<()> {
    // OMEMO 2.
    let device_list = DeviceList {
        devices: vec![Device {
            id: device_id,
            label: None,
            labelsig: None,
        }],
    };
    publish_device_list(client, &device_list)
        .await
        .context("publish OMEMO 2 device list")?;
    publish_my_bundle(store, client, device_id)
        .await
        .context("publish OMEMO 2 bundle")?;

    // OMEMO 0.3 alongside, so an oldmemo peer sees the same device.
    let old_list = OldDeviceList {
        devices: vec![device_id],
    };
    publish_old_device_list(client, &old_list)
        .await
        .context("publish OMEMO 0.3 device list")?;
    let old_bundle =
        old_bundle_from_store(store).context("derive OMEMO 0.3 bundle from store")?;
    publish_old_bundle(client, device_id, &old_bundle)
        .await
        .context("publish OMEMO 0.3 bundle")?;

    Ok(())
}

async fn run_init(
    cli: &Cli,
    bare_jid: &BareJid,
    store_path: &std::path::Path,
    device_id_hint: Option<u32>,
    opk_count: u32,
) -> Result<()> {
    let mut store = open_store(store_path)?;
    let device_id = ensure_local_identity(bare_jid, &mut store, device_id_hint, opk_count)?;

    let mut client = connect(cli, bare_jid.clone()).await?;
    await_online(&mut client).await?;
    announce_presence(&mut client).await?;
    publish_identity(&mut client, &store, device_id).await?;
    client.send_end().await.ok();

    println!("Ready: {} device id {}", bare_jid.as_str(), device_id);
    Ok(())
}

async fn run_send(
    cli: &Cli,
    bare_jid: &BareJid,
    store_path: &std::path::Path,
    peer_jid_str: &str,
    peer_device_id_opt: Option<u32>,
    body: &str,
    backend: BackendArg,
) -> Result<()> {
    let mut store = open_store(store_path)?;
    let device_id = ensure_local_identity(bare_jid, &mut store, None, DEFAULT_OPK_COUNT)?;

    let peer_jid = BareJid::from_str(peer_jid_str).context("parse --peer as a bare JID")?;

    let mut client = connect(cli, bare_jid.clone()).await?;
    await_online(&mut client).await?;
    announce_presence(&mut client).await?;
    publish_identity(&mut client, &store, device_id).await?;

    let peer_device_id = match peer_device_id_opt {
        Some(id) => id,
        None => match backend {
            BackendArg::Twomemo => fetch_device_list(&mut client, Some(peer_jid.clone()))
                .await
                .context("fetch peer device list (twomemo)")?
                .devices
                .first()
                .ok_or_else(|| anyhow!("peer has an empty OMEMO 2 device list"))?
                .id,
            BackendArg::Oldmemo => *fetch_old_device_list(&mut client, Some(peer_jid.clone()))
                .await
                .context("fetch peer device list (oldmemo)")?
                .devices
                .first()
                .ok_or_else(|| anyhow!("peer has an empty OMEMO 0.3 device list"))?,
        },
    };

    match backend {
        BackendArg::Twomemo => {
            send_twomemo(
                &mut store,
                &mut client,
                device_id,
                &peer_jid,
                peer_device_id,
                body,
            )
            .await?;
        }
        BackendArg::Oldmemo => {
            send_oldmemo(
                &mut store,
                &mut client,
                device_id,
                &peer_jid,
                peer_device_id,
                body,
            )
            .await?;
        }
    }
    client.send_end().await.ok();
    println!(
        "Sent {} byte body to {}/{peer_device_id} ({})",
        body.len(),
        peer_jid_str,
        match backend {
            BackendArg::Twomemo => "OMEMO 2",
            BackendArg::Oldmemo => "OMEMO 0.3",
        }
    );
    Ok(())
}

async fn send_twomemo(
    store: &mut Store,
    client: &mut Client,
    device_id: u32,
    peer_jid: &BareJid,
    peer_device_id: u32,
    body: &str,
) -> Result<()> {
    let kex = if store
        .load_session_snapshot(peer_jid.as_str(), peer_device_id)?
        .is_none()
    {
        let bundle = fetch_bundle(client, Some(peer_jid.clone()), peer_device_id)
            .await
            .context("fetch peer bundle (twomemo)")?;
        let chosen_opk_id = bundle
            .prekeys
            .first()
            .ok_or_else(|| anyhow!("peer twomemo bundle has no OPKs left"))?
            .id;
        let mut ephemeral_priv = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_priv);
        Some(
            bootstrap_and_save_active(
                store,
                peer_jid.as_str(),
                peer_device_id,
                &bundle,
                chosen_opk_id,
                ephemeral_priv,
                random_priv_provider(32),
            )
            .context("bootstrap_active (twomemo)")?,
        )
    } else {
        None
    };

    let encrypted = encrypt_to_peer(
        store,
        device_id,
        peer_jid.as_str(),
        peer_device_id,
        body,
        kex,
        random_priv_provider(16),
    )
    .context("encrypt_to_peer (twomemo)")?;
    send_encrypted(client, peer_jid.clone(), &encrypted)
        .await
        .context("send_encrypted (twomemo)")?;
    Ok(())
}

async fn send_oldmemo(
    store: &mut Store,
    client: &mut Client,
    device_id: u32,
    peer_jid: &BareJid,
    peer_device_id: u32,
    body: &str,
) -> Result<()> {
    let kex = if store
        .load_oldmemo_session_snapshot(peer_jid.as_str(), peer_device_id)?
        .is_none()
    {
        let bundle = fetch_old_bundle(client, Some(peer_jid.clone()), peer_device_id)
            .await
            .context("fetch peer bundle (oldmemo)")?;
        let chosen_opk_id = bundle
            .prekeys
            .first()
            .ok_or_else(|| anyhow!("peer oldmemo bundle has no OPKs left"))?
            .id;
        let mut ephemeral_priv = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_priv);
        Some(
            bootstrap_and_save_active_oldmemo(
                store,
                peer_jid.as_str(),
                peer_device_id,
                &bundle,
                chosen_opk_id,
                ephemeral_priv,
                random_priv_provider(32),
            )
            .context("bootstrap_active (oldmemo)")?,
        )
    } else {
        None
    };

    let encrypted = encrypt_to_peer_oldmemo(
        store,
        device_id,
        peer_jid.as_str(),
        peer_device_id,
        body,
        kex,
        random_priv_provider(16),
    )
    .context("encrypt_to_peer (oldmemo)")?;
    send_encrypted_old(client, peer_jid.clone(), &encrypted)
        .await
        .context("send_encrypted (oldmemo)")?;
    Ok(())
}

async fn run_recv(
    cli: &Cli,
    bare_jid: &BareJid,
    store_path: &std::path::Path,
    timeout: u64,
) -> Result<()> {
    let mut store = open_store(store_path)?;
    let device_id = ensure_local_identity(bare_jid, &mut store, None, DEFAULT_OPK_COUNT)?;

    let mut client = connect(cli, bare_jid.clone()).await?;
    await_online(&mut client).await?;
    announce_presence(&mut client).await?;
    publish_identity(&mut client, &store, device_id).await?;

    let (sender_jid_opt, encrypted_any) = tokio::time::timeout(
        Duration::from_secs(timeout),
        wait_for_encrypted_any(&mut client),
    )
    .await
    .map_err(|_| anyhow!("no message arrived within {timeout}s"))?
    .context("wait_for_encrypted_any")?;
    let sender_jid = sender_jid_opt.ok_or_else(|| anyhow!("inbound message has no `from` JID"))?;

    match encrypted_any {
        EncryptedAny::Twomemo(encrypted) => {
            let sender_device_id = encrypted.sid;
            let _ = fetch_device_list(&mut client, Some(sender_jid.clone())).await;
            let kind = inbound_kind(&encrypted, bare_jid.as_str(), device_id)
                .context("classify inbound (twomemo)")?;
            let recovered = match kind {
                InboundKind::Kex => receive_first_message(
                    &mut store,
                    &encrypted,
                    bare_jid.as_str(),
                    device_id,
                    bare_jid.as_str(),
                    sender_jid.as_str(),
                    sender_device_id,
                    TrustPolicy::Tofu,
                    random_priv_provider(16),
                )
                .context("receive_first_message (twomemo)")?,
                InboundKind::Follow => receive_followup(
                    &mut store,
                    &encrypted,
                    bare_jid.as_str(),
                    device_id,
                    bare_jid.as_str(),
                    sender_jid.as_str(),
                    sender_device_id,
                    random_priv_provider(16),
                )
                .context("receive_followup (twomemo)")?,
            };
            let _added = replenish_opks(&mut store, REPLENISH_TARGET, &mut OsRng)?;
            publish_my_bundle(&store, &mut client, device_id).await.ok();
            client.send_end().await.ok();
            let mut stdout = std::io::stdout().lock();
            writeln!(
                stdout,
                "[{}] {}/{}: {}",
                recovered.timestamp, sender_jid, sender_device_id, recovered.body
            )?;
        }
        EncryptedAny::Oldmemo(encrypted) => {
            let sender_device_id = encrypted.sid;
            // Need the sender's IK in Ed25519 form. The OMEMO 0.3
            // KEX wire only carries Curve25519, so we fetch the
            // sender's published OMEMO 0.3 bundle to recover the
            // sign bit.
            let kind = inbound_kind_oldmemo(&encrypted, device_id)
                .context("classify inbound (oldmemo)")?;
            let body_bytes = match kind {
                InboundOldKind::Kex => {
                    let sender_bundle =
                        fetch_old_bundle(&mut client, Some(sender_jid.clone()), sender_device_id)
                            .await
                            .context("fetch sender oldmemo bundle for IK lookup")?;
                    receive_first_message_oldmemo(
                        &mut store,
                        &encrypted,
                        device_id,
                        sender_jid.as_str(),
                        sender_device_id,
                        sender_bundle.identity_key_ed,
                        TrustPolicy::Tofu,
                        random_priv_provider(16),
                    )
                    .context("receive_first_message_oldmemo")?
                }
                InboundOldKind::Follow => receive_followup_oldmemo(
                    &mut store,
                    &encrypted,
                    device_id,
                    sender_jid.as_str(),
                    sender_device_id,
                    random_priv_provider(16),
                )
                .context("receive_followup_oldmemo")?,
            };
            let _added = replenish_opks(&mut store, REPLENISH_TARGET, &mut OsRng)?;
            publish_my_bundle(&store, &mut client, device_id).await.ok();
            client.send_end().await.ok();
            let body =
                String::from_utf8(body_bytes).context("oldmemo body is not valid UTF-8")?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{}/{}: {}", sender_jid, sender_device_id, body)?;
        }
    }
    Ok(())
}

/// Build a `Box<dyn DhPrivProvider>` filled with random 32-byte privs.
/// Sized to outlast any single ratchet step the call site might
/// trigger. Production callers will eventually replace this with a
/// real `OsRng`-backed priv provider that doesn't materialise all
/// the bytes up front.
fn random_priv_provider(count: usize) -> Box<dyn omemo_doubleratchet::dh_ratchet::DhPrivProvider> {
    let privs: Vec<[u8; 32]> = (0..count)
        .map(|_| {
            let mut p = [0u8; 32];
            OsRng.fill_bytes(&mut p);
            p
        })
        .collect();
    omemo_twomemo::fixed_priv_provider(privs)
}
