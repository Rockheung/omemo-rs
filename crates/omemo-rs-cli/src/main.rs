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
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use omemo_pep::{
    bootstrap_and_save_active, connect_plaintext, connect_starttls, connect_starttls_addr,
    encrypt_to_peer, fetch_bundle, fetch_device_list, inbound_kind, install_identity_random,
    publish_device_list, publish_my_bundle, receive_first_message, receive_followup,
    replenish_opks, send_encrypted, wait_for_encrypted, BareJid, Client, Device, DeviceList, Event,
    InboundKind, Store, TrustPolicy,
};
use rand_core::{OsRng, RngCore};

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
        #[arg(long, value_name = "u32")]
        peer_device: u32,
        /// Message body (UTF-8).
        #[arg(long)]
        body: String,
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
        } => run_send(&cli, &bare_jid, &store_path, peer, *peer_device, body).await,
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

/// Publish our device list + bundle to PEP. Idempotent — calling
/// it on every connect is fine and keeps the bundle's OPK pool
/// fresh when paired with [`replenish_opks`].
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
        .context("publish device list")?;
    publish_my_bundle(store, client, device_id)
        .await
        .context("publish bundle")?;
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
    peer_device_id: u32,
    body: &str,
) -> Result<()> {
    let mut store = open_store(store_path)?;
    let device_id = ensure_local_identity(bare_jid, &mut store, None, DEFAULT_OPK_COUNT)?;

    let peer_jid = BareJid::from_str(peer_jid_str).context("parse --peer as a bare JID")?;

    let mut client = connect(cli, bare_jid.clone()).await?;
    await_online(&mut client).await?;
    announce_presence(&mut client).await?;
    publish_identity(&mut client, &store, device_id).await?;

    // Need a session for `(peer, peer_device_id)` before encrypt_to_peer
    // can run. If absent, fetch the bundle + bootstrap_active.
    let kex = if store
        .load_session_snapshot(peer_jid.as_str(), peer_device_id)?
        .is_none()
    {
        let bundle = fetch_bundle(&mut client, Some(peer_jid.clone()), peer_device_id)
            .await
            .context("fetch peer bundle")?;
        let chosen_opk_id = bundle
            .prekeys
            .first()
            .ok_or_else(|| anyhow!("peer bundle has no OPKs left"))?
            .id;
        let mut ephemeral_priv = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_priv);
        Some(
            bootstrap_and_save_active(
                &mut store,
                peer_jid.as_str(),
                peer_device_id,
                &bundle,
                chosen_opk_id,
                ephemeral_priv,
                random_priv_provider(32),
            )
            .context("bootstrap_active_session_from_bundle")?,
        )
    } else {
        None
    };

    let encrypted = encrypt_to_peer(
        &mut store,
        device_id,
        peer_jid.as_str(),
        peer_device_id,
        body,
        kex,
        random_priv_provider(16),
    )
    .context("encrypt_to_peer")?;
    send_encrypted(&mut client, peer_jid.clone(), &encrypted)
        .await
        .context("send_encrypted")?;
    client.send_end().await.ok();
    println!(
        "Sent {} byte body to {}/{peer_device_id}",
        body.len(),
        peer_jid_str
    );
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

    let (sender_jid_opt, encrypted) = tokio::time::timeout(
        Duration::from_secs(timeout),
        wait_for_encrypted(&mut client),
    )
    .await
    .map_err(|_| anyhow!("no message arrived within {timeout}s"))?
    .context("wait_for_encrypted")?;
    let sender_jid = sender_jid_opt.ok_or_else(|| anyhow!("inbound message has no `from` JID"))?;
    let sender_device_id = encrypted.sid;

    // We don't know the peer's device list ahead of time on this code
    // path — fetch it so the inbound classifier doesn't reject (and
    // so the trust store learns about every device the peer might
    // send from in the future).
    let _ = fetch_device_list(&mut client, Some(sender_jid.clone())).await;

    let kind = inbound_kind(&encrypted, bare_jid.as_str(), device_id)
        .context("classify inbound encrypted")?;
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
        .context("receive_first_message")?,
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
        .context("receive_followup")?,
    };

    // Refill the OPK pool now that one was consumed (if KEX), then
    // republish the bundle so peers see the new entries.
    let _added = replenish_opks(&mut store, REPLENISH_TARGET, &mut OsRng)?;
    publish_my_bundle(&store, &mut client, device_id).await.ok();

    client.send_end().await.ok();
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "[{}] {}/{}: {}",
        recovered.timestamp, sender_jid, sender_device_id, recovered.body
    )?;
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
