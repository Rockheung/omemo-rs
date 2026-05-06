//! XMPP integration layer for OMEMO 2.
//!
//! Stage 4 (`omemo-pep`) is the first crate in the workspace that touches
//! the network. It glues `omemo-twomemo` (crypto + wire format) and
//! `omemo-stanza` (XEP-0384 envelope) onto a real XMPP stream via
//! `tokio-xmpp` 5.0.
//!
//! Current capabilities:
//! * Plaintext connect helper for localhost integration tests.
//! * PEP publish/fetch for the OMEMO 2 device list
//!   (`urn:xmpp:omemo:2:devices`).
//!
//! Planned (next sub-tasks): bundle publish/fetch, stanza interceptors
//! (encrypt/decrypt `<message>`), trust-on-first-use device acceptance,
//! StartTLS for production use.
//!
//! Licence note: depends on MPL-2.0 crates (`tokio-xmpp`, `xmpp-parsers`,
//! `jid`) per ADR-007. Our own code remains MIT.

pub use jid::BareJid;
pub use omemo_stanza::axolotl_stanza::{
    Bundle as OldBundle, DeviceList as OldDeviceList, Encrypted as OldEncrypted,
    KeyEntry as OldKeyEntry, PreKey as OldPreKey,
};
pub use omemo_stanza::{
    Bundle, Device, DeviceList, Encrypted, Key, KeysGroup, PreKey, SignedPreKey,
};
pub use omemo_session::Backend;
pub use tokio_xmpp::{connect::DnsConfig, xmlstream::Timeouts, Client, Event, Stanza};

mod message;
mod message_old;
mod muc;
mod pep;
mod store;
mod store_old;
mod wire;

pub use message::{
    bootstrap_active_session_from_bundle, decrypt_inbound_kex, decrypt_message, encrypt_message,
    inbound_kind, InboundKind, KexCarrier, MessageError, Recipient,
};
pub use message_old::{
    bootstrap_active_session_oldmemo_from_bundle, decrypt_inbound_kex_oldmemo,
    decrypt_message_oldmemo, encrypt_message_oldmemo, inbound_kind_oldmemo, InboundOldKind,
    KexCarrierOld, MessageOldError, RecipientOld,
};
pub use muc::{MucError, MucEvent, MucRoom, Occupant};
pub use pep::{
    fetch_bundle, fetch_device_list, fetch_old_bundle, fetch_old_device_list, publish_bundle,
    publish_device_list, publish_old_bundle, publish_old_device_list, PepError, BUNDLES_NODE,
    DEVICES_NODE, ITEM_ID_CURRENT, OLD_BUNDLES_NODE_PREFIX, OLD_DEVICES_NODE,
};
pub use store::{
    bootstrap_and_save_active, bundle_from_store, encrypt_to_peer, encrypt_to_peers,
    install_identity, install_identity_random, publish_my_bundle, receive_first_message,
    receive_followup, replenish_opks, x3dh_state_from_store, IdentitySeed, InboundEnvelope,
    PeerSpec, StoreFlowError, TrustPolicy,
};
pub use store_old::{
    bootstrap_and_save_active_oldmemo, encrypt_to_peer_oldmemo, old_bundle_from_store,
    receive_first_message_oldmemo, receive_followup_oldmemo,
};
pub use wire::{
    parse_encrypted_message, send_encrypted, send_encrypted_old, wait_for_encrypted,
    wait_for_encrypted_any, EncryptedAny, WireError,
};

pub use omemo_session::{
    OutboxEntry, OutboxKind, OwnIdentity, SessionStoreError, Store, TrustState, TrustedDevice,
};

/// Build a `tokio-xmpp` client that connects in cleartext to a fixed
/// `host:port` socket address.
///
/// **Localhost integration tests only.** Anything reachable over the
/// public network MUST use [`connect_starttls`] (or compose
/// [`tokio_xmpp::Client::new_starttls`] yourself).
///
/// `addr` is parsed by `tokio-xmpp` as a `SocketAddr`-style string,
/// e.g. `"127.0.0.1:5222"`.
pub fn connect_plaintext(
    jid: BareJid,
    password: impl Into<String>,
    addr: impl Into<String>,
) -> Client {
    let dns_config = DnsConfig::Addr { addr: addr.into() };
    Client::new_plaintext(jid, password, dns_config, Timeouts::default())
}

/// Build a production `tokio-xmpp` client. Resolves the server via
/// `_xmpp-client._tcp.<domain>` SRV (with the standard fallback to
/// `<domain>:5222`), upgrades the cleartext stream via XMPP StartTLS
/// (RFC 6120 §5), and validates the server certificate against the OS
/// trust roots (`rustls-native-certs` + `aws_lc_rs`).
///
/// Use this for any non-localhost deployment.
pub fn connect_starttls(jid: BareJid, password: impl Into<String>) -> Client {
    Client::new(jid, password)
}

/// StartTLS variant that bypasses SRV and connects to an explicit
/// `host:port`. Useful for staging deployments that do not publish
/// SRV records and for self-hosted servers behind a load balancer.
/// Production should prefer [`connect_starttls`].
pub fn connect_starttls_addr(
    jid: BareJid,
    password: impl Into<String>,
    addr: impl Into<String>,
) -> Client {
    let dns_config = DnsConfig::Addr { addr: addr.into() };
    Client::new_starttls(jid, password, dns_config, Timeouts::default())
}
