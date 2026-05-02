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
pub use omemo_stanza::{
    Bundle, Device, DeviceList, Encrypted, Key, KeysGroup, PreKey, SignedPreKey,
};
pub use tokio_xmpp::{connect::DnsConfig, xmlstream::Timeouts, Client, Event};

mod message;
mod muc;
mod pep;
mod store;
mod wire;

pub use message::{
    bootstrap_active_session_from_bundle, decrypt_inbound_kex, decrypt_message, encrypt_message,
    inbound_kind, InboundKind, KexCarrier, MessageError, Recipient,
};
pub use muc::{MucError, MucEvent, MucRoom, Occupant};
pub use pep::{
    fetch_bundle, fetch_device_list, publish_bundle, publish_device_list, PepError, BUNDLES_NODE,
    DEVICES_NODE, ITEM_ID_CURRENT,
};
pub use store::{
    bootstrap_and_save_active, bundle_from_store, encrypt_to_peer, install_identity,
    receive_first_message, receive_followup, x3dh_state_from_store, IdentitySeed, InboundEnvelope,
    StoreFlowError, TrustPolicy,
};
pub use wire::{send_encrypted, wait_for_encrypted, WireError};

pub use omemo_session::{OwnIdentity, SessionStoreError, Store, TrustState, TrustedDevice};

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
