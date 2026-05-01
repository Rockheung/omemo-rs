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
pub use omemo_stanza::{Bundle, Device, DeviceList, PreKey, SignedPreKey};
pub use tokio_xmpp::{connect::DnsConfig, xmlstream::Timeouts, Client, Event};

mod pep;
pub use pep::{
    fetch_bundle, fetch_device_list, publish_bundle, publish_device_list, PepError, BUNDLES_NODE,
    DEVICES_NODE, ITEM_ID_CURRENT,
};

/// Build a `tokio-xmpp` client that connects in cleartext to a fixed
/// `host:port` socket address.
///
/// **Localhost integration tests only.** Anything reachable over the
/// public network MUST use [`tokio_xmpp::Client::new`] (StartTLS + SRV).
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
