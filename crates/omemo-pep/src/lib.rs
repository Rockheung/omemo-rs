//! XMPP integration layer for OMEMO 2.
//!
//! Stage 4 (`omemo-pep`) is the first crate in the workspace that touches
//! the network. It will eventually own:
//!
//! * PEP (XEP-0163) publish/fetch for own `urn:xmpp:omemo:2:devices` and
//!   `urn:xmpp:omemo:2:bundles:{deviceId}` nodes.
//! * Stanza interceptors that wrap/unwrap `<encrypted>` on outbound /
//!   inbound `<message>` (delegating crypto to `omemo-twomemo`).
//! * SCE envelope wrap/unwrap (already in `omemo-stanza::sce`).
//!
//! This first cut exposes only a thin transport convenience: a plaintext
//! connect helper for localhost integration tests. Production code on
//! the public network must use StartTLS and SRV resolution; that path
//! comes online when we wire up real PEP flows.
//!
//! Licence note: depends on MPL-2.0 crates (`tokio-xmpp`, `xmpp-parsers`,
//! `jid`) per ADR-007. Our own code remains MIT.

pub use jid::BareJid;
pub use tokio_xmpp::{connect::DnsConfig, xmlstream::Timeouts, Client, Event};

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
