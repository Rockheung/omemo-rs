//! Prometheus exporter (P3-4).
//!
//! Disabled by default. Opt in with `--metrics-bind HOST:PORT`
//! on the daemon CLI; the daemon then exposes `/metrics` over
//! HTTP using the prometheus text exposition format.
//!
//! Counters tick on protocol events (sent / received / error /
//! pending_trust / ik_drift / outbox_replays / spk_rotations);
//! gauges are refreshed by the daemon's bundle-health timer.

use std::sync::Arc;

use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicI64;

/// Backend label for counters / gauges that split across
/// twomemo (OMEMO 2) and oldmemo (OMEMO 0.3).
#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BackendLabel {
    pub backend: &'static str,
}

/// Error-kind label for the `omemo_errors_total` counter.
#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ErrorLabel {
    pub kind: String,
}

/// All counters / gauges the daemon writes to.
///
/// Wrapped in an `Arc` so the daemon can clone references into
/// its event-handling fast paths cheaply. `prometheus_client`'s
/// metric types are themselves cheaply cloneable (atomic
/// pointers internally), so cloning the struct is cheap.
#[derive(Clone)]
pub struct DaemonMetrics {
    pub sent_total: Family<BackendLabel, Counter>,
    pub received_total: Family<BackendLabel, Counter>,
    pub errors_total: Family<ErrorLabel, Counter>,
    pub pending_trust_total: Counter,
    pub ik_drift_total: Counter,
    pub outbox_replays_total: Counter,
    pub spk_rotations_total: Counter,
    pub opk_pool_size: Gauge<i64, AtomicI64>,
    pub active_sessions: Family<BackendLabel, Gauge<i64, AtomicI64>>,
    pub joined_mucs: Gauge<i64, AtomicI64>,
    pub outbox_pending: Gauge<i64, AtomicI64>,
}

impl Default for DaemonMetrics {
    fn default() -> Self {
        Self {
            sent_total: Family::default(),
            received_total: Family::default(),
            errors_total: Family::default(),
            pending_trust_total: Counter::default(),
            ik_drift_total: Counter::default(),
            outbox_replays_total: Counter::default(),
            spk_rotations_total: Counter::default(),
            opk_pool_size: Gauge::default(),
            active_sessions: Family::default(),
            joined_mucs: Gauge::default(),
            outbox_pending: Gauge::default(),
        }
    }
}

impl DaemonMetrics {
    /// Wire every metric into a fresh Registry. Returns the
    /// registry the HTTP handler renders.
    pub fn registry(&self) -> Registry {
        let mut r = Registry::default();
        // prometheus_client's text encoder auto-suffixes
        // counters with `_total` per the OpenMetrics spec —
        // register the bare name (without _total) here so the
        // emitted metric is `omemo_sent_total`, not
        // `omemo_sent_total_total`.
        r.register(
            "omemo_sent",
            "OMEMO messages successfully encrypted and sent",
            self.sent_total.clone(),
        );
        r.register(
            "omemo_received",
            "OMEMO messages successfully decrypted",
            self.received_total.clone(),
        );
        r.register(
            "omemo_errors",
            "Error events emitted on stdout, by kind",
            self.errors_total.clone(),
        );
        r.register(
            "omemo_pending_trust",
            "pending_trust events emitted (manual policy first-sight)",
            self.pending_trust_total.clone(),
        );
        r.register(
            "omemo_ik_drift",
            "ik_drift events emitted (peer device's IK changed)",
            self.ik_drift_total.clone(),
        );
        r.register(
            "omemo_outbox_replays",
            "Outbox rows replayed at daemon startup",
            self.outbox_replays_total.clone(),
        );
        r.register(
            "omemo_spk_rotations",
            "Signed prekey rotations performed",
            self.spk_rotations_total.clone(),
        );
        r.register(
            "omemo_opk_pool_size",
            "Unconsumed one-time prekeys remaining",
            self.opk_pool_size.clone(),
        );
        r.register(
            "omemo_active_sessions",
            "Active per-peer-device sessions, by backend",
            self.active_sessions.clone(),
        );
        r.register(
            "omemo_joined_mucs",
            "Number of MUC rooms the daemon has joined",
            self.joined_mucs.clone(),
        );
        r.register(
            "omemo_outbox_pending",
            "Outbox rows waiting to send (or replay)",
            self.outbox_pending.clone(),
        );
        r
    }
}

/// Spawn a tiny HTTP server on `bind` that serves `/metrics`.
/// Anything else returns 404. Returns immediately after the
/// listener is up; failures are logged on stderr only —
/// metrics aren't critical-path so we don't refuse to start
/// the daemon over a busy port.
pub async fn serve_metrics(
    bind: std::net::SocketAddr,
    metrics: DaemonMetrics,
) -> anyhow::Result<()> {
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let registry = Arc::new(metrics.registry());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(bind = %bind, "metrics endpoint listening on /metrics");

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "metrics accept failed");
                    continue;
                }
            };
            let registry = registry.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let registry = registry.clone();
                    async move {
                        if req.uri().path() != "/metrics" {
                            return Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(404)
                                    .body(Full::new(Bytes::from_static(b"not found")))
                                    .unwrap(),
                            );
                        }
                        let mut buf = String::new();
                        if let Err(e) = encode(&mut buf, &registry) {
                            tracing::warn!(error = %e, "metrics encode failed");
                        }
                        Ok(Response::builder()
                            .status(200)
                            .header(
                                "Content-Type",
                                "application/openmetrics-text; version=1.0.0; charset=utf-8",
                            )
                            .body(Full::new(Bytes::from(buf)))
                            .unwrap())
                    }
                });
                if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await
                {
                    tracing::debug!(error = %e, "metrics conn ended");
                }
            });
        }
    });
    Ok(())
}
