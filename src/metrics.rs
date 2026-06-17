//! Prometheus metrics for the proxy data plane.
//!
//! Defines a single [`Metrics`] registry shared between the request path and
//! the admin listener. The request path records counters and latency
//! observations as events occur; the admin listener refreshes the live gauges
//! and encodes the registry in the OpenMetrics text format on each scrape.
//!
//! Every series is namespaced under `palisade_`. All recording operations are
//! atomic and lock-free, so instrumentation adds no contention to the hot
//! path.

use std::time::Duration;

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

/// Latency histogram buckets in seconds, spanning sub-millisecond responses to
/// a ten-second tail so both fast and slow upstreams are resolved.
const LATENCY_BUCKETS: [f64; 13] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Label set carrying the response status code for the request counter.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct StatusLabel {
    status: u16,
}

/// Label set carrying the upstream URI for per-backend health gauges.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct UpstreamLabel {
    upstream: String,
}

/// The proxy metrics registry and the handles used to record observations.
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    requests: Family<StatusLabel, Counter>,
    request_duration_seconds: Histogram,
    rate_limited: Counter,
    upstream_healthy: Family<UpstreamLabel, Gauge>,
    in_flight_requests: Gauge,
    open_connections: Gauge,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Builds a new metrics registry with every series registered under the
    /// `palisade` namespace.
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("palisade");

        let requests = Family::<StatusLabel, Counter>::default();
        registry.register(
            "requests",
            "Responses served, labelled by HTTP status code",
            requests.clone(),
        );

        let request_duration_seconds = Histogram::new(LATENCY_BUCKETS);
        registry.register(
            "request_duration_seconds",
            "End-to-end request handling latency in seconds",
            request_duration_seconds.clone(),
        );

        let rate_limited = Counter::default();
        registry.register(
            "rate_limited_requests",
            "Requests rejected by the per-IP rate limiter",
            rate_limited.clone(),
        );

        let upstream_healthy = Family::<UpstreamLabel, Gauge>::default();
        registry.register(
            "upstream_healthy",
            "Upstream backend health (1 = healthy, 0 = unhealthy)",
            upstream_healthy.clone(),
        );

        let in_flight_requests = Gauge::default();
        registry.register(
            "in_flight_requests",
            "Requests currently being processed",
            in_flight_requests.clone(),
        );

        let open_connections = Gauge::default();
        registry.register(
            "open_connections",
            "Client connections currently open",
            open_connections.clone(),
        );

        Self {
            registry,
            requests,
            request_duration_seconds,
            rate_limited,
            upstream_healthy,
            in_flight_requests,
            open_connections,
        }
    }

    /// Records a served response: increments the per-status counter and
    /// observes the end-to-end handling latency.
    pub fn record_response(&self, status: u16, latency: Duration) {
        self.requests.get_or_create(&StatusLabel { status }).inc();
        self.request_duration_seconds.observe(latency.as_secs_f64());
    }

    /// Records a request rejected by the per-IP rate limiter.
    pub fn record_rate_limited(&self) {
        self.rate_limited.inc();
    }

    /// Sets the gauge of in-flight requests to the given live value.
    pub fn set_in_flight(&self, value: i64) {
        self.in_flight_requests.set(value);
    }

    /// Sets the gauge of open client connections to the given live value.
    pub fn set_open_connections(&self, value: i64) {
        self.open_connections.set(value);
    }

    /// Sets the health gauge for a single upstream backend.
    pub fn set_upstream_healthy(&self, upstream: &str, healthy: bool) {
        self.upstream_healthy
            .get_or_create(&UpstreamLabel {
                upstream: upstream.to_owned(),
            })
            .set(i64::from(healthy));
    }

    /// Encodes the registry in the OpenMetrics text exposition format.
    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        // Writing into a `String` is infallible, so the encode result cannot error.
        let _ = encode(&mut buffer, &self.registry);
        buffer
    }
}
