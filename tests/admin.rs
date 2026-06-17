//! Integration tests for the administrative listener.
//!
//! Exercises the metrics exposition, liveness, and readiness endpoints served
//! on the dedicated admin bind address.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Empty};
use hyper::header::CONTENT_TYPE;
use hyper::{HeaderMap, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use palisade::{AdminState, LoadBalancer, Metrics, serve_admin};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Spawns the admin listener on an ephemeral port and returns its address.
async fn spawn_admin(balancer: LoadBalancer, metrics: Arc<Metrics>) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind admin listener");
    let addr = listener.local_addr().unwrap();

    let state = AdminState {
        metrics,
        balancer,
        request_semaphore: Arc::new(Semaphore::new(100)),
        concurrency_limit: 100,
        connection_semaphore: Arc::new(Semaphore::new(1000)),
        max_connections: 1000,
    };

    tokio::spawn(serve_admin(listener, state));
    addr
}

/// A throwaway HTTP client for probing the admin endpoints.
fn admin_client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Builds a balancer over a single dummy upstream; the admin endpoints only
/// read health flags, so no backend is ever contacted.
fn dummy_balancer() -> LoadBalancer {
    let config = test_config("127.0.0.1:9".parse().unwrap());
    test_balancer(&config)
}

/// Issues a GET to the admin listener and returns the status, headers, and body.
async fn get(addr: SocketAddr, path: &str) -> (StatusCode, HeaderMap, String) {
    let uri = format!("http://{addr}{path}").parse().unwrap();
    let resp = admin_client().get(uri).await.expect("admin request failed");
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn livez_returns_ok() {
    init_tracing();
    let addr = spawn_admin(dummy_balancer(), Arc::new(Metrics::new())).await;
    let (status, _headers, body) = get(addr, "/livez").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn readyz_reflects_upstream_health() {
    init_tracing();
    let balancer = dummy_balancer();
    let addr = spawn_admin(balancer.clone(), Arc::new(Metrics::new())).await;

    let (status, _h, _b) = get(addr, "/readyz").await;
    assert_eq!(status, StatusCode::OK, "ready while an upstream is healthy");

    balancer.pool().all()[0].mark_unhealthy();
    let (status, _h, _b) = get(addr, "/readyz").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "not ready once every upstream is ejected"
    );
}

#[tokio::test]
async fn unknown_path_returns_404() {
    init_tracing();
    let addr = spawn_admin(dummy_balancer(), Arc::new(Metrics::new())).await;
    let (status, _h, _b) = get(addr, "/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_endpoint_exposes_recorded_series() {
    init_tracing();
    let metrics = Arc::new(Metrics::new());
    metrics.record_response(200, Duration::from_millis(5));
    metrics.record_rate_limited();

    let addr = spawn_admin(dummy_balancer(), Arc::clone(&metrics)).await;
    let (status, headers, body) = get(addr, "/metrics").await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.contains("openmetrics")),
        "metrics must be served as OpenMetrics text"
    );

    // Counter recorded before the scrape, labelled by status code.
    assert!(body.contains("palisade_requests_total"));
    assert!(body.contains("status=\"200\""));
    // Rate-limit rejection counter.
    assert!(body.contains("palisade_rate_limited_requests_total"));
    // Latency histogram series.
    assert!(body.contains("palisade_request_duration_seconds_bucket"));
    assert!(body.contains("palisade_request_duration_seconds_count"));
    // Live gauges refreshed from runtime state at scrape time.
    assert!(body.contains("palisade_in_flight_requests"));
    assert!(body.contains("palisade_open_connections"));
    assert!(body.contains("palisade_upstream_healthy"));
}
