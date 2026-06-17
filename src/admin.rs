//! Administrative listener exposing metrics and health probes.
//!
//! Runs on a bind address distinct from the proxy data plane so that
//! Prometheus scrapes and orchestrator probes are never reachable through the
//! client-facing listener (the configuration layer rejects a shared address).
//! Serves three routes:
//!
//! - `GET /metrics` — OpenMetrics exposition of the proxy metrics.
//! - `GET /livez` — process liveness; `200 OK` while the server is running.
//! - `GET /readyz` — readiness; `200 OK` when at least one upstream is
//!   healthy, otherwise `503 Service Unavailable`.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::{LoadBalancer, Metrics};

/// Shared state for the admin listener.
pub struct AdminState {
    /// Metrics registry refreshed and encoded on each `/metrics` scrape.
    pub metrics: Arc<Metrics>,
    /// Balancer whose pool backs the readiness probe and health gauges.
    pub balancer: LoadBalancer,
    /// In-flight request limiter, read to derive the saturation gauge.
    pub request_semaphore: Arc<Semaphore>,
    /// Configured in-flight request ceiling.
    pub concurrency_limit: usize,
    /// Open-connection limiter, read to derive the connection gauge.
    pub connection_semaphore: Arc<Semaphore>,
    /// Configured open-connection ceiling.
    pub max_connections: usize,
}

/// Serves the admin endpoints on `listener` until the task is cancelled.
///
/// Each connection is handled by the automatic HTTP/1.1-or-HTTP/2 builder with
/// a header-read timeout to bound slow-header connections.
pub async fn serve_admin(listener: TcpListener, state: AdminState) {
    let state = Arc::new(state);

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10));
    builder.http2().timer(TokioTimer::new());

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                warn!(%e, "admin: failed to accept connection");
                continue;
            }
        };

        let state = Arc::clone(&state);
        let builder = builder.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let state = Arc::clone(&state);
                async move { Ok::<_, Infallible>(route(&req, &state)) }
            });
            if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                debug!(%e, "admin connection error");
            }
        });
    }
}

/// Routes an admin request to the matching handler.
fn route(req: &Request<Incoming>, state: &AdminState) -> Response<Full<Bytes>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => metrics_response(state),
        (&Method::GET, "/livez") => text_response(StatusCode::OK, "ok"),
        (&Method::GET, "/readyz") => readiness_response(state),
        _ => text_response(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Refreshes the live gauges from current runtime state and encodes the
/// metrics registry in the OpenMetrics text format.
fn metrics_response(state: &AdminState) -> Response<Full<Bytes>> {
    let in_flight = state
        .concurrency_limit
        .saturating_sub(state.request_semaphore.available_permits());
    let open = state
        .max_connections
        .saturating_sub(state.connection_semaphore.available_permits());

    state
        .metrics
        .set_in_flight(i64::try_from(in_flight).unwrap_or(i64::MAX));
    state
        .metrics
        .set_open_connections(i64::try_from(open).unwrap_or(i64::MAX));
    for backend in state.balancer.pool().all() {
        state
            .metrics
            .set_upstream_healthy(&backend.uri().to_string(), backend.is_healthy());
    }

    let body = state.metrics.encode();
    Response::builder()
        .status(StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| text_response(StatusCode::INTERNAL_SERVER_ERROR, "encode error"))
}

/// Answers a readiness probe: ready when at least one upstream is healthy.
fn readiness_response(state: &AdminState) -> Response<Full<Bytes>> {
    let ready = state
        .balancer
        .pool()
        .all()
        .iter()
        .any(|backend| backend.is_healthy());
    if ready {
        text_response(StatusCode::OK, "ready")
    } else {
        text_response(StatusCode::SERVICE_UNAVAILABLE, "no healthy upstreams")
    }
}

/// Builds a plain-text response with the given status and static body.
fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("static admin response must build")
}
