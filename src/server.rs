//! Server accept loop, background tasks, and graceful shutdown.
//!
//! Contains the runtime infrastructure that sits between the TCP listener
//! and the per-request proxy pipeline. This module is intentionally
//! decoupled from `main()` so that the server logic remains testable
//! and reusable without pulling in process-level concerns like signal
//! handling or `std::process::exit`.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::Response;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::{BoxBody, IpRateLimiter, LoadBalancer, ProxyError, RuntimeConfig, handle_request};

/// Runtime state shared across the accept loop.
pub struct ServerState {
    /// Validated proxy configuration shared by all handlers.
    pub config: Arc<RuntimeConfig>,
    /// Weighted round-robin load balancer over healthy upstream backends.
    pub balancer: LoadBalancer,
    /// Bounds the number of concurrent in-flight requests.
    pub semaphore: Arc<Semaphore>,
    /// Cached value of the semaphore capacity, used in error messages.
    pub concurrency_limit: usize,
    /// Per-IP rate limiter. `None` disables rate limiting.
    pub rate_limiter: Option<IpRateLimiter>,
    /// TLS acceptor for client-facing connections. `None` means plain HTTP.
    pub tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
}

/// Accepts connections on `listener`, optionally wrapping each in TLS, and
/// dispatches them through the proxy pipeline using the given `client` and
/// shared `state`. Generic over the client connector type so that both
/// plain-HTTP and HTTPS upstreams use the same accept loop.
///
/// Runs until `shutdown` resolves, then stops accepting new connections
/// and waits up to `shutdown_timeout` for in-flight requests to drain.
/// Any connections still active after the deadline are dropped.
pub async fn serve<C>(
    listener: TcpListener,
    client: hyper_util::client::legacy::Client<C, BoxBody>,
    state: ServerState,
    shutdown: impl Future<Output = ()>,
) where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    let ServerState {
        config,
        balancer,
        semaphore,
        concurrency_limit,
        rate_limiter,
        tls_acceptor,
    } = state;

    let shutdown_timeout = config.shutdown_timeout;
    let max_connections = config.max_connections;
    let header_read_timeout = config.header_read_timeout;
    let client_tls = tls_acceptor.is_some();
    let connection_semaphore = Arc::new(Semaphore::new(max_connections));
    let mut connections = JoinSet::new();

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, client_addr) = match result {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(%e, "failed to accept connection");
                        continue;
                    }
                };

                if let Err(e) = stream.set_nodelay(true) {
                    warn!(%e, "failed to set TCP_NODELAY");
                }

                let permit = match Arc::clone(&connection_semaphore).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(
                            limit = max_connections,
                            %client_addr,
                            "max connections reached, dropping connection"
                        );
                        continue;
                    }
                };

                let client = client.clone();
                let config = Arc::clone(&config);
                let semaphore = Arc::clone(&semaphore);
                let tls_acceptor = tls_acceptor.clone();
                let balancer = balancer.clone();
                let rate_limiter = rate_limiter.clone();

                connections.spawn(async move {
                    let _permit = permit;
                    let svc = service_fn(move |req: hyper::Request<Incoming>| {
                        let client = client.clone();
                        let config = Arc::clone(&config);
                        let semaphore = Arc::clone(&semaphore);
                        let balancer = balancer.clone();
                        let rate_limiter = rate_limiter.clone();
                        async move {
                            let _permit = match semaphore.try_acquire() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!(
                                        limit = concurrency_limit,
                                        "concurrency limit reached, rejecting request"
                                    );
                                    let err = ProxyError::ServiceUnavailable {
                                        limit: concurrency_limit,
                                    };
                                    return Ok::<Response<BoxBody>, std::convert::Infallible>(
                                        err.into_response().map(|b| {
                                            b.map_err(
                                                |never| -> Box<
                                                    dyn std::error::Error + Send + Sync,
                                                > {
                                                    match never {}
                                                },
                                            )
                                            .boxed()
                                        }),
                                    );
                                }
                            };

                            let resp = handle_request(
                                req,
                                client,
                                config,
                                balancer,
                                client_addr,
                                client_tls,
                                rate_limiter.as_ref(),
                            )
                            .await
                            .unwrap_or_else(|e| {
                                e.into_response().map(|b| {
                                    b.map_err(
                                        |never| -> Box<
                                            dyn std::error::Error + Send + Sync,
                                        > {
                                            match never {}
                                        },
                                    )
                                    .boxed()
                                })
                            });
                            Ok::<Response<BoxBody>, std::convert::Infallible>(resp)
                        }
                    });

                    let mut builder = http1::Builder::new();
                    builder
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(header_read_timeout);

                    let result = match tls_acceptor {
                        Some(acceptor) => {
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!(%e, "TLS handshake failed");
                                    return;
                                }
                            };
                            builder
                                .serve_connection(TokioIo::new(tls_stream), svc)
                                .await
                        }
                        None => {
                            builder
                                .serve_connection(TokioIo::new(stream), svc)
                                .await
                        }
                    };

                    if let Err(e) = result {
                        warn!(%e, "connection error");
                    }
                });
            }
            () = &mut shutdown => {
                info!("shutting down, no longer accepting connections");
                break;
            }
        }
    }

    if !connections.is_empty() {
        let in_flight = connections.len();
        info!(
            in_flight,
            timeout = ?shutdown_timeout,
            "draining in-flight connections"
        );

        let drain_result = tokio::time::timeout(shutdown_timeout, async {
            while connections.join_next().await.is_some() {}
        })
        .await;

        if drain_result.is_err() {
            let remaining = connections.len();
            warn!(
                remaining,
                "shutdown drain timeout exceeded, aborting remaining connections"
            );
            connections.shutdown().await;
        }
    }
}

/// Spawns a background task that periodically probes each upstream backend
/// at the configured health check path, updating health state based on
/// HTTP response status.
pub fn spawn_health_checker<C>(
    balancer: LoadBalancer,
    client: hyper_util::client::legacy::Client<C, http_body_util::Empty<bytes::Bytes>>,
    interval: Duration,
    path: &str,
    failure_threshold: u32,
    healthy_threshold: u32,
    timeout: Duration,
) -> tokio::task::JoinHandle<()>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    let path = path.to_owned();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;

            for backend in balancer.pool().all() {
                let uri_str = format!(
                    "{}://{}{}",
                    backend.uri().scheme_str().unwrap_or("http"),
                    backend
                        .uri()
                        .authority()
                        .map(|a| a.as_str())
                        .unwrap_or("localhost"),
                    path,
                );

                let uri = match uri_str.parse::<hyper::Uri>() {
                    Ok(u) => u,
                    Err(e) => {
                        warn!(
                            upstream = %backend.uri(),
                            error = %e,
                            "failed to build health check URI"
                        );
                        continue;
                    }
                };

                let result = tokio::time::timeout(timeout, client.get(uri)).await;

                match result {
                    Ok(Ok(resp)) if resp.status().is_success() => {
                        let recovered = backend.record_success(healthy_threshold);
                        if recovered {
                            info!(
                                upstream = %backend.uri(),
                                "health check passed, backend recovered"
                            );
                        }
                    }
                    Ok(Ok(resp)) => {
                        let transitioned = backend.record_failure(failure_threshold);
                        warn!(
                            upstream = %backend.uri(),
                            status = resp.status().as_u16(),
                            marked_unhealthy = transitioned,
                            "health check returned non-success status"
                        );
                    }
                    Ok(Err(e)) => {
                        let transitioned = backend.record_failure(failure_threshold);
                        warn!(
                            upstream = %backend.uri(),
                            error = %e,
                            marked_unhealthy = transitioned,
                            "health check request failed"
                        );
                    }
                    Err(_) => {
                        let transitioned = backend.record_failure(failure_threshold);
                        warn!(
                            upstream = %backend.uri(),
                            marked_unhealthy = transitioned,
                            "health check timed out"
                        );
                    }
                }
            }
        }
    })
}

/// Spawns a background task that periodically prunes stale entries from the
/// rate limiter, preventing unbounded memory growth.
pub fn spawn_rate_limit_cleanup(limiter: IpRateLimiter) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let before = limiter.tracked_ip_count();
            limiter.retain_recent();
            let after = limiter.tracked_ip_count();
            if before != after {
                info!(
                    before,
                    after,
                    pruned = before - after,
                    "rate limiter cleanup completed"
                );
            }
        }
    })
}

/// Awaits a shutdown signal (SIGINT or SIGTERM on Unix, Ctrl+C on all
/// platforms). Returns once the first signal is received.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => info!("received SIGINT, initiating graceful shutdown"),
            _ = sigterm.recv() => info!("received SIGTERM, initiating graceful shutdown"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
        info!("received Ctrl+C, initiating graceful shutdown");
    }
}
