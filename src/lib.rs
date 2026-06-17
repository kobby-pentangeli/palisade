//! An HTTP reverse proxy built on [hyper], [tokio], and [rustls].
//!
//! This crate provides the core proxy logic: configuration loading with
//! pre-compiled regex patterns, request forwarding with body streaming,
//! header and parameter blocking across all methods, sensitive data
//! masking in response bodies, weighted round-robin load balancing with
//! passive and active health checks, structured observability via [tracing],
//! configurable timeouts, connection pool tuning, concurrency limiting,
//! per-IP rate limiting, and graceful shutdown.
//!
//! Production observability is served on a separate admin listener
//! ([`serve_admin`]): Prometheus metrics ([`Metrics`]) at `/metrics`, plus
//! liveness and readiness probes. The admin bind address is kept distinct
//! from the data-plane listener so operational endpoints are never reachable
//! by proxy clients.
//!
//! Every inbound request is assigned a request ID---a validated inbound
//! `X-Request-Id` when the client supplies one, otherwise a monotonic
//! per-process counter---injected into the response as an `X-Request-Id`
//! header, and wrapped in a [`tracing::Span`] carrying the request method,
//! URI, and client address as structured fields.
//!
//! # Example
//!
//! Load a TOML configuration, build an HTTP client, and forward a single
//! request programmatically:
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//!
//! use palisade::{
//!     Config, LoadBalancer, UpstreamPool, build_client, handle_request,
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = Config::load_from_file("config.toml")
//!         .and_then(|c| c.into_runtime())
//!         .expect("valid configuration");
//!
//!     let client = build_client(&config);
//!     let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
//!     let balancer = LoadBalancer::new(pool);
//!     let config = Arc::new(config);
//!
//!     let req = hyper::Request::builder()
//!         .uri("http://localhost/hello")
//!         .body(http_body_util::Empty::<bytes::Bytes>::new())
//!         .unwrap();
//!
//!     let resp = handle_request(
//!         req,
//!         client,
//!         config,
//!         balancer,
//!         SocketAddr::from(([127, 0, 0, 1], 0)),
//!         false,
//!         None,
//!     )
//!     .await
//!     .expect("proxy succeeded");
//!
//!     println!("status: {}", resp.status());
//! }
//! ```
//!
//! [hyper]: https://hyper.rs/
//! [tokio]: https://tokio.rs/
//! [rustls]: https://docs.rs/rustls
//! [tracing]: https://docs.rs/tracing

pub mod admin;
pub mod balancer;
pub mod config;
pub mod error;
pub mod headers;
pub mod metrics;
pub mod proxy;
pub mod rate_limit;
pub mod server;
pub mod tls;
pub mod upstream;

pub use admin::{AdminState, serve_admin};
pub use balancer::LoadBalancer;
pub use config::{
    AdminConfig, Config, HealthCheckConfig, PoolConfig, RateLimitConfig, RuntimeConfig,
    TimeoutsConfig, TlsConfig, UpstreamConfig,
};
pub use error::ProxyError;
pub use metrics::Metrics;
pub use proxy::{
    BoxBody, HttpClient, HttpsClient, build_client, build_https_client, handle_request,
};
pub use rate_limit::IpRateLimiter;
pub use upstream::{UpstreamPool, UpstreamState};

pub type Result<T> = std::result::Result<T, ProxyError>;
