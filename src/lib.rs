//! An HTTP reverse proxy built on [hyper], [tokio], and [rustls].
//!
//! This crate provides the core proxy logic: configuration loading with
//! pre-compiled regex patterns, request forwarding with body streaming,
//! header and parameter blocking for GET requests, sensitive data
//! masking in response bodies, weighted round-robin load balancing with
//! passive and active health checks, structured observability via [tracing],
//! configurable timeouts, connection pool tuning, concurrency limiting,
//! per-IP rate limiting, and graceful shutdown.
//!
//! Every inbound request is assigned a monotonic request ID, injected
//! into the response as an `X-Request-Id` header, and wrapped in a
//! [`tracing::Span`] carrying the request method, URI, and client
//! address as structured fields.
//!
//! # Example
//!
//! Load a YAML configuration, build an HTTP client, and forward a single
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
//!     let config = Config::load_from_file("Config.yml")
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

pub mod balancer;
pub mod config;
pub mod error;
pub mod headers;
pub mod proxy;
pub mod rate_limit;
pub mod server;
pub mod tls;
pub mod upstream;

pub use balancer::LoadBalancer;
pub use config::{
    Config, HealthCheckConfig, PoolConfig, RateLimitConfig, RuntimeConfig, TimeoutsConfig,
    TlsConfig, UpstreamConfig,
};
pub use error::ProxyError;
pub use proxy::{
    BoxBody, HttpClient, HttpsClient, build_client, build_https_client, handle_request,
};
pub use rate_limit::IpRateLimiter;
pub use upstream::{UpstreamPool, UpstreamState};

pub type Result<T> = std::result::Result<T, ProxyError>;
