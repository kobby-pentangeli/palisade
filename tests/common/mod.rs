//! Shared test infrastructure for integration tests.
//!
//! Provides throwaway HTTP and TLS backend servers, configuration
//! builders, client constructors, and utility functions used across
//! all integration test modules.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use palisade::{
    BoxBody, Config, HttpClient, LoadBalancer, RuntimeConfig, UpstreamConfig, UpstreamPool,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A synthetic client address used in all test invocations.
const TEST_CLIENT_ADDR: &str = "192.168.1.100:54321";

/// Initializes a tracing subscriber for test output.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("debug")
        .try_init();
}

pub fn test_addr() -> SocketAddr {
    TEST_CLIENT_ADDR.parse().unwrap()
}

pub fn test_client() -> HttpClient {
    Client::builder(TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new())
}

/// Collects a [`BoxBody`] into [`Bytes`], mapping any body error to a
/// descriptive panic so test assertions remain concise.
pub async fn collect_body(body: BoxBody) -> Bytes {
    body.collect()
        .await
        .expect("failed to collect response body")
        .to_bytes()
}

/// Wraps a single address into the upstream config list.
pub fn single_upstream(addr: SocketAddr) -> Vec<UpstreamConfig> {
    vec![UpstreamConfig {
        address: format!("http://{addr}"),
        weight: 1,
    }]
}

/// Builds a `RuntimeConfig` targeting the given local backend address.
pub fn test_config(addr: SocketAddr) -> Arc<RuntimeConfig> {
    Arc::new(
        Config {
            upstreams: single_upstream(addr),
            blocked_headers: vec!["x-blocked".into()],
            blocked_params: vec!["secret_key".into()],
            masked_params: vec!["password".into(), "ssn".into()],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

/// Builds a `RuntimeConfig` with response header stripping enabled.
pub fn test_config_with_stripping(addr: SocketAddr) -> Arc<RuntimeConfig> {
    Arc::new(
        Config {
            upstreams: single_upstream(addr),
            strip_response_headers: vec!["server".into(), "x-powered-by".into()],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

/// Builds a `RuntimeConfig` with a specific body size limit.
pub fn test_config_with_body_limit(addr: SocketAddr, limit: u64) -> Arc<RuntimeConfig> {
    Arc::new(
        Config {
            upstreams: single_upstream(addr),
            max_body_size: Some(limit),
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

/// Builds a `RuntimeConfig` that masks `password` but only buffers responses
/// up to `ceiling` bytes for masking.
pub fn test_config_with_mask_ceiling(addr: SocketAddr, ceiling: u64) -> Arc<RuntimeConfig> {
    Arc::new(
        Config {
            upstreams: single_upstream(addr),
            masked_params: vec!["password".into()],
            mask_max_body_size: Some(ceiling),
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

/// Builds a `RuntimeConfig` with a short request timeout for testing.
///
/// `timeout_ms` is accepted in milliseconds for test ergonomics but
/// converted to whole seconds (rounded up) for the config layer.
pub fn test_config_with_timeout(addr: SocketAddr, timeout_ms: u64) -> Arc<RuntimeConfig> {
    use palisade::TimeoutsConfig;

    let timeout_secs = timeout_ms.div_ceil(1000).max(1);

    Arc::new(
        Config {
            upstreams: single_upstream(addr),
            timeouts: TimeoutsConfig {
                request: timeout_secs,
                ..Default::default()
            },
            ..Default::default()
        }
        .into_runtime()
        .expect("test config must be valid"),
    )
}

/// Builds a [`LoadBalancer`] backed by the upstream(s) in the given config.
pub fn test_balancer(config: &RuntimeConfig) -> LoadBalancer {
    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    LoadBalancer::new(pool)
}

/// Starts a local HTTP server that responds to every request with the given
/// status, content-type, and body. Returns the server address and a handle
/// to shut it down.
pub async fn start_backend(
    status: StatusCode,
    content_type: &'static str,
    body: &'static str,
) -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind test backend");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut shutdown = std::pin::pin!(async {
            let _ = rx.await;
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.expect("accept failed");
                    let service = service_fn(move |_req: Request<Incoming>| {
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(status)
                                    .header("content-type", content_type)
                                    .body(Full::new(Bytes::from(body)))
                                    .expect("test response must build"),
                            )
                        }
                    });
                    tokio::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
                () = &mut shutdown => break,
            }
        }
    });

    (addr, tx)
}

/// Starts a local backend that captures and echoes request headers as the
/// response body. Used to verify that the proxy correctly transforms headers.
pub async fn start_echo_headers_backend() -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind test backend");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut shutdown = std::pin::pin!(async {
            let _ = rx.await;
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.expect("accept failed");
                    let service = service_fn(|req: Request<Incoming>| async move {
                        let mut lines = Vec::new();
                        for (name, value) in req.headers() {
                            if let Ok(v) = value.to_str() {
                                lines.push(format!("{}: {}", name.as_str(), v));
                            }
                        }
                        lines.sort();
                        let body = lines.join("\n");
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from(body)))
                                .expect("test response must build"),
                        )
                    });
                    tokio::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
                () = &mut shutdown => break,
            }
        }
    });

    (addr, tx)
}

/// Starts a backend that returns responses with internal implementation headers.
pub async fn start_leaky_backend() -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind test backend");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut shutdown = std::pin::pin!(async {
            let _ = rx.await;
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.expect("accept failed");
                    let service = service_fn(|_req: Request<Incoming>| async {
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain")
                                .header("server", "Apache/2.4.52")
                                .header("x-powered-by", "PHP/8.1")
                                .header("connection", "keep-alive")
                                .header("keep-alive", "timeout=5")
                                .body(Full::new(Bytes::from("ok")))
                                .expect("test response must build"),
                        )
                    });
                    tokio::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
                () = &mut shutdown => break,
            }
        }
    });

    (addr, tx)
}

/// Starts a backend that sleeps for the given duration before responding.
pub async fn start_slow_backend(delay: Duration) -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind test backend");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut shutdown = std::pin::pin!(async {
            let _ = rx.await;
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.expect("accept failed");
                    let service = service_fn(move |_req: Request<Incoming>| async move {
                        tokio::time::sleep(delay).await;
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from("slow")))
                                .expect("test response must build"),
                        )
                    });
                    tokio::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
                () = &mut shutdown => break,
            }
        }
    });

    (addr, tx)
}

/// Generates a self-signed certificate and private key for testing.
/// Returns (certificate PEM, private key PEM).
pub fn generate_test_cert() -> (String, String) {
    let subject_alt_names = vec!["localhost".into(), "127.0.0.1".into()];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();
    (cert_pem, key_pem)
}

/// Writes `content` to a temporary file and returns its path.
pub fn write_temp_file(prefix: &str, content: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("reverse-proxy-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{prefix}-{}.pem", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}

/// Starts a TLS-enabled backend using the given cert and key PEM data.
pub async fn start_tls_backend(
    cert_pem: &str,
    key_pem: &str,
    status: StatusCode,
    content_type: &'static str,
    body: &'static str,
) -> (SocketAddr, oneshot::Sender<()>) {
    let (tx, rx) = oneshot::channel::<()>();

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();

    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind TLS test backend");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut shutdown = std::pin::pin!(async {
            let _ = rx.await;
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result.expect("accept failed");
                    let tls_acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        let tls_stream = match tls_acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        let service = service_fn(move |_req: Request<Incoming>| {
                            async move {
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .header("content-type", content_type)
                                        .body(Full::new(Bytes::from(body)))
                                        .expect("test response must build"),
                                )
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(tls_stream), service)
                            .await;
                    });
                }
                () = &mut shutdown => break,
            }
        }
    });

    (addr, tx)
}

/// Builds an HTTPS client that trusts the given self-signed certificate.
pub fn test_https_client(cert_pem: &str) -> palisade::HttpsClient {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let cert_der: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &cert_der {
        root_store.add(cert.clone()).unwrap();
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(connector)
}

/// Builds an HTTPS probe client (empty request body) that trusts the given
/// self-signed certificate, for exercising the active health checker against
/// a TLS backend.
pub fn test_https_probe_client(
    cert_pem: &str,
) -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Empty<Bytes>,
> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let cert_der: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &cert_der {
        root_store.add(cert.clone()).unwrap();
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder(TokioExecutor::new()).build(connector)
}
