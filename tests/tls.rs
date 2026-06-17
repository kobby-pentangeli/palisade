//! Integration tests for TLS termination and origination.
//!
//! Verifies that the proxy correctly handles HTTPS on both the inbound
//! (client -> proxy) and outbound (proxy -> upstream) legs, using
//! self-signed certificates generated at test time via [`rcgen`].

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use palisade::server::{ServerState, serve, spawn_health_checker};
use palisade::{Config, LoadBalancer, TlsConfig, UpstreamConfig, UpstreamPool, handle_request};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};

/// Launches the proxy accept loop behind the given TLS acceptor, forwarding
/// to a plain-HTTP backend. Returns the proxy address and a shutdown sender.
async fn spawn_tls_proxy(
    backend_addr: SocketAddr,
    tls_acceptor: tokio_rustls::TlsAcceptor,
) -> (SocketAddr, oneshot::Sender<()>) {
    let config = Arc::new(
        Config {
            upstreams: vec![UpstreamConfig {
                address: format!("http://{backend_addr}"),
                weight: 1,
            }],
            ..Default::default()
        }
        .into_runtime()
        .expect("valid test config"),
    );

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("failed to bind proxy listener");
    let addr = listener.local_addr().unwrap();

    let balancer = test_balancer(&config);
    let concurrency_limit = config.max_concurrent_requests;
    let semaphore = Arc::new(Semaphore::new(concurrency_limit));

    let state = ServerState {
        config: Arc::clone(&config),
        balancer,
        semaphore,
        concurrency_limit,
        rate_limiter: None,
        tls_acceptor: Some(tls_acceptor),
    };

    let (tx, rx) = oneshot::channel::<()>();
    let client = test_client();
    tokio::spawn(async move {
        serve(listener, client, state, async move {
            let _ = rx.await;
        })
        .await;
    });

    (addr, tx)
}

/// Builds a client that trusts `cert_pem`, offering either `h2`+`http/1.1`
/// or only `http/1.1` over ALPN depending on `offer_h2`.
fn alpn_client(
    cert_pem: &str,
    offer_h2: bool,
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, http_body_util::Empty<Bytes>> {
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

    let builder = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http();
    let connector = if offer_h2 {
        builder.enable_all_versions().build()
    } else {
        builder.enable_http1().build()
    };

    Client::builder(TokioExecutor::new()).build(connector)
}

#[tokio::test]
async fn alpn_negotiates_http2_over_tls() {
    init_tracing();
    let (cert_pem, key_pem) = generate_test_cert();
    let cert_path = write_temp_file("alpn-h2-cert", &cert_pem);
    let key_path = write_temp_file("alpn-h2-key", &key_pem);

    let tls_acceptor = palisade::tls::build_tls_acceptor(&TlsConfig {
        cert_path: cert_path.to_str().unwrap().into(),
        key_path: key_path.to_str().unwrap().into(),
    })
    .unwrap();

    let (backend_addr, _backend) = start_backend(StatusCode::OK, "text/plain", "h2-ok").await;
    let (proxy_addr, _shutdown) = spawn_tls_proxy(backend_addr, tls_acceptor).await;

    let client = alpn_client(&cert_pem, true);
    let resp = client
        .get(
            format!("https://localhost:{}/", proxy_addr.port())
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.version(),
        hyper::Version::HTTP_2,
        "ALPN should negotiate HTTP/2 with an h2-capable client"
    );
    let body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from("h2-ok"));

    std::fs::remove_file(&cert_path).ok();
    std::fs::remove_file(&key_path).ok();
}

#[tokio::test]
async fn http1_served_over_tls_when_h2_not_offered() {
    init_tracing();
    let (cert_pem, key_pem) = generate_test_cert();
    let cert_path = write_temp_file("alpn-h1-cert", &cert_pem);
    let key_path = write_temp_file("alpn-h1-key", &key_pem);

    let tls_acceptor = palisade::tls::build_tls_acceptor(&TlsConfig {
        cert_path: cert_path.to_str().unwrap().into(),
        key_path: key_path.to_str().unwrap().into(),
    })
    .unwrap();

    let (backend_addr, _backend) = start_backend(StatusCode::OK, "text/plain", "h1-ok").await;
    let (proxy_addr, _shutdown) = spawn_tls_proxy(backend_addr, tls_acceptor).await;

    let client = alpn_client(&cert_pem, false);
    let resp = client
        .get(
            format!("https://localhost:{}/", proxy_addr.port())
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.version(),
        hyper::Version::HTTP_11,
        "a client offering only http/1.1 must still be served over HTTP/1.1"
    );
    let body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from("h1-ok"));

    std::fs::remove_file(&cert_path).ok();
    std::fs::remove_file(&key_path).ok();
}

#[tokio::test]
async fn proxies_to_http2_upstream() {
    init_tracing();
    let (cert_pem, key_pem) = generate_test_cert();
    let (addr, _shutdown) = start_alpn_tls_backend(&cert_pem, &key_pem).await;

    let config = Arc::new(
        Config {
            upstreams: vec![UpstreamConfig {
                address: format!("https://localhost:{}", addr.port()),
                weight: 1,
            }],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let client = test_h2_https_client(&cert_pem);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost:{}/", addr.port()))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let balancer = test_balancer(&config);
    let resp = handle_request(req, client, config, balancer, test_addr(), false, None)
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp.into_body()).await;
    assert_eq!(
        body,
        Bytes::from("HTTP/2.0"),
        "proxy should multiplex to the upstream over HTTP/2"
    );
}

#[tokio::test]
async fn tls_origination_forwards_to_https_upstream() {
    init_tracing();
    let (cert_pem, key_pem) = generate_test_cert();
    let (addr, _shutdown) = start_tls_backend(
        &cert_pem,
        &key_pem,
        StatusCode::OK,
        "text/plain",
        "tls-hello",
    )
    .await;

    let config = Arc::new(
        Config {
            upstreams: vec![UpstreamConfig {
                address: format!("https://localhost:{}", addr.port()),
                weight: 1,
            }],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let client = test_https_client(&cert_pem);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost:{}/", addr.port()))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let balancer = test_balancer(&config);
    let resp = handle_request(req, client, config, balancer, test_addr(), false, None)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("tls-hello"));
}

#[tokio::test]
async fn https_health_check_probes_tls_backend() {
    init_tracing();
    let (cert_pem, key_pem) = generate_test_cert();
    let (addr, _shutdown) =
        start_tls_backend(&cert_pem, &key_pem, StatusCode::OK, "text/plain", "ok").await;

    let config = Arc::new(
        Config {
            upstreams: vec![UpstreamConfig {
                address: format!("https://localhost:{}", addr.port()),
                weight: 1,
            }],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    // Eject the backend so a successful probe must transition it back.
    balancer.pool().all()[0].mark_unhealthy();
    assert!(!balancer.pool().all()[0].is_healthy());

    let probe_client = test_https_probe_client(&cert_pem);
    let handle = spawn_health_checker(
        balancer.clone(),
        probe_client,
        Duration::from_millis(50),
        "/health",
        3,
        1,
        Duration::from_secs(2),
    );

    let mut recovered = false;
    for _ in 0..40 {
        if balancer.pool().all()[0].is_healthy() {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.abort();

    assert!(
        recovered,
        "HTTPS health check should probe the TLS backend over TLS and recover it"
    );
}

#[tokio::test]
async fn tls_termination_acceptor_loads_valid_certs() {
    let (cert_pem, key_pem) = generate_test_cert();
    let cert_path = write_temp_file("cert", &cert_pem);
    let key_path = write_temp_file("key", &key_pem);

    let tls_config = TlsConfig {
        cert_path: cert_path.to_str().unwrap().into(),
        key_path: key_path.to_str().unwrap().into(),
    };

    let result = palisade::tls::build_tls_acceptor(&tls_config);
    assert!(result.is_ok(), "should build TLS acceptor from valid certs");

    std::fs::remove_file(&cert_path).ok();
    std::fs::remove_file(&key_path).ok();
}

#[tokio::test]
async fn tls_termination_rejects_missing_cert_file() {
    let tls_config = TlsConfig {
        cert_path: "/nonexistent/cert.pem".into(),
        key_path: "/nonexistent/key.pem".into(),
    };

    let result = palisade::tls::build_tls_acceptor(&tls_config);
    assert!(result.is_err(), "should fail with missing cert file");
}

#[tokio::test]
async fn tls_termination_serves_https_connection() {
    init_tracing();
    let (cert_pem, key_pem) = generate_test_cert();
    let cert_path = write_temp_file("e2e-cert", &cert_pem);
    let key_path = write_temp_file("e2e-key", &key_pem);

    let tls_config = TlsConfig {
        cert_path: cert_path.to_str().unwrap().into(),
        key_path: key_path.to_str().unwrap().into(),
    };
    let tls_acceptor = palisade::tls::build_tls_acceptor(&tls_config).unwrap();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let (backend_addr, _backend_shutdown) =
        start_backend(StatusCode::OK, "text/plain", "tls-termination-ok").await;

    let config = Arc::new(
        Config {
            upstreams: vec![UpstreamConfig {
                address: format!("http://{backend_addr}"),
                weight: 1,
            }],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );
    let client = test_client();
    let balancer = test_balancer(&config);

    tokio::spawn(async move {
        let (stream, client_addr) = listener.accept().await.unwrap();
        let tls_stream = tls_acceptor.accept(stream).await.unwrap();

        let config = Arc::clone(&config);
        let service = service_fn(move |req: Request<Incoming>| {
            let client = client.clone();
            let config = Arc::clone(&config);
            let balancer = balancer.clone();
            async move {
                let resp = handle_request(req, client, config, balancer, client_addr, true, None)
                    .await
                    .unwrap_or_else(|e| {
                        e.into_response().map(|b| {
                            b.map_err(|never| -> Box<dyn std::error::Error + Send + Sync> {
                                match never {}
                            })
                            .boxed()
                        })
                    });
                Ok::<_, std::convert::Infallible>(resp)
            }
        });

        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(tls_stream), service)
            .await;
    });

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
    let client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(client_tls)
        .https_or_http()
        .enable_http1()
        .build();
    let https_client: hyper_util::client::legacy::Client<_, http_body_util::Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let resp = https_client
        .get(
            format!("https://localhost:{}/", proxy_addr.port())
                .parse()
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from("tls-termination-ok"));

    std::fs::remove_file(&cert_path).ok();
    std::fs::remove_file(&key_path).ok();
}
