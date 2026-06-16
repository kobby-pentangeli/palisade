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
use hyper_util::rt::{TokioExecutor, TokioIo};
use palisade::server::spawn_health_checker;
use palisade::{Config, LoadBalancer, TlsConfig, UpstreamConfig, UpstreamPool, handle_request};
use tokio::net::TcpListener;

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
    let resp = handle_request(req, client, config, balancer, test_addr(), None)
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
                let resp = handle_request(req, client, config, balancer, client_addr, None)
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
