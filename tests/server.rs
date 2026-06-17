//! Integration tests for connection-level resource bounding.
//!
//! Drives the real accept loop ([`serve`]) over a TCP socket to verify the
//! maximum-connection ceiling and the header-read timeout that together
//! bound slow-connection (slowloris) resource exhaustion.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use hyper::StatusCode;
use palisade::server::{ServerState, serve};
use palisade::{Config, UpstreamConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};

/// Launches the proxy accept loop on an ephemeral port, returning its address
/// and a shutdown sender (dropping the sender drains the server).
async fn spawn_proxy(config: Config) -> (SocketAddr, oneshot::Sender<()>) {
    let config = Arc::new(config.into_runtime().expect("valid test config"));
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
        tls_acceptor: None,
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

#[tokio::test]
async fn connection_cap_drops_excess_connections() {
    init_tracing();
    let (backend_addr, _backend) = start_slow_backend(Duration::from_secs(1)).await;

    let config = Config {
        upstreams: vec![UpstreamConfig {
            address: format!("http://{backend_addr}"),
            weight: 1,
        }],
        max_connections: Some(1),
        ..Default::default()
    };
    let (proxy_addr, _shutdown) = spawn_proxy(config).await;

    // Connection A occupies the single permit with an in-flight slow request.
    let mut conn_a = TcpStream::connect(proxy_addr).await.unwrap();
    conn_a
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Connection B exceeds the cap and must be closed without a response.
    let mut conn_b = TcpStream::connect(proxy_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let result = tokio::time::timeout(Duration::from_secs(2), conn_b.read(&mut buf)).await;
    let closed = matches!(result, Ok(Ok(0)) | Ok(Err(_)));
    assert!(
        closed,
        "second connection should be closed at the connection cap, got {result:?}"
    );

    drop(conn_a);
}

#[tokio::test]
async fn graceful_shutdown_closes_idle_keepalive_connection() {
    init_tracing();
    let (backend_addr, _backend) = start_backend(StatusCode::OK, "text/plain", "ok").await;

    let config = Config {
        upstreams: vec![UpstreamConfig {
            address: format!("http://{backend_addr}"),
            weight: 1,
        }],
        ..Default::default()
    };
    let (proxy_addr, shutdown) = spawn_proxy(config).await;

    // Issue one request and read the response, leaving the keep-alive
    // connection open and idle.
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0, "expected a response on the keep-alive connection");
    assert!(
        String::from_utf8_lossy(&buf[..n]).contains("200 OK"),
        "expected a 200 response before shutdown"
    );

    // Initiating shutdown must gracefully close the idle connection well
    // within the drain window rather than holding it until the timeout.
    drop(shutdown);

    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut rest)).await;
    assert!(
        closed.is_ok(),
        "graceful shutdown should close the idle keep-alive connection within the window"
    );
}

#[tokio::test]
async fn header_read_timeout_closes_stalled_connection() {
    init_tracing();
    let (backend_addr, _backend) = start_backend(StatusCode::OK, "text/plain", "ok").await;

    let config = Config {
        upstreams: vec![UpstreamConfig {
            address: format!("http://{backend_addr}"),
            weight: 1,
        }],
        header_read_timeout: Some(1),
        ..Default::default()
    };
    let (proxy_addr, _shutdown) = spawn_proxy(config).await;

    // Send an incomplete header block and stall: the proxy must close the
    // connection once the header-read timeout elapses rather than waiting
    // indefinitely.
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
    assert!(
        result.is_ok(),
        "header-read timeout should close the stalled connection within the window"
    );
}
