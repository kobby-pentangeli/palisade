//! Integration tests for the core HTTP proxy pipeline.
//!
//! Exercises request forwarding, method handling, header/parameter blocking,
//! response masking, hop-by-hop stripping, body size limits, timeouts, and
//! `X-Request-Id` injection against throwaway local backends.

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use http_body_util::Full;
use hyper::{Method, Request, StatusCode};
use palisade::{Config, handle_request};

#[tokio::test]
async fn get_request_forwards_to_upstream() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "hello").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/path?q=1"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("hello"));
}

#[tokio::test]
async fn post_request_forwards_to_upstream() {
    init_tracing();
    let (addr, _shutdown) =
        start_backend(StatusCode::CREATED, "application/json", r#"{"id":1}"#).await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/resource"))
        .body(Full::new(Bytes::from(r#"{"name":"test"}"#)))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn post_with_blocked_header_returns_403() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "should not reach").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/resource"))
        .header("x-blocked", "present")
        .body(Full::new(Bytes::from(r#"{"name":"test"}"#)))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_with_blocked_param_returns_403() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "should not reach").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/resource?secret_key=abc"))
        .body(Full::new(Bytes::from("payload")))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_request_forwards_to_upstream() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "updated").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("http://{addr}/resource/1"))
        .body(Full::new(Bytes::from("new content")))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_request_forwards_to_upstream() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::NO_CONTENT, "text/plain", "").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("http://{addr}/resource/1"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn upstream_preserves_status_code() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::NOT_FOUND, "text/plain", "not found").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/missing"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_blocked_header_returns_403() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "should not reach").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("x-blocked", "present")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_blocked_param_returns_403() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "should not reach").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/?secret_key=abc"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn blocked_param_substring_is_allowed() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    // `test_config` blocks `secret_key`; a parameter that merely contains it
    // as a substring must not be treated as a match.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/?my_secret_key=abc"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn response_body_masking_replaces_sensitive_params() {
    init_tracing();
    let (addr, _shutdown) = start_backend(
        StatusCode::OK,
        "application/x-www-form-urlencoded",
        "user=alice&password=hunter2&ssn=123-45-6789",
    )
    .await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);

    assert!(body_str.contains("password=****"));
    assert!(body_str.contains("ssn=****"));
    assert!(body_str.contains("user=alice"));
}

#[tokio::test]
async fn response_body_not_masked_for_json_content_type() {
    init_tracing();
    let (addr, _shutdown) = start_backend(
        StatusCode::OK,
        "application/json",
        r#"{"password":"secret"}"#,
    )
    .await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from(r#"{"password":"secret"}"#));
}

#[tokio::test]
async fn no_masking_when_mask_rules_empty() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "password=visible").await;

    let config = Arc::new(
        Config {
            upstreams: single_upstream(addr),
            masked_params: vec![],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("password=visible"));
}

#[tokio::test]
async fn smuggling_attempt_returns_400() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "unreachable").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/"))
        .header("content-length", "5")
        .header("transfer-encoding", "chunked")
        .body(Full::new(Bytes::from("hello")))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn body_too_large_returns_413() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "unreachable").await;
    let config = test_config_with_body_limit(addr, 100);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/"))
        .header("content-length", "1000")
        .body(Full::new(Bytes::from("x".repeat(1000))))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn body_within_limit_succeeds() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config_with_body_limit(addr, 1000);

    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/"))
        .header("content-length", "5")
        .body(Full::new(Bytes::from("hello")))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn oversized_body_without_content_length_returns_413() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "unreachable").await;
    let config = test_config_with_body_limit(addr, 100);

    // No declared Content-Length: the up-front header check is bypassed, so
    // the streaming length limit must reject the oversized body mid-flight.
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}/"))
        .body(Full::new(Bytes::from("x".repeat(1000))))
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn response_above_masking_ceiling_streams_unmasked() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "password=secret123").await;
    // Ceiling of 4 bytes is smaller than the 18-byte response body, so the
    // proxy streams it through unmasked rather than buffering it.
    let config = test_config_with_mask_ceiling(addr, 4);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("password=secret123"));
}

#[tokio::test]
async fn response_within_masking_ceiling_is_masked() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "password=secret123").await;
    let config = test_config_with_mask_ceiling(addr, 1024);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("password=****"));
}

#[tokio::test]
async fn forwarding_headers_injected_to_upstream() {
    init_tracing();
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/test"))
        .header("host", "client-facing.example.com")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains("x-forwarded-for: 192.168.1.100"),
        "missing x-forwarded-for in: {body_str}"
    );
    assert!(
        body_str.contains("x-forwarded-proto: http"),
        "missing x-forwarded-proto in: {body_str}"
    );
    assert!(
        body_str.contains("x-forwarded-host: client-facing.example.com"),
        "missing x-forwarded-host in: {body_str}"
    );
}

#[tokio::test]
async fn forwarded_proto_is_https_under_tls_termination() {
    init_tracing();
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/test"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    // `client_tls = true` models an inbound connection terminated by the proxy.
    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        true,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains("x-forwarded-proto: https"),
        "expected https forwarded proto in: {body_str}"
    );
}

#[tokio::test]
async fn spoofed_forwarded_for_replaced_by_default() {
    init_tracing();
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/test"))
        .header("x-forwarded-for", "1.2.3.4")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains("x-forwarded-for: 192.168.1.100"),
        "expected observed client address in: {body_str}"
    );
    assert!(
        !body_str.contains("1.2.3.4"),
        "spoofed forwarded-for must be discarded: {body_str}"
    );
}

#[tokio::test]
async fn forwarded_for_appended_when_trusted() {
    init_tracing();
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config_trusting_forwarded(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/test"))
        .header("x-forwarded-for", "1.2.3.4")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains("x-forwarded-for: 1.2.3.4, 192.168.1.100"),
        "expected appended forwarded-for chain in: {body_str}"
    );
}

#[tokio::test]
async fn host_header_rewritten_to_upstream() {
    init_tracing();
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("host", "original-host.com")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains(&format!("host: {addr}")),
        "host should be rewritten to upstream authority, got: {body_str}"
    );
}

#[tokio::test]
async fn hop_by_hop_headers_stripped_from_request() {
    init_tracing();
    let (addr, _shutdown) = start_echo_headers_backend().await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("connection", "keep-alive")
        .header("keep-alive", "timeout=5")
        .header("proxy-authorization", "Bearer token123")
        .header("x-custom", "preserved")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        !body_str.contains("connection:"),
        "connection header should be stripped: {body_str}"
    );
    assert!(
        !body_str.contains("keep-alive:"),
        "keep-alive header should be stripped: {body_str}"
    );
    assert!(
        !body_str.contains("proxy-authorization:"),
        "proxy-authorization should be stripped: {body_str}"
    );
    assert!(
        body_str.contains("x-custom: preserved"),
        "x-custom should be preserved: {body_str}"
    );
}

#[tokio::test]
async fn response_strips_internal_and_hop_by_hop_headers() {
    init_tracing();
    let (addr, _shutdown) = start_leaky_backend().await;
    let config = test_config_with_stripping(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();

    assert!(
        !resp.headers().contains_key("server"),
        "server header should be stripped"
    );
    assert!(
        !resp.headers().contains_key("x-powered-by"),
        "x-powered-by header should be stripped"
    );
    assert!(
        !resp.headers().contains_key("connection"),
        "connection hop-by-hop header should be stripped"
    );
    assert!(
        !resp.headers().contains_key("keep-alive"),
        "keep-alive hop-by-hop header should be stripped"
    );
    assert!(resp.headers().contains_key("content-type"));
}

#[tokio::test]
async fn request_timeout_returns_504() {
    init_tracing();
    let (addr, _shutdown) = start_slow_backend(Duration::from_secs(5)).await;
    let config = test_config_with_timeout(addr, 100);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
}

#[tokio::test]
async fn request_within_timeout_succeeds() {
    init_tracing();
    let (addr, _shutdown) = start_slow_backend(Duration::from_millis(10)).await;
    let config = test_config_with_timeout(addr, 5000);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("slow"));
}

#[tokio::test]
async fn response_includes_x_request_id() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();

    let request_id = resp
        .headers()
        .get("x-request-id")
        .expect("response must include x-request-id header");

    let id_value = request_id
        .to_str()
        .expect("x-request-id must be valid UTF-8")
        .parse::<u64>()
        .expect("x-request-id must be a numeric value");

    assert!(id_value > 0, "request id should be a positive integer");
}

#[tokio::test]
async fn propagates_valid_inbound_x_request_id() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("x-request-id", "trace-abc-123")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        resp.headers().get("x-request-id").unwrap(),
        "trace-abc-123",
        "a well-formed inbound correlation id must be echoed unchanged"
    );
}

#[tokio::test]
async fn malformed_inbound_x_request_id_falls_back_to_counter() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    // A 200-character id exceeds the accepted length bound and is rejected.
    let oversized = "x".repeat(200);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .header("x-request-id", oversized.clone())
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        None,
    )
    .await
    .unwrap();

    let echoed = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert_ne!(echoed, oversized, "an oversized id must not be propagated");
    assert!(
        echoed.parse::<u64>().is_ok(),
        "a rejected id must fall back to the numeric counter"
    );
}

#[tokio::test]
async fn x_request_id_increments_across_requests() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    let mut ids = Vec::new();
    for _ in 0..3 {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{addr}/"))
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();

        let resp = handle_request(
            req,
            test_client(),
            config.clone(),
            test_balancer(&config),
            test_addr(),
            false,
            None,
        )
        .await
        .unwrap();

        let id = resp
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        ids.push(id);
    }

    assert!(
        ids[1] > ids[0],
        "request IDs must be monotonically increasing"
    );
    assert!(
        ids[2] > ids[1],
        "request IDs must be monotonically increasing"
    );
}
