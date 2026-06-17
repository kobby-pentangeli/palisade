//! Integration tests for rate limiting.
//!
//! Verifies that the proxy enforces rate limits keyed by client IP,
//! returns 429 with a `Retry-After` header when exceeded, passes
//! requests through when within limits, and behaves correctly when
//! rate limiting is disabled.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::Bytes;
use common::*;
use hyper::{Method, Request, StatusCode};
use palisade::config::RateLimitConfig;
use palisade::{IpRateLimiter, handle_request};

#[inline]
fn rate_limiter_from_config(c: &RateLimitConfig) -> IpRateLimiter {
    IpRateLimiter::from_config(c).expect("failed to create rate limiter from config")
}

#[tokio::test]
async fn requests_within_limit_succeed() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    let limiter = rate_limiter_from_config(&RateLimitConfig {
        requests_per_second: 10,
        burst: 10,
    });

    for _ in 0..5 {
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
            Some(&limiter),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn requests_exceeding_burst_returns_429() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    let limiter = rate_limiter_from_config(&RateLimitConfig {
        requests_per_second: 1,
        burst: 2,
    });

    // First two requests consume the burst tokens.
    for _ in 0..2 {
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
            Some(&limiter),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Third request should exceed the burst.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let err = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        Some(&limiter),
    )
    .await
    .unwrap_err();

    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        resp.headers().contains_key("retry-after"),
        "429 response must include retry-after header"
    );
}

#[tokio::test]
async fn rate_limit_is_per_ip() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    let limiter = rate_limiter_from_config(&RateLimitConfig {
        requests_per_second: 1,
        burst: 1,
    });

    let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345);
    let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 12345);

    // Exhaust the bucket for IP A.
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
        addr_a,
        false,
        Some(&limiter),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // IP A is now rate limited.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let err = handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        addr_a,
        false,
        Some(&limiter),
    )
    .await
    .unwrap_err();
    assert_eq!(err.into_response().status(), StatusCode::TOO_MANY_REQUESTS);

    // IP B should still be allowed.
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
        addr_b,
        false,
        Some(&limiter),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn no_rate_limiter_passes_all_requests() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    for _ in 0..10 {
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
    }
}

#[tokio::test]
async fn rate_limit_recovery_after_wait() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "ok").await;
    let config = test_config(addr);

    let limiter = rate_limiter_from_config(&RateLimitConfig {
        requests_per_second: 10,
        burst: 1,
    });

    // Exhaust the single burst token.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    handle_request(
        req,
        test_client(),
        config.clone(),
        test_balancer(&config),
        test_addr(),
        false,
        Some(&limiter),
    )
    .await
    .unwrap();

    // Immediately rate limited.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}/"))
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    assert!(
        handle_request(
            req,
            test_client(),
            config.clone(),
            test_balancer(&config),
            test_addr(),
            false,
            Some(&limiter),
        )
        .await
        .is_err()
    );

    // Wait for the token to replenish (100ms at 10 rps).
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Should succeed again.
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
        Some(&limiter),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn retain_recent_preserves_active_entries() {
    let limiter = rate_limiter_from_config(&RateLimitConfig {
        requests_per_second: 100,
        burst: 100,
    });

    // Generate traffic from several IPs, all touched microseconds ago.
    for i in 1..=5u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        let _ = limiter.check(&ip);
    }

    assert_eq!(limiter.tracked_ip_count(), 5);

    // Cleanup must keep entries still inside the tracking window; pruning a
    // freshly-active IP would drop its rate-limit state and let it burst again.
    limiter.retain_recent();
    assert_eq!(limiter.tracked_ip_count(), 5);
}
