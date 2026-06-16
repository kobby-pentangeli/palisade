//! Integration tests for load balancing, passive health tracking, and
//! multi-upstream request distribution.
//!
//! Verifies that the proxy distributes requests across multiple backends
//! according to configured weights, marks unhealthy backends after
//! consecutive failures, and recovers once backends return to health.

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::*;
use hyper::{Method, Request, StatusCode};
use palisade::{
    Config, LoadBalancer, TimeoutsConfig, UpstreamConfig, UpstreamPool, handle_request,
};

#[tokio::test]
async fn requests_distributed_across_multiple_backends() {
    init_tracing();

    let (addr1, _s1) = start_backend(StatusCode::OK, "text/plain", "backend-1").await;
    let (addr2, _s2) = start_backend(StatusCode::OK, "text/plain", "backend-2").await;

    let config = Arc::new(
        Config {
            upstreams: vec![
                UpstreamConfig {
                    address: format!("http://{addr1}"),
                    weight: 1,
                },
                UpstreamConfig {
                    address: format!("http://{addr2}"),
                    weight: 1,
                },
            ],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    let mut bodies = Vec::new();
    for _ in 0..4 {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://any-host/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();

        let resp = handle_request(
            req,
            test_client(),
            config.clone(),
            balancer.clone(),
            test_addr(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect_body(resp.into_body()).await;
        bodies.push(String::from_utf8_lossy(&body).to_string());
    }

    let b1_count = bodies.iter().filter(|b| *b == "backend-1").count();
    let b2_count = bodies.iter().filter(|b| *b == "backend-2").count();
    assert_eq!(
        b1_count, 2,
        "expected 2 requests to backend-1, got {b1_count}"
    );
    assert_eq!(
        b2_count, 2,
        "expected 2 requests to backend-2, got {b2_count}"
    );
}

#[tokio::test]
async fn weighted_distribution_sends_more_to_heavier_backend() {
    init_tracing();

    let (addr1, _s1) = start_backend(StatusCode::OK, "text/plain", "heavy").await;
    let (addr2, _s2) = start_backend(StatusCode::OK, "text/plain", "light").await;

    let config = Arc::new(
        Config {
            upstreams: vec![
                UpstreamConfig {
                    address: format!("http://{addr1}"),
                    weight: 3,
                },
                UpstreamConfig {
                    address: format!("http://{addr2}"),
                    weight: 1,
                },
            ],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    let mut heavy_count = 0u32;
    let mut light_count = 0u32;

    for _ in 0..40 {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://any-host/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();

        let resp = handle_request(
            req,
            test_client(),
            config.clone(),
            balancer.clone(),
            test_addr(),
            None,
        )
        .await
        .unwrap();
        let body = collect_body(resp.into_body()).await;
        if body == "heavy" {
            heavy_count += 1;
        } else {
            light_count += 1;
        }
    }

    assert_eq!(heavy_count, 30, "expected 30 requests to heavy backend");
    assert_eq!(light_count, 10, "expected 10 requests to light backend");
}

#[tokio::test]
async fn unhealthy_backend_is_skipped() {
    init_tracing();

    let (addr_good, _s1) = start_backend(StatusCode::OK, "text/plain", "good").await;
    // Use an address that won't be reachable (port 1 on localhost is
    // typically refused immediately, triggering a connection error).
    let addr_bad = "127.0.0.1:1";

    let config = Arc::new(
        Config {
            upstreams: vec![
                UpstreamConfig {
                    address: format!("http://{addr_bad}"),
                    weight: 1,
                },
                UpstreamConfig {
                    address: format!("http://{addr_good}"),
                    weight: 1,
                },
            ],
            timeouts: TimeoutsConfig {
                request: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    // Pre-mark the bad backend as unhealthy so all requests hit the good one.
    balancer.pool().all()[0].mark_unhealthy();

    for _ in 0..4 {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://any-host/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();

        let resp = handle_request(
            req,
            test_client(),
            config.clone(),
            balancer.clone(),
            test_addr(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect_body(resp.into_body()).await;
        assert_eq!(body, Bytes::from("good"));
    }
}

#[tokio::test]
async fn all_backends_unhealthy_returns_503() {
    init_tracing();

    let config = Arc::new(
        Config {
            upstreams: vec![
                UpstreamConfig {
                    address: "http://127.0.0.1:1".into(),
                    weight: 1,
                },
                UpstreamConfig {
                    address: "http://127.0.0.1:2".into(),
                    weight: 1,
                },
            ],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    balancer.pool().all()[0].mark_unhealthy();
    balancer.pool().all()[1].mark_unhealthy();

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://any-host/")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let err = handle_request(req, test_client(), config, balancer, test_addr(), None)
        .await
        .unwrap_err();
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn recovered_backend_receives_traffic_again() {
    init_tracing();

    let (addr1, _s1) = start_backend(StatusCode::OK, "text/plain", "backend-1").await;
    let (addr2, _s2) = start_backend(StatusCode::OK, "text/plain", "backend-2").await;

    let config = Arc::new(
        Config {
            upstreams: vec![
                UpstreamConfig {
                    address: format!("http://{addr1}"),
                    weight: 1,
                },
                UpstreamConfig {
                    address: format!("http://{addr2}"),
                    weight: 1,
                },
            ],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    // Mark backend-1 unhealthy.
    balancer.pool().all()[0].mark_unhealthy();

    // All traffic should go to backend-2.
    let req = Request::builder()
        .method(Method::GET)
        .uri("http://any-host/")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();
    let resp = handle_request(
        req,
        test_client(),
        config.clone(),
        balancer.clone(),
        test_addr(),
        None,
    )
    .await
    .unwrap();
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("backend-2"));

    // Recover backend-1.
    balancer.pool().all()[0].mark_healthy();

    // Now both should receive traffic again.
    let mut saw_b1 = false;
    let mut saw_b2 = false;
    for _ in 0..4 {
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://any-host/")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = handle_request(
            req,
            test_client(),
            config.clone(),
            balancer.clone(),
            test_addr(),
            None,
        )
        .await
        .unwrap();
        let body = collect_body(resp.into_body()).await;
        match body.as_ref() {
            b"backend-1" => saw_b1 = true,
            b"backend-2" => saw_b2 = true,
            _ => panic!("unexpected body: {body:?}"),
        }
    }

    assert!(saw_b1, "backend-1 should receive traffic after recovery");
    assert!(saw_b2, "backend-2 should still receive traffic");
}

#[tokio::test]
async fn single_upstream_routes_all_traffic() {
    init_tracing();
    let (addr, _shutdown) = start_backend(StatusCode::OK, "text/plain", "single").await;

    let config = Arc::new(
        Config {
            upstreams: vec![UpstreamConfig {
                address: format!("http://{addr}"),
                weight: 1,
            }],
            ..Default::default()
        }
        .into_runtime()
        .expect("test config"),
    );

    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    let req = Request::builder()
        .method(Method::GET)
        .uri("http://any-host/")
        .body(http_body_util::Empty::<Bytes>::new())
        .unwrap();

    let resp = handle_request(req, test_client(), config, balancer, test_addr(), None)
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = collect_body(resp.into_body()).await;
    assert_eq!(body, Bytes::from("single"));
}
