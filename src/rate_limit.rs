//! Per-IP rate limiting using the GCRA (Generic Cell Rate Algorithm).
//!
//! Wraps the [`governor`] crate's keyed rate limiter to enforce a configurable
//! requests-per-second limit per client IP address. Each unique IP gets its
//! own token bucket with the configured sustained rate and burst capacity.
//!
//! Stale entries for IPs that have not been seen recently are periodically
//! pruned via [`IpRateLimiter::retain_recent`], which should be called from
//! a background task to prevent unbounded memory growth under high-cardinality
//! traffic.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};

use crate::{ProxyError, RateLimitConfig, Result};

/// The concrete governor rate limiter type keyed by client IP address.
type InnerLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock, NoOpMiddleware>;

/// A thread-safe, per-IP rate limiter backed by a GCRA token bucket.
///
/// Constructed from a [`RateLimitConfig`] at startup and shared across all
/// request handlers via `Arc`. The limiter is lock-free for the hot path
/// (`check_key`) and uses a `DashMap` internally for concurrent access.
#[derive(Debug, Clone)]
pub struct IpRateLimiter {
    inner: Arc<InnerLimiter>,
}

impl IpRateLimiter {
    /// Creates a new rate limiter from the given configuration.
    ///
    /// The quota is set to `requests_per_second` sustained rate with
    /// `burst` additional tokens available for traffic spikes.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Internal`] if `requests_per_second` or `burst`
    /// is zero. Configuration loaded through [`Config::into_runtime`] rejects
    /// these at startup, so this path is unreachable for validated config.
    ///
    /// [`Config::into_runtime`]: crate::Config::into_runtime
    pub fn from_config(config: &RateLimitConfig) -> Result<Self> {
        let rps = NonZeroU32::new(config.requests_per_second)
            .ok_or_else(|| ProxyError::Internal("requests_per_second must be non-zero".into()))?;
        let burst = NonZeroU32::new(config.burst)
            .ok_or_else(|| ProxyError::Internal("burst must be non-zero".into()))?;

        let quota = Quota::per_second(rps).allow_burst(burst);
        let limiter = RateLimiter::dashmap(quota);

        Ok(Self {
            inner: Arc::new(limiter),
        })
    }

    /// Checks whether the given IP address is within its rate limit.
    ///
    /// Returns `Ok(())` if the request is allowed, or `Err(retry_after_ms)`
    /// with the estimated wait time in milliseconds if the limit is exceeded.
    pub fn check(&self, ip: &IpAddr) -> std::result::Result<(), u64> {
        self.inner.check_key(ip).map_err(|not_until| {
            not_until
                .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()))
                .as_millis() as u64
        })
    }

    /// Removes entries for IP addresses that have not been seen within the
    /// rate limiter's internal tracking window.
    ///
    /// Should be called periodically from a background task to prevent
    /// unbounded memory growth under high-cardinality traffic patterns.
    pub fn retain_recent(&self) {
        self.inner.retain_recent();
    }

    /// Returns the number of IP addresses currently tracked by the limiter.
    pub fn tracked_ip_count(&self) -> usize {
        self.inner.len()
    }
}
