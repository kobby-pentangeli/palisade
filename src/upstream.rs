//! Per-backend health state tracking.
//!
//! Each upstream backend is represented by an [`UpstreamState`] that holds
//! its validated URI, weight, and atomic health counters. Health transitions
//! are lock-free: consecutive failures are tracked via [`AtomicU32`] and
//! the healthy/unhealthy flag via [`AtomicBool`].
//!
//! An ejected backend recovers through one of two paths: an active health
//! check (when configured) or a cooldown-gated half-open trial. After
//! ejection the backend is held out for `cooldown`; once it elapses the
//! backend becomes eligible for a single trial request, and the balancer
//! re-arms the cooldown as it routes that trial so traffic stays bounded to
//! roughly one probe per window until a success promotes it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::ValidatedUpstream;

/// Manages the full set of upstream backends and their health states.
#[derive(Debug, Clone)]
pub struct UpstreamPool {
    backends: Arc<Vec<UpstreamState>>,
}

/// Runtime state for a single upstream backend.
#[derive(Debug, Clone)]
pub struct UpstreamState {
    state: Arc<InnerState>,
}

#[derive(Debug)]
struct InnerState {
    /// The validated upstream URI.
    uri: hyper::Uri,
    /// Relative weight for load balancing.
    weight: u32,
    /// Number of consecutive failures observed.
    consecutive_failures: AtomicU32,
    /// Number of consecutive successes observed while unhealthy.
    consecutive_successes: AtomicU32,
    /// Whether this backend is currently considered healthy.
    healthy: AtomicBool,
    /// Monotonic baseline against which cooldown timestamps are measured.
    created: Instant,
    /// Half-open cooldown length in milliseconds.
    cooldown_ms: u64,
    /// Milliseconds since [`InnerState::created`] before which no trial
    /// request may be routed to this backend while it is unhealthy.
    cooldown_until_ms: AtomicU64,
}

impl UpstreamPool {
    /// Constructs a pool from validated upstream configurations, marking
    /// all backends as initially healthy. `cooldown` is the half-open
    /// recovery window applied to every backend on ejection.
    pub fn from_validated(upstreams: &[ValidatedUpstream], cooldown: Duration) -> Self {
        let backends = upstreams
            .iter()
            .map(|u| UpstreamState::new(u, cooldown))
            .collect();
        Self {
            backends: Arc::new(backends),
        }
    }

    /// Returns a slice of all backends (healthy and unhealthy).
    pub fn all(&self) -> &[UpstreamState] {
        &self.backends
    }
}

impl UpstreamState {
    /// Creates a new healthy upstream from a validated configuration entry.
    /// `cooldown` is the half-open window applied when the backend is ejected.
    pub fn new(backend: &ValidatedUpstream, cooldown: Duration) -> Self {
        Self {
            state: Arc::new(InnerState {
                uri: backend.uri.clone(),
                weight: backend.weight,
                consecutive_failures: AtomicU32::new(0),
                consecutive_successes: AtomicU32::new(0),
                healthy: AtomicBool::new(true),
                created: Instant::now(),
                cooldown_ms: u64::try_from(cooldown.as_millis()).unwrap_or(u64::MAX),
                cooldown_until_ms: AtomicU64::new(0),
            }),
        }
    }

    /// Returns the upstream URI.
    pub fn uri(&self) -> &hyper::Uri {
        &self.state.uri
    }

    /// Returns the load-balancing weight.
    pub fn weight(&self) -> u32 {
        self.state.weight
    }

    /// Returns `true` if this backend is currently healthy.
    pub fn is_healthy(&self) -> bool {
        self.state.healthy.load(Ordering::Acquire)
    }

    /// Returns `true` if this backend may be selected by the balancer: it is
    /// either healthy, or an ejected backend whose cooldown has elapsed and
    /// is therefore eligible for a half-open trial request.
    pub fn is_eligible(&self) -> bool {
        self.is_healthy() || self.trial_ready()
    }

    /// Returns `true` if this backend is unhealthy but its cooldown has
    /// elapsed, making it eligible for a single trial request.
    pub fn trial_ready(&self) -> bool {
        !self.is_healthy() && self.now_ms() >= self.state.cooldown_until_ms.load(Ordering::Acquire)
    }

    /// Starts (or restarts) the cooldown window, pushing the next-eligible
    /// time forward by the configured cooldown. Called both on ejection and
    /// by the balancer as it routes a half-open trial, so an unhealthy
    /// backend receives at most one trial per window until it is promoted.
    pub fn arm_cooldown(&self) {
        let until = self.now_ms().saturating_add(self.state.cooldown_ms);
        self.state.cooldown_until_ms.store(until, Ordering::Release);
    }

    /// Milliseconds elapsed since this backend was created.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.state.created.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Records a successful health check probe, resetting the failure counter
    /// and incrementing consecutive successes. When the backend is unhealthy
    /// and consecutive successes reach `healthy_threshold`, the backend is
    /// promoted back to healthy status.
    ///
    /// Returns `true` if this success caused a health transition from
    /// unhealthy to healthy.
    pub fn record_success(&self, healthy_threshold: u32) -> bool {
        self.state.consecutive_failures.store(0, Ordering::Release);

        if self.is_healthy() {
            self.state.consecutive_successes.store(0, Ordering::Release);
            return false;
        }

        let prev = self
            .state
            .consecutive_successes
            .fetch_add(1, Ordering::AcqRel);
        let new_count = prev.saturating_add(1);

        if new_count >= healthy_threshold {
            self.state.consecutive_successes.store(0, Ordering::Release);
            self.state.cooldown_until_ms.store(0, Ordering::Release);
            self.state.healthy.store(true, Ordering::Release);
            return true;
        }

        false
    }

    /// Records a failed request, incrementing the consecutive failure counter
    /// and resetting consecutive successes. If the failure counter reaches
    /// `threshold`, the backend is marked unhealthy.
    ///
    /// Returns `true` if this failure caused a health transition from
    /// healthy to unhealthy.
    pub fn record_failure(&self, threshold: u32) -> bool {
        self.state.consecutive_successes.store(0, Ordering::Release);

        let prev = self
            .state
            .consecutive_failures
            .fetch_add(1, Ordering::AcqRel);
        let new_count = prev.saturating_add(1);

        if new_count >= threshold && self.state.healthy.swap(false, Ordering::AcqRel) {
            self.arm_cooldown();
            return true;
        }

        false
    }

    /// Marks this backend as healthy, resetting both counters and clearing
    /// any pending cooldown.
    pub fn mark_healthy(&self) {
        self.state.consecutive_failures.store(0, Ordering::Release);
        self.state.consecutive_successes.store(0, Ordering::Release);
        self.state.cooldown_until_ms.store(0, Ordering::Release);
        self.state.healthy.store(true, Ordering::Release);
    }

    /// Marks this backend as unhealthy, resetting the success counter and
    /// starting the half-open cooldown window.
    pub fn mark_unhealthy(&self) {
        self.state.consecutive_successes.store(0, Ordering::Release);
        self.state.healthy.store(false, Ordering::Release);
        self.arm_cooldown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG_COOLDOWN: Duration = Duration::from_secs(30);

    fn test_upstream(addr: &str, weight: u32) -> ValidatedUpstream {
        ValidatedUpstream {
            uri: addr.parse().unwrap(),
            weight,
        }
    }

    fn state(addr: &str, cooldown: Duration) -> UpstreamState {
        UpstreamState::new(&test_upstream(addr, 1), cooldown)
    }

    #[test]
    fn new_upstream_starts_healthy() {
        let state = state("http://localhost:3000", LONG_COOLDOWN);
        assert!(state.is_healthy());
        assert!(state.is_eligible());
    }

    #[test]
    fn record_success_resets_failures() {
        let state = state("http://localhost:3000", LONG_COOLDOWN);
        // Two failures below the threshold of three: still healthy.
        state.record_failure(3);
        state.record_failure(3);
        assert!(state.is_healthy());

        // A success resets the failure counter; two further failures should
        // not eject, proving the counter restarted from zero.
        state.record_success(1);
        state.record_failure(3);
        state.record_failure(3);
        assert!(state.is_healthy());

        // The third consecutive failure now ejects.
        assert!(state.record_failure(3));
        assert!(!state.is_healthy());
    }

    #[test]
    fn record_success_requires_threshold_for_recovery() {
        let state = state("http://localhost:3000", LONG_COOLDOWN);
        state.mark_unhealthy();

        assert!(!state.record_success(3));
        assert!(!state.is_healthy());
        assert!(!state.record_success(3));
        assert!(!state.is_healthy());
        assert!(state.record_success(3));
        assert!(state.is_healthy());
    }

    #[test]
    fn failure_resets_consecutive_successes() {
        let state = state("http://localhost:3000", LONG_COOLDOWN);
        state.mark_unhealthy();

        state.record_success(3);
        state.record_success(3);
        state.record_failure(10);
        assert!(!state.is_healthy());

        state.record_success(3);
        assert!(!state.is_healthy());
    }

    #[test]
    fn record_failure_marks_unhealthy_at_threshold() {
        let state = state("http://localhost:3000", LONG_COOLDOWN);

        assert!(!state.record_failure(3));
        assert!(!state.record_failure(3));
        assert!(state.record_failure(3));

        assert!(!state.is_healthy());
    }

    #[test]
    fn record_failure_beyond_threshold_does_not_retrigger() {
        let state = state("http://localhost:3000", LONG_COOLDOWN);

        state.record_failure(2);
        assert!(state.record_failure(2));
        assert!(!state.record_failure(2));
    }

    #[test]
    fn ejected_backend_is_not_eligible_during_cooldown() {
        let state = state("http://localhost:3000", LONG_COOLDOWN);
        state.mark_unhealthy();

        assert!(!state.is_healthy());
        assert!(!state.trial_ready());
        assert!(!state.is_eligible());
    }

    #[test]
    fn ejected_backend_becomes_trial_ready_after_cooldown() {
        let state = state("http://localhost:3000", Duration::from_millis(20));
        state.mark_unhealthy();
        assert!(!state.trial_ready());

        std::thread::sleep(Duration::from_millis(40));
        assert!(state.trial_ready());
        assert!(state.is_eligible());

        // Routing a trial re-arms the cooldown, suppressing further trials.
        state.arm_cooldown();
        assert!(!state.trial_ready());
    }

    #[test]
    fn promotion_clears_cooldown() {
        let state = state("http://localhost:3000", Duration::from_millis(20));
        state.mark_unhealthy();

        assert!(state.record_success(1));
        assert!(state.is_healthy());
        assert!(state.is_eligible());
    }
}
