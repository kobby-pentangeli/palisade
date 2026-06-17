//! Smooth weighted round-robin load balancer.
//!
//! Distributes requests across eligible upstream backends proportionally
//! to their configured weights using the nginx-style interleaving
//! algorithm: each selection adds every eligible backend's weight to its
//! running current-weight, picks the backend with the greatest current
//! weight, and subtracts the eligible total from the winner. This spreads a
//! heavy backend's selections evenly through the sequence rather than in a
//! contiguous run, with `O(n_backends)` time and state and no slot
//! expansion (so a backend with a very large `u32` weight costs nothing
//! extra).
//!
//! Selection is lock-free: the running current-weights are held in an array
//! of [`AtomicI64`] and updated with atomic read-modify-write operations.
//! Under concurrency the per-request interleaving may deviate slightly from
//! the strictly sequential order, but selection stays correct, fair on
//! average, and never blocks. Eligibility (healthy, or an ejected backend
//! whose cooldown has elapsed) is read from the pool, and the balancer arms the
//! cooldown as it routes a half-open trial but otherwise never mutates
//! health state.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::{ProxyError, Result, UpstreamPool, UpstreamState};

/// A smooth weighted round-robin load balancer over an [`UpstreamPool`].
///
/// Cheaply cloneable and safe to call concurrently from multiple request
/// handlers; clones share the same running selection state.
#[derive(Debug, Clone)]
pub struct LoadBalancer {
    pool: UpstreamPool,
    /// Per-backend running current-weight, indexed in lockstep with
    /// [`UpstreamPool::all`]. Oscillates around zero within `+/-total_weight`.
    current_weights: Arc<Vec<AtomicI64>>,
}

impl LoadBalancer {
    /// Creates a new smooth weighted round-robin balancer from the pool.
    pub fn new(pool: UpstreamPool) -> Self {
        let current_weights = pool.all().iter().map(|_| AtomicI64::new(0)).collect();
        Self {
            pool,
            current_weights: Arc::new(current_weights),
        }
    }

    /// Selects the next eligible upstream backend by smooth weighted
    /// round-robin.
    ///
    /// Returns [`ProxyError::NoHealthyUpstream`] when no backend is eligible.
    pub fn next(&self) -> Result<UpstreamState> {
        let backends = self.pool.all();

        let mut total: i64 = 0;
        let mut best: Option<usize> = None;
        let mut best_weight = i64::MIN;

        for (idx, backend) in backends.iter().enumerate() {
            if !backend.is_eligible() {
                continue;
            }
            let weight = i64::from(backend.weight());
            total = total.saturating_add(weight);
            let current = self.current_weights[idx]
                .fetch_add(weight, Ordering::AcqRel)
                .saturating_add(weight);
            if current > best_weight {
                best_weight = current;
                best = Some(idx);
            }
        }

        match best {
            Some(idx) => {
                self.current_weights[idx].fetch_sub(total, Ordering::AcqRel);
                let selected = &backends[idx];
                if !selected.is_healthy() {
                    selected.arm_cooldown();
                }
                Ok(selected.clone())
            }
            None => Err(ProxyError::NoHealthyUpstream),
        }
    }

    /// Returns a reference to the underlying upstream pool.
    pub fn pool(&self) -> &UpstreamPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::config::ValidatedUpstream;

    const LONG_COOLDOWN: Duration = Duration::from_secs(30);

    fn make_pool(specs: &[(&str, u32)]) -> UpstreamPool {
        make_pool_with_cooldown(specs, LONG_COOLDOWN)
    }

    fn make_pool_with_cooldown(specs: &[(&str, u32)], cooldown: Duration) -> UpstreamPool {
        let validated = specs
            .iter()
            .map(|(addr, weight)| ValidatedUpstream {
                uri: addr.parse().unwrap(),
                weight: *weight,
            })
            .collect::<Vec<ValidatedUpstream>>();
        UpstreamPool::from_validated(&validated, cooldown)
    }

    #[test]
    fn single_backend_always_selected() {
        let pool = make_pool(&[("http://b1:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        for _ in 0..10 {
            let selected = balancer.next().unwrap();
            assert_eq!(
                selected.uri(),
                &"http://b1:3000".parse::<hyper::Uri>().unwrap()
            );
        }
    }

    #[test]
    fn equal_weight_round_robins() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        let first = balancer.next().unwrap();
        let second = balancer.next().unwrap();
        let third = balancer.next().unwrap();

        assert_ne!(first.uri(), second.uri());
        assert_eq!(first.uri(), third.uri());
    }

    #[test]
    fn weighted_distribution_respects_weights() {
        let pool = make_pool(&[("http://b1:3000", 3), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        let mut b1_count = 0u32;
        let mut b2_count = 0u32;
        let b1_uri = "http://b1:3000".parse::<hyper::Uri>().unwrap();

        for _ in 0..400 {
            let selected = balancer.next().unwrap();
            if *selected.uri() == b1_uri {
                b1_count += 1;
            } else {
                b2_count += 1;
            }
        }

        assert_eq!(b1_count, 300);
        assert_eq!(b2_count, 100);
    }

    #[test]
    fn skips_unhealthy_backends() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        balancer.pool().all()[0].mark_unhealthy();

        for _ in 0..10 {
            let selected = balancer.next().unwrap();
            assert_eq!(
                selected.uri(),
                &"http://b2:3000".parse::<hyper::Uri>().unwrap()
            );
        }
    }

    #[test]
    fn all_unhealthy_returns_error() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        balancer.pool().all()[0].mark_unhealthy();
        balancer.pool().all()[1].mark_unhealthy();

        let result = balancer.next();
        assert!(result.is_err());
    }

    #[test]
    fn recovery_after_mark_healthy() {
        let pool = make_pool(&[("http://b1:3000", 1), ("http://b2:3000", 1)]);
        let balancer = LoadBalancer::new(pool);

        balancer.pool().all()[0].mark_unhealthy();
        balancer.pool().all()[1].mark_unhealthy();
        assert!(balancer.next().is_err());

        balancer.pool().all()[0].mark_healthy();
        let selected = balancer.next().unwrap();
        assert_eq!(
            selected.uri(),
            &"http://b1:3000".parse::<hyper::Uri>().unwrap()
        );
    }

    #[test]
    fn large_weight_does_not_allocate_slot_table() {
        let pool = make_pool(&[("http://b1:3000", u32::MAX)]);
        let balancer = LoadBalancer::new(pool);

        for _ in 0..5 {
            assert_eq!(
                balancer.next().unwrap().uri(),
                &"http://b1:3000".parse::<hyper::Uri>().unwrap()
            );
        }
    }

    #[test]
    fn ejected_backend_recovers_after_cooldown() {
        let pool = make_pool_with_cooldown(&[("http://b1:3000", 1)], Duration::from_millis(20));
        let balancer = LoadBalancer::new(pool);

        balancer.pool().all()[0].mark_unhealthy();
        // During cooldown the only backend is ineligible.
        assert!(balancer.next().is_err());

        std::thread::sleep(Duration::from_millis(40));
        // Once the cooldown elapses the ejected backend earns a trial.
        assert!(balancer.next().is_ok());
    }
}
