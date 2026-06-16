//! Configuration loading, validation, and pre-compiled runtime state.
//!
//! The proxy reads its YAML configuration exactly once at startup.
//! All regex patterns for sensitive data masking are compiled at load time
//! and stored alongside the raw config for zero-allocation lookups at
//! request time.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hyper::header::HeaderName;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{ProxyError, Result};

/// Default maximum request body size: 10 MiB.
pub const DEFAULT_MAX_BODY_SIZE: u64 = 10 * 1024 * 1024;

/// Default connect timeout for establishing upstream TCP connections.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default total request timeout covering the entire upstream round-trip.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default idle timeout for pooled connections before they are closed.
pub const DEFAULT_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default maximum number of idle connections kept per upstream host.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 32;

/// Default maximum number of concurrent in-flight requests the proxy
/// will handle before returning 503 Service Unavailable.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 1000;

/// Default weight assigned to upstream backends when none is specified.
pub const DEFAULT_UPSTREAM_WEIGHT: u32 = 1;

/// Default socket address the proxy binds to.
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8100";

/// Default number of consecutive failures before marking a backend unhealthy.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// Default number of consecutive successes before marking a backend healthy.
pub const DEFAULT_HEALTHY_THRESHOLD: u32 = 1;

/// Default cooldown period before re-checking an unhealthy backend.
pub const DEFAULT_HEALTH_CHECK_COOLDOWN: Duration = Duration::from_secs(30);

/// Default interval between active health check probes.
pub const DEFAULT_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// Default path for active health check probes.
pub const DEFAULT_HEALTH_CHECK_PATH: &str = "/health";

/// Default timeout for individual health check probes.
pub const DEFAULT_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// Default per-IP rate limit in requests per second.
pub const DEFAULT_RATE_LIMIT_RPS: u32 = 100;

/// Default burst size for per-IP rate limiting.
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 50;

/// Default graceful shutdown drain timeout.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Raw configuration as deserialized from the YAML file.
///
/// This struct maps directly to the on-disk schema. After loading, it is
/// transformed into a [`RuntimeConfig`] that holds pre-compiled regex
/// patterns and validated upstream URIs.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Socket address the proxy listens on (default `"127.0.0.1:8100"`).
    #[serde(default)]
    pub listen: Option<String>,
    /// Upstream backends with optional weights and health check config.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    /// Header names whose presence causes the request to be rejected.
    #[serde(default)]
    pub blocked_headers: Vec<String>,
    /// Query parameter names whose presence causes the request to be rejected.
    #[serde(default)]
    pub blocked_params: Vec<String>,
    /// Parameter names whose values are masked in response bodies.
    #[serde(default)]
    pub masked_params: Vec<String>,
    /// Maximum allowed request body size in bytes (default: 10 MiB).
    /// Requests with a `Content-Length` exceeding this limit receive 413.
    #[serde(default)]
    pub max_body_size: Option<u64>,
    /// Response header names to strip before returning to the client.
    /// Typically `["server", "x-powered-by"]` to hide backend details.
    #[serde(default)]
    pub strip_response_headers: Vec<String>,
    /// Maximum concurrent in-flight requests before returning 503
    /// Service Unavailable (default: 1000).
    #[serde(default)]
    pub max_concurrent_requests: Option<usize>,
    /// Timeout configuration for upstream connections and requests.
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
    /// Connection pool tuning parameters.
    #[serde(default)]
    pub pool: PoolConfig,
    /// TLS termination configuration for accepting HTTPS connections from
    /// clients. When absent, the proxy listens on plain HTTP.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Health check configuration for upstream backends.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// Per-IP rate limiting configuration. When absent, rate limiting is
    /// disabled.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Graceful shutdown drain timeout in seconds (default: 30).
    /// After signal receipt, in-flight requests have this long to complete
    /// before the proxy forcibly terminates them.
    #[serde(default)]
    pub shutdown_timeout: Option<u64>,
}

/// Upstream connection and request timeout configuration.
///
/// All values are in seconds. When absent, sensible defaults are applied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeoutsConfig {
    /// Timeout in seconds for establishing an upstream TCP connection
    /// (default: 5).
    #[serde(default = "default_connect_timeout_secs")]
    pub connect: u64,
    /// Total timeout in seconds for the entire upstream round-trip
    /// (default: 30). Requests exceeding this receive 504.
    #[serde(default = "default_request_timeout_secs")]
    pub request: u64,
}

fn default_connect_timeout_secs() -> u64 {
    DEFAULT_CONNECT_TIMEOUT.as_secs()
}

fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT.as_secs()
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            connect: default_connect_timeout_secs(),
            request: default_request_timeout_secs(),
        }
    }
}

/// Connection pool tuning parameters.
///
/// Controls how the proxy manages persistent upstream connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoolConfig {
    /// Idle timeout in seconds for pooled connections (default: 60).
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub idle_timeout: u64,
    /// Maximum idle connections kept per upstream host (default: 32).
    #[serde(default = "default_pool_max_idle_per_host")]
    pub max_idle_per_host: usize,
}

fn default_pool_idle_timeout_secs() -> u64 {
    DEFAULT_POOL_IDLE_TIMEOUT.as_secs()
}

fn default_pool_max_idle_per_host() -> usize {
    DEFAULT_POOL_MAX_IDLE_PER_HOST
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: default_pool_idle_timeout_secs(),
            max_idle_per_host: default_pool_max_idle_per_host(),
        }
    }
}

/// Configuration for a single upstream backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamConfig {
    /// The backend address (e.g. `"http://backend1:3000"`).
    pub address: String,
    /// Relative weight for load balancing. Higher values receive
    /// proportionally more traffic. Defaults to 1.
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    DEFAULT_UPSTREAM_WEIGHT
}

/// Active health check configuration.
///
/// When present, the proxy spawns a background task that periodically
/// probes each upstream at the configured path, marking backends as
/// healthy or unhealthy based on response status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthCheckConfig {
    /// HTTP path to probe (default: `/health`).
    #[serde(default = "default_health_path")]
    pub path: String,
    /// Interval between health check probes in seconds (default: 10).
    #[serde(default = "default_health_interval_secs")]
    pub interval: u64,
    /// Number of consecutive failures before marking a backend unhealthy
    /// (default: 3).
    #[serde(default = "default_failure_threshold")]
    pub unhealthy_threshold: u32,
    /// Number of consecutive successes before marking an unhealthy backend
    /// as healthy again (default: 1).
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    /// Cooldown period in seconds before re-checking an unhealthy
    /// backend (default: 30).
    #[serde(default = "default_cooldown_secs")]
    pub cooldown: u64,
    /// Timeout in seconds for individual health check probes (default: 3).
    #[serde(default = "default_health_timeout_secs")]
    pub timeout: u64,
}

fn default_health_path() -> String {
    DEFAULT_HEALTH_CHECK_PATH.into()
}

fn default_health_interval_secs() -> u64 {
    DEFAULT_HEALTH_CHECK_INTERVAL.as_secs()
}

fn default_failure_threshold() -> u32 {
    DEFAULT_FAILURE_THRESHOLD
}

fn default_healthy_threshold() -> u32 {
    DEFAULT_HEALTHY_THRESHOLD
}

fn default_cooldown_secs() -> u64 {
    DEFAULT_HEALTH_CHECK_COOLDOWN.as_secs()
}

fn default_health_timeout_secs() -> u64 {
    DEFAULT_HEALTH_CHECK_TIMEOUT.as_secs()
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            path: default_health_path(),
            interval: default_health_interval_secs(),
            unhealthy_threshold: default_failure_threshold(),
            healthy_threshold: default_healthy_threshold(),
            cooldown: default_cooldown_secs(),
            timeout: default_health_timeout_secs(),
        }
    }
}

/// Per-IP rate limiting configuration.
///
/// When present, the proxy applies a token-bucket rate limiter keyed by
/// client IP address. Requests exceeding the limit receive a 429
/// Too Many Requests response with a `Retry-After` header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second per client IP (default: 100).
    #[serde(default = "default_rate_limit_rps")]
    pub requests_per_second: u32,
    /// Maximum burst size above the sustained rate (default: 50).
    #[serde(default = "default_rate_limit_burst")]
    pub burst: u32,
}

fn default_rate_limit_rps() -> u32 {
    DEFAULT_RATE_LIMIT_RPS
}

fn default_rate_limit_burst() -> u32 {
    DEFAULT_RATE_LIMIT_BURST
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_rate_limit_rps(),
            burst: default_rate_limit_burst(),
        }
    }
}

/// TLS termination configuration.
///
/// When present in the config file, the proxy accepts HTTPS connections
/// using the certificate chain and private key at the specified paths.
/// Both files must be PEM-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain file.
    pub cert_path: String,
    /// Path to the PEM-encoded private key file.
    pub key_path: String,
}

/// Validated upstream backend descriptor produced from [`UpstreamConfig`].
#[derive(Debug, Clone)]
pub struct ValidatedUpstream {
    /// The parsed and validated upstream URI.
    pub uri: hyper::Uri,
    /// Relative weight for load balancing.
    pub weight: u32,
}

/// Fully validated, ready-to-use configuration with pre-compiled patterns.
///
/// Created once at startup and shared across all request handlers via `Arc`.
/// Contains every value the proxy needs at runtime without touching the
/// filesystem or compiling regexes on the hot path.
#[derive(Debug)]
pub struct RuntimeConfig {
    /// Socket address the proxy binds to.
    pub listen: SocketAddr,
    /// Validated upstream backends with their load-balancing weights.
    pub upstreams: Vec<ValidatedUpstream>,
    /// Pre-parsed header names whose presence triggers a 403 on GET requests.
    pub blocked_headers: Vec<HeaderName>,
    /// Query parameter names whose presence triggers a 403 on GET requests.
    pub blocked_params: Vec<String>,
    /// Pre-compiled masking rules for response body inspection.
    pub mask_rules: Vec<MaskRule>,
    /// Maximum request body size in bytes. Requests whose `Content-Length`
    /// exceeds this threshold are rejected with 413 Payload Too Large.
    pub max_body_size: u64,
    /// Lowercased response header names to strip before returning to the
    /// client (e.g. `"server"`, `"x-powered-by"`).
    pub strip_response_headers: Vec<String>,
    /// Connect timeout for upstream TCP connections.
    pub connect_timeout: Duration,
    /// Total request timeout for the upstream round-trip. Expiry yields 504.
    pub request_timeout: Duration,
    /// Idle timeout for pooled upstream connections.
    pub pool_idle_timeout: Duration,
    /// Maximum idle connections per upstream host.
    pub pool_max_idle_per_host: usize,
    /// Maximum concurrent in-flight requests. Overflow yields 503.
    pub max_concurrent_requests: usize,
    /// TLS termination configuration. `None` means plain HTTP.
    pub tls: Option<TlsConfig>,
    /// Active health check configuration. `None` disables active probing.
    pub health_check: Option<HealthCheckConfig>,
    /// Number of consecutive failures before marking a backend unhealthy.
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking a backend healthy.
    pub healthy_threshold: u32,
    /// Per-IP rate limiting configuration. `None` disables rate limiting.
    pub rate_limit: Option<RateLimitConfig>,
    /// Graceful shutdown drain timeout. After signal receipt, in-flight
    /// requests have this long to complete before forced termination.
    pub shutdown_timeout: Duration,
}

/// A single pre-compiled masking rule binding a parameter name to its regex.
#[derive(Debug, Clone)]
pub struct MaskRule {
    /// The original parameter name this rule applies to.
    pub param: String,
    /// Compiled regex matching `{param}={value}` in query-string-style text.
    pub pattern: Regex,
}

/// Validates a single upstream address string, returning a [`ValidatedUpstream`].
fn validate_upstream(address: &str, weight: u32) -> Result<ValidatedUpstream> {
    if address.is_empty() {
        return Err(ProxyError::InvalidUpstream(
            "upstream address must not be empty".into(),
        ));
    }

    let uri = address
        .parse::<hyper::Uri>()
        .map_err(|e| ProxyError::InvalidUpstream(format!("{e}")))?;

    uri.authority().ok_or_else(|| {
        ProxyError::InvalidUpstream(format!("upstream URI has no authority: {address}"))
    })?;

    if weight == 0 {
        return Err(ProxyError::Config(format!(
            "upstream weight must be positive: {address}"
        )));
    }

    Ok(ValidatedUpstream { uri, weight })
}

impl Config {
    /// Loads configuration from a YAML file at the given path.
    ///
    /// Returns a [`ProxyError::Config`] if the file cannot be opened or
    /// its contents fail YAML deserialization.
    pub fn load_from_file(file_path: &(impl AsRef<Path> + ?Sized)) -> Result<Self> {
        let file = std::fs::File::open(file_path).map_err(|e| {
            ProxyError::Config(format!(
                "failed to open {}: {e}",
                file_path.as_ref().display()
            ))
        })?;

        serde_yaml::from_reader(file)
            .map_err(|e| ProxyError::Config(format!("failed to parse config: {e}")))
    }

    /// Validates all fields and compiles regex patterns, producing a
    /// [`RuntimeConfig`] suitable for the proxy hot path.
    ///
    /// At least one upstream must be configured.
    pub fn into_runtime(self) -> Result<RuntimeConfig> {
        if self.upstreams.is_empty() {
            return Err(ProxyError::Config(
                "at least one upstream must be configured".into(),
            ));
        }

        let listen_str = self.listen.as_deref().unwrap_or(DEFAULT_LISTEN_ADDR);
        let listen = listen_str.parse::<SocketAddr>().map_err(|e| {
            ProxyError::Config(format!("invalid listen address \"{listen_str}\": {e}"))
        })?;

        let upstreams = self
            .upstreams
            .iter()
            .map(|u| validate_upstream(&u.address, u.weight))
            .collect::<Result<Vec<_>>>()?;

        let mut seen = HashSet::with_capacity(upstreams.len());
        if let Some(dup) = upstreams.iter().find(|u| !seen.insert(&u.uri)) {
            return Err(ProxyError::Config(format!(
                "duplicate upstream address: {}",
                dup.uri
            )));
        }

        let blocked_headers = self
            .blocked_headers
            .iter()
            .map(|h| {
                HeaderName::from_bytes(h.as_bytes()).map_err(|e| {
                    ProxyError::Config(format!("invalid blocked header name \"{h}\": {e}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let mask_rules = self
            .masked_params
            .iter()
            .map(|param| {
                let escaped = regex::escape(param);
                Regex::new(&format!("{escaped}=([^&]+)"))
                    .map(|pattern| MaskRule {
                        param: param.clone(),
                        pattern,
                    })
                    .map_err(|e| {
                        ProxyError::Config(format!("invalid mask pattern for {param}: {e}"))
                    })
            })
            .collect::<Result<Vec<_>>>()?;

        let max_body_size = self.max_body_size.unwrap_or(DEFAULT_MAX_BODY_SIZE);

        let strip_response_headers = self
            .strip_response_headers
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();

        let connect_timeout = Duration::from_secs(self.timeouts.connect);
        let request_timeout = Duration::from_secs(self.timeouts.request);
        let pool_idle_timeout = Duration::from_secs(self.pool.idle_timeout);
        let pool_max_idle_per_host = self.pool.max_idle_per_host;

        let max_concurrent_requests = self
            .max_concurrent_requests
            .unwrap_or(DEFAULT_MAX_CONCURRENT_REQUESTS);
        if max_concurrent_requests == 0 {
            return Err(ProxyError::Config(
                "max_concurrent_requests must be positive".into(),
            ));
        }

        if let Some(rl) = self.rate_limit.as_ref() {
            if rl.requests_per_second == 0 {
                return Err(ProxyError::Config(
                    "rate_limit.requests_per_second must be positive".into(),
                ));
            }
            if rl.burst == 0 {
                return Err(ProxyError::Config(
                    "rate_limit.burst must be positive".into(),
                ));
            }
        }

        if let Some(hc) = self.health_check.as_ref() {
            if hc.unhealthy_threshold == 0 {
                return Err(ProxyError::Config(
                    "health_check.unhealthy_threshold must be positive".into(),
                ));
            }
            if hc.healthy_threshold == 0 {
                return Err(ProxyError::Config(
                    "health_check.healthy_threshold must be positive".into(),
                ));
            }
            if !hc.path.starts_with('/') {
                return Err(ProxyError::Config(format!(
                    "health_check.path must begin with '/': \"{}\"",
                    hc.path
                )));
            }
        }

        let failure_threshold = self
            .health_check
            .as_ref()
            .map_or(DEFAULT_FAILURE_THRESHOLD, |hc| hc.unhealthy_threshold);

        let healthy_threshold = self
            .health_check
            .as_ref()
            .map_or(DEFAULT_HEALTHY_THRESHOLD, |hc| hc.healthy_threshold);

        let shutdown_timeout = self
            .shutdown_timeout
            .map_or(DEFAULT_SHUTDOWN_TIMEOUT, Duration::from_secs);

        Ok(RuntimeConfig {
            listen,
            upstreams,
            blocked_headers,
            blocked_params: self.blocked_params,
            mask_rules,
            max_body_size,
            strip_response_headers,
            connect_timeout,
            request_timeout,
            pool_idle_timeout,
            pool_max_idle_per_host,
            max_concurrent_requests,
            tls: self.tls,
            health_check: self.health_check,
            failure_threshold,
            healthy_threshold,
            rate_limit: self.rate_limit,
            shutdown_timeout,
        })
    }
}

impl RuntimeConfig {
    /// Returns `true` if any configured upstream uses the HTTPS scheme.
    pub fn has_https_upstream(&self) -> bool {
        self.upstreams.iter().any(|u| {
            u.uri
                .scheme_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("https"))
        })
    }

    /// Applies all configured masking rules to the given text, replacing
    /// matched parameter values with `****`.
    ///
    /// Returns the masked string, which may be identical to the input if
    /// no rules match.
    pub fn mask_sensitive_data(&self, data: &str) -> String {
        self.mask_rules.iter().fold(data.to_owned(), |acc, rule| {
            rule.pattern
                .replace_all(&acc, format!("{}=****", rule.param))
                .into_owned()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_upstream(addr: &str) -> Vec<UpstreamConfig> {
        vec![UpstreamConfig {
            address: addr.into(),
            weight: 1,
        }]
    }

    #[test]
    fn loads_config_from_file() {
        let config = Config::load_from_file("./Config.example.yml")
            .expect("Config.example.yml should be loadable");

        assert_eq!(config.listen, Some("127.0.0.1:8100".into()));
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].address, "http://localhost:3000");
        assert_eq!(
            config.blocked_headers,
            vec!["X-Debug-Token", "X-Internal-Auth"]
        );
        assert_eq!(config.blocked_params, vec!["access_token", "secret_key"]);
        assert_eq!(config.masked_params, vec!["password", "ssn", "credit_card"]);
        assert_eq!(config.timeouts.connect, 5);
        assert_eq!(config.timeouts.request, 30);
        assert_eq!(config.pool.idle_timeout, 60);
        assert_eq!(config.pool.max_idle_per_host, 32);
        assert_eq!(config.max_concurrent_requests, Some(1000));
        assert_eq!(
            config.rate_limit,
            Some(RateLimitConfig {
                requests_per_second: 100,
                burst: 50,
            })
        );
    }

    #[test]
    fn into_runtime_rejects_empty_upstreams() {
        let config = Config::default();
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_malformed_upstream() {
        let config = Config {
            upstreams: vec![UpstreamConfig {
                address: "not a valid uri %%".into(),
                weight: 1,
            }],
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_lowercases_blocked_headers() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_headers: vec!["X-Custom-Header".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");
        assert_eq!(
            rt.blocked_headers,
            vec![HeaderName::from_static("x-custom-header")]
        );
    }

    #[test]
    fn into_runtime_rejects_invalid_blocked_header_name() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_headers: vec!["invalid header".into()],
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_duplicate_upstreams() {
        let config = Config {
            upstreams: vec![
                UpstreamConfig {
                    address: "http://backend:3000".into(),
                    weight: 1,
                },
                UpstreamConfig {
                    address: "http://backend:3000".into(),
                    weight: 2,
                },
            ],
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_zero_max_concurrent_requests() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            max_concurrent_requests: Some(0),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_zero_rate_limit_rps() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            rate_limit: Some(RateLimitConfig {
                requests_per_second: 0,
                burst: 50,
            }),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_zero_rate_limit_burst() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            rate_limit: Some(RateLimitConfig {
                requests_per_second: 100,
                burst: 0,
            }),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_zero_health_thresholds() {
        let unhealthy = Config {
            upstreams: single_upstream("http://localhost:3000"),
            health_check: Some(HealthCheckConfig {
                unhealthy_threshold: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(unhealthy.into_runtime().is_err());

        let healthy = Config {
            upstreams: single_upstream("http://localhost:3000"),
            health_check: Some(HealthCheckConfig {
                healthy_threshold: 0,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(healthy.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_rejects_health_path_without_leading_slash() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            health_check: Some(HealthCheckConfig {
                path: "health".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn into_runtime_validates_upstreams() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");
        assert_eq!(rt.upstreams.len(), 1);
        assert_eq!(
            rt.upstreams[0].uri,
            "http://localhost:3000".parse::<hyper::Uri>().unwrap()
        );
        assert_eq!(rt.upstreams[0].weight, 1);
    }

    #[test]
    fn into_runtime_handles_multiple_upstreams() {
        let config = Config {
            upstreams: vec![
                UpstreamConfig {
                    address: "http://backend1:3000".into(),
                    weight: 3,
                },
                UpstreamConfig {
                    address: "http://backend2:3000".into(),
                    weight: 1,
                },
            ],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");
        assert_eq!(rt.upstreams.len(), 2);
        assert_eq!(
            rt.upstreams[0].uri,
            "http://backend1:3000".parse::<hyper::Uri>().unwrap()
        );
        assert_eq!(rt.upstreams[0].weight, 3);
        assert_eq!(rt.upstreams[1].weight, 1);
    }

    #[test]
    fn into_runtime_rejects_zero_weight() {
        let config = Config {
            upstreams: vec![UpstreamConfig {
                address: "http://localhost:3000".into(),
                weight: 0,
            }],
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn has_https_upstream_detects_scheme() {
        let config = Config {
            upstreams: vec![
                UpstreamConfig {
                    address: "http://backend1:3000".into(),
                    weight: 1,
                },
                UpstreamConfig {
                    address: "https://backend2:3000".into(),
                    weight: 1,
                },
            ],
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert!(rt.has_https_upstream());
    }

    #[test]
    fn mask_sensitive_data_replaces_values() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            masked_params: vec!["password".into(), "token".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");

        let input = "username=john&password=secret&token=1234567890";
        let masked = rt.mask_sensitive_data(input);
        assert_eq!(masked, "username=john&password=****&token=****");
    }

    #[test]
    fn mask_sensitive_data_leaves_unmatched_text_intact() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            masked_params: vec!["password".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");

        let input = "username=john&role=admin";
        assert_eq!(rt.mask_sensitive_data(input), input);
    }

    #[test]
    fn mask_handles_regex_special_characters_in_param_name() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            masked_params: vec!["user.password".into()],
            ..Default::default()
        };
        let rt = config.into_runtime().expect("valid config");

        let input = "user.password=secret123&other=value";
        assert_eq!(
            rt.mask_sensitive_data(input),
            "user.password=****&other=value"
        );
    }

    #[test]
    fn into_runtime_defaults_listen_address() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(
            rt.listen,
            DEFAULT_LISTEN_ADDR.parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn into_runtime_parses_custom_listen_address() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            listen: Some("0.0.0.0:9090".into()),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.listen, "0.0.0.0:9090".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn into_runtime_rejects_invalid_listen_address() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            listen: Some("not-an-address".into()),
            ..Default::default()
        };
        assert!(config.into_runtime().is_err());
    }

    #[test]
    fn health_check_config_uses_defaults() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            health_check: Some(HealthCheckConfig::default()),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.failure_threshold, DEFAULT_FAILURE_THRESHOLD);
        assert_eq!(rt.healthy_threshold, DEFAULT_HEALTHY_THRESHOLD);
        assert!(rt.health_check.is_some());
        let hc = rt.health_check.as_ref().unwrap();
        assert_eq!(hc.cooldown, DEFAULT_HEALTH_CHECK_COOLDOWN.as_secs());
        assert_eq!(hc.timeout, DEFAULT_HEALTH_CHECK_TIMEOUT.as_secs());
    }

    #[test]
    fn timeouts_config_uses_defaults() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(rt.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(rt.pool_idle_timeout, DEFAULT_POOL_IDLE_TIMEOUT);
        assert_eq!(rt.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
    }

    #[test]
    fn custom_timeouts_propagate() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            timeouts: TimeoutsConfig {
                connect: 2,
                request: 10,
            },
            pool: PoolConfig {
                idle_timeout: 90,
                max_idle_per_host: 16,
            },
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.connect_timeout, Duration::from_secs(2));
        assert_eq!(rt.request_timeout, Duration::from_secs(10));
        assert_eq!(rt.pool_idle_timeout, Duration::from_secs(90));
        assert_eq!(rt.pool_max_idle_per_host, 16);
    }

    #[test]
    fn shutdown_timeout_defaults() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.shutdown_timeout, DEFAULT_SHUTDOWN_TIMEOUT);
    }

    #[test]
    fn custom_shutdown_timeout() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            shutdown_timeout: Some(10),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.shutdown_timeout, Duration::from_secs(10));
    }

    #[test]
    fn healthy_threshold_propagates() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            health_check: Some(HealthCheckConfig {
                healthy_threshold: 5,
                ..Default::default()
            }),
            ..Default::default()
        };
        let rt = config.into_runtime().unwrap();
        assert_eq!(rt.healthy_threshold, 5);
    }
}
