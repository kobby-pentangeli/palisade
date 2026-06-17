# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-17

Implements support for HTTP/2, observability, graceful shutdown, a fully validated configuration layer, a memory-bounded balancer, and closed DoS and policy-bypass surfaces. Includes one breaking change (the configuration format).

### Added

- **HTTP/2** negotiated via ALPN on both the client-facing listener (`h2` then `http/1.1`) and the upstream connector, so the proxy multiplexes to backends that support it while still serving HTTP/1.1 clients.
- **Prometheus metrics and liveness/readiness probes** on an optional, separate admin listener (the `[admin]` config section, off by default and required to differ from the data-plane address). `/metrics` exposes request counts by status, a request-latency histogram, per-upstream health, rate-limit rejections, and in-flight request / open-connection saturation gauges; `/livez` and `/readyz` serve container and orchestrator probes.
- **`X-Request-Id` propagation:** a validated inbound id is echoed for end-to-end correlation, falling back to the monotonic per-process identifier when absent or malformed.
- **Half-open recovery:** an ejected backend becomes eligible for a single trial request after a configurable `cooldown`, so passive-only deployments recover backends without active health checks.
- **Connection-level DoS bounds:** `max_connections` caps simultaneously-open client connections and `header_read_timeout` closes slow-header (slowloris) connections; `mask_max_body_size` bounds the response body buffered for masking.
- **Trusted-proxy handling** via `trust_forwarded_headers` for deployment behind another trusted proxy.
- **Deployment artifacts and docs:** a multi-stage distroless `Dockerfile`, a demo `docker-compose.yml`, a hardened `systemd` unit, a deployment guide, a `SECURITY.md` threat model, and a developer guide.

### Changed

- **BREAKING:** Configuration format migrated from YAML to TOML. The archived, unmaintained `serde_yaml` dependency is replaced by the maintained `toml` crate, and the default config path is now `./config.toml`. Rename your `Config.yml` to `config.toml` and convert it to TOML; note that in TOML all top-level keys must appear before any `[section]` or `[[upstreams]]` tables.

  ```toml
  listen = "127.0.0.1:8100"

  blocked_params = ["access_token", "secret_key"]

  [[upstreams]]
  address = "http://localhost:3000"
  weight = 1

  [timeouts]
  connect = 5
  request = 30

  [rate_limit]
  requests_per_second = 100
  burst = 50
  ```

- Load balancing replaced the memory-unbounded slot-expansion table with smooth weighted round-robin: `O(n_backends)` selection and state, so a large `u32` weight no longer allocates a proportional table.
- Request body-size limits are enforced on the actual byte count regardless of framing---a chunked oversized body is now rejected with `413` mid-stream, not only when a declared `Content-Length` exceeds the limit.
- Header and query-parameter block rules are enforced on every method (previously `GET` only), and query parameters are matched by exact decoded key (previously a substring match that both over- and under-matched, e.g. `secret_key` matching `my_secret_key`).
- `X-Forwarded-Proto` now reflects the actual inbound scheme (`https` under TLS termination), and `X-Forwarded-For` is replaced with the observed client address unless `trust_forwarded_headers` is enabled.
- The upstream connect timeout is now actually applied (plain, TLS, and health-check clients); previously it was parsed but ignored.
- On shutdown, in-flight connections are drained gracefully within `shutdown_timeout` instead of being aborted.
- Trimmed the `hyper`, `hyper-util`, and `tokio` feature sets to the minimum the crate uses.

### Fixed

- Content-encoded (e.g. gzip) text responses are no longer decoded as text for masking---which corrupted them---and now stream through untouched.
- Active health checks probe `https://` upstreams over TLS instead of always failing over plaintext and flapping healthy backends.
- A masked response now carries a corrected `Content-Length` instead of echoing the upstream's stale value.
- Invalid configuration is rejected at load (zero limits, timeouts, or thresholds; a health-check interval that would panic the health task; duplicate upstreams; malformed addresses) rather than panicking or silently misbehaving at runtime.

### Removed

- `serde_yaml` dependency (archived and unmaintained upstream).

### Security

- Resolved RUSTSEC-2026-0099 (name-constraint checking accepting a wildcard name outside a permitted subtree) and RUSTSEC-2026-0104 (a reachable panic parsing a malformed certificate revocation list) by updating the transitive `rustls-webpki` dependency to a patched release.
- Added a `cargo-deny` policy (`deny.toml`) gating advisories, banned crates, dependency sources, and an enumerated license allow-list, run in CI on a schedule and on any manifest, lockfile, or policy change.

## [0.1.0] - 2026-02-12

Initial release.

### Added

- HTTP reverse proxy built on hyper 1.x, tokio, and rustls
- Weighted round-robin load balancing across multiple upstream backends
- Active health checks with configurable interval, timeout, unhealthy/healthy thresholds, and cooldown
- Passive health tracking on upstream request failures and timeouts
- TLS termination for client-facing HTTPS connections (PEM cert + key)
- TLS origination for HTTPS upstream backends via hyper-rustls
- Per-IP rate limiting using the GCRA algorithm (governor) with automatic stale-entry pruning
- Request policy enforcement: header blocking, query parameter blocking, body size limits
- Sensitive data masking in response bodies via pre-compiled regex patterns
- Hop-by-hop header stripping per RFC 2616 and `Connection`-declared headers
- Configurable response header removal (e.g. `Server`, `X-Powered-By`)
- HTTP request smuggling defense (rejects ambiguous `Transfer-Encoding` + `Content-Length`)
- Concurrency limiting with 503 backpressure when the in-flight cap is reached
- Graceful shutdown with configurable drain timeout for in-flight connections
- TCP_NODELAY on accepted connections for reduced latency
- Monotonic `X-Request-Id` header on every response
- Forwarding headers: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`
- Structured logging via tracing with selectable pretty or JSON output
- YAML-based configuration with nested timeout, pool, health check, and rate limit sections
- CLI interface via clap with `--config`, `--log-format`, and `--log-level` options
- Comprehensive unit and integration test suite covering all major code paths

---

## Guidelines for Contributors

When adding entries to this changelog for future releases:

1. **Format**: Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
2. **Categories**: Use Added, Changed, Deprecated, Removed, Fixed, Security
3. **Audience**: Write for users, not developers (focus on impact, not implementation)
4. **Links**: Add comparison links at the bottom: `[0.3.0]: https://github.com/kobby-pentangeli/palisade/compare/v0.2.0...v0.3.0`

[0.2.0]: https://github.com/kobby-pentangeli/palisade/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kobby-pentangeli/palisade/releases/tag/v0.1.0
