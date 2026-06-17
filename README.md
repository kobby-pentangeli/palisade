# palisade

[![CI](https://github.com/kobby-pentangeli/palisade/workflows/CI/badge.svg)](https://github.com/kobby-pentangeli/palisade/actions)
[![Release](https://img.shields.io/github/v/release/kobby-pentangeli/palisade?sort=semver)](https://github.com/kobby-pentangeli/palisade/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

An HTTP reverse proxy built on [hyper](https://hyper.rs/), [tokio](https://tokio.rs/), and [rustls](https://docs.rs/rustls). Distributes traffic across weighted upstream backends with active and passive health checks, enforces request policies (header/parameter blocking, body size limits, sensitive data masking), and terminates TLS---all with streaming I/O and zero per-request allocation for config lookups.

## Features

- *Weighted round-robin load balancing* across multiple upstreams
- *Active and passive health checks* with configurable thresholds and cooldowns
- *HTTP/1.1 and HTTP/2* with ALPN negotiation on the listener and to HTTPS upstreams
- *TLS termination* (HTTPS clients) and *TLS origination* (HTTPS upstreams) via rustls
- *Per-IP rate limiting* (GCRA token bucket) with automatic stale-entry cleanup
- *Request policy enforcement*: header blocking, query parameter blocking, body size limits
- *Response body masking* of sensitive parameters (passwords, SSNs, etc.)
- *Hop-by-hop header stripping* and response header removal (e.g. `Server`, `X-Powered-By`)
- *HTTP request smuggling defense* (rejects ambiguous `Transfer-Encoding` + `Content-Length`)
- *Concurrency limiting* with 503 backpressure
- *Graceful shutdown* with configurable drain timeout
- *Structured logging* via tracing (pretty or JSON)
- *Prometheus metrics and liveness/readiness probes* on a separate admin listener (off by default)
- *Request correlation* via `X-Request-Id`: a validated inbound id is propagated, otherwise a monotonic one is assigned

## Architecture

Palisade is a single-process, streaming, lock-free-on-the-hot-path reverse proxy. Every inbound request flows through one pipeline:

```text
client → [TLS termination] → accept loop (connection + concurrency bounds)
       → rate limit → smuggling defense → body-size limit → policy (header/param)
       → balancer (smooth weighted round-robin over healthy upstreams)
       → hop-by-hop strip → forwarding headers → host/URI rewrite
       → upstream (HTTP/1.1 or HTTP/2, optional TLS origination)
       → response: hop-by-hop strip → header strip → bounded masking → X-Request-Id
```

The design holds to a few commitments:

- **Streaming, not buffering.** Request and response bodies flow through without being collected into memory; the sole exception, response masking, is explicitly bounded by `mask_max_body_size`.
- **Zero per-request allocation for config lookups.** The hot path reads an immutable `RuntimeConfig` built once at startup: masking regexes are pre-compiled and blocked header names pre-parsed.
- **Lock-free health and selection.** Backend health is tracked with atomics and selection uses atomic running weights; there is no mutex on the request path.
- **Fail closed at load.** Every configuration invariant is validated at startup and surfaced as an error, so the process refuses to start on bad config rather than panicking on a request.

For the module layout see the [Development Guide](./docs/development.md); for the trust boundary see [SECURITY.md](./SECURITY.md).

## Quick Start

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.85+ (edition 2024)

### Build and Run

```bash
git clone https://github.com/kobby-pentangeli/palisade.git
cd palisade
cp config.example.toml config.toml   # create your local config
cargo build --release
```

Edit `config.toml` to point at your backend(s), then start the proxy:

```bash
cargo run --release
# or run the binary directly:
./target/release/palisade
```

The proxy listens on `127.0.0.1:8100` by default. Send some requests:

```bash
# Basic GET — forwarded to an upstream backend
curl -i http://127.0.0.1:8100/

# POST with a JSON body
curl -i http://127.0.0.1:8100/api/users \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "alice"}'

# GET with a blocked query parameter (returns 403)
curl -i "http://127.0.0.1:8100/search?access_token=secret"

# GET with a blocked header (returns 403)
curl -i http://127.0.0.1:8100/ -H "X-Debug-Token: abc123"

# Response includes X-Request-Id and stripped internal headers
curl -si http://127.0.0.1:8100/ | grep -i x-request-id
```

### CLI Options

```text
palisade [OPTIONS]

Options:
  -c, --config <PATH>        Path to TOML config file [default: ./config.toml]
      --log-format <FORMAT>  Log output format: pretty | json [default: pretty]
      --log-level <LEVEL>    Log verbosity, overrides RUST_LOG [e.g. debug, info]
  -h, --help                 Print help
  -V, --version              Print version
```

## Configuration

All configuration lives in a single TOML file. Below is a complete example with defaults shown:

```toml
listen = "127.0.0.1:8100"

max_concurrent_requests = 1000
max_connections = 10000          # simultaneously open client connections
header_read_timeout = 10         # seconds to read full request headers
max_body_size = 10485760         # 10 MiB, enforced on actual bytes
mask_max_body_size = 1048576     # 1 MiB; larger responses stream unmasked
shutdown_timeout = 30            # seconds

blocked_headers = ["X-Debug-Token", "X-Internal-Auth"]
blocked_params = ["access_token", "secret_key"]
masked_params = ["password", "ssn", "credit_card"]
strip_response_headers = ["server", "x-powered-by"]

# replace X-Forwarded-For/Proto unless behind a trusted proxy
trust_forwarded_headers = false

[[upstreams]]
address = "http://localhost:3000"
weight = 1

[[upstreams]]
address = "http://localhost:3001"
weight = 2

[timeouts]
connect = 5                      # seconds
request = 30                     # seconds

[pool]
idle_timeout = 60                # seconds (idle timeout for pooled upstream connections)
max_idle_per_host = 32

[health_check]
path = "/health"
interval = 10                    # seconds
unhealthy_threshold = 3
healthy_threshold = 1
cooldown = 30                    # seconds
timeout = 3                      # seconds

[rate_limit]
requests_per_second = 100
burst = 50

# Admin listener for metrics and health probes (optional, off by default).
# Must bind a different address than the data-plane `listen`.
# [admin]
# listen = "127.0.0.1:9090"

# TLS termination (optional)
# [tls]
# cert_path = "/path/to/cert.pem"
# key_path = "/path/to/key.pem"
```

All time values are in **seconds**. Only `listen` and `upstreams` are required; everything else has sensible defaults. In TOML, all top-level keys must precede the `[section]` and `[[upstreams]]` tables.

## Observability

When an `[admin]` listener is configured, the proxy serves operational endpoints on that address, kept separate from the data plane so they are never reachable by proxy clients:

- `GET /metrics` --- Prometheus/OpenMetrics exposition: request counts by status (`palisade_requests_total`), latency histogram (`palisade_request_duration_seconds`), per-upstream health (`palisade_upstream_healthy`), rate-limit rejections (`palisade_rate_limited_requests_total`), and in-flight request / open-connection saturation gauges.
- `GET /livez` --- process liveness, for container restart probes.
- `GET /readyz` --- readiness, `200` while at least one upstream is healthy and `503` otherwise, for load-balancer and orchestrator gating.

Every response carries an `X-Request-Id`. A well-formed inbound `X-Request-Id` is propagated for end-to-end correlation, otherwise the proxy assigns a monotonic per-process id.

## Deployment

A multi-stage [`Dockerfile`](./Dockerfile) builds a small distroless image, and a [`docker-compose.yml`](./docker-compose.yml) runs the proxy in front of a demo echo backend:

```bash
docker compose up --build
curl -i http://localhost:8100/
```

A hardened [`systemd` unit](./deploy/palisade.service) is provided for bare-metal hosts. See the [Deployment Guide](./deploy/README.md) for the container image, the compose demo, systemd installation, and operational guidance (health gating, metrics scraping, TLS, graceful shutdown).

## Development

For toolchains, the project layout, and the test organization, see the [Development Guide](./docs/development.md). The canonical dev commands are:

```bash
cargo build                                                # debug build
cargo test --all-features                                  # run all tests
cargo +nightly fmt                                         # format
cargo clippy --all-features --all-targets -- -D warnings   # lint
cargo build --release --all-features --all-targets         # release build
```

## Security

Palisade is the trust boundary between untrusted clients and trusted upstreams: it validates configuration at load, enforces request policy on every method, defends against request smuggling and slow-header/oversized-body attacks, and does not trust client-supplied forwarding headers by default. See [SECURITY.md](./SECURITY.md) for the full threat model, what is out of scope, and how to report a vulnerability.

## Contributing

All contributions large and small are actively accepted.

- Read the [contribution guidelines](./CONTRIBUTING.md).
- Browse [Good First Issues](https://github.com/kobby-pentangeli/palisade/labels/good%20first%20issue).

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT license](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this codebase by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
