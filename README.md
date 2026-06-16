# palisade

[![Crates.io](https://img.shields.io/crates/v/palisade.svg)](https://crates.io/crates/palisade)
[![Documentation](https://docs.rs/palisade/badge.svg)](https://docs.rs/palisade)
[![CI](https://github.com/kobby-pentangeli/palisade/workflows/CI/badge.svg)](https://github.com/kobby-pentangeli/palisade/actions)
[![License](https://img.shields.io/crates/l/palisade.svg)](https://github.com/kobby-pentangeli/palisade#license)

An HTTP reverse proxy built on [hyper](https://hyper.rs/), [tokio](https://tokio.rs/), and [rustls](https://docs.rs/rustls). Distributes traffic across weighted upstream backends with active and passive health checks, enforces request policies (header/parameter blocking, body size limits, sensitive data masking), and terminates TLS -- all with streaming I/O and zero per-request allocation for config lookups.

## Features

- *Weighted round-robin load balancing* across multiple upstreams
- *Active and passive health checks* with configurable thresholds and cooldowns
- *TLS termination* (HTTPS clients) and *TLS origination* (HTTPS upstreams) via rustls
- *Per-IP rate limiting* (GCRA token bucket) with automatic stale-entry cleanup
- *Request policy enforcement*: header blocking, query parameter blocking, body size limits
- *Response body masking* of sensitive parameters (passwords, SSNs, etc.)
- *Hop-by-hop header stripping* and response header removal (e.g. `Server`, `X-Powered-By`)
- *HTTP request smuggling defense* (rejects ambiguous `Transfer-Encoding` + `Content-Length`)
- *Concurrency limiting* with 503 backpressure
- *Graceful shutdown* with configurable drain timeout
- *Structured logging* via tracing (pretty or JSON)
- *Monotonic `X-Request-Id`* on every response

## Quick Start

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.85+ (edition 2024)

### Build and Run

```bash
git clone https://github.com/kobby-pentangeli/palisade.git
cd palisade
cp Config.example.yml Config.yml   # create your local config
cargo build --release
```

Edit `Config.yml` to point at your backend(s), then start the proxy:

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
  -c, --config <PATH>        Path to YAML config file [default: ./Config.yml]
      --log-format <FORMAT>  Log output format: pretty | json [default: pretty]
      --log-level <LEVEL>    Log verbosity, overrides RUST_LOG [e.g. debug, info]
  -h, --help                 Print help
  -V, --version              Print version
```

## Configuration

All configuration lives in a single YAML file. Below is a complete example with defaults shown:

```yaml
listen: "127.0.0.1:8100"

upstreams:
  - address: "http://localhost:3000"
    weight: 1
  - address: "http://localhost:3001"
    weight: 2

timeouts:
  connect: 5       # seconds
  request: 30      # seconds

pool:
  idle_timeout: 60       # seconds  (idle timeout for pooled upstream connections)
  max_idle_per_host: 32

max_concurrent_requests: 1000
max_connections: 10000          # simultaneously open client connections
header_read_timeout: 10         # seconds to read full request headers
max_body_size: 10485760         # 10 MiB, enforced on actual bytes
mask_max_body_size: 1048576     # 1 MiB; larger responses stream unmasked

blocked_headers:
  - X-Debug-Token
  - X-Internal-Auth

blocked_params:
  - access_token
  - secret_key

masked_params:
  - password
  - ssn
  - credit_card

strip_response_headers:
  - server
  - x-powered-by

health_check:
  path: /health
  interval: 10            # seconds
  unhealthy_threshold: 3
  healthy_threshold: 1
  cooldown: 30            # seconds
  timeout: 3              # seconds

rate_limit:
  requests_per_second: 100
  burst: 50

shutdown_timeout: 30  # seconds

# TLS termination (optional)
# tls:
#   cert_path: /path/to/cert.pem
#   key_path: /path/to/key.pem
```

All time values are in **seconds**. Only `listen` and `upstreams` are required; everything else has sensible defaults.

## Development

```bash
cargo build                                                # debug build
cargo test --all-features                                  # run all tests
cargo +nightly fmt                                         # format
cargo clippy --all-features --all-targets -- -D warnings   # lint
cargo build --release --all-features --all-targets         # release build
```

## Contributing

All contributions large and small are actively accepted.

- Read the [contribution guidelines](./CONTRIBUTING.md).
- Browse [Good First Issues](https://github.com/kobby-pentangeli/palisade/labels/good%20first%20issue).

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or [MIT license](./LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this codebase by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
