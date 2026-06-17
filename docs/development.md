# Development Guide

This guide covers the toolchains, commands, and layout needed to build, test, and lint Palisade. For deployment, see the [Deployment Guide](../deploy/README.md); for the security posture, see [SECURITY.md](../SECURITY.md).

## Toolchains

- **Rust stable** for building and testing. The crate uses the 2024 edition, which requires Rust **1.85 or newer**.
- **Rust nightly** for formatting only: the project formats with `cargo +nightly fmt` (the style in `rustfmt.toml` uses unstable options).

```bash
rustup toolchain install stable
rustup toolchain install nightly
rustup component add clippy
```

No other toolchains, system libraries, or services are required: TLS is provided by `rustls` with the `ring` provider, so there is no OpenSSL build dependency, and the integration tests spin up their own throwaway HTTP/TLS backends in-process.

## Dev commands

Run these from the repository root before opening a pull request; CI gates on all of them:

```bash
cargo +nightly fmt
cargo clippy --all-features --all-targets -- -D warnings
cargo build --release --all-features --all-targets
cargo doc --all-features --no-deps --document-private-items
cargo test --all-features --all-targets
cargo test --all-features --doc
```

## Project layout

Palisade is a single crate exposing both a library (`src/lib.rs`) and a binary (`src/main.rs`); `main` is a thin wiring layer over the library so the server logic stays testable without process-level concerns.

| Path                | Responsibility                                                     |
| ------------------- | ------------------------------------------------------------------ |
| `src/config.rs`     | TOML loading, validation, and the pre-compiled `RuntimeConfig`.    |
| `src/proxy.rs`      | The request pipeline: filtering, forwarding, masking, body limits. |
| `src/server.rs`     | Accept loop, graceful shutdown, health-check and cleanup tasks.    |
| `src/balancer.rs`   | Smooth weighted round-robin selection over the upstream pool.      |
| `src/upstream.rs`   | Per-backend lock-free health state and half-open recovery.         |
| `src/headers.rs`    | Hop-by-hop stripping, forwarding headers, smuggling detection.     |
| `src/tls.rs`        | TLS termination and origination setup.                             |
| `src/rate_limit.rs` | Per-IP GCRA rate limiter.                                          |
| `src/metrics.rs`    | Prometheus registry; `src/admin.rs` serves it plus health probes.  |
| `src/error.rs`      | `ProxyError` and its HTTP status / JSON-body mapping.              |

## Tests

- **Unit tests** live in `#[cfg(test)]` modules beside the code they cover (config validation, header logic, health transitions, balancer distribution, masking).
- **Integration tests** live in `tests/`, driving `handle_request` and the real `serve` loop against throwaway backends. Shared fixtures (backend servers, config builders, self-signed certs) are in `tests/common/mod.rs`.

## Supply chain

Dependency advisories, license policy, banned crates, and source registries are gated by [`deny.toml`](../deny.toml):

```bash
cargo install cargo-deny    # once
cargo deny check advisories bans sources licenses
```

The security workflow runs the same check on a schedule and whenever a manifest, the lockfile, or `deny.toml` changes.
