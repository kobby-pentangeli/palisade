# Security Policy

> Palisade is pre-1.0 and under active development. Review this threat model and validate the configuration against your environment before production use.

## Reporting a Vulnerability

Please report security issues privately, **not** through public issues or pull requests. Use GitHub's [private vulnerability reporting](https://github.com/kobby-pentangeli/palisade/security/advisories/new) ("Report a vulnerability" under the repository's *Security* tab). Include a description, the affected component, and a reproduction or proof of concept where possible. You will receive an acknowledgement, and we ask that you allow a reasonable window for a fix before any public disclosure.

## Threat Model

Palisade is a single-process, streaming reverse proxy that sits between untrusted clients and trusted upstream backends. It is the trust boundary: it terminates client connections, enforces request policy, and forwards sanitized requests to upstreams it is configured to trust. The notes below state what that boundary covers and what it does not.

### What the proxy enforces

- **Configuration fails closed at load.** Every invariant (positive limits and timeouts, non-zero rate and health thresholds, a health path beginning with `/`, no duplicate upstreams, a valid listen address, an admin address distinct from the data plane) is validated once in `Config::into_runtime`. The process refuses to start on bad config rather than panicking on the first request.
- **Request policy on every method.** Blocked headers and blocked query parameters are rejected with `403` on all methods, not just `GET`. Query parameters are matched against the decoded query string by exact key, so neither a substring (`secret_key` does not match `my_secret_key`) nor a percent-encoded name bypasses a rule.
- **Request-smuggling defense.** A request carrying both `Content-Length` and `Transfer-Encoding` is rejected with `400` (RFC 9112 §6.1) before forwarding.
- **Body-size limits on actual bytes.** `max_body_size` is enforced on the real byte count regardless of framing; an oversized or chunked body is rejected with `413` mid-stream, not merely on a declared `Content-Length`.
- **Connection-level DoS bounds.** Simultaneously-open client connections are capped (`max_connections`), in-flight requests are capped (`max_concurrent_requests`, `503` on overflow), and a `header_read_timeout` closes slow-header (slowloris) connections.
- **Header hygiene.** Hop-by-hop headers (and any listed in a `Connection` header) are stripped from both directions per RFC 9110 §7.6.1; configured internal response headers (e.g. `Server`, `X-Powered-By`) are removed to avoid leaking backend topology.
- **Forwarding metadata is not spoofable by default.** With `trust_forwarded_headers = false` (the default) the proxy replaces `X-Forwarded-For` with the observed client address and sets `X-Forwarded-Proto` from the real inbound scheme, discarding client-supplied values. Enable the flag only when Palisade itself sits behind a trusted proxy that sets these headers.
- **Response masking.** Configured sensitive parameters are masked in text/form-encoded response bodies, bounded by `mask_max_body_size`; larger or content-encoded bodies stream through untouched rather than being buffered or corrupted.
- **Per-IP rate limiting.** An optional GCRA token bucket keyed by client IP returns `429` with `Retry-After` when exceeded.
- **Operational isolation.** Metrics and health probes are served on a separate admin listener whose bind address is validated to differ from the data plane, so they are never reachable through the client-facing port.

### TLS posture

- **Termination (client → proxy).** `rustls` with the `ring` provider, TLS 1.2 and 1.3, no client authentication, ALPN advertising `h2` then `http/1.1`. The operator supplies the PEM certificate and key.
- **Origination (proxy → upstream).** `https://` upstreams are verified against the Mozilla root bundle vendored by `webpki-roots`, **not** the operating system trust store. An upstream presenting a certificate outside that bundle (e.g. a private CA) will fail verification.

## Out of Scope

The following are the operator's responsibility or are explicitly not addressed in this release:

- **Client authentication / authorization.** Palisade does not authenticate clients; there is no mutual TLS or client-certificate auth in this release. Put authentication in front of or behind the proxy as your design requires.
- **Web application firewalling.** The proxy enforces header/parameter/body-size policy and smuggling defense, but it is not a WAF, i.e., it does not inspect request bodies for attack signatures or sanitize upstream content beyond stripping configured headers and masking configured parameters.
- **Compromised upstreams.** Configured upstreams are trusted. A malicious or compromised backend can return harmful content; the proxy is not a content sanitizer.
- **Volumetric / L3–L4 DoS.** The connection, concurrency, slow-header, and body-size bounds mitigate single-process resource exhaustion. They are not a substitute for upstream DDoS protection. Per-IP rate limiting is best-effort and does not defend against spoofed source addresses, large botnets, or many clients behind a shared NAT.
- **Admin listener exposure.** The proxy enforces that the admin address differs from the data plane, but it cannot enforce your network boundary. Bind the admin listener to an internal interface or host loopback and firewall it; never expose `/metrics` or the probes to untrusted networks.
- **Secret material on disk.** TLS private keys and the configuration file are protected by filesystem permissions you set. Restrict them (e.g. `0640`, owner-only key access) and never commit them.
- **Private-CA upstreams.** Because upstream verification uses the bundled Mozilla roots, upstreams behind a private CA are not supported without code changes; do not disable verification.
