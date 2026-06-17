//! Core proxy handler: request forwarding, body streaming, and filtering.
//!
//! Implements the full proxy pipeline including HTTP spec compliance
//! (hop-by-hop header stripping, forwarding headers, request smuggling
//! defense) and policy enforcement (header/param blocking, body size
//! limits, response masking, load balancing).
//!
//! Every inbound request is assigned a request ID---a validated inbound
//! `X-Request-Id` when the client supplies one, otherwise a monotonic
//! per-process counter---and wrapped in a [`tracing::Span`] carrying
//! structured fields for observability.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::HeaderName;
use hyper::{Request, Response, Uri, Version};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use tokio::time::timeout;
use tracing::{Instrument, debug, info, warn};

use crate::{IpRateLimiter, LoadBalancer, ProxyError, Result, RuntimeConfig, headers, tls};

/// Maximum accepted length of an inbound `X-Request-Id`. Bounds the value the
/// proxy echoes and logs, defending against oversized or log-injecting ids.
const MAX_REQUEST_ID_LEN: usize = 128;

/// An alias to simplify the calls to `Box<dyn std::error::Error + Send + Sync>`.
type StdError = Box<dyn std::error::Error + Send + Sync>;

/// Type-erased body used for both request forwarding and response streaming.
///
/// Wraps any body implementation behind a single boxed trait object,
/// allowing the handler to accept requests with arbitrary body types
/// (e.g. `Incoming`, `Full<Bytes>`, `Empty<Bytes>`) and return a uniform
/// response type regardless of origin.
///
/// Uses a trait-object error type so that both `Incoming` (which yields
/// `hyper::Error`) and locally constructed bodies (which are infallible)
/// can be erased into the same type without lossy conversions.
pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, StdError>;

/// The HTTP client type for plain TCP upstream connections.
pub type HttpClient = Client<HttpConnector, BoxBody>;

/// The HTTPS client type for TLS-secured upstream connections.
pub type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody>;

/// Global monotonic counter for assigning unique request IDs.
static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Constructs a new [`HttpClient`] for plain HTTP upstream connections.
pub fn build_client(config: &RuntimeConfig) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(config.connect_timeout));
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(config.pool_idle_timeout)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .build(connector)
}

/// Constructs a new [`HttpsClient`] capable of both HTTP and HTTPS
/// upstream connections, using the Mozilla root certificate store for
/// server verification.
pub fn build_https_client(config: &RuntimeConfig) -> HttpsClient {
    let connector = tls::build_https_connector(config.connect_timeout);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(config.pool_idle_timeout)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .build(connector)
}

/// Processes a single inbound request through the proxy pipeline.
///
/// The pipeline performs the following steps in order:
///
/// 1. **Rate limiting** — If a rate limiter is configured, the client IP is
///    checked against the per-IP token bucket. Requests exceeding the limit
///    receive a 429 Too Many Requests response with a `Retry-After` header.
/// 2. **Request smuggling defense** — Rejects requests carrying both
///    `Content-Length` and `Transfer-Encoding` headers (RFC 9112 §6.1).
/// 3. **Body size enforcement** — Rejects requests whose declared
///    `Content-Length` exceeds `max_body_size` up front, and wraps the
///    forwarded body in a length limit so an oversized or chunked body is
///    rejected on actual byte count mid-stream with 413 Payload Too Large.
/// 4. **Policy inspection** — On every method, blocked headers and query
///    parameters are checked. The query string is parsed into decoded
///    key/value pairs and matched by exact key, so a substring or
///    percent-encoded parameter name cannot bypass a block rule. Requests
///    matching any rule receive a 403 Forbidden response.
/// 5. **Upstream selection** — The round-robin balancer selects the next
///    healthy backend. If none are available, returns 503.
/// 6. **Hop-by-hop stripping** — Connection-scoped headers are removed
///    before forwarding, per RFC 9110 §7.6.1.
/// 7. **Forwarding headers** — `X-Forwarded-For`, `X-Forwarded-Proto`, and
///    `X-Forwarded-Host` are injected to preserve client origin metadata.
///    `X-Forwarded-Proto` reflects the actual inbound scheme; unless
///    `trust_forwarded_headers` is enabled, `X-Forwarded-For` is replaced
///    with the observed client address rather than trusting client input.
/// 8. **Host rewriting** — The `Host` header is set to the upstream authority.
/// 9. **URI rewriting** — The request URI is rewritten to target the selected
///    upstream, preserving the original path and query string.
/// 10. **Body streaming** — The request body is passed through to the upstream
///     without buffering.
/// 11. **Passive health tracking** — On upstream success, the backend's
///     failure counter is reset. On failure/timeout, it is incremented and
///     the backend may be marked unhealthy.
/// 12. **Response hop-by-hop stripping** — Connection-scoped headers are
///     removed from the upstream response.
/// 13. **Response header stripping** — Configured internal headers (e.g.
///     `Server`, `X-Powered-By`) are removed from the response.
/// 14. **Response masking** — For text-based upstream responses within the
///     configured masking ceiling, sensitive parameter values are masked
///     before returning to the client; larger or unbounded responses stream
///     through unmasked rather than being buffered.
/// 15. **Request ID injection** — An `X-Request-Id` header is added to every
///     response for client-side log correlation: a validated inbound id is
///     propagated when present, otherwise the monotonic per-process id is used.
pub async fn handle_request<B, C>(
    req: Request<B>,
    client: Client<C, BoxBody>,
    config: Arc<RuntimeConfig>,
    balancer: LoadBalancer,
    client_addr: SocketAddr,
    client_tls: bool,
    rate_limiter: Option<&IpRateLimiter>,
) -> Result<Response<BoxBody>>
where
    B: hyper::body::Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<StdError>,
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    let seq = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let request_id = inbound_request_id(req.headers()).unwrap_or_else(|| seq.to_string());
    let method = req.method().clone();
    let uri = req.uri().clone();

    let span = tracing::info_span!(
        "request",
        id = %request_id,
        method = %method,
        uri = %uri,
        client = %client_addr,
    );

    async move {
        if let Some(limiter) = rate_limiter {
            limiter.check(&client_addr.ip()).map_err(|retry_after_ms| {
                warn!(
                    ip = %client_addr.ip(),
                    retry_after_ms,
                    "rate limit exceeded"
                );
                ProxyError::RateLimited { retry_after_ms }
            })?;
        }

        if headers::is_smuggling_attempt(req.headers()) {
            warn!("request smuggling attempt detected");
            return Err(ProxyError::RequestSmuggling);
        }

        if headers::content_length_exceeds(req.headers(), config.max_body_size) {
            let declared = req
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            warn!(
                content_length = declared,
                limit = config.max_body_size,
                "request body exceeds size limit"
            );
            return Err(ProxyError::BodyTooLarge {
                limit: config.max_body_size,
            });
        }

        inspect_request(&req, &config)?;

        let upstream = balancer.next()?;
        let upstream_uri_target = upstream.uri();
        info!(upstream = %upstream_uri_target, "received request");

        let rewritten_uri = rewrite_uri(&uri, upstream_uri_target)?;
        let (mut parts, body) = req.into_parts();

        headers::strip_hop_by_hop(&mut parts.headers);
        headers::inject_forwarding_headers(
            &mut parts.headers,
            client_addr,
            client_tls,
            config.trust_forwarded_headers,
        );
        headers::rewrite_host(
            &mut parts.headers,
            upstream_uri_target
                .authority()
                .ok_or_else(|| ProxyError::InvalidUpstream("upstream has no authority".into()))?,
        );

        config.blocked_headers.iter().for_each(|name| {
            parts.headers.remove(name);
        });

        parts.uri = rewritten_uri;

        // The inbound and upstream legs are independent: the upstream
        // protocol is chosen by its connection (plain HTTP/1.1, or ALPN
        // negotiation for TLS), so the forwarded request must not inherit the
        // client's negotiated version. An explicit HTTP/2 version would force
        // the client to require h2 and fail against an HTTP/1-only upstream.
        parts.version = Version::HTTP_11;

        debug!(
            headers = ?parts.headers,
            upstream_uri = %parts.uri,
            "forwarding request"
        );

        let start = std::time::Instant::now();
        let elapsed_ms = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let body_limit = usize::try_from(config.max_body_size).unwrap_or(usize::MAX);
        let proxy_req = Request::from_parts(parts, Limited::new(body, body_limit).boxed());

        let upstream_result = timeout(config.request_timeout, client.request(proxy_req)).await;

        let mut upstream_resp = match upstream_result {
            Ok(Ok(resp)) => {
                upstream.record_success(config.healthy_threshold);
                resp
            }
            Ok(Err(e)) => {
                if is_length_limit_error(&e) {
                    warn!(
                        limit = config.max_body_size,
                        upstream = %upstream_uri_target,
                        "request body exceeded size limit mid-stream"
                    );
                    return Err(ProxyError::BodyTooLarge {
                        limit: config.max_body_size,
                    });
                }
                let transitioned = upstream.record_failure(config.failure_threshold);
                warn!(
                    error = %e,
                    latency_ms = elapsed_ms(),
                    upstream = %upstream_uri_target,
                    marked_unhealthy = transitioned,
                    "upstream request failed"
                );
                return Err(ProxyError::Upstream(e));
            }
            Err(_elapsed) => {
                let transitioned = upstream.record_failure(config.failure_threshold);
                warn!(
                    timeout = ?config.request_timeout,
                    latency_ms = elapsed_ms(),
                    upstream = %upstream_uri_target,
                    marked_unhealthy = transitioned,
                    "upstream request timed out"
                );
                return Err(ProxyError::Timeout(config.request_timeout));
            }
        };

        let latency_ms = elapsed_ms();
        info!(
            status = upstream_resp.status().as_u16(),
            latency_ms,
            upstream = %upstream_uri_target,
            "upstream responded"
        );

        headers::strip_hop_by_hop(upstream_resp.headers_mut());
        if !config.strip_response_headers.is_empty() {
            headers::strip_response_headers(
                upstream_resp.headers_mut(),
                &config.strip_response_headers,
            );
        }

        let mut resp = build_response(upstream_resp, &config).await?;
        let id_value = hyper::header::HeaderValue::from_str(&request_id)
            .unwrap_or_else(|_| hyper::header::HeaderValue::from(seq));
        resp.headers_mut()
            .insert(HeaderName::from_static("x-request-id"), id_value);
        Ok(resp)
    }
    .instrument(span)
    .await
}

/// Extracts a client-supplied `X-Request-Id` to propagate, if present and
/// well-formed. Accepts a non-empty, length-bounded value of visible ASCII
/// characters; anything else is rejected so the proxy falls back to its own
/// monotonic identifier.
fn inbound_request_id(headers: &hyper::header::HeaderMap) -> Option<String> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|id| {
            !id.is_empty()
                && id.len() <= MAX_REQUEST_ID_LEN
                && id.bytes().all(|b| b.is_ascii_graphic())
        })
        .map(str::to_owned)
}

/// Checks a request against configured block rules, regardless of method.
///
/// Blocked headers are matched by name. Blocked query parameters are matched
/// against the decoded query string by exact key, so neither a substring
/// (`secret_key` does not match `my_secret_key`) nor a percent-encoded name
/// can slip past a rule.
///
/// Returns `ProxyError::BlockedHeader` or `ProxyError::BlockedParam`
/// if any rule matches, allowing the caller to short-circuit with a 403.
fn inspect_request<B>(req: &Request<B>, config: &RuntimeConfig) -> Result<()> {
    let headers = req.headers();
    config
        .blocked_headers
        .iter()
        .find(|name| headers.contains_key(*name))
        .map_or(Ok(()), |name| {
            warn!(header = %name, "blocked header detected");
            Err(ProxyError::BlockedHeader(name.to_string()))
        })?;

    let query = req.uri().query().unwrap_or_default();
    form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| {
            config
                .blocked_params
                .iter()
                .any(|param| param.as_str() == key.as_ref())
        })
        .map_or(Ok(()), |(key, _)| {
            warn!(param = %key, "blocked parameter detected");
            Err(ProxyError::BlockedParam(key.into_owned()))
        })
}

/// Rewrites the original request URI to target the configured upstream,
/// preserving the path and query string.
fn rewrite_uri(original: &Uri, upstream: &Uri) -> Result<Uri> {
    let authority = upstream
        .authority()
        .ok_or_else(|| ProxyError::InvalidUpstream("upstream has no authority".into()))?;

    let scheme = upstream
        .scheme()
        .ok_or_else(|| ProxyError::InvalidUpstream("upstream has no scheme".into()))?;

    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    Uri::builder()
        .scheme(scheme.clone())
        .authority(authority.clone())
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| ProxyError::Internal(format!("failed to build upstream URI: {e}")))
}

/// Returns `true` if any error in the chain is a body length-limit overflow,
/// signalling that the forwarded request body exceeded `max_body_size`.
fn is_length_limit_error(err: &(dyn std::error::Error + 'static)) -> bool {
    std::iter::successors(Some(err), |e| e.source()).any(|e| e.is::<LengthLimitError>())
}

/// Builds the client-facing response from the upstream response.
///
/// A response is buffered and scanned for sensitive parameter values only
/// when masking is configured, its `Content-Type` indicates text or
/// form-encoded data, it carries no content coding, and its declared
/// `Content-Length` is within the configured masking ceiling. Every other
/// response---no masking rules, non-text or content-encoded content, or a
/// body that is unbounded or larger than the ceiling---is streamed through
/// unmodified so the proxy never buffers an upstream body unboundedly and
/// never decodes a compressed body as text. The collect is additionally
/// bounded by the ceiling to guard against an upstream that understates its
/// length.
async fn build_response(
    upstream_resp: Response<Incoming>,
    config: &RuntimeConfig,
) -> Result<Response<BoxBody>> {
    let maskable_content_type = upstream_resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .is_some_and(|ct| ct.contains("text/") || ct.contains("application/x-www-form-urlencoded"));

    let content_encoded = upstream_resp
        .headers()
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .is_some_and(|enc| !enc.is_empty() && !enc.eq_ignore_ascii_case("identity"));

    let within_ceiling = upstream_resp
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|len| len <= config.mask_max_body_size);

    if config.mask_rules.is_empty() || !maskable_content_type || content_encoded || !within_ceiling
    {
        if !config.mask_rules.is_empty() && maskable_content_type && !within_ceiling {
            debug!(
                ceiling = config.mask_max_body_size,
                "maskable response has no declared length or exceeds masking ceiling; streaming unmasked"
            );
        }
        let (parts, body) = upstream_resp.into_parts();
        return Ok(Response::from_parts(
            parts,
            body.map_err(|e| -> StdError { Box::new(e) }).boxed(),
        ));
    }

    let (parts, body) = upstream_resp.into_parts();
    let ceiling = usize::try_from(config.mask_max_body_size).unwrap_or(usize::MAX);
    let body_bytes = Limited::new(body, ceiling)
        .collect()
        .await
        .map_err(|e| {
            ProxyError::Internal(format!("failed to read upstream body for masking: {e}"))
        })?
        .to_bytes();

    let body_str = String::from_utf8_lossy(&body_bytes);
    let masked = Bytes::from(config.mask_sensitive_data(&body_str));
    let masked_len = masked.len();

    let mut response = Response::new(
        Full::new(masked)
            .map_err(|never| -> StdError { match never {} })
            .boxed(),
    );
    *response.status_mut() = parts.status;
    *response.headers_mut() = parts.headers;
    *response.version_mut() = parts.version;
    response.headers_mut().insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from(masked_len),
    );

    Ok(response)
}

#[cfg(test)]
mod tests {
    use http_body_util::Empty;
    use hyper::Method;

    use super::*;
    use crate::Config;
    use crate::config::UpstreamConfig;

    fn parse_uri(uri: &str) -> Uri {
        uri.parse::<Uri>().expect("failed to parse URI")
    }

    fn single_upstream(addr: &str) -> Vec<UpstreamConfig> {
        vec![UpstreamConfig {
            address: addr.into(),
            weight: 1,
        }]
    }

    #[test]
    fn rewrite_uri_preserves_path_and_query() {
        let original = parse_uri("http://client-facing.com/api/v1?key=val");
        let upstream = parse_uri("http://localhost:3000");

        let result = rewrite_uri(&original, &upstream).unwrap();
        assert_eq!(result.scheme_str(), Some("http"));
        assert_eq!(result.authority().unwrap().as_str(), "localhost:3000");
        assert_eq!(result.path_and_query().unwrap().as_str(), "/api/v1?key=val");
    }

    #[test]
    fn rewrite_uri_defaults_to_root_path() {
        let original = parse_uri("http://client-facing.com");
        let upstream = parse_uri("http://localhost:3000");

        let result = rewrite_uri(&original, &upstream).unwrap();
        assert_eq!(result.path_and_query().unwrap().as_str(), "/");
    }

    #[test]
    fn inspect_detects_blocked_header() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_headers: vec!["x-bad-header".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/")
            .header("x-bad-header", "anything")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let result = inspect_request(&req, &config);
        assert!(result.is_err());
    }

    #[test]
    fn inspect_detects_blocked_param() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_params: vec!["secret_key".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/?secret_key=abc123")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let result = inspect_request(&req, &config);
        assert!(result.is_err());
    }

    #[test]
    fn inspect_enforces_blocked_header_on_non_get() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_headers: vec!["x-bad-header".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::POST)
            .uri("http://example.com/resource")
            .header("x-bad-header", "anything")
            .body(Empty::<Bytes>::new())
            .unwrap();

        assert!(inspect_request(&req, &config).is_err());
    }

    #[test]
    fn inspect_blocked_param_requires_exact_key() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_params: vec!["secret_key".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/?my_secret_key=abc123")
            .body(Empty::<Bytes>::new())
            .unwrap();

        assert!(inspect_request(&req, &config).is_ok());
    }

    #[test]
    fn inspect_blocked_param_matches_percent_encoded_key() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_params: vec!["secret key".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/?secret%20key=abc123")
            .body(Empty::<Bytes>::new())
            .unwrap();

        assert!(inspect_request(&req, &config).is_err());
    }

    #[test]
    fn inspect_allows_clean_request() {
        let config = Config {
            upstreams: single_upstream("http://localhost:3000"),
            blocked_headers: vec!["x-bad-header".into()],
            blocked_params: vec!["secret_key".into()],
            ..Default::default()
        }
        .into_runtime()
        .unwrap();

        let req = Request::builder()
            .method(Method::GET)
            .uri("http://example.com/path?safe=true")
            .header("x-good-header", "ok")
            .body(Empty::<Bytes>::new())
            .unwrap();

        assert!(inspect_request(&req, &config).is_ok());
    }
}
