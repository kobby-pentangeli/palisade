//! HTTP header processing: hop-by-hop removal, forwarding header injection,
//! host rewriting, and response header sanitization.
//!
//! Implements the header-level requirements of RFC 9110 Section 7.6.1
//! (connection-scoped header handling) and the de-facto `X-Forwarded-*`
//! convention for reverse proxies.

use std::net::SocketAddr;

use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::http::uri::Authority;

/// Removes all hop-by-hop headers from the given header map.
///
/// Strips the standard set (`Connection`, `Keep-Alive`,
/// `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`,
/// `Transfer-Encoding`, `Upgrade`), plus any additional header names
/// declared in the `Connection` header value, per RFC 9110 Section 7.6.1.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let conn: Vec<HeaderName> = headers
        .get("connection")
        .and_then(|val| val.to_str().ok())
        .map(|val| {
            val.split(',')
                .filter_map(|s| HeaderName::from_bytes(s.trim().as_bytes()).ok())
                .collect()
        })
        .unwrap_or_default();

    conn.iter().for_each(|name| {
        headers.remove(name);
    });

    [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .for_each(|name| {
        headers.remove(*name);
    });
}

/// Injects `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`
/// headers into the given header map.
///
/// `client_tls` reflects whether the inbound client connection was
/// TLS-terminated by this proxy, and `trust_forwarded` selects how
/// client-supplied forwarding metadata is treated.
pub fn inject_forwarding_headers(
    headers: &mut HeaderMap,
    client_addr: SocketAddr,
    client_tls: bool,
    trust_forwarded: bool,
) {
    let client_ip = client_addr.ip().to_string();

    let xff_value = if trust_forwarded {
        headers
            .get("x-forwarded-for")
            .and_then(|existing| existing.to_str().ok())
            .map(|existing| format!("{existing}, {client_ip}"))
            .unwrap_or(client_ip)
    } else {
        client_ip
    };

    if let Ok(val) = HeaderValue::from_str(&xff_value) {
        headers.insert("x-forwarded-for", val);
    }

    if !(trust_forwarded && headers.contains_key("x-forwarded-proto")) {
        let proto = if client_tls { "https" } else { "http" };
        headers.insert("x-forwarded-proto", HeaderValue::from_static(proto));
    }

    if let Some(host) = headers.get(hyper::header::HOST) {
        headers.insert("x-forwarded-host", host.clone());
    }
}

/// Rewrites the `Host` header to match the upstream authority.
///
/// This ensures the upstream server receives the correct `Host` value
/// regardless of what the client originally sent.
pub fn rewrite_host(headers: &mut HeaderMap, upstream_auth: &Authority) {
    if let Ok(val) = HeaderValue::from_str(upstream_auth.as_str()) {
        headers.insert(hyper::header::HOST, val);
    }
}

/// Removes configured internal headers from an upstream response before
/// returning it to the client, preventing leakage of backend topology.
pub fn strip_response_headers(headers: &mut HeaderMap, names: &[String]) {
    names.iter().for_each(|name| {
        if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&header_name);
        }
    });
}

/// Returns `true` if the request contains both `Content-Length` and
/// `Transfer-Encoding` headers, which is a request smuggling indicator
/// per RFC 9112 Section 6.1.
pub fn is_smuggling_attempt(headers: &HeaderMap) -> bool {
    headers.contains_key(hyper::header::CONTENT_LENGTH)
        && headers.contains_key(hyper::header::TRANSFER_ENCODING)
}

/// Returns `true` if the `Content-Length` header value exceeds the given
/// maximum body size in bytes.
///
/// Returns `false` if no `Content-Length` is present or the value is
/// unparseable (hyper handles malformed content-length at the protocol level).
pub fn content_length_exceeds(headers: &HeaderMap, max_bytes: u64) -> bool {
    headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|val| val.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|len| len > max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_MAX_BODY_SIZE;

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .fold(HeaderMap::new(), |mut map, (name, value)| {
                map.insert(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_str(value).unwrap(),
                );
                map
            })
    }

    #[test]
    fn strips_standard_hop_by_hop_headers() {
        let mut headers = header_map(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("x-custom", "preserved"),
        ]);

        strip_hop_by_hop(&mut headers);

        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("transfer-encoding"));

        assert!(headers.contains_key("x-custom"));
    }

    #[test]
    fn strips_connection_declared_headers() {
        let mut headers = header_map(&[
            ("connection", "x-secret-internal, x-debug-token"),
            ("x-secret-internal", "leaked"),
            ("x-debug-token", "abc"),
            ("x-safe", "keep"),
        ]);

        strip_hop_by_hop(&mut headers);

        assert!(!headers.contains_key("x-secret-internal"));
        assert!(!headers.contains_key("x-debug-token"));
        assert!(!headers.contains_key("connection"));

        assert!(headers.contains_key("x-safe"));
    }

    #[test]
    fn injects_xff_with_no_prior_value() {
        let mut headers = HeaderMap::new();
        let addr = "192.168.1.10:5000".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, false);

        assert_eq!(
            headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "192.168.1.10"
        );
    }

    #[test]
    fn replaces_existing_xff_when_untrusted() {
        let mut headers = header_map(&[("x-forwarded-for", "10.0.0.1")]);
        let addr = "192.168.1.10:5000".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, false);

        assert_eq!(
            headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "192.168.1.10"
        );
    }

    #[test]
    fn appends_to_existing_xff_when_trusted() {
        let mut headers = header_map(&[("x-forwarded-for", "10.0.0.1")]);
        let addr = "192.168.1.10:5000".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, true);

        assert_eq!(
            headers.get("x-forwarded-for").unwrap().to_str().unwrap(),
            "10.0.0.1, 192.168.1.10"
        );
    }

    #[test]
    fn injects_forwarded_proto_http() {
        let mut headers = HeaderMap::new();
        let addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, false);

        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "http"
        );
    }

    #[test]
    fn injects_forwarded_proto_https_under_tls() {
        let mut headers = HeaderMap::new();
        let addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, true, false);

        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "https"
        );
    }

    #[test]
    fn overwrites_spoofed_forwarded_proto_when_untrusted() {
        let mut headers = header_map(&[("x-forwarded-proto", "https")]);
        let addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, false);

        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "http"
        );
    }

    #[test]
    fn preserves_forwarded_proto_when_trusted() {
        let mut headers = header_map(&[("x-forwarded-proto", "https")]);
        let addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, true);

        assert_eq!(
            headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
            "https"
        );
    }

    #[test]
    fn injects_forwarded_host_from_original() {
        let mut headers = header_map(&[("host", "api.example.com")]);
        let addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, false);

        assert_eq!(
            headers.get("x-forwarded-host").unwrap().to_str().unwrap(),
            "api.example.com"
        );
    }

    #[test]
    fn no_forwarded_host_when_host_absent() {
        let mut headers = HeaderMap::new();
        let addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();

        inject_forwarding_headers(&mut headers, addr, false, false);

        assert!(!headers.contains_key("x-forwarded-host"));
    }

    #[test]
    fn rewrites_host_to_upstream_authority() {
        let mut headers = header_map(&[("host", "client-facing.com")]);
        let authority = "backend.internal:3000".parse::<Authority>().unwrap();

        rewrite_host(&mut headers, &authority);

        assert_eq!(
            headers.get("host").unwrap().to_str().unwrap(),
            "backend.internal:3000"
        );
    }

    #[test]
    fn strips_configured_response_headers() {
        let mut headers = header_map(&[
            ("server", "nginx/1.25"),
            ("x-powered-by", "Express"),
            ("content-type", "text/html"),
        ]);

        strip_response_headers(&mut headers, &["server".into(), "x-powered-by".into()]);

        assert!(!headers.contains_key("server"));
        assert!(!headers.contains_key("x-powered-by"));
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn detects_smuggling_attempt() {
        let headers = header_map(&[("content-length", "42"), ("transfer-encoding", "chunked")]);
        assert!(is_smuggling_attempt(&headers));
    }

    #[test]
    fn no_smuggling_with_only_content_length() {
        let headers = header_map(&[("content-length", "42")]);
        assert!(!is_smuggling_attempt(&headers));
    }

    #[test]
    fn no_smuggling_with_only_transfer_encoding() {
        let headers = header_map(&[("transfer-encoding", "chunked")]);
        assert!(!is_smuggling_attempt(&headers));
    }

    #[test]
    fn content_length_within_limit() {
        let headers = header_map(&[("content-length", "1024")]);
        assert!(!content_length_exceeds(&headers, DEFAULT_MAX_BODY_SIZE));
    }

    #[test]
    fn content_length_exceeds_limit() {
        let headers = header_map(&[("content-length", "20000000")]);
        assert!(content_length_exceeds(&headers, DEFAULT_MAX_BODY_SIZE));
    }

    #[test]
    fn missing_content_length_does_not_exceed() {
        let headers = HeaderMap::new();
        assert!(!content_length_exceeds(&headers, DEFAULT_MAX_BODY_SIZE));
    }

    #[test]
    fn unparseable_content_length_does_not_exceed() {
        let headers = header_map(&[("content-length", "not-a-number")]);
        assert!(!content_length_exceeds(&headers, DEFAULT_MAX_BODY_SIZE));
    }
}
