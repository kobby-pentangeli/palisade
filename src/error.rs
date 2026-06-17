//! Error types and HTTP status code mapping.
//!
//! Provides the [ProxyError] type that captures every failure mode the proxy
//! can encounter, and converts each variant into the appropriate HTTP
//! response with a structured JSON body.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use tracing::warn;

/// Every failure the proxy can produce, each mapping to a specific HTTP status.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// The configuration file could not be loaded or parsed.
    #[error("configuration error: {0}")]
    Config(String),

    /// The upstream target URI is malformed or unparseable.
    #[error("invalid upstream: {0}")]
    InvalidUpstream(String),

    /// A blocked header was detected in the incoming request.
    #[error("blocked header: {0}")]
    BlockedHeader(String),

    /// A blocked query parameter was detected in the incoming request.
    #[error("blocked parameter: {0}")]
    BlockedParam(String),

    /// The request body exceeds the configured maximum size.
    #[error("request body exceeds {limit} byte limit")]
    BodyTooLarge {
        /// The configured ceiling in bytes.
        limit: u64,
    },

    /// The request contains both `Content-Length` and `Transfer-Encoding`,
    /// indicating a potential HTTP request smuggling attack (RFC 9112 §6.1).
    #[error("ambiguous request framing: both Content-Length and Transfer-Encoding present")]
    RequestSmuggling,

    /// The upstream server returned an error or was unreachable.
    #[error("upstream error: {0}")]
    Upstream(#[from] hyper_util::client::legacy::Error),

    /// An HTTP protocol-level error (e.g. invalid header construction).
    #[error("http error: {0}")]
    Http(#[from] hyper::http::Error),

    /// An invalid header value was encountered during header construction.
    #[error("invalid header value: {0}")]
    InvalidHeaderValue(#[from] hyper::header::InvalidHeaderValue),

    /// An invalid header name was encountered during header construction.
    #[error("invalid header name: {0}")]
    InvalidHeaderName(#[from] hyper::header::InvalidHeaderName),

    /// The upstream request exceeded the configured timeout.
    #[error("upstream request timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// The proxy has reached its maximum concurrent request capacity.
    #[error("service at capacity: {limit} concurrent requests")]
    ServiceUnavailable {
        /// The configured concurrency ceiling.
        limit: usize,
    },

    /// A TLS configuration or handshake error.
    #[error("tls error: {0}")]
    Tls(String),

    /// The client has exceeded the configured per-IP rate limit.
    #[error("rate limit exceeded, retry after {retry_after_ms}ms")]
    RateLimited {
        /// Suggested wait time in milliseconds before retrying.
        retry_after_ms: u64,
    },

    /// No healthy upstream backend is available to serve the request.
    #[error("no healthy upstream backend available")]
    NoHealthyUpstream,

    /// An internal error that does not fit other categories.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ProxyError {
    /// Returns the HTTP status code corresponding to this error variant.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Config(_)
            | Self::Internal(_)
            | Self::InvalidUpstream(_)
            | Self::Http(_)
            | Self::InvalidHeaderValue(_)
            | Self::InvalidHeaderName(_)
            | Self::Tls(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NoHealthyUpstream => StatusCode::SERVICE_UNAVAILABLE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::BlockedHeader(_) | Self::BlockedParam(_) => StatusCode::FORBIDDEN,
            Self::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RequestSmuggling => StatusCode::BAD_REQUEST,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Converts this error into an HTTP response with a JSON body.
    ///
    /// Emits a WARN-level log line with the status code and error tag
    /// before constructing the response.
    pub fn into_response(self) -> Response<Full<Bytes>> {
        let status = self.status_code();
        warn!(
            status = status.as_u16(),
            error = self.error_tag(),
            %self,
            "returning error response"
        );
        let retry_after_ms = match &self {
            Self::RateLimited { retry_after_ms } => Some(*retry_after_ms),
            _ => None,
        };

        let body = serde_json::json!({
            "error": self.error_tag(),
            "message": self.to_string(),
        });

        let mut builder = Response::builder()
            .status(status)
            .header("content-type", "application/json");

        if let Some(ms) = retry_after_ms {
            let retry_secs = ms.div_ceil(1000);
            builder = builder.header("retry-after", retry_secs.to_string());
        }

        builder
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .expect("building fallback response must not fail")
            })
    }

    /// Returns the machine-readable error tag for JSON responses.
    fn error_tag(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_error",
            Self::InvalidUpstream(_) => "invalid_upstream",
            Self::BlockedHeader(_) => "blocked_header",
            Self::BlockedParam(_) => "blocked_param",
            Self::BodyTooLarge { .. } => "body_too_large",
            Self::RequestSmuggling => "request_smuggling",
            Self::Upstream(_) => "upstream_error",
            Self::Timeout(_) => "gateway_timeout",
            Self::ServiceUnavailable { .. } => "service_unavailable",
            Self::Http(_) | Self::InvalidHeaderValue(_) | Self::InvalidHeaderName(_) => {
                "http_error"
            }
            Self::Tls(_) => "tls_error",
            Self::RateLimited { .. } => "rate_limited",
            Self::NoHealthyUpstream => "no_healthy_upstream",
            Self::Internal(_) => "internal_error",
        }
    }
}
