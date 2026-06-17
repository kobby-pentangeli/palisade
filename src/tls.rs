//! TLS configuration for both inbound (termination) and outbound (origination).
//!
//! Provides helpers to load PEM-encoded certificates and private keys from
//! disk and to construct [`rustls::ServerConfig`] and
//! [`hyper_rustls::HttpsConnector`] instances for the proxy's two TLS roles:
//!
//! - **Termination (client -> proxy):** Accepts HTTPS connections using a
//!   locally loaded certificate chain and private key.
//! - **Origination (proxy -> upstream):** Initiates HTTPS connections to
//!   upstream backends, verifying servers against the Mozilla root
//!   certificate bundle vendored by [`webpki_roots`], not the OS trust store.

use std::sync::Arc;
use std::time::Duration;

use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::{ProxyError, Result, TlsConfig};

/// Builds a [`TlsAcceptor`] from the given TLS configuration.
///
/// Loads the PEM-encoded certificate chain and private key from the paths
/// specified in `config`, constructs a [`rustls::ServerConfig`] with safe
/// defaults (no client authentication), and wraps it in a
/// [`TlsAcceptor`] suitable for use with [`tokio::net::TcpListener`].
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ProxyError::Tls(format!("failed to build TLS server config: {e}")))?;

    // Advertise HTTP/2 ahead of HTTP/1.1 so ALPN-capable clients negotiate the
    // multiplexed protocol while plain HTTP/1.1 clients still connect.
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Builds an HTTPS connector for outbound connections to upstream backends.
///
/// Uses the Mozilla root certificate store via [`webpki_roots`] for server
/// verification. The resulting connector supports both `http://` and
/// `https://` schemes; plain HTTP connections pass through unmodified.
/// For `https://` upstreams it negotiates HTTP/2 or HTTP/1.1 over ALPN,
/// allowing the proxy to multiplex requests to backends that support it.
///
/// `connect_timeout` bounds the TCP connect phase of every upstream
/// connection the resulting connector establishes.
pub fn build_https_connector(
    connect_timeout: Duration,
) -> hyper_rustls::HttpsConnector<HttpConnector> {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(connect_timeout));
    http.enforce_http(false);

    HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http)
}

/// Loads PEM-encoded X.509 certificates from the file at `path`.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_file_iter(path)
        .map_err(|e| ProxyError::Tls(format!("failed to open cert file {path}: {e}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ProxyError::Tls(format!("failed to parse certificates from {path}: {e}")))
}

/// Loads the first PEM-encoded private key from the file at `path`.
///
/// Supports PKCS#1 (RSA), PKCS#8, and SEC1 (EC) key formats.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| ProxyError::Tls(format!("failed to load private key from {path}: {e}")))
}
