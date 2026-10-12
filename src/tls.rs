//! # Sovereign SNI TLS Termination Engine
//! High-performance, zero-allocation multi-domain TLS termination using pure-Rust `rustls`.
//! Dynamically routes SNI handshakes to domain-specific certificates and keys with ALPN support.

use crate::config::RouteConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O error loading TLS materials from '{0}': {1}")]
    Io(String, #[source] std::io::Error),
    #[error("Rustls cryptographic error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("Failed to parse certificate chain in '{0}'")]
    CertificateParse(String),
    #[error("Failed to parse private key in '{0}'")]
    PrivateKeyParse(String),
    #[error("Failed to parse private key: {0}")]
    KeyParse(String),
    #[error("No routes configured for TLS setup")]
    NoRoutes,
}

/// Helper to load a PEM-encoded certificate chain from disk
pub fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let p = path.as_ref();
    let file = File::open(p).map_err(|e| TlsError::Io(p.display().to_string(), e))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::CertificateParse(p.display().to_string()))?;

    if certs.is_empty() {
        return Err(TlsError::CertificateParse(format!(
            "No valid certificates found in {}",
            p.display()
        )));
    }

    Ok(certs)
}

/// Helper to load a PEM-encoded private key (PKCS#8, PKCS#1, or SEC1) from disk
pub fn load_private_key<P: AsRef<Path>>(path: P) -> Result<PrivateKeyDer<'static>, TlsError> {
    let p = path.as_ref();
    let file = File::open(p).map_err(|e| TlsError::Io(p.display().to_string(), e))?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)
            .map_err(|e| TlsError::Io(p.display().to_string(), e))?
        {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            None => break,
            _ => continue,
        }
    }

    Err(TlsError::PrivateKeyParse(format!(
        "No valid private key found in {}",
        p.display()
    )))
}

#[derive(Debug)]
pub struct SovereignSniResolver {
    sni_resolver: ResolvesServerCertUsingSni,
    fallback: Arc<CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for SovereignSniResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(cert) = self.sni_resolver.resolve(client_hello) {
            Some(cert)
        } else {
            Some(Arc::clone(&self.fallback))
        }
    }
}

/// Builds a TlsAcceptor armed with all configured SNI domain certificates
pub fn build_sni_tls_acceptor(routes: &[RouteConfig]) -> Result<TlsAcceptor, TlsError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if routes.is_empty() {
        return Err(TlsError::NoRoutes);
    }

    let mut sni_resolver = ResolvesServerCertUsingSni::new();
    let mut fallback_key: Option<Arc<CertifiedKey>> = None;

    for route in routes {
        let cert_chain = load_certs(&route.cert)?;
        let private_key = load_private_key(&route.key)?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
            .map_err(|e| TlsError::KeyParse(format!("{:?}", e)))?;

        let certified_key = CertifiedKey::new(cert_chain, signing_key);

        if fallback_key.is_none() {
            fallback_key = Some(Arc::new(certified_key.clone()));
        }

        for domain in &route.domains {
            let clean_domain = domain.trim().to_ascii_lowercase();
            sni_resolver
                .add(&clean_domain, certified_key.clone())
                .map_err(|e| {
                    TlsError::KeyParse(format!("Failed to register SNI {}: {:?}", clean_domain, e))
                })?;
        }
    }

    let fallback = fallback_key
        .ok_or_else(|| TlsError::CertificateParse("No routes available for TLS fallback".into()))?;

    let sovereign_resolver = SovereignSniResolver {
        sni_resolver,
        fallback,
    };

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(sovereign_resolver));

    // Support ALPN HTTP/2 and HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_certs_and_key() {
        let cert = rcgen::generate_simple_self_signed(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
        ])
        .unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();

        let certs = load_certs(cert_file.path()).unwrap();
        assert_eq!(certs.len(), 1);

        let key = load_private_key(key_file.path()).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));

        let routes = vec![RouteConfig::single(
            vec!["example.com".into(), "www.example.com".into()],
            "127.0.0.1:8080".parse().unwrap(),
            cert_file.path().to_path_buf(),
            key_file.path().to_path_buf(),
            true,
        )];

        let acceptor = build_sni_tls_acceptor(&routes);
        assert!(acceptor.is_ok());
    }
}
