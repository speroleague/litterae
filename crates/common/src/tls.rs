//! Shared TLS cert/key loading for every listener that terminates TLS
//! itself (smtp-in, submission, jmap, admin). Each listener decides
//! separately whether a missing cert/key is optional (opportunistic
//! STARTTLS) or fatal (submission, and JMAP/admin when a `[listener]
//! tls_*` path is set) -- this just parses PEM into a `rustls::ServerConfig`.

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::{Error, Result};

pub fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| Error::Config(format!("tls_cert_path: {e}")))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("failed to parse TLS cert chain: {e}")))?;
    if certs.is_empty() {
        return Err(Error::Config("tls_cert_path contains no certificates".into()));
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| Error::Config(format!("failed to parse TLS private key: {e}")))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(format!("invalid TLS cert/key pair: {e}")))?;

    Ok(Arc::new(server_config))
}
