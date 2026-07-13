//! Opportunistic STARTTLS (spec §8.1, §0 guardrails: port 25 must never
//! *require* TLS). If no cert/key is configured, `load_acceptor` returns
//! `None` and the session loop simply doesn't advertise STARTTLS.

use common::config::SmtpConfig;
use common::Result;
use tokio_rustls::TlsAcceptor;

pub fn load_acceptor(config: &SmtpConfig) -> Result<Option<TlsAcceptor>> {
    let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) else {
        return Ok(None);
    };
    let server_config = common::tls::load_server_config(cert_path, key_path)?;
    Ok(Some(TlsAcceptor::from(server_config)))
}
