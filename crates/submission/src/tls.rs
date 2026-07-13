//! TLS is mandatory for submission (both the STARTTLS and implicit-TLS
//! listeners) -- unlike inbound port 25, there's no opportunistic mode
//! here, so a missing cert/key is a startup error, not a silently-degraded
//! capability.

use common::config::SubmissionConfig;
use common::{Error, Result};
use tokio_rustls::TlsAcceptor;

pub fn load_acceptor(config: &SubmissionConfig) -> Result<TlsAcceptor> {
    let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) else {
        return Err(Error::Config(
            "submission requires tls_cert_path and tls_key_path (TLS is mandatory)".into(),
        ));
    };
    let server_config = common::tls::load_server_config(cert_path, key_path)?;
    Ok(TlsAcceptor::from(server_config))
}
