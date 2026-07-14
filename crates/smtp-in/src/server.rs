//! Accept loop: binds the inbound SMTP listener and spawns one task per
//! connection (spec §1: async I/O everywhere; each connection is cheap).

use std::sync::Arc;

use mail_auth::MessageAuthenticator;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use admin::AdminStore;
use auth::AuthStore;
use common::config::SmtpConfig;
use common::{Error, Result};
use store::{BlobStore, MetadataStore};

use crate::session::{self, Deps};
use crate::tls::load_acceptor;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    config: &SmtpConfig,
    hostname: String,
    auth_store: Arc<AuthStore>,
    admin_store: Arc<AdminStore>,
    blobs: Arc<BlobStore>,
    metadata: Arc<MetadataStore>,
    scanner: Arc<scan::Scanner>,
    audit: Arc<audit::AuditStore>,
    notifier: Arc<common::changes::ChangeNotifier>,
) -> Result<()> {
    const MAX_CONNECTIONS: usize = 512;
    const MAX_SESSION_DURATION: std::time::Duration = std::time::Duration::from_secs(10 * 60);
    let tls_acceptor = load_acceptor(config)?;
    let authenticator = Arc::new(
        MessageAuthenticator::new_system_conf()
            .map_err(|_| Error::Config("failed to initialize DNS resolver".into()))?,
    );

    let deps = Arc::new(Deps {
        hostname,
        max_message_size: config.max_message_size,
        auth_store,
        admin_store,
        blobs,
        metadata,
        authenticator,
        tls_acceptor,
        scanner,
        audit,
        notifier,
    });

    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| Error::Config(format!("failed to bind {}: {e}", config.listen_addr)))?;
    tracing::info!(addr = %config.listen_addr, tls = deps.tls_acceptor.is_some(), "smtp-in listening");

    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "failed to accept connection");
                continue;
            }
        };
        let Ok(permit) = connection_limit.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "rejecting SMTP connection: connection limit reached");
            drop(stream);
            continue;
        };
        let deps = deps.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if tokio::time::timeout(
                MAX_SESSION_DURATION,
                session::handle_connection(stream, peer.ip(), deps),
            )
            .await
            .is_err()
            {
                tracing::warn!(%peer, "SMTP session timed out");
            }
        });
    }
}
