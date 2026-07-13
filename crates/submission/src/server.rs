//! Binds both submission listeners (587 STARTTLS, 465 implicit TLS) and
//! runs them concurrently. Both fail startup together if TLS isn't
//! configured -- there is no plaintext-only submission mode.

use std::sync::Arc;

use tokio::net::TcpListener;

use std::time::Duration;

use auth::AuthStore;
use common::config::{Argon2Config, SubmissionConfig};
use common::throttle::LoginThrottle;
use common::{Error, Result};
use queue::QueueStore;
use store::BlobStore;

use crate::session::{self, Deps};
use crate::tls::load_acceptor;

const THROTTLE_BASE_DELAY: Duration = Duration::from_secs(1);
const THROTTLE_MAX_DELAY: Duration = Duration::from_secs(60);

pub async fn run(
    config: &SubmissionConfig,
    hostname: String,
    auth_store: Arc<AuthStore>,
    queue: Arc<QueueStore>,
    blobs: Arc<BlobStore>,
    audit: Arc<audit::AuditStore>,
    argon2_config: Arc<Argon2Config>,
) -> Result<()> {
    let tls_acceptor = load_acceptor(config)?;
    let deps = Arc::new(Deps {
        hostname,
        max_message_size: config.max_message_size,
        auth_store,
        queue,
        blobs,
        audit,
        login_throttle: Arc::new(LoginThrottle::new(THROTTLE_BASE_DELAY, THROTTLE_MAX_DELAY)),
        argon2_config,
        tls_acceptor,
    });

    let starttls_listener = TcpListener::bind(&config.listen_addr_starttls)
        .await
        .map_err(|e| Error::Config(format!("failed to bind {}: {e}", config.listen_addr_starttls)))?;
    let implicit_listener = TcpListener::bind(&config.listen_addr_implicit)
        .await
        .map_err(|e| Error::Config(format!("failed to bind {}: {e}", config.listen_addr_implicit)))?;

    tracing::info!(
        starttls = %config.listen_addr_starttls,
        implicit = %config.listen_addr_implicit,
        "submission listening"
    );

    let starttls_deps = deps.clone();
    let starttls_task = async move {
        loop {
            match starttls_listener.accept().await {
                Ok((stream, peer)) => {
                    let deps = starttls_deps.clone();
                    tokio::spawn(session::handle_starttls_connection(stream, peer.ip(), deps));
                }
                Err(e) => tracing::warn!(error = %e, "failed to accept submission (starttls) connection"),
            }
        }
    };

    let implicit_deps = deps.clone();
    let implicit_task = async move {
        loop {
            match implicit_listener.accept().await {
                Ok((stream, peer)) => {
                    let deps = implicit_deps.clone();
                    tokio::spawn(session::handle_implicit_connection(stream, peer.ip(), deps));
                }
                Err(e) => tracing::warn!(error = %e, "failed to accept submission (implicit) connection"),
            }
        }
    };

    tokio::join!(starttls_task, implicit_task);
    Ok(())
}
