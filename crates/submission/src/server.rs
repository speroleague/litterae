//! Binds both submission listeners (587 STARTTLS, 465 implicit TLS) and
//! runs them concurrently. Both fail startup together if TLS isn't
//! configured -- there is no plaintext-only submission mode.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;

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
    const MAX_CONNECTIONS: usize = 256;
    const MAX_SESSION_DURATION: std::time::Duration = std::time::Duration::from_secs(10 * 60);
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
        auth_semaphore: Arc::new(Semaphore::new(2)),
        tls_acceptor,
    });

    let starttls_listener = TcpListener::bind(&config.listen_addr_starttls)
        .await
        .map_err(|e| {
            Error::Config(format!(
                "failed to bind {}: {e}",
                config.listen_addr_starttls
            ))
        })?;
    let implicit_listener = TcpListener::bind(&config.listen_addr_implicit)
        .await
        .map_err(|e| {
            Error::Config(format!(
                "failed to bind {}: {e}",
                config.listen_addr_implicit
            ))
        })?;

    tracing::info!(
        starttls = %config.listen_addr_starttls,
        implicit = %config.listen_addr_implicit,
        "submission listening"
    );

    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let starttls_deps = deps.clone();
    let starttls_limit = connection_limit.clone();
    let starttls_task = async move {
        loop {
            match starttls_listener.accept().await {
                Ok((stream, peer)) => {
                    let Ok(permit) = starttls_limit.clone().try_acquire_owned() else {
                        tracing::warn!(%peer, "rejecting submission connection: connection limit reached");
                        drop(stream);
                        continue;
                    };
                    let deps = starttls_deps.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(
                            MAX_SESSION_DURATION,
                            session::handle_starttls_connection(stream, peer.ip(), deps),
                        )
                        .await;
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to accept submission (starttls) connection")
                }
            }
        }
    };

    let implicit_deps = deps.clone();
    let implicit_limit = connection_limit;
    let implicit_task = async move {
        loop {
            match implicit_listener.accept().await {
                Ok((stream, peer)) => {
                    let Ok(permit) = implicit_limit.clone().try_acquire_owned() else {
                        tracing::warn!(%peer, "rejecting submission connection: connection limit reached");
                        drop(stream);
                        continue;
                    };
                    let deps = implicit_deps.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(
                            MAX_SESSION_DURATION,
                            session::handle_implicit_connection(stream, peer.ip(), deps),
                        )
                        .await;
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to accept submission (implicit) connection")
                }
            }
        }
    };

    tokio::join!(starttls_task, implicit_task);
    Ok(())
}
