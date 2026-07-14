use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;

use audit::AuditStore;
use auth::AuthStore;
use common::config::Argon2Config;
use common::throttle::LoginThrottle;
use queue::QueueStore;
use store::{BlobStore, MetadataStore};

use crate::handlers;
use crate::session_store::SessionRegistry;

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// JMAP method-call bodies are JSON, not raw message bytes (those go
/// through the blob endpoints once those exist) -- generous enough for a
/// large batch of method calls, nowhere near attachment-sized.
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const THROTTLE_BASE_DELAY: Duration = Duration::from_secs(1);
const THROTTLE_MAX_DELAY: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AppState {
    pub auth_store: Arc<AuthStore>,
    pub blobs: Arc<BlobStore>,
    pub metadata: Arc<MetadataStore>,
    pub audit_store: Arc<AuditStore>,
    pub argon2_config: Arc<Argon2Config>,
    pub sessions: Arc<SessionRegistry>,
    pub login_throttle: Arc<LoginThrottle>,
    /// Outbound queue/DKIM -- only touched by the compose-send path
    /// (`EmailSubmission/set`), everything else in this crate is read-only
    /// against `metadata`/`blobs`.
    pub queue_store: Arc<QueueStore>,
    /// Backs the `/jmap/sse` push endpoint -- shared with smtp-in and the
    /// outbound worker so inbound delivery and DSNs also wake up an open
    /// SSE stream, not just this crate's own mutations.
    pub notifier: Arc<common::changes::ChangeNotifier>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auth_store: Arc<AuthStore>,
        blobs: Arc<BlobStore>,
        metadata: Arc<MetadataStore>,
        audit_store: Arc<AuditStore>,
        argon2_config: Arc<Argon2Config>,
        queue_store: Arc<QueueStore>,
        notifier: Arc<common::changes::ChangeNotifier>,
    ) -> Self {
        Self {
            auth_store,
            blobs,
            metadata,
            audit_store,
            argon2_config,
            sessions: Arc::new(SessionRegistry::new(DEFAULT_IDLE_TIMEOUT)),
            login_throttle: Arc::new(LoginThrottle::new(THROTTLE_BASE_DELAY, THROTTLE_MAX_DELAY)),
            queue_store,
            notifier,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    // The frontend is a separately-deployed origin (its own static host or
    // dev server) talking to this API purely over bearer tokens in headers,
    // never cookies -- there's no ambient credential for a cross-origin
    // request to ride along on, so a permissive CORS policy doesn't open a
    // CSRF hole the way it would for a cookie-authenticated API.
    Router::new()
        .route("/auth/unlock", post(handlers::unlock))
        .route("/auth/lock", post(handlers::lock))
        .route("/jmap/session", get(handlers::jmap_session))
        .route("/jmap/api", post(handlers::jmap_api))
        .route("/jmap/sse", get(handlers::sse))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
