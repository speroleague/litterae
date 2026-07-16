use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Semaphore;
use tower_http::cors::CorsLayer;

use audit::AuditStore;
use auth::AuthStore;
use common::config::Argon2Config;
use common::throttle::LoginThrottle;
use queue::QueueStore;
use scan::clamav::ClamavClient;
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
const MAX_CONCURRENT_PASSWORD_KDFS: usize = 2;

#[derive(Clone)]
pub struct AppState {
    pub auth_store: Arc<AuthStore>,
    pub blobs: Arc<BlobStore>,
    pub metadata: Arc<MetadataStore>,
    pub audit_store: Arc<AuditStore>,
    pub argon2_config: Arc<Argon2Config>,
    pub sessions: Arc<SessionRegistry>,
    pub login_throttle: Arc<LoginThrottle>,
    pub auth_semaphore: Arc<Semaphore>,
    /// Outbound queue/DKIM -- only touched by the compose-send path
    /// (`EmailSubmission/set`), everything else in this crate is read-only
    /// against `metadata`/`blobs`.
    pub queue_store: Arc<QueueStore>,
    /// Backs the `/jmap/sse` push endpoint -- shared with smtp-in and the
    /// outbound worker so inbound delivery and DSNs also wake up an open
    /// SSE stream, not just this crate's own mutations.
    pub notifier: Arc<common::changes::ChangeNotifier>,
    /// `None` means AV is unconfigured (`antivirus.endpoint` unset), same
    /// as everywhere else in this system -- `/jmap/upload` then lets files
    /// through unscanned rather than breaking every upload for an operator
    /// who never set up clamd.
    pub clamav: Option<Arc<ClamavClient>>,
    /// Caps a single `/jmap/upload` body and, separately, an assembled
    /// outbound message's total attachment size at send time.
    pub max_upload_size: usize,
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
        clamav: Option<Arc<ClamavClient>>,
        max_upload_size: usize,
    ) -> Self {
        Self {
            auth_store,
            blobs,
            metadata,
            audit_store,
            argon2_config,
            sessions: Arc::new(SessionRegistry::new(DEFAULT_IDLE_TIMEOUT)),
            login_throttle: Arc::new(LoginThrottle::new(THROTTLE_BASE_DELAY, THROTTLE_MAX_DELAY)),
            auth_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_PASSWORD_KDFS)),
            queue_store,
            notifier,
            clamav,
            max_upload_size,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    // The frontend is a separately-deployed origin (its own static host or
    // dev server) talking to this API purely over bearer tokens in headers,
    // never cookies -- there's no ambient credential for a cross-origin
    // request to ride along on, so a permissive CORS policy doesn't open a
    // CSRF hole the way it would for a cookie-authenticated API.
    // Per-route `.layer(...)` on the upload route runs closer to the
    // handler than the router-wide `DefaultBodyLimit` below, so it wins:
    // `DefaultBodyLimit` doesn't nest limits, it just stashes the active
    // one in a request extension, and each layer's `call()` overwrites
    // whatever the outer one stashed. Confirmed against axum-core's
    // `DefaultBodyLimitService` -- not just going by the doc example.
    let upload_body_limit = DefaultBodyLimit::max(state.max_upload_size);
    Router::new()
        .route("/auth/unlock", post(handlers::unlock))
        .route("/auth/lock", post(handlers::lock))
        .route("/jmap/session", get(handlers::jmap_session))
        .route("/jmap/api", post(handlers::jmap_api))
        .route("/jmap/sse", get(handlers::sse))
        .route("/jmap/download/{blob_id}", get(handlers::download))
        .route(
            "/jmap/upload",
            post(handlers::upload).layer(upload_body_limit),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    fn test_state(max_upload_size: usize) -> AppState {
        let tmp = tempfile::tempdir().unwrap();
        AppState::new(
            Arc::new(AuthStore::open_in_memory().unwrap()),
            Arc::new(BlobStore::open(tmp.path()).unwrap()),
            Arc::new(MetadataStore::open_in_memory().unwrap()),
            Arc::new(AuditStore::open_in_memory().unwrap()),
            Arc::new(Argon2Config {
                m_cost_kib: 8 * 1024,
                t_cost: 1,
                p_cost: 1,
            }),
            Arc::new(QueueStore::open_in_memory().unwrap()),
            Arc::new(common::changes::ChangeNotifier::new()),
            None,
            max_upload_size,
        )
    }

    /// The router-wide `DefaultBodyLimit` (sized for JSON method-call
    /// bodies) must not shadow the larger per-route limit on
    /// `/jmap/upload` -- axum layers don't nest limits, each one just
    /// overwrites a request-extension value, so whichever layer runs
    /// closer to the handler wins. This proves that's actually the
    /// upload route's own layer, not the router-wide one, by sending a
    /// body bigger than the router-wide cap to both routes.
    #[tokio::test]
    async fn upload_route_accepts_a_body_larger_than_the_api_routes_cap() {
        let oversized = vec![0u8; MAX_REQUEST_BODY_BYTES + 1024];
        let state = test_state(oversized.len() + 1024);
        let app = build_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/jmap/upload")
            .header("content-type", "application/octet-stream")
            .header("authorization", "Bearer nonexistent-token")
            .body(Body::from(oversized.clone()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        // The body itself must not be rejected for size -- 401 (bad
        // token, since none of this cares about auth) proves the request
        // body was read and passed through to the handler, not bounced
        // by a body-limit layer (which would be 413).
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let req = Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .header("authorization", "Bearer nonexistent-token")
            .body(Body::from(oversized))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
