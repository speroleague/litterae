use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post};
use axum::Router;
use tower_http::cors::CorsLayer;

use audit::AuditStore;
use auth::AuthStore;
use common::config::Argon2Config;
use common::throttle::LoginThrottle;
use dns::Resolver;
use queue::QueueStore;

use crate::handlers;
use crate::session::AdminSessionRegistry;
use crate::AdminStore;

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Admin bodies are small JSON CRUD payloads only -- generous headroom
/// without leaving the endpoint open to an oversized-body DoS.
const MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;
const THROTTLE_BASE_DELAY: Duration = Duration::from_secs(1);
const THROTTLE_MAX_DELAY: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AppState {
    pub admin_store: Arc<AdminStore>,
    pub auth_store: Arc<AuthStore>,
    pub queue_store: Arc<QueueStore>,
    pub audit_store: Arc<AuditStore>,
    pub argon2_config: Arc<Argon2Config>,
    pub sessions: Arc<AdminSessionRegistry>,
    pub login_throttle: Arc<LoginThrottle>,
    /// Set from `LITTERAE_LOG_DIR` (see `common::tracing_init::init`) --
    /// `None` means file logging isn't enabled, so `/admin/logs` has
    /// nothing to read (stdout-only logging has no file to tail).
    pub log_dir: Option<PathBuf>,
    /// Used only by domain verification (a live TXT lookup against the
    /// domain's real public DNS) -- a separate `Resolver` instance from
    /// the outbound queue worker's, same pattern as `main.rs` already uses
    /// for giving the worker its own independent store handles.
    pub dns_resolver: Arc<Resolver>,
}

#[allow(clippy::too_many_arguments)]
impl AppState {
    pub fn new(
        admin_store: Arc<AdminStore>,
        auth_store: Arc<AuthStore>,
        queue_store: Arc<QueueStore>,
        audit_store: Arc<AuditStore>,
        argon2_config: Arc<Argon2Config>,
        log_dir: Option<PathBuf>,
        dns_resolver: Arc<Resolver>,
    ) -> Self {
        Self {
            admin_store,
            auth_store,
            queue_store,
            audit_store,
            argon2_config,
            sessions: Arc::new(AdminSessionRegistry::new(DEFAULT_IDLE_TIMEOUT)),
            login_throttle: Arc::new(LoginThrottle::new(THROTTLE_BASE_DELAY, THROTTLE_MAX_DELAY)),
            log_dir,
            dns_resolver,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/admin/status", get(handlers::status))
        .route("/admin/login", post(handlers::login))
        .route("/admin/logout", post(handlers::logout))
        .route("/admin/change-password", post(handlers::change_password))
        .route("/admin/domains", get(handlers::list_domains).post(handlers::create_domain))
        .route(
            "/admin/domains/{id}",
            patch(handlers::update_domain).delete(handlers::delete_domain),
        )
        .route("/admin/domains/{id}/dkim", get(handlers::domain_dkim))
        .route("/admin/domains/{id}/verify", post(handlers::verify_domain))
        .route("/admin/accounts", get(handlers::list_accounts).post(handlers::create_account))
        .route("/admin/accounts/{id}", delete(handlers::delete_account))
        .route("/admin/queue", get(handlers::queue_status))
        .route("/admin/audit", get(handlers::audit_log))
        .route("/admin/logs", get(handlers::logs))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .with_state(state)
}
