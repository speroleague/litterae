//! REST-ish admin API. Deliberately not JMAP -- domain/account/queue
//! management aren't mail operations, so bolting them onto the JMAP
//! method-call protocol would be a non-standard extension for no benefit.
//! Every handler except `status` and `login` requires a valid admin
//! bearer token.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::{AppState, Domain};

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<i64, StatusCode> {
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let admin_id = state
        .sessions
        .admin_id(token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if state.sessions.password_change_required(token) != Some(false) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(admin_id)
}

#[derive(Serialize)]
pub struct StatusResponse {
    #[serde(rename = "hasAdmin")]
    has_admin: bool,
    #[serde(rename = "domainCount")]
    domain_count: i64,
    #[serde(rename = "accountCount")]
    account_count: i64,
}

pub async fn status(State(state): State<AppState>) -> Result<Json<StatusResponse>, StatusCode> {
    let has_admin = state
        .admin_store
        .has_admin()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let domain_count = state
        .admin_store
        .list_domains()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .len() as i64;
    let account_count = state
        .auth_store
        .list_accounts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .len() as i64;
    Ok(Json(StatusResponse {
        has_admin,
        domain_count,
        account_count,
    }))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token: String,
    #[serde(rename = "mustChangePassword")]
    must_change_password: bool,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    if state.login_throttle.check(&req.username).is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let permit = state
        .auth_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let store = state.admin_store.clone();
    let config = state.argon2_config.clone();
    let username = req.username.clone();
    let password = req.password;
    let outcome = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.verify_login(&username, password.as_bytes(), &config)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some((admin, wrap_key)) = outcome else {
        state.login_throttle.record_failure(&req.username);
        let _ = state.audit_store.log("auth.login_failed", &req.username);
        tracing::warn!(event = "auth_failure", remote_ip = %peer.ip(), username = %req.username, "admin login failed");
        return Err(StatusCode::UNAUTHORIZED);
    };
    state.login_throttle.record_success(&req.username);

    let token = state
        .sessions
        .create(admin.id, wrap_key, admin.must_change_password);
    let _ = state.audit_store.log("auth.login", &admin.username);
    Ok(Json(LoginResponse {
        token,
        must_change_password: admin.must_change_password,
    }))
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    if let Some(token) = bearer_token(&headers) {
        if let Some(admin_id) = state.sessions.admin_id(token) {
            let _ = state
                .audit_store
                .log("session.close", &admin_id.to_string());
        }
        state.sessions.remove(token);
    }
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(rename = "currentPassword")]
    current_password: String,
    #[serde(rename = "newPassword")]
    new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    if req.new_password.len() < 12 {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let admin_id = state
        .sessions
        .admin_id(token)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Re-verify the current password rather than trusting the session
    // alone -- a stolen bearer token shouldn't be enough to permanently
    // lock the real admin out by changing the password.
    let username = state
        .admin_store
        .username_for_id(admin_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let permit = state
        .auth_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let store = state.admin_store.clone();
    let config = state.argon2_config.clone();
    let username_for_change = username.clone();
    let current_password = req.current_password;
    let new_password = req.new_password;
    let keys = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let Some((_, old_wrap_key)) =
            store.verify_login(&username_for_change, current_password.as_bytes(), &config)?
        else {
            return Ok::<_, common::Error>(None);
        };
        let new_wrap_key = store.change_password(admin_id, new_password.as_bytes(), &config)?;
        Ok(Some((old_wrap_key, new_wrap_key)))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let (old_wrap_key, new_wrap_key) = keys.ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .audit_store
        .rewrap_audit_key(&old_wrap_key, &new_wrap_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !state
        .sessions
        .complete_password_change(token, admin_id, new_wrap_key)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let _ = state.audit_store.log("admin.password_change", &username);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct DomainResponse {
    id: i64,
    name: String,
    #[serde(rename = "catchAllLocalPart")]
    catch_all_local_part: Option<String>,
    #[serde(rename = "verificationToken")]
    verification_token: String,
    verified: bool,
}

impl From<Domain> for DomainResponse {
    fn from(d: Domain) -> Self {
        DomainResponse {
            id: d.id,
            name: d.name,
            catch_all_local_part: d.catch_all_local_part,
            verification_token: d.verification_token,
            verified: d.verified_at.is_some(),
        }
    }
}

pub async fn list_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DomainResponse>>, StatusCode> {
    require_admin(&state, &headers)?;
    let domains = state
        .admin_store
        .list_domains()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        domains.into_iter().map(DomainResponse::from).collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    name: String,
    #[serde(rename = "catchAllLocalPart")]
    catch_all_local_part: Option<String>,
}

pub async fn create_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<DomainResponse>, StatusCode> {
    require_admin(&state, &headers)?;
    if !common::input::valid_domain_name(&req.name)
        || req
            .catch_all_local_part
            .as_deref()
            .is_some_and(|value| !common::input::valid_local_part(value))
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let domain = state
        .admin_store
        .create_domain(&req.name, req.catch_all_local_part.as_deref())
        .map_err(|_| StatusCode::CONFLICT)?;
    let _ = state.audit_store.log("admin.domain_create", &domain.name);
    Ok(Json(DomainResponse::from(domain)))
}

#[derive(Deserialize)]
pub struct SetCatchAllRequest {
    #[serde(rename = "catchAllLocalPart")]
    catch_all_local_part: Option<String>,
}

pub async fn update_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<SetCatchAllRequest>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&state, &headers)?;
    if req
        .catch_all_local_part
        .as_deref()
        .is_some_and(|value| !common::input::valid_local_part(value))
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    state
        .admin_store
        .set_catch_all(id, req.catch_all_local_part.as_deref())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state
        .audit_store
        .log("admin.domain_update", &id.to_string());
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&state, &headers)?;
    state
        .admin_store
        .delete_domain(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state
        .audit_store
        .log("admin.domain_delete", &id.to_string());
    Ok(StatusCode::NO_CONTENT)
}

/// Prefix for the DNS TXT ownership-verification challenge, matching the
/// `{selector}._domainkey.{domain}` naming convention DKIM already uses
/// for its own TXT record -- a fixed, well-known label under the
/// operator's domain, not guessable-but-secret (the token itself is the
/// secret half).
const VERIFICATION_LABEL: &str = "_litterae-challenge";

#[derive(Serialize)]
pub struct DkimResponse {
    domain: String,
    selector: String,
    #[serde(rename = "recordName")]
    record_name: String,
    #[serde(rename = "recordValue")]
    record_value: String,
}

/// Returns the domain's DKIM selector + DNS TXT record value, generating
/// the keypair on first call (idempotent -- `ensure_dkim_key` returns the
/// existing key on every call after the first). This is the only way to
/// retrieve it today besides the `litterae dkim-init` CLI command; both
/// read/write the same `dkim_keys` table.
pub async fn domain_dkim(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<DkimResponse>, StatusCode> {
    require_admin(&state, &headers)?;
    let domain = state
        .admin_store
        .get_domain(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let key = state
        .queue_store
        .ensure_dkim_key(&domain.name)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(DkimResponse {
        domain: domain.name.clone(),
        selector: key.selector.clone(),
        record_name: format!("{}._domainkey.{}", key.selector, domain.name),
        record_value: key.dns_txt_record(),
    }))
}

#[derive(Serialize)]
pub struct VerifyDomainResponse {
    verified: bool,
    #[serde(rename = "recordName")]
    record_name: String,
    #[serde(rename = "recordValue")]
    record_value: String,
}

/// Checks for the domain's ownership-verification TXT record and records
/// success if found. Advisory only (spec: this doesn't gate account
/// creation or sending -- see `Domain::verified_at`'s doc comment) --
/// existing mail servers' own SPF/DKIM/DMARC checks on the receiving end
/// are the enforcement that actually matters; this just lets the operator
/// confirm their own DNS setup from the admin panel instead of finding out
/// via a bounced/junked test message.
pub async fn verify_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<VerifyDomainResponse>, StatusCode> {
    require_admin(&state, &headers)?;
    let domain = state
        .admin_store
        .get_domain(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let record_name = format!("{VERIFICATION_LABEL}.{}", domain.name);
    let expected = format!("litterae-verify={}", domain.verification_token);
    let records = state
        .dns_resolver
        .resolve_txt(&record_name)
        .await
        .unwrap_or_default();
    let verified = records.iter().any(|r| r.trim() == expected);

    if verified {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        state
            .admin_store
            .mark_domain_verified(id, now)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let _ = state.audit_store.log("admin.domain_verified", &domain.name);
    }

    Ok(Json(VerifyDomainResponse {
        verified,
        record_name,
        record_value: expected,
    }))
}

#[derive(Serialize)]
pub struct AccountResponse {
    id: i64,
    address: String,
    #[serde(rename = "createdAt")]
    created_at: i64,
}

pub async fn list_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AccountResponse>>, StatusCode> {
    require_admin(&state, &headers)?;
    let accounts = state
        .auth_store
        .list_accounts()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        accounts
            .into_iter()
            .map(|a| AccountResponse {
                id: a.id,
                address: a.address(),
                created_at: a.created_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    #[serde(rename = "localPart")]
    local_part: String,
    domain: String,
    password: String,
}

pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<AccountResponse>, StatusCode> {
    require_admin(&state, &headers)?;
    if !common::input::valid_local_part(&req.local_part)
        || !common::input::valid_domain_name(&req.domain)
        || req.password.len() < 12
    {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    // Only allow provisioning on domains the admin has explicitly added --
    // the guided path shouldn't let you typo your way into hosting a
    // domain you don't control.
    let domain_known = state
        .admin_store
        .get_domain_by_name(&req.domain)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some();
    if !domain_known {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }

    let account = state
        .auth_store
        .provision(
            &req.local_part,
            &req.domain,
            req.password.as_bytes(),
            &state.argon2_config,
        )
        .map_err(|_| StatusCode::CONFLICT)?;
    let _ = state
        .audit_store
        .log("admin.account_create", &account.address());
    Ok(Json(AccountResponse {
        id: account.id,
        address: account.address(),
        created_at: account.created_at,
    }))
}

pub async fn delete_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&state, &headers)?;
    state
        .auth_store
        .delete_account(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = state
        .audit_store
        .log("admin.account_delete", &id.to_string());
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct QueueMetricsResponse {
    ready: i64,
    claimed: i64,
    deferred: i64,
    delivered: i64,
    failed: i64,
    expired: i64,
}

#[derive(Serialize)]
pub struct QueueStatusResponse {
    metrics: QueueMetricsResponse,
    #[serde(rename = "recentFailures")]
    recent_failures: Vec<RecentFailureResponse>,
}

#[derive(Serialize)]
pub struct RecentFailureResponse {
    id: i64,
    #[serde(rename = "rcptTo")]
    rcpt_to: String,
    domain: String,
    attempts: i64,
    #[serde(rename = "lastCode")]
    last_code: Option<i64>,
    #[serde(rename = "lastStatus")]
    last_status: Option<String>,
    #[serde(rename = "lastDetail")]
    last_detail: Option<String>,
}

pub async fn queue_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<QueueStatusResponse>, StatusCode> {
    require_admin(&state, &headers)?;
    let metrics = state
        .queue_store
        .metrics()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let recent_failures = state
        .queue_store
        .recent_failures(20)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .map(|r| RecentFailureResponse {
            id: r.id,
            rcpt_to: r.rcpt_to,
            domain: r.domain,
            attempts: r.attempts,
            last_code: r.last_code,
            last_status: r.last_status,
            last_detail: r.last_detail,
        })
        .collect();
    Ok(Json(QueueStatusResponse {
        metrics: QueueMetricsResponse {
            ready: metrics.ready,
            claimed: metrics.claimed,
            deferred: metrics.deferred,
            delivered: metrics.delivered,
            failed: metrics.failed,
            expired: metrics.expired,
        },
        recent_failures,
    }))
}

#[derive(Serialize)]
pub struct AuditEntryResponse {
    seq: i64,
    at: i64,
    action: String,
    detail: String,
}

pub async fn audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEntryResponse>>, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .sessions
        .admin_id(token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    // The session's wrap key -- not just proof of who's logged in -- is
    // what makes entry detail readable; a valid token alone isn't enough.
    let wrap_key = state
        .sessions
        .wrap_key(token)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let entries = state
        .audit_store
        .read_recent(&wrap_key, 100)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        entries
            .into_iter()
            .map(|e| AuditEntryResponse {
                seq: e.seq,
                at: e.at,
                action: e.action,
                detail: e.detail,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct LogQuery {
    /// Unix seconds; defaults to 24 hours before `until`.
    since: Option<i64>,
    /// Unix seconds; defaults to now.
    until: Option<i64>,
    /// Exact match against the JSON `level` field (e.g. "WARN"),
    /// case-insensitive. Omit for all levels.
    level: Option<String>,
    /// Capped at 1000 regardless of what's requested -- this reads real
    /// files off disk, not an indexed store.
    limit: Option<usize>,
}

const DEFAULT_LOG_LIMIT: usize = 200;
const MAX_LOG_LIMIT: usize = 1000;
const DEFAULT_LOG_WINDOW_SECS: i64 = 24 * 60 * 60;

pub async fn logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    require_admin(&state, &headers)?;

    let Some(log_dir) = &state.log_dir else {
        // File logging isn't enabled (LITTERAE_LOG_DIR unset) -- nothing
        // to read. Empty result rather than an error: the admin UI can
        // render "no log file configured" from this without special-casing
        // a distinct status code.
        return Ok(Json(Vec::new()));
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let until = query.until.unwrap_or(now);
    let since = query.since.unwrap_or(until - DEFAULT_LOG_WINDOW_SECS);
    let level_filter = query.level.map(|l| l.to_uppercase());
    let limit = query.limit.unwrap_or(DEFAULT_LOG_LIMIT).min(MAX_LOG_LIMIT);

    let since_dt = OffsetDateTime::from_unix_timestamp(since).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let until_dt = OffsetDateTime::from_unix_timestamp(until).unwrap_or(now_dt());

    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(log_dir)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("litterae.log"))
        })
        .collect();
    // tracing-appender's daily rotation suffixes filenames with the date
    // (litterae.log.YYYY-MM-DD), so lexicographic order is chronological
    // order -- newest file last, which we want reversed to read
    // newest-first without needing to parse the suffix at all.
    files.sort();
    files.reverse();

    let mut results = Vec::new();
    'files: for path in files {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines().rev() {
            if results.len() >= limit {
                break 'files;
            }
            let Some((ts, level, value)) = parse_log_line(line) else {
                continue;
            };
            if ts < since_dt || ts > until_dt {
                continue;
            }
            if let Some(want) = &level_filter {
                if &level != want {
                    continue;
                }
            }
            results.push(value);
        }
    }

    Ok(Json(results))
}

fn now_dt() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn parse_log_line(line: &str) -> Option<(OffsetDateTime, String, serde_json::Value)> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let timestamp = value.get("timestamp")?.as_str()?;
    let ts = OffsetDateTime::parse(timestamp, &Rfc3339).ok()?;
    let level = value.get("level")?.as_str()?.to_uppercase();
    Some((ts, level, value))
}
