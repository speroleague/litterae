//! HTTP handlers: our own password-unlock bootstrap (not part of the JMAP
//! wire format itself) plus the JMAP session resource, method-call API, and
//! SSE push endpoint (RFC 8620 §2, §3, §7.3).

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::Json;
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::api::{dispatch, AccountContext};
use crate::session_store::SessionIdentity;
use crate::types::{
    JmapAccount, JmapSession, Request, Response, CAPABILITY_CORE, CAPABILITY_MAIL,
};
use crate::AppState;

#[derive(Deserialize)]
pub struct UnlockRequest {
    pub local_part: String,
    pub domain: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct UnlockResponse {
    pub token: String,
    #[serde(rename = "accountId")]
    pub account_id: String,
}

pub async fn unlock(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<UnlockRequest>,
) -> Result<Json<UnlockResponse>, StatusCode> {
    let identity = format!("{}@{}", req.local_part, req.domain);
    if state.login_throttle.check(&identity).is_err() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let account = state
        .auth_store
        .find_by_address(&req.local_part, &req.domain)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(account) = account else {
        state.login_throttle.record_failure(&identity);
        let _ = state.audit_store.log("auth.unlock_failed", &identity);
        tracing::warn!(event = "auth_failure", remote_ip = %peer.ip(), identity, "jmap unlock failed: no such account");
        return Err(StatusCode::UNAUTHORIZED);
    };
    let unlocked = match state.auth_store.unlock(&account, req.password.as_bytes(), &state.argon2_config) {
        Ok(unlocked) => unlocked,
        Err(_) => {
            state.login_throttle.record_failure(&identity);
            let _ = state.audit_store.log("auth.unlock_failed", &account.address());
            tracing::warn!(event = "auth_failure", remote_ip = %peer.ip(), identity, "jmap unlock failed: wrong password");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };
    state.login_throttle.record_success(&identity);

    let session_identity = SessionIdentity {
        account_pub: account.account_pub,
        key_id: account.key_id,
        address: account.address(),
    };
    let token = state.sessions.create(account.id, unlocked, session_identity);
    let _ = state.audit_store.log("auth.unlock", &account.address());
    Ok(Json(UnlockResponse {
        token,
        account_id: account.id.to_string(),
    }))
}

pub async fn lock(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    if let Some(token) = bearer_token(&headers) {
        if let Some(account_id) = state.sessions.account_id(token) {
            let _ = state.audit_store.log("session.close", &account_id.to_string());
        }
        state.sessions.remove(token);
    }
    StatusCode::NO_CONTENT
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub async fn jmap_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JmapSession>, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let account_id = state
        .sessions
        .account_id(token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let account_id_str = account_id.to_string();

    let mut accounts = HashMap::new();
    accounts.insert(
        account_id_str.clone(),
        JmapAccount {
            name: account_id_str.clone(),
            is_personal: true,
            is_read_only: true,
            account_capabilities: serde_json::json!({ CAPABILITY_MAIL: {} }),
        },
    );
    let mut primary_accounts = HashMap::new();
    primary_accounts.insert(CAPABILITY_MAIL.to_string(), account_id_str.clone());

    Ok(Json(JmapSession {
        capabilities: serde_json::json!({ CAPABILITY_CORE: {}, CAPABILITY_MAIL: {} }),
        accounts,
        primary_accounts,
        username: account_id_str,
        api_url: "/jmap/api".to_string(),
        download_url: "/jmap/download/{blobId}".to_string(),
        upload_url: "/jmap/upload".to_string(),
        event_source_url: "/jmap/sse".to_string(),
        state: "1".to_string(),
    }))
}

pub async fn jmap_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Request>,
) -> Result<Json<Response>, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let account_id_str = state
        .sessions
        .account_id(token)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();

    let mut method_responses = Vec::with_capacity(req.method_calls.len());
    for call in req.method_calls {
        // Run the whole dispatch inside the session lock's closure so the
        // account private key is only ever touched by reference, never
        // copied out to a local variable. Account priv and the search
        // index come from the same locked section (see with_session's
        // doc) so a text-search filter doesn't need to re-lock the
        // registry.
        let response = state.sessions.with_session(token, |account_id, account_priv, search_index, identity, amk| {
            let search_fn = |query: &str| -> common::Result<Vec<i64>> {
                search_index.search(&state.blobs, &state.metadata, account_id, account_priv, query)
            };
            let ctx = AccountContext {
                account_id_str: account_id_str.clone(),
                blobs: &state.blobs,
                metadata: &state.metadata,
                queue: &state.queue_store,
                auth_store: &state.auth_store,
                account_priv,
                account_pub: &identity.account_pub,
                key_id: identity.key_id,
                address: &identity.address,
                amk,
                search: &search_fn,
                notifier: &state.notifier,
            };
            dispatch(call, &ctx)
        });
        match response {
            Some(r) => method_responses.push(r),
            None => return Err(StatusCode::UNAUTHORIZED),
        }
    }

    Ok(Json(Response { method_responses }))
}

#[derive(Deserialize)]
pub struct SseQuery {
    /// `EventSource` can't set an `Authorization` header, so this is the
    /// only way a browser push connection can authenticate -- accepted
    /// here in addition to (not instead of) the header, which any
    /// non-browser JMAP client should keep using. Tradeoff accepted
    /// deliberately: this token is bearer-only, read-only in effect (SSE
    /// never accepts input), and no worse-exposed than any other query
    /// string an access log might capture.
    token: Option<String>,
}

pub async fn sse(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SseQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let token = bearer_token(&headers)
        .map(str::to_string)
        .or(query.token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let account_id = state
        .sessions
        .account_id(&token)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let rx = state.notifier.subscribe();
    let stream = stream::unfold((rx, account_id), |(mut rx, account_id)| async move {
        loop {
            tokio::select! {
                changed = rx.recv() => {
                    match changed {
                        Ok(c) if c.account_id == account_id => {
                            let payload = serde_json::json!({
                                "@type": "StateChange",
                                "changed": {
                                    account_id.to_string(): {
                                        "Mailbox": c.state.to_string(),
                                        "Email": c.state.to_string(),
                                    }
                                }
                            });
                            let event = Event::default().event("state").data(payload.to_string());
                            return Some((Ok(event), (rx, account_id)));
                        }
                        // Not this connection's account -- keep waiting,
                        // don't emit anything for it.
                        Ok(_) => continue,
                        // A slow consumer missed some notifications; not
                        // fatal, just re-fetch will catch it up (same
                        // effect as coalescing several "changed" events).
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    return Some((Ok(Event::default().comment("heartbeat")), (rx, account_id)));
                }
            }
        }
    });
    Ok(Sse::new(stream))
}
