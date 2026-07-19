//! HTTP handlers: our own password-unlock bootstrap (not part of the JMAP
//! wire format itself) plus the JMAP session resource, method-call API, and
//! SSE push endpoint (RFC 8620 §2, §3, §7.3).

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use axum::Json;
use futures_util::stream::{self, Stream};
use mail_parser::{MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::api::{dispatch, now_unix, AccountContext};
use crate::content_disposition::attachment_header;
use crate::session_store::SessionIdentity;
use crate::types::{JmapAccount, JmapSession, Request, Response, CAPABILITY_CORE, CAPABILITY_MAIL};
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
    let permit = state
        .auth_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let auth_store = state.auth_store.clone();
    let argon2_config = state.argon2_config.clone();
    let account_for_unlock = account.clone();
    let password = req.password;
    let unlock_result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth_store.unlock(&account_for_unlock, password.as_bytes(), &argon2_config)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let unlocked = match unlock_result {
        Ok(unlocked) => unlocked,
        Err(_) => {
            state.login_throttle.record_failure(&identity);
            let _ = state
                .audit_store
                .log("auth.unlock_failed", &account.address());
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
    let token = state
        .sessions
        .create(account.id, unlocked, session_identity);
    let _ = state.audit_store.log("auth.unlock", &account.address());
    Ok(Json(UnlockResponse {
        token,
        account_id: account.id.to_string(),
    }))
}

pub async fn lock(State(state): State<AppState>, headers: HeaderMap) -> StatusCode {
    if let Some(token) = bearer_token(&headers) {
        if let Some(account_id) = state.sessions.account_id(token) {
            let _ = state
                .audit_store
                .log("session.close", &account_id.to_string());
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
    let token = bearer_token(&headers)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let account_id_str = state
        .sessions
        .account_id(&token)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();

    // Decryption, MIME parsing, and HTML sanitization inside `dispatch`
    // are synchronous CPU work, not I/O -- running them straight on the
    // async task would tie up a Tokio worker thread for the whole batch
    // and serialize unrelated requests behind it. `spawn_blocking` moves
    // the whole per-call loop onto the blocking pool, so concurrent
    // `Email/get` calls (different tabs, different accounts) actually
    // run in parallel across threads.
    let method_responses = tokio::task::spawn_blocking(move || {
        let mut method_responses = Vec::with_capacity(req.method_calls.len());
        for call in req.method_calls {
            // Run the whole dispatch inside the session lock's closure so the
            // account private key is only ever touched by reference, never
            // copied out to a local variable. Account priv and the search
            // index come from the same locked section (see with_session's
            // doc) so a text-search filter doesn't need to re-lock the
            // registry.
            let response = state.sessions.with_session(
                &token,
                |account_id, account_priv, search_index, identity, amk| {
                    let search_fn = |query: &str| -> common::Result<Vec<i64>> {
                        search_index.search(
                            &state.blobs,
                            &state.metadata,
                            account_id,
                            account_priv,
                            query,
                        )
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
                        max_upload_size: state.max_upload_size,
                        search: &search_fn,
                        notifier: &state.notifier,
                    };
                    dispatch(call, &ctx)
                },
            );
            match response {
                Some(r) => method_responses.push(r),
                None => return Err(StatusCode::UNAUTHORIZED),
            }
        }
        Ok(method_responses)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)??;

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
    // Unlike every other authenticated endpoint (which re-validates via
    // `with_session`/`account_id` on every call, including the idle
    // timeout), a streaming connection has no natural "next request" to
    // hang that check on -- so the heartbeat tick doubles as one. This
    // means a revoked or idled-out token stops this stream within one
    // heartbeat interval instead of staying live until the client
    // disconnects on its own.
    let stream = stream::unfold(
        (rx, account_id, state.sessions.clone(), token),
        |(mut rx, account_id, sessions, token)| async move {
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
                                return Some((Ok(event), (rx, account_id, sessions, token)));
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
                        if sessions.account_id(&token) != Some(account_id) {
                            return None;
                        }
                        return Some((Ok(Event::default().comment("heartbeat")), (rx, account_id, sessions, token)));
                    }
            }
        }
    });
    Ok(Sse::new(stream))
}

/// Resolves a blobId to (filename, content_type, plaintext bytes),
/// enforcing account ownership. Returns `None` for "doesn't exist" *and*
/// "exists but isn't yours" alike -- the caller must map both to the same
/// 404, never a distinguishable 403 that would confirm something exists.
fn resolve_blob(
    state: &AppState,
    account_id: i64,
    account_priv: &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN],
    blob_id: &str,
) -> Option<(String, String, Vec<u8>)> {
    if let Some(rest) = blob_id.strip_prefix('m') {
        let (message_id, index) = rest.split_once('.')?;
        let message_id: i64 = message_id.parse().ok()?;
        let index: usize = index.parse().ok()?;

        let stored = state.metadata.get_message(message_id).ok().flatten()?;
        if stored.account_id != account_id {
            return None;
        }
        let raw = delivery::open_message(&state.blobs, &stored, account_priv).ok()?;
        let message = MessageParser::default().parse(&raw)?;
        let part = message.attachments().nth(index)?;
        let filename = part
            .attachment_name()
            .unwrap_or("attachment")
            .to_string();
        let content_type = part
            .content_type()
            .map(|ct| match &ct.c_subtype {
                Some(sub) => format!("{}/{sub}", ct.c_type),
                None => ct.c_type.to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        Some((filename, content_type, part.contents().to_vec()))
    } else if let Some(rest) = blob_id.strip_prefix('u') {
        let upload_id: i64 = rest.parse().ok()?;

        let stored = state.metadata.get_upload(upload_id).ok().flatten()?;
        if stored.account_id != account_id {
            return None;
        }
        let bytes = delivery::open_blob(
            &state.blobs,
            &stored.blob_hash,
            &stored.dek_wrap,
            account_priv,
        )
        .ok()?;
        Some((stored.filename, stored.content_type, bytes))
    } else {
        None
    }
}

pub async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(blob_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let token = bearer_token(&headers)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    // Same reasoning as `jmap_api`: decrypting the message blob and
    // MIME-parsing it to find one attachment is CPU work, not I/O.
    let resolved = tokio::task::spawn_blocking(move || {
        state
            .sessions
            .with_account(&token, |account_id, account_priv| {
                resolve_blob(&state, account_id, account_priv, &blob_id)
            })
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::UNAUTHORIZED)?;
    let (filename, content_type, bytes) = resolved.ok_or(StatusCode::NOT_FOUND)?;

    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (
                header::CONTENT_DISPOSITION,
                attachment_header(&filename),
            ),
            (
                header::HeaderName::from_static("x-content-type-options"),
                "nosniff".to_string(),
            ),
        ],
        bytes,
    ))
}

#[derive(Deserialize)]
pub struct UploadQuery {
    filename: Option<String>,
}

#[derive(Serialize)]
pub struct UploadResponse {
    #[serde(rename = "accountId")]
    account_id: String,
    #[serde(rename = "blobId")]
    blob_id: String,
    #[serde(rename = "type")]
    content_type: String,
    size: i64,
}

pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UploadQuery>,
    body: Bytes,
) -> Result<Json<UploadResponse>, StatusCode> {
    let token = bearer_token(&headers)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();

    let filename = query.filename.unwrap_or_else(|| "attachment".to_string());
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    if !common::input::valid_header_value(&filename) || !common::input::valid_header_value(&content_type) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // ClamAV can't scan ciphertext, so this must run before sealing --
    // never reorder. Fails closed (unlike inbound mail's fail-open
    // policy): this is a single retryable interactive action, not mail
    // that has to keep flowing for availability reasons.
    if let Some(clamav) = &state.clamav {
        match clamav.scan_with_timeout(&body).await {
            Ok(scan::clamav::ClamavVerdict::Clean) => {}
            Ok(scan::clamav::ClamavVerdict::Found(_)) => {
                return Err(StatusCode::UNPROCESSABLE_ENTITY)
            }
            Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    let size = body.len() as i64;
    // Sealing (crypto) and the metadata insert are the same kind of
    // synchronous work as `jmap_api`'s dispatch -- off the async task.
    let result = tokio::task::spawn_blocking(move || {
        state.sessions.with_session(
            &token,
            |account_id, _account_priv, _search_index, identity, _amk| -> Result<UploadResponse, StatusCode> {
                let (blob_hash, dek_wrap) = delivery::seal_for_account(
                    &state.blobs,
                    &identity.account_pub,
                    identity.key_id,
                    &body,
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                let upload_id = state
                    .metadata
                    .insert_upload(&store::NewUpload {
                        account_id,
                        blob_hash: &blob_hash,
                        dek_wrap: &dek_wrap,
                        key_id: identity.key_id,
                        filename: &filename,
                        content_type: &content_type,
                        size_bytes: size,
                        created_at: now_unix(),
                    })
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok(UploadResponse {
                    account_id: account_id.to_string(),
                    blob_id: format!("u{upload_id}"),
                    content_type: content_type.clone(),
                    size,
                })
            },
        )
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Some(Ok(resp)) => Ok(Json(resp)),
        Some(Err(status)) => Err(status),
        None => Err(StatusCode::UNAUTHORIZED),
    }
}
