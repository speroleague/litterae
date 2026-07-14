//! Drives the real admin HTTP API: status before/after bootstrap, forced
//! password change, domain + catch-all management, account provisioning
//! guarded by domain ownership, and queue status reporting.

use std::sync::Arc;

use admin::{build_router, AppState};
use auth::AuthStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::config::Argon2Config;
use queue::QueueStore;
use store::BlobStore;
use tower::ServiceExt;

fn fast_argon2() -> Argon2Config {
    Argon2Config {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn test_resolver() -> Arc<dns::Resolver> {
    Arc::new(dns::Resolver::new().unwrap())
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    app.clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn bootstrap_login_forced_reset_domains_accounts_and_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let admin_store = Arc::new(admin::AdminStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let queue_store = Arc::new(QueueStore::open_in_memory().unwrap());
    let audit_store = Arc::new(audit::AuditStore::open_in_memory().unwrap());
    let blobs = BlobStore::open(tmp.path()).unwrap();
    let cfg = Arc::new(fast_argon2());

    let state = AppState::new(
        admin_store.clone(),
        auth_store,
        queue_store.clone(),
        audit_store.clone(),
        cfg.clone(),
        None,
        test_resolver(),
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    // --- Before bootstrap: no admin. ---
    let resp = request(&app, "GET", "/admin/status", None, None).await;
    let body = json_body(resp).await;
    assert_eq!(body["hasAdmin"], false);

    let bootstrap_pk = admin_store
        .bootstrap("admin", b"change-me-please", &cfg)
        .unwrap()
        .unwrap();
    audit_store.bootstrap_keys(&bootstrap_pk).unwrap();

    let resp = request(&app, "GET", "/admin/status", None, None).await;
    let body = json_body(resp).await;
    assert_eq!(body["hasAdmin"], true);

    // --- Login with the bootstrap password: must-change flag is set. ---
    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": "change-me-please"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["mustChangePassword"], true);
    let token = body["token"].as_str().unwrap().to_string();

    // A bootstrap session is restricted server-side, not merely redirected
    // by the browser UI.
    let resp = request(&app, "GET", "/admin/domains", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // --- Change password; old password stops working, new one works. ---
    let resp = request(
        &app,
        "POST",
        "/admin/change-password",
        Some(&token),
        Some(serde_json::json!({"currentPassword": "change-me-please", "newPassword": "a-much-better-password"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": "change-me-please"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // --- That failure starts a lockout clock: an immediate retry is
    // throttled rather than checked, even with the correct password. ---
    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": "a-much-better-password"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": "a-much-better-password"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["mustChangePassword"], false);
    let token = body["token"].as_str().unwrap().to_string();

    // --- Unauthenticated requests to protected endpoints are rejected. ---
    let resp = request(&app, "GET", "/admin/domains", None, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // --- Domain + catch-all management. ---
    let resp = request(
        &app,
        "POST",
        "/admin/domains",
        Some(&token),
        Some(serde_json::json!({"name": "example.com", "catchAllLocalPart": "hello"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let domain_id = body["id"].as_i64().unwrap();
    assert_eq!(body["catchAllLocalPart"], "hello");

    let resp = request(&app, "GET", "/admin/domains", Some(&token), None).await;
    let domains = json_body(resp).await;
    assert_eq!(domains.as_array().unwrap().len(), 1);

    let resp = request(
        &app,
        "PATCH",
        &format!("/admin/domains/{domain_id}"),
        Some(&token),
        Some(serde_json::json!({"catchAllLocalPart": null})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // --- Account provisioning: rejected for an unhosted domain. ---
    let resp = request(
        &app,
        "POST",
        "/admin/accounts",
        Some(&token),
        Some(serde_json::json!({"localPart": "alice", "domain": "not-hosted.example", "password": "pw123456"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // --- Account provisioning: succeeds for a hosted domain. ---
    let resp = request(
        &app,
        "POST",
        "/admin/accounts",
        Some(&token),
        Some(serde_json::json!({"localPart": "alice", "domain": "example.com", "password": "pw123456789012"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["address"], "alice@example.com");
    let account_id = body["id"].as_i64().unwrap();

    let resp = request(&app, "GET", "/admin/accounts", Some(&token), None).await;
    let accounts = json_body(resp).await;
    assert_eq!(accounts.as_array().unwrap().len(), 1);

    let resp = request(
        &app,
        "DELETE",
        &format!("/admin/accounts/{account_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = request(&app, "GET", "/admin/accounts", Some(&token), None).await;
    let accounts = json_body(resp).await;
    assert!(accounts.as_array().unwrap().is_empty());

    // --- Queue status. ---
    let key = queue_store.ensure_dkim_key("example.com").unwrap();
    queue::enqueue(
        &queue_store,
        &blobs,
        &key,
        &queue::NewOutbound {
            account_id: 1,
            envelope_from: "alice@example.com",
            raw_message: b"From: alice@example.com\r\nTo: bob@example.net\r\nSubject: hi\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n",
            recipients: &["bob@example.net"],
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        },
    )
    .unwrap();

    let resp = request(&app, "GET", "/admin/queue", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["metrics"]["ready"], 1);

    // --- Audit log: readable through the session, and covers what just
    // happened (chain integrity holds independent of the read). ---
    assert!(audit_store.verify_chain().unwrap());
    let resp = request(&app, "GET", "/admin/audit", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let entries = json_body(resp).await;
    let actions: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"admin.domain_create"));
    assert!(actions.contains(&"admin.account_create"));
    assert!(actions.contains(&"admin.account_delete"));
    assert!(actions.contains(&"admin.password_change"));

    // --- Oversized request bodies are rejected before touching a handler. ---
    let huge_password = "x".repeat(1024 * 1024);
    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": huge_password})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // --- Logout invalidates the token. ---
    let resp = request(&app, "POST", "/admin/logout", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = request(&app, "GET", "/admin/domains", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn domain_dkim_and_verification_endpoints() {
    let admin_store = Arc::new(admin::AdminStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let queue_store = Arc::new(QueueStore::open_in_memory().unwrap());
    let audit_store = Arc::new(audit::AuditStore::open_in_memory().unwrap());
    let cfg = Arc::new(fast_argon2());
    let bootstrap_pk = admin_store
        .bootstrap("admin", b"pw", &cfg)
        .unwrap()
        .unwrap();
    audit_store.bootstrap_keys(&bootstrap_pk).unwrap();

    let state = AppState::new(
        admin_store,
        auth_store,
        queue_store,
        audit_store,
        cfg,
        None,
        test_resolver(),
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": "pw"})),
    )
    .await;
    let token = json_body(resp).await["token"].as_str().unwrap().to_string();
    let resp = request(
        &app,
        "POST",
        "/admin/change-password",
        Some(&token),
        Some(serde_json::json!({"currentPassword": "pw", "newPassword": "strong-test-password"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = request(
        &app,
        "POST",
        "/admin/domains",
        Some(&token),
        Some(serde_json::json!({"name": "example.com", "catchAllLocalPart": null})),
    )
    .await;
    let created = json_body(resp).await;
    let domain_id = created["id"].as_i64().unwrap();
    assert_eq!(created["verified"], false);
    assert!(!created["verificationToken"].as_str().unwrap().is_empty());

    // --- DKIM record: generated on first request, stable on repeat calls. ---
    let resp = request(
        &app,
        "GET",
        &format!("/admin/domains/{domain_id}/dkim"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let dkim = json_body(resp).await;
    assert_eq!(dkim["domain"], "example.com");
    assert!(dkim["recordName"]
        .as_str()
        .unwrap()
        .ends_with("._domainkey.example.com"));
    let first_value = dkim["recordValue"].as_str().unwrap().to_string();

    let resp = request(
        &app,
        "GET",
        &format!("/admin/domains/{domain_id}/dkim"),
        Some(&token),
        None,
    )
    .await;
    let dkim_again = json_body(resp).await;
    assert_eq!(dkim_again["recordValue"].as_str().unwrap(), first_value);

    // --- Verification: example.com is a real, stable domain but doesn't
    // publish our specific challenge token, so this must come back false
    // rather than erroring -- a live DNS lookup happens, it just finds no
    // matching record. ---
    let resp = request(
        &app,
        "POST",
        &format!("/admin/domains/{domain_id}/verify"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let verify = json_body(resp).await;
    assert_eq!(verify["verified"], false);
    assert!(verify["recordName"]
        .as_str()
        .unwrap()
        .starts_with("_litterae-challenge."));

    let resp = request(&app, "GET", "/admin/domains", Some(&token), None).await;
    let domains = json_body(resp).await;
    assert_eq!(domains[0]["verified"], false);

    // --- Unauthenticated requests are rejected on both new routes. ---
    let resp = request(
        &app,
        "GET",
        &format!("/admin/domains/{domain_id}/dkim"),
        None,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = request(
        &app,
        "POST",
        &format!("/admin/domains/{domain_id}/verify"),
        None,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logs_endpoint_filters_by_time_and_level() {
    let log_dir = tempfile::tempdir().unwrap();
    let today = time::OffsetDateTime::now_utc();
    let file_name = format!(
        "litterae.log.{:04}-{:02}-{:02}",
        today.year(),
        today.month() as u8,
        today.day()
    );

    let old = today - time::Duration::hours(2);
    let recent = today - time::Duration::minutes(5);
    let lines = [
        format!(
            r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"old info line"}},"target":"litterae"}}"#,
            old.format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        ),
        format!(
            r#"{{"timestamp":"{}","level":"WARN","fields":{{"message":"recent warn line"}},"target":"litterae"}}"#,
            recent
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        ),
        format!(
            r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"recent info line"}},"target":"litterae"}}"#,
            recent
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        ),
    ];
    std::fs::write(log_dir.path().join(&file_name), lines.join("\n")).unwrap();

    let admin_store = Arc::new(admin::AdminStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let queue_store = Arc::new(QueueStore::open_in_memory().unwrap());
    let audit_store = Arc::new(audit::AuditStore::open_in_memory().unwrap());
    let cfg = Arc::new(fast_argon2());
    let bootstrap_pk = admin_store
        .bootstrap("admin", b"pw", &cfg)
        .unwrap()
        .unwrap();
    audit_store.bootstrap_keys(&bootstrap_pk).unwrap();

    let state = AppState::new(
        admin_store,
        auth_store,
        queue_store,
        audit_store,
        cfg.clone(),
        Some(log_dir.path().to_path_buf()),
        test_resolver(),
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": "pw"})),
    )
    .await;
    let token = json_body(resp).await["token"].as_str().unwrap().to_string();
    let resp = request(
        &app,
        "POST",
        "/admin/change-password",
        Some(&token),
        Some(serde_json::json!({"currentPassword": "pw", "newPassword": "strong-test-password"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // No filters: all 3 lines, newest first.
    let resp = request(&app, "GET", "/admin/logs", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let list = body.as_array().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0]["fields"]["message"], "recent info line");

    // since = 30 minutes ago: excludes the 2h-old line.
    let since = (today - time::Duration::minutes(30)).unix_timestamp();
    let resp = request(
        &app,
        "GET",
        &format!("/admin/logs?since={since}"),
        Some(&token),
        None,
    )
    .await;
    let body = json_body(resp).await;
    assert_eq!(body.as_array().unwrap().len(), 2);

    // level=WARN: only the one warn line, regardless of time range.
    let resp = request(&app, "GET", "/admin/logs?level=warn", Some(&token), None).await;
    let body = json_body(resp).await;
    let list = body.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["fields"]["message"], "recent warn line");

    // Unauthenticated requests are rejected like every other admin route.
    let resp = request(&app, "GET", "/admin/logs", None, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logs_endpoint_returns_empty_without_a_log_dir() {
    let admin_store = Arc::new(admin::AdminStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let queue_store = Arc::new(QueueStore::open_in_memory().unwrap());
    let audit_store = Arc::new(audit::AuditStore::open_in_memory().unwrap());
    let cfg = Arc::new(fast_argon2());
    let bootstrap_pk = admin_store
        .bootstrap("admin", b"pw", &cfg)
        .unwrap()
        .unwrap();
    audit_store.bootstrap_keys(&bootstrap_pk).unwrap();

    let state = AppState::new(
        admin_store,
        auth_store,
        queue_store,
        audit_store,
        cfg.clone(),
        None,
        test_resolver(),
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let resp = request(
        &app,
        "POST",
        "/admin/login",
        None,
        Some(serde_json::json!({"username": "admin", "password": "pw"})),
    )
    .await;
    let token = json_body(resp).await["token"].as_str().unwrap().to_string();
    let resp = request(
        &app,
        "POST",
        "/admin/change-password",
        Some(&token),
        Some(serde_json::json!({"currentPassword": "pw", "newPassword": "strong-test-password"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = request(&app, "GET", "/admin/logs", Some(&token), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body.as_array().unwrap().is_empty());
}
