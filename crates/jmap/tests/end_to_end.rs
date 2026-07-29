//! Drives the real HTTP surface (via `tower::ServiceExt::oneshot`, no
//! sockets needed) through unlock -> Email/query -> Email/get, confirming
//! the decrypted content that comes back over JMAP matches what was
//! delivered.

use std::sync::Arc;

use auth::AuthStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::config::Argon2Config;
use delivery::{AuthResults, InboundEnvelope, RecipientAccount};
use jmap::{build_router, AppState};
use store::{BlobStore, MetadataStore};
use tower::ServiceExt;

fn fast_argon2() -> Argon2Config {
    Argon2Config {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

async fn json_body(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn unlock_query_get_round_trips_decrypted_content() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let account = auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    delivery::deliver(
        &blobs,
        &metadata,
        &RecipientAccount {
            id: account.id,
            account_pub: account.account_pub,
            key_id: account.key_id,
        },
        &InboundEnvelope {
            mail_from: "sender@example.net".into(),
            rcpt_to: "alice@example.com".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        },
        &AuthResults {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        },
        b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Hello JMAP\r\n\r\nBody text here.\r\n",
        1_700_000_000,
        None,
        delivery::ScanMetadata::default(),
    )
    .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    // 1. Unlock.
    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "local_part": "alice",
                "domain": "example.com",
                "password": "correct horse battery staple",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    // 2. Email/query.
    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/query", { "accountId": account_id }, "c1"]
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let ids = body["methodResponses"][0][1]["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 1);
    let email_id = ids[0].as_str().unwrap().to_string();

    // 3. Email/get -- this is the step that actually decrypts.
    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Email/get", { "accountId": account_id, "ids": [email_id] }, "c2"]
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let list = body["methodResponses"][0][1]["list"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["subject"], "Hello JMAP");
    assert_eq!(list[0]["from"][0]["email"], "sender@example.net");
    assert_eq!(list[0]["bodyText"], "Body text here.\r\n");

    // 4. Wrong password must not unlock.
    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "local_part": "alice",
                "domain": "example.com",
                "password": "wrong",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 5. Lock invalidates the token.
    let req = Request::builder()
        .method("POST")
        .uri("/auth/lock")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let req = Request::builder()
        .method("GET")
        .uri("/jmap/session")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn repeated_failed_unlocks_are_throttled() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let attempt = |app: axum::Router, password: &'static str| {
        let req = Request::builder()
            .method("POST")
            .uri("/auth/unlock")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"local_part": "alice", "domain": "example.com", "password": password}).to_string(),
            ))
            .unwrap();
        app.oneshot(req)
    };

    // First wrong password: a normal 401, and it starts the lockout clock.
    let resp = attempt(app.clone(), "wrong").await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Immediately retrying -- even with the *correct* password -- is
    // throttled rather than checked, so the lockout can't be raced.
    let resp = attempt(app.clone(), "correct horse battery staple")
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn jmap_api_without_token_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(fast_argon2()),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "using": [], "methodCalls": [] }).to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn html_email_is_sanitized_and_images_blocked_over_jmap() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let account = auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    let raw = b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: HTML\r\n\
        Content-Type: text/html\r\n\r\n\
        <p>hi</p><script>alert(1)</script><img src=\"https://evil.example/pixel.gif\">\
        <a href=\"https://example.com\" onclick=\"steal()\">link</a>\r\n";
    delivery::deliver(
        &blobs,
        &metadata,
        &RecipientAccount {
            id: account.id,
            account_pub: account.account_pub,
            key_id: account.key_id,
        },
        &InboundEnvelope {
            mail_from: "sender@example.net".into(),
            rcpt_to: "alice@example.com".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        },
        &AuthResults {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        },
        raw,
        1_700_000_000,
        None,
        delivery::ScanMetadata::default(),
    )
    .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "local_part": "alice",
                "domain": "example.com",
                "password": "correct horse battery staple",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", { "accountId": account_id }, "c1"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let email_id = body["methodResponses"][0][1]["ids"][0]
        .as_str()
        .unwrap()
        .to_string();

    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", { "accountId": account_id, "ids": [email_id] }, "c2"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let email = &body["methodResponses"][0][1]["list"][0];

    let html = email["bodyHtml"].as_str().unwrap();
    assert!(!html.contains("script"));
    assert!(!html.contains("alert"));
    assert!(!html.contains("onclick"));
    assert!(!html.contains("steal"));
    assert!(html.contains("data-blocked-src=\"https://evil.example/pixel.gif\""));
    assert!(html.contains("data-real-href=\"https://example.com\""));
    assert_eq!(email["blockedImageCount"], 1);
}

#[tokio::test]
async fn email_get_properties_filter_skips_attachments_and_html_when_not_requested() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let account = auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    let raw = b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Invoice\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n\
        --BOUNDARY\r\n\
        Content-Type: text/html\r\n\r\n\
        <p>See attached.</p>\r\n\
        --BOUNDARY\r\n\
        Content-Type: application/pdf\r\n\
        Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
        Content-Transfer-Encoding: base64\r\n\r\n\
        JVBERi1mYWtl\r\n\
        --BOUNDARY--\r\n";
    delivery::deliver(
        &blobs,
        &metadata,
        &RecipientAccount {
            id: account.id,
            account_pub: account.account_pub,
            key_id: account.key_id,
        },
        &InboundEnvelope {
            mail_from: "sender@example.net".into(),
            rcpt_to: "alice@example.com".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        },
        &AuthResults {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        },
        raw,
        1_700_000_000,
        None,
        delivery::ScanMetadata::default(),
    )
    .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "local_part": "alice",
                "domain": "example.com",
                "password": "correct horse battery staple",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", { "accountId": account_id }, "c1"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let email_id = body["methodResponses"][0][1]["ids"][0]
        .as_str()
        .unwrap()
        .to_string();

    // A list-view-shaped request (no bodyHtml/attachments in `properties`)
    // gets neither back, even though the message has both.
    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", {
            "accountId": account_id,
            "ids": [email_id.clone()],
            "properties": ["id", "subject", "preview"]
        }, "c2"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let summary = &body["methodResponses"][0][1]["list"][0];
    assert_eq!(summary["subject"], "Invoice");
    assert!(summary["bodyHtml"].is_null());
    assert_eq!(summary["attachments"].as_array().unwrap().len(), 0);

    // Omitting `properties` entirely still returns everything (unchanged
    // default behavior, matching every pre-existing caller).
    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", { "accountId": account_id, "ids": [email_id] }, "c3"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let full = &body["methodResponses"][0][1]["list"][0];
    assert!(full["bodyHtml"].as_str().unwrap().contains("See attached"));
    assert_eq!(full["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(full["attachments"][0]["name"], "invoice.pdf");
}

#[tokio::test]
async fn inbound_attachment_metadata_is_exposed_over_jmap() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let account = auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    let raw = b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Invoice\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n\
        --BOUNDARY\r\n\
        Content-Type: text/plain\r\n\r\n\
        See attached.\r\n\
        --BOUNDARY\r\n\
        Content-Type: application/pdf\r\n\
        Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
        Content-Transfer-Encoding: base64\r\n\r\n\
        JVBERi1mYWtl\r\n\
        --BOUNDARY--\r\n";
    delivery::deliver(
        &blobs,
        &metadata,
        &RecipientAccount {
            id: account.id,
            account_pub: account.account_pub,
            key_id: account.key_id,
        },
        &InboundEnvelope {
            mail_from: "sender@example.net".into(),
            rcpt_to: "alice@example.com".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        },
        &AuthResults {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        },
        raw,
        1_700_000_000,
        None,
        delivery::ScanMetadata::default(),
    )
    .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "local_part": "alice",
                "domain": "example.com",
                "password": "correct horse battery staple",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", { "accountId": account_id }, "c1"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let email_id = body["methodResponses"][0][1]["ids"][0]
        .as_str()
        .unwrap()
        .to_string();

    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", { "accountId": account_id, "ids": [email_id] }, "c2"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let email = &body["methodResponses"][0][1]["list"][0];

    let attachments = email["attachments"].as_array().unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0]["name"], "invoice.pdf");
    assert_eq!(attachments[0]["type"], "application/pdf");
    assert!(attachments[0]["size"].as_i64().unwrap() > 0);
    let blob_id = attachments[0]["blobId"].as_str().unwrap();
    assert!(blob_id.starts_with(&format!("{}.", email["id"].as_str().unwrap())));
}

/// Covers both blobId shapes (`m{id}.{index}` for an inbound message
/// attachment, `u{id}` for a pending upload): the owning account can
/// fetch either, and a different account gets an identical 404 for
/// either -- never a distinguishable 403 that would confirm the blob
/// exists under someone else's account.
#[tokio::test]
async fn download_is_a_uniform_404_across_accounts_for_message_and_upload_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let alice = auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();
    auth_store
        .provision("bob", "example.com", b"another horse battery staple", &cfg)
        .unwrap();

    let raw = b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Invoice\r\n\
        MIME-Version: 1.0\r\n\
        Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n\
        --BOUNDARY\r\n\
        Content-Type: text/plain\r\n\r\n\
        See attached.\r\n\
        --BOUNDARY\r\n\
        Content-Type: application/pdf\r\n\
        Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
        Content-Transfer-Encoding: base64\r\n\r\n\
        JVBERi1mYWtl\r\n\
        --BOUNDARY--\r\n";
    delivery::deliver(
        &blobs,
        &metadata,
        &RecipientAccount {
            id: alice.id,
            account_pub: alice.account_pub,
            key_id: alice.key_id,
        },
        &InboundEnvelope {
            mail_from: "sender@example.net".into(),
            rcpt_to: "alice@example.com".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        },
        &AuthResults {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        },
        raw,
        1_700_000_000,
        None,
        delivery::ScanMetadata::default(),
    )
    .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let unlock = |app: axum::Router, local_part: &'static str, password: &'static str| {
        let req = Request::builder()
            .method("POST")
            .uri("/auth/unlock")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "local_part": local_part,
                    "domain": "example.com",
                    "password": password,
                })
                .to_string(),
            ))
            .unwrap();
        app.oneshot(req)
    };

    let resp = unlock(app.clone(), "alice", "correct horse battery staple")
        .await
        .unwrap();
    let body = json_body(resp).await;
    let alice_token = body["token"].as_str().unwrap().to_string();
    let alice_account_id = body["accountId"].as_str().unwrap().to_string();

    let resp = unlock(app.clone(), "bob", "another horse battery staple")
        .await
        .unwrap();
    let bob_token = json_body(resp).await["token"].as_str().unwrap().to_string();

    // Alice's message attachment blobId, via Email/query + Email/get.
    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", { "accountId": alice_account_id }, "c1"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {alice_token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let email_id = json_body(resp).await["methodResponses"][0][1]["ids"][0]
        .as_str()
        .unwrap()
        .to_string();

    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", { "accountId": alice_account_id, "ids": [email_id] }, "c2"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {alice_token}"))
        .body(Body::from(method_calls.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let message_blob_id = body["methodResponses"][0][1]["list"][0]["attachments"][0]["blobId"]
        .as_str()
        .unwrap()
        .to_string();

    // Alice uploads a file directly -> a `u{id}` blobId.
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/upload?filename=notes.txt")
        .header("content-type", "text/plain")
        .header("authorization", format!("Bearer {alice_token}"))
        .body(Body::from("hello from alice"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upload_blob_id = json_body(resp).await["blobId"]
        .as_str()
        .unwrap()
        .to_string();

    // Alice can fetch both of her own blobs.
    for blob_id in [&message_blob_id, &upload_blob_id] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/jmap/download/{blob_id}"))
            .header("authorization", format!("Bearer {alice_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "alice should be able to fetch her own {blob_id}"
        );
    }

    // Bob gets a uniform 404 for both -- never a 403 that would confirm
    // something exists under an account that isn't his.
    for blob_id in [&message_blob_id, &upload_blob_id] {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/jmap/download/{blob_id}"))
            .header("authorization", format!("Bearer {bob_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "bob must get 404, not 403, for {blob_id}"
        );
    }
}

/// Contact/set create+update+destroy round trip over the real HTTP surface,
/// plus the app-level duplicate-email rejection (there's no SQL UNIQUE for
/// this since the email lives inside the sealed blob -- see
/// `crates/jmap/src/api.rs::contact_set`).
#[tokio::test]
async fn contact_crud_round_trip_and_rejects_duplicate_email() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "local_part": "alice",
                "domain": "example.com",
                "password": "correct horse battery staple",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    let call = |method_calls: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(method_calls.to_string()))
            .unwrap()
    };

    // 1. Create a contact.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Contact/set", { "accountId": account_id, "create": { "c1": { "name": "Bob", "email": "bob@example.net" } } }, "r1"]
        ]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let created = &body["methodResponses"][0][1]["created"]["c1"];
    assert_eq!(created["email"], "bob@example.net");
    let contact_id = created["id"].as_str().unwrap().to_string();

    // 2. A second contact with the same email (any case) is rejected.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Contact/set", { "accountId": account_id, "create": { "c2": { "name": "Bobby", "email": "BOB@example.net" } } }, "r2"]
        ]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert!(body["methodResponses"][0][1]["created"].get("c2").is_none());
    assert_eq!(
        body["methodResponses"][0][1]["notCreated"]["c2"]["type"],
        "serverFail"
    );

    // 3. Contact/get lists the one contact that was actually created.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Contact/get", { "accountId": account_id }, "r3"]
        ]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let list = body["methodResponses"][0][1]["list"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], contact_id);
    assert_eq!(list[0]["name"], "Bob");

    // 4. Update the name.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Contact/set", { "accountId": account_id, "update": { (contact_id.clone()): { "name": "Bob Smith" } } }, "r4"]
        ]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert!(body["methodResponses"][0][1]["updated"]
        .get(&contact_id)
        .is_some());

    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Contact/get", { "accountId": account_id, "ids": [contact_id.clone()] }, "r5"]
        ]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert_eq!(
        body["methodResponses"][0][1]["list"][0]["name"],
        "Bob Smith"
    );

    // 5. Destroy it, then confirm it's gone.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Contact/set", { "accountId": account_id, "destroy": [contact_id.clone()] }, "r6"]
        ]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert_eq!(body["methodResponses"][0][1]["destroyed"][0], contact_id);

    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Contact/get", { "accountId": account_id }, "r7"]
        ]
    }));
    let resp = app.oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert!(body["methodResponses"][0][1]["list"]
        .as_array()
        .unwrap()
        .is_empty());
}

/// `snoozeUntil`/`nudgeAt` (spec §8.6) over the real HTTP surface: setting
/// either schedules a `scheduled_events` row (verified by querying the
/// same `QueueStore` handle the router was built with -- the actual
/// worker loop that fires them lives in the `queue` crate and is tested
/// there), and a pending snooze hides the message from the default
/// mailbox query until cancelled.
#[tokio::test]
async fn snooze_and_nudge_schedule_events_and_snooze_hides_from_query() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let queue_store = Arc::new(queue::QueueStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let account = auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    delivery::deliver(
        &blobs,
        &metadata,
        &RecipientAccount {
            id: account.id,
            account_pub: account.account_pub,
            key_id: account.key_id,
        },
        &InboundEnvelope {
            mail_from: "sender@example.net".into(),
            rcpt_to: "alice@example.com".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        },
        &AuthResults {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        },
        b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Snooze me\r\n\r\nBody.\r\n",
        1_700_000_000,
        None,
        delivery::ScanMetadata::default(),
    )
    .unwrap();

    let state = AppState::new(
        auth_store,
        blobs,
        metadata,
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        queue_store.clone(),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "local_part": "alice",
                "domain": "example.com",
                "password": "correct horse battery staple",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    let call = |method_calls: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(method_calls.to_string()))
            .unwrap()
    };

    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", { "accountId": account_id }, "q1"]]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let email_id = body["methodResponses"][0][1]["ids"][0]
        .as_str()
        .unwrap()
        .to_string();

    // Snooze: sets $snoozed (client's own responsibility, same call) and
    // schedules a snooze_resurface event.
    let fire_at = 1_700_100_000i64;
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            { "accountId": account_id, "update": { (email_id.clone()): { "keywords/$snoozed": true, "snoozeUntil": fire_at } } },
            "r1"
        ]]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert!(body["methodResponses"][0][1]["updated"]
        .get(&email_id)
        .is_some());

    let pending = queue_store
        .pending_events_for_account(account.id, queue::ScheduledKind::SnoozeResurface)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].fire_at, fire_at);
    assert_eq!(pending[0].payload.as_deref(), Some(email_id.as_str()));

    // The default mailbox query no longer shows it.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", { "accountId": account_id }, "q2"]]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert!(body["methodResponses"][0][1]["ids"]
        .as_array()
        .unwrap()
        .is_empty());

    // Email/get reports snoozedUntil.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/get", { "accountId": account_id, "ids": [email_id.clone()] }, "g1"]]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert_eq!(
        body["methodResponses"][0][1]["list"][0]["snoozedUntil"],
        fire_at
    );

    // A nudge can be scheduled independently of the snooze.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            { "accountId": account_id, "update": { (email_id.clone()): { "nudgeAt": fire_at } } },
            "r2"
        ]]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert!(body["methodResponses"][0][1]["updated"]
        .get(&email_id)
        .is_some());
    let pending_nudges = queue_store
        .pending_events_for_account(account.id, queue::ScheduledKind::FollowupNudge)
        .unwrap();
    assert_eq!(pending_nudges.len(), 1);

    // Cancelling both (null) clears the pending events and un-hides the
    // message from the default query.
    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [[
            "Email/set",
            { "accountId": account_id, "update": { (email_id.clone()): { "keywords/$snoozed": false, "snoozeUntil": null, "nudgeAt": null } } },
            "r3"
        ]]
    }));
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert!(body["methodResponses"][0][1]["updated"]
        .get(&email_id)
        .is_some());

    assert!(queue_store
        .pending_events_for_account(account.id, queue::ScheduledKind::SnoozeResurface)
        .unwrap()
        .is_empty());
    assert!(queue_store
        .pending_events_for_account(account.id, queue::ScheduledKind::FollowupNudge)
        .unwrap()
        .is_empty());

    let req = call(serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [["Email/query", { "accountId": account_id }, "q3"]]
    }));
    let resp = app.oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    assert_eq!(
        body["methodResponses"][0][1]["ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn app_passwords_can_be_created_used_and_revoked() {
    let tmp = tempfile::tempdir().unwrap();
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    auth_store
        .provision(
            "alice",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    let state = AppState::new(
        auth_store,
        Arc::new(BlobStore::open(tmp.path()).unwrap()),
        Arc::new(MetadataStore::open_in_memory().unwrap()),
        Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        Arc::new(cfg),
        Arc::new(queue::QueueStore::open_in_memory().unwrap()),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    async fn unlock(app: &axum::Router, password: &str) -> Option<String> {
        let req = Request::builder()
            .method("POST")
            .uri("/auth/unlock")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"local_part": "alice", "domain": "example.com", "password": password})
                    .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        if resp.status() != StatusCode::OK {
            return None;
        }
        Some(json_body(resp).await["token"].as_str().unwrap().to_string())
    }

    let primary_token = unlock(&app, "correct horse battery staple").await.unwrap();

    // Create a full-scope app password.
    let req = Request::builder()
        .method("POST")
        .uri("/auth/app-passwords")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {primary_token}"))
        .body(Body::from(
            serde_json::json!({"label": "Thunderbird", "scope": "full"}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["label"], "Thunderbird");
    assert_eq!(body["scope"], "full");
    let full_password = body["password"].as_str().unwrap().to_string();
    let full_id = body["id"].as_i64().unwrap();

    // Create a submission-scoped app password.
    let req = Request::builder()
        .method("POST")
        .uri("/auth/app-passwords")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {primary_token}"))
        .body(Body::from(
            serde_json::json!({"label": "relay", "scope": "submission"}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let submission_password = json_body(resp).await["password"]
        .as_str()
        .unwrap()
        .to_string();

    // Listing shows both, without ever exposing the secret again.
    let req = Request::builder()
        .method("GET")
        .uri("/auth/app-passwords")
        .header("authorization", format!("Bearer {primary_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let list = json_body(resp).await;
    let labels: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels.len(), 2);
    assert!(labels.contains(&"Thunderbird"));
    assert!(labels.contains(&"relay"));
    assert!(list[0].get("password").is_none());

    // A full-scope app password unlocks JMAP just like the primary password.
    let via_full = unlock(&app, &full_password).await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri("/jmap/session")
        .header("authorization", format!("Bearer {via_full}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // A submission-scoped app password must not unlock JMAP -- same 401 as
    // a wrong password, not a distinct error.
    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"local_part": "alice", "domain": "example.com", "password": submission_password})
                .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Revoking the full-scope password invalidates it for future unlocks
    // (the already-open session above is untouched -- same as a password
    // change not retroactively killing other open sessions).
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/auth/app-passwords/{full_id}"))
        .header("authorization", format!("Bearer {primary_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    assert!(unlock(&app, &full_password).await.is_none());

    // The primary password is unaffected by revoking a different
    // credential -- wait out the login throttle's lockout window first
    // (the failed attempts above against the shared "alice@example.com"
    // identity started its exponential backoff, same mechanism the login
    // end-to-end test already waits out).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(unlock(&app, "correct horse battery staple").await.is_some());
}
