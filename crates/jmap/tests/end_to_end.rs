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
