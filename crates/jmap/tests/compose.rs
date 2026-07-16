//! Drives compose end-to-end over the real HTTP surface: unlock ->
//! Email/set create (draft, and a reply) -> EmailSubmission/set (send) ->
//! confirms the draft moved to Sent with `$draft` cleared, joined the
//! right thread, and actually landed in the outbound queue.

use std::sync::Arc;

use auth::AuthStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::config::Argon2Config;
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

async fn unlock(
    app: &axum::Router,
    local_part: &str,
    domain: &str,
    password: &str,
) -> (String, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "local_part": local_part, "domain": domain, "password": password })
                .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    (
        body["token"].as_str().unwrap().to_string(),
        body["accountId"].as_str().unwrap().to_string(),
    )
}

async fn jmap_call(
    app: &axum::Router,
    token: &str,
    method: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let method_calls = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [[method, args, "c1"]]
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
    json_body(resp).await["methodResponses"][0][1].clone()
}

#[tokio::test]
async fn compose_save_draft_then_send_lands_in_sent_and_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let queue_store = Arc::new(queue::QueueStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    auth_store
        .provision(
            "alice",
            "example.test",
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
        queue_store.clone(),
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let (token, account_id) = unlock(
        &app,
        "alice",
        "example.test",
        "correct horse battery staple",
    )
    .await;

    // 1. Save a draft.
    let result = jmap_call(
        &app,
        &token,
        "Email/set",
        serde_json::json!({
            "accountId": account_id,
            "create": {
                "draft1": {
                    "to": [{ "email": "bob@example.net" }],
                    "subject": "Hello Bob",
                    "bodyText": "hi there"
                }
            }
        }),
    )
    .await;
    let created = &result["created"]["draft1"];
    assert!(
        created["id"].is_string(),
        "expected a created email id, got {result:?}"
    );
    let email_id = created["id"].as_str().unwrap().to_string();
    let thread_id = created["threadId"].as_str().unwrap().to_string();

    // It should show up in Drafts, tagged $draft.
    let get_result = jmap_call(
        &app,
        &token,
        "Email/get",
        serde_json::json!({ "accountId": account_id, "ids": [email_id] }),
    )
    .await;
    let list = get_result["list"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["subject"], "Hello Bob");
    assert_eq!(list[0]["keywords"]["$draft"], true);

    let mailboxes = jmap_call(
        &app,
        &token,
        "Mailbox/get",
        serde_json::json!({ "accountId": account_id }),
    )
    .await;
    let mailbox_list = mailboxes["list"].as_array().unwrap();
    let drafts_id = mailbox_list.iter().find(|m| m["role"] == "drafts").unwrap()["id"]
        .as_str()
        .unwrap();
    assert_eq!(list[0]["mailboxIds"][drafts_id], true);

    // 2. Send it.
    let submit_result = jmap_call(
        &app,
        &token,
        "EmailSubmission/set",
        serde_json::json!({
            "accountId": account_id,
            "create": {
                "sub1": {
                    "emailId": email_id,
                    "envelope": { "rcptTo": [{ "email": "bob@example.net" }] }
                }
            }
        }),
    )
    .await;
    assert!(
        submit_result["created"]["sub1"].is_object(),
        "expected a created submission, got {submit_result:?}"
    );

    // It should have moved to Sent and lost $draft, same thread.
    let get_result = jmap_call(
        &app,
        &token,
        "Email/get",
        serde_json::json!({ "accountId": account_id, "ids": [email_id] }),
    )
    .await;
    let list = get_result["list"].as_array().unwrap();
    assert_eq!(list[0]["keywords"].get("$draft"), None);
    assert_eq!(list[0]["threadId"], thread_id);

    let mailboxes = jmap_call(
        &app,
        &token,
        "Mailbox/get",
        serde_json::json!({ "accountId": account_id }),
    )
    .await;
    let sent_id = mailboxes["list"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "sent")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    assert_eq!(list[0]["mailboxIds"][sent_id], true);

    // And it actually landed in the outbound queue, DKIM-signed and all.
    let metrics = queue_store.metrics().unwrap();
    assert_eq!(metrics.ready, 1);
}

#[tokio::test]
async fn a_draft_reply_joins_the_original_thread() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let queue_store = Arc::new(queue::QueueStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    let account = auth_store
        .provision(
            "alice",
            "example.test",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();

    delivery::deliver(
        &blobs,
        &metadata,
        &delivery::RecipientAccount {
            id: account.id,
            account_pub: account.account_pub,
            key_id: account.key_id,
        },
        &delivery::InboundEnvelope {
            mail_from: "carol@example.net".into(),
            rcpt_to: "alice@example.test".into(),
            remote_ip: "203.0.113.5".parse().unwrap(),
        },
        &delivery::AuthResults { spf: "pass".into(), dkim: "pass".into(), dmarc: "pass".into() },
        b"From: carol@example.net\r\nTo: alice@example.test\r\nSubject: Original\r\nMessage-ID: <orig@example.net>\r\n\r\nHi\r\n",
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
        queue_store,
        Arc::new(common::changes::ChangeNotifier::new()),
        None,
        25 * 1024 * 1024,
    );
    let app = build_router(state).layer(axum::extract::connect_info::MockConnectInfo(
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
    ));

    let (token, account_id) = unlock(
        &app,
        "alice",
        "example.test",
        "correct horse battery staple",
    )
    .await;

    let query_result = jmap_call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({ "accountId": account_id }),
    )
    .await;
    let original_id = query_result["ids"][0].as_str().unwrap().to_string();
    let original = jmap_call(
        &app,
        &token,
        "Email/get",
        serde_json::json!({ "accountId": account_id, "ids": [original_id] }),
    )
    .await;
    let original_thread = original["list"][0]["threadId"]
        .as_str()
        .unwrap()
        .to_string();

    let set_result = jmap_call(
        &app,
        &token,
        "Email/set",
        serde_json::json!({
            "accountId": account_id,
            "create": {
                "reply1": {
                    "to": [{ "email": "carol@example.net" }],
                    "subject": "Re: Original",
                    "bodyText": "reply text",
                    "inReplyTo": original_id
                }
            }
        }),
    )
    .await;
    let reply_thread = set_result["created"]["reply1"]["threadId"]
        .as_str()
        .unwrap();
    assert_eq!(reply_thread, original_thread);
}
