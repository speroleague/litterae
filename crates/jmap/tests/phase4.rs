//! Phase 4 acceptance: flag/move/delete round-trip, full-text search while
//! unlocked, and structured filters (mailbox/keyword) working before the
//! search index has ever been built ("cold index").

use std::sync::Arc;

use auth::AuthStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::config::Argon2Config;
use delivery::{deliver, AuthResults, InboundEnvelope, RecipientAccount};
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

fn deliver_message(
    blobs: &BlobStore,
    metadata: &MetadataStore,
    account: &RecipientAccount,
    raw: &[u8],
    received_at: i64,
) {
    deliver(
        blobs,
        metadata,
        account,
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
        received_at,
        None,
        delivery::ScanMetadata::default(),
    )
    .unwrap();
}

async fn call(
    app: &axum::Router,
    token: &str,
    method: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [[method, args, "c1"]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    body["methodResponses"][0][1].clone()
}

#[tokio::test]
async fn flag_move_delete_search_and_threads() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let account = auth_store
        .provision("alice", "example.com", b"password123", &cfg)
        .unwrap();
    let recipient_account = RecipientAccount {
        id: account.id,
        account_pub: account.account_pub,
        key_id: account.key_id,
    };

    deliver_message(
        &blobs,
        &metadata,
        &recipient_account,
        b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Pizza night\r\nMessage-ID: <1@example.net>\r\n\r\nWant to get pizza tonight?\r\n",
        1_700_000_000,
    );
    deliver_message(
        &blobs,
        &metadata,
        &recipient_account,
        b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Re: Pizza night\r\nMessage-ID: <2@example.net>\r\nIn-Reply-To: <1@example.net>\r\n\r\nSounds great, see you then.\r\n",
        1_700_000_100,
    );
    deliver_message(
        &blobs,
        &metadata,
        &recipient_account,
        b"From: sender@example.net\r\nTo: alice@example.com\r\nSubject: Invoice #42\r\nMessage-ID: <3@example.net>\r\n\r\nPlease find your invoice attached.\r\n",
        1_700_000_200,
    );

    let state = AppState::new(
        auth_store,
        blobs,
        metadata.clone(),
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

    // Unlock.
    let req = Request::builder()
        .method("POST")
        .uri("/auth/unlock")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"local_part": "alice", "domain": "example.com", "password": "password123"}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    // --- Structured filter (inMailbox) works before any search has run,
    // i.e. with a cold FTS index. ---
    let mailbox_result = call(
        &app,
        &token,
        "Mailbox/get",
        serde_json::json!({"accountId": account_id}),
    )
    .await;
    let mailboxes = mailbox_result["list"].as_array().unwrap();
    assert_eq!(mailboxes.len(), 6, "expected the 6 system mailboxes");
    let inbox = mailboxes.iter().find(|m| m["role"] == "inbox").unwrap();
    let archive = mailboxes.iter().find(|m| m["role"] == "archive").unwrap();
    let trash = mailboxes.iter().find(|m| m["role"] == "trash").unwrap();
    assert_eq!(inbox["totalEmails"], 3);

    let inbox_id = inbox["id"].as_str().unwrap().to_string();
    let query_result = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"inMailbox": inbox_id}}),
    )
    .await;
    let ids: Vec<String> = query_result["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        ids.len(),
        3,
        "cold-index structured filter should still see all 3 messages"
    );

    // --- Thread/get: the reply joined the original's thread. ---
    let get_result = call(
        &app,
        &token,
        "Email/get",
        serde_json::json!({"accountId": account_id, "ids": ids}),
    )
    .await;
    let emails = get_result["list"].as_array().unwrap();
    let pizza = emails
        .iter()
        .find(|e| e["subject"] == "Pizza night")
        .unwrap();
    let pizza_reply = emails
        .iter()
        .find(|e| e["subject"] == "Re: Pizza night")
        .unwrap();
    let invoice = emails
        .iter()
        .find(|e| e["subject"] == "Invoice #42")
        .unwrap();
    assert_eq!(pizza["threadId"], pizza_reply["threadId"]);
    assert_ne!(pizza["threadId"], invoice["threadId"]);

    let thread_result = call(
        &app,
        &token,
        "Thread/get",
        serde_json::json!({"accountId": account_id, "ids": [pizza["threadId"]]}),
    )
    .await;
    let thread_email_ids = thread_result["list"][0]["emailIds"].as_array().unwrap();
    assert_eq!(thread_email_ids.len(), 2);

    // --- Email/set: flag the invoice as $seen and $flagged. ---
    let invoice_id = invoice["id"].as_str().unwrap().to_string();
    let set_result = call(
        &app,
        &token,
        "Email/set",
        serde_json::json!({
            "accountId": account_id,
            "update": { invoice_id.clone(): { "keywords": {"$seen": true, "$flagged": true} } }
        }),
    )
    .await;
    assert!(
        set_result["updated"].get(&invoice_id).is_some(),
        "{set_result:?}"
    );

    let flagged_result = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"hasKeyword": "$flagged"}}),
    )
    .await;
    let flagged_ids = flagged_result["ids"].as_array().unwrap();
    assert_eq!(flagged_ids.len(), 1);
    assert_eq!(flagged_ids[0], invoice_id);

    // --- Email/set: move the pizza thread's original message to Archive. ---
    let pizza_id = pizza["id"].as_str().unwrap().to_string();
    let archive_id = archive["id"].as_str().unwrap().to_string();
    call(
        &app,
        &token,
        "Email/set",
        serde_json::json!({
            "accountId": account_id,
            "update": { pizza_id.clone(): { "mailboxIds": { archive_id.clone(): true } } }
        }),
    )
    .await;

    let inbox_after_move = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"inMailbox": inbox["id"].clone()}}),
    )
    .await;
    assert_eq!(inbox_after_move["ids"].as_array().unwrap().len(), 2);
    let archive_after_move = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"inMailbox": archive_id}}),
    )
    .await;
    assert_eq!(archive_after_move["ids"].as_array().unwrap().len(), 1);

    // --- Email/set: destroy (soft-delete) the reply -> lands in Trash, not gone. ---
    let reply_id = pizza_reply["id"].as_str().unwrap().to_string();
    let destroy_result = call(
        &app,
        &token,
        "Email/set",
        serde_json::json!({"accountId": account_id, "destroy": [reply_id.clone()]}),
    )
    .await;
    assert!(destroy_result["destroyed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == &reply_id));
    let trash_id = trash["id"].as_str().unwrap().to_string();
    let trash_contents = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"inMailbox": trash_id}}),
    )
    .await;
    assert_eq!(trash_contents["ids"].as_array().unwrap().len(), 1);

    // Destroying it again (now that it's already in Trash) hard-deletes it.
    let destroy_again = call(
        &app,
        &token,
        "Email/set",
        serde_json::json!({"accountId": account_id, "destroy": [reply_id.clone()]}),
    )
    .await;
    assert!(destroy_again["destroyed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == &reply_id));
    let get_after_hard_delete = call(
        &app,
        &token,
        "Email/get",
        serde_json::json!({"accountId": account_id, "ids": [reply_id.clone()]}),
    )
    .await;
    assert!(get_after_hard_delete["notFound"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == &reply_id));

    // --- Full-text search (builds the in-RAM index on first use). ---
    let search_result = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"text": "invoice"}}),
    )
    .await;
    let search_ids = search_result["ids"].as_array().unwrap();
    assert_eq!(search_ids.len(), 1);
    assert_eq!(search_ids[0], invoice_id);

    let no_hits = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"text": "nonexistentxyz"}}),
    )
    .await;
    assert!(no_hits["ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unread_filter_spans_every_mailbox_and_pagination_reports_a_stable_total() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();

    let account = auth_store
        .provision("alice", "example.com", b"password123", &cfg)
        .unwrap();
    let recipient_account = RecipientAccount {
        id: account.id,
        account_pub: account.account_pub,
        key_id: account.key_id,
    };

    // 5 messages delivered to Inbox -- none marked $seen yet.
    for i in 0..5 {
        deliver_message(
            &blobs,
            &metadata,
            &recipient_account,
            format!(
                "From: sender@example.net\r\nTo: alice@example.com\r\nSubject: msg {i}\r\nMessage-ID: <{i}@example.net>\r\n\r\nbody\r\n"
            )
            .as_bytes(),
            1_700_000_000 + i,
        );
    }

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
            serde_json::json!({"local_part": "alice", "domain": "example.com", "password": "password123"}).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let body = json_body(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let account_id = body["accountId"].as_str().unwrap().to_string();

    // --- Unread spans the whole account, all 5 unseen messages. ---
    let result = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"notHasKeyword": "$seen"}}),
    )
    .await;
    assert_eq!(result["ids"].as_array().unwrap().len(), 5);
    assert_eq!(result["total"], 5);

    // --- Mark one message seen; unread count drops accordingly. ---
    let first_id = result["ids"][0].as_str().unwrap().to_string();
    call(
        &app,
        &token,
        "Email/set",
        serde_json::json!({"accountId": account_id, "update": {first_id: {"keywords/$seen": true}}}),
    )
    .await;

    let result = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "filter": {"notHasKeyword": "$seen"}}),
    )
    .await;
    assert_eq!(result["ids"].as_array().unwrap().len(), 4);
    assert_eq!(result["total"], 4);

    // --- Pagination: total reflects the full match count regardless of
    // limit/position, and a limit smaller than the total actually caps
    // the returned ids -- this is the "does the list silently cut off"
    // behavior the admin UI needs `total` for. ---
    let page = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "limit": 2}),
    )
    .await;
    assert_eq!(page["ids"].as_array().unwrap().len(), 2);
    assert_eq!(page["total"], 5);

    let next_page = call(
        &app,
        &token,
        "Email/query",
        serde_json::json!({"accountId": account_id, "position": 2, "limit": 2}),
    )
    .await;
    assert_eq!(next_page["ids"].as_array().unwrap().len(), 2);
    assert_eq!(next_page["total"], 5);
    assert_ne!(page["ids"], next_page["ids"]);
}
