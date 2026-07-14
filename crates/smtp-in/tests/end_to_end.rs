//! End-to-end exercise of Phase 1's acceptance criteria (spec §11): a real
//! message sent over a real TCP/SMTP dialog lands, decrypts on unlock, and
//! has its DKIM/SPF/DMARC verdicts stored. This drives the actual listener
//! code (`session::handle_connection`) over a real socket rather than
//! calling internal functions directly.

use std::sync::Arc;

use admin::AdminStore;
use auth::AuthStore;
use common::config::Argon2Config;
use mail_auth::MessageAuthenticator;
use store::{BlobStore, MetadataStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use smtp_in::session::{handle_connection, Deps};

fn fast_argon2() -> Argon2Config {
    Argon2Config {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn test_audit_store() -> Arc<audit::AuditStore> {
    let store = audit::AuditStore::open_in_memory().unwrap();
    store.bootstrap_keys(&[7u8; 32]).unwrap();
    Arc::new(store)
}

async fn read_reply<S: tokio::io::AsyncRead + Unpin>(reader: &mut BufReader<S>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line
}

async fn send_line<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
    line: &str,
) {
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
}

#[tokio::test]
async fn real_message_lands_decrypts_on_unlock_dkim_stored() {
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

    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());
    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 25 * 1024 * 1024,
        auth_store: auth_store.clone(),
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs: blobs.clone(),
        metadata: metadata.clone(),
        authenticator,
        tls_acceptor: None,
        scanner: Arc::new(scan::Scanner::new(None, None)),
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let deps = deps.clone();
            tokio::spawn(handle_connection(stream, peer.ip(), deps));
        }
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = BufReader::new(stream);

    let greeting = read_reply(&mut conn).await;
    assert!(
        greeting.starts_with("220"),
        "unexpected greeting: {greeting}"
    );

    send_line(&mut conn, "EHLO mail.sender.example.net").await;
    // Drain the multiline EHLO reply (last line has a space after the code).
    loop {
        let line = read_reply(&mut conn).await;
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }

    send_line(&mut conn, "MAIL FROM:<sender@sender.example.net>").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("250"), "MAIL FROM rejected: {reply}");

    send_line(&mut conn, "RCPT TO:<alice@example.com>").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("250"), "RCPT TO rejected: {reply}");

    send_line(&mut conn, "DATA").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("354"), "DATA not accepted: {reply}");

    let body = concat!(
        "From: sender@sender.example.net\r\n",
        "To: alice@example.com\r\n",
        "Subject: Hello from Phase 1\r\n",
        "\r\n",
        "This is a real end-to-end test message.\r\n",
        ".\r\n",
    );
    conn.write_all(body.as_bytes()).await.unwrap();
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("250"), "message not accepted: {reply}");

    send_line(&mut conn, "QUIT").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("221"), "QUIT not acknowledged: {reply}");

    // --- The message landed: verify metadata was recorded, including the
    // DKIM verdict (Phase 1 acceptance criterion). ---
    let messages = metadata.messages_for_account(account.id).unwrap();
    assert_eq!(messages.len(), 1, "expected exactly one delivered message");
    let stored = &messages[0];
    assert_eq!(stored.mail_from, "sender@sender.example.net");
    assert_eq!(stored.rcpt_to, "alice@example.com");
    // No DKIM-Signature header was present, so mail-auth correctly reports
    // "none" rather than fabricating a pass/fail.
    assert_eq!(stored.dkim_result, "none");
    assert!(!stored.spf_result.is_empty());

    // --- Decrypts on unlock: recover the account key with the real
    // password and confirm the sealed blob decrypts to the original bytes. ---
    let unlocked = auth_store
        .unlock(&account, b"correct horse battery staple", &cfg)
        .unwrap();
    let opened = delivery::open_message(&blobs, stored, &unlocked.account_priv).unwrap();
    let opened_text = String::from_utf8(opened).unwrap();
    assert!(opened_text.contains("Subject: Hello from Phase 1"));
    assert!(opened_text.contains("This is a real end-to-end test message."));

    // Wrong password must not recover a usable key.
    assert!(auth_store
        .unlock(&account, b"wrong password", &cfg)
        .is_err());
}

#[tokio::test]
async fn catch_all_delivers_to_configured_mailbox() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let admin_store = Arc::new(AdminStore::open_in_memory().unwrap());

    let cfg = fast_argon2();
    let account = auth_store
        .provision(
            "catchall",
            "example.com",
            b"correct horse battery staple",
            &cfg,
        )
        .unwrap();
    admin_store
        .create_domain("example.com", Some("catchall"))
        .unwrap();

    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());
    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 25 * 1024 * 1024,
        auth_store,
        admin_store,
        blobs,
        metadata: metadata.clone(),
        authenticator,
        tls_acceptor: None,
        scanner: Arc::new(scan::Scanner::new(None, None)),
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_connection(stream, peer.ip(), deps).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = BufReader::new(stream);
    let _ = read_reply(&mut conn).await;

    send_line(&mut conn, "EHLO mail.sender.example.net").await;
    loop {
        let line = read_reply(&mut conn).await;
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }

    send_line(&mut conn, "MAIL FROM:<sender@sender.example.net>").await;
    let _ = read_reply(&mut conn).await;

    // No account is provisioned for "whatever@example.com" -- only the
    // domain's catch-all ("catchall@example.com") should receive it.
    send_line(&mut conn, "RCPT TO:<whatever@example.com>").await;
    let reply = read_reply(&mut conn).await;
    assert!(
        reply.starts_with("250"),
        "catch-all recipient should be accepted: {reply}"
    );

    send_line(&mut conn, "DATA").await;
    let _ = read_reply(&mut conn).await;
    let body = concat!(
        "From: sender@sender.example.net\r\n",
        "To: whatever@example.com\r\n",
        "Subject: Caught by the catch-all\r\n",
        "\r\n",
        "This should land in the catch-all mailbox.\r\n",
        ".\r\n",
    );
    conn.write_all(body.as_bytes()).await.unwrap();
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("250"), "message not accepted: {reply}");

    let messages = metadata.messages_for_account(account.id).unwrap();
    assert_eq!(
        messages.len(),
        1,
        "expected the message in the catch-all account"
    );
    assert_eq!(messages[0].rcpt_to, "whatever@example.com");
}

#[tokio::test]
async fn unknown_recipient_is_rejected_no_open_relay() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 1024,
        auth_store,
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs,
        metadata,
        authenticator,
        tls_acceptor: None,
        scanner: Arc::new(scan::Scanner::new(None, None)),
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_connection(stream, peer.ip(), deps).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = BufReader::new(stream);
    let _ = read_reply(&mut conn).await;

    send_line(&mut conn, "EHLO mail.sender.example.net").await;
    loop {
        let line = read_reply(&mut conn).await;
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }

    send_line(&mut conn, "MAIL FROM:<sender@sender.example.net>").await;
    let _ = read_reply(&mut conn).await;

    send_line(&mut conn, "RCPT TO:<nobody@example.com>").await;
    let reply = read_reply(&mut conn).await;
    assert!(
        reply.starts_with("550"),
        "unknown recipient must be rejected, not relayed: {reply}"
    );
}

#[tokio::test]
async fn oversized_message_is_rejected_early() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    auth_store
        .provision("bob", "example.com", b"pw", &cfg)
        .unwrap();
    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 64, // tiny, to trigger the limit deterministically
        auth_store,
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs,
        metadata,
        authenticator,
        tls_acceptor: None,
        scanner: Arc::new(scan::Scanner::new(None, None)),
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_connection(stream, peer.ip(), deps).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = BufReader::new(stream);
    let _ = read_reply(&mut conn).await;
    send_line(&mut conn, "EHLO mail.sender.example.net").await;
    loop {
        let line = read_reply(&mut conn).await;
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    send_line(&mut conn, "MAIL FROM:<sender@sender.example.net>").await;
    let _ = read_reply(&mut conn).await;
    send_line(&mut conn, "RCPT TO:<bob@example.com>").await;
    let _ = read_reply(&mut conn).await;
    send_line(&mut conn, "DATA").await;
    let _ = read_reply(&mut conn).await;

    let big_body = "X".repeat(1000);
    conn.write_all(big_body.as_bytes()).await.unwrap();
    conn.write_all(b"\r\n.\r\n").await.unwrap();
    let reply = read_reply(&mut conn).await;
    assert!(
        reply.starts_with("552"),
        "oversized message not rejected: {reply}"
    );
}

#[tokio::test]
async fn starttls_upgrades_and_delivers_over_encrypted_channel() {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let tmp = tempfile::tempdir().unwrap();
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["mx.example.com".to_string()]).unwrap();
    let cert_path = tmp.path().join("cert.pem");
    let key_path = tmp.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();

    let smtp_config = common::config::SmtpConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        max_message_size: 1024 * 1024,
        tls_cert_path: Some(cert_path),
        tls_key_path: Some(key_path),
    };
    let tls_acceptor = smtp_in::tls::load_acceptor(&smtp_config)
        .unwrap()
        .expect("acceptor should be built when cert/key are configured");

    let blob_dir = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(blob_dir.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    let account = auth_store
        .provision("carol", "example.com", b"pw", &cfg)
        .unwrap();
    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: smtp_config.max_message_size,
        auth_store,
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs,
        metadata: metadata.clone(),
        authenticator,
        tls_acceptor: Some(tls_acceptor),
        scanner: Arc::new(scan::Scanner::new(None, None)),
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_connection(stream, peer.ip(), deps).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = BufReader::new(stream);
    let _ = read_reply(&mut conn).await;

    send_line(&mut conn, "EHLO mail.sender.example.net").await;
    let mut saw_starttls = false;
    loop {
        let line = read_reply(&mut conn).await;
        if line.to_ascii_uppercase().contains("STARTTLS") {
            saw_starttls = true;
        }
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    assert!(
        saw_starttls,
        "STARTTLS must be advertised when a cert is configured"
    );

    send_line(&mut conn, "STARTTLS").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("220"), "STARTTLS not accepted: {reply}");

    // Upgrade the client side to TLS, trusting the self-signed cert we just
    // generated.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("mx.example.com").unwrap();
    let tcp = conn.into_inner();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    let mut tls_conn = BufReader::new(tls_stream);

    // RFC 3207: envelope state resets, EHLO is required again.
    send_line(&mut tls_conn, "EHLO mail.sender.example.net").await;
    loop {
        let line = read_reply(&mut tls_conn).await;
        assert!(
            !line.to_ascii_uppercase().contains("STARTTLS"),
            "must not offer STARTTLS again inside an already-encrypted session"
        );
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }

    send_line(&mut tls_conn, "MAIL FROM:<sender@sender.example.net>").await;
    let reply = read_reply(&mut tls_conn).await;
    assert!(
        reply.starts_with("250"),
        "MAIL FROM over TLS rejected: {reply}"
    );

    send_line(&mut tls_conn, "RCPT TO:<carol@example.com>").await;
    let reply = read_reply(&mut tls_conn).await;
    assert!(
        reply.starts_with("250"),
        "RCPT TO over TLS rejected: {reply}"
    );

    send_line(&mut tls_conn, "DATA").await;
    let _ = read_reply(&mut tls_conn).await;
    let body = "From: sender@sender.example.net\r\nTo: carol@example.com\r\nSubject: over TLS\r\n\r\nEncrypted in transit.\r\n.\r\n";
    tls_conn.write_all(body.as_bytes()).await.unwrap();
    let reply = read_reply(&mut tls_conn).await;
    assert!(
        reply.starts_with("250"),
        "message over TLS not accepted: {reply}"
    );

    let messages = metadata.messages_for_account(account.id).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].mail_from, "sender@sender.example.net");
}

/// Spawns a fake rspamd `checkv2` endpoint that always answers with the
/// given `action`, and returns its address string (suitable for
/// `scan::rspamd::RspamdClient::new`).
async fn fake_rspamd(action: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 65536];
                let _ = stream.read(&mut buf).await;
                let body = format!(r#"{{"score":20.0,"required_score":15.0,"action":"{action}"}}"#);
                let response = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr.to_string()
}

/// Spawns a fake clamd that always answers `stream: <reply>\0` after
/// draining one INSTREAM payload.
async fn fake_clamd(reply: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut command = [0u8; 10];
                if stream.read_exact(&mut command).await.is_err() {
                    return;
                }
                loop {
                    let mut len_bytes = [0u8; 4];
                    if stream.read_exact(&mut len_bytes).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len_bytes) as usize;
                    if len == 0 {
                        break;
                    }
                    let mut chunk = vec![0u8; len];
                    if stream.read_exact(&mut chunk).await.is_err() {
                        return;
                    }
                }
                let _ = stream
                    .write_all(format!("stream: {reply}\0").as_bytes())
                    .await;
            });
        }
    });
    addr.to_string()
}

async fn deliver_one_message(deps: Arc<Deps>, rcpt: &str, subject: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_connection(stream, peer.ip(), deps).await;
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut conn = BufReader::new(stream);
    let _ = read_reply(&mut conn).await;
    send_line(&mut conn, "EHLO mail.sender.example.net").await;
    loop {
        let line = read_reply(&mut conn).await;
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    send_line(&mut conn, "MAIL FROM:<sender@sender.example.net>").await;
    let _ = read_reply(&mut conn).await;
    send_line(&mut conn, &format!("RCPT TO:<{rcpt}>")).await;
    let _ = read_reply(&mut conn).await;
    send_line(&mut conn, "DATA").await;
    let _ = read_reply(&mut conn).await;
    let body = format!(
        "From: sender@sender.example.net\r\nTo: {rcpt}\r\nSubject: {subject}\r\n\r\nbody\r\n.\r\n"
    );
    conn.write_all(body.as_bytes()).await.unwrap();
    read_reply(&mut conn).await
}

#[tokio::test]
async fn rspamd_add_header_routes_message_to_junk() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    let account = auth_store
        .provision("alice", "example.com", b"pw", &cfg)
        .unwrap();
    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());

    let rspamd_addr = fake_rspamd("add header").await;
    let scanner = Arc::new(scan::Scanner::new(
        Some(scan::rspamd::RspamdClient::new(&rspamd_addr)),
        None,
    ));

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 1024 * 1024,
        auth_store,
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs,
        metadata: metadata.clone(),
        authenticator,
        tls_acceptor: None,
        scanner,
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let reply = deliver_one_message(deps, "alice@example.com", "spammy subject").await;
    assert!(
        reply.starts_with("250"),
        "spam-flagged message should still be accepted: {reply}"
    );

    let messages = metadata.messages_for_account(account.id).unwrap();
    assert_eq!(messages.len(), 1);
    let junk = metadata
        .get_mailbox_by_role(account.id, store::ROLE_JUNK)
        .unwrap()
        .unwrap();
    assert_eq!(messages[0].mailbox_id, junk.id);
    assert!(messages[0].keywords.contains(store::KEYWORD_JUNK));
}

#[tokio::test]
async fn rspamd_reject_gets_5xx_and_no_delivery() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    let account = auth_store
        .provision("alice", "example.com", b"pw", &cfg)
        .unwrap();
    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());

    let rspamd_addr = fake_rspamd("reject").await;
    let scanner = Arc::new(scan::Scanner::new(
        Some(scan::rspamd::RspamdClient::new(&rspamd_addr)),
        None,
    ));

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 1024 * 1024,
        auth_store,
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs,
        metadata: metadata.clone(),
        authenticator,
        tls_acceptor: None,
        scanner,
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let reply = deliver_one_message(deps, "alice@example.com", "spam").await;
    assert!(
        reply.starts_with("550"),
        "rejected message should get a 5xx: {reply}"
    );
    assert!(metadata
        .messages_for_account(account.id)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn clamav_found_gets_5xx_and_no_delivery() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    let account = auth_store
        .provision("alice", "example.com", b"pw", &cfg)
        .unwrap();
    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());

    let clamd_addr = fake_clamd("Eicar-Test-Signature FOUND").await;
    let scanner = Arc::new(scan::Scanner::new(
        None,
        Some(scan::clamav::ClamavClient::new(&clamd_addr)),
    ));

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 1024 * 1024,
        auth_store,
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs,
        metadata: metadata.clone(),
        authenticator,
        tls_acceptor: None,
        scanner,
        audit: test_audit_store(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let reply = deliver_one_message(deps, "alice@example.com", "eicar").await;
    assert!(
        reply.starts_with("550"),
        "malware should get a 5xx: {reply}"
    );
    assert!(metadata
        .messages_for_account(account.id)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn unreachable_scanner_fails_open_to_inbox() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let metadata = Arc::new(MetadataStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    let account = auth_store
        .provision("alice", "example.com", b"pw", &cfg)
        .unwrap();
    let authenticator = Arc::new(MessageAuthenticator::new_system_conf().unwrap());

    // Port 0 never accepts connections: guaranteed-unreachable endpoint.
    let scanner = Arc::new(
        scan::Scanner::new(Some(scan::rspamd::RspamdClient::new("127.0.0.1:0")), None)
            .with_timeout(std::time::Duration::from_millis(200)),
    );
    let audit = test_audit_store();

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 1024 * 1024,
        auth_store,
        admin_store: Arc::new(AdminStore::open_in_memory().unwrap()),
        blobs,
        metadata: metadata.clone(),
        authenticator,
        tls_acceptor: None,
        scanner,
        audit: audit.clone(),
        notifier: Arc::new(common::changes::ChangeNotifier::new()),
    });

    let reply = deliver_one_message(deps, "alice@example.com", "normal mail").await;
    assert!(
        reply.starts_with("250"),
        "unreachable scanner must fail open: {reply}"
    );

    let messages = metadata.messages_for_account(account.id).unwrap();
    assert_eq!(messages.len(), 1);
    let inbox = metadata
        .get_mailbox_by_role(account.id, store::ROLE_INBOX)
        .unwrap()
        .unwrap();
    assert_eq!(
        messages[0].mailbox_id, inbox.id,
        "must land in Inbox, not Junk"
    );

    let entries = audit.read_recent(&[7u8; 32], 10).unwrap();
    assert!(entries.iter().any(|e| e.action == "smtp.scan_unreachable"));
}
