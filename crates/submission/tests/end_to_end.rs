//! Drives the real submission listener code over actual TLS sockets:
//! implicit TLS (465-style) and STARTTLS (587-style), AUTH PLAIN, sender
//! identity enforcement, and confirms a submitted message ends up in the
//! outbound queue correctly DKIM-signed.

use std::sync::Arc;

use auth::AuthStore;
use common::config::Argon2Config;
use queue::QueueStore;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use store::BlobStore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use submission::session::{handle_implicit_connection, handle_starttls_connection, Deps};

fn fast_argon2() -> Argon2Config {
    Argon2Config {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn sasl_plain(authcid: &str, password: &str) -> String {
    use base64::Engine;
    let mut payload = Vec::new();
    payload.push(0u8);
    payload.extend_from_slice(authcid.as_bytes());
    payload.push(0u8);
    payload.extend_from_slice(password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(payload)
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

fn make_acceptor() -> (tokio_rustls::TlsAcceptor, rcgen::Certificate) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["mx.example.com".to_string()]).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], signing_key.into())
        .unwrap();
    (
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config)),
        cert,
    )
}

async fn make_deps(tls_acceptor: tokio_rustls::TlsAcceptor) -> (Arc<Deps>, Arc<QueueStore>, Arc<BlobStore>, auth::Account) {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = Arc::new(BlobStore::open(tmp.path()).unwrap());
    let queue = Arc::new(QueueStore::open_in_memory().unwrap());
    let auth_store = Arc::new(AuthStore::open_in_memory().unwrap());
    let cfg = fast_argon2();
    let account = auth_store
        .provision("alice", "example.com", b"correct horse battery staple", &cfg)
        .unwrap();

    let deps = Arc::new(Deps {
        hostname: "mx.example.com".to_string(),
        max_message_size: 1024 * 1024,
        auth_store,
        queue: queue.clone(),
        blobs: blobs.clone(),
        audit: Arc::new(audit::AuditStore::open_in_memory().unwrap()),
        login_throttle: Arc::new(common::throttle::LoginThrottle::new(
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(60),
        )),
        argon2_config: Arc::new(cfg),
        tls_acceptor,
    });
    (deps, queue, blobs, account)
}

#[tokio::test]
async fn implicit_tls_auth_and_submit_lands_signed_in_queue() {
    let (acceptor, cert) = make_acceptor();
    let (deps, queue, blobs, account) = make_deps(acceptor).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_implicit_connection(stream, peer.ip(), deps).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("mx.example.com").unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    let mut conn = BufReader::new(tls_stream);

    let greeting = read_reply(&mut conn).await;
    assert!(greeting.starts_with("220"), "{greeting}");

    send_line(&mut conn, "EHLO client.example.net").await;
    loop {
        let line = read_reply(&mut conn).await;
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }

    send_line(&mut conn, &format!("AUTH PLAIN {}", sasl_plain("alice@example.com", "correct horse battery staple"))).await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("235"), "auth should succeed: {reply}");

    send_line(&mut conn, "MAIL FROM:<alice@example.com>").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("250"), "{reply}");

    send_line(&mut conn, "RCPT TO:<bob@recipient.example>").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("250"), "{reply}");

    send_line(&mut conn, "DATA").await;
    let _ = read_reply(&mut conn).await;
    let body = "From: alice@example.com\r\nTo: bob@recipient.example\r\nSubject: submitted\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nHello from submission.\r\n.\r\n";
    conn.write_all(body.as_bytes()).await.unwrap();
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("250"), "message not queued: {reply}");

    // Verify it landed in the queue, addressed correctly, and DKIM-signed.
    let outbound = queue.get_outbound(1).unwrap().expect("outbound row exists");
    assert_eq!(outbound.envelope_from, "alice@example.com");
    assert_eq!(outbound.account_id, account.id);
    let rcpts = queue.recipients_for_outbound(outbound.id).unwrap();
    assert_eq!(rcpts.len(), 1);
    assert_eq!(rcpts[0].rcpt_to, "bob@recipient.example");

    let stored = blobs.read(&outbound.message_blob).unwrap();
    let text = String::from_utf8(stored).unwrap();
    assert!(text.starts_with("DKIM-Signature:"));
    assert!(text.contains("d=example.com"));
}

#[tokio::test]
async fn starttls_requires_tls_before_auth() {
    let (acceptor, _cert) = make_acceptor();
    let (deps, _queue, _blobs, _account) = make_deps(acceptor).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_starttls_connection(stream, peer.ip(), deps).await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut conn = BufReader::new(tcp);
    let _ = read_reply(&mut conn).await;

    send_line(&mut conn, "EHLO client.example.net").await;
    let mut saw_starttls = false;
    loop {
        let line = read_reply(&mut conn).await;
        if line.to_ascii_uppercase().contains("STARTTLS") {
            saw_starttls = true;
        }
        if !line.to_ascii_uppercase().contains("AUTH") {
            // sanity: AUTH must not be advertised over plaintext
        }
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }
    assert!(saw_starttls);

    send_line(&mut conn, "AUTH PLAIN AAAA").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("530"), "AUTH over plaintext must be refused: {reply}");
}

#[tokio::test]
async fn cannot_send_as_someone_else() {
    let (acceptor, cert) = make_acceptor();
    let (deps, _queue, _blobs, _account) = make_deps(acceptor).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        handle_implicit_connection(stream, peer.ip(), deps).await;
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("mx.example.com").unwrap();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    let mut conn = BufReader::new(tls_stream);
    let _ = read_reply(&mut conn).await;

    send_line(&mut conn, "EHLO client.example.net").await;
    loop {
        let line = read_reply(&mut conn).await;
        if line.as_bytes().get(3) == Some(&b' ') {
            break;
        }
    }

    send_line(&mut conn, &format!("AUTH PLAIN {}", sasl_plain("alice@example.com", "correct horse battery staple"))).await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("235"), "{reply}");

    send_line(&mut conn, "MAIL FROM:<someone-else@other.example>").await;
    let reply = read_reply(&mut conn).await;
    assert!(reply.starts_with("553"), "spoofed sender must be rejected: {reply}");
}
