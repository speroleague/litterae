//! Drives `RspamdClient::check` against a fake in-process listener
//! speaking the wire-level shape of rspamd's `checkv2` protocol,
//! confirming request framing and response parsing over a real socket.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use scan::rspamd::{CheckRequest, RspamdAction, RspamdClient};

#[tokio::test]
async fn sends_expected_headers_and_parses_the_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();

        assert!(request.starts_with("POST /checkv2 HTTP/1.0\r\n"));
        assert!(request.contains("IP: 203.0.113.5\r\n"));
        assert!(request.contains("Helo: mail.sender.example.net\r\n"));
        assert!(request.contains("From: sender@example.net\r\n"));
        assert!(request.contains("Rcpt: alice@example.com\r\n"));
        assert!(request.contains("Rcpt: bob@example.com\r\n"));
        assert!(request.contains("Content-Length: 11\r\n"));
        assert!(request.ends_with("hello world"));

        let body = br#"{"score":2.0,"required_score":15.0,"action":"no action"}"#;
        let response = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let client = RspamdClient::new(&addr.to_string());
    let verdict = client
        .check(&CheckRequest {
            remote_ip: "203.0.113.5".parse().unwrap(),
            helo: "mail.sender.example.net",
            mail_from: "sender@example.net",
            rcpt_to: &["alice@example.com".to_string(), "bob@example.com".to_string()],
            raw_message: b"hello world",
        })
        .await
        .unwrap();

    assert_eq!(verdict.action, RspamdAction::NoAction);
    assert_eq!(verdict.score, 2.0);
    assert_eq!(verdict.required_score, 15.0);

    server.await.unwrap();
}

#[tokio::test]
async fn unreachable_endpoint_is_an_error() {
    // Port 0 never accepts connections; connecting to it fails immediately.
    let client = RspamdClient::new("127.0.0.1:0");
    let result = client
        .check(&CheckRequest {
            remote_ip: "203.0.113.5".parse().unwrap(),
            helo: "",
            mail_from: "",
            rcpt_to: &[],
            raw_message: b"x",
        })
        .await;
    assert!(result.is_err());
}
