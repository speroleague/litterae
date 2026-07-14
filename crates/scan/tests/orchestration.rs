//! `Scanner`-level behavior: not-configured is a no-op, an unreachable
//! backend fails open with a warning, and ClamAV's verdict overrides
//! rspamd's regardless of which one answers first.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use scan::clamav::ClamavClient;
use scan::rspamd::RspamdClient;
use scan::{ScanRequest, Scanner, Verdict};

fn request(raw: &'static [u8]) -> ScanRequest<'static> {
    ScanRequest {
        remote_ip: "203.0.113.5".parse().unwrap(),
        helo: "mail.sender.example.net",
        mail_from: "sender@example.net",
        rcpt_to: &[],
        raw_message: raw,
    }
}

async fn fake_rspamd(action: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = stream.read(&mut buf).await.unwrap();
        let body = format!(r#"{{"score":20.0,"required_score":15.0,"action":"{action}"}}"#);
        let response = format!(
            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    addr.to_string()
}

async fn fake_clamav(reply: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut command = [0u8; 10];
        stream.read_exact(&mut command).await.unwrap();
        loop {
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await.unwrap();
            if u32::from_be_bytes(len_bytes) == 0 {
                break;
            }
            let mut chunk = vec![0u8; u32::from_be_bytes(len_bytes) as usize];
            stream.read_exact(&mut chunk).await.unwrap();
        }
        stream.write_all(reply.as_bytes()).await.unwrap();
    });
    addr.to_string()
}

#[tokio::test]
async fn not_configured_skips_entirely_with_no_network_calls() {
    let scanner = Scanner::new(None, None).with_timeout(Duration::from_millis(200));
    let start = Instant::now();
    let result = scanner.scan(&request(b"hello")).await;
    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.warnings.is_empty());
    assert!(
        start.elapsed() < Duration::from_millis(50),
        "should never touch the network"
    );
}

#[tokio::test]
async fn unreachable_rspamd_fails_open_with_a_warning() {
    let rspamd = RspamdClient::new("127.0.0.1:0");
    let scanner = Scanner::new(Some(rspamd), None).with_timeout(Duration::from_millis(200));
    let result = scanner.scan(&request(b"hello")).await;
    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.warnings.iter().any(|w| w.contains("rspamd")));
}

#[tokio::test]
async fn unreachable_clamav_fails_open_with_a_warning() {
    let clamav = ClamavClient::new("127.0.0.1:0");
    let scanner = Scanner::new(None, Some(clamav)).with_timeout(Duration::from_millis(200));
    let result = scanner.scan(&request(b"hello")).await;
    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.warnings.iter().any(|w| w.contains("clamav")));
}

#[tokio::test]
async fn clamav_found_overrides_rspamd_no_action() {
    let rspamd_addr = fake_rspamd("no action").await;
    let clamav_addr = fake_clamav("stream: Eicar-Test-Signature FOUND\0").await;
    let scanner = Scanner::new(
        Some(RspamdClient::new(&rspamd_addr)),
        Some(ClamavClient::new(&clamav_addr)),
    )
    .with_timeout(Duration::from_secs(2));

    let result = scanner.scan(&request(b"hello")).await;
    assert!(matches!(result.verdict, Verdict::Reject { .. }));
}

#[tokio::test]
async fn rspamd_reject_wins_regardless_of_clamav_clean() {
    let rspamd_addr = fake_rspamd("reject").await;
    let clamav_addr = fake_clamav("stream: OK\0").await;
    let scanner = Scanner::new(
        Some(RspamdClient::new(&rspamd_addr)),
        Some(ClamavClient::new(&clamav_addr)),
    )
    .with_timeout(Duration::from_secs(2));

    let result = scanner.scan(&request(b"hello")).await;
    assert!(matches!(result.verdict, Verdict::Reject { .. }));
}

#[tokio::test]
async fn add_header_routes_to_spam() {
    let rspamd_addr = fake_rspamd("add header").await;
    let scanner = Scanner::new(Some(RspamdClient::new(&rspamd_addr)), None)
        .with_timeout(Duration::from_secs(2));
    let result = scanner.scan(&request(b"hello")).await;
    assert!(matches!(result.verdict, Verdict::Spam { .. }));
}

#[tokio::test]
async fn soft_reject_routes_to_defer() {
    let rspamd_addr = fake_rspamd("soft reject").await;
    let scanner = Scanner::new(Some(RspamdClient::new(&rspamd_addr)), None)
        .with_timeout(Duration::from_secs(2));
    let result = scanner.scan(&request(b"hello")).await;
    assert!(matches!(result.verdict, Verdict::Defer { .. }));
}

#[tokio::test]
async fn both_scanners_run_concurrently_not_sequentially() {
    // Each fake server sleeps briefly before answering; if the two calls
    // were sequential the total would be close to 2x the per-call delay.
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr1 = listener1.local_addr().unwrap();
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener1.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = stream.read(&mut buf).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let body = r#"{"score":1.0,"required_score":15.0,"action":"no action"}"#;
        let response = format!(
            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    tokio::spawn(async move {
        let (mut stream, _) = listener2.accept().await.unwrap();
        let mut command = [0u8; 10];
        stream.read_exact(&mut command).await.unwrap();
        loop {
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await.unwrap();
            if u32::from_be_bytes(len_bytes) == 0 {
                break;
            }
            let mut chunk = vec![0u8; u32::from_be_bytes(len_bytes) as usize];
            stream.read_exact(&mut chunk).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        stream.write_all(b"stream: OK\0").await.unwrap();
    });

    let scanner = Scanner::new(
        Some(RspamdClient::new(&addr1.to_string())),
        Some(ClamavClient::new(&addr2.to_string())),
    )
    .with_timeout(Duration::from_secs(2));

    let start = Instant::now();
    let result = scanner.scan(&request(b"hello")).await;
    let elapsed = start.elapsed();

    assert_eq!(result.verdict, Verdict::Clean);
    assert!(
        elapsed < Duration::from_millis(280),
        "expected concurrent ~150ms, got {elapsed:?}"
    );
}
