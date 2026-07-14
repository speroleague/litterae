//! Drives `ClamavClient::scan` against a fake in-process listener
//! speaking clamd's INSTREAM protocol, confirming chunk framing and
//! reply parsing over a real socket.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use scan::clamav::{ClamavClient, ClamavVerdict};

async fn read_instream_payload(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut command = [0u8; 10];
    stream.read_exact(&mut command).await.unwrap();
    assert_eq!(&command, b"zINSTREAM\0");

    let mut payload = Vec::new();
    loop {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.unwrap();
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 {
            break;
        }
        let mut chunk = vec![0u8; len];
        stream.read_exact(&mut chunk).await.unwrap();
        payload.extend_from_slice(&chunk);
    }
    payload
}

#[tokio::test]
async fn reassembles_chunked_payload_and_parses_clean_reply() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let original = b"a perfectly ordinary test message".to_vec();
    let expected = original.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let payload = read_instream_payload(&mut stream).await;
        assert_eq!(payload, expected);
        stream.write_all(b"stream: OK\0").await.unwrap();
    });

    let client = ClamavClient::new(&addr.to_string());
    let verdict = client.scan(&original).await.unwrap();
    assert_eq!(verdict, ClamavVerdict::Clean);

    server.await.unwrap();
}

#[tokio::test]
async fn found_reply_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_instream_payload(&mut stream).await;
        stream
            .write_all(b"stream: Eicar-Test-Signature FOUND\0")
            .await
            .unwrap();
    });

    let client = ClamavClient::new(&addr.to_string());
    let verdict = client
        .scan(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
        .await
        .unwrap();
    assert_eq!(
        verdict,
        ClamavVerdict::Found("Eicar-Test-Signature".to_string())
    );

    server.await.unwrap();
}

#[tokio::test]
async fn unreachable_endpoint_is_an_error() {
    let client = ClamavClient::new("127.0.0.1:0");
    let result = client.scan(b"x").await;
    assert!(result.is_err());
}
