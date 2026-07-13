//! Serves an axum `Router` over a listener that is either plain TCP or, if
//! a `rustls::ServerConfig` is supplied, TLS terminated in-process (spec
//! §8.4: JMAP and admin are meant to run over TLS; a reverse proxy in front
//! is the other supported way to satisfy that, which is why TLS here stays
//! optional rather than mandatory like submission's).
//!
//! Both paths expose the peer's `SocketAddr` to handlers via
//! `axum::extract::ConnectInfo` -- login/auth failure logging (spec §8.4
//! hardening) needs the source IP, and this is the one place both serving
//! paths funnel through.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use common::{Error, Result};

pub async fn serve(addr: &str, router: Router, tls_config: Option<Arc<ServerConfig>>) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| Error::Config(format!("failed to bind {addr}: {e}")))?;

    let Some(tls_config) = tls_config else {
        let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
        return axum::serve(listener, make_service)
            .await
            .map_err(|e| Error::Config(format!("server error on {addr}: {e}")));
    };

    let acceptor = TlsAcceptor::from(tls_config);
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, %addr, "failed to accept connection");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone().layer(Extension(ConnectInfo(peer_addr)));
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "TLS handshake failed");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let hyper_service = TowerToHyperService::new(router);
            if let Err(e) = Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                tracing::warn!(error = %e, "connection error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn plaintext_router_exposes_peer_connect_info() {
        let router = Router::new().route(
            "/whoami",
            get(|ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { addr.ip().to_string() }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let addr_string = addr.to_string();
        tokio::spawn(async move {
            let _ = serve(&addr_string, router, None).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200"), "unexpected response: {response}");
        assert!(response.ends_with("127.0.0.1"), "expected peer IP in body: {response}");
    }

    #[tokio::test]
    async fn tls_router_exposes_peer_connect_info() {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use tokio_rustls::rustls;

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], signing_key.serialize_der().try_into().unwrap())
            .unwrap();

        let router = Router::new().route(
            "/whoami",
            get(|ConnectInfo(addr): ConnectInfo<SocketAddr>| async move { addr.ip().to_string() }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let addr_string = addr.to_string();
        tokio::spawn(async move {
            let _ = serve(&addr_string, router, Some(Arc::new(server_config))).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls_stream = connector.connect(server_name, tcp).await.unwrap();
        tls_stream
            .write_all(b"GET /whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        tls_stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200"), "unexpected response: {response}");
        assert!(response.ends_with("127.0.0.1"), "expected peer IP in body: {response}");
    }

    #[tokio::test]
    async fn plaintext_router_serves_a_real_request() {
        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let addr_string = addr.to_string();
        tokio::spawn(async move {
            let _ = serve(&addr_string, router, None).await;
        });

        // Give the spawned task a moment to bind before connecting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200"), "unexpected response: {response}");
        assert!(response.ends_with("pong"), "unexpected body: {response}");
    }

    #[tokio::test]
    async fn tls_router_serves_a_real_request_over_a_real_handshake() {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use tokio_rustls::rustls;

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], signing_key.serialize_der().try_into().unwrap())
            .unwrap();

        let router = Router::new().route("/ping", get(|| async { "pong" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let addr_string = addr.to_string();
        tokio::spawn(async move {
            let _ = serve(&addr_string, router, Some(Arc::new(server_config))).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls_stream = connector.connect(server_name, tcp).await.unwrap();
        tls_stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        tls_stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200"), "unexpected response: {response}");
        assert!(response.ends_with("pong"), "unexpected body: {response}");
    }
}
