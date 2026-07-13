//! Connects to a content scanner (rspamd or clamd) over either a Unix
//! domain socket or plain TCP, from a single config string -- paths
//! starting with `/` are Unix sockets, anything else is `host:port` TCP.
//! Both scanners are commonly deployed either way.

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};

#[derive(Debug, Clone)]
pub(crate) enum Endpoint {
    Unix(PathBuf),
    Tcp(String),
}

impl Endpoint {
    pub(crate) fn parse(s: &str) -> Self {
        if s.starts_with('/') {
            Endpoint::Unix(PathBuf::from(s))
        } else {
            Endpoint::Tcp(s.to_string())
        }
    }
}

pub(crate) enum Conn {
    Tcp(TcpStream),
    Unix(UnixStream),
}

pub(crate) async fn connect(endpoint: &Endpoint) -> common::Result<Conn> {
    match endpoint {
        Endpoint::Tcp(addr) => TcpStream::connect(addr).await.map(Conn::Tcp),
        Endpoint::Unix(path) => UnixStream::connect(path).await.map(Conn::Unix),
    }
    .map_err(common::Error::Io)
}

impl AsyncRead for Conn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_flush(cx),
            Conn::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Conn::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_prefixed_string_is_a_unix_socket() {
        assert!(matches!(Endpoint::parse("/var/run/rspamd/rspamd.sock"), Endpoint::Unix(_)));
    }

    #[test]
    fn host_port_string_is_tcp() {
        assert!(matches!(Endpoint::parse("127.0.0.1:11333"), Endpoint::Tcp(_)));
        assert!(matches!(Endpoint::parse("rspamd:11333"), Endpoint::Tcp(_)));
    }
}
