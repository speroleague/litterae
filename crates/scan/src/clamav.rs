//! clamd's INSTREAM protocol: send `zINSTREAM\0`, then the payload as
//! 4-byte-big-endian-length-prefixed chunks terminated by a zero-length
//! chunk, then read one null-terminated reply line.
//! https://docs.clamav.net/manual/Usage/Scanning.html#instream

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::endpoint::{connect, Endpoint};

/// Arbitrary per the protocol -- large enough to keep syscall count low,
/// small enough to keep memory bounded for very large messages.
const CHUNK_SIZE: usize = 256 * 1024;

/// `scan()` itself has no timeout (a wedged clamd that accepts the
/// connection but never replies would hang it forever) -- `Scanner`
/// normally supplies one via its own wrapper; `scan_with_timeout` is for
/// callers that talk to `ClamavClient` directly, outside `Scanner`.
const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct ClamavClient {
    endpoint: Endpoint,
    timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClamavVerdict {
    Clean,
    Found(String),
}

impl ClamavClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: Endpoint::parse(endpoint),
            timeout: DEFAULT_SCAN_TIMEOUT,
        }
    }

    /// Overrides the default timeout `scan_with_timeout` uses (tests use
    /// this to avoid a slow real wait against a deliberately-wedged
    /// listener).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn scan(&self, raw_message: &[u8]) -> common::Result<ClamavVerdict> {
        let mut conn = connect(&self.endpoint).await?;

        conn.write_all(b"zINSTREAM\0")
            .await
            .map_err(common::Error::Io)?;
        for chunk in raw_message.chunks(CHUNK_SIZE) {
            conn.write_all(&(chunk.len() as u32).to_be_bytes())
                .await
                .map_err(common::Error::Io)?;
            conn.write_all(chunk).await.map_err(common::Error::Io)?;
        }
        conn.write_all(&0u32.to_be_bytes())
            .await
            .map_err(common::Error::Io)?;

        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = conn.read(&mut byte).await.map_err(common::Error::Io)?;
            if n == 0 || byte[0] == 0 {
                break;
            }
            line.push(byte[0]);
        }
        parse_stream_reply(&String::from_utf8_lossy(&line))
    }

    /// Same as `scan`, bounded by this client's timeout (`with_timeout`,
    /// defaulting to `DEFAULT_SCAN_TIMEOUT`) so a wedged clamd can't hang
    /// the caller forever.
    pub async fn scan_with_timeout(&self, raw_message: &[u8]) -> common::Result<ClamavVerdict> {
        match tokio::time::timeout(self.timeout, self.scan(raw_message)).await {
            Ok(result) => result,
            Err(_) => Err(common::Error::Network("clamd scan timed out".into())),
        }
    }
}

fn parse_stream_reply(line: &str) -> common::Result<ClamavVerdict> {
    let rest = line
        .trim()
        .strip_prefix("stream:")
        .ok_or_else(|| common::Error::Network(format!("malformed clamd reply: {line:?}")))?
        .trim();
    if rest == "OK" {
        return Ok(ClamavVerdict::Clean);
    }
    if let Some(sig) = rest.strip_suffix("FOUND") {
        return Ok(ClamavVerdict::Found(sig.trim().to_string()));
    }
    Err(common::Error::Network(format!(
        "unrecognized clamd reply: {line:?}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_reply_parses() {
        assert_eq!(
            parse_stream_reply("stream: OK").unwrap(),
            ClamavVerdict::Clean
        );
    }

    #[test]
    fn found_reply_parses_with_signature_name() {
        assert_eq!(
            parse_stream_reply("stream: Eicar-Test-Signature FOUND").unwrap(),
            ClamavVerdict::Found("Eicar-Test-Signature".to_string())
        );
    }

    #[test]
    fn garbage_reply_is_an_error() {
        assert!(parse_stream_reply("not a clamd reply at all").is_err());
    }

    #[test]
    fn unrecognized_status_is_an_error_not_a_silent_clean() {
        // A reply that starts right but ends in neither OK nor FOUND must
        // never be treated as clean.
        assert!(parse_stream_reply("stream: ERROR something broke").is_err());
    }
}
