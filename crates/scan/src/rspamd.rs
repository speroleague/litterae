//! rspamd's `checkv2` protocol: an HTTP-shaped request/response over a
//! plain TCP or Unix-socket connection to rspamd's *normal* worker (not
//! the controller). See https://rspamd.com/doc/architecture/protocol.html

use std::net::IpAddr;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::endpoint::{connect, Endpoint};

#[derive(Debug, Clone)]
pub struct RspamdClient {
    endpoint: Endpoint,
}

pub struct CheckRequest<'a> {
    pub remote_ip: IpAddr,
    pub helo: &'a str,
    pub mail_from: &'a str,
    pub rcpt_to: &'a [String],
    pub raw_message: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RspamdAction {
    NoAction,
    AddHeader,
    RewriteSubject,
    SoftReject,
    Reject,
    Greylist,
    Unknown(String),
}

impl RspamdAction {
    fn parse(s: &str) -> Self {
        match s {
            "no action" => RspamdAction::NoAction,
            "add header" => RspamdAction::AddHeader,
            "rewrite subject" => RspamdAction::RewriteSubject,
            "soft reject" => RspamdAction::SoftReject,
            "reject" => RspamdAction::Reject,
            "greylist" => RspamdAction::Greylist,
            other => RspamdAction::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RspamdVerdict {
    pub action: RspamdAction,
    pub score: f64,
    pub required_score: f64,
}

#[derive(Deserialize)]
struct RawResponse {
    #[serde(default)]
    score: f64,
    #[serde(default)]
    required_score: f64,
    action: String,
}

impl RspamdClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: Endpoint::parse(endpoint),
        }
    }

    pub async fn check(&self, req: &CheckRequest<'_>) -> common::Result<RspamdVerdict> {
        let mut conn = connect(&self.endpoint).await?;

        let mut head = format!(
            "POST /checkv2 HTTP/1.0\r\nContent-Length: {}\r\nIP: {}\r\nHelo: {}\r\nFrom: {}\r\n",
            req.raw_message.len(),
            req.remote_ip,
            req.helo,
            req.mail_from,
        );
        for rcpt in req.rcpt_to {
            head.push_str(&format!("Rcpt: {rcpt}\r\n"));
        }
        head.push_str("\r\n");

        conn.write_all(head.as_bytes())
            .await
            .map_err(common::Error::Io)?;
        conn.write_all(req.raw_message)
            .await
            .map_err(common::Error::Io)?;

        let mut response = Vec::new();
        conn.read_to_end(&mut response)
            .await
            .map_err(common::Error::Io)?;
        parse_response(&response)
    }
}

fn parse_response(response: &[u8]) -> common::Result<RspamdVerdict> {
    let separator = b"\r\n\r\n";
    let split_at = response
        .windows(separator.len())
        .position(|w| w == separator)
        .ok_or_else(|| {
            common::Error::Network("malformed rspamd response: no header/body separator".into())
        })?;
    let body = &response[split_at + separator.len()..];

    let raw: RawResponse = serde_json::from_slice(body)
        .map_err(|e| common::Error::Network(format!("malformed rspamd JSON response: {e}")))?;

    Ok(RspamdVerdict {
        action: RspamdAction::parse(&raw.action),
        score: raw.score,
        required_score: raw.required_score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_actions() {
        assert_eq!(RspamdAction::parse("no action"), RspamdAction::NoAction);
        assert_eq!(RspamdAction::parse("add header"), RspamdAction::AddHeader);
        assert_eq!(
            RspamdAction::parse("rewrite subject"),
            RspamdAction::RewriteSubject
        );
        assert_eq!(RspamdAction::parse("soft reject"), RspamdAction::SoftReject);
        assert_eq!(RspamdAction::parse("reject"), RspamdAction::Reject);
        assert_eq!(RspamdAction::parse("greylist"), RspamdAction::Greylist);
    }

    #[test]
    fn unrecognized_action_falls_back_to_unknown() {
        assert_eq!(
            RspamdAction::parse("some future action"),
            RspamdAction::Unknown("some future action".to_string())
        );
    }

    #[test]
    fn parses_a_canned_response() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"score\":12.5,\"required_score\":15.0,\"action\":\"add header\"}";
        let verdict = parse_response(response).unwrap();
        assert_eq!(verdict.action, RspamdAction::AddHeader);
        assert_eq!(verdict.score, 12.5);
        assert_eq!(verdict.required_score, 15.0);
    }

    #[test]
    fn malformed_json_body_is_an_error() {
        let response = b"HTTP/1.0 200 OK\r\n\r\nnot json";
        assert!(parse_response(response).is_err());
    }

    #[test]
    fn missing_separator_is_an_error() {
        let response = b"garbage with no header body split";
        assert!(parse_response(response).is_err());
    }
}
