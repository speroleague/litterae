//! Submission state machine: EHLO -> (STARTTLS on 587; already TLS on
//! 465) -> AUTH PLAIN -> MAIL FROM (must match the authenticated
//! identity) -> RCPT TO (any external address) -> DATA -> enqueue.
//! TLS is mandatory: AUTH is refused outright over plaintext.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use auth::{Account, AuthStore};
use common::config::Argon2Config;
use common::throttle::LoginThrottle;
use queue::QueueStore;
use store::BlobStore;

const MAX_COMMAND_LINE: usize = 4096;
const MAX_DATA_LINE: usize = 65536;
const MAX_RECIPIENTS: usize = 100;

pub struct Deps {
    pub hostname: String,
    pub max_message_size: usize,
    pub auth_store: Arc<AuthStore>,
    pub queue: Arc<QueueStore>,
    pub blobs: Arc<BlobStore>,
    pub audit: Arc<audit::AuditStore>,
    pub login_throttle: Arc<LoginThrottle>,
    pub argon2_config: Arc<Argon2Config>,
    pub auth_semaphore: Arc<Semaphore>,
    pub tls_acceptor: TlsAcceptor,
}

#[derive(Default)]
struct Envelope {
    helo_domain: Option<String>,
    authenticated: Option<Account>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

impl Envelope {
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }
}

enum LoopOutcome {
    Closed,
    StartTls,
}

enum DataError {
    TooLarge,
    Io,
}

/// Port 587: plaintext until STARTTLS.
pub async fn handle_starttls_connection(tcp: TcpStream, remote_ip: IpAddr, deps: Arc<Deps>) {
    let mut reader = BufReader::new(tcp);
    let mut envelope = Envelope::default();

    let outcome = command_loop(&mut reader, &mut envelope, remote_ip, &deps, false, true).await;
    if !matches!(outcome, LoopOutcome::StartTls) {
        return;
    }
    if !reader.buffer().is_empty() {
        tracing::warn!("rejecting submission connection: data pipelined past STARTTLS");
        return;
    }

    let tcp = reader.into_inner();
    match deps.tls_acceptor.accept(tcp).await {
        Ok(tls_stream) => {
            let mut tls_reader = BufReader::new(tls_stream);
            envelope = Envelope::default();
            // RFC 3207: no new greeting after STARTTLS -- the client goes
            // straight to EHLO.
            let _ = command_loop(
                &mut tls_reader,
                &mut envelope,
                remote_ip,
                &deps,
                true,
                false,
            )
            .await;
        }
        Err(e) => tracing::warn!(error = %e, "submission TLS handshake failed"),
    }
}

/// Port 465: implicit TLS from the first byte.
pub async fn handle_implicit_connection(tcp: TcpStream, remote_ip: IpAddr, deps: Arc<Deps>) {
    match deps.tls_acceptor.accept(tcp).await {
        Ok(tls_stream) => {
            let mut reader = BufReader::new(tls_stream);
            let mut envelope = Envelope::default();
            let _ = command_loop(&mut reader, &mut envelope, remote_ip, &deps, true, true).await;
        }
        Err(e) => tracing::warn!(error = %e, "submission implicit TLS handshake failed"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn command_loop<S>(
    reader: &mut BufReader<S>,
    envelope: &mut Envelope,
    remote_ip: IpAddr,
    deps: &Deps,
    is_tls: bool,
    greet: bool,
) -> LoopOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if greet
        && write_reply(
            reader,
            220,
            &format!("{} ESMTP Litterae Submission", deps.hostname),
        )
        .await
        .is_err()
    {
        return LoopOutcome::Closed;
    }

    let mut line = Vec::new();
    loop {
        match read_line_bounded(reader, MAX_COMMAND_LINE, &mut line).await {
            Ok(false) => return LoopOutcome::Closed,
            Ok(true) => {}
            Err(_) => {
                let _ = write_reply(reader, 500, "Line too long").await;
                return LoopOutcome::Closed;
            }
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\r', '\n']);
        let (verb, rest) = split_command(text);

        match verb.to_ascii_uppercase().as_str() {
            "EHLO" | "HELO" => {
                envelope.helo_domain = Some(rest.trim().to_string());
                envelope.reset();
                let mut lines = vec![format!("{} Hello", deps.hostname)];
                if verb.eq_ignore_ascii_case("EHLO") {
                    lines.push(format!("SIZE {}", deps.max_message_size));
                    if !is_tls {
                        lines.push("STARTTLS".to_string());
                    } else {
                        lines.push("AUTH PLAIN".to_string());
                    }
                    lines.push("8BITMIME".to_string());
                }
                if write_multiline_reply(reader, 250, &lines).await.is_err() {
                    return LoopOutcome::Closed;
                }
            }
            "STARTTLS" => {
                if is_tls {
                    let _ = write_reply(reader, 503, "Already using TLS").await;
                } else if !rest.is_empty() {
                    let _ = write_reply(reader, 501, "Syntax error").await;
                } else if write_reply(reader, 220, "Go ahead").await.is_ok() {
                    return LoopOutcome::StartTls;
                } else {
                    return LoopOutcome::Closed;
                }
            }
            "AUTH" => {
                if !is_tls {
                    let _ = write_reply(reader, 530, "Must issue STARTTLS first").await;
                    continue;
                }
                if envelope.authenticated.is_some() {
                    let _ = write_reply(reader, 503, "Already authenticated").await;
                    continue;
                }
                match handle_auth(reader, deps, remote_ip, rest).await {
                    Ok(Some(account)) => {
                        envelope.authenticated = Some(account);
                        let _ = write_reply(reader, 235, "Authentication successful").await;
                    }
                    Ok(None) => {
                        let _ = write_reply(reader, 535, "Authentication failed").await;
                    }
                    Err(()) => return LoopOutcome::Closed,
                }
            }
            "MAIL" => {
                let Some(account) = &envelope.authenticated else {
                    let _ = write_reply(reader, 530, "Authentication required").await;
                    continue;
                };
                match parse_addr_param(rest, "FROM:") {
                    Some(addr) if addr.eq_ignore_ascii_case(&account.address()) => {
                        envelope.mail_from = Some(addr);
                        envelope.rcpt_to.clear();
                        let _ = write_reply(reader, 250, "OK").await;
                    }
                    Some(_) => {
                        let _ = write_reply(
                            reader,
                            553,
                            "Sender address does not match authenticated identity",
                        )
                        .await;
                    }
                    None => {
                        let _ = write_reply(reader, 501, "Syntax error in parameters").await;
                    }
                }
            }
            "RCPT" => {
                if envelope.mail_from.is_none() {
                    let _ = write_reply(reader, 503, "Bad sequence of commands").await;
                    continue;
                }
                match parse_addr_param(rest, "TO:") {
                    Some(_) if envelope.rcpt_to.len() >= MAX_RECIPIENTS => {
                        let _ = write_reply(reader, 452, "Too many recipients").await;
                    }
                    Some(addr) if common::input::valid_email_address(&addr) => {
                        envelope.rcpt_to.push(addr);
                        let _ = write_reply(reader, 250, "OK").await;
                    }
                    _ => {
                        let _ = write_reply(reader, 501, "Syntax error in parameters").await;
                    }
                }
            }
            "DATA" => {
                if envelope.mail_from.is_none() || envelope.rcpt_to.is_empty() {
                    let _ = write_reply(reader, 503, "Bad sequence of commands").await;
                    continue;
                }
                if write_reply(reader, 354, "Start mail input; end with <CRLF>.<CRLF>")
                    .await
                    .is_err()
                {
                    return LoopOutcome::Closed;
                }
                match read_data(reader, deps.max_message_size).await {
                    Ok(raw) => {
                        let account = envelope.authenticated.as_ref().expect("checked above");
                        let reply = match enqueue_submission(deps, account, envelope, &raw).await {
                            Ok(()) => write_reply(reader, 250, "OK: message queued").await,
                            Err(e) => {
                                tracing::error!(error = %e, "failed to enqueue submitted message");
                                write_reply(reader, 451, "Local error in processing").await
                            }
                        };
                        if reply.is_err() {
                            return LoopOutcome::Closed;
                        }
                    }
                    Err(DataError::TooLarge) => {
                        let _ = write_reply(reader, 552, "Message size exceeds fixed limit").await;
                        return LoopOutcome::Closed;
                    }
                    Err(DataError::Io) => return LoopOutcome::Closed,
                }
                envelope.reset();
            }
            "RSET" => {
                envelope.reset();
                let _ = write_reply(reader, 250, "OK").await;
            }
            "NOOP" => {
                let _ = write_reply(reader, 250, "OK").await;
            }
            "QUIT" => {
                let _ = write_reply(reader, 221, "Bye").await;
                return LoopOutcome::Closed;
            }
            _ => {
                let _ = write_reply(reader, 502, "Command not implemented").await;
            }
        }
    }
}

async fn handle_auth<S>(
    reader: &mut BufReader<S>,
    deps: &Deps,
    remote_ip: IpAddr,
    rest: &str,
) -> Result<Option<Account>, ()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mechanism, initial) = split_command(rest);
    if !mechanism.eq_ignore_ascii_case("PLAIN") {
        let _ = write_reply(reader, 504, "Unsupported authentication mechanism").await;
        return Ok(None);
    }

    let payload_b64 = if initial.is_empty() {
        if write_reply(reader, 334, "").await.is_err() {
            return Err(());
        }
        let mut line = Vec::new();
        match read_line_bounded(reader, MAX_COMMAND_LINE, &mut line).await {
            Ok(true) => {}
            _ => return Err(()),
        }
        String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string()
    } else {
        initial.to_string()
    };

    use base64::Engine;
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(payload_b64.trim()) else {
        return Ok(None);
    };
    let Some((authcid, password)) = parse_sasl_plain(&decoded) else {
        return Ok(None);
    };
    let Some((local_part, domain)) = authcid.split_once('@') else {
        return Ok(None);
    };

    if deps.login_throttle.check(&authcid).is_err() {
        return Ok(None);
    }

    let Ok(Some(account)) = deps.auth_store.find_by_address(local_part, domain) else {
        deps.login_throttle.record_failure(&authcid);
        let _ = deps.audit.log("auth.submission_failed", &authcid);
        tracing::warn!(event = "auth_failure", remote_ip = %remote_ip, authcid, "submission auth failed: no such account");
        return Ok(None);
    };
    let permit = deps
        .auth_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ())?;
    let auth_store = deps.auth_store.clone();
    let config = deps.argon2_config.clone();
    let account_for_unlock = account.clone();
    let password = password.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth_store.unlock(&account_for_unlock, password.as_bytes(), &config)
    })
    .await
    .map_err(|_| ())?;
    match result {
        Ok(_unlocked) => {
            deps.login_throttle.record_success(&authcid);
            let _ = deps.audit.log("auth.submission", &authcid);
            Ok(Some(account))
        }
        Err(_) => {
            deps.login_throttle.record_failure(&authcid);
            let _ = deps.audit.log("auth.submission_failed", &authcid);
            tracing::warn!(event = "auth_failure", remote_ip = %remote_ip, authcid, "submission auth failed: wrong password");
            Ok(None)
        }
    }
}

fn parse_sasl_plain(payload: &[u8]) -> Option<(String, String)> {
    let parts: Vec<&[u8]> = payload.splitn(3, |&b| b == 0).collect();
    if parts.len() != 3 {
        return None;
    }
    let authcid = String::from_utf8(parts[1].to_vec()).ok()?;
    let passwd = String::from_utf8(parts[2].to_vec()).ok()?;
    Some((authcid, passwd))
}

async fn enqueue_submission(
    deps: &Deps,
    account: &Account,
    envelope: &Envelope,
    raw: &[u8],
) -> common::Result<()> {
    let sender = envelope.mail_from.clone().unwrap_or_default();
    let domain_key = deps.queue.ensure_dkim_key(&account.domain)?;
    let recipients: Vec<&str> = envelope.rcpt_to.iter().map(String::as_str).collect();
    queue::enqueue(
        &deps.queue,
        &deps.blobs,
        &domain_key,
        &queue::NewOutbound {
            account_id: account.id,
            envelope_from: &sender,
            raw_message: raw,
            recipients: &recipients,
            is_dsn: false,
            dsn_envid: None,
            dsn_ret: None,
        },
    )?;
    Ok(())
}

async fn read_data<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    max_size: usize,
) -> Result<Vec<u8>, DataError> {
    let mut out = Vec::new();
    let mut line = Vec::new();
    loop {
        let got = read_line_bounded(reader, MAX_DATA_LINE, &mut line)
            .await
            .map_err(|_| DataError::TooLarge)?;
        if !got {
            return Err(DataError::Io);
        }
        if line == b".\r\n" || line == b".\n" {
            break;
        }
        let content: &[u8] = if line.first() == Some(&b'.') {
            &line[1..]
        } else {
            &line[..]
        };
        if out.len() + content.len() > max_size {
            return Err(DataError::TooLarge);
        }
        out.extend_from_slice(content);
    }
    Ok(out)
}

async fn read_line_bounded<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    max_len: usize,
    out: &mut Vec<u8>,
) -> std::io::Result<bool> {
    use tokio::io::AsyncReadExt;
    out.clear();
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(false);
        }
        out.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(true);
        }
        if out.len() > max_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line exceeds maximum length",
            ));
        }
    }
}

async fn write_reply<S: AsyncWrite + Unpin>(
    writer: &mut S,
    code: u16,
    text: &str,
) -> std::io::Result<()> {
    writer
        .write_all(format!("{code} {text}\r\n").as_bytes())
        .await
}

async fn write_multiline_reply<S: AsyncWrite + Unpin>(
    writer: &mut S,
    code: u16,
    lines: &[String],
) -> std::io::Result<()> {
    for (i, text) in lines.iter().enumerate() {
        let sep = if i + 1 == lines.len() { ' ' } else { '-' };
        writer
            .write_all(format!("{code}{sep}{text}\r\n").as_bytes())
            .await?;
    }
    Ok(())
}

fn split_command(line: &str) -> (&str, &str) {
    match line.find(' ') {
        Some(idx) => (&line[..idx], line[idx + 1..].trim()),
        None => (line, ""),
    }
}

fn parse_addr_param(rest: &str, prefix: &str) -> Option<String> {
    let rest = rest.trim();
    if rest.len() < prefix.len() || !rest[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    let after = rest[prefix.len()..].trim_start();
    let after = after.strip_prefix('<')?;
    let end = after.find('>')?;
    Some(after[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sasl_plain_payload() {
        let payload = b"\0alice@example.com\0hunter2";
        let (user, pass) = parse_sasl_plain(payload).unwrap();
        assert_eq!(user, "alice@example.com");
        assert_eq!(pass, "hunter2");
    }

    #[test]
    fn rejects_malformed_sasl_plain() {
        assert!(parse_sasl_plain(b"nothing-here").is_none());
    }

    #[test]
    fn parse_addr_param_extracts_address() {
        assert_eq!(
            parse_addr_param("FROM:<alice@example.com>", "FROM:"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn rejects_control_characters_in_addresses() {
        assert!(!common::input::valid_email_address(
            "victim@example.com\r\nRSET"
        ));
    }
}
