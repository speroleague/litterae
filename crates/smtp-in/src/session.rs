//! Inbound SMTP state machine (spec §8.1): connect -> EHLO ->
//! opportunistic STARTTLS -> MAIL FROM -> RCPT TO -> DATA. Runs SPF/DKIM
//! verification via `mail-auth` on arrival, then hands each accepted
//! recipient to `delivery`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use admin::AdminStore;
use auth::AuthStore;
use delivery::{AuthResults, InboundEnvelope};
use scan::{ScanRequest, Scanner, Verdict};
use store::{BlobStore, MetadataStore};

/// Hard backstops against unbounded memory use while parsing untrusted
/// input (spec §8.1 "bound parser memory"). `max_message_size` (the total
/// DATA cap) is config-driven; these are per-line floors underneath it.
const MAX_COMMAND_LINE: usize = 4096;
const MAX_DATA_LINE: usize = 65536;

pub struct Deps {
    pub hostname: String,
    pub max_message_size: usize,
    pub auth_store: Arc<AuthStore>,
    pub admin_store: Arc<AdminStore>,
    pub blobs: Arc<BlobStore>,
    pub metadata: Arc<MetadataStore>,
    pub authenticator: Arc<MessageAuthenticator>,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub scanner: Arc<Scanner>,
    pub audit: Arc<audit::AuditStore>,
}

#[derive(Default)]
struct Envelope {
    helo_domain: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<ResolvedRecipient>,
}

impl Envelope {
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }
}

#[derive(Clone)]
struct ResolvedRecipient {
    address: String,
    account_id: i64,
    account_pub: [u8; crypto::hpke_seal::PUBLIC_KEY_LEN],
    account_key_id: u16,
}

enum LoopOutcome {
    Closed,
    StartTls,
}

enum DataError {
    TooLarge,
    Io,
}

pub async fn handle_connection(tcp: TcpStream, remote_ip: IpAddr, deps: Arc<Deps>) {
    let mut reader = BufReader::new(tcp);
    let mut envelope = Envelope::default();

    let outcome = command_loop(&mut reader, &mut envelope, remote_ip, &deps, false).await;
    if !matches!(outcome, LoopOutcome::StartTls) {
        return;
    }

    // Defense against STARTTLS command/response injection (the historical
    // "plaintext injection" class of bug): if the client pipelined bytes
    // past the STARTTLS command before seeing our response, those bytes are
    // already sitting in the plaintext BufReader. Never carry them into the
    // encrypted session -- refuse the connection instead of discarding
    // silently, since a benign client never does this.
    if !reader.buffer().is_empty() {
        tracing::warn!(%remote_ip, "rejecting connection: data pipelined past STARTTLS");
        return;
    }

    let Some(acceptor) = &deps.tls_acceptor else {
        return;
    };
    let tcp = reader.into_inner();
    match acceptor.accept(tcp).await {
        Ok(tls_stream) => {
            let mut tls_reader = BufReader::new(tls_stream);
            // RFC 3207: prior envelope state must not survive STARTTLS; the
            // client is required to send EHLO again.
            envelope = Envelope::default();
            let _ = command_loop(&mut tls_reader, &mut envelope, remote_ip, &deps, true).await;
        }
        Err(e) => tracing::warn!(%remote_ip, error = %e, "TLS handshake failed"),
    }
}

async fn command_loop<S>(
    reader: &mut BufReader<S>,
    envelope: &mut Envelope,
    remote_ip: IpAddr,
    deps: &Deps,
    is_tls: bool,
) -> LoopOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // RFC 3207: a fresh 220 greeting is only sent on the initial plaintext
    // connection. After STARTTLS the client proceeds straight to EHLO with
    // no new greeting -- sending one here would desync the reply stream.
    if !is_tls
        && write_reply(reader, 220, &format!("{} ESMTP Litterae", deps.hostname))
            .await
            .is_err()
    {
        return LoopOutcome::Closed;
    }

    let mut line = Vec::new();
    loop {
        match read_line_bounded(reader, MAX_COMMAND_LINE, &mut line).await {
            Ok(false) => return LoopOutcome::Closed, // EOF
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
                    lines.push("8BITMIME".to_string());
                    lines.push("SMTPUTF8".to_string());
                    if !is_tls && deps.tls_acceptor.is_some() {
                        lines.push("STARTTLS".to_string());
                    }
                }
                if write_multiline_reply(reader, 250, &lines).await.is_err() {
                    return LoopOutcome::Closed;
                }
            }
            "STARTTLS" => {
                if is_tls {
                    let _ = write_reply(reader, 503, "Already using TLS").await;
                } else if deps.tls_acceptor.is_none() {
                    let _ = write_reply(reader, 502, "STARTTLS not supported").await;
                } else if !rest.is_empty() {
                    let _ = write_reply(reader, 501, "Syntax error").await;
                } else if write_reply(reader, 220, "Go ahead").await.is_ok() {
                    return LoopOutcome::StartTls;
                } else {
                    return LoopOutcome::Closed;
                }
            }
            "MAIL" => {
                if envelope.helo_domain.is_none() {
                    let _ = write_reply(reader, 503, "Bad sequence of commands").await;
                } else {
                    match parse_addr_param(rest, "FROM:") {
                        Some(addr) => {
                            envelope.mail_from = Some(addr);
                            envelope.rcpt_to.clear();
                            let _ = write_reply(reader, 250, "OK").await;
                        }
                        None => {
                            let _ = write_reply(reader, 501, "Syntax error in parameters").await;
                        }
                    }
                }
            }
            "RCPT" => {
                if envelope.mail_from.is_none() {
                    let _ = write_reply(reader, 503, "Bad sequence of commands").await;
                } else {
                    match parse_addr_param(rest, "TO:") {
                        Some(addr) => match resolve_recipient(deps, &addr) {
                            Some(resolved) => {
                                envelope.rcpt_to.push(resolved);
                                let _ = write_reply(reader, 250, "OK").await;
                            }
                            None => {
                                let _ = write_reply(reader, 550, "No such user here").await;
                            }
                        },
                        None => {
                            let _ = write_reply(reader, 501, "Syntax error in parameters").await;
                        }
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
                        let rcpt_addresses: Vec<String> =
                            envelope.rcpt_to.iter().map(|r| r.address.clone()).collect();
                        let scan_result = deps
                            .scanner
                            .scan(&ScanRequest {
                                remote_ip,
                                helo: envelope.helo_domain.as_deref().unwrap_or_default(),
                                mail_from: envelope.mail_from.as_deref().unwrap_or_default(),
                                rcpt_to: &rcpt_addresses,
                                raw_message: &raw,
                            })
                            .await;

                        for warning in &scan_result.warnings {
                            tracing::warn!(%remote_ip, warning, "content scanner unreachable, failing open");
                            let _ = deps.audit.log("smtp.scan_unreachable", warning);
                        }

                        let spam_reason = match scan_result.verdict {
                            Verdict::Reject { reason } => {
                                tracing::warn!(%remote_ip, reason = %reason, "rejecting message: scanner verdict");
                                let _ = deps.audit.log("smtp.scan_reject", &reason);
                                let _ =
                                    write_reply(reader, 550, "Message rejected by content policy").await;
                                envelope.reset();
                                continue;
                            }
                            Verdict::Defer { reason } => {
                                tracing::info!(%remote_ip, reason = %reason, "deferring message: scanner verdict");
                                let _ = deps.audit.log("smtp.scan_defer", &reason);
                                let _ = write_reply(
                                    reader,
                                    451,
                                    "Requested action aborted: try again later",
                                )
                                .await;
                                envelope.reset();
                                continue;
                            }
                            Verdict::Spam { reason } => Some(reason),
                            Verdict::Clean => None,
                        };

                        let results = run_auth_checks(deps, envelope, remote_ip, &raw).await;
                        let received_at = now_unix();
                        let mut delivered_any = false;
                        for rcpt in &envelope.rcpt_to {
                            match deliver_one(
                                deps,
                                envelope,
                                remote_ip,
                                rcpt,
                                &results,
                                &raw,
                                received_at,
                                spam_reason.as_deref(),
                            ) {
                                Ok(()) => delivered_any = true,
                                Err(e) => {
                                    tracing::error!(error = %e, rcpt = %rcpt.address, "delivery failed")
                                }
                            }
                        }
                        let reply = if delivered_any {
                            write_reply(reader, 250, "OK: message accepted").await
                        } else {
                            write_reply(
                                reader,
                                451,
                                "Requested action aborted: local error in processing",
                            )
                            .await
                        };
                        if reply.is_err() {
                            return LoopOutcome::Closed;
                        }
                    }
                    Err(DataError::TooLarge) => {
                        let _ = write_reply(reader, 552, "Message size exceeds fixed limit").await;
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

fn resolve_recipient(deps: &Deps, addr: &str) -> Option<ResolvedRecipient> {
    let (local_part, domain) = addr.rsplit_once('@')?;
    let account = match deps.auth_store.find_by_address(local_part, domain).ok()? {
        Some(account) => account,
        // No mailbox at that local part -- if the domain has a catch-all
        // configured, route there instead of bouncing.
        None => {
            let catch_all_local_part = deps
                .admin_store
                .get_domain_by_name(domain)
                .ok()??
                .catch_all_local_part?;
            deps.auth_store
                .find_by_address(&catch_all_local_part, domain)
                .ok()??
        }
    };
    Some(ResolvedRecipient {
        address: addr.to_string(),
        account_id: account.id,
        account_pub: account.account_pub,
        account_key_id: account.key_id,
    })
}

#[allow(clippy::too_many_arguments)]
fn deliver_one(
    deps: &Deps,
    envelope: &Envelope,
    remote_ip: IpAddr,
    rcpt: &ResolvedRecipient,
    results: &AuthResults,
    raw: &[u8],
    received_at: i64,
    spam_reason: Option<&str>,
) -> common::Result<()> {
    let inbound_envelope = InboundEnvelope {
        mail_from: envelope.mail_from.clone().unwrap_or_default(),
        rcpt_to: rcpt.address.clone(),
        remote_ip,
    };
    let account = delivery::RecipientAccount {
        id: rcpt.account_id,
        account_pub: rcpt.account_pub,
        key_id: rcpt.account_key_id,
    };
    delivery::deliver(
        &deps.blobs,
        &deps.metadata,
        &account,
        &inbound_envelope,
        results,
        raw,
        received_at,
        spam_reason,
    )?;
    Ok(())
}

async fn run_auth_checks(
    deps: &Deps,
    envelope: &Envelope,
    remote_ip: IpAddr,
    raw: &[u8],
) -> AuthResults {
    let helo = envelope.helo_domain.clone().unwrap_or_default();
    let mail_from = envelope.mail_from.clone().unwrap_or_default();

    let spf_output = deps
        .authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            remote_ip,
            &helo,
            &deps.hostname,
            &mail_from,
        ))
        .await;
    let spf_str = format!("{:?}", spf_output.result()).to_lowercase();

    let Some(auth_message) = AuthenticatedMessage::parse(raw) else {
        return AuthResults {
            spf: spf_str,
            dkim: "none".into(),
            dmarc: "none".into(),
        };
    };

    let dkim_outputs = deps.authenticator.verify_dkim(&auth_message).await;
    let dkim_str = if dkim_outputs.is_empty() {
        "none".to_string()
    } else if dkim_outputs
        .iter()
        .any(|o| matches!(o.result(), DkimResult::Pass))
    {
        "pass".to_string()
    } else {
        "fail".to_string()
    };

    let mail_from_domain = mail_from
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(&helo)
        .to_string();
    let dmarc_output = deps
        .authenticator
        .verify_dmarc(DmarcParameters {
            message: &auth_message,
            dkim_output: &dkim_outputs,
            dkim2_output: None,
            rfc5321_mail_from_domain: &mail_from_domain,
            spf_output: &spf_output,
        })
        .await;
    let dmarc_str = format!("{:?}", dmarc_output.policy()).to_lowercase();

    AuthResults {
        spf: spf_str,
        dkim: dkim_str,
        dmarc: dmarc_str,
    }
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
            return Err(DataError::Io); // EOF mid-DATA
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

/// Reads one line (through the trailing `\n`) without ever buffering past
/// `max_len` bytes, regardless of how much the client sends. Returns
/// `Ok(false)` on clean EOF, `Err` if the line exceeds `max_len`.
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

/// Parses `PREFIX<addr>` (e.g. `FROM:<sender@example.net>`), case-insensitive
/// on the prefix, tolerant of ESMTP parameters after the closing `>`.
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

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_command_handles_verb_and_args() {
        assert_eq!(split_command("EHLO mail.example.com"), ("EHLO", "mail.example.com"));
        assert_eq!(split_command("STARTTLS"), ("STARTTLS", ""));
        assert_eq!(split_command("MAIL FROM:<a@b.com>"), ("MAIL", "FROM:<a@b.com>"));
    }

    #[test]
    fn parse_addr_param_extracts_address() {
        assert_eq!(
            parse_addr_param("FROM:<sender@example.net>", "FROM:"),
            Some("sender@example.net".to_string())
        );
        assert_eq!(
            parse_addr_param("to:<alice@example.com> SIZE=100", "TO:"),
            Some("alice@example.com".to_string())
        );
        assert_eq!(parse_addr_param("FROM:<>", "FROM:"), Some(String::new()));
        assert_eq!(parse_addr_param("garbage", "FROM:"), None);
    }
}
