//! SMTP reply classification: turns a `mail_send::Error` (or a delivered
//! `Ok`) from a send attempt into an `Outcome`. Get this wrong and you
//! either retry a permanent rejection forever or give up on a transient
//! one -- both are how senders end up on blocklists.

#[derive(Debug, Clone)]
pub enum Outcome {
    Delivered,
    /// Retry later: 4xx, or a connection/TLS/timeout problem that isn't a
    /// hard DNS failure.
    Transient {
        code: Option<u16>,
        status: Option<String>,
        detail: String,
    },
    /// Stop retrying: 5xx, or NXDOMAIN on the recipient domain.
    Permanent {
        code: Option<u16>,
        status: Option<String>,
        detail: String,
    },
}

pub fn classify_send_result(result: &Result<(), mail_send::Error>) -> Outcome {
    match result {
        Ok(()) => Outcome::Delivered,
        Err(mail_send::Error::UnexpectedReply(resp)) | Err(mail_send::Error::AuthenticationFailed(resp)) => {
            classify_code(resp.code, format_esc(resp.esc), resp.message.to_string())
        }
        Err(e) => Outcome::Transient {
            code: None,
            status: None,
            detail: e.to_string(),
        },
    }
}

/// A connection-level failure before any reply was received (DNS, connect,
/// TLS handshake). `hard_dns_failure` distinguishes NXDOMAIN (permanent --
/// the domain doesn't exist) from everything else (transient).
pub fn classify_connect_failure(detail: String, hard_dns_failure: bool) -> Outcome {
    if hard_dns_failure {
        Outcome::Permanent {
            code: None,
            status: None,
            detail,
        }
    } else {
        Outcome::Transient {
            code: None,
            status: None,
            detail,
        }
    }
}

fn classify_code(code: u16, status: Option<String>, detail: String) -> Outcome {
    match code / 100 {
        2 => Outcome::Delivered,
        4 => Outcome::Transient {
            code: Some(code),
            status,
            detail,
        },
        5 => Outcome::Permanent {
            code: Some(code),
            status,
            detail,
        },
        // Unknown/malformed code: never guess permanent -- treat as
        // transient so a weird reply doesn't silently drop mail.
        _ => Outcome::Transient {
            code: Some(code),
            status,
            detail,
        },
    }
}

fn format_esc(esc: [u8; 3]) -> Option<String> {
    if esc == [0, 0, 0] {
        None
    } else {
        Some(format!("{}.{}.{}", esc[0], esc[1], esc[2]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivered_on_ok() {
        assert!(matches!(classify_send_result(&Ok(())), Outcome::Delivered));
    }

    #[test]
    fn permanent_on_5xx() {
        let outcome = classify_code(550, Some("5.1.1".into()), "no such user".into());
        assert!(matches!(outcome, Outcome::Permanent { code: Some(550), .. }));
    }

    #[test]
    fn transient_on_4xx() {
        let outcome = classify_code(450, None, "mailbox full".into());
        assert!(matches!(outcome, Outcome::Transient { code: Some(450), .. }));
    }

    #[test]
    fn nxdomain_is_permanent_but_other_connect_failures_are_transient() {
        assert!(matches!(
            classify_connect_failure("NXDOMAIN".into(), true),
            Outcome::Permanent { .. }
        ));
        assert!(matches!(
            classify_connect_failure("connection refused".into(), false),
            Outcome::Transient { .. }
        ));
    }
}
