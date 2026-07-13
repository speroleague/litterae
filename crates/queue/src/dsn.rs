//! DSN / bounce generation (RFC 3464, RFC 3461). Built as a
//! multipart/report with a human-readable part, a machine-readable
//! `message/delivery-status` part, and (if `RET=FULL`) the original
//! message. Loop guards live in `worker.rs`, which never calls this for a
//! message whose envelope-from is `<>` or that's itself a DSN.

use mail_builder::mime::MimePart;
use mail_builder::MessageBuilder;

use common::{Error, Result};

pub enum DsnAction {
    Failed,
    Delayed,
}

impl DsnAction {
    fn as_str(&self) -> &'static str {
        match self {
            DsnAction::Failed => "failed",
            DsnAction::Delayed => "delayed",
        }
    }
}

pub struct FailedRecipient<'a> {
    pub rcpt_to: &'a str,
    pub action: DsnAction,
    pub status: Option<&'a str>,
    pub diagnostic: &'a str,
}

pub struct DsnInput<'a> {
    pub reporting_mta: &'a str,
    pub original_envelope_from: &'a str,
    pub original_subject: Option<&'a str>,
    pub recipients: &'a [FailedRecipient<'a>],
    /// Original message bytes to attach, if `RET=FULL` was requested.
    pub original_message: Option<&'a [u8]>,
}

/// Builds the DSN as raw RFC 5322 bytes, ready to hand to `delivery`/`queue`
/// for local delivery to `original_envelope_from`.
pub fn build_dsn(input: &DsnInput) -> Result<Vec<u8>> {
    let mut human_readable = String::new();
    human_readable.push_str("This is an automatically generated Delivery Status Notification.\r\n\r\n");
    for rcpt in input.recipients {
        match rcpt.action {
            DsnAction::Failed => human_readable.push_str(&format!(
                "Delivery to the following recipient failed permanently:\r\n\r\n  {}\r\n\r\n{}\r\n\r\n",
                rcpt.rcpt_to, rcpt.diagnostic
            )),
            DsnAction::Delayed => human_readable.push_str(&format!(
                "Delivery to the following recipient has been delayed:\r\n\r\n  {}\r\n\r\n{}\r\n\r\n",
                rcpt.rcpt_to, rcpt.diagnostic
            )),
        }
    }

    let mut status = format!("Reporting-MTA: dns;{}\r\n\r\n", input.reporting_mta);
    for rcpt in input.recipients {
        status.push_str(&format!("Final-Recipient: rfc822;{}\r\n", rcpt.rcpt_to));
        status.push_str(&format!("Action: {}\r\n", rcpt.action.as_str()));
        if let Some(s) = rcpt.status {
            status.push_str(&format!("Status: {s}\r\n"));
        }
        status.push_str(&format!("Diagnostic-Code: smtp;{}\r\n\r\n", rcpt.diagnostic));
    }

    let mut report_parts = vec![
        MimePart::new("text/plain", human_readable),
        MimePart::new("message/delivery-status", status),
    ];
    if let Some(original) = input.original_message {
        report_parts.push(MimePart::raw(original.to_vec()));
    }

    let body = MimePart::new(
        "multipart/report;report-type=delivery-status",
        report_parts,
    );

    let subject = match input.recipients.first().map(|r| &r.action) {
        Some(DsnAction::Delayed) => "Delivery delayed",
        _ => "Delivery Status Notification (Failure)",
    };
    let _ = input.original_subject; // kept for future inclusion in the human-readable part

    MessageBuilder::new()
        .from((
            "Mail Delivery Subsystem".to_string(),
            format!("mailer-daemon@{}", input.reporting_mta),
        ))
        .to(input.original_envelope_from)
        .subject(subject)
        .header("Auto-Submitted", mail_builder::headers::raw::Raw::new("auto-replied"))
        .body(body)
        .write_to_vec()
        .map_err(|e| Error::Storage(format!("failed to build DSN: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_failure_dsn() {
        let recipients = [FailedRecipient {
            rcpt_to: "bob@example.net",
            action: DsnAction::Failed,
            status: Some("5.1.1"),
            diagnostic: "550 5.1.1 No such user",
        }];
        let input = DsnInput {
            reporting_mta: "mx.example.com",
            original_envelope_from: "alice@example.com",
            original_subject: Some("hi"),
            recipients: &recipients,
            original_message: None,
        };
        let raw = build_dsn(&input).unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("multipart/report"));
        assert!(text.contains("Final-Recipient: rfc822;bob@example.net"));
        assert!(text.contains("Action: failed"));
        assert!(text.contains("Status: 5.1.1"));
        assert!(text.contains("Auto-Submitted: auto-replied"));
        assert!(text.contains("To: <alice@example.com>"));
    }
}
