//! Assembles a raw RFC 5322 message from a JMAP compose request, via
//! `mail_builder::MessageBuilder` (multipart/attachment encoding, MIME
//! boundaries, etc. -- nothing here hand-rolls MIME anymore).
//!
//! `mail_builder` does **not** protect against CRLF header injection on
//! its own (traced: a value containing a well-formed `\r\n` pair never
//! trips its "needs encoding" path and gets written raw). The only thing
//! preventing it is `common::input::valid_header_value`/
//! `valid_email_address`, called on every header-bound value -- including
//! attachment filenames -- before anything reaches the builder. Do not
//! remove these checks under the assumption the "real MIME library"
//! handles it; it doesn't.

use rand::RngExt;

use crate::types::EmailAddressIn;

/// Headers this builder writes, in order. Matches `queue::dkim::SIGNED_HEADERS`
/// (From/To/Subject/Date/Message-ID) plus Cc/In-Reply-To/References, which
/// aren't DKIM-signed but are still real headers a compliant client expects.
pub struct RawMessage {
    pub bytes: Vec<u8>,
    /// Bare, unbracketed (`"hex@domain"`, not `"<hex@domain>"`) -- matches
    /// `mail_parser::Message::message_id()`'s convention for inbound mail,
    /// which is also unbracketed. `store::threads` joins messages by exact
    /// string equality on this column, so compose- and delivery-created
    /// messages must agree on format or reply-threading silently stops
    /// matching by Message-ID (falling back to the subject-hash path).
    pub message_id_header: String,
}

/// A file to attach, already scanned and validated by the caller
/// (`crates/jmap/src/handlers.rs`'s upload handler) -- this module only
/// assembles MIME, it doesn't scan or seal anything.
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// An inline (`cid:`-referenced) image, already resolved from a
/// `POST /jmap/upload` blobId by the caller (`crates/jmap/src/api.rs`).
/// `content_id` is the bare (unbracketed) id referenced from the
/// sanitized HTML's `cid:` src -- `mail_builder`'s `.inline()` brackets
/// it itself when writing the `Content-ID` header, same bracket
/// convention as `Message-ID`.
pub struct InlineImage {
    pub content_id: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    from_address: &str,
    to: &[EmailAddressIn],
    cc: &[EmailAddressIn],
    subject: Option<&str>,
    body_text: Option<&str>,
    body_html: Option<&str>,
    in_reply_to_header: Option<&str>,
    references_header: Option<&str>,
    sent_at: i64,
    attachments: &[Attachment],
    inline_images: &[InlineImage],
) -> Result<RawMessage, String> {
    if !common::input::valid_email_address(from_address)
        || subject.is_some_and(|value| !common::input::valid_header_value(value))
        || in_reply_to_header.is_some_and(|value| !common::input::valid_header_value(value))
        || references_header.is_some_and(|value| !common::input::valid_header_value(value))
        || to.iter().chain(cc.iter()).any(|address| {
            !common::input::valid_email_address(&address.email)
                || address
                    .name
                    .as_deref()
                    .is_some_and(|value| !common::input::valid_header_value(value))
        })
        || attachments.iter().any(|a| {
            !common::input::valid_header_value(&a.filename)
                || !common::input::valid_header_value(&a.content_type)
        })
        || inline_images.iter().any(|img| {
            !common::input::valid_header_value(&img.content_id)
                || !common::input::valid_header_value(&img.content_type)
        })
    {
        return Err("invalid message header value".to_string());
    }

    let message_id = generate_message_id(from_address);

    let mut builder = mail_builder::MessageBuilder::new()
        .from(from_address)
        .message_id(message_id.as_str())
        .date(sent_at)
        .subject(subject.unwrap_or(""))
        .text_body(body_text.unwrap_or(""));

    if let Some(html) = body_html {
        builder = builder.html_body(html.to_string());
    }
    if !to.is_empty() {
        builder = builder.to(to_address_list(to));
    }
    if !cc.is_empty() {
        builder = builder.cc(to_address_list(cc));
    }
    if let Some(irt) = in_reply_to_header {
        builder = builder.in_reply_to(parse_message_ids(irt));
    }
    if let Some(refs) = references_header {
        builder = builder.references(parse_message_ids(refs));
    }
    for attachment in attachments {
        builder = builder.attachment(
            attachment.content_type.clone(),
            attachment.filename.clone(),
            attachment.bytes.clone(),
        );
    }
    for inline_image in inline_images {
        builder = builder.inline(
            inline_image.content_type.clone(),
            inline_image.content_id.clone(),
            inline_image.bytes.clone(),
        );
    }

    let bytes = builder
        .write_to_vec()
        .map_err(|e| format!("failed to assemble message: {e}"))?;

    Ok(RawMessage {
        bytes,
        message_id_header: message_id,
    })
}

fn to_address_list(addrs: &[EmailAddressIn]) -> mail_builder::headers::address::Address<'_> {
    mail_builder::headers::address::Address::new_list(
        addrs
            .iter()
            .map(|a| match &a.name {
                Some(name) if !name.is_empty() => {
                    mail_builder::headers::address::Address::new_address(
                        Some(name.as_str()),
                        a.email.as_str(),
                    )
                }
                _ => mail_builder::headers::address::Address::new_address(
                    None::<&str>,
                    a.email.as_str(),
                ),
            })
            .collect(),
    )
}

/// `mail_builder`'s `MessageId` header writer always wraps each id in
/// `<...>` itself -- callers must hand it bare ids, not pre-bracketed
/// ones (verified: `MessageId::write_header` unconditionally emits `<`
/// and `>` around every entry). `in_reply_to_header`/`references_header`
/// arrive here already RFC-5322-formatted (space-separated, bracketed,
/// e.g. `"<a@b> <c@d>"`), so this splits and strips brackets back off.
fn parse_message_ids(header_value: &str) -> Vec<&str> {
    header_value
        .split_whitespace()
        .map(|id| id.trim_start_matches('<').trim_end_matches('>'))
        .collect()
}

fn generate_message_id(from_address: &str) -> String {
    let domain = from_address
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or("localhost");
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    format!("{}@{}", hex::encode(bytes), domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_includes_recipients_subject_and_body() {
        let msg = build(
            "alice@example.test",
            &[EmailAddressIn {
                name: None,
                email: "bob@example.test".into(),
            }],
            &[],
            Some("Hello"),
            Some("hi there"),
            None,
            None,
            None,
            1_700_000_000,
            &[],
            &[],
        )
        .unwrap();
        let text = String::from_utf8(msg.bytes).unwrap();
        assert!(text.contains("From: <alice@example.test>\r\n"));
        assert!(text.contains("To: <bob@example.test>\r\n"));
        assert!(text.contains("Subject: Hello\r\n"));
        assert!(text.contains("hi there"));
        assert!(!msg.message_id_header.starts_with('<'));
        assert!(msg.message_id_header.ends_with("@example.test"));
        assert!(text.contains(&format!("Message-ID: <{}>", msg.message_id_header)));
    }

    #[test]
    fn build_omits_cc_header_when_empty() {
        let msg = build(
            "alice@example.test",
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            0,
            &[],
            &[],
        )
        .unwrap();
        let text = String::from_utf8(msg.bytes).unwrap();
        assert!(!text.contains("Cc:"));
    }

    #[test]
    fn message_ids_are_unique() {
        let a = generate_message_id("alice@example.test");
        let b = generate_message_id("alice@example.test");
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_header_injection() {
        assert!(build(
            "alice@example.test",
            &[],
            &[],
            Some("hello\r\nBcc: victim@example.net"),
            None,
            None,
            None,
            None,
            0,
            &[],
            &[],
        )
        .is_err());
    }

    #[test]
    fn rejects_header_injection_in_attachment_filename() {
        assert!(build(
            "alice@example.test",
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            0,
            &[Attachment {
                filename: "innocuous.txt\r\nBcc: victim@example.net".to_string(),
                content_type: "text/plain".to_string(),
                bytes: b"hi".to_vec(),
            }],
            &[],
        )
        .is_err());
    }

    #[test]
    fn rejects_header_injection_in_inline_image_content_id() {
        assert!(build(
            "alice@example.test",
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            0,
            &[],
            &[InlineImage {
                content_id: "u1\r\nBcc: victim@example.net".to_string(),
                content_type: "image/png".to_string(),
                bytes: vec![1, 2, 3],
            }],
        )
        .is_err());
    }

    #[test]
    fn attachment_bytes_and_filename_survive_round_trip() {
        let msg = build(
            "alice@example.test",
            &[],
            &[],
            None,
            Some("body"),
            None,
            None,
            None,
            0,
            &[Attachment {
                filename: "invoice.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                bytes: b"%PDF-1.4 fake".to_vec(),
            }],
            &[],
        )
        .unwrap();
        let text = String::from_utf8_lossy(&msg.bytes);
        assert!(text.contains("invoice.pdf"));
        assert!(text.contains("application/pdf"));
        // Base64-encoded attachment content, not the raw bytes verbatim.
        assert!(!text.contains("%PDF-1.4 fake"));
    }

    #[test]
    fn html_and_attachment_nest_as_multipart_alternative_inside_mixed() {
        let msg = build(
            "alice@example.test",
            &[],
            &[],
            None,
            Some("plain body"),
            Some("<p>html body</p>"),
            None,
            None,
            0,
            &[Attachment {
                filename: "invoice.pdf".to_string(),
                content_type: "application/pdf".to_string(),
                bytes: b"%PDF-1.4 fake".to_vec(),
            }],
            &[],
        )
        .unwrap();
        let text = String::from_utf8_lossy(&msg.bytes);
        assert!(text.contains("multipart/alternative"));
        assert!(text.contains("multipart/mixed"));
        assert!(text.contains("Content-Type: text/plain"));
        assert!(text.contains("Content-Type: text/html"));
        assert!(text.contains("Content-Type: application/pdf"));
    }

    #[test]
    fn inline_image_gets_bracketed_content_id_and_inline_disposition() {
        let msg = build(
            "alice@example.test",
            &[],
            &[],
            None,
            Some("see the image"),
            Some(r#"<p>see <img src="cid:u5"></p>"#),
            None,
            None,
            0,
            &[],
            &[InlineImage {
                content_id: "u5".to_string(),
                content_type: "image/png".to_string(),
                bytes: vec![0x89, b'P', b'N', b'G'],
            }],
        )
        .unwrap();
        let text = String::from_utf8_lossy(&msg.bytes);
        assert!(text.contains("Content-ID: <u5>"));
        assert!(text.contains("Content-Disposition: inline"));
        assert!(text.contains("cid:u5"));
        assert!(!text.contains("Content-Disposition: attachment"));
    }

    #[test]
    fn in_reply_to_and_references_are_not_double_bracketed() {
        let msg = build(
            "alice@example.test",
            &[],
            &[],
            None,
            None,
            None,
            Some("<parent@example.net>"),
            Some("<a@example.net> <parent@example.net>"),
            0,
            &[],
            &[],
        )
        .unwrap();
        let text = String::from_utf8(msg.bytes).unwrap();
        assert!(text.contains("In-Reply-To: <parent@example.net>\r\n"));
        assert!(!text.contains("<<parent@example.net>>"));
        assert!(text.contains("References: <a@example.net> <parent@example.net>\r\n"));
    }
}
