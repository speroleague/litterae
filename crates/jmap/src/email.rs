//! Turns a stored (sealed) message into a JMAP `Email` object. This is the
//! one place that actually decrypts message content -- it always requires
//! the account's private key, i.e. the mailbox must be unlocked.

use std::collections::HashMap;

use mail_parser::{MessageParser, MimeHeaders};

use store::{BlobStore, StoredMessage};

use crate::html_sanitize::{self, CidImages, ALLOWED_CID_IMAGE_TYPES};
use crate::types::{EmailAddress, EmailAttachment, EmailObject};

const PREVIEW_LEN: usize = 200;

pub fn open_and_parse(
    blobs: &BlobStore,
    stored: &StoredMessage,
    account_priv: &[u8; crypto::hpke_seal::PRIVATE_KEY_LEN],
) -> common::Result<EmailObject> {
    let raw = delivery::open_message(blobs, stored, account_priv)?;
    let message = MessageParser::default().parse(&raw);

    // Attachments already live inside the one sealed blob this message
    // is -- no separate storage, just metadata pulled from the same
    // parse. Bytes are read on demand at download time (regular
    // downloads), except inline images, whose bytes are needed right
    // here to resolve `cid:` references in the HTML body below -- both
    // built from one enumeration pass, not two.
    let mut attachments = Vec::new();
    let mut cid_images: CidImages = HashMap::new();
    if let Some(m) = &message {
        for (index, part) in m.attachments().enumerate() {
            let content_type = part
                .content_type()
                .map(|ct| match &ct.c_subtype {
                    Some(sub) => format!("{}/{sub}", ct.c_type),
                    None => ct.c_type.to_string(),
                })
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let contents = part.contents();
            attachments.push(EmailAttachment {
                blob_id: format!("m{}.{}", stored.id, index),
                name: part.attachment_name().unwrap_or("attachment").to_string(),
                content_type: content_type.clone(),
                size: contents.len() as i64,
            });
            if let Some(cid) = part.content_id() {
                if ALLOWED_CID_IMAGE_TYPES.contains(&content_type.as_str()) {
                    cid_images.insert(cid.to_string(), (content_type, contents.to_vec()));
                }
            }
        }
    }

    let (from, to, subject, body_text, sanitized_html) = match &message {
        Some(m) => (
            addresses(m.from()),
            addresses(m.to()),
            m.subject().map(|s| s.to_string()),
            m.body_text(0).map(|s| s.to_string()),
            (m.html_body_count() > 0)
                .then(|| m.body_html(0))
                .flatten()
                .map(|html| html_sanitize::sanitize(&html, &cid_images)),
        ),
        None => (Vec::new(), Vec::new(), None, None, None),
    };

    let preview = body_text
        .as_deref()
        .map(|text| truncate(text, PREVIEW_LEN))
        .unwrap_or_default();

    let mut mailbox_ids = HashMap::new();
    mailbox_ids.insert(format!("b{}", stored.mailbox_id), true);
    let keywords = stored
        .keywords
        .split(',')
        .filter(|k| !k.is_empty())
        .map(|k| (k.to_string(), true))
        .collect();

    Ok(EmailObject {
        id: format!("m{}", stored.id),
        thread_id: format!("t{}", stored.thread_id),
        mailbox_ids,
        keywords,
        from,
        to,
        subject,
        received_at: iso8601(stored.received_at),
        preview,
        body_text,
        size: stored.size_bytes,
        message_id: stored.message_id_header.clone(),
        in_reply_to_message_id: stored.in_reply_to.clone(),
        spam_score: stored.spam_score,
        av_clean: stored.av_clean,
        body_html: sanitized_html.as_ref().map(|s| s.html.clone()),
        blocked_image_count: sanitized_html.as_ref().map(|s| s.blocked_image_count),
        attachments,
    })
}

fn addresses(addr: Option<&mail_parser::Address>) -> Vec<EmailAddress> {
    let Some(addr) = addr else {
        return Vec::new();
    };
    addr.as_list()
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    a.address().map(|email| EmailAddress {
                        name: a.name().map(|n| n.to_string()),
                        email: email.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn truncate(text: &str, max_chars: usize) -> String {
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        collapsed
    } else {
        collapsed.chars().take(max_chars).collect::<String>() + "…"
    }
}

fn iso8601(unix_secs: i64) -> String {
    // A minimal RFC 3339 formatter (UTC only) so this crate doesn't need a
    // full datetime dependency for one field.
    let days_since_epoch = unix_secs.div_euclid(86400);
    let secs_of_day = unix_secs.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days_since_epoch);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days` algorithm (proleptic Gregorian, days
/// since 1970-01-01) -- avoids pulling in a datetime crate for one field.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_formats_known_timestamp() {
        // 2024-01-15T12:30:00Z
        assert_eq!(iso8601(1_705_321_800), "2024-01-15T12:30:00Z");
    }

    #[test]
    fn iso8601_formats_epoch() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn truncate_short_text_is_unchanged() {
        assert_eq!(truncate("hello world", 200), "hello world");
    }

    #[test]
    fn truncate_long_text_is_cut_with_ellipsis() {
        let long = "a".repeat(300);
        let result = truncate(&long, 200);
        assert_eq!(result.chars().count(), 201); // 200 + ellipsis char
        assert!(result.ends_with('…'));
    }
}
