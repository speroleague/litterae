//! Assembles a raw RFC 5322 message from a JMAP compose request. The one
//! place in this crate that writes MIME instead of reading it.

use rand::RngExt;

use crate::types::EmailAddressIn;

/// Headers this builder writes, in order. Matches `queue::dkim::SIGNED_HEADERS`
/// (From/To/Subject/Date/Message-ID) plus Cc/In-Reply-To/References, which
/// aren't DKIM-signed but are still real headers a compliant client expects.
pub struct RawMessage {
    pub bytes: Vec<u8>,
    pub message_id_header: String,
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    from_address: &str,
    to: &[EmailAddressIn],
    cc: &[EmailAddressIn],
    subject: Option<&str>,
    body_text: Option<&str>,
    in_reply_to_header: Option<&str>,
    references_header: Option<&str>,
    sent_at: i64,
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
    {
        return Err("invalid message header value".to_string());
    }
    let message_id_header = generate_message_id(from_address);

    let mut raw = String::new();
    raw.push_str(&format!("From: {from_address}\r\n"));
    if !to.is_empty() {
        raw.push_str(&format!("To: {}\r\n", format_address_list(to)));
    }
    if !cc.is_empty() {
        raw.push_str(&format!("Cc: {}\r\n", format_address_list(cc)));
    }
    raw.push_str(&format!("Subject: {}\r\n", subject.unwrap_or("")));
    raw.push_str(&format!("Date: {}\r\n", rfc2822(sent_at)));
    raw.push_str(&format!("Message-ID: {message_id_header}\r\n"));
    if let Some(irt) = in_reply_to_header {
        raw.push_str(&format!("In-Reply-To: {irt}\r\n"));
    }
    if let Some(refs) = references_header {
        raw.push_str(&format!("References: {refs}\r\n"));
    }
    raw.push_str("MIME-Version: 1.0\r\n");
    raw.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    raw.push_str("\r\n");
    raw.push_str(body_text.unwrap_or(""));

    Ok(RawMessage {
        bytes: raw.into_bytes(),
        message_id_header,
    })
}

fn format_address_list(addrs: &[EmailAddressIn]) -> String {
    addrs
        .iter()
        .map(|a| match &a.name {
            Some(name) if !name.is_empty() => format!("{name} <{}>", a.email),
            _ => a.email.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn generate_message_id(from_address: &str) -> String {
    let domain = from_address
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or("localhost");
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    format!("<{}@{}>", hex::encode(bytes), domain)
}

/// RFC 5322 §3.3 Date header. A minimal formatter (UTC only, matching
/// `email::iso8601`'s reasoning for not pulling in a datetime crate for one
/// field) -- this one just needs weekday/month names on top of the same
/// civil-date math.
fn rfc2822(unix_secs: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days_since_epoch = unix_secs.div_euclid(86400);
    let secs_of_day = unix_secs.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days_since_epoch);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    // Unix epoch (1970-01-01) was a Thursday, i.e. offset 0 into WEEKDAYS.
    let weekday = WEEKDAYS[days_since_epoch.rem_euclid(7) as usize];
    let month_name = MONTHS[(month - 1) as usize];

    format!("{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} +0000")
}

/// Howard Hinnant's `civil_from_days` algorithm -- duplicated from
/// `email.rs` rather than shared, since that copy is private to this crate
/// and small enough that a shared module would be more ceremony than the
/// ~10 lines it saves.
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
    fn rfc2822_formats_known_timestamp() {
        // 2024-01-15T12:30:00Z was a Monday.
        assert_eq!(rfc2822(1_705_321_800), "Mon, 15 Jan 2024 12:30:00 +0000");
    }

    #[test]
    fn rfc2822_formats_epoch_thursday() {
        assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

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
            1_700_000_000,
        )
        .unwrap();
        let text = String::from_utf8(msg.bytes).unwrap();
        assert!(text.contains("From: alice@example.test\r\n"));
        assert!(text.contains("To: bob@example.test\r\n"));
        assert!(text.contains("Subject: Hello\r\n"));
        assert!(text.ends_with("hi there"));
        assert!(msg.message_id_header.starts_with('<'));
        assert!(msg.message_id_header.ends_with("@example.test>"));
    }

    #[test]
    fn build_omits_cc_header_when_empty() {
        let msg = build("alice@example.test", &[], &[], None, None, None, None, 0).unwrap();
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
            0,
        )
        .is_err());
    }
}
