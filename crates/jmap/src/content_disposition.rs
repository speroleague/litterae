//! RFC 6266 `Content-Disposition` filename encoding for attachment
//! downloads. An inbound attachment's filename (`attachment_name()`) is
//! fully attacker-controlled -- this is the thing that keeps it from
//! landing in the response header raw. Always emits `attachment`, never
//! `inline`; the caller is responsible for also setting
//! `X-Content-Type-Options: nosniff` (that's what actually stops an
//! accurate `text/html`/`image/svg+xml` content-type from rendering
//! in-page, not this header).

pub fn attachment_header(filename: &str) -> String {
    let fallback = ascii_fallback(filename);
    if filename.is_ascii() && !needs_extended_encoding(filename) {
        return format!("attachment; filename=\"{fallback}\"");
    }
    format!(
        "attachment; filename=\"{fallback}\"; filename*=UTF-8''{}",
        percent_encode(filename)
    )
}

fn needs_extended_encoding(s: &str) -> bool {
    s.chars().any(|c| c == '"' || c == '\\' || c.is_control())
}

/// Best-effort ASCII fallback for clients that don't understand
/// `filename*=`. Control characters (including `\r`/`\n`) and quoting
/// metacharacters are replaced rather than escaped, since a replaced
/// character can't reopen the header either way.
fn ascii_fallback(filename: &str) -> String {
    let cleaned: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_control() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed.to_string()
    }
}

/// RFC 5987 `ext-value` percent-encoding (used by RFC 6266's `filename*`).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_safe_name_uses_plain_filename_only() {
        let header = attachment_header("invoice.pdf");
        assert_eq!(header, "attachment; filename=\"invoice.pdf\"");
    }

    #[test]
    fn non_ascii_name_adds_extended_parameter() {
        let header = attachment_header("café.pdf");
        assert!(header.starts_with("attachment; filename=\"caf_.pdf\""));
        assert!(header.contains("filename*=UTF-8''caf%C3%A9.pdf"));
    }

    #[test]
    fn crlf_in_filename_never_reaches_the_header() {
        let header = attachment_header("evil\r\nX-Injected: yes.txt");
        assert!(!header.contains('\r'));
        assert!(!header.contains('\n'));
    }

    #[test]
    fn quote_in_filename_is_replaced_not_escaped() {
        let header = attachment_header("quo\"te.txt");
        assert!(!header.contains("\"te.txt\""));
        assert_eq!(header, "attachment; filename=\"quo_te.txt\"; filename*=UTF-8''quo%22te.txt");
    }

    #[test]
    fn empty_filename_falls_back_to_a_placeholder() {
        let header = attachment_header("");
        assert_eq!(header, "attachment; filename=\"attachment\"");
    }
}
