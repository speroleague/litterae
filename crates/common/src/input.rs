//! Validation for strings that cross mail protocol boundaries.
//!
//! These checks are deliberately conservative. Litterae advertises SMTPUTF8,
//! so non-ASCII local parts are allowed, but protocol delimiters, whitespace,
//! and control characters are never valid in the unquoted address form used
//! by the server.

/// Returns true when `value` is safe to place in a single RFC 5322 header
/// field value. Encoding display names is the caller's responsibility; this
/// function's security property is that a value cannot create another header.
pub fn valid_header_value(value: &str) -> bool {
    !value
        .chars()
        .any(|c| c == '\r' || c == '\n' || c == '\0' || c.is_control())
}

/// Validates the addr-spec subset accepted by Litterae for envelope and
/// compose addresses. Quoted local parts and domain literals are intentionally
/// unsupported; accepting them safely requires a real address parser.
pub fn valid_email_address(address: &str) -> bool {
    if address.is_empty() || address.len() > 254 || !valid_header_value(address) {
        return false;
    }
    if address.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | ':' | '\\' | '"'
            )
    }) {
        return false;
    }
    let mut parts = address.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if local.is_empty()
        || domain.is_empty()
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !valid_domain_name(domain)
    {
        return false;
    }
    true
}

pub fn valid_domain_name(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && valid_header_value(domain)
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn valid_local_part(local: &str) -> bool {
    valid_email_address(&format!("{local}@example.invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_and_smtputf8_addresses() {
        assert!(valid_email_address("alice@example.com"));
        assert!(valid_email_address("δοκιμή@example.com"));
    }

    #[test]
    fn rejects_protocol_and_header_injection() {
        for address in [
            "victim@example.com\r\nDATA",
            "a@example.com>\r\nRSET",
            "a b@example.com",
            "a@@example.com",
            "@example.com",
            "a@",
        ] {
            assert!(!valid_email_address(address), "accepted {address:?}");
        }
        assert!(!valid_header_value("hello\r\nBcc: victim@example.com"));
    }
}
