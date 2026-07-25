//! TLS-RPT (RFC 8460) DNS record. No ingestion code needed: with a
//! `mailto:` rua, aggregate reports arrive as ordinary inbound mail (a
//! gzip'd JSON attachment) to whatever mailbox the address resolves to --
//! the same delivery path every other message already goes through, not a
//! new feature.

pub fn dns_txt_record(domain: &str, rua_local_part: &str) -> String {
    format!("_smtp._tls.{domain}  IN TXT  \"v=TLSRPTv1; rua=mailto:{rua_local_part}@{domain}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_has_expected_shape() {
        let record = dns_txt_record("example.com", "tlsrpt");
        assert_eq!(
            record,
            "_smtp._tls.example.com  IN TXT  \"v=TLSRPTv1; rua=mailto:tlsrpt@example.com\""
        );
    }
}
