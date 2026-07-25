//! MTA-STS (RFC 8461) policy generation. litterae doesn't serve this
//! dynamically -- same "litterae prints the record, the operator
//! publishes it" pattern as `queue::dkim::DomainKey::dns_txt_record`. The
//! operator saves `policy_file_body()`'s output as a static file served
//! at `https://mta-sts.<domain>/.well-known/mta-sts.txt` (Caddy already
//! fronts every other public surface in the default deployment, so this
//! is one more static site block, not new application code) and publishes
//! the `_mta-sts` TXT record below.

use sha2::{Digest, Sha256};

pub struct MtaStsPolicy {
    /// "enforce" or "testing" per RFC 8461 §3 -- start with "testing"
    /// (report-only, no delivery impact) until validators are green.
    pub mode: String,
    /// The MX hostname this policy covers, e.g. "mail.yourdomain.com".
    pub mx: String,
    /// How long senders may cache this policy, in seconds.
    pub max_age: u32,
}

impl MtaStsPolicy {
    pub fn policy_file_body(&self) -> String {
        format!(
            "version: STSv1\nmode: {}\nmx: {}\nmax_age: {}\n",
            self.mode, self.mx, self.max_age
        )
    }

    /// RFC 8461 §3.2 requires this to change whenever the policy content
    /// changes, so caching senders know to refetch -- a content hash
    /// satisfies that without needing to persist a version counter
    /// anywhere. Capped at the spec's 32-character id limit (32 hex chars
    /// = 16 hashed bytes).
    pub fn id(&self) -> String {
        let digest = Sha256::digest(self.policy_file_body().as_bytes());
        hex::encode(&digest[..16])
    }

    pub fn dns_txt_record(&self, domain: &str) -> String {
        format!("_mta-sts.{domain}  IN TXT  \"v=STSv1; id={}\"", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> MtaStsPolicy {
        MtaStsPolicy {
            mode: "testing".to_string(),
            mx: "mail.example.com".to_string(),
            max_age: 604800,
        }
    }

    #[test]
    fn policy_body_has_expected_shape() {
        let body = sample().policy_file_body();
        assert!(body.contains("version: STSv1"));
        assert!(body.contains("mode: testing"));
        assert!(body.contains("mx: mail.example.com"));
        assert!(body.contains("max_age: 604800"));
    }

    #[test]
    fn id_is_stable_for_the_same_policy() {
        assert_eq!(sample().id(), sample().id());
    }

    #[test]
    fn id_changes_when_policy_content_changes() {
        let mut changed = sample();
        changed.mode = "enforce".to_string();
        assert_ne!(sample().id(), changed.id());
    }

    #[test]
    fn id_is_within_the_32_char_rfc_limit() {
        assert_eq!(sample().id().len(), 32);
    }

    #[test]
    fn dns_record_has_expected_shape() {
        let record = sample().dns_txt_record("example.com");
        assert!(record.starts_with("_mta-sts.example.com"));
        assert!(record.contains("v=STSv1"));
        assert!(record.contains(&format!("id={}", sample().id())));
    }
}
