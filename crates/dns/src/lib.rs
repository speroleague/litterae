//! DNS lookups the outbound queue needs: MX (RFC 5321 §5) and DANE/TLSA
//! (RFC 6698) records. TLSA records are resolved and returned but not yet
//! enforced against the negotiated TLS certificate -- that requires a
//! custom rustls certificate verifier (RFC 6698 matching-type/DNSSEC-chain
//! validation) that hasn't been built yet. Callers should treat
//! `resolve_tlsa` as informational until that lands.

use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use common::{Error, Result};

pub struct Resolver {
    inner: TokioResolver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    pub cert_usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub cert_data: Vec<u8>,
}

fn resolve_err(e: impl std::fmt::Display) -> Error {
    Error::Config(format!("DNS resolution failed: {e}"))
}

impl Resolver {
    pub fn new() -> Result<Self> {
        let inner = TokioResolver::builder_tokio()
            .map_err(resolve_err)?
            .build()
            .map_err(resolve_err)?;
        Ok(Self { inner })
    }

    /// Resolves MX records for `domain`, sorted by preference (lowest
    /// first). Falls back to treating the domain itself as an implicit MX
    /// (RFC 5321 §5.1) when no MX records are published at all -- common
    /// for small domains. A domain that instead publishes an explicit
    /// "null MX" (RFC 7505: a single record with exchange `.`) is declaring
    /// it accepts no mail; that record is returned as-is rather than
    /// silently swallowed, and callers must treat `exchange == "."` as a
    /// permanent non-deliverable rather than attempting a connection.
    pub async fn resolve_mx(&self, domain: &str) -> Result<Vec<MxRecord>> {
        let fqdn = format!("{}.", domain.trim_end_matches('.'));
        let lookup = self
            .inner
            .lookup(fqdn.as_str(), RecordType::MX)
            .await
            .map_err(resolve_err)?;

        let mut records: Vec<MxRecord> = lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::MX(mx) => Some(MxRecord {
                    preference: mx.preference,
                    exchange: mx.exchange.to_string(),
                }),
                _ => None,
            })
            .collect();

        if records.is_empty() {
            records.push(MxRecord {
                preference: 0,
                exchange: fqdn,
            });
        }
        records.sort_by_key(|r| r.preference);
        Ok(records)
    }

    /// Resolves TLSA records for `_{port}._tcp.{hostname}` (RFC 6698 §3).
    pub async fn resolve_tlsa(&self, port: u16, hostname: &str) -> Result<Vec<TlsaRecord>> {
        let name = format!("_{port}._tcp.{}.", hostname.trim_end_matches('.'));
        let lookup = match self.inner.lookup(name.as_str(), RecordType::TLSA).await {
            Ok(l) => l,
            Err(_) => return Ok(Vec::new()), // no TLSA published, or NXDOMAIN
        };

        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TLSA(tlsa) => Some(TlsaRecord {
                    cert_usage: u8::from(tlsa.cert_usage),
                    selector: u8::from(tlsa.selector),
                    matching: u8::from(tlsa.matching),
                    cert_data: tlsa.cert_data.clone(),
                }),
                _ => None,
            })
            .collect())
    }

    /// Resolves TXT records for `hostname`, one entry per RR (a single TXT
    /// RR can carry multiple `<character-string>` segments, which are
    /// concatenated per RFC 1035 §3.3.14 -- most real-world use, including
    /// SPF/DKIM/verification tokens, treats a TXT value as one logical
    /// string regardless of how it's chunked on the wire). Returns an empty
    /// list rather than an error for NXDOMAIN/no-records, matching
    /// `resolve_tlsa`'s reasoning: "nothing published" is a normal, expected
    /// outcome for a caller checking for an optional record, not a failure.
    pub async fn resolve_txt(&self, hostname: &str) -> Result<Vec<String>> {
        let fqdn = format!("{}.", hostname.trim_end_matches('.'));
        let lookup = match self.inner.lookup(fqdn.as_str(), RecordType::TXT).await {
            Ok(l) => l,
            Err(_) => return Ok(Vec::new()),
        };

        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|chunk| String::from_utf8_lossy(chunk))
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_mx_for_a_real_domain() {
        let resolver = Resolver::new().unwrap();
        let records = resolver.resolve_mx("gmail.com").await.unwrap();
        assert!(!records.is_empty());
        assert!(records
            .windows(2)
            .all(|w| w[0].preference <= w[1].preference));
    }

    #[tokio::test]
    async fn resolves_txt_for_a_real_domain() {
        let resolver = Resolver::new().unwrap();
        let records = resolver.resolve_txt("gmail.com").await.unwrap();
        // gmail.com has published an SPF TXT record for a very long time;
        // a real lookup finding it confirms both the query type and the
        // multi-segment concatenation are correct, not just "returns Ok".
        assert!(records.iter().any(|r| r.contains("spf")));
    }

    #[tokio::test]
    async fn txt_lookup_on_nonexistent_name_returns_empty_not_error() {
        let resolver = Resolver::new().unwrap();
        let records = resolver
            .resolve_txt("this-name-should-not-exist-12345.gmail.com")
            .await
            .unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn mx_lookup_never_returns_empty() {
        // Whatever example.com currently publishes (no records, or an
        // RFC 7505 null MX), resolve_mx must never hand back an empty
        // list -- callers always get a routable-or-explicitly-null answer.
        let resolver = Resolver::new().unwrap();
        let records = resolver.resolve_mx("example.com").await.unwrap();
        assert!(!records.is_empty());
        assert_eq!(records[0].preference, 0);
    }
}
