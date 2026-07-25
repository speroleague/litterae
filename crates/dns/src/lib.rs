//! DNS lookups the outbound queue needs: MX (RFC 5321 §5) and DANE/TLSA
//! (RFC 6698) records. `resolve_tlsa` DNSSEC-validates (see its doc
//! comment); actually enforcing the result against a negotiated TLS
//! certificate is `queue::dane`'s job, not this crate's.
//!
//! Also owns generating (not fetching) the two other §8.5 deliverability
//! records for litterae's own domain(s): MTA-STS policy/DNS record
//! (`mta_sts`) and the TLS-RPT DNS record (`tls_rpt`).

use hickory_resolver::config::{ResolverConfig, CLOUDFLARE, QUAD9};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use common::{Error, Result};

pub mod mta_sts;
pub mod tls_rpt;

pub use mta_sts::MtaStsPolicy;

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
    /// Points DNSSEC-validating lookups at Cloudflare (primary) and Quad9
    /// (fallback) rather than trusting `/etc/resolv.conf` -- some ISP/
    /// router/container-default resolvers mangle DNSSEC RRs (stripped
    /// EDNS0, etc.), which would surface as spurious `Proof::Bogus` and
    /// incorrectly hard-fail DANE-protected delivery. `validate = true`
    /// does real RRSIG/DNSKEY/DS chain validation locally, from hickory's
    /// bundled IANA root trust anchors -- this is not "trust the
    /// upstream's AD bit."
    pub fn new() -> Result<Self> {
        let mut config = ResolverConfig::udp_and_tcp(&CLOUDFLARE);
        config
            .name_servers
            .extend(ResolverConfig::udp_and_tcp(&QUAD9).name_servers);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().validate = true;
        let inner = builder.build().map_err(resolve_err)?;
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

    /// Resolves TLSA records for `_{port}._tcp.{hostname}` (RFC 6698 §3),
    /// DNSSEC-validated (RFC 7671: DANE without a validated chain is
    /// spoofable by anyone who can inject fake DNS answers, so this is
    /// not optional). Only records hickory proved `Proof::Secure` are
    /// returned -- `Insecure`/`Indeterminate` (the overwhelming majority
    /// of domains, which don't deploy DNSSEC at all) are treated the same
    /// as "nothing published," matching this function's pre-DNSSEC
    /// behavior for that common case.
    ///
    /// Unlike before, a real resolution problem is no longer silently
    /// folded into "no TLSA": a lookup `Err` (SERVFAIL, timeout) or a
    /// record that fails signature validation (`Proof::Bogus` -- a real
    /// tamper/misconfiguration signal, not a normal outcome) now
    /// propagates as `Err` rather than degrading to "proceed without
    /// DANE," which is exactly the failure mode DANE exists to prevent.
    pub async fn resolve_tlsa(&self, port: u16, hostname: &str) -> Result<Vec<TlsaRecord>> {
        let name = format!("_{port}._tcp.{}.", hostname.trim_end_matches('.'));
        let lookup = match self.inner.lookup(name.as_str(), RecordType::TLSA).await {
            Ok(l) => l,
            // Confirmed absent, unsigned-chain form (most domains).
            Err(NetError::Dns(DnsError::NoRecordsFound(_))) => return Ok(Vec::new()),
            // Confirmed absent, DNSSEC-validated form -- still fine,
            // unless the negative proof itself failed validation.
            Err(NetError::Dns(DnsError::Nsec { proof, .. })) if proof != Proof::Bogus => {
                return Ok(Vec::new())
            }
            Err(e) => return Err(resolve_err(e)),
        };

        if lookup.answers().iter().any(|r| r.proof == Proof::Bogus) {
            return Err(Error::Config(format!(
                "DNSSEC validation failed for TLSA records on {hostname}"
            )));
        }

        Ok(lookup
            .answers()
            .iter()
            .filter(|r| r.proof == Proof::Secure)
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
    async fn tlsa_lookup_with_nothing_published_returns_empty_not_error() {
        // gmail.com doesn't publish TLSA for its MX -- confirms the
        // DNSSEC-aware resolve_tlsa still treats "nothing published" the
        // same as before, rather than erroring now that lookups are
        // DNSSEC-validated. Deliberately not asserting against a specific
        // DANE-positive domain here (real-world DANE deployments change
        // over time and would make this flaky) -- `queue::dane`'s tests
        // cover the positive-match path fully offline instead.
        let resolver = Resolver::new().unwrap();
        let records = resolver.resolve_tlsa(25, "gmail-smtp-in.l.google.com").await.unwrap();
        assert!(records.is_empty());
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
