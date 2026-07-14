//! DKIM key management (RSA-2048, RFC 6376) and signing. One key per
//! sending domain, generated on first use and persisted; the operator
//! publishes the matching DNS TXT record once (`dns_txt_record` renders
//! it). Signing itself is delegated to `mail_auth::dkim`.

use mail_auth::common::crypto::{RsaKey, Sha256};
use mail_auth::dkim::generate::DkimKeyPair;
use mail_auth::dkim::DkimSigner;
use rusqlite::OptionalExtension;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};
use std::time::{SystemTime, UNIX_EPOCH};

use common::{Error, Result};

use crate::schema::{storage_err, QueueStore};

pub const SELECTOR: &str = "litterae";
const RSA_BITS: usize = 2048;
/// Headers DKIM-signed on every outbound message. A fixed, minimal set --
/// covers the fields that matter for spoofing protection without brittling
/// on messages that omit optional headers.
pub const SIGNED_HEADERS: &[&str] = &["From", "To", "Subject", "Date", "Message-ID"];

pub struct DomainKey {
    pub domain: String,
    pub selector: String,
    pub private_der: Vec<u8>,
    pub public_der: Vec<u8>,
}

impl QueueStore {
    /// Returns the domain's DKIM key, generating and persisting a fresh
    /// RSA-2048 keypair on first use.
    pub fn ensure_dkim_key(&self, domain: &str) -> Result<DomainKey> {
        if let Some(key) = self.load_dkim_key(domain)? {
            return Ok(key);
        }

        let keypair = DkimKeyPair::generate_rsa(RSA_BITS)
            .map_err(|e| Error::Crypto(format!("DKIM key generation failed: {e}")))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs() as i64;

        let conn = self.conn.lock().expect("queue store mutex poisoned");
        conn.execute(
            "INSERT INTO dkim_keys (domain, selector, private_der, public_der, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                domain,
                SELECTOR,
                keypair.private_key(),
                keypair.public_key(),
                now
            ],
        )
        .map_err(storage_err)?;

        Ok(DomainKey {
            domain: domain.to_string(),
            selector: SELECTOR.to_string(),
            private_der: keypair.private_key().to_vec(),
            public_der: keypair.public_key().to_vec(),
        })
    }

    fn load_dkim_key(&self, domain: &str) -> Result<Option<DomainKey>> {
        let conn = self.conn.lock().expect("queue store mutex poisoned");
        conn.query_row(
            "SELECT selector, private_der, public_der FROM dkim_keys WHERE domain = ?1",
            (domain,),
            |row| {
                Ok(DomainKey {
                    domain: domain.to_string(),
                    selector: row.get(0)?,
                    private_der: row.get(1)?,
                    public_der: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(storage_err)
    }
}

impl DomainKey {
    /// The DNS TXT record value to publish at
    /// `{selector}._domainkey.{domain}`.
    pub fn dns_txt_record(&self) -> String {
        format!("v=DKIM1; k=rsa; p={}", base64_encode(&self.public_der))
    }

    fn signing_key(&self) -> Result<RsaKey<Sha256>> {
        RsaKey::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(
            self.private_der.clone(),
        )))
        .map_err(|e| Error::Crypto(format!("invalid DKIM private key: {e}")))
    }

    /// Signs `raw_message`, returning the `DKIM-Signature:` header line to
    /// prepend to it.
    pub fn sign(&self, raw_message: &[u8]) -> Result<String> {
        let signing_key = self.signing_key()?;
        let signer = DkimSigner::from_key(signing_key)
            .domain(self.domain.clone())
            .selector(self.selector.clone())
            .headers(SIGNED_HEADERS.iter().copied());
        let signature = signer
            .sign(raw_message)
            .map_err(|e| Error::Crypto(format!("DKIM signing failed: {e}")))?;
        // `Display` on `Signature` renders the relaxed-canonicalized form
        // used internally to compute the signature, not a usable header --
        // `HeaderWriter::to_header()` is what actually produces
        // "DKIM-Signature: ...\r\n".
        Ok(mail_auth::common::headers::HeaderWriter::to_header(
            &signature,
        ))
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_persists_key() {
        let store = QueueStore::open_in_memory().unwrap();
        let key1 = store.ensure_dkim_key("example.com").unwrap();
        let key2 = store.ensure_dkim_key("example.com").unwrap();
        assert_eq!(key1.private_der, key2.private_der);
        assert_eq!(key1.selector, SELECTOR);
    }

    #[test]
    fn different_domains_get_different_keys() {
        let store = QueueStore::open_in_memory().unwrap();
        let key1 = store.ensure_dkim_key("a.example").unwrap();
        let key2 = store.ensure_dkim_key("b.example").unwrap();
        assert_ne!(key1.private_der, key2.private_der);
    }

    #[test]
    fn signs_a_message() {
        let store = QueueStore::open_in_memory().unwrap();
        let key = store.ensure_dkim_key("example.com").unwrap();
        let msg = b"From: a@example.com\r\nTo: b@example.net\r\nSubject: hi\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nbody\r\n";
        let header = key.sign(msg).unwrap();
        assert!(header.contains("d=example.com"));
        assert!(header.contains("s=litterae"));
    }

    #[test]
    fn dns_record_has_expected_shape() {
        let store = QueueStore::open_in_memory().unwrap();
        let key = store.ensure_dkim_key("example.com").unwrap();
        let record = key.dns_txt_record();
        assert!(record.starts_with("v=DKIM1; k=rsa; p="));
    }
}
