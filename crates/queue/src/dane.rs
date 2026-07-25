//! DANE-EE(3)/SPKI(1)/SHA-256(1) TLS certificate verification (RFC 6698
//! §2.1, RFC 7671 §4.2) -- the one TLSA profile Claude.md scopes this to.
//! `dns::Resolver::resolve_tlsa` has already done the DNSSEC validation;
//! this module only does the cryptographic cert check inside the TLS
//! handshake itself, via a custom `rustls::client::danger::ServerCertVerifier`
//! plugged into `mail_send::SmtpClientBuilder::tls_connector`.
//!
//! Deliberately does **not** stub out `verify_tls12/13_signature` the way
//! `mail_send`'s own `DummyVerifier` (used for `allow_invalid_certs()`)
//! does -- an SPKI-hash match only proves *which* certificate is expected,
//! not that the remote holds its private key. Real signature verification
//! (delegated to `rustls::crypto::verify_tls12/13_signature` against a
//! real `WebPkiSupportedAlgorithms`) is what proves that. Skipping it
//! would let an attacker replay a legitimate leaf cert's public bytes
//! (passing the hash check) while forging the handshake signature, for a
//! full MITM despite "matching" DANE -- confirmed present as a real bug
//! in Stalwart's own production `DummyVerifier` (same authors as
//! `mail_send`), not a hypothetical.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::prelude::FromDer;

use dns::TlsaRecord;

const USAGE_DANE_EE: u8 = 3;
const SELECTOR_SPKI: u8 = 1;
const MATCHING_SHA256: u8 = 1;

#[derive(Debug)]
pub struct DaneVerifier {
    /// Empty means "TLSA records existed but none matched the supported
    /// profile" -- deliberately not a separate code path from "no
    /// records at all": an empty list makes `verify_server_cert` reject
    /// every certificate by construction, which is exactly the fail-
    /// closed behavior an unsupported-but-present TLSA record needs (an
    /// attacker can't force a downgrade by advertising a profile this
    /// verifier doesn't implement).
    expected_spki_sha256: Vec<[u8; 32]>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl DaneVerifier {
    /// `None` if `records` is empty -- callers use that to mean "no DANE
    /// required for this host," distinct from "DANE required but nothing
    /// will match" (a non-empty `records` list that just doesn't contain
    /// a supported profile still produces `Some` with an empty hash set).
    pub fn new(records: &[TlsaRecord]) -> Option<Self> {
        if records.is_empty() {
            return None;
        }
        let expected_spki_sha256 = records
            .iter()
            .filter(|r| {
                r.cert_usage == USAGE_DANE_EE
                    && r.selector == SELECTOR_SPKI
                    && r.matching == MATCHING_SHA256
                    && r.cert_data.len() == 32
            })
            .map(|r| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&r.cert_data);
                hash
            })
            .collect();
        let supported_algs = rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms;
        Some(Self {
            expected_spki_sha256,
            supported_algs,
        })
    }
}

impl ServerCertVerifier for DaneVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        let spki_hash = Sha256::digest(cert.public_key().raw);

        if self
            .expected_spki_sha256
            .iter()
            .any(|expected| expected.as_slice() == spki_hash.as_slice())
        {
            Ok(ServerCertVerified::assertion())
        } else {
            // RFC 7671 §4.2: for DANE-EE, expiry/hostname/CA-chain checks
            // are explicitly not required -- the pinned cert *is* the
            // trust anchor. Not performing them here is intentional, not
            // an oversight.
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Builds a `rustls::ClientConfig` around a [`DaneVerifier`], ready to
/// wrap in a `tokio_rustls::TlsConnector` and assign to
/// `SmtpClientBuilder::tls_connector`. Uses an explicit `aws_lc_rs`
/// provider instance rather than the process-wide default (never
/// installed anywhere in this codebase today) so this doesn't depend on
/// install order or on anything else in the process having set one up.
pub fn client_config(verifier: DaneVerifier) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws_lc_rs's own default provider supports its own default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlsa(cert_usage: u8, selector: u8, matching: u8, cert_data: Vec<u8>) -> TlsaRecord {
        TlsaRecord {
            cert_usage,
            selector,
            matching,
            cert_data,
        }
    }

    /// A real self-signed cert (via `rcgen`) and its actual SPKI SHA-256 --
    /// exercises the real x509 parsing + hashing path, not a stub.
    fn generate_test_cert() -> (CertificateDer<'static>, [u8; 32]) {
        let cert = rcgen::generate_simple_self_signed(vec!["mx.example.test".to_string()])
            .expect("rcgen can self-sign a simple cert");
        let der = cert.cert.der().clone();
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
            .expect("rcgen output is valid DER");
        let hash: [u8; 32] = Sha256::digest(parsed.public_key().raw).into();
        (der, hash)
    }

    #[test]
    fn new_returns_none_for_no_records() {
        assert!(DaneVerifier::new(&[]).is_none());
    }

    #[test]
    fn new_filters_to_the_dane_ee_spki_sha256_profile_only() {
        let matching = tlsa(3, 1, 1, vec![1u8; 32]);
        let wrong_usage = tlsa(2, 1, 1, vec![2u8; 32]);
        let wrong_selector = tlsa(3, 0, 1, vec![3u8; 32]);
        let wrong_matching = tlsa(3, 1, 2, vec![4u8; 32]);
        let verifier =
            DaneVerifier::new(&[matching, wrong_usage, wrong_selector, wrong_matching]).unwrap();
        assert_eq!(verifier.expected_spki_sha256, vec![[1u8; 32]]);
    }

    #[test]
    fn unsupported_profile_still_fails_closed_via_empty_hash_set() {
        // TLSA records exist, but none match the profile this verifier
        // supports -- must not be treated as "no DANE required."
        let verifier = DaneVerifier::new(&[tlsa(2, 0, 2, vec![9u8; 64])]).unwrap();
        assert!(verifier.expected_spki_sha256.is_empty());

        let (cert, _) = generate_test_cert();
        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("mx.example.test").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn accepts_a_certificate_matching_the_pinned_spki_hash() {
        let (cert, hash) = generate_test_cert();
        let verifier = DaneVerifier::new(&[tlsa(3, 1, 1, hash.to_vec())]).unwrap();

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("mx.example.test").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_a_certificate_with_a_different_spki_hash() {
        let (cert, _) = generate_test_cert();
        let verifier = DaneVerifier::new(&[tlsa(3, 1, 1, vec![0xAB; 32])]).unwrap();

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("mx.example.test").unwrap(),
            &[],
            UnixTime::now(),
        );
        assert!(matches!(
            result,
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        ));
    }

    #[test]
    fn supported_verify_schemes_is_non_empty() {
        // Sanity check that the real WebPkiSupportedAlgorithms wiring
        // (not a stub) is actually in place.
        let verifier = DaneVerifier::new(&[tlsa(3, 1, 1, vec![1u8; 32])]).unwrap();
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    /// A real TLS handshake over a real socket, both sides doing real
    /// crypto -- not calling `verify_server_cert` directly like the tests
    /// above. Proves the verifier is actually wired correctly into
    /// rustls's handshake state machine (right trait methods invoked at
    /// the right times) rather than just being individually correct in
    /// isolation.
    #[tokio::test]
    async fn real_tls_handshake_accepts_matching_cert_and_rejects_mismatched_cert() {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["mx.example.test".to_string()]).unwrap();
        let cert_der = cert.der().clone();
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
            .expect("rcgen output is valid DER");
        let correct_hash: [u8; 32] = Sha256::digest(parsed.public_key().raw).into();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                // Each connection just needs the handshake to complete (or
                // fail) -- no protocol beyond TLS itself matters here.
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });

        let matching = DaneVerifier::new(&[tlsa(3, 1, 1, correct_hash.to_vec())]).unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_config(matching));
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(
                ServerName::try_from("mx.example.test").unwrap().to_owned(),
                stream,
            )
            .await;
        assert!(
            result.is_ok(),
            "handshake with a matching DANE-EE cert must succeed: {:?}",
            result.err()
        );

        let mismatched = DaneVerifier::new(&[tlsa(3, 1, 1, vec![0xABu8; 32])]).unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_config(mismatched));
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = connector
            .connect(
                ServerName::try_from("mx.example.test").unwrap().to_owned(),
                stream,
            )
            .await;
        assert!(
            result.is_err(),
            "handshake with a mismatched DANE-EE cert must fail, not silently succeed"
        );
    }
}
