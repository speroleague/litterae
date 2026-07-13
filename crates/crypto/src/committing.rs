//! Key-committing AEAD wrap (spec §3.4), REQUIRED for every password- or
//! recovery-derived wrap (`PK -> AMK`, `RK -> AMK`). Plain XChaCha20-Poly1305
//! is not key-committing, and partitioning-oracle attacks
//! (Len-Grubbs-Ristenpart, USENIX 2021) exploit exactly that when the key is
//! low-entropy -- i.e. password-derived. Per-message DEKs are full-entropy
//! 256-bit and use the plain (non-committing) construction in `aead.rs`
//! instead.
//!
//! Construction (Albertini et al., USENIX 2022 / ePrint 2020/1456): prepend a
//! fixed all-zero prefix to the plaintext before AEAD-encrypting; on decrypt,
//! verify the prefix is intact in constant time before accepting. This is
//! the padding-transform committing construction referenced by RFC 9771.

use chacha20poly1305::{aead::Aead, Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngExt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use common::header::{AgilityHeader, AlgId};

use crate::error::{CryptoError, Result};

/// 128-bit zero prefix: within the spec's "<= 512 bits / 4 blocks" allowance,
/// and well beyond the security margin needed to make forging a valid prefix
/// under a wrong key computationally infeasible.
const ZERO_PREFIX_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Seals `plaintext` (typically a 32-byte AMK) under a password- or
/// recovery-derived `key`, using the committing construction. `key_id`
/// identifies which PK/RK generation this was wrapped under (for password
/// rotation bookkeeping).
pub fn committing_seal(key: &[u8; 32], key_id: u16, plaintext: &[u8]) -> Vec<u8> {
    let mut prefixed = vec![0u8; ZERO_PREFIX_LEN + plaintext.len()];
    prefixed[ZERO_PREFIX_LEN..].copy_from_slice(plaintext);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce: XNonce = nonce_bytes.into();

    let cipher_key: Key = (*key).into();
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    // Encryption of a fixed-format, bounded-length buffer under a fresh
    // random nonce cannot fail.
    let ciphertext = cipher
        .encrypt(&nonce, prefixed.as_slice())
        .expect("XChaCha20Poly1305 encryption of committing wrap cannot fail");

    let header = AgilityHeader::new(
        AlgId::CommittingWrapXChaCha20Poly1305,
        key_id,
        nonce_bytes.to_vec(),
    );
    let mut out = header.encode();
    out.extend_from_slice(&ciphertext);
    out
}

/// Opens a blob sealed by `committing_seal`. Returns `CommitmentFailed` if
/// the key is wrong (whether or not the AEAD tag happens to verify) or the
/// ciphertext was tampered with.
pub fn committing_open(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (header, ciphertext) = AgilityHeader::decode(sealed)?;
    if header.alg_id != AlgId::CommittingWrapXChaCha20Poly1305 {
        return Err(CryptoError::WrongAlgorithm);
    }
    let nonce: XNonce = XNonce::try_from(header.nonce.as_slice())
        .map_err(|_| CryptoError::InvalidKey("bad nonce length".into()))?;

    let cipher_key: Key = (*key).into();
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let opened = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::OpenFailed)?;
    let opened = Zeroizing::new(opened);

    if opened.len() < ZERO_PREFIX_LEN {
        return Err(CryptoError::CommitmentFailed);
    }
    let (prefix, plaintext) = opened.split_at(ZERO_PREFIX_LEN);
    let zero_prefix = [0u8; ZERO_PREFIX_LEN];
    // Constant-time: do not let a timing side-channel leak how much of the
    // prefix matched.
    if prefix.ct_eq(&zero_prefix).unwrap_u8() != 1 {
        return Err(CryptoError::CommitmentFailed);
    }

    Ok(Zeroizing::new(plaintext.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = [3u8; 32];
        let amk = [9u8; 32];
        let sealed = committing_seal(&key, 1, &amk);
        let opened = committing_open(&key, &sealed).unwrap();
        assert_eq!(&opened[..], &amk[..]);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [3u8; 32];
        let wrong_key = [4u8; 32];
        let amk = [9u8; 32];
        let sealed = committing_seal(&key, 1, &amk);
        assert!(committing_open(&wrong_key, &sealed).is_err());
    }

    #[test]
    fn tampered_prefix_rejected() {
        // Directly exercise the commitment check: craft ciphertext where the
        // AEAD tag verifies (same key) but the decrypted prefix is nonzero,
        // simulating a forged low-entropy-key collision.
        let key = [3u8; 32];
        let mut prefixed = vec![1u8; ZERO_PREFIX_LEN]; // non-zero prefix
        prefixed.extend_from_slice(&[9u8; 32]);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill(&mut nonce_bytes);
        let nonce: XNonce = nonce_bytes.into();
        let cipher_key: Key = key.into();
        let cipher = XChaCha20Poly1305::new(&cipher_key);
        let ciphertext = cipher.encrypt(&nonce, prefixed.as_slice()).unwrap();

        let header = AgilityHeader::new(
            AlgId::CommittingWrapXChaCha20Poly1305,
            1,
            nonce_bytes.to_vec(),
        );
        let mut sealed = header.encode();
        sealed.extend_from_slice(&ciphertext);

        assert!(matches!(
            committing_open(&key, &sealed),
            Err(CryptoError::CommitmentFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = [3u8; 32];
        let amk = [9u8; 32];
        let mut sealed = committing_seal(&key, 1, &amk);
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(committing_open(&key, &sealed).is_err());
    }
}
