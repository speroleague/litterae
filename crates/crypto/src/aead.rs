//! Plain (non-committing) XChaCha20-Poly1305 AEAD (spec §3.5), for
//! full-entropy 256-bit keys where partitioning-oracle attacks don't apply:
//! per-message DEK blob encryption, and AMK-wrapped private-key wraps
//! (`wrap(AMK, account_priv)`, `wrap(AMK, index_priv)`, `wrap(AMK,
//! audit_priv)`).
//!
//! 192-bit random nonces are collision-safe with no counter coordination,
//! which matters because DEKs are minted concurrently across the delivery
//! path.

use chacha20poly1305::{aead::Aead as _, Key, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngExt;
use zeroize::Zeroizing;

use common::header::{AgilityHeader, AlgId};

use crate::error::{CryptoError, Result};

const NONCE_LEN: usize = 24;

/// Seals `plaintext` under a full-entropy 256-bit `key`. `key_id` identifies
/// the key generation (for rotation bookkeeping).
pub fn aead_seal(key: &[u8; 32], key_id: u16, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill(&mut nonce_bytes);
    let nonce: XNonce = nonce_bytes.into();

    let cipher_key: Key = (*key).into();
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20Poly1305 encryption cannot fail");

    let header = AgilityHeader::new(AlgId::XChaCha20Poly1305, key_id, nonce_bytes.to_vec());
    let mut out = header.encode();
    out.extend_from_slice(&ciphertext);
    out
}

/// Opens a blob sealed by `aead_seal`.
pub fn aead_open(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (header, ciphertext) = AgilityHeader::decode(sealed)?;
    if header.alg_id != AlgId::XChaCha20Poly1305 {
        return Err(CryptoError::WrongAlgorithm);
    }
    let nonce: XNonce = XNonce::try_from(header.nonce.as_slice())
        .map_err(|_| CryptoError::InvalidKey("bad nonce length".into()))?;

    let cipher_key: Key = (*key).into();
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let opened = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::OpenFailed)?;
    Ok(Zeroizing::new(opened))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = [5u8; 32];
        let sealed = aead_seal(&key, 1, b"a per-message DEK, 32 bytes long");
        let opened = aead_open(&key, &sealed).unwrap();
        assert_eq!(&opened[..], b"a per-message DEK, 32 bytes long");
    }

    #[test]
    fn wrong_key_fails() {
        let key = [5u8; 32];
        let wrong = [6u8; 32];
        let sealed = aead_seal(&key, 1, b"secret");
        assert!(aead_open(&wrong, &sealed).is_err());
    }

    #[test]
    fn nonces_are_random_per_call() {
        let key = [5u8; 32];
        let a = aead_seal(&key, 1, b"same plaintext");
        let b = aead_seal(&key, 1, b"same plaintext");
        assert_ne!(a, b, "identical plaintext must not produce identical ciphertext");
    }
}
