//! HMAC-SHA256 (spec §6): chains the audit log by a *keyed* hash of each
//! entry's plaintext rather than a plain hash, so verifying the chain does
//! not itself leak a dictionary oracle over sealed entry contents to anyone
//! without the chain key.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const KEY_LEN: usize = 32;
pub const HASH_LEN: usize = 32;

pub fn keyed_hash(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_key_and_data() {
        let key = [7u8; KEY_LEN];
        assert_eq!(keyed_hash(&key, b"hello"), keyed_hash(&key, b"hello"));
    }

    #[test]
    fn different_keys_diverge() {
        let a = keyed_hash(&[1u8; KEY_LEN], b"hello");
        let b = keyed_hash(&[2u8; KEY_LEN], b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn different_data_diverges() {
        let key = [7u8; KEY_LEN];
        assert_ne!(keyed_hash(&key, b"hello"), keyed_hash(&key, b"world"));
    }
}
