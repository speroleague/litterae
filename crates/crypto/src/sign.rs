//! Ed25519 signing (spec §6: "periodically sign the chain head"). Distinct
//! from the HPKE keypairs elsewhere in this crate -- HPKE encrypts, it
//! cannot sign, and a hash chain alone only proves internal consistency,
//! not that the head hasn't been quietly re-pointed by whoever holds the
//! database.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const PRIVATE_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

pub struct SigningKeypair {
    pub public: [u8; PUBLIC_KEY_LEN],
    pub private: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
}

impl SigningKeypair {
    pub fn generate() -> Self {
        let seed = crate::rand_key::random_key_256();
        let signing_key = SigningKey::from_bytes(&seed);
        Self {
            public: signing_key.verifying_key().to_bytes(),
            private: seed,
        }
    }

    pub fn from_private_bytes(private: [u8; PRIVATE_KEY_LEN]) -> Self {
        let private = Zeroizing::new(private);
        let signing_key = SigningKey::from_bytes(&private);
        Self {
            public: signing_key.verifying_key().to_bytes(),
            private,
        }
    }
}

pub fn sign(keypair: &SigningKeypair, message: &[u8]) -> [u8; SIGNATURE_LEN] {
    let signing_key = SigningKey::from_bytes(&keypair.private);
    signing_key.sign(message).to_bytes()
}

pub fn verify(public: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let signature = Signature::from_bytes(signature);
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let kp = SigningKeypair::generate();
        let sig = sign(&kp, b"chain head");
        assert!(verify(&kp.public, b"chain head", &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = SigningKeypair::generate();
        let sig = sign(&kp, b"chain head");
        assert!(!verify(&kp.public, b"different message", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let kp = SigningKeypair::generate();
        let other = SigningKeypair::generate();
        let sig = sign(&kp, b"chain head");
        assert!(!verify(&other.public, b"chain head", &sig));
    }

    #[test]
    fn same_private_bytes_reproduce_same_keypair() {
        let kp = SigningKeypair::generate();
        let private_bytes = *kp.private;
        let reconstructed = SigningKeypair::from_private_bytes(private_bytes);
        assert_eq!(kp.public, reconstructed.public);
    }
}
