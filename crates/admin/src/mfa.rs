//! TOTP construction and recovery-code hashing for admin MFA (spec §8.4).
//! Persistence lives in `store.rs`; this module only handles the stateless
//! crypto/encoding around it.

use rand::RngExt;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, TOTP};

/// 160 bits -- RFC 4226's recommended minimum secret length.
const SECRET_LEN: usize = 20;
const RECOVERY_CODE_COUNT: usize = 8;
/// 80 bits of entropy per code: unlike a user-chosen password, this is
/// never guessed, so a fast hash (below) is fine -- no Argon2id needed.
const RECOVERY_CODE_BYTES: usize = 10;

pub fn generate_secret() -> Vec<u8> {
    let mut bytes = [0u8; SECRET_LEN];
    rand::rng().fill(&mut bytes);
    bytes.to_vec()
}

/// `issuer` is shown alongside the account name in the user's authenticator
/// app -- the server's own domain, so multiple litterae instances don't
/// collide in one app.
fn totp_for(secret: Vec<u8>, issuer: &str, username: &str) -> TOTP {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some(issuer.to_string()),
        username.to_string(),
    )
    .expect("fixed digit count, step, and RFC-4226-length secret always validate")
}

pub fn provisioning_uri(secret: Vec<u8>, issuer: &str, username: &str) -> String {
    totp_for(secret, issuer, username).get_url()
}

pub fn secret_base32(secret: Vec<u8>, issuer: &str, username: &str) -> String {
    totp_for(secret, issuer, username).get_secret_base32()
}

pub fn check_code(secret: Vec<u8>, issuer: &str, username: &str, code: &str) -> bool {
    totp_for(secret, issuer, username)
        .check_current(code)
        .unwrap_or(false)
}

/// Returns `(plaintext codes to show once, hashes to persist)`. Plaintext
/// codes are never stored -- only shown to the admin at confirm time.
pub fn generate_recovery_codes() -> (Vec<String>, Vec<String>) {
    let mut plaintext = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut hashed = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut raw = [0u8; RECOVERY_CODE_BYTES];
        rand::rng().fill(&mut raw);
        let code = hex::encode(raw);
        hashed.push(hash_recovery_code(&code));
        plaintext.push(code);
    }
    (plaintext, hashed)
}

fn hash_recovery_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

/// Checks `candidate` against the stored hash list. Returns the index to
/// remove on success so the caller can persist the shrunk list -- each code
/// is single-use.
pub fn match_recovery_code(candidate: &str, hashed: &[String]) -> Option<usize> {
    let candidate_hash = hash_recovery_code(candidate);
    hashed.iter().position(|stored| {
        stored
            .as_bytes()
            .ct_eq(candidate_hash.as_bytes())
            .unwrap_u8()
            == 1
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_code_verifies() {
        let secret = generate_secret();
        let totp = totp_for(secret.clone(), "litterae.test", "admin");
        let code = totp.generate_current().unwrap();
        assert!(check_code(secret, "litterae.test", "admin", &code));
    }

    #[test]
    fn wrong_code_is_rejected() {
        let secret = generate_secret();
        assert!(!check_code(secret, "litterae.test", "admin", "000000"));
    }

    #[test]
    fn recovery_codes_are_unique_and_match_once() {
        let (plaintext, hashed) = generate_recovery_codes();
        assert_eq!(plaintext.len(), RECOVERY_CODE_COUNT);
        let unique: std::collections::HashSet<_> = plaintext.iter().collect();
        assert_eq!(unique.len(), RECOVERY_CODE_COUNT);

        let idx = match_recovery_code(&plaintext[3], &hashed).unwrap();
        assert_eq!(idx, 3);
    }

    #[test]
    fn unknown_recovery_code_does_not_match() {
        let (_, hashed) = generate_recovery_codes();
        assert!(match_recovery_code("not-a-real-code", &hashed).is_none());
    }
}
