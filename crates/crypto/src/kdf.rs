//! Argon2id unlock KDF (spec §3.5): `password --Argon2id(salt, params)--> PK`.
//! PK is never stored and never touches disk; it only ever wraps the AMK
//! (see `amk.rs`).

use argon2::{Algorithm, Argon2, Params, Version};
use common::config::Argon2Config;
use rand::RngExt;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

pub const SALT_LEN: usize = 16;
pub const PK_LEN: usize = 32;

/// Random per-account salt for the unlock KDF. Not secret; stored alongside
/// the wrapped AMK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salt(pub [u8; SALT_LEN]);

impl Salt {
    pub fn generate() -> Self {
        let mut bytes = [0u8; SALT_LEN];
        rand::rng().fill(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }
}

/// The password-derived key (PK). Held only transiently in memory to unwrap
/// or rewrap the AMK; never persisted (spec §3.1, §3.2).
pub struct PasswordKey(pub(crate) Zeroizing<[u8; PK_LEN]>);

impl PasswordKey {
    pub fn as_bytes(&self) -> &[u8; PK_LEN] {
        &self.0
    }
}

/// Runs Argon2id over `password` with `salt` and `config`, producing PK.
/// Params floor per spec §3.5: m = 64 MiB, t = 3, p = 4 (RFC 9106
/// second-recommended); tune upward toward ~0.5-1.0s wall clock on the
/// target host via `config`.
pub fn derive_pk(password: &[u8], salt: &Salt, config: &Argon2Config) -> Result<PasswordKey> {
    let params = Params::new(
        config.m_cost_kib,
        config.t_cost,
        config.p_cost,
        Some(PK_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; PK_LEN]);
    argon2
        .hash_password_into(password, &salt.0, out.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(PasswordKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_config() -> Argon2Config {
        // Minimal-but-valid params so tests run quickly; production uses the
        // config-driven floor (64 MiB / t=3 / p=4).
        Argon2Config {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn same_password_and_salt_are_deterministic() {
        let salt = Salt::generate();
        let cfg = fast_config();
        let pk1 = derive_pk(b"hunter2", &salt, &cfg).unwrap();
        let pk2 = derive_pk(b"hunter2", &salt, &cfg).unwrap();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn different_password_differs() {
        let salt = Salt::generate();
        let cfg = fast_config();
        let pk1 = derive_pk(b"hunter2", &salt, &cfg).unwrap();
        let pk2 = derive_pk(b"hunter3", &salt, &cfg).unwrap();
        assert_ne!(pk1.as_bytes(), pk2.as_bytes());
    }
}
