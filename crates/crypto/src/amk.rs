//! The Account Master Key (AMK) hierarchy (spec §3.2). AMK is a random
//! 256-bit symmetric key; it is the single indirection point that makes
//! password change cheap (re-wrap one 32-byte blob) and lets multiple unlock
//! paths (password, recovery key, future second device) each independently
//! wrap the same AMK.

use zeroize::Zeroizing;

use crate::committing::{committing_open, committing_seal};
use crate::error::Result;
use crate::kdf::PasswordKey;

pub const AMK_LEN: usize = 32;

/// Account Master Key: random 256-bit symmetric key, never stored, never at
/// rest except as `commit_wrap(PK, AMK)` (or `commit_wrap(RK, AMK)` for the
/// recovery path).
pub struct AccountMasterKey(pub(crate) Zeroizing<[u8; AMK_LEN]>);

impl AccountMasterKey {
    pub fn generate() -> Self {
        Self(crate::rand_key::random_key_256())
    }

    pub fn as_bytes(&self) -> &[u8; AMK_LEN] {
        &self.0
    }
}

/// Wraps the AMK under a password- or recovery-derived key (PK or RK) using
/// the committing construction (spec §3.4). `key_id` distinguishes wrap
/// generations across password changes.
pub fn wrap_amk(pk: &PasswordKey, key_id: u16, amk: &AccountMasterKey) -> Vec<u8> {
    committing_seal(pk.as_bytes(), key_id, amk.as_bytes().as_slice())
}

/// Unwraps an AMK previously wrapped by `wrap_amk`. Fails (indistinguishably
/// from a tampered blob, by design) if `pk` does not match the wrapping key.
pub fn unwrap_amk(pk: &PasswordKey, wrapped: &[u8]) -> Result<AccountMasterKey> {
    let opened = committing_open(pk.as_bytes(), wrapped)?;
    let mut bytes = Zeroizing::new([0u8; AMK_LEN]);
    bytes.copy_from_slice(&opened);
    Ok(AccountMasterKey(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_pk, Salt};
    use common::config::Argon2Config;

    fn fast_config() -> Argon2Config {
        Argon2Config {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let salt = Salt::generate();
        let cfg = fast_config();
        let pk = derive_pk(b"correct horse battery staple", &salt, &cfg).unwrap();
        let amk = AccountMasterKey::generate();

        let wrapped = wrap_amk(&pk, 1, &amk);
        let unwrapped = unwrap_amk(&pk, &wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), amk.as_bytes());
    }

    #[test]
    fn password_change_only_rewraps_one_blob() {
        let salt = Salt::generate();
        let cfg = fast_config();
        let old_pk = derive_pk(b"old password", &salt, &cfg).unwrap();
        let amk = AccountMasterKey::generate();
        let wrapped_old = wrap_amk(&old_pk, 1, &amk);

        // Password change: derive new PK, rewrap the same AMK bytes. The
        // mailbox itself (blobs, wraps under AMK) is untouched.
        let new_salt = Salt::generate();
        let new_pk = derive_pk(b"new password", &new_salt, &cfg).unwrap();
        let wrapped_new = wrap_amk(&new_pk, 2, &amk);

        assert!(unwrap_amk(&old_pk, &wrapped_new).is_err());
        let unwrapped = unwrap_amk(&new_pk, &wrapped_new).unwrap();
        assert_eq!(unwrapped.as_bytes(), amk.as_bytes());
        // Old wrap remains valid under the old PK until explicitly discarded.
        assert_eq!(unwrap_amk(&old_pk, &wrapped_old).unwrap().as_bytes(), amk.as_bytes());
    }
}
