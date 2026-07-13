//! Wrapping the private halves of the account/index/audit HPKE keypairs
//! under the AMK (spec §3.2: `wrap(AMK, priv)`). These are full-entropy
//! 256-bit-keyed wraps, so the plain (non-committing) AEAD construction is
//! sufficient -- the committing construction in `committing.rs` exists
//! specifically for the *low-entropy* password/recovery-derived layers.

use zeroize::Zeroizing;

use crate::aead::{aead_open, aead_seal};
use crate::amk::AccountMasterKey;
use crate::error::Result;

/// Wraps a private key's raw bytes under the AMK.
pub fn wrap_priv_key(amk: &AccountMasterKey, key_id: u16, priv_key: &[u8]) -> Vec<u8> {
    aead_seal(amk.as_bytes(), key_id, priv_key)
}

/// Unwraps a private key previously wrapped by `wrap_priv_key`.
pub fn unwrap_priv_key(amk: &AccountMasterKey, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    aead_open(amk.as_bytes(), wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke_seal::HpkeKeypair;

    #[test]
    fn wraps_account_private_key() {
        let amk = AccountMasterKey::generate();
        let account = HpkeKeypair::generate();

        let wrapped = wrap_priv_key(&amk, 1, account.private.as_slice());
        let unwrapped = unwrap_priv_key(&amk, &wrapped).unwrap();
        assert_eq!(&unwrapped[..], account.private.as_slice());
    }

    #[test]
    fn wrong_amk_fails() {
        let amk = AccountMasterKey::generate();
        let other_amk = AccountMasterKey::generate();
        let account = HpkeKeypair::generate();

        let wrapped = wrap_priv_key(&amk, 1, account.private.as_slice());
        assert!(unwrap_priv_key(&other_amk, &wrapped).is_err());
    }
}
