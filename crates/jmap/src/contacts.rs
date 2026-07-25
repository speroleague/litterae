//! Seal/open for address-book entries. Contacts are only ever read or
//! written from an unlocked session -- unlike mail, there's no "a locked
//! server must still be able to write this" requirement -- so they're
//! sealed symmetrically under the account's AMK exactly like the
//! Identity signature (`identity_set`/`load_identity` in `api.rs`), not
//! HPKE-sealed to `account_pub` and not routed through the blob store.

use serde::{Deserialize, Serialize};

use common::{Error, Result};
use crypto::AccountMasterKey;

#[derive(Serialize, Deserialize)]
pub struct ContactPlain {
    pub name: Option<String>,
    pub email: String,
}

pub fn seal_contact(amk: &AccountMasterKey, plain: &ContactPlain) -> Vec<u8> {
    let bytes = serde_json::to_vec(plain).expect("ContactPlain always serializes");
    crypto::aead_seal(amk.as_bytes(), 1, &bytes)
}

pub fn open_contact(amk: &AccountMasterKey, sealed: &[u8]) -> Result<ContactPlain> {
    let opened = crypto::aead_open(amk.as_bytes(), sealed).map_err(|e| Error::Crypto(e.to_string()))?;
    serde_json::from_slice(&opened).map_err(|e| Error::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_amk() -> AccountMasterKey {
        AccountMasterKey::generate()
    }

    #[test]
    fn seal_open_round_trips() {
        let amk = sample_amk();
        let plain = ContactPlain {
            name: Some("Alice".to_string()),
            email: "alice@example.test".to_string(),
        };
        let sealed = seal_contact(&amk, &plain);
        let opened = open_contact(&amk, &sealed).unwrap();
        assert_eq!(opened.name.as_deref(), Some("Alice"));
        assert_eq!(opened.email, "alice@example.test");
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let amk = sample_amk();
        let other = sample_amk();
        let plain = ContactPlain {
            name: None,
            email: "bob@example.test".to_string(),
        };
        let sealed = seal_contact(&amk, &plain);
        assert!(open_contact(&other, &sealed).is_err());
    }
}
