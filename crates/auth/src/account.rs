//! An account is one local mailbox (`local_part@domain`) and the single
//! crypto boundary in v1 (spec §3.2, §10): no key ever wraps across an
//! account boundary.

#[derive(Debug, Clone)]
pub struct Account {
    pub id: i64,
    pub local_part: String,
    pub domain: String,
    /// Current account HPKE key generation, for rotation bookkeeping.
    pub key_id: u16,
    /// Argon2id salt for this account's unlock KDF.
    pub salt: [u8; crypto::kdf::SALT_LEN],
    /// `commit_wrap(PK, AMK)` -- opaque ciphertext, safe to read while
    /// locked.
    pub wrapped_amk: Vec<u8>,
    /// Cleartext by design (spec §3.1): a locked server seals inbound mail
    /// to this key without ever holding the private half.
    pub account_pub: [u8; crypto::hpke_seal::PUBLIC_KEY_LEN],
    /// `wrap(AMK, account_priv)` -- opaque ciphertext.
    pub wrapped_account_priv: Vec<u8>,
    pub created_at: i64,
}

impl Account {
    pub fn address(&self) -> String {
        format!("{}@{}", self.local_part, self.domain)
    }
}
