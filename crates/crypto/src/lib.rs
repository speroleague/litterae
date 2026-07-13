//! All cryptographic operations live here and nowhere else (spec §1, §3).
//! Every other crate calls these typed helpers; none of them import a
//! cipher/KEM/KDF directly. That keeps the crypto-agility header
//! (`common::AgilityHeader`) enforced in one place and makes a future PQ
//! migration a one-crate change (spec §3.6, §10).

pub mod aead;
pub mod amk;
pub mod committing;
pub mod error;
pub mod hpke_seal;
pub mod kdf;
pub mod keyed_hash;
pub mod keys;
pub mod rand_key;
pub mod sign;

pub use error::{CryptoError, Result};

pub use aead::{aead_open, aead_seal};
pub use amk::{unwrap_amk, wrap_amk, AccountMasterKey};
pub use committing::{committing_open, committing_seal};
pub use hpke_seal::{hpke_open, hpke_seal, HpkeKeypair};
pub use kdf::{derive_pk, PasswordKey, Salt};
pub use keyed_hash::keyed_hash;
pub use keys::{unwrap_priv_key, wrap_priv_key};
pub use rand_key::random_key_256;
pub use sign::{sign, verify, SigningKeypair};
