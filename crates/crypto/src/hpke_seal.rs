//! HPKE (RFC 9180) base mode, classical X25519 DHKEM (spec §3.5), the public
//! key half of the "locked server is a pure producer" principle (spec §3.1):
//! `account.pub`, `index_pub`, and `audit_pub` are all cleartext, so a
//! locked server can seal to them (inbound mail, search fragments, audit
//! entries) without ever holding a decryption key.
//!
//! Base mode is unauthenticated -- that is fine (anyone may write to your
//! inbox), but the seal proves nothing about *who* wrote it. Sender identity
//! (DKIM/ARC results) must be carried as separate authenticated metadata,
//! never inferred from the seal (spec §3.5).
//!
//! This is the single crate-internal seam for the v1 -> PQ-HPKE migration
//! (spec §3.6, §10): only `Kem`/`Kdf`/`Aead` below change.

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use zeroize::Zeroizing;

use common::header::{AgilityHeader, AlgId};

use crate::error::{CryptoError, Result};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const PRIVATE_KEY_LEN: usize = 32;

/// A classical X25519 HPKE keypair. The public half is meant to be held in
/// cleartext (account/index/audit ambient inbound keys, spec §3.2-3.3); the
/// private half must always be wrapped under the AMK before it touches disk
/// (see `keys.rs`).
pub struct HpkeKeypair {
    pub public: [u8; PUBLIC_KEY_LEN],
    pub private: Zeroizing<[u8; PRIVATE_KEY_LEN]>,
}

impl HpkeKeypair {
    pub fn generate() -> Self {
        let (sk, pk) = Kem::gen_keypair();
        let mut public = [0u8; PUBLIC_KEY_LEN];
        public.copy_from_slice(&pk.to_bytes());
        let mut private = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
        private.copy_from_slice(&sk.to_bytes());
        Self { public, private }
    }
}

/// Seals `plaintext` to `pub_key`. `info` is HPKE's context-binding string
/// (not secret, but must match between seal and open -- e.g. distinguish
/// "message DEK" from "search index fragment" seals under the same key).
/// `key_id` records which key generation `pub_key` belongs to, for rotation.
pub fn hpke_seal(
    pub_key: &[u8; PUBLIC_KEY_LEN],
    key_id: u16,
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(pub_key)
        .map_err(|e| CryptoError::Hpke(format!("bad public key: {e:?}")))?;
    let (encapped, ciphertext) =
        single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &pk, info, plaintext, &[])
            .map_err(|e| CryptoError::Hpke(format!("seal failed: {e:?}")))?;

    let header = AgilityHeader::new(
        AlgId::HpkeX25519Sha256ChaCha20Poly1305,
        key_id,
        encapped.to_bytes().to_vec(),
    );
    let mut out = header.encode();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a blob sealed by `hpke_seal`. `info` must match what was passed to
/// `hpke_seal`.
pub fn hpke_open(
    priv_key: &[u8; PRIVATE_KEY_LEN],
    info: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let (header, ciphertext) = AgilityHeader::decode(sealed)?;
    if header.alg_id != AlgId::HpkeX25519Sha256ChaCha20Poly1305 {
        return Err(CryptoError::WrongAlgorithm);
    }
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(priv_key)
        .map_err(|e| CryptoError::Hpke(format!("bad private key: {e:?}")))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&header.nonce)
        .map_err(|e| CryptoError::Hpke(format!("bad encapped key: {e:?}")))?;

    let plaintext = single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        info,
        ciphertext,
        &[],
    )
    .map_err(|_| CryptoError::OpenFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &[u8] = b"litterae/test-dek-v1";

    #[test]
    fn round_trips() {
        let kp = HpkeKeypair::generate();
        let sealed = hpke_seal(&kp.public, 1, INFO, b"a 32-byte per-message DEK.......").unwrap();
        let opened = hpke_open(&kp.private, INFO, &sealed).unwrap();
        assert_eq!(&opened[..], b"a 32-byte per-message DEK.......");
    }

    #[test]
    fn wrong_key_fails() {
        let kp = HpkeKeypair::generate();
        let other = HpkeKeypair::generate();
        let sealed = hpke_seal(&kp.public, 1, INFO, b"secret").unwrap();
        assert!(hpke_open(&other.private, INFO, &sealed).is_err());
    }

    #[test]
    fn mismatched_info_fails() {
        let kp = HpkeKeypair::generate();
        let sealed = hpke_seal(&kp.public, 1, INFO, b"secret").unwrap();
        assert!(hpke_open(&kp.private, b"different-info", &sealed).is_err());
    }

    #[test]
    fn locked_server_can_seal_without_private_key() {
        // The core invariant of spec §3.1: sealing to a cleartext public key
        // requires no private key material at all.
        let kp = HpkeKeypair::generate();
        let pub_only = kp.public;
        let sealed = hpke_seal(&pub_only, 1, INFO, b"inbound mail while locked").unwrap();
        let opened = hpke_open(&kp.private, INFO, &sealed).unwrap();
        assert_eq!(&opened[..], b"inbound mail while locked");
    }
}
