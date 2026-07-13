//! The crypto-agility header (spec §3.6): every wrapped/sealed blob on disk
//! starts with this fixed header. `crypto` dispatches on `alg_id`; no other
//! crate ever inspects these bytes. This is the entire reason migrating DEK
//! sealing to a PQ HPKE suite later touches no plaintext and no other crate.

use crate::error::{Error, Result};

pub const MAGIC: [u8; 4] = *b"LTR1";
pub const HEADER_VERSION: u8 = 1;

/// Algorithm identifiers for wrapped/sealed blobs. Values are stable on disk;
/// never renumber a shipped variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AlgId {
    /// Committing AEAD wrap (zero-prefix construction, §3.4) over
    /// XChaCha20-Poly1305, used for password/recovery-derived key wraps
    /// (PK -> AMK, RK -> AMK).
    CommittingWrapXChaCha20Poly1305 = 1,
    /// Plain (non-committing) XChaCha20-Poly1305 AEAD, used for full-entropy
    /// keys: per-message DEK blob encryption, AMK-wrapped private key wraps.
    XChaCha20Poly1305 = 2,
    /// HPKE (RFC 9180) base mode, classical X25519 DHKEM, HKDF-SHA256,
    /// ChaCha20-Poly1305 AEAD. Used for account/index/audit pubkey seals.
    HpkeX25519Sha256ChaCha20Poly1305 = 3,
}

impl AlgId {
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            1 => Ok(AlgId::CommittingWrapXChaCha20Poly1305),
            2 => Ok(AlgId::XChaCha20Poly1305),
            3 => Ok(AlgId::HpkeX25519Sha256ChaCha20Poly1305),
            other => Err(Error::Crypto(format!("unknown alg_id {other}"))),
        }
    }
}

/// Fixed header prepended to every wrapped/sealed blob:
/// `magic | version:u8 | alg_id:u16 | key_id:u16 | nonce_len:u16 | nonce`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgilityHeader {
    pub version: u8,
    pub alg_id: AlgId,
    /// Identifies which key (by rotation generation) this blob is sealed/wrapped
    /// under. Opaque to `common`; `crypto` and `auth` assign meaning.
    pub key_id: u16,
    /// Algorithm-specific nonce / encapsulated-key material (e.g. a 24-byte
    /// XChaCha20-Poly1305 nonce, or an HPKE `enc` value).
    pub nonce: Vec<u8>,
}

impl AgilityHeader {
    pub fn new(alg_id: AlgId, key_id: u16, nonce: Vec<u8>) -> Self {
        Self {
            version: HEADER_VERSION,
            alg_id,
            key_id,
            nonce,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 2 + 2 + 2 + self.nonce.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.extend_from_slice(&self.alg_id.to_u16().to_be_bytes());
        out.extend_from_slice(&self.key_id.to_be_bytes());
        out.extend_from_slice(&(self.nonce.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Decodes a header from the front of `buf`, returning the header and the
    /// remaining bytes (the ciphertext payload).
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < 4 + 1 + 2 + 2 + 2 {
            return Err(Error::Crypto("truncated agility header".into()));
        }
        let (magic, rest) = buf.split_at(4);
        if magic != MAGIC {
            return Err(Error::Crypto("bad magic on agility header".into()));
        }
        let (version, rest) = (rest[0], &rest[1..]);
        let (alg_bytes, rest) = rest.split_at(2);
        let alg_id = AlgId::from_u16(u16::from_be_bytes([alg_bytes[0], alg_bytes[1]]))?;
        let (key_id_bytes, rest) = rest.split_at(2);
        let key_id = u16::from_be_bytes([key_id_bytes[0], key_id_bytes[1]]);
        let (nonce_len_bytes, rest) = rest.split_at(2);
        let nonce_len = u16::from_be_bytes([nonce_len_bytes[0], nonce_len_bytes[1]]) as usize;
        if rest.len() < nonce_len {
            return Err(Error::Crypto("truncated agility header nonce".into()));
        }
        let (nonce, payload) = rest.split_at(nonce_len);
        Ok((
            Self {
                version,
                alg_id,
                key_id,
                nonce: nonce.to_vec(),
            },
            payload,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let h = AgilityHeader::new(AlgId::XChaCha20Poly1305, 7, vec![1, 2, 3, 4]);
        let mut encoded = h.encode();
        encoded.extend_from_slice(b"payload-bytes");
        let (decoded, payload) = AgilityHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(payload, b"payload-bytes");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = vec![0u8; 20];
        bytes[0..4].copy_from_slice(b"XXXX");
        assert!(AgilityHeader::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated() {
        assert!(AgilityHeader::decode(&[1, 2, 3]).is_err());
    }
}
