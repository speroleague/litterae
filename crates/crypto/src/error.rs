use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("header error: {0}")]
    Header(#[from] common::Error),

    #[error("AEAD seal failed")]
    SealFailed,

    #[error("AEAD open failed (wrong key, or ciphertext tampered)")]
    OpenFailed,

    #[error("committing-wrap prefix check failed: wrong key or tampered ciphertext")]
    CommitmentFailed,

    #[error("HPKE operation failed: {0}")]
    Hpke(String),

    #[error("KDF operation failed: {0}")]
    Kdf(String),

    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("unexpected alg_id for this operation")]
    WrongAlgorithm,
}
