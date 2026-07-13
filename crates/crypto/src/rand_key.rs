//! Single source of randomness for freshly-minted 256-bit symmetric keys
//! (AMK generation, per-message DEK generation). Keeping this in one place
//! matches spec §1's rule that only `crypto` touches key material directly.

use rand::RngExt;
use zeroize::Zeroizing;

pub fn random_key_256() -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rng().fill(bytes.as_mut());
    bytes
}
