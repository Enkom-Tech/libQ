//! KEM trait definitions

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::error::HpkeError;

/// Trait for KEM implementations.
///
/// Secret material (secret keys and shared secrets) is returned in [`Zeroizing`] buffers so it is
/// cleared from memory on drop; public values (public keys, ciphertexts) are plain `Vec<u8>`.
pub trait Kem {
    /// Generate a key pair, returning `(public_key, secret_key)`.
    fn generate_keypair(&self) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError>;

    /// Encapsulate a shared secret, returning `(ciphertext, shared_secret)`.
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError>;

    /// Decapsulate a shared secret.
    fn decapsulate(
        &self,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HpkeError>;
}
