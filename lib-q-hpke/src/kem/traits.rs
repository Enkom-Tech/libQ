//! KEM trait definitions

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HpkeError;

/// Trait for KEM implementations
pub trait Kem {
    /// Generate a key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), HpkeError>;

    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HpkeError>;

    /// Decapsulate a shared secret
    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError>;
}
