//! AEAD trait definitions

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HpkeError;

/// Trait for AEAD implementations
pub trait Aead {
    /// Encrypt and authenticate plaintext
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;

    /// Decrypt and verify ciphertext
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError>;
}
