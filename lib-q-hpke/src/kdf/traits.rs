//! Key Derivation Function (KDF) traits

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::HpkeError;
use crate::types::HpkeKdf;

/// Trait for Key Derivation Functions
pub trait Kdf {
    /// Extract a pseudorandom key from input keying material
    fn extract(&self, kdf: HpkeKdf, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, HpkeError>;

    /// Expand a pseudorandom key to the desired length
    fn expand(
        &self,
        kdf: HpkeKdf,
        prk: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, HpkeError>;

    /// Get the extract length for a given KDF
    fn extract_len(&self, kdf: HpkeKdf) -> usize;
}
