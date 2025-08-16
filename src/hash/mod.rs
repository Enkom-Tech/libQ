//! Hash Functions for libQ
//!
//! This module provides SHA-3 family hash functions.

use crate::error::{Error, Result};

/// Trait for hash functions
pub trait Hash {
    /// Hash data
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Get the output size in bytes
    fn output_size(&self) -> usize;
}

/// Hash algorithm types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHAKE256
    Shake256,
    /// SHAKE128
    Shake128,
    /// cSHAKE256
    CShake256,
}

impl HashAlgorithm {
    /// Get the output size for this algorithm
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Shake256 => 32,
            HashAlgorithm::Shake128 => 16,
            HashAlgorithm::CShake256 => 32,
        }
    }
}
