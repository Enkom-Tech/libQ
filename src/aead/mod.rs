//! Authenticated Encryption with Associated Data (AEAD) for libQ
//!
//! This module provides post-quantum AEAD constructions.

use crate::error::{Error, Result};

/// Trait for AEAD operations
pub trait Aead {
    /// Encrypt a message
    fn encrypt(&self, key: &AeadKey, nonce: &Nonce, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt a message
    fn decrypt(&self, key: &AeadKey, nonce: &Nonce, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;
}

/// AEAD key
pub struct AeadKey {
    pub data: Vec<u8>,
}

/// AEAD nonce
pub struct Nonce {
    pub data: Vec<u8>,
}

impl AeadKey {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl Nonce {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}
