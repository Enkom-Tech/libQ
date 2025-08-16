//! Key Encapsulation Mechanisms (KEMs) for libQ
//!
//! This module provides post-quantum key encapsulation mechanisms.

use crate::error::{Error, Result};

/// Trait for key encapsulation mechanisms
pub trait Kem {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<KemKeypair>;
    
    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Decapsulate a shared secret
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// KEM keypair
pub struct KemKeypair {
    pub public_key: KemPublicKey,
    pub secret_key: KemSecretKey,
}

/// KEM public key
pub struct KemPublicKey {
    pub data: Vec<u8>,
}

/// KEM secret key
pub struct KemSecretKey {
    pub data: Vec<u8>,
}

impl KemKeypair {
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key: KemPublicKey { data: public_key },
            secret_key: KemSecretKey { data: secret_key },
        }
    }
}
