//! Digital Signatures for libQ
//!
//! This module provides post-quantum digital signature schemes.

use crate::error::{Error, Result};

/// Trait for digital signatures
pub trait Signature {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<SigKeypair>;
    
    /// Sign a message
    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>>;
    
    /// Verify a signature
    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Signature keypair
pub struct SigKeypair {
    pub public_key: SigPublicKey,
    pub secret_key: SigSecretKey,
}

/// Signature public key
pub struct SigPublicKey {
    pub data: Vec<u8>,
}

/// Signature secret key
pub struct SigSecretKey {
    pub data: Vec<u8>,
}

impl SigKeypair {
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key: SigPublicKey { data: public_key },
            secret_key: SigSecretKey { data: secret_key },
        }
    }
}
