//! Digital Signatures for libQ
//!
//! This module provides post-quantum digital signature schemes.

use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait for digital signatures
pub trait Signature {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<SigKeypair>;

    /// Sign a message
    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature
    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Signature keypair with automatic memory zeroization
pub struct SigKeypair {
    pub public_key: SigPublicKey,
    pub secret_key: SigSecretKey,
}

/// Signature public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigPublicKey {
    pub data: Vec<u8>,
}

/// Signature secret key with automatic memory zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigSecretKey {
    pub data: Vec<u8>,
}

impl SigKeypair {
    /// Create a new signature keypair
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key data
    /// * `secret_key` - The secret key data (will be zeroized on drop)
    ///
    /// # Returns
    ///
    /// A new signature keypair
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key: SigPublicKey { data: public_key },
            secret_key: SigSecretKey { data: secret_key },
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &SigPublicKey {
        &self.public_key
    }

    /// Get the secret key (use with caution)
    pub fn secret_key(&self) -> &SigSecretKey {
        &self.secret_key
    }
}

impl SigPublicKey {
    /// Create a new public key
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the key data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the key size
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

impl SigSecretKey {
    /// Create a new secret key
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the key data (use with caution)
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the key size
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

// Implement Debug for SigSecretKey (but don't show the actual data)
impl std::fmt::Debug for SigSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigSecretKey")
            .field("data", &"[REDACTED]")
            .field("size", &self.data.len())
            .finish()
    }
}

// Implement PartialEq and Eq for SigSecretKey (constant-time comparison)
impl PartialEq for SigSecretKey {
    fn eq(&self, other: &Self) -> bool {
        if self.data.len() != other.data.len() {
            return false;
        }

        // Constant-time comparison
        let mut result = 0u8;
        for (a, b) in self.data.iter().zip(other.data.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl Eq for SigSecretKey {}

// Implement Zeroize for SigKeypair to zeroize the secret key
impl Zeroize for SigKeypair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

// Implement ZeroizeOnDrop for SigKeypair
impl Drop for SigKeypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_keypair_creation() {
        let public_key = vec![1, 2, 3, 4];
        let secret_key = vec![5, 6, 7, 8];

        let keypair = SigKeypair::new(public_key.clone(), secret_key.clone());

        assert_eq!(keypair.public_key.data, public_key);
        assert_eq!(keypair.secret_key.data, secret_key);
    }

    #[test]
    fn test_sig_public_key() {
        let data = vec![1, 2, 3, 4];
        let public_key = SigPublicKey::new(data.clone());

        assert_eq!(public_key.data(), &data);
        assert_eq!(public_key.size(), 4);
    }

    #[test]
    fn test_sig_secret_key() {
        let data = vec![1, 2, 3, 4];
        let secret_key = SigSecretKey::new(data.clone());

        assert_eq!(secret_key.data(), &data);
        assert_eq!(secret_key.size(), 4);
    }

    #[test]
    fn test_secret_key_constant_time_comparison() {
        let key1 = SigSecretKey::new(vec![1, 2, 3, 4]);
        let key2 = SigSecretKey::new(vec![1, 2, 3, 4]);
        let key3 = SigSecretKey::new(vec![1, 2, 3, 5]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
