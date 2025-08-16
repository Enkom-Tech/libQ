//! Key Encapsulation Mechanisms (KEMs) for lib-Q
//!
//! This module provides post-quantum key encapsulation mechanisms.

use crate::error::Result;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait for key encapsulation mechanisms
pub trait Kem {
    /// Generate a keypair
    fn generate_keypair(&self) -> Result<KemKeypair>;

    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &KemPublicKey) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a shared secret
    fn decapsulate(&self, secret_key: &KemSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// KEM keypair with automatic memory zeroization
pub struct KemKeypair {
    pub public_key: KemPublicKey,
    pub secret_key: KemSecretKey,
}

/// KEM public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublicKey {
    pub data: Vec<u8>,
}

/// KEM secret key with automatic memory zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemSecretKey {
    pub data: Vec<u8>,
}

impl KemKeypair {
    /// Create a new KEM keypair
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key data
    /// * `secret_key` - The secret key data (will be zeroized on drop)
    ///
    /// # Returns
    ///
    /// A new KEM keypair
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key: KemPublicKey { data: public_key },
            secret_key: KemSecretKey { data: secret_key },
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &KemPublicKey {
        &self.public_key
    }

    /// Get the secret key (use with caution)
    pub fn secret_key(&self) -> &KemSecretKey {
        &self.secret_key
    }
}

impl KemPublicKey {
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

impl KemSecretKey {
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

// Implement Debug for KemSecretKey (but don't show the actual data)
impl std::fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KemSecretKey")
            .field("data", &"[REDACTED]")
            .field("size", &self.data.len())
            .finish()
    }
}

// Implement PartialEq and Eq for KemSecretKey (constant-time comparison)
impl PartialEq for KemSecretKey {
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

impl Eq for KemSecretKey {}

// Implement Zeroize for KemKeypair to zeroize the secret key
impl Zeroize for KemKeypair {
    fn zeroize(&mut self) {
        self.secret_key.zeroize();
    }
}

// Implement ZeroizeOnDrop for KemKeypair
impl Drop for KemKeypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_keypair_creation() {
        let public_key = vec![1, 2, 3, 4];
        let secret_key = vec![5, 6, 7, 8];

        let keypair = KemKeypair::new(public_key.clone(), secret_key.clone());

        assert_eq!(keypair.public_key.data, public_key);
        assert_eq!(keypair.secret_key.data, secret_key);
    }

    #[test]
    fn test_kem_public_key() {
        let data = vec![1, 2, 3, 4];
        let public_key = KemPublicKey::new(data.clone());

        assert_eq!(public_key.data(), &data);
        assert_eq!(public_key.size(), 4);
    }

    #[test]
    fn test_kem_secret_key() {
        let data = vec![1, 2, 3, 4];
        let secret_key = KemSecretKey::new(data.clone());

        assert_eq!(secret_key.data(), &data);
        assert_eq!(secret_key.size(), 4);
    }

    #[test]
    fn test_secret_key_constant_time_comparison() {
        let key1 = KemSecretKey::new(vec![1, 2, 3, 4]);
        let key2 = KemSecretKey::new(vec![1, 2, 3, 4]);
        let key3 = KemSecretKey::new(vec![1, 2, 3, 5]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
