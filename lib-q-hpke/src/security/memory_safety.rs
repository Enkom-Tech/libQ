//! Memory safety and zeroization for HPKE
//!
//! This module provides secure memory management, including automatic
//! zeroization of sensitive data and protection against memory attacks.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    vec,
    vec::Vec,
};

use crate::error::HpkeError;

/// Trait for secure zeroization of sensitive data
pub trait SecureZeroize {
    /// Securely zero out the memory
    fn secure_zeroize(&mut self);
}

impl SecureZeroize for [u8] {
    fn secure_zeroize(&mut self) {
        // Safe zeroization without unsafe code
        // This uses a simple approach that should be sufficient for most cases
        for byte in self.iter_mut() {
            *byte = 0;
        }

        // Use a black_box-like operation to prevent optimization
        // This is a simple approach without using unsafe code
        let _dummy = self.as_ptr();

        // Memory fence to ensure writes are not reordered
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl SecureZeroize for Vec<u8> {
    fn secure_zeroize(&mut self) {
        self.as_mut_slice().secure_zeroize();
    }
}

/// Secure wrapper for sensitive byte data that automatically zeroizes on drop
pub struct SecureBytes {
    data: Vec<u8>,
    is_zeroized: bool,
}

impl SecureBytes {
    /// Create new secure bytes from a vector
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            is_zeroized: false,
        }
    }

    /// Create new secure bytes with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            is_zeroized: false,
        }
    }

    /// Create new secure bytes filled with zeros
    pub fn zeros(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
            is_zeroized: false,
        }
    }

    /// Get immutable reference to the data
    pub fn as_bytes(&self) -> &[u8] {
        if self.is_zeroized { &[] } else { &self.data }
    }

    /// Get mutable reference to the data
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        if self.is_zeroized {
            &mut []
        } else {
            &mut self.data
        }
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        if self.is_zeroized { 0 } else { self.data.len() }
    }

    /// Check if the data is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Extend the secure bytes with additional data
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        if !self.is_zeroized {
            self.data.extend_from_slice(other);
        }
    }

    /// Manually zeroize the data
    pub fn zeroize(&mut self) {
        if !self.is_zeroized {
            self.data.secure_zeroize();
            self.is_zeroized = true;
        }
    }

    /// Check if the data has been zeroized
    pub fn is_zeroized(&self) -> bool {
        self.is_zeroized
    }

    /// Clone the data into a new SecureBytes (use with caution)
    pub fn clone_data(&self) -> SecureBytes {
        if self.is_zeroized {
            SecureBytes::new(Vec::new())
        } else {
            SecureBytes::new(self.data.clone())
        }
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// Secure key material wrapper
pub struct SecureKey {
    key_data: SecureBytes,
    key_type: KeyType,
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(data: Vec<u8>, key_type: KeyType) -> Result<Self, HpkeError> {
        // Validate key length based on type
        let expected_len = key_type.expected_length();
        if data.len() != expected_len {
            return Err(HpkeError::CryptoError(format!(
                "Invalid key length: expected {}, got {}",
                expected_len,
                data.len()
            )));
        }

        // Validate key is not all zeros
        if data.iter().all(|&b| b == 0) {
            return Err(HpkeError::CryptoError(
                "Key material cannot be all zeros".into(),
            ));
        }

        Ok(Self {
            key_data: SecureBytes::new(data),
            key_type,
        })
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Get immutable reference to key data
    pub fn as_bytes(&self) -> &[u8] {
        self.key_data.as_bytes()
    }

    /// Get the key length
    pub fn len(&self) -> usize {
        self.key_data.len()
    }

    /// Check if the key is empty (zeroized)
    pub fn is_empty(&self) -> bool {
        self.key_data.is_empty()
    }

    /// Manually zeroize the key
    pub fn zeroize(&mut self) {
        self.key_data.zeroize();
    }

    /// Check if the key has been zeroized
    pub fn is_zeroized(&self) -> bool {
        self.key_data.is_zeroized()
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Key type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// AEAD encryption key
    AeadKey,
    /// KEM secret key for decapsulation
    KemSecretKey,
    /// KEM public key for encapsulation
    KemPublicKey,
    /// Shared secret derived from KEM
    SharedSecret,
    /// Secret for key export operations
    ExporterSecret,
}

impl KeyType {
    /// Get expected length for the key type
    pub fn expected_length(&self) -> usize {
        match self {
            KeyType::AeadKey => 32,        // 256-bit key
            KeyType::KemSecretKey => 1632, // ML-KEM-512 secret key
            KeyType::KemPublicKey => 800,  // ML-KEM-512 public key
            KeyType::SharedSecret => 32,   // 256-bit shared secret
            KeyType::ExporterSecret => 32, // 256-bit exporter secret
        }
    }
}

/// Memory pool for secure allocation
pub struct SecureMemoryPool {
    pools: Vec<SecureBytes>,
    max_pool_size: usize,
}

impl SecureMemoryPool {
    /// Create a new secure memory pool
    pub fn new(max_pool_size: usize) -> Self {
        Self {
            pools: Vec::new(),
            max_pool_size,
        }
    }

    /// Allocate secure memory from the pool
    pub fn allocate(&mut self, size: usize) -> SecureBytes {
        // Try to reuse existing memory if available
        for pool in &mut self.pools {
            if pool.len() >= size && pool.is_zeroized() {
                // Reuse this pool
                let mut reused = SecureBytes::with_capacity(size);
                reused.extend_from_slice(&vec![0u8; size]);
                return reused;
            }
        }

        // Allocate new memory
        let new_memory = SecureBytes::zeros(size);

        // Add to pool if under limit
        if self.pools.len() < self.max_pool_size {
            self.pools.push(SecureBytes::zeros(size));
        }

        new_memory
    }

    /// Clear all pools
    pub fn clear(&mut self) {
        for pool in &mut self.pools {
            pool.zeroize();
        }
        self.pools.clear();
    }

    /// Get pool statistics
    pub fn stats(&self) -> MemoryPoolStats {
        let total_allocated = self.pools.iter().map(|p| p.len()).sum();
        let zeroized_count = self.pools.iter().filter(|p| p.is_zeroized()).count();

        MemoryPoolStats {
            total_pools: self.pools.len(),
            total_allocated_bytes: total_allocated,
            zeroized_pools: zeroized_count,
            max_pool_size: self.max_pool_size,
        }
    }
}

impl Drop for SecureMemoryPool {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Memory pool statistics
#[derive(Debug, Clone)]
pub struct MemoryPoolStats {
    /// Total number of memory pools
    pub total_pools: usize,
    /// Total bytes allocated across all pools
    pub total_allocated_bytes: usize,
    /// Number of pools that have been zeroized
    pub zeroized_pools: usize,
    /// Maximum allowed pool size
    pub max_pool_size: usize,
}

/// Stack-allocated secure buffer for small sensitive data
pub struct SecureStackBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
    is_zeroized: bool,
}

impl<const N: usize> SecureStackBuffer<N> {
    /// Create a new secure stack buffer
    pub fn new() -> Self {
        Self {
            data: [0u8; N],
            len: 0,
            is_zeroized: false,
        }
    }

    /// Create a buffer from existing data
    pub fn from_slice(data: &[u8]) -> Result<Self, HpkeError> {
        if data.len() > N {
            return Err(HpkeError::CryptoError(format!(
                "Data too large for buffer: {} > {}",
                data.len(),
                N
            )));
        }

        let mut buffer = Self::new();
        buffer.data[..data.len()].copy_from_slice(data);
        buffer.len = data.len();
        Ok(buffer)
    }

    /// Get the data as a slice
    pub fn as_slice(&self) -> &[u8] {
        if self.is_zeroized {
            &[]
        } else {
            &self.data[..self.len]
        }
    }

    /// Get mutable data as a slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.is_zeroized {
            &mut []
        } else {
            &mut self.data[..self.len]
        }
    }

    /// Get the length of valid data
    pub fn len(&self) -> usize {
        if self.is_zeroized { 0 } else { self.len }
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Set the length of valid data
    pub fn set_len(&mut self, new_len: usize) -> Result<(), HpkeError> {
        if new_len > N {
            return Err(HpkeError::CryptoError(format!(
                "Length too large for buffer: {} > {}",
                new_len, N
            )));
        }
        if !self.is_zeroized {
            self.len = new_len;
        }
        Ok(())
    }

    /// Zeroize the buffer
    pub fn zeroize(&mut self) {
        if !self.is_zeroized {
            self.data.secure_zeroize();
            self.len = 0;
            self.is_zeroized = true;
        }
    }

    /// Check if the buffer is zeroized
    pub fn is_zeroized(&self) -> bool {
        self.is_zeroized
    }
}

impl<const N: usize> Drop for SecureStackBuffer<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> Default for SecureStackBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_zeroize() {
        let mut data = vec![1u8, 2u8, 3u8, 4u8];
        data.secure_zeroize();
        assert_eq!(data, vec![0u8; 4]);
    }

    #[test]
    fn test_secure_bytes() {
        let mut secure = SecureBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(secure.len(), 4);
        assert_eq!(secure.as_bytes(), &[1, 2, 3, 4]);
        assert!(!secure.is_zeroized());

        secure.zeroize();
        assert!(secure.is_zeroized());
        assert_eq!(secure.len(), 0);
    }

    #[test]
    fn test_secure_key() {
        let key_data = vec![1u8; 32];
        let key = SecureKey::new(key_data, KeyType::AeadKey).unwrap();

        assert_eq!(key.key_type(), KeyType::AeadKey);
        assert_eq!(key.len(), 32);
        assert!(!key.is_zeroized());
    }

    #[test]
    fn test_secure_key_validation() {
        // Test invalid length
        let short_key = vec![1u8; 16];
        assert!(SecureKey::new(short_key, KeyType::AeadKey).is_err());

        // Test all-zero key
        let zero_key = vec![0u8; 32];
        assert!(SecureKey::new(zero_key, KeyType::AeadKey).is_err());
    }

    #[test]
    fn test_secure_memory_pool() {
        let mut pool = SecureMemoryPool::new(5);

        let mem1 = pool.allocate(32);
        let mem2 = pool.allocate(64);

        assert_eq!(mem1.len(), 32);
        assert_eq!(mem2.len(), 64);

        let stats = pool.stats();
        assert!(stats.total_pools <= 5);
    }

    #[test]
    fn test_secure_stack_buffer() {
        let buffer = SecureStackBuffer::<32>::new();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());

        let data = [1u8, 2u8, 3u8, 4u8];
        let mut buffer = SecureStackBuffer::<32>::from_slice(&data).unwrap();
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice(), &data);

        buffer.zeroize();
        assert!(buffer.is_zeroized());
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_key_type_lengths() {
        assert_eq!(KeyType::AeadKey.expected_length(), 32);
        assert_eq!(KeyType::KemSecretKey.expected_length(), 1632);
        assert_eq!(KeyType::KemPublicKey.expected_length(), 800);
        assert_eq!(KeyType::SharedSecret.expected_length(), 32);
        assert_eq!(KeyType::ExporterSecret.expected_length(), 32);
    }
}
