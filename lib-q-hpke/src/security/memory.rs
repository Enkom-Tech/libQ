//! Secure memory handling utilities

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use zeroize::{
    Zeroize,
    ZeroizeOnDrop,
};

/// Secure key container that automatically zeroizes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    data: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new secure key with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get the key data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the key data as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length of the key
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Resize the key to the given length
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }

    /// Extend the key with additional data
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other);
    }

    /// Clone the secure key
    pub fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl From<Vec<u8>> for SecureKey {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureKey {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// Secure nonce container that automatically zeroizes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureNonce {
    data: Vec<u8>,
}

impl SecureNonce {
    /// Create a new secure nonce from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new secure nonce with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get the nonce data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the nonce data as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length of the nonce
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the nonce is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Resize the nonce to the given length
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }

    /// Clone the secure nonce
    pub fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl From<Vec<u8>> for SecureNonce {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureNonce {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// Secure buffer that automatically zeroizes on drop
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a new secure buffer with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Get the buffer data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the buffer data as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Push a byte to the buffer
    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Extend the buffer with additional data
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other);
    }

    /// Resize the buffer to the given length
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }
}

impl Default for SecureBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_secure_key() {
        let key_data = vec![1u8, 2u8, 3u8, 4u8];
        let mut key = SecureKey::new(key_data.clone());

        assert_eq!(key.as_slice(), &key_data);
        assert_eq!(key.len(), 4);
        assert!(!key.is_empty());

        key.resize(6, 0);
        assert_eq!(key.len(), 6);
        assert_eq!(key.as_slice(), &[1u8, 2u8, 3u8, 4u8, 0u8, 0u8]);
    }

    #[test]
    fn test_secure_nonce() {
        let nonce_data = vec![5u8, 6u8, 7u8, 8u8];
        let nonce = SecureNonce::new(nonce_data.clone());

        assert_eq!(nonce.as_slice(), &nonce_data);
        assert_eq!(nonce.len(), 4);
        assert!(!nonce.is_empty());
    }

    #[test]
    fn test_secure_buffer() {
        let mut buffer = SecureBuffer::new();
        assert!(buffer.is_empty());

        buffer.push(1);
        buffer.push(2);
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.as_slice(), &[1u8, 2u8]);

        buffer.extend_from_slice(&[3u8, 4u8]);
        assert_eq!(buffer.as_slice(), &[1u8, 2u8, 3u8, 4u8]);

        buffer.clear();
        assert!(buffer.is_empty());
    }
}
