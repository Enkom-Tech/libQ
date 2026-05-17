//! Stack Buffer Utilities
//!
//! This module provides fixed-size stack-allocated buffers for cryptographic operations,
//! following libQ's zero dynamic allocation memory model.

use core::mem::MaybeUninit;
use core::ops::{
    Deref,
    DerefMut,
};

use crate::security::memory::secure_zero_slice;

/// Maximum size for stack-allocated buffers
pub const MAX_STACK_BUFFER_SIZE: usize = 32768; // 32KB max stack usage

/// Memory-efficient uninitialized stack buffer
///
/// This buffer uses MaybeUninit to avoid zeroing memory that will be immediately overwritten,
/// providing better performance for large buffers.
#[derive(Debug)]
pub struct UninitStackBuffer<const N: usize> {
    data: [MaybeUninit<u8>; N],
    used: usize,
}

impl<const N: usize> Default for UninitStackBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> UninitStackBuffer<N> {
    /// Create a new uninitialized stack buffer
    pub fn new() -> Self {
        Self {
            data: unsafe { MaybeUninit::uninit().assume_init() },
            used: 0,
        }
    }

    /// Get the maximum capacity of the buffer
    pub fn capacity(&self) -> usize {
        N
    }

    /// Get the number of bytes currently used
    pub fn len(&self) -> usize {
        self.used
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Get the used portion as a slice
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data.as_ptr() as *const u8, self.used) }
    }

    /// Get the used portion as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.data.as_mut_ptr() as *mut u8, self.used) }
    }

    /// Resize the buffer to the specified length
    pub fn resize(&mut self, new_len: usize) -> Result<(), &'static str> {
        if new_len > N {
            return Err("New length exceeds buffer capacity");
        }
        self.used = new_len;
        Ok(())
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        if self.used > 0 {
            secure_zero_slice(self.as_mut_slice());
            self.used = 0;
        }
    }

    /// Append data to the buffer
    pub fn append(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.used + data.len() > N {
            return Err("Not enough space in buffer");
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.data.as_mut_ptr().add(self.used) as *mut u8,
                data.len(),
            );
        }
        self.used += data.len();
        Ok(())
    }
}

impl<const N: usize> Drop for UninitStackBuffer<N> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Fixed-size stack-allocated buffer for cryptographic operations
///
/// This buffer provides a safe, stack-allocated alternative to dynamic allocations
/// for cryptographic operations. It automatically zeroes sensitive data on drop.
#[derive(Debug)]
pub struct StackBuffer<const N: usize> {
    data: [u8; N],
    used: usize,
}

impl<const N: usize> StackBuffer<N> {
    /// Create a new stack buffer
    pub fn new() -> Self {
        Self {
            data: [0u8; N],
            used: 0,
        }
    }

    /// Create a new stack buffer with initial data
    pub fn from_slice(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() > N {
            return Err("Data too large for buffer");
        }

        let mut buffer = Self::new();
        buffer.data[..data.len()].copy_from_slice(data);
        buffer.used = data.len();
        Ok(buffer)
    }

    /// Get the maximum capacity of the buffer
    pub fn capacity(&self) -> usize {
        N
    }

    /// Get the number of bytes currently used
    pub fn len(&self) -> usize {
        self.used
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Get the remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        N - self.used
    }

    /// Clear the buffer and reset usage
    pub fn clear(&mut self) {
        secure_zero_slice(&mut self.data[..self.used]);
        self.used = 0;
    }

    /// Resize the buffer to a new length
    pub fn resize(&mut self, new_len: usize) -> Result<(), &'static str> {
        if new_len > N {
            return Err("New length exceeds buffer capacity");
        }

        if new_len < self.used {
            // Zero the unused portion
            secure_zero_slice(&mut self.data[new_len..self.used]);
        }

        self.used = new_len;
        Ok(())
    }

    /// Append data to the buffer
    pub fn append(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if self.used + data.len() > N {
            return Err("Not enough space in buffer");
        }

        self.data[self.used..self.used + data.len()].copy_from_slice(data);
        self.used += data.len();
        Ok(())
    }

    /// Get a slice of the used portion
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.used]
    }

    /// Get a mutable slice of the used portion
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.used]
    }

    /// Get a slice of the entire buffer (including unused portion)
    pub fn as_full_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable slice of the entire buffer (including unused portion)
    pub fn as_full_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Copy data from another buffer
    pub fn copy_from(&mut self, other: &StackBuffer<N>) {
        self.data.copy_from_slice(&other.data);
        self.used = other.used;
    }

    /// Copy data from a slice
    pub fn copy_from_slice(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > N {
            return Err("Data too large for buffer");
        }

        self.data[..data.len()].copy_from_slice(data);
        self.used = data.len();
        Ok(())
    }

    /// Copy data to a slice
    pub fn copy_to_slice(&self, dest: &mut [u8]) -> Result<(), &'static str> {
        if dest.len() < self.used {
            return Err("Destination slice too small");
        }

        dest[..self.used].copy_from_slice(&self.data[..self.used]);
        Ok(())
    }
}

impl<const N: usize> Default for StackBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Clone for StackBuffer<N> {
    fn clone(&self) -> Self {
        let mut new_buffer = Self::new();
        new_buffer.copy_from(self);
        new_buffer
    }
}

impl<const N: usize> Deref for StackBuffer<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const N: usize> DerefMut for StackBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<const N: usize> Drop for StackBuffer<N> {
    fn drop(&mut self) {
        // Securely zero the entire buffer on drop
        secure_zero_slice(&mut self.data);
    }
}

/// Predefined buffer sizes for common cryptographic operations
pub const KEY_BUFFER_SIZE: usize = 64; // 64 bytes for keys
pub const NONCE_BUFFER_SIZE: usize = 32; // 32 bytes for nonces
pub const TAG_BUFFER_SIZE: usize = 64; // 64 bytes for authentication tags
pub const HASH_BUFFER_SIZE: usize = 64; // 64 bytes for hash outputs
pub const IV_BUFFER_SIZE: usize = 32; // 32 bytes for initialization vectors
pub const CIPHERTEXT_BUFFER_SIZE: usize = 4096; // 4KB for ciphertext operations
pub const PLAINTEXT_BUFFER_SIZE: usize = 4096; // 4KB for plaintext operations

/// Type aliases for common buffer sizes
pub type KeyBuffer = StackBuffer<KEY_BUFFER_SIZE>;
pub type NonceBuffer = StackBuffer<NONCE_BUFFER_SIZE>;
pub type TagBuffer = StackBuffer<TAG_BUFFER_SIZE>;
pub type HashBuffer = StackBuffer<HASH_BUFFER_SIZE>;
pub type IvBuffer = StackBuffer<IV_BUFFER_SIZE>;
pub type CiphertextBuffer = StackBuffer<CIPHERTEXT_BUFFER_SIZE>;
pub type PlaintextBuffer = StackBuffer<PLAINTEXT_BUFFER_SIZE>;

/// Type aliases for memory-efficient uninitialized buffers
pub type UninitKeyBuffer = UninitStackBuffer<KEY_BUFFER_SIZE>;
pub type UninitNonceBuffer = UninitStackBuffer<NONCE_BUFFER_SIZE>;
pub type UninitTagBuffer = UninitStackBuffer<TAG_BUFFER_SIZE>;
pub type UninitHashBuffer = UninitStackBuffer<HASH_BUFFER_SIZE>;
pub type UninitIvBuffer = UninitStackBuffer<IV_BUFFER_SIZE>;
pub type UninitCiphertextBuffer = UninitStackBuffer<CIPHERTEXT_BUFFER_SIZE>;
pub type UninitPlaintextBuffer = UninitStackBuffer<PLAINTEXT_BUFFER_SIZE>;

/// Utility functions for working with stack buffers
pub mod utils {
    use super::*;

    /// Create a key buffer from a slice
    pub fn create_key_buffer(data: &[u8]) -> Result<KeyBuffer, &'static str> {
        KeyBuffer::from_slice(data)
    }

    /// Create a nonce buffer from a slice
    pub fn create_nonce_buffer(data: &[u8]) -> Result<NonceBuffer, &'static str> {
        NonceBuffer::from_slice(data)
    }

    /// Create a tag buffer from a slice
    pub fn create_tag_buffer(data: &[u8]) -> Result<TagBuffer, &'static str> {
        TagBuffer::from_slice(data)
    }

    /// Create a hash buffer from a slice
    pub fn create_hash_buffer(data: &[u8]) -> Result<HashBuffer, &'static str> {
        HashBuffer::from_slice(data)
    }

    /// Create an IV buffer from a slice
    pub fn create_iv_buffer(data: &[u8]) -> Result<IvBuffer, &'static str> {
        IvBuffer::from_slice(data)
    }

    /// Create a ciphertext buffer from a slice
    pub fn create_ciphertext_buffer(data: &[u8]) -> Result<CiphertextBuffer, &'static str> {
        CiphertextBuffer::from_slice(data)
    }

    /// Create a plaintext buffer from a slice
    pub fn create_plaintext_buffer(data: &[u8]) -> Result<PlaintextBuffer, &'static str> {
        PlaintextBuffer::from_slice(data)
    }

    /// Copy data between buffers of different sizes
    pub fn copy_between_buffers<const SRC_SIZE: usize, const DST_SIZE: usize>(
        src: &StackBuffer<SRC_SIZE>,
        dst: &mut StackBuffer<DST_SIZE>,
    ) -> Result<(), &'static str> {
        if src.len() > DST_SIZE {
            return Err("Source buffer too large for destination");
        }

        dst.copy_from_slice(src.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_buffer_creation() {
        let buffer = StackBuffer::<32>::new();
        assert_eq!(buffer.capacity(), 32);
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_stack_buffer_from_slice() {
        let data = b"hello world";
        let buffer = StackBuffer::<32>::from_slice(data).unwrap();
        assert_eq!(buffer.len(), data.len());
        assert_eq!(buffer.as_slice(), data);
    }

    #[test]
    fn test_stack_buffer_append() {
        let mut buffer = StackBuffer::<32>::new();
        buffer.append(b"hello").unwrap();
        buffer.append(b" world").unwrap();
        assert_eq!(buffer.as_slice(), b"hello world");
    }

    #[test]
    fn test_stack_buffer_resize() {
        let mut buffer = StackBuffer::<32>::new();
        buffer.append(b"hello").unwrap();
        buffer.resize(3).unwrap();
        assert_eq!(buffer.as_slice(), b"hel");
    }

    #[test]
    fn test_stack_buffer_clear() {
        let mut buffer = StackBuffer::<32>::new();
        buffer.append(b"hello").unwrap();
        buffer.clear();
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_stack_buffer_copy() {
        let mut buffer1 = StackBuffer::<32>::new();
        buffer1.append(b"hello").unwrap();

        let mut buffer2 = StackBuffer::<32>::new();
        buffer2.copy_from(&buffer1);
        assert_eq!(buffer2.as_slice(), buffer1.as_slice());
    }

    #[test]
    fn test_predefined_buffers() {
        let key_buf = KeyBuffer::new();
        assert_eq!(key_buf.capacity(), KEY_BUFFER_SIZE);

        let nonce_buf = NonceBuffer::new();
        assert_eq!(nonce_buf.capacity(), NONCE_BUFFER_SIZE);

        let tag_buf = TagBuffer::new();
        assert_eq!(tag_buf.capacity(), TAG_BUFFER_SIZE);
    }

    #[test]
    fn test_utils() {
        let data = b"test data";
        let key_buf = utils::create_key_buffer(data).unwrap();
        assert_eq!(key_buf.as_slice(), data);

        let nonce_buf = utils::create_nonce_buffer(data).unwrap();
        assert_eq!(nonce_buf.as_slice(), data);
    }

    #[test]
    fn test_copy_between_buffers() {
        let mut src = StackBuffer::<16>::new();
        src.append(b"hello").unwrap();

        let mut dst = StackBuffer::<32>::new();
        utils::copy_between_buffers(&src, &mut dst).unwrap();
        assert_eq!(dst.as_slice(), src.as_slice());
    }
}
