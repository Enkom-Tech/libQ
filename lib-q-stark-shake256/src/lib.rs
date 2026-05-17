//! SHAKE256 adapter for lib-Q STARK implementation.
//!
//! This module provides an implementation of the `CryptographicHasher` trait
//! from `lib-q-stark-symmetric` using SHAKE256 from `lib-q-sha3`.
//!
//! # Security Considerations
//!
//! ## Constant-Time Guarantees
//! SHAKE256 operations are constant-time, preventing timing attacks.
//! The underlying SHAKE256 implementation from `lib-q-sha3` ensures that
//! all hash operations execute in constant time regardless of input.
//!
//! ## Post-Quantum Security
//! SHAKE256 is NIST-approved for post-quantum security (FIPS 202).
//! It provides 256 bits of security against both classical and quantum attacks.
//!
//! ## Usage
//! This adapter provides SHAKE256 for STARK proof generation and verification.
//! All hash operations are suitable for use in zero-knowledge proof systems.

#![no_std]

extern crate alloc;

use digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_sha3::Shake256;
use lib_q_stark_symmetric::CryptographicHasher;

/// Buffer size for streaming hash operations (4KB).
/// This balances memory usage with update call frequency.
const STREAM_BUFFER_SIZE: usize = 4096;

/// SHAKE256 hash function adapter for STARK.
///
/// This implements the `CryptographicHasher` trait using SHAKE256,
/// which is a NIST-approved post-quantum hash function.
#[derive(Clone, Copy, Debug)]
pub struct Shake256Hash;

impl CryptographicHasher<u8, [u8; 32]> for Shake256Hash {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let mut hasher = Shake256::default();
        let mut buffer = [0u8; STREAM_BUFFER_SIZE];
        let mut buffer_pos = 0;
        let mut has_data = false;

        // Stream input in fixed-size chunks to avoid collecting into Vec
        for byte in input {
            has_data = true;
            buffer[buffer_pos] = byte;
            buffer_pos += 1;

            // When buffer is full, update hasher and reset buffer
            if buffer_pos >= STREAM_BUFFER_SIZE {
                hasher.update(&buffer);
                buffer_pos = 0;
            }
        }

        // Update with remaining data in buffer
        if has_data && buffer_pos > 0 {
            hasher.update(&buffer[..buffer_pos]);
        }

        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; 32];
        reader.read(&mut output);
        output
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
        u8: 'a,
    {
        let mut hasher = Shake256::default();
        for chunk in input {
            hasher.update(chunk);
        }

        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; 32];
        reader.read(&mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_shake256_hash() {
        let hasher = Shake256Hash;
        let input = b"test input";
        let output = hasher.hash_slice(input);

        // Verify output is 32 bytes
        assert_eq!(output.len(), 32);

        // Verify deterministic
        let output2 = hasher.hash_slice(input);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_shake256_hash_iter() {
        let hasher = Shake256Hash;
        let input: Vec<u8> = (0..100).collect();
        let output = hasher.hash_iter(input.iter().copied());

        assert_eq!(output.len(), 32);
    }
}
