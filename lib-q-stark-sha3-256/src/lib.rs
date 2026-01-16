//! SHA3-256 adapter for lib-Q STARK implementation.
//!
//! This module provides an implementation of the `CryptographicHasher` trait
//! from `lib-q-stark-symmetric` using SHA3-256 from `lib-q-sha3`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use digest::Digest;
use lib_q_sha3::Sha3_256;
use lib_q_stark_symmetric::CryptographicHasher;

/// SHA3-256 hash function adapter for STARK.
///
/// This implements the `CryptographicHasher` trait using SHA3-256,
/// which is a NIST-approved post-quantum hash function (256-bit security level).
/// Unlike SHAKE functions, SHA3-256 is a fixed-length hash function.
#[derive(Clone, Copy, Debug)]
pub struct Sha3_256Hash;

impl CryptographicHasher<u8, [u8; 32]> for Sha3_256Hash {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let mut hasher = Sha3_256::new();

        // Collect iterator into chunks for efficiency
        let input_vec: Vec<u8> = input.into_iter().collect();
        if !input_vec.is_empty() {
            Digest::update(&mut hasher, &input_vec);
        }

        hasher.finalize().into()
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
        u8: 'a,
    {
        let mut hasher = Sha3_256::new();
        for chunk in input {
            Digest::update(&mut hasher, chunk);
        }

        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_hash() {
        let hasher = Sha3_256Hash;
        let input = b"test input";
        let output = hasher.hash_slice(input);

        // Verify output is 32 bytes
        assert_eq!(output.len(), 32);

        // Verify deterministic
        let output2 = hasher.hash_slice(input);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_sha3_256_hash_iter() {
        let hasher = Sha3_256Hash;
        let input: Vec<u8> = (0..100).collect();
        let output = hasher.hash_iter(input.iter().copied());

        assert_eq!(output.len(), 32);
    }
}
