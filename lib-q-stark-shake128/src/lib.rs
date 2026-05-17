//! SHAKE128 adapter for lib-Q STARK implementation.
//!
//! This module provides an implementation of the `CryptographicHasher` trait
//! from `lib-q-stark-symmetric` using SHAKE128 from `lib-q-sha3`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use digest::{
    ExtendableOutput,
    Update,
    XofReader,
};
use lib_q_sha3::Shake128;
use lib_q_stark_symmetric::CryptographicHasher;

/// SHAKE128 hash function adapter for STARK.
///
/// This implements the `CryptographicHasher` trait using SHAKE128,
/// which is a NIST-approved post-quantum hash function (128-bit security level).
#[derive(Clone, Copy, Debug)]
pub struct Shake128Hash;

impl CryptographicHasher<u8, [u8; 32]> for Shake128Hash {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        let mut hasher = Shake128::default();

        // Collect iterator into chunks for efficiency
        let input_vec: Vec<u8> = input.into_iter().collect();
        if !input_vec.is_empty() {
            hasher.update(&input_vec);
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
        let mut hasher = Shake128::default();
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
    use super::*;

    #[test]
    fn test_shake128_hash() {
        let hasher = Shake128Hash;
        let input = b"test input";
        let output = hasher.hash_slice(input);

        // Verify output is 32 bytes
        assert_eq!(output.len(), 32);

        // Verify deterministic
        let output2 = hasher.hash_slice(input);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_shake128_hash_iter() {
        let hasher = Shake128Hash;
        let input: Vec<u8> = (0..100).collect();
        let output = hasher.hash_iter(input.iter().copied());

        assert_eq!(output.len(), 32);
    }
}
