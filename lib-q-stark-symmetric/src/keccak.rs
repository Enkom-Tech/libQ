//! Keccak-f[1600] permutation wrapper for STARK symmetric primitives.
//!
//! This provides a NIST-approved permutation (Keccak-f is the core of SHA-3)
//! for use in sponge constructions and Merkle tree hashing.

use lib_q_keccak::f1600;

use crate::permutation::{
    CryptographicPermutation,
    Permutation,
};

/// Keccak-f[1600] permutation over 25 u64 lanes (200 bytes total state).
///
/// This is the core permutation used in SHA-3 and is NIST-approved.
/// It operates on a state of 25 u64 values (1600 bits total).
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakF;

impl Permutation<[u64; 25]> for KeccakF {
    fn permute_mut(&self, state: &mut [u64; 25]) {
        f1600(state);
    }
}

impl CryptographicPermutation<[u64; 25]> for KeccakF {}
