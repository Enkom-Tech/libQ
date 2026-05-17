//! Poseidon-based MMCS for recursive STARK verification.
//!
//! Merkle trees built with this MMCS use Poseidon128 compression at each level,
//! so siblings are compatible with MerkleInclusionAir (which constrains
//! Poseidon(left || right) == parent in-circuit).

use alloc::vec::Vec;

#[cfg(feature = "poseidon")]
use lib_q_poseidon::{
    Poseidon,
    Poseidon128,
    PoseidonField,
};
use lib_q_stark_symmetric::{
    CryptographicHasher,
    PseudoCompressionFunction,
};

use crate::MerkleTreeMmcs;

/// Hasher that hashes sequences of PoseidonField to a single digest via Poseidon128.
/// Satisfies both value and packed hasher bounds when P = PW = PoseidonField.
#[derive(Clone, Debug)]
pub struct PoseidonHasher;

#[cfg(feature = "poseidon")]
impl CryptographicHasher<PoseidonField, [PoseidonField; 1]> for PoseidonHasher {
    fn hash_iter<I>(&self, input: I) -> [PoseidonField; 1]
    where
        I: IntoIterator<Item = PoseidonField>,
    {
        let vec: Vec<PoseidonField> = input.into_iter().collect();
        let out = Poseidon128.hash(&vec);
        [out[0]]
    }
}

/// Compressor that merges two digests with Poseidon128::hash_single([left, right]).
#[derive(Clone, Debug)]
pub struct PoseidonCompressor;

#[cfg(feature = "poseidon")]
impl PseudoCompressionFunction<[PoseidonField; 1], 2> for PoseidonCompressor {
    fn compress(&self, input: [[PoseidonField; 1]; 2]) -> [PoseidonField; 1] {
        let pair = [input[0][0], input[1][0]];
        let out = Poseidon128.hash_single(&pair);
        [out]
    }
}

/// Poseidon-based MMCS: Merkle tree with Poseidon128 for row hashing and node compression.
/// Digest is a single field element. Use this as the outer STARK's commitment scheme when
/// recursive verification (MerkleInclusionAir) must verify Merkle paths in-circuit.
#[cfg(feature = "poseidon")]
pub type PoseidonMmcs =
    MerkleTreeMmcs<PoseidonField, PoseidonField, PoseidonHasher, PoseidonCompressor, 1>;

/// Build a Poseidon MMCS instance (hasher + compressor) for use with MerkleTreeMmcs.
#[cfg(feature = "poseidon")]
pub fn poseidon_mmcs_instance() -> (PoseidonHasher, PoseidonCompressor) {
    (PoseidonHasher, PoseidonCompressor)
}
