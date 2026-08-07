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
///
/// # Do not use this with `MerkleInclusionAir`
///
/// Poseidon128 is rate-2, so hashing exactly two elements *fills the rate*: `hash_single`
/// permutes once, then `10*1` padding adds `ONE` at `state[0]` and `state[1]` and permutes
/// **again**. The node function is therefore `P(P([l, r, 0, 0, 0]) + [1, 1, 0, 0, 0])[0]` — two
/// permutations. `lib-q-zkp`'s `MerkleInclusionAir` constrains a **single** permutation,
/// `P([l, r, 0, 0, 0])[0]`, because modelling the sponge's second permutation in-circuit would
/// cost another ~960 Poseidon columns per tree level. The two conventions can never agree, so a
/// recursive verifier fed a tree built with this compressor cannot reproduce any root, from any
/// valid path. That was a live defect (card `t_4333e4ea`); use
/// `lib_q_zkp::air::air_poseidon_mmcs::AirPoseidonCompressor` for anything verified in-circuit.
///
/// # Leaf/node collision
///
/// `PoseidonCompressor.compress([[l], [r]])` is **bit-identical** to
/// `PoseidonHasher.hash_iter([l, r])` — both reduce to `Poseidon128.hash([l, r])[0]`. So the
/// digest of a two-column *leaf row* equals the digest of an internal *node* over the same two
/// values, with no domain separation between them. Anything relying on leaf digests and node
/// digests being distinguishable must not use this pair.
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
/// Digest is a single field element.
///
/// **This doc previously said to use this "when recursive verification (MerkleInclusionAir) must
/// verify Merkle paths in-circuit". That was exactly backwards** and is corrected here: this
/// MMCS's node function is the padded sponge, which `MerkleInclusionAir` does not constrain, so
/// the recursive verifier can never reproduce its roots. See [`PoseidonCompressor`] for the
/// arithmetic and for a second, independent reason (leaf/node collision) not to pair it with an
/// in-circuit verifier. For that use case take
/// `lib_q_zkp::air::air_poseidon_mmcs::AirPoseidonMmcs` instead.
///
/// As of the fix for card `t_4333e4ea` nothing in this workspace uses this type; it is retained
/// because it is public API of a published crate.
#[cfg(feature = "poseidon")]
pub type PoseidonMmcs =
    MerkleTreeMmcs<PoseidonField, PoseidonField, PoseidonHasher, PoseidonCompressor, 1>;

/// Build a Poseidon MMCS instance (hasher + compressor) for use with MerkleTreeMmcs.
#[cfg(feature = "poseidon")]
pub fn poseidon_mmcs_instance() -> (PoseidonHasher, PoseidonCompressor) {
    (PoseidonHasher, PoseidonCompressor)
}
