//! Poseidon-based MMCS. **Not for recursive STARK verification** — see below.
//!
//! This module's doc used to read "Merkle trees built with this MMCS use Poseidon128 compression
//! at each level, so siblings are compatible with MerkleInclusionAir (which constrains
//! Poseidon(left || right) == parent in-circuit)". **That was false**, and it is how a live defect
//! (card `t_4333e4ea`) came to be written: `Poseidon128::hash_single` on two elements fills the
//! rate and permutes *twice*, while `MerkleInclusionAir` constrains a *single* permutation. A
//! recursive verifier could not reproduce any root from any valid path.
//!
//! `PoseidonCompressor`, `PoseidonMmcs` and `poseidon_mmcs_instance` were deprecated for that
//! reason and are now **removed** outright rather than carried as deprecated public API. They had
//! two independent defects, not one: the padded-sponge node function above, and a leaf/node
//! collision — `PoseidonCompressor.compress([[l], [r]])` was bit-identical to
//! `PoseidonHasher.hash_iter([l, r])`, so an internal node's digest equalled a two-column leaf
//! row's digest with no domain separation between them.
//!
//! A deprecation warning is a footgun with a label on it; the type could still be instantiated,
//! and its remaining plausible uses were the unsafe ones. Nothing in this workspace used them.
//! For in-circuit verification use `lib_q_zkp::air::air_poseidon_mmcs::AirPoseidonMmcs`.
//!
//! [`PoseidonHasher`] is unaffected and stays — leaf row hashing was never the problem, and it is
//! all this module provides now.

use alloc::vec::Vec;

#[cfg(feature = "poseidon")]
use lib_q_poseidon::{
    Poseidon,
    Poseidon128,
    PoseidonField,
};
use lib_q_stark_symmetric::CryptographicHasher;

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
