//! Poseidon MMCS whose node compression is the one [`MerkleInclusionAir`] actually constrains.
//!
//! # Why this exists
//!
//! Recursive verification only works if the Merkle tree the inner proof committed to is built
//! with the *same* node function the outer AIR re-computes with. Those two were not the same:
//!
//! * The tree was built by [`lib_q_stark_merkle::PoseidonCompressor`], which compresses via
//!   `Poseidon128::hash_single(&[l, r])`. That is a **rate-2 sponge**: absorbing two elements
//!   exactly fills the rate, so it permutes once, then `10*1` padding adds `ONE` at `state[0]`
//!   and `ONE` at `state[1]` and it permutes **again**. Node = `P(P([l,r,0,0,0]) + [1,1,0,0,0])[0]`.
//! * [`MerkleInclusionAir`] constrains, via
//!   [`PoseidonGadget::constrain`](crate::air::PoseidonGadget::constrain), a **single bare
//!   permutation** of the state `[l, r, 0, 0, 0]`, reading the node off `state[0]`.
//!
//! The consequence was that the recursive verifier could never reproduce a commitment root
//! from a (perfectly valid) Merkle path, which is what
//! `MerkleInclusionAir mismatch @ commit0` in
//! [`StarkVerifierAir::generate_trace`](crate::air::StarkVerifierAir) was reporting.
//!
//! # Which side moved, and why
//!
//! The compressor did. A fixed 2-to-1 Merkle compression is conventionally a *single*
//! permutation with the children in the rate and the output truncated from the state — running
//! a full padded sponge costs two permutations for no added binding, and doubling the
//! in-circuit Poseidon columns to model the second permutation would roughly double the width
//! of every AIR that embeds `MerkleInclusionAir` (commitment, opening, anonymous-auth, batch
//! verifier). Compressing with one permutation is both cheaper and what
//! `lib-q-stark-merkle/src/poseidon_mmcs.rs`'s own module docs claim it does ("so siblings are
//! compatible with MerkleInclusionAir").
//!
//! Digest binding is unchanged: both variants emit one `Complex<Mersenne31>` (~62 bits), so
//! the digest width — not the number of permutations — is what bounds collision resistance
//! here. See the wide-digest note on [`PoseidonGadget`](crate::air::PoseidonGadget).
//!
//! Leaf hashing is untouched: [`lib_q_stark_merkle::PoseidonHasher`] still hashes a row with
//! the full sponge, and the AIR consumes that digest as a given (`leaf_hash_direct`) rather
//! than re-deriving it in-circuit.
//!
//! [`MerkleInclusionAir`]: crate::air::MerkleInclusionAir

use lib_q_poseidon::{
    Poseidon128,
    PoseidonField,
    PoseidonPermutation,
};
use lib_q_stark_merkle::{
    MerkleTreeMmcs,
    PoseidonHasher,
};
use lib_q_stark_symmetric::PseudoCompressionFunction;

/// Node compression matching `MerkleInclusionAir`: one Poseidon-128 permutation of
/// `[left, right, 0, 0, 0]`, truncated to `state[0]`.
///
/// This is exactly the value [`PoseidonGadget::constrain`](crate::air::PoseidonGadget::constrain)
/// binds `computed_hash` to, so a Merkle path through a tree built with this compressor can be
/// re-derived in-circuit.
#[derive(Clone, Debug)]
pub struct AirPoseidonCompressor {
    perm: PoseidonPermutation,
    width: usize,
}

impl AirPoseidonCompressor {
    /// Build the compressor (pre-instantiates the Poseidon-128 permutation).
    #[must_use]
    pub fn new() -> Self {
        let params = Poseidon128::params();
        let width = params.state_width;
        Self {
            perm: PoseidonPermutation::new(params),
            width,
        }
    }
}

impl Default for AirPoseidonCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl PseudoCompressionFunction<[PoseidonField; 1], 2> for AirPoseidonCompressor {
    fn compress(&self, input: [[PoseidonField; 1]; 2]) -> [PoseidonField; 1] {
        use lib_q_stark_field::PrimeCharacteristicRing;
        let mut state = alloc::vec![PoseidonField::ZERO; self.width];
        state[0] = input[0][0];
        state[1] = input[1][0];
        [self.perm.permute(state)[0]]
    }
}

/// Poseidon MMCS for recursive STARK verification: sponge row-hashing (unchanged) plus
/// [`AirPoseidonCompressor`] node compression, so `MerkleInclusionAir` can verify its paths.
pub type AirPoseidonMmcs =
    MerkleTreeMmcs<PoseidonField, PoseidonField, PoseidonHasher, AirPoseidonCompressor, 1>;

/// Hasher + compressor pair for [`AirPoseidonMmcs`].
#[must_use]
pub fn air_poseidon_mmcs_instance() -> (PoseidonHasher, AirPoseidonCompressor) {
    (PoseidonHasher, AirPoseidonCompressor::new())
}

#[cfg(test)]
mod tests {
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;
    use crate::air::merkle_inclusion::{
        MerkleHash,
        compute_merkle_root,
    };

    fn fe(a: u32, b: u32) -> PoseidonField {
        PoseidonField::new_complex(Mersenne31::new(a), Mersenne31::new(b))
    }

    /// The contract this module exists to enforce: MMCS node compression == the AIR's node
    /// function. `compute_merkle_root` with a one-level path is the AIR's node function
    /// applied to (leaf_digest, sibling), so a depth-1 root must equal `compress`.
    #[test]
    fn compressor_matches_merkle_inclusion_air_node() {
        let compressor = AirPoseidonCompressor::new();
        for (a, b) in [(1u32, 2u32), (7, 9), (123_456, 654_321), (0, 0)] {
            let sibling = fe(b, b + 1);
            // depth-1 tree: leaf hashed by the AIR's leaf rule, then one node with `sibling`.
            let leaf = alloc::vec![a as u8, b as u8, 3, 4];
            let air_root = compute_merkle_root(&leaf, &[false], &[MerkleHash::from_field(sibling)]);
            // Recover the AIR's leaf digest so we can feed the compressor the same inputs.
            let leaf_digest = {
                use lib_q_poseidon::Poseidon;
                Poseidon128.hash(&crate::air::bytes_to_poseidon_field(&leaf))[0]
            };
            let compressed = compressor.compress([[leaf_digest], [sibling]])[0];
            assert_eq!(
                compressed,
                *air_root.as_field(),
                "AirPoseidonCompressor must equal the MerkleInclusionAir node function"
            );
        }
    }

    /// Negative control for the test above: the *previous* compressor
    /// (`lib_q_stark_merkle::PoseidonCompressor`, a padded sponge) does NOT satisfy it. This is
    /// the defect that made `MerkleInclusionAir mismatch @ commit0` unavoidable (card
    /// t_4333e4ea); if this ever starts matching, the assertion above has become vacuous.
    #[test]
    fn previous_sponge_compressor_does_not_match_the_air() {
        use lib_q_stark_merkle::PoseidonCompressor;
        let l = fe(11, 22);
        let r = fe(33, 44);
        let sponge = PoseidonCompressor.compress([[l], [r]])[0];
        let air = AirPoseidonCompressor::new().compress([[l], [r]])[0];
        assert_ne!(
            sponge, air,
            "the sponge compressor is expected to differ from the AIR node function; if these \
             are equal the compatibility test above proves nothing"
        );
    }

    /// The compression must depend on child order, otherwise Merkle path bits carry no
    /// information and an inclusion proof would not pin a position in the tree.
    #[test]
    fn compression_is_order_sensitive() {
        let c = AirPoseidonCompressor::new();
        let l = fe(5, 6);
        let r = fe(7, 8);
        assert_ne!(c.compress([[l], [r]])[0], c.compress([[r], [l]])[0]);
    }

    /// Leaf/node domain separation in the MMCS.
    ///
    /// `MerkleTreeMmcs` digests a matrix ROW with [`PoseidonHasher`] and an internal NODE with the
    /// compressor. The old [`lib_q_stark_merkle::PoseidonCompressor`] used the *same* function for
    /// both (`Poseidon128::hash_single(&[l, r])` is literally `PoseidonHasher::hash_iter([l, r])`),
    /// so the digest of a two-column leaf row was indistinguishable from the node above two
    /// children — a prover could present a leaf as an internal node, or vice versa, at no cost.
    /// The single-permutation compressor is a different function, so that structural collision is
    /// gone. The first assertion is the positive control: it shows the property is measurable and
    /// that the second assertion is not vacuous.
    #[test]
    fn air_compressor_is_domain_separated_from_leaf_row_hashing() {
        use lib_q_stark_merkle::PoseidonCompressor;
        use lib_q_stark_symmetric::CryptographicHasher;

        let l = fe(31, 41);
        let r = fe(59, 26);
        let row_digest: [PoseidonField; 1] = PoseidonHasher.hash_iter([l, r]);

        assert_eq!(
            PoseidonCompressor.compress([[l], [r]])[0],
            row_digest[0],
            "positive control: the OLD sponge compressor is the same function as leaf row \
             hashing, so leaf and node digests collided by construction"
        );
        assert_ne!(
            AirPoseidonCompressor::new().compress([[l], [r]])[0],
            row_digest[0],
            "node compression must not equal the leaf row hash of the same two elements"
        );
    }
}
