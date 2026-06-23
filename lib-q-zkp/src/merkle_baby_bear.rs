//! Wide-digest (BabyBear / Poseidon2) binary Merkle tree — the Arm B analogue of
//! [`crate::merkle::WidePoseidonMerkleTree`].
//!
//! Each node is a [`WideDigestBb`] (9 BabyBear elements) and the 2-to-1 compression is
//! [`compress_bb`] — the SAME function the membership / wide-Merkle-path AIRs constrain
//! (`air::wide_merkle_path_baby_bear`), so a tree's `root` and `path(idx)` are exactly what the
//! circuit proves. This lets a caller build a real membership set over BabyBear and extract an
//! authentication path by index, at parity with Arm A (Arm B previously only synthesized single
//! paths in test harnesses).
//!
//! RED: the Poseidon2 / sponge soundness obligations are unmet (see the Arm B obligation packet);
//! this is a functional builder, not a soundness statement.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_core::Result;
use lib_q_stark_baby_bear::BabyBear;

use crate::air::next_power_of_two;
use crate::air::wide_merkle_path_baby_bear::{
    WideDigestBb,
    compress_bb,
};
use crate::air::wide_sponge_baby_bear::poseidon2_wide_hash_bb;

/// Maximum supported tree depth. `from_leaf_digests` materializes `2^depth` leaves, so this caps
/// the in-memory builder; deeper trees should stream/synthesize paths instead.
pub const MAX_TREE_DEPTH_BB: usize = 28;

/// 2-to-1 node hash (`compress_bb`) — re-exported under the Merkle-builder name for symmetry with
/// Arm A's [`crate::merkle::wide_node_hash`].
#[must_use]
pub fn wide_node_hash_bb(left: &WideDigestBb, right: &WideDigestBb) -> WideDigestBb {
    compress_bb(left, right)
}

/// Canonical wide digest for empty/padding leaves: `H()` (Poseidon2 sponge of empty input).
#[must_use]
pub fn wide_empty_leaf_bb() -> WideDigestBb {
    let h: [BabyBear; 9] = poseidon2_wide_hash_bb(&[]);
    h
}

/// Wide-digest (BabyBear / Poseidon2) binary Merkle tree. Mirrors
/// [`crate::merkle::WidePoseidonMerkleTree`] with `WideDigestBb` nodes and [`compress_bb`].
#[derive(Clone)]
pub struct WidePoseidonMerkleTreeBb {
    /// `layers[0]` = leaf digests (padded to a power of two), `layers[depth]` = `[root]`.
    layers: Vec<Vec<WideDigestBb>>,
    /// Number of real leaves (before power-of-two padding).
    num_real_leaves: usize,
}

impl WidePoseidonMerkleTreeBb {
    /// Build a tree from precomputed leaf digests (in the membership statement each leaf is
    /// `L = H(t)`). Count is padded to the next power of two with [`wide_empty_leaf_bb`].
    ///
    /// # Errors
    /// Leaf count 0, or padded depth exceeds [`MAX_TREE_DEPTH_BB`].
    pub fn from_leaf_digests(leaves: &[WideDigestBb]) -> Result<Self> {
        let n = leaves.len();
        if n == 0 {
            return Err(lib_q_core::Error::InvalidState {
                operation: "WidePoseidonMerkleTreeBb::from_leaf_digests".into(),
                reason: "at least one leaf required".into(),
            });
        }
        let padded = core::cmp::max(2, next_power_of_two(n));
        let depth = (padded as u64).trailing_zeros() as usize;
        if depth > MAX_TREE_DEPTH_BB {
            return Err(lib_q_core::Error::InvalidState {
                operation: "WidePoseidonMerkleTreeBb::from_leaf_digests".into(),
                reason: alloc::format!("leaf count (padded {padded}) exceeds 2^{MAX_TREE_DEPTH_BB}"),
            });
        }

        let mut layer0 = leaves.to_vec();
        let empty = wide_empty_leaf_bb();
        while layer0.len() < padded {
            layer0.push(empty);
        }

        let mut layers = vec![layer0];
        for _ in 0..depth {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                next.push(compress_bb(&pair[0], &pair[1]));
            }
            layers.push(next);
        }

        Ok(Self { layers, num_real_leaves: n })
    }

    /// Root digest.
    #[must_use]
    pub fn root(&self) -> WideDigestBb {
        self.layers.last().and_then(|v| v.first()).copied().unwrap_or_else(wide_empty_leaf_bb)
    }

    /// Tree depth (number of path levels).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.layers.len().saturating_sub(1)
    }

    /// Number of real leaves (before padding).
    #[must_use]
    pub fn num_leaves(&self) -> usize {
        self.num_real_leaves
    }

    /// Authentication path for a leaf index: `(path_bits, siblings)` where `path_bits[level]` is
    /// true when the leaf is the RIGHT child at that level (the convention the AIR uses).
    ///
    /// # Errors
    /// `leaf_index >= num_leaves()`.
    pub fn path(&self, leaf_index: usize) -> Result<(Vec<bool>, Vec<WideDigestBb>)> {
        if leaf_index >= self.num_real_leaves {
            return Err(lib_q_core::Error::InvalidState {
                operation: "WidePoseidonMerkleTreeBb::path".into(),
                reason: alloc::format!(
                    "leaf_index {leaf_index} >= num_leaves {}",
                    self.num_real_leaves
                ),
            });
        }
        let mut path_bits = Vec::with_capacity(self.depth());
        let mut siblings = Vec::with_capacity(self.depth());
        let mut idx = leaf_index;
        for layer in self.layers.iter().take(self.depth()) {
            let sibling = layer.get(idx ^ 1).copied().unwrap_or_else(wide_empty_leaf_bb);
            siblings.push(sibling);
            path_bits.push((idx & 1) == 1);
            idx >>= 1;
        }
        Ok((path_bits, siblings))
    }

    /// Recompute the root from a leaf + path and compare. Same direction convention as [`Self::path`].
    #[must_use]
    pub fn verify_path(
        root: &WideDigestBb,
        leaf: &WideDigestBb,
        path_bits: &[bool],
        siblings: &[WideDigestBb],
    ) -> bool {
        if path_bits.len() != siblings.len() {
            return false;
        }
        let mut cur = *leaf;
        for (bit, sib) in path_bits.iter().zip(siblings.iter()) {
            cur = if *bit { compress_bb(sib, &cur) } else { compress_bb(&cur, sib) };
        }
        cur == *root
    }
}

impl core::fmt::Debug for WidePoseidonMerkleTreeBb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WidePoseidonMerkleTreeBb")
            .field("depth", &self.depth())
            .field("num_real_leaves", &self.num_real_leaves)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::unlinkable_membership_baby_bear::membership_leaf_bb;

    const P: u32 = 2_013_265_921;
    fn t_from_seed(seed: u32) -> [BabyBear; 6] {
        let mut x = seed.wrapping_mul(40_503).wrapping_add(11);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }

    #[test]
    fn empty_input_rejected() {
        assert!(WidePoseidonMerkleTreeBb::from_leaf_digests(&[]).is_err());
    }

    #[test]
    fn build_root_path_verify_roundtrip() {
        // 6 members → padded to 8 leaves → depth 3 (non-power-of-two leaf count exercises padding).
        let leaves: Vec<WideDigestBb> =
            (0..6u32).map(|i| membership_leaf_bb(&t_from_seed(i))).collect();
        let tree = WidePoseidonMerkleTreeBb::from_leaf_digests(&leaves).unwrap();
        assert_eq!(tree.depth(), 3);
        assert_eq!(tree.num_leaves(), 6);
        for idx in 0..6usize {
            let (bits, sibs) = tree.path(idx).unwrap();
            assert_eq!(bits.len(), 3);
            // The extracted path folds the real leaf back to the tree root.
            assert!(
                WidePoseidonMerkleTreeBb::verify_path(&tree.root(), &leaves[idx], &bits, &sibs),
                "path for leaf {idx} must verify against the root"
            );
        }
        // A wrong leaf must NOT verify against a real path.
        let (bits, sibs) = tree.path(2).unwrap();
        let wrong = membership_leaf_bb(&t_from_seed(999));
        assert!(!WidePoseidonMerkleTreeBb::verify_path(&tree.root(), &wrong, &bits, &sibs));
    }

    #[test]
    fn path_index_out_of_range_rejected() {
        let leaves: Vec<WideDigestBb> =
            (0..4u32).map(|i| membership_leaf_bb(&t_from_seed(i))).collect();
        let tree = WidePoseidonMerkleTreeBb::from_leaf_digests(&leaves).unwrap();
        assert!(tree.path(4).is_err());
    }
}
