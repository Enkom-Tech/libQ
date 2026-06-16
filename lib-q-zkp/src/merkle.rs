//! Poseidon Merkle tree builder compatible with MerkleInclusionAir.
//!
//! Builds a binary Merkle tree using Poseidon-128; roots and paths work with
//! `prove_membership` and `verify_membership`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_core::Result;

use crate::air::merkle_inclusion::{
    MAX_TREE_DEPTH,
    MerkleHash,
};
use crate::air::{
    merkle_root_to_bytes,
    next_power_of_two,
};

/// Canonical hash for empty/padding leaves (Poseidon-128 of empty input).
fn empty_leaf_hash() -> MerkleHash {
    MerkleHash::hash_data(&[])
}

/// Poseidon-128 binary Merkle tree.
///
/// Layers are stored for path extraction. Layer 0 = leaf hashes (padded to
/// power of 2), top layer = single root. Uses same hashing as
/// `MerkleInclusionAir` so paths verify with `prove_membership` / `verify_membership`.
#[derive(Clone)]
pub struct PoseidonMerkleTree {
    /// layers[0] = leaf hashes, layers[depth] = [root]
    layers: Vec<Vec<MerkleHash>>,
    /// Number of real leaves (before power-of-2 padding)
    num_real_leaves: usize,
}

impl PoseidonMerkleTree {
    /// Build a Merkle tree from leaf data.
    ///
    /// Leaves are hashed with Poseidon-128 (same as MerkleInclusionAir).
    /// Count is padded to the next power of two with a canonical empty hash.
    ///
    /// # Errors
    ///
    /// Returns error if leaf count is 0 or exceeds 2^MAX_TREE_DEPTH.
    pub fn from_leaves(leaves: &[&[u8]]) -> Result<Self> {
        let n = leaves.len();
        if n == 0 {
            return Err(lib_q_core::Error::InvalidState {
                operation: "PoseidonMerkleTree::from_leaves".into(),
                reason: "at least one leaf required".into(),
            });
        }
        let padded = core::cmp::max(2, next_power_of_two(n));
        let depth = (padded as u64).trailing_zeros() as usize;
        if depth > MAX_TREE_DEPTH {
            return Err(lib_q_core::Error::InvalidState {
                operation: "PoseidonMerkleTree::from_leaves".into(),
                reason: alloc::format!(
                    "leaf count (padded {}) exceeds 2^{}",
                    padded,
                    MAX_TREE_DEPTH
                ),
            });
        }

        let mut layer0: Vec<MerkleHash> = leaves
            .iter()
            .map(|leaf| MerkleHash::hash_data(leaf))
            .collect();
        let empty = empty_leaf_hash();
        while layer0.len() < padded {
            layer0.push(empty.clone());
        }

        let mut layers = vec![layer0];

        for _ in 0..depth {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                let left = pair[0].as_field();
                let right = pair[1].as_field();
                // Node hash MUST match the MerkleInclusionAir gadget, which constrains a single
                // Poseidon permutation of [left, right] (not a padded sponge). Using the same
                // function here keeps tree roots consistent with what the AIR proves.
                let (combined, _) =
                    crate::air::merkle_inclusion::compute_poseidon_with_intermediates(&[
                        *left, *right,
                    ]);
                next.push(MerkleHash::from_field(combined));
            }
            layers.push(next);
        }

        Ok(Self {
            layers,
            num_real_leaves: n,
        })
    }

    /// Root hash of the tree.
    #[must_use]
    pub fn root(&self) -> MerkleHash {
        self.layers
            .last()
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(empty_leaf_hash)
    }

    /// Root as 32-byte array for `verify_membership(proof, &root_bytes)`.
    #[must_use]
    pub fn root_bytes(&self) -> [u8; 32] {
        merkle_root_to_bytes(self.root().as_field())
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

    /// Extract authentication path for a leaf index.
    ///
    /// Returns `(path_bits, siblings)` where `path_bits[level]` is true when
    /// the leaf is on the right at that level. Use these to build
    /// `MerklePath { path_bits, siblings }` for `prove_membership`.
    ///
    /// # Errors
    ///
    /// Returns error if `leaf_index >= num_leaves()` (real leaves only).
    pub fn path(&self, leaf_index: usize) -> Result<(Vec<bool>, Vec<MerkleHash>)> {
        if leaf_index >= self.num_real_leaves {
            return Err(lib_q_core::Error::InvalidState {
                operation: "PoseidonMerkleTree::path".into(),
                reason: alloc::format!(
                    "leaf_index {} >= num_leaves {}",
                    leaf_index,
                    self.num_real_leaves
                ),
            });
        }

        let mut path_bits = Vec::with_capacity(self.depth());
        let mut siblings = Vec::with_capacity(self.depth());
        let mut idx = leaf_index;

        for layer in self.layers.iter().take(self.depth()) {
            let sibling_idx = idx ^ 1;
            let sibling = layer
                .get(sibling_idx)
                .cloned()
                .unwrap_or_else(empty_leaf_hash);
            siblings.push(sibling);
            path_bits.push((idx & 1) == 1);
            idx >>= 1;
        }

        Ok((path_bits, siblings))
    }

    /// Recompute root from leaf and path and compare to expected (constant-time friendly).
    ///
    /// Uses the same convention as `MerkleInclusionAir::public_values`.
    #[must_use]
    pub fn verify_path(
        root: &MerkleHash,
        leaf: &[u8],
        path_bits: &[bool],
        siblings: &[MerkleHash],
    ) -> bool {
        use crate::air::merkle_inclusion::compute_merkle_root;
        if path_bits.len() != siblings.len() {
            return false;
        }
        let computed = compute_merkle_root(leaf, path_bits, siblings);
        computed.as_field() == root.as_field()
    }
}

impl Drop for PoseidonMerkleTree {
    fn drop(&mut self) {
        for layer in self.layers.iter_mut() {
            layer.clear();
        }
        self.layers.clear();
    }
}

impl core::fmt::Debug for PoseidonMerkleTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoseidonMerkleTree")
            .field("depth", &self.depth())
            .field("num_real_leaves", &self.num_real_leaves)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_leaves_rejects_empty_input() {
        let result = PoseidonMerkleTree::from_leaves(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_tree_path_and_verify_path_round_trip() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree = PoseidonMerkleTree::from_leaves(&leaves).expect("tree");

        let (path_bits, siblings) = tree.path(1).expect("path for index 1");
        assert_eq!(path_bits.len(), tree.depth());
        assert_eq!(siblings.len(), tree.depth());
        assert_eq!(tree.num_leaves(), 3);
        assert!(tree.root_bytes().iter().any(|b| *b != 0u8));

        let is_valid =
            PoseidonMerkleTree::verify_path(&tree.root(), leaves[1], &path_bits, &siblings);
        assert!(is_valid);
    }

    #[test]
    fn test_tree_path_rejects_out_of_bounds_index() {
        let leaves: Vec<&[u8]> = vec![b"x", b"y"];
        let tree = PoseidonMerkleTree::from_leaves(&leaves).expect("tree");
        let result = tree.path(2);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_path_rejects_invalid_inputs() {
        let leaves: Vec<&[u8]> = vec![b"left", b"right"];
        let tree = PoseidonMerkleTree::from_leaves(&leaves).expect("tree");
        let (path_bits, siblings) = tree.path(0).expect("path");

        let mut wrong_siblings = siblings.clone();
        wrong_siblings[0] = MerkleHash::hash_data(b"wrong");
        assert!(!PoseidonMerkleTree::verify_path(
            &tree.root(),
            leaves[0],
            &path_bits,
            &wrong_siblings
        ));

        assert!(!PoseidonMerkleTree::verify_path(
            &tree.root(),
            leaves[0],
            &path_bits[..0],
            &siblings
        ));
    }
}
