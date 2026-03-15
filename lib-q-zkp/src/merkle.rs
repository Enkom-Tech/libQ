//! Poseidon Merkle tree builder compatible with MerkleInclusionAir.
//!
//! Builds a binary Merkle tree using Poseidon-128; roots and paths work with
//! `prove_membership` and `verify_membership`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_core::Result;
use lib_q_poseidon::{
    Poseidon,
    Poseidon128,
};

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

        let poseidon = Poseidon128;
        for _ in 0..depth {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                let left = pair[0].as_field();
                let right = pair[1].as_field();
                let combined = poseidon.hash(&[*left, *right]);
                next.push(MerkleHash::from_field(combined[0]));
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
    /// Returns `(path_bits, siblings)` where path_bits[level] is true when
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
