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
use crate::air::wide_hash::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
    poseidon256_wide_hash,
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

// ---------------------------------------------------------------------------
// Wide-digest (Poseidon-256, ≥128-bit) Merkle tree — M2, RED (ADR 113).
// ---------------------------------------------------------------------------

/// 2-to-1 wide-digest compression: parent = H(left ‖ right) over the 10 child field
/// elements via the canonical padded Poseidon-256 sponge ([`poseidon256_wide_hash`]).
///
/// This is the node hash the wide-Merkle AIR (`air::wide_merkle`, M2) constrains. Keeping
/// the value-level builder and the AIR on the SAME function is what makes roots/paths
/// consistent with what the circuit proves (cf. the Poseidon-128 note in
/// [`PoseidonMerkleTree::from_leaves`]).
pub fn wide_node_hash(left: &WideDigest, right: &WideDigest) -> WideDigest {
    let mut input = Vec::with_capacity(2 * WIDE_DIGEST_ELEMS);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    poseidon256_wide_hash(&input)
}

/// Canonical wide digest for empty/padding leaves: `H()` (Poseidon-256 sponge of empty
/// input — absorbs nothing, pads, permutes).
pub fn wide_empty_leaf() -> WideDigest {
    poseidon256_wide_hash(&[])
}

/// Wide-digest (Poseidon-256, ~155-bit capacity ceiling) binary Merkle tree.
///
/// Mirrors [`PoseidonMerkleTree`] but every node is a [`WideDigest`] (5 field elements)
/// and the compression is [`wide_node_hash`]. Leaves are themselves wide digests (in the
/// membership statement, each leaf is `L = H(t)`); use [`Self::from_leaf_digests`].
///
/// RED: Poseidon-256 round counts are NOT verified for GF(p²) — see the
/// `air::wide_hash` freeze-gate. Gated behind the ADR-113 review.
#[derive(Clone)]
pub struct WidePoseidonMerkleTree {
    /// layers[0] = leaf digests (padded to power of 2), layers[depth] = [root]
    layers: Vec<Vec<WideDigest>>,
    /// Number of real leaves (before power-of-2 padding)
    num_real_leaves: usize,
}

impl WidePoseidonMerkleTree {
    /// Build a wide-digest Merkle tree from precomputed leaf digests.
    ///
    /// In the membership statement each leaf is `L = H(t)` (a wide digest), so leaves are
    /// supplied already-hashed. Count is padded to the next power of two with
    /// [`wide_empty_leaf`].
    ///
    /// # Errors
    ///
    /// Returns error if leaf count is 0 or the padded depth exceeds [`MAX_TREE_DEPTH`].
    pub fn from_leaf_digests(leaves: &[WideDigest]) -> Result<Self> {
        let n = leaves.len();
        if n == 0 {
            return Err(lib_q_core::Error::InvalidState {
                operation: "WidePoseidonMerkleTree::from_leaf_digests".into(),
                reason: "at least one leaf required".into(),
            });
        }
        let padded = core::cmp::max(2, next_power_of_two(n));
        let depth = (padded as u64).trailing_zeros() as usize;
        if depth > MAX_TREE_DEPTH {
            return Err(lib_q_core::Error::InvalidState {
                operation: "WidePoseidonMerkleTree::from_leaf_digests".into(),
                reason: alloc::format!(
                    "leaf count (padded {}) exceeds 2^{}",
                    padded,
                    MAX_TREE_DEPTH
                ),
            });
        }

        let mut layer0 = leaves.to_vec();
        let empty = wide_empty_leaf();
        while layer0.len() < padded {
            layer0.push(empty);
        }

        let mut layers = vec![layer0];
        for _ in 0..depth {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                next.push(wide_node_hash(&pair[0], &pair[1]));
            }
            layers.push(next);
        }

        Ok(Self {
            layers,
            num_real_leaves: n,
        })
    }

    /// Root digest of the tree.
    pub fn root(&self) -> WideDigest {
        self.layers
            .last()
            .and_then(|v| v.first())
            .copied()
            .unwrap_or_else(wide_empty_leaf)
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
    /// Returns `(path_bits, siblings)` where `path_bits[level]` is true when the leaf is on
    /// the right at that level.
    ///
    /// # Errors
    ///
    /// Returns error if `leaf_index >= num_leaves()` (real leaves only).
    pub fn path(&self, leaf_index: usize) -> Result<(Vec<bool>, Vec<WideDigest>)> {
        if leaf_index >= self.num_real_leaves {
            return Err(lib_q_core::Error::InvalidState {
                operation: "WidePoseidonMerkleTree::path".into(),
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
                .copied()
                .unwrap_or_else(wide_empty_leaf);
            siblings.push(sibling);
            path_bits.push((idx & 1) == 1);
            idx >>= 1;
        }

        Ok((path_bits, siblings))
    }

    /// Recompute the root from a leaf digest and path and compare to `root`.
    ///
    /// Uses the same direction convention as [`Self::path`]: `path_bits[level] == true`
    /// means the running digest is the RIGHT child at that level.
    #[must_use]
    pub fn verify_path(
        root: &WideDigest,
        leaf: &WideDigest,
        path_bits: &[bool],
        siblings: &[WideDigest],
    ) -> bool {
        if path_bits.len() != siblings.len() {
            return false;
        }
        let mut cur = *leaf;
        for (bit, sib) in path_bits.iter().zip(siblings.iter()) {
            cur = if *bit {
                wide_node_hash(sib, &cur)
            } else {
                wide_node_hash(&cur, sib)
            };
        }
        cur == *root
    }
}

impl core::fmt::Debug for WidePoseidonMerkleTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WidePoseidonMerkleTree")
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

    // ---- Wide-digest tree (Poseidon-256) ----

    use crate::air::wide_hash::{
        WIDE_DIGEST_ELEMS,
        WideDigest,
        poseidon256_wide_hash,
    };

    fn leaf_digest(seed: u8) -> WideDigest {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;
        // L = H(t) with t a single secret field element, per the membership statement.
        let t = Complex::<Mersenne31>::from(Mersenne31::new(seed as u32 + 1));
        poseidon256_wide_hash(&[t])
    }

    #[test]
    fn test_wide_tree_rejects_empty_input() {
        assert!(WidePoseidonMerkleTree::from_leaf_digests(&[]).is_err());
    }

    #[test]
    fn test_wide_tree_path_and_verify_round_trip() {
        let leaves: Vec<WideDigest> = (0..5u8).map(leaf_digest).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        assert_eq!(tree.num_leaves(), 5);
        // 5 leaves → padded to 8 → depth 3.
        assert_eq!(tree.depth(), 3);

        for (i, leaf) in leaves.iter().enumerate() {
            let (path_bits, siblings) = tree.path(i).expect("path");
            assert_eq!(path_bits.len(), tree.depth());
            assert_eq!(siblings.len(), tree.depth());
            assert!(
                WidePoseidonMerkleTree::verify_path(&tree.root(), leaf, &path_bits, &siblings),
                "leaf {i} must verify against the root"
            );
        }
    }

    #[test]
    fn test_wide_tree_verify_rejects_tampering() {
        let leaves: Vec<WideDigest> = (0..4u8).map(leaf_digest).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        let (path_bits, siblings) = tree.path(2).expect("path");

        // Tamper a sibling: must fail.
        let mut bad_siblings = siblings.clone();
        bad_siblings[0][0] += leaf_digest(99)[0];
        assert!(!WidePoseidonMerkleTree::verify_path(
            &tree.root(),
            &leaves[2],
            &path_bits,
            &bad_siblings
        ));

        // Flip a direction bit: must fail (different root).
        let mut bad_bits = path_bits.clone();
        bad_bits[0] = !bad_bits[0];
        assert!(!WidePoseidonMerkleTree::verify_path(
            &tree.root(),
            &leaves[2],
            &bad_bits,
            &siblings
        ));

        // Wrong leaf: must fail.
        assert!(!WidePoseidonMerkleTree::verify_path(
            &tree.root(),
            &leaf_digest(123),
            &path_bits,
            &siblings
        ));

        // Length mismatch: must fail.
        assert!(!WidePoseidonMerkleTree::verify_path(
            &tree.root(),
            &leaves[2],
            &path_bits[..1],
            &siblings
        ));
    }

    #[test]
    fn test_wide_node_hash_is_order_sensitive() {
        let a = leaf_digest(1);
        let b = leaf_digest(2);
        assert_ne!(
            wide_node_hash(&a, &b),
            wide_node_hash(&b, &a),
            "2-to-1 compression must not be symmetric"
        );
        assert_eq!(wide_node_hash(&a, &b).len(), WIDE_DIGEST_ELEMS);
    }
}
