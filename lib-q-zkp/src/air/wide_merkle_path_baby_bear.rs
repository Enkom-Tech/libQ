//! Wide-digest Merkle path AIR over Poseidon2-BabyBear (Arm B, build-spec step 4b) — the
//! BabyBear analogue of `wide_merkle_path.rs`.
//!
//! Proves a leaf digest `L` (9 BabyBear cells) is included under a public `root` (9 cells)
//! via a private authentication path (siblings + direction bits). A wide-digest node compresses
//! two 9-cell children (18 inputs) into a 9-cell parent with the shared wide sponge.
//!
//! One trace ROW per tree level. Row layout (width `PATH_ROW_WIDTH = 826`):
//! `[ running(9) | sibling(9) | dir(1) | interm(3·269 = 807) ]`.
//! * `running` — digest entering this level (row 0 = leaf; threaded up the tree).
//! * `sibling` — authentication-path sibling at this level (private witness).
//! * `dir`     — boolean direction bit: `dir == 1` ⇒ `running` is the RIGHT child.
//!
//! Public values: `[ leaf(9) ‖ root(9) ]`. First row binds `running == leaf`; the transition
//! binds the next level's `running` to this level's `parent`; the last row binds `parent == root`.
//! Tier RED.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::{
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;

use crate::air::wide_sponge_baby_bear::{
    WIDE_DIGEST_ELEMS,
    constrain_wide_sponge_bb,
    generate_wide_sponge_bb_cells,
    poseidon2_wide_hash_bb,
    wide_sponge_bb_interm_cols,
};

/// A wide digest: `WIDE_DIGEST_ELEMS` BabyBear cells.
pub type WideDigestBb = [BabyBear; WIDE_DIGEST_ELEMS];

const RUNNING_START: usize = 0;
const SIBLING_START: usize = WIDE_DIGEST_ELEMS; // 9
const DIR_COL: usize = 2 * WIDE_DIGEST_ELEMS; // 18
const PERM_INTERM_START: usize = 2 * WIDE_DIGEST_ELEMS + 1; // 19
/// A node hashes `left ‖ right` = 18 inputs.
pub const NODE_INPUT_LEN: usize = 2 * WIDE_DIGEST_ELEMS;
/// Columns per path row: control (19) + node-sponge intermediates (3·269 = 807) = 826.
pub const PATH_ROW_WIDTH: usize = PERM_INTERM_START + wide_sponge_bb_interm_cols(NODE_INPUT_LEN);
/// Public values: `leaf(9) ‖ root(9)`.
pub const PATH_NUM_PUBLIC: usize = 2 * WIDE_DIGEST_ELEMS;

/// Value-level 2-to-1 compression: `parent = H(left ‖ right)`.
pub fn compress_bb(left: &WideDigestBb, right: &WideDigestBb) -> WideDigestBb {
    let mut input = [BabyBear::ZERO; NODE_INPUT_LEN];
    input[..WIDE_DIGEST_ELEMS].copy_from_slice(left);
    input[WIDE_DIGEST_ELEMS..].copy_from_slice(right);
    poseidon2_wide_hash_bb(&input)
}

/// Depth-agnostic Merkle-path AIR: one row per level threads the running digest leaf→root.
#[derive(Debug, Clone, Copy, Default)]
pub struct WideMerklePathBbAir;

impl<F: Field> BaseAir<F> for WideMerklePathBbAir {
    fn width(&self) -> usize {
        PATH_ROW_WIDTH
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for WideMerklePathBbAir {
    fn eval(&self, builder: &mut AB) {
        // Read control columns (drop the `main` borrow before any gadget call).
        let (running, sibling, dir_expr, dir_var) = {
            let main = builder.main();
            let local = main.current_slice();
            let running: Vec<AB::Expr> =
                (0..WIDE_DIGEST_ELEMS).map(|i| local[RUNNING_START + i].into()).collect();
            let sibling: Vec<AB::Expr> =
                (0..WIDE_DIGEST_ELEMS).map(|i| local[SIBLING_START + i].into()).collect();
            let dir_var = local[DIR_COL];
            let dir_expr: AB::Expr = local[DIR_COL].into();
            (running, sibling, dir_expr, dir_var)
        };

        // Direction bit must be boolean.
        builder.assert_bool(dir_var);

        // Build the 18-element node input `left ‖ right` (direction-selected):
        //   left[i]  = running[i] + dir·(sibling[i] − running[i])   (= running if dir==0)
        //   right[i] = sibling[i] + dir·(running[i] − sibling[i])   (= sibling if dir==0)
        let mut input: Vec<AB::Expr> = Vec::with_capacity(NODE_INPUT_LEN);
        for i in 0..WIDE_DIGEST_ELEMS {
            input.push(
                running[i].clone() + dir_expr.clone() * (sibling[i].clone() - running[i].clone()),
            );
        }
        for i in 0..WIDE_DIGEST_ELEMS {
            input.push(
                sibling[i].clone() + dir_expr.clone() * (running[i].clone() - sibling[i].clone()),
            );
        }

        // Constrain the node hash `parent = H(left ‖ right)`.
        let parent = constrain_wide_sponge_bb(builder, &input, PERM_INTERM_START);

        // FIRST ROW: running entering level 0 is the (public) leaf.
        {
            let pub_leaf: Vec<AB::Expr> = {
                let pubs = builder.public_values();
                (0..WIDE_DIGEST_ELEMS).map(|i| pubs[i].into()).collect()
            };
            let mut b = builder.when_first_row();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(running[i].clone(), pub_leaf[i].clone());
            }
        }

        // TRANSITION (level k → k+1): next level's running is this level's parent.
        {
            let next_running: Vec<AB::Expr> = {
                let main = builder.main();
                let next = main.next_slice();
                (0..WIDE_DIGEST_ELEMS).map(|i| next[RUNNING_START + i].into()).collect()
            };
            let mut b = builder.when_transition();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(next_running[i].clone(), parent[i].clone());
            }
        }

        // LAST ROW: the final parent is the (public) root.
        {
            let pub_root: Vec<AB::Expr> = {
                let pubs = builder.public_values();
                (0..WIDE_DIGEST_ELEMS).map(|i| pubs[WIDE_DIGEST_ELEMS + i].into()).collect()
            };
            let mut b = builder.when_last_row();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(parent[i].clone(), pub_root[i].clone());
            }
        }
    }
}

/// Generate the `depth`-row trace for a wide-digest Merkle path. `path_bits[k]` and
/// `siblings[k]` are the direction bit and sibling at level `k` (leaf-to-root).
pub fn generate_path_trace_bb(
    leaf: &WideDigestBb,
    path_bits: &[bool],
    siblings: &[WideDigestBb],
) -> RowMajorMatrix<BabyBear> {
    debug_assert_eq!(path_bits.len(), siblings.len());
    let depth = path_bits.len();
    let mut cells: Vec<BabyBear> = Vec::with_capacity(depth * PATH_ROW_WIDTH);
    let mut running = *leaf;

    for level in 0..depth {
        let dir = path_bits[level];
        let sib = siblings[level];
        let (left, right) = if dir { (sib, running) } else { (running, sib) };

        let mut input = [BabyBear::ZERO; NODE_INPUT_LEN];
        input[..WIDE_DIGEST_ELEMS].copy_from_slice(&left);
        input[WIDE_DIGEST_ELEMS..].copy_from_slice(&right);

        cells.extend_from_slice(&running);
        cells.extend_from_slice(&sib);
        cells.push(if dir { BabyBear::ONE } else { BabyBear::ZERO });

        let (interm, parent) = generate_wide_sponge_bb_cells(&input);
        cells.extend_from_slice(&interm);
        running = parent;
    }

    debug_assert_eq!(cells.len(), depth * PATH_ROW_WIDTH);
    RowMajorMatrix::new(cells, PATH_ROW_WIDTH)
}

/// Public values for the path AIR: `leaf(9) ‖ root(9)`.
pub fn path_public_values_bb(leaf: &WideDigestBb, root: &WideDigestBb) -> Vec<BabyBear> {
    let mut v = Vec::with_capacity(PATH_NUM_PUBLIC);
    v.extend_from_slice(leaf);
    v.extend_from_slice(root);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check_constraints;

    const P: u32 = 2_013_265_921;

    fn digest_from_seed(seed: u32) -> WideDigestBb {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }

    /// Build a depth-`depth` tree over `2^depth` deterministic leaves, return the path for
    /// `leaf_index`: `(leaf, path_bits, siblings, root)`.
    fn build_tree_and_path(
        depth: usize,
        leaf_index: usize,
    ) -> (WideDigestBb, Vec<bool>, Vec<WideDigestBb>, WideDigestBb) {
        let n = 1usize << depth;
        let mut level: Vec<WideDigestBb> = (0..n as u32).map(digest_from_seed).collect();
        let leaf = level[leaf_index];
        let mut idx = leaf_index;
        let mut path_bits = Vec::new();
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let sib_idx = idx ^ 1;
            siblings.push(level[sib_idx]);
            path_bits.push((idx & 1) == 1); // odd index ⇒ running is the RIGHT child
            let mut next = Vec::with_capacity(level.len() / 2);
            let mut j = 0;
            while j < level.len() {
                next.push(compress_bb(&level[j], &level[j + 1]));
                j += 2;
            }
            level = next;
            idx /= 2;
        }
        (leaf, path_bits, siblings, level[0])
    }

    #[test]
    fn row_width_is_826() {
        assert_eq!(PATH_ROW_WIDTH, 826);
        assert_eq!(NODE_INPUT_LEN, 18);
    }

    #[test]
    fn fixture_roundtrip_constraints_hold_all_depths() {
        for depth in [1usize, 2, 4, 8] {
            for &leaf_index in &[0usize, 1, (1 << depth) - 1] {
                let (leaf, bits, sibs, root) = build_tree_and_path(depth, leaf_index);
                let trace = generate_path_trace_bb(&leaf, &bits, &sibs);
                let pubs = path_public_values_bb(&leaf, &root);
                check_constraints(&WideMerklePathBbAir, &trace, &pubs);
            }
        }
    }

    #[test]
    #[should_panic]
    fn wrong_sibling_rejected() {
        let (leaf, bits, mut sibs, root) = build_tree_and_path(4, 3);
        sibs[1][0] = sibs[1][0] + BabyBear::ONE; // corrupt a sibling at level 1
        let trace = generate_path_trace_bb(&leaf, &bits, &sibs);
        let pubs = path_public_values_bb(&leaf, &root);
        check_constraints(&WideMerklePathBbAir, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn wrong_direction_rejected() {
        let (leaf, mut bits, sibs, root) = build_tree_and_path(4, 3);
        bits[2] = !bits[2]; // flip a direction bit (changes child order → wrong parent)
        let trace = generate_path_trace_bb(&leaf, &bits, &sibs);
        let pubs = path_public_values_bb(&leaf, &root);
        check_constraints(&WideMerklePathBbAir, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn wrong_intermediate_rejected() {
        let (leaf, bits, sibs, root) = build_tree_and_path(4, 3);
        let mut trace = generate_path_trace_bb(&leaf, &bits, &sibs);
        trace.values[PERM_INTERM_START] = trace.values[PERM_INTERM_START] + BabyBear::ONE;
        let pubs = path_public_values_bb(&leaf, &root);
        check_constraints(&WideMerklePathBbAir, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn wrong_root_rejected() {
        let (leaf, bits, sibs, root) = build_tree_and_path(4, 3);
        let trace = generate_path_trace_bb(&leaf, &bits, &sibs);
        let mut pubs = path_public_values_bb(&leaf, &root);
        pubs[WIDE_DIGEST_ELEMS] = pubs[WIDE_DIGEST_ELEMS] + BabyBear::ONE; // corrupt public root
        check_constraints(&WideMerklePathBbAir, &trace, &pubs);
    }
}
