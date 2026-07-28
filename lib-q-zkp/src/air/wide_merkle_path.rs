//! Wide-digest Merkle PATH AIR (M2, RED — ADR 113 freeze-gate).
//!
//! Proves a leaf digit `L` (5 field elements) is included under a public `root` (5 field
//! elements) of a [`crate::merkle::WidePoseidonMerkleTree`], via a private authentication
//! path (siblings + direction bits).
//!
//! # Why one row per LEVEL (not per permutation, not one row total)
//!
//! A wide-digest node compresses two 5-element children (10 inputs) into a 5-element parent
//! via a 6-permutation Poseidon-256 sponge ([`crate::merkle::wide_node_hash`]). There are
//! three ways to lay this out as an AIR:
//!
//! * **One row total** (like [`super::merkle_inclusion::MerkleInclusionAir`]): at wide
//!   digests this is `6 × 1428 ≈ 8568` cols per level × depth ⇒ ~550k cols at depth 64,
//!   past `MAX_TRACE_WIDTH` (131072). Infeasible.
//! * **One row per permutation** (like the [`super::wide_merkle::WideNodeHashAir`] atom):
//!   narrow (~1437 cols) but `depth × 6` rows, and threading the running digest across
//!   level boundaries needs a constrained block-position counter (selector machinery) since
//!   the AIR only sees a 2-row window. Sound but fiddly.
//! * **One row per level** (THIS module): each row holds all 6 permutations of one node
//!   hash (`11 + 6×1428 = 8579` cols, comfortably < `MAX_TRACE_WIDTH`) over exactly `depth`
//!   rows. The running digest threads through a plain 2-row transition window
//!   (`next.running == parent`), and the entire injection schedule (which child element is
//!   absorbed in which block, plus the `10*1` padding constant) is baked into the eval
//!   *expressions* — there are NO committed injection columns for a prover to tamper. This
//!   is the simplest sound layout and what the membership AIR (M3) composes on.
//!
//! # Column layout (one row = one Merkle level)
//!
//! `[ running(5) | sibling(5) | dir(1) | interm_0(1428) | … | interm_5(1428) ]`
//!
//! * `running` — the digest entering this level (level 0 = the leaf).
//! * `sibling` — the authentication-path sibling at this level (private witness).
//! * `dir` — direction bit (boolean-constrained): `dir == 1` ⇒ running is the RIGHT child.
//! * `interm_p` — the round intermediates of permutation `p` of the 6-perm sponge.
//!
//! Public values: `[ leaf(5) ‖ root(5) ]` (10 elements). First row binds `running == leaf`;
//! last row binds `parent == root`.
//!
//! RED: Poseidon-256 round counts are NOT verified for GF(p²) — see `super::wide_hash`.

extern crate alloc;

use alloc::vec::Vec;

use lib_q_poseidon::PoseidonField;
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::poseidon_to_field;
use super::wide_hash::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
};
use super::wide_sponge::{
    constrain_wide_sponge,
    generate_wide_sponge_cells,
    wide_sponge_interm_cols,
};

/// A wide node absorbs `2 × WIDE_DIGEST_ELEMS` = 10 input elements (`left ‖ right`).
const NODE_INPUT_LEN: usize = 2 * WIDE_DIGEST_ELEMS; // 10

/// Column offsets within one level row.
const RUNNING_START: usize = 0;
const SIBLING_START: usize = RUNNING_START + WIDE_DIGEST_ELEMS; // 5
const DIR_COL: usize = SIBLING_START + WIDE_DIGEST_ELEMS; // 10
const PERM_INTERM_START: usize = DIR_COL + 1; // 11
/// Total width of one level row: `11 + 6 × 1428 = 8579` (control + the node sponge's
/// 6 permutation-intermediate regions).
pub const PATH_ROW_WIDTH: usize = PERM_INTERM_START + wide_sponge_interm_cols(NODE_INPUT_LEN);

/// Number of public values: `leaf(5) ‖ root(5)`.
pub const PATH_NUM_PUBLIC: usize = 2 * WIDE_DIGEST_ELEMS; // 10

/// AIR proving wide-digest Merkle inclusion: each row verifies one level's node hash and
/// threads the running digest from leaf to root.
///
/// Depth-agnostic: the path depth is the trace height; `width()` is constant. Siblings and
/// direction bits are private witnesses; only `leaf` and `root` are public.
#[derive(Debug, Clone, Default)]
pub struct WideMerklePathAir;

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for WideMerklePathAir {
    fn width(&self) -> usize {
        PATH_ROW_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for WideMerklePathAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);

        // --- Read control columns (drop the `main` borrow before any gadget call). ---
        let (running, sibling, dir_expr, dir_var) = {
            let main = builder.main();
            let local = main.current_slice();
            let running: Vec<AB::Expr> = (0..WIDE_DIGEST_ELEMS)
                .map(|i| local[RUNNING_START + i].into())
                .collect();
            let sibling: Vec<AB::Expr> = (0..WIDE_DIGEST_ELEMS)
                .map(|i| local[SIBLING_START + i].into())
                .collect();
            let dir_var = local[DIR_COL];
            let dir_expr: AB::Expr = local[DIR_COL].into();
            (running, sibling, dir_expr, dir_var)
        };

        // Direction bit must be boolean.
        builder.assert_bool(dir_var);

        // --- Build the 10-element node input `left ‖ right` (direction-selected). ---
        // left[i]  = running[i] + dir·(sibling[i] − running[i])   (= running if dir==0)
        // right[i] = sibling[i] + dir·(running[i] − sibling[i])   (= sibling if dir==0)
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

        // --- Constrain the node hash `parent = H(left ‖ right)` via the shared wide sponge.
        let parent = match constrain_wide_sponge(builder, &input, PERM_INTERM_START) {
            Ok(p) => p,
            Err(_) => {
                builder.assert_zero(one.clone());
                return;
            }
        };

        // --- Boundary / threading constraints. ---

        // FIRST ROW: the running digest entering level 0 is the (public) leaf.
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

        // TRANSITION (level k → k+1): next level's running digest is this level's parent.
        {
            let next_running: Vec<AB::Expr> = {
                let main = builder.main();
                let next = main.next_slice();
                (0..WIDE_DIGEST_ELEMS)
                    .map(|i| next[RUNNING_START + i].into())
                    .collect()
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
                (0..WIDE_DIGEST_ELEMS)
                    .map(|i| pubs[WIDE_DIGEST_ELEMS + i].into())
                    .collect()
            };
            let mut b = builder.when_last_row();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(parent[i].clone(), pub_root[i].clone());
            }
        }
    }
}

/// Generate the `depth`-row trace for a wide-digest Merkle path.
///
/// Each row holds one level's control columns (`running`, `sibling`, `dir`) and the round
/// intermediates of all 6 permutations of that level's node hash. The running digest of row
/// `k+1` equals the computed parent of row `k`; the last row's parent equals the tree root
/// (matches [`crate::merkle::WidePoseidonMerkleTree::verify_path`]).
///
/// `path_bits` and `siblings` must have the same length (the tree depth).
pub fn generate_path_trace<F: Field + BasedVectorSpace<Mersenne31>>(
    leaf: &WideDigest,
    path_bits: &[bool],
    siblings: &[WideDigest],
) -> RowMajorMatrix<F> {
    debug_assert_eq!(path_bits.len(), siblings.len());
    let zero = PoseidonField::ZERO;
    let one = PoseidonField::ONE;
    let depth = path_bits.len();

    let mut cells: Vec<PoseidonField> = Vec::with_capacity(depth * PATH_ROW_WIDTH);
    let mut running = *leaf;

    for level in 0..depth {
        let dir = path_bits[level];
        let sib = siblings[level];
        let (left, right) = if dir { (sib, running) } else { (running, sib) };

        let mut input = [zero; NODE_INPUT_LEN];
        input[..WIDE_DIGEST_ELEMS].copy_from_slice(&left);
        input[WIDE_DIGEST_ELEMS..].copy_from_slice(&right);

        // Control columns, then the node sponge's intermediate cells.
        cells.extend_from_slice(&running);
        cells.extend_from_slice(&sib);
        cells.push(if dir { one } else { zero });

        let (interm, parent) = generate_wide_sponge_cells(&input);
        cells.extend_from_slice(&interm);
        running = parent;
    }

    debug_assert_eq!(cells.len(), depth * PATH_ROW_WIDTH);
    let values: Vec<F> = cells.iter().map(poseidon_to_field).collect();
    RowMajorMatrix::new(values, PATH_ROW_WIDTH)
}

/// Public values for the path AIR: `leaf(5) ‖ root(5)`.
pub fn path_public_values<F: Field + BasedVectorSpace<Mersenne31>>(
    leaf: &WideDigest,
    root: &WideDigest,
) -> Vec<F> {
    leaf.iter()
        .chain(root.iter())
        .map(poseidon_to_field)
        .collect()
}

#[cfg(test)]
mod tests {
    use lib_q_stark::check_constraints;
    use lib_q_stark_field::extension::Complex;

    use super::*;
    use crate::air::wide_hash::poseidon256_wide_hash;
    use crate::merkle::WidePoseidonMerkleTree;

    type TestField = Complex<Mersenne31>;

    fn leaf_digest(seed: u8) -> WideDigest {
        let t = Complex::<Mersenne31>::from(Mersenne31::new(seed as u32 + 1));
        poseidon256_wide_hash(&[t])
    }

    fn cell(trace: &RowMajorMatrix<TestField>, row: usize, col: usize) -> TestField {
        trace.values[row * PATH_ROW_WIDTH + col]
    }
    fn set_cell(trace: &mut RowMajorMatrix<TestField>, row: usize, col: usize, v: TestField) {
        trace.values[row * PATH_ROW_WIDTH + col] = v;
    }

    /// Build an 8-leaf (depth-3) tree and return `(leaf, root, path_bits, siblings)` for an
    /// index.
    fn fixture(index: usize) -> (WideDigest, WideDigest, Vec<bool>, Vec<WideDigest>) {
        let leaves: Vec<WideDigest> = (0..6u8).map(leaf_digest).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        let (path_bits, siblings) = tree.path(index).expect("path");
        (leaves[index], tree.root(), path_bits, siblings)
    }

    #[test]
    fn path_trace_root_matches_tree() {
        let (leaf, root, path_bits, siblings) = fixture(3);
        // Value-level invariant the AIR relies on.
        assert!(WidePoseidonMerkleTree::verify_path(
            &root, &leaf, &path_bits, &siblings
        ));
        let trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        assert_eq!(trace.values.len(), path_bits.len() * PATH_ROW_WIDTH);
    }

    #[test]
    fn path_air_round_trip_all_indices() {
        for index in 0..6 {
            let (leaf, root, path_bits, siblings) = fixture(index);
            let trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
            let pubs = path_public_values::<TestField>(&leaf, &root);
            check_constraints(&WideMerklePathAir, &trace, &pubs);
        }
    }

    #[test]
    #[should_panic(expected = "constraints had nonzero value")]
    fn path_air_rejects_wrong_root() {
        let (leaf, root, path_bits, siblings) = fixture(2);
        let trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let mut pubs = path_public_values::<TestField>(&leaf, &root);
        pubs[WIDE_DIGEST_ELEMS] += TestField::ONE; // perturb root[0]
        check_constraints(&WideMerklePathAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "constraints had nonzero value")]
    fn path_air_rejects_wrong_leaf_public() {
        let (leaf, root, path_bits, siblings) = fixture(2);
        let trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let mut pubs = path_public_values::<TestField>(&leaf, &root);
        pubs[0] += TestField::ONE; // public leaf no longer matches row-0 running
        check_constraints(&WideMerklePathAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "constraints had nonzero value")]
    fn path_air_rejects_non_member_leaf() {
        // A leaf NOT in the tree, but presented with a real member's path: the recomputed
        // root cannot match the public root (would require a hash collision).
        let (_leaf, root, path_bits, siblings) = fixture(1);
        let forged = leaf_digest(200);
        let trace = generate_path_trace::<TestField>(&forged, &path_bits, &siblings);
        let pubs = path_public_values::<TestField>(&forged, &root);
        check_constraints(&WideMerklePathAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn path_air_rejects_tampered_sibling() {
        let (leaf, root, path_bits, siblings) = fixture(4);
        let mut trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let pubs = path_public_values::<TestField>(&leaf, &root);
        // Tamper sibling[0] on row 0: its node input changes, so parent != next.running.
        let v = cell(&trace, 0, SIBLING_START);
        set_cell(&mut trace, 0, SIBLING_START, v + TestField::ONE);
        check_constraints(&WideMerklePathAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "values didn't match on row")]
    fn path_air_rejects_tampered_intermediate() {
        let (leaf, root, path_bits, siblings) = fixture(0);
        let mut trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let pubs = path_public_values::<TestField>(&leaf, &root);
        let v = cell(&trace, 1, PERM_INTERM_START + 200);
        set_cell(&mut trace, 1, PERM_INTERM_START + 200, v + TestField::ONE);
        check_constraints(&WideMerklePathAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "constraints had nonzero value")]
    fn path_air_rejects_broken_running_carry() {
        // Corrupt row 1's running digest: it must equal row 0's computed parent.
        let (leaf, root, path_bits, siblings) = fixture(5);
        let mut trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let pubs = path_public_values::<TestField>(&leaf, &root);
        let v = cell(&trace, 1, RUNNING_START);
        set_cell(&mut trace, 1, RUNNING_START, v + TestField::ONE);
        check_constraints(&WideMerklePathAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "constraints had nonzero value")]
    fn path_air_rejects_nonboolean_dir() {
        let (leaf, root, path_bits, siblings) = fixture(3);
        let mut trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let pubs = path_public_values::<TestField>(&leaf, &root);
        let two = TestField::ONE + TestField::ONE;
        set_cell(&mut trace, 0, DIR_COL, two);
        check_constraints(&WideMerklePathAir, &trace, &pubs);
    }

    /// Full STARK prove → verify round-trip at a power-of-2 depth (4). This de-risks the
    /// degree/FRI-config assumptions of the 6-perm-per-row layout against the REAL prover
    /// (not just `check_constraints`) before the membership AIR (M3) composes on it.
    #[test]
    fn path_air_real_prover_round_trip_depth4() {
        use crate::stark::{
            StarkProver,
            StarkVerifier,
            fast_proof_config,
        };

        // 16 leaves → padded depth 4 → trace height 4 (power of two).
        let leaves: Vec<WideDigest> = (0..16u8).map(leaf_digest).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        assert_eq!(tree.depth(), 4);

        let index = 11;
        let (path_bits, siblings) = tree.path(index).expect("path");
        let leaf = leaves[index];
        let root = tree.root();

        let trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let pubs = path_public_values::<TestField>(&leaf, &root);

        let cfg = fast_proof_config();
        let proof = StarkProver::new(cfg.clone())
            .prove(&WideMerklePathAir, trace, &pubs)
            .expect("prove");
        StarkVerifier::new(cfg)
            .verify(&WideMerklePathAir, &proof, &pubs)
            .expect("verify");
    }

    /// The real prover/verifier must REJECT a path proven against the wrong public root.
    #[test]
    fn path_air_real_prover_rejects_wrong_root() {
        use crate::stark::{
            StarkProver,
            StarkVerifier,
            fast_proof_config,
        };

        let leaves: Vec<WideDigest> = (0..16u8).map(leaf_digest).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        let index = 4;
        let (path_bits, siblings) = tree.path(index).expect("path");
        let leaf = leaves[index];
        let root = tree.root();

        let trace = generate_path_trace::<TestField>(&leaf, &path_bits, &siblings);
        let honest_pubs = path_public_values::<TestField>(&leaf, &root);

        let cfg = fast_proof_config();
        let proof = StarkProver::new(cfg.clone())
            .prove(&WideMerklePathAir, trace, &honest_pubs)
            .expect("prove");

        // Verify against a tampered public root: must fail.
        let mut wrong_pubs = honest_pubs.clone();
        wrong_pubs[WIDE_DIGEST_ELEMS] += TestField::ONE;
        assert!(
            StarkVerifier::new(cfg)
                .verify(&WideMerklePathAir, &proof, &wrong_pubs)
                .is_err(),
            "proof must not verify against the wrong root"
        );
    }
}
