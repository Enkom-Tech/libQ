//! Unlinkable set-membership AIR (M3/M4, RED — ADR 113 freeze-gate).
//!
//! Proves the unlinkable membership statement (Semaphore/Tornado nullifier shape, for
//! Sybil / domain admission):
//!
//! ```text
//! ∃ (secret t, path):
//!     MerkleVerify(root, L = H(t), path) = true
//!   ∧ N = H(domain ‖ t ‖ ctx)
//! reveal only (root, ctx, N);  L and t stay private.
//! ```
//!
//! `H` is the truncated-output Poseidon-256 wide sponge ([`super::wide_sponge`],
//! ≥128-bit capacity). The single secret trapdoor `t` produces BOTH the Merkle leaf `L` and
//! the nullifier `N`, so a member can prove admission under a fresh `ctx` while the verifier
//! learns only an unlinkable nullifier — and double-use under the same `ctx` collides on `N`.
//!
//! # Trace geometry
//!
//! One row per Merkle level (`depth` rows; reuses the single-row-per-level node sponge of
//! [`super::wide_merkle_path`]). Row 0 *additionally* carries two row-0-gated blocks:
//!
//! ```text
//! [ running(5) | sibling(5) | dir(1) | node_interm(6·1428)      ]   (every row)
//! [ t(3) | leaf_interm(2·1428) ]  [ ctx(2) | null_interm(4·1428) ]  (row 0 only)
//! ```
//!
//! * **Merkle (every row):** `parent = H(select(dir, running, sibling))`, `running` threaded
//!   `next.running == parent`, last row `parent == public root`.
//! * **Leaf (row 0):** `L = H(t)`, bound `running == L` (so the Merkle path starts at the
//!   leaf of the secret `t`; `L` is never made public).
//! * **Nullifier (row 0):** `N = H(domain ‖ t ‖ ctx)`, bound `N == public N`, and `ctx`
//!   bound to the public `ctx`.
//!
//! **Same-`t` binding is structural:** the leaf block and the nullifier block read the SAME
//! committed `t` columns — there is no separate `t_leaf == t_null` constraint to get wrong.
//! **`domain` is a baked circuit constant** (not a witness, not a public input), giving the
//! strongest cross-protocol nullifier separation.
//!
//! The leaf/nullifier **sponge** constraints run on every row (so the max constraint degree
//! stays at 5 — the x⁵ S-box — and the FRI blowup is not overflowed); only the cheap row-0
//! **bindings** (`running == L`, `ctx == public ctx`, `N == public N`) are gated with
//! [`AirBuilder::when_first_row`]. Rows 1.. therefore carry valid hashes of a zero preimage
//! as padding; their values are semantically irrelevant because no binding references them.
//! (Gating the sponge itself would raise its degree to 6 and overflow `quotient_degree`.)
//!
//! RED: Poseidon-256 round counts are NOT verified for GF(p²) (`super::wide_hash`); the whole
//! tier is gated behind the ADR-113 review and is NOT proven zero-knowledge / sound yet.

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

use super::wide_hash::{
    WIDE_DIGEST_ELEMS,
    WideDigest,
    poseidon256_wide_hash,
};
use super::wide_sponge::{
    constrain_wide_sponge,
    generate_wide_sponge_cells,
    wide_sponge_interm_cols,
};
use super::{
    bytes_to_poseidon_field,
    poseidon_to_field,
};

/// Secret-trapdoor length (field elements). 3 × ~62-bit ≈ 186-bit min-entropy ≥ 128-bit.
pub const SECRET_T_ELEMS: usize = 3;
/// Domain-separator length (baked circuit constant).
pub const DOMAIN_ELEMS: usize = 2;
/// Public-context length (`ctx`).
pub const CTX_ELEMS: usize = 2;

/// A wide Merkle node absorbs `left ‖ right` = 10 elements.
const NODE_INPUT_LEN: usize = 2 * WIDE_DIGEST_ELEMS; // 10
/// Nullifier preimage `domain ‖ t ‖ ctx`.
const NULL_INPUT_LEN: usize = DOMAIN_ELEMS + SECRET_T_ELEMS + CTX_ELEMS; // 7

// --- Column layout (one row = one Merkle level; leaf/nullifier live in row 0). ---
const M_RUNNING_START: usize = 0;
const M_SIBLING_START: usize = M_RUNNING_START + WIDE_DIGEST_ELEMS; // 5
const M_DIR_COL: usize = M_SIBLING_START + WIDE_DIGEST_ELEMS; // 10
const M_INTERM_START: usize = M_DIR_COL + 1; // 11
const LEAF_REGION_START: usize = M_INTERM_START + wide_sponge_interm_cols(NODE_INPUT_LEN); // 8579

const T_START: usize = LEAF_REGION_START; // 8579
const LEAF_INTERM_START: usize = T_START + SECRET_T_ELEMS; // 8582
const NULL_REGION_START: usize = LEAF_INTERM_START + wide_sponge_interm_cols(SECRET_T_ELEMS); // 11438

const CTX_START: usize = NULL_REGION_START; // 11438
const NULL_INTERM_START: usize = CTX_START + CTX_ELEMS; // 11440
/// Total trace width: `11440 + 4·1428 = 17152`.
pub const MEMBERSHIP_ROW_WIDTH: usize = NULL_INTERM_START + wide_sponge_interm_cols(NULL_INPUT_LEN);

// --- Public-value layout: [ root(5) ‖ ctx(2) ‖ N(5) ]. ---
const PUB_ROOT_START: usize = 0;
const PUB_CTX_START: usize = PUB_ROOT_START + WIDE_DIGEST_ELEMS; // 5
const PUB_NULL_START: usize = PUB_CTX_START + CTX_ELEMS; // 7
/// Number of public values.
pub const MEMBERSHIP_NUM_PUBLIC: usize = PUB_NULL_START + WIDE_DIGEST_ELEMS; // 12

/// Domain-separator string for the membership nullifier (statement domain).
pub const MEMBERSHIP_DOMAIN_STR: &str = "libq.zkfri.membership.v0";

/// The baked domain-separator field constants `domain` = first [`DOMAIN_ELEMS`] elements of
/// `H(MEMBERSHIP_DOMAIN_STR)`. Deterministic, fixed, nonzero, and statement-bound.
pub fn membership_domain() -> [PoseidonField; DOMAIN_ELEMS] {
    let felts = bytes_to_poseidon_field(MEMBERSHIP_DOMAIN_STR.as_bytes());
    let h = poseidon256_wide_hash(&felts);
    core::array::from_fn(|i| h[i])
}

/// The nullifier `N = H(domain ‖ t ‖ ctx)` (value-level reference).
pub fn membership_nullifier(
    t: &[PoseidonField; SECRET_T_ELEMS],
    ctx: &[PoseidonField; CTX_ELEMS],
) -> WideDigest {
    let mut input = Vec::with_capacity(NULL_INPUT_LEN);
    input.extend_from_slice(&membership_domain());
    input.extend_from_slice(t);
    input.extend_from_slice(ctx);
    poseidon256_wide_hash(&input)
}

/// The leaf `L = H(t)` (value-level reference; this is the digest the membership tree stores).
pub fn membership_leaf(t: &[PoseidonField; SECRET_T_ELEMS]) -> WideDigest {
    poseidon256_wide_hash(t)
}

/// AIR for the unlinkable membership statement. Depth-agnostic (path depth = trace height).
#[derive(Debug, Clone, Default)]
pub struct UnlinkableMembershipAir;

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for UnlinkableMembershipAir {
    fn width(&self) -> usize {
        MEMBERSHIP_ROW_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for UnlinkableMembershipAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);

        // --- Read current-row columns and public values up front (drop borrows). ---
        let (m_running, m_sibling, m_dir_var, m_dir, t_cols, ctx_cols) = {
            let main = builder.main();
            let local = main.current_slice();
            let m_running: Vec<AB::Expr> = (0..WIDE_DIGEST_ELEMS)
                .map(|i| local[M_RUNNING_START + i].into())
                .collect();
            let m_sibling: Vec<AB::Expr> = (0..WIDE_DIGEST_ELEMS)
                .map(|i| local[M_SIBLING_START + i].into())
                .collect();
            let m_dir_var = local[M_DIR_COL];
            let m_dir: AB::Expr = local[M_DIR_COL].into();
            let t_cols: Vec<AB::Expr> = (0..SECRET_T_ELEMS)
                .map(|i| local[T_START + i].into())
                .collect();
            let ctx_cols: Vec<AB::Expr> = (0..CTX_ELEMS)
                .map(|i| local[CTX_START + i].into())
                .collect();
            (m_running, m_sibling, m_dir_var, m_dir, t_cols, ctx_cols)
        };
        let (pub_root, pub_ctx, pub_null) = {
            let pubs = builder.public_values();
            let pub_root: Vec<AB::Expr> = (0..WIDE_DIGEST_ELEMS)
                .map(|i| pubs[PUB_ROOT_START + i].into())
                .collect();
            let pub_ctx: Vec<AB::Expr> = (0..CTX_ELEMS)
                .map(|i| pubs[PUB_CTX_START + i].into())
                .collect();
            let pub_null: Vec<AB::Expr> = (0..WIDE_DIGEST_ELEMS)
                .map(|i| pubs[PUB_NULL_START + i].into())
                .collect();
            (pub_root, pub_ctx, pub_null)
        };

        // === Merkle level (every row) ===
        builder.assert_bool(m_dir_var);

        // node input = left ‖ right, direction-selected.
        let mut node_input: Vec<AB::Expr> = Vec::with_capacity(NODE_INPUT_LEN);
        for i in 0..WIDE_DIGEST_ELEMS {
            node_input.push(
                m_running[i].clone() +
                    m_dir.clone() * (m_sibling[i].clone() - m_running[i].clone()),
            );
        }
        for i in 0..WIDE_DIGEST_ELEMS {
            node_input.push(
                m_sibling[i].clone() +
                    m_dir.clone() * (m_running[i].clone() - m_sibling[i].clone()),
            );
        }
        let parent = match constrain_wide_sponge(builder, &node_input, M_INTERM_START) {
            Ok(p) => p,
            Err(_) => {
                builder.assert_zero(one.clone());
                return;
            }
        };

        // Thread the running digest: next.running == this level's parent.
        {
            let next_running: Vec<AB::Expr> = {
                let main = builder.main();
                let next = main.next_slice();
                (0..WIDE_DIGEST_ELEMS)
                    .map(|i| next[M_RUNNING_START + i].into())
                    .collect()
            };
            let mut b = builder.when_transition();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(next_running[i].clone(), parent[i].clone());
            }
        }
        // Last row: the final parent is the public root.
        {
            let mut b = builder.when_last_row();
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(parent[i].clone(), pub_root[i].clone());
            }
        }

        // === Leaf hash L = H(t) (ungated; bound only on row 0) ===
        // The sponge constraints run on EVERY row to keep the max constraint degree at 5
        // (the x⁵ S-box). Gating them with `is_first_row` would raise the degree to 6 and
        // overflow the FRI blowup (quotient_degree 8 > blowup 4). Rows 1.. therefore carry
        // valid hashes of a zero preimage (see `generate_membership_trace`); only the row-0
        // BINDINGS below give `t`/`ctx`/`N` their meaning.
        let leaf_out = match constrain_wide_sponge(builder, &t_cols, LEAF_INTERM_START) {
            Ok(d) => d,
            Err(_) => {
                builder.assert_zero(one.clone());
                return;
            }
        };

        // === Nullifier hash N = H(domain ‖ t ‖ ctx) (ungated; bound only on row 0) ===
        let mut null_input: Vec<AB::Expr> = Vec::with_capacity(NULL_INPUT_LEN);
        for d in membership_domain() {
            null_input.push(AB::Expr::from(poseidon_to_field::<AB::F>(&d)));
        }
        null_input.extend(t_cols.iter().cloned());
        null_input.extend(ctx_cols.iter().cloned());
        let null_out = match constrain_wide_sponge(builder, &null_input, NULL_INTERM_START) {
            Ok(d) => d,
            Err(_) => {
                builder.assert_zero(one.clone());
                return;
            }
        };

        // === Row-0 bindings ===
        {
            let mut b = builder.when_first_row();
            // Merkle path starts at the leaf of the secret t (L stays private).
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(m_running[i].clone(), leaf_out[i].clone());
            }
            // ctx is revealed.
            for i in 0..CTX_ELEMS {
                b.assert_eq(ctx_cols[i].clone(), pub_ctx[i].clone());
            }
            // Nullifier is revealed.
            for i in 0..WIDE_DIGEST_ELEMS {
                b.assert_eq(null_out[i].clone(), pub_null[i].clone());
            }
        }
    }
}

/// Generate the `depth`-row membership trace.
///
/// `t` is the secret trapdoor, `ctx` the public context, and `(path_bits, siblings)` the
/// authentication path of the leaf `L = H(t)` in a [`crate::merkle::WidePoseidonMerkleTree`].
/// Row 0 carries the leaf and nullifier blocks; rows 1.. carry only their Merkle level (the
/// leaf/nullifier regions are zero there — their constraints are gated to row 0).
pub fn generate_membership_trace<F: Field + BasedVectorSpace<Mersenne31>>(
    t: &[PoseidonField; SECRET_T_ELEMS],
    ctx: &[PoseidonField; CTX_ELEMS],
    path_bits: &[bool],
    siblings: &[WideDigest],
) -> RowMajorMatrix<F> {
    debug_assert_eq!(path_bits.len(), siblings.len());
    let zero = PoseidonField::ZERO;
    let one = PoseidonField::ONE;
    let depth = path_bits.len();

    // Padding leaf/nullifier blocks for rows 1.. : the sponge constraints are ungated, so
    // these rows must still hold a VALID hash — of a zero preimage (their bindings are gated
    // off, so the values are otherwise irrelevant).
    let zero_t = [zero; SECRET_T_ELEMS];
    let zero_ctx = [zero; CTX_ELEMS];
    let (pad_leaf_cells, _) = generate_wide_sponge_cells(&zero_t);
    let pad_null_cells = {
        let mut input = Vec::with_capacity(NULL_INPUT_LEN);
        input.extend_from_slice(&membership_domain());
        input.extend_from_slice(&zero_t);
        input.extend_from_slice(&zero_ctx);
        generate_wide_sponge_cells(&input).0
    };

    let mut cells: Vec<PoseidonField> = Vec::with_capacity(depth * MEMBERSHIP_ROW_WIDTH);
    let mut running = membership_leaf(t); // L = H(t)

    for level in 0..depth {
        let dir = path_bits[level];
        let sib = siblings[level];
        let (left, right) = if dir { (sib, running) } else { (running, sib) };

        let mut node_input = [zero; NODE_INPUT_LEN];
        node_input[..WIDE_DIGEST_ELEMS].copy_from_slice(&left);
        node_input[WIDE_DIGEST_ELEMS..].copy_from_slice(&right);

        // Merkle control + node sponge.
        cells.extend_from_slice(&running);
        cells.extend_from_slice(&sib);
        cells.push(if dir { one } else { zero });
        let (node_cells, parent) = generate_wide_sponge_cells(&node_input);
        cells.extend_from_slice(&node_cells);

        // Leaf + nullifier blocks: real in row 0, zero-padded elsewhere.
        if level == 0 {
            // Leaf: t ‖ H(t) intermediates.
            cells.extend_from_slice(t);
            let (leaf_cells, _l) = generate_wide_sponge_cells(t);
            cells.extend_from_slice(&leaf_cells);
            // Nullifier: ctx ‖ H(domain ‖ t ‖ ctx) intermediates.
            cells.extend_from_slice(ctx);
            let mut null_input = Vec::with_capacity(NULL_INPUT_LEN);
            null_input.extend_from_slice(&membership_domain());
            null_input.extend_from_slice(t);
            null_input.extend_from_slice(ctx);
            let (null_cells, _n) = generate_wide_sponge_cells(&null_input);
            cells.extend_from_slice(&null_cells);
        } else {
            // Padding row: valid zero-preimage hashes (bindings are gated to row 0).
            cells.extend_from_slice(&zero_t);
            cells.extend_from_slice(&pad_leaf_cells);
            cells.extend_from_slice(&zero_ctx);
            cells.extend_from_slice(&pad_null_cells);
        }
        running = parent;
    }

    debug_assert_eq!(cells.len(), depth * MEMBERSHIP_ROW_WIDTH);
    let values: Vec<F> = cells.iter().map(poseidon_to_field).collect();
    RowMajorMatrix::new(values, MEMBERSHIP_ROW_WIDTH)
}

/// Public values `[ root(5) ‖ ctx(2) ‖ N(5) ]` for the membership AIR.
pub fn membership_public_values<F: Field + BasedVectorSpace<Mersenne31>>(
    root: &WideDigest,
    ctx: &[PoseidonField; CTX_ELEMS],
    nullifier: &WideDigest,
) -> Vec<F> {
    let mut out: Vec<F> = Vec::with_capacity(MEMBERSHIP_NUM_PUBLIC);
    out.extend(root.iter().map(poseidon_to_field::<F>));
    out.extend(ctx.iter().map(poseidon_to_field::<F>));
    out.extend(nullifier.iter().map(poseidon_to_field::<F>));
    out
}

#[cfg(test)]
mod tests {
    use lib_q_stark::check_constraints;
    use lib_q_stark_field::extension::Complex;

    use super::*;
    use crate::merkle::WidePoseidonMerkleTree;

    type TestField = Complex<Mersenne31>;

    fn fe(x: u32) -> PoseidonField {
        Complex::<Mersenne31>::from(Mersenne31::new(x))
    }

    fn secret(seed: u32) -> [PoseidonField; SECRET_T_ELEMS] {
        core::array::from_fn(|i| fe(seed * 7 + i as u32 + 1))
    }

    fn ctx_of(seed: u32) -> [PoseidonField; CTX_ELEMS] {
        core::array::from_fn(|i| fe(seed * 13 + i as u32 + 100))
    }

    /// Build a 16-leaf (depth-4) membership tree from secrets `0..16`; return the tree and the
    /// secrets so a member can be selected.
    fn build_tree() -> (WidePoseidonMerkleTree, Vec<[PoseidonField; SECRET_T_ELEMS]>) {
        let secrets: Vec<_> = (0..16u32).map(secret).collect();
        let leaves: Vec<WideDigest> = secrets.iter().map(membership_leaf).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        (tree, secrets)
    }

    fn cell(trace: &RowMajorMatrix<TestField>, row: usize, col: usize) -> TestField {
        trace.values[row * MEMBERSHIP_ROW_WIDTH + col]
    }
    fn set_cell(trace: &mut RowMajorMatrix<TestField>, row: usize, col: usize, v: TestField) {
        trace.values[row * MEMBERSHIP_ROW_WIDTH + col] = v;
    }

    #[test]
    fn layout_constants_are_consistent() {
        assert_eq!(LEAF_REGION_START, 8579);
        assert_eq!(NULL_REGION_START, 11438);
        assert_eq!(MEMBERSHIP_ROW_WIDTH, 17152);
        assert_eq!(MEMBERSHIP_NUM_PUBLIC, 12);
        // domain is fixed and nonzero.
        assert!(
            membership_domain()
                .iter()
                .any(|d| *d != PoseidonField::ZERO)
        );
    }

    #[test]
    fn membership_round_trip_check_constraints() {
        let (tree, secrets) = build_tree();
        assert_eq!(tree.depth(), 4);
        for index in [0usize, 5, 11, 15] {
            let t = secrets[index];
            let ctx = ctx_of(index as u32);
            let (path_bits, siblings) = tree.path(index).expect("path");
            let trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
            let n = membership_nullifier(&t, &ctx);
            let pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);
            check_constraints(&UnlinkableMembershipAir, &trace, &pubs);
        }
    }

    #[test]
    fn nullifier_is_context_separated_and_deterministic() {
        let t = secret(3);
        let n1 = membership_nullifier(&t, &ctx_of(1));
        let n1b = membership_nullifier(&t, &ctx_of(1));
        let n2 = membership_nullifier(&t, &ctx_of(2));
        assert_eq!(n1, n1b, "same (t, ctx) ⇒ same nullifier");
        assert_ne!(n1, n2, "different ctx ⇒ unlinkable nullifier");
        // Different secret ⇒ different nullifier under the same ctx.
        assert_ne!(n1, membership_nullifier(&secret(4), &ctx_of(1)));
    }

    #[test]
    #[should_panic(expected = "")]
    fn rejects_wrong_root() {
        let (tree, secrets) = build_tree();
        let (t, ctx) = (secrets[2], ctx_of(2));
        let (path_bits, siblings) = tree.path(2).expect("path");
        let trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let mut pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);
        pubs[PUB_ROOT_START] += TestField::ONE;
        check_constraints(&UnlinkableMembershipAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn rejects_wrong_nullifier() {
        let (tree, secrets) = build_tree();
        let (t, ctx) = (secrets[7], ctx_of(7));
        let (path_bits, siblings) = tree.path(7).expect("path");
        let trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let mut pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);
        pubs[PUB_NULL_START + 1] += TestField::ONE;
        check_constraints(&UnlinkableMembershipAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn rejects_ctx_mismatch_public_vs_witness() {
        // Public ctx differs from the witnessed ctx (the one the nullifier was built from):
        // the row-0 `ctx == public ctx` binding must fail.
        let (tree, secrets) = build_tree();
        let (t, ctx) = (secrets[4], ctx_of(4));
        let (path_bits, siblings) = tree.path(4).expect("path");
        let trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let mut pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);
        pubs[PUB_CTX_START] += TestField::ONE; // public ctx no longer matches witness
        check_constraints(&UnlinkableMembershipAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn rejects_non_member_secret() {
        // A secret whose leaf is NOT in the tree, presented with a real member's path: the
        // recomputed root cannot match (would need a hash collision).
        let (tree, _secrets) = build_tree();
        let (path_bits, siblings) = tree.path(1).expect("path");
        let t = secret(9999);
        let ctx = ctx_of(1);
        let trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);
        check_constraints(&UnlinkableMembershipAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn rejects_tampered_secret_breaks_leaf_binding() {
        // Change the witnessed t in row 0 without recomputing: L = H(t) no longer equals the
        // committed running digest (which still recomputes the original root).
        let (tree, secrets) = build_tree();
        let (t, ctx) = (secrets[6], ctx_of(6));
        let (path_bits, siblings) = tree.path(6).expect("path");
        let mut trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);
        let v = cell(&trace, 0, T_START);
        set_cell(&mut trace, 0, T_START, v + TestField::ONE);
        check_constraints(&UnlinkableMembershipAir, &trace, &pubs);
    }

    #[test]
    #[should_panic(expected = "")]
    fn rejects_tampered_running_carry() {
        let (tree, secrets) = build_tree();
        let (t, ctx) = (secrets[10], ctx_of(10));
        let (path_bits, siblings) = tree.path(10).expect("path");
        let mut trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);
        let v = cell(&trace, 1, M_RUNNING_START);
        set_cell(&mut trace, 1, M_RUNNING_START, v + TestField::ONE);
        check_constraints(&UnlinkableMembershipAir, &trace, &pubs);
    }

    /// De-risk O4 (zero-knowledge): the membership AIR must prove/verify under the HIDING
    /// (zk) PCS — `is_zk()` doubles the trace domain and blinds openings, so this confirms the
    /// AIR is mechanically ZK-compatible before a production ZK config is wired.
    #[test]
    fn membership_zk_config_round_trip() {
        use crate::stark::{
            StarkProver,
            StarkVerifier,
            zk_config_with_params,
        };

        // The Poseidon x⁵ S-box (constraint degree 5) needs the hiding LDE at log_blowup >= 3
        // under ZK (the trace is randomized to ~2·height degree). Height 4 is also below the ZK
        // FRI minimum, so use depth 8 (256 leaves) → height 8.
        let secrets: Vec<[PoseidonField; SECRET_T_ELEMS]> = (0..256u32).map(secret).collect();
        let leaves: Vec<WideDigest> = secrets.iter().map(membership_leaf).collect();
        let tree = WidePoseidonMerkleTree::from_leaf_digests(&leaves).expect("tree");
        assert_eq!(tree.depth(), 8);
        let index = 100;
        let (t, ctx) = (secrets[index], ctx_of(index as u32));
        let (path_bits, siblings) = tree.path(index).expect("path");
        let trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);

        // log_blowup=3, fast test query params. The prover seeds the blinding RNG with its
        // (secret) entropy (7, 8); the VERIFIER must succeed with DIFFERENT seeds (0, 1) —
        // verification must not depend on the prover's hiding randomness (that is the ZK
        // secret), only on the FRI parameters.
        let proof = StarkProver::new(zk_config_with_params(3, 2, 1, 7, 8))
            .prove(&UnlinkableMembershipAir, trace, &pubs)
            .expect("zk prove");
        StarkVerifier::new(zk_config_with_params(3, 2, 1, 0, 1))
            .verify(&UnlinkableMembershipAir, &proof, &pubs)
            .expect("zk verify must not need the prover's blinding seeds");

        // Wrong nullifier must still be rejected under the hiding PCS.
        let mut bad = pubs.clone();
        bad[PUB_NULL_START] += TestField::ONE;
        assert!(
            StarkVerifier::new(zk_config_with_params(3, 2, 1, 0, 1))
                .verify(&UnlinkableMembershipAir, &proof, &bad)
                .is_err(),
            "zk verifier must reject a tampered nullifier"
        );
    }

    /// Full STARK prove → verify round-trip at depth 4 (power-of-two height), plus a negative
    /// (wrong nullifier) against the REAL prover/verifier.
    #[test]
    fn membership_real_prover_round_trip_and_negative() {
        use crate::stark::{
            StarkProver,
            StarkVerifier,
            fast_proof_config,
        };

        let (tree, secrets) = build_tree();
        let index = 11;
        let (t, ctx) = (secrets[index], ctx_of(index as u32));
        let (path_bits, siblings) = tree.path(index).expect("path");
        let trace = generate_membership_trace::<TestField>(&t, &ctx, &path_bits, &siblings);
        let n = membership_nullifier(&t, &ctx);
        let pubs = membership_public_values::<TestField>(&tree.root(), &ctx, &n);

        let cfg = fast_proof_config();
        let proof = StarkProver::new(cfg.clone())
            .prove(&UnlinkableMembershipAir, trace, &pubs)
            .expect("prove");
        StarkVerifier::new(cfg.clone())
            .verify(&UnlinkableMembershipAir, &proof, &pubs)
            .expect("verify");

        // Tampered public nullifier must be rejected by the real verifier.
        let mut bad = pubs.clone();
        bad[PUB_NULL_START] += TestField::ONE;
        assert!(
            StarkVerifier::new(cfg)
                .verify(&UnlinkableMembershipAir, &proof, &bad)
                .is_err(),
            "verifier must reject a tampered nullifier"
        );
    }
}
