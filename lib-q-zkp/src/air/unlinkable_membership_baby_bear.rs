//! Unlinkable membership AIR over Poseidon2-BabyBear (Arm B, build-spec step 5) — the BabyBear
//! analogue of `unlinkable_membership.rs`.
//!
//! Proves the unlinkable-membership statement (Semaphore/Tornado nullifier shape):
//! ```text
//!   ∃ (L, t, path):  L = H(t)  ∧  MerklePath(L → root)  ∧  N = H(domain ‖ t ‖ ctx)
//!   reveal only (root, ctx, N);  L and t stay private.
//! ```
//! A fresh `ctx` ⇒ an unlinkable nullifier `N`; reuse under the same `ctx` collides on `N`.
//! Same-`t` binding is structural: the leaf block and the nullifier block read the SAME `t`
//! columns. `domain` is a baked circuit constant (statement-bound, not a witness/public input).
//!
//! Row layout (one row = one Merkle level; leaf/nullifier live in row 0; width 1661):
//! `[ running(9)|sibling(9)|dir(1)|node_input(18)|m_interm(807) ]  [ t(6)|leaf_interm(269) ]  [ ctx(4)|null_interm(538) ]`.
//! `node_input` stores the direction-selected Merkle `left‖right` as `Var`s so the AIR's max
//! constraint degree is 7 (the x⁷ S-box) rather than 14 — see `M_NODE_INPUT_START`.
//! The leaf/nullifier **sponges run on EVERY row** (so max constraint degree stays at 7, the x⁷
//! S-box; gating them would raise it). Rows 1.. carry valid hashes of a ZERO preimage — only the
//! row-0 bindings (`running==L`, `ctx==pub ctx`, `N==pub N`) give `t`/`ctx`/`N` meaning.
//!
//! Public statement: `[ root(9 cells = 36 B) ‖ ctx(4 cells = 16 B) ‖ N(9 cells = 36 B) ]`. The
//! 1-byte instantiation tag (Arm A `0x01`, this arm `0x02`) lives in the consuming envelope.
//!
//! DOMAIN DERIVATION NOTE: the build spec suggested `domain = first cells of K12(separator)`.
//! Here `domain` is derived the way Arm A derives it — the first `DOMAIN_ELEMS` cells of the
//! arm's OWN wide hash of the separator string — to keep the two arms structurally parallel and
//! avoid a K12 dependency. It is a baked off-circuit constant either way; switching to a
//! K12-derived constant (cross-family separation) is a trivial off-circuit change. The separator
//! STRING is unchanged (`libq.zkfri.membership.v0`). Tier RED.

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

use crate::air::wide_merkle_path_baby_bear::{
    NODE_INPUT_LEN,
    WideDigestBb,
};
use crate::air::wide_sponge_baby_bear::{
    WIDE_DIGEST_ELEMS,
    constrain_wide_sponge_bb,
    generate_wide_sponge_bb_cells,
    poseidon2_wide_hash_bb,
    wide_sponge_bb_interm_cols,
};

/// Secret trapdoor length. 6 BabyBear cells ≈ 185-bit secret (≥128); Arm A used 3 cells over
/// GF(p²) ≈ 186 bits, but 3 base-field cells would be only ~93 bits — hence the widening.
pub const SECRET_T_ELEMS: usize = 6;
/// Baked domain-separator length (cells).
pub const DOMAIN_ELEMS: usize = 2;
/// Public-context length (`ctx`), 4 cells = 16 B.
pub const CTX_ELEMS: usize = 4;
/// Nullifier preimage `domain ‖ t ‖ ctx`.
const NULL_INPUT_LEN: usize = DOMAIN_ELEMS + SECRET_T_ELEMS + CTX_ELEMS; // 12

// --- Column layout (one row = one Merkle level; leaf/nullifier live in row 0). ---
const M_RUNNING_START: usize = 0;
const M_SIBLING_START: usize = WIDE_DIGEST_ELEMS; // 9
const M_DIR_COL: usize = 2 * WIDE_DIGEST_ELEMS; // 18
/// Direction-selected Merkle node input `left‖right`, **stored as `Var`s** (degree-7
/// optimization): feeds the node sponge degree-1 `Var`s so the membership AIR's max constraint
/// degree is 7 (the x⁷ S-box on leaf/nullifier/node) rather than 14 (deg-2 dir-select × x⁷).
const M_NODE_INPUT_START: usize = M_DIR_COL + 1; // 19
const M_INTERM_START: usize = M_NODE_INPUT_START + NODE_INPUT_LEN; // 37
const LEAF_REGION_START: usize = M_INTERM_START + wide_sponge_bb_interm_cols(NODE_INPUT_LEN); // 844
const T_START: usize = LEAF_REGION_START; // 844
const LEAF_INTERM_START: usize = T_START + SECRET_T_ELEMS; // 850
const NULL_REGION_START: usize = LEAF_INTERM_START + wide_sponge_bb_interm_cols(SECRET_T_ELEMS); // 1119
const CTX_START: usize = NULL_REGION_START; // 1119
const NULL_INTERM_START: usize = CTX_START + CTX_ELEMS; // 1123
/// Total columns per membership row (= 1661).
pub const MEMBERSHIP_ROW_WIDTH: usize =
    NULL_INTERM_START + wide_sponge_bb_interm_cols(NULL_INPUT_LEN);

// --- Public-value layout: [ root(9) ‖ ctx(4) ‖ N(9) ]. ---
const PUB_ROOT_START: usize = 0;
const PUB_CTX_START: usize = PUB_ROOT_START + WIDE_DIGEST_ELEMS; // 9
const PUB_NULL_START: usize = PUB_CTX_START + CTX_ELEMS; // 13
/// Number of public values (= 22).
pub const MEMBERSHIP_NUM_PUBLIC: usize = PUB_NULL_START + WIDE_DIGEST_ELEMS;

/// Domain-separator string for the membership nullifier (statement domain). UNCHANGED.
pub const MEMBERSHIP_DOMAIN_STR: &str = "libq.zkfri.membership.v0";

/// The baked domain constants: first `DOMAIN_ELEMS` cells of the wide hash of the separator
/// (bytes → one BabyBear cell each, mirroring Arm A's `bytes_to_poseidon_field`).
pub fn membership_domain_bb() -> [BabyBear; DOMAIN_ELEMS] {
    let felts: Vec<BabyBear> =
        MEMBERSHIP_DOMAIN_STR.as_bytes().iter().map(|b| BabyBear::new(*b as u32)).collect();
    let h = poseidon2_wide_hash_bb(&felts);
    core::array::from_fn(|i| h[i])
}

/// The nullifier `N = H(domain ‖ t ‖ ctx)` (value-level reference).
pub fn membership_nullifier_bb(
    t: &[BabyBear; SECRET_T_ELEMS],
    ctx: &[BabyBear; CTX_ELEMS],
) -> WideDigestBb {
    let mut input = Vec::with_capacity(NULL_INPUT_LEN);
    input.extend_from_slice(&membership_domain_bb());
    input.extend_from_slice(t);
    input.extend_from_slice(ctx);
    poseidon2_wide_hash_bb(&input)
}

/// The leaf `L = H(t)` (value-level reference; the digest the membership tree stores).
pub fn membership_leaf_bb(t: &[BabyBear; SECRET_T_ELEMS]) -> WideDigestBb {
    poseidon2_wide_hash_bb(t)
}

/// AIR for the unlinkable membership statement. Depth-agnostic (path depth = trace height).
#[derive(Debug, Clone, Copy, Default)]
pub struct UnlinkableMembershipBbAir;

impl<F: Field> BaseAir<F> for UnlinkableMembershipBbAir {
    fn width(&self) -> usize {
        MEMBERSHIP_ROW_WIDTH
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for UnlinkableMembershipBbAir {
    fn eval(&self, builder: &mut AB) {
        // Read current-row columns and public values up front (drop borrows before gadget calls).
        let (m_running, m_sibling, m_dir_var, m_dir, t_cols, ctx_cols) = {
            let main = builder.main();
            let local = main.current_slice();
            let m_running: Vec<AB::Expr> =
                (0..WIDE_DIGEST_ELEMS).map(|i| local[M_RUNNING_START + i].into()).collect();
            let m_sibling: Vec<AB::Expr> =
                (0..WIDE_DIGEST_ELEMS).map(|i| local[M_SIBLING_START + i].into()).collect();
            let m_dir_var = local[M_DIR_COL];
            let m_dir: AB::Expr = local[M_DIR_COL].into();
            let t_cols: Vec<AB::Expr> =
                (0..SECRET_T_ELEMS).map(|i| local[T_START + i].into()).collect();
            let ctx_cols: Vec<AB::Expr> =
                (0..CTX_ELEMS).map(|i| local[CTX_START + i].into()).collect();
            (m_running, m_sibling, m_dir_var, m_dir, t_cols, ctx_cols)
        };
        let (pub_root, pub_ctx, pub_null) = {
            let pubs = builder.public_values();
            let pub_root: Vec<AB::Expr> =
                (0..WIDE_DIGEST_ELEMS).map(|i| pubs[PUB_ROOT_START + i].into()).collect();
            let pub_ctx: Vec<AB::Expr> =
                (0..CTX_ELEMS).map(|i| pubs[PUB_CTX_START + i].into()).collect();
            let pub_null: Vec<AB::Expr> =
                (0..WIDE_DIGEST_ELEMS).map(|i| pubs[PUB_NULL_START + i].into()).collect();
            (pub_root, pub_ctx, pub_null)
        };

        // === Merkle level (every row) ===
        builder.assert_bool(m_dir_var);

        // Stored direction-selected node input (degree-7 optimization): read the columns as
        // `Var`s, pin them to the direction selection (degree-2), and feed the `Var`s to the
        // sponge so its first S-box sees a degree-1 input ⇒ membership AIR max degree 7.
        let node_input: Vec<AB::Expr> = {
            let main = builder.main();
            let local = main.current_slice();
            (0..NODE_INPUT_LEN).map(|i| local[M_NODE_INPUT_START + i].into()).collect()
        };
        for i in 0..WIDE_DIGEST_ELEMS {
            builder.assert_eq(
                node_input[i].clone(),
                m_running[i].clone() + m_dir.clone() * (m_sibling[i].clone() - m_running[i].clone()),
            );
            builder.assert_eq(
                node_input[WIDE_DIGEST_ELEMS + i].clone(),
                m_sibling[i].clone() + m_dir.clone() * (m_running[i].clone() - m_sibling[i].clone()),
            );
        }
        let parent = constrain_wide_sponge_bb(builder, &node_input, M_INTERM_START);

        // Thread the running digest: next.running == this level's parent.
        {
            let next_running: Vec<AB::Expr> = {
                let main = builder.main();
                let next = main.next_slice();
                (0..WIDE_DIGEST_ELEMS).map(|i| next[M_RUNNING_START + i].into()).collect()
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
        let leaf_out = constrain_wide_sponge_bb(builder, &t_cols, LEAF_INTERM_START);

        // === Nullifier N = H(domain ‖ t ‖ ctx) (ungated; bound only on row 0) ===
        let mut null_input: Vec<AB::Expr> = Vec::with_capacity(NULL_INPUT_LEN);
        for d in membership_domain_bb() {
            null_input.push(AB::Expr::from(d));
        }
        null_input.extend(t_cols.iter().cloned());
        null_input.extend(ctx_cols.iter().cloned());
        let null_out = constrain_wide_sponge_bb(builder, &null_input, NULL_INTERM_START);

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

/// Generate the `depth`-row membership trace. Row 0 carries the leaf and nullifier blocks; rows
/// 1.. carry only their Merkle level (leaf/nullifier regions hash a zero preimage there).
pub fn generate_membership_trace_bb(
    t: &[BabyBear; SECRET_T_ELEMS],
    ctx: &[BabyBear; CTX_ELEMS],
    path_bits: &[bool],
    siblings: &[WideDigestBb],
) -> RowMajorMatrix<BabyBear> {
    debug_assert_eq!(path_bits.len(), siblings.len());
    let zero = BabyBear::ZERO;
    let depth = path_bits.len();

    // Padding leaf/nullifier blocks for rows 1.. : valid zero-preimage hashes (bindings gated off).
    let zero_t = [zero; SECRET_T_ELEMS];
    let zero_ctx = [zero; CTX_ELEMS];
    let (pad_leaf_cells, _) = generate_wide_sponge_bb_cells(&zero_t);
    let pad_null_cells = {
        let mut input = Vec::with_capacity(NULL_INPUT_LEN);
        input.extend_from_slice(&membership_domain_bb());
        input.extend_from_slice(&zero_t);
        input.extend_from_slice(&zero_ctx);
        generate_wide_sponge_bb_cells(&input).0
    };

    let mut cells: Vec<BabyBear> = Vec::with_capacity(depth * MEMBERSHIP_ROW_WIDTH);
    let mut running = membership_leaf_bb(t); // L = H(t)

    for level in 0..depth {
        let dir = path_bits[level];
        let sib = siblings[level];
        let (left, right) = if dir { (sib, running) } else { (running, sib) };

        let mut node_input = [zero; NODE_INPUT_LEN];
        node_input[..WIDE_DIGEST_ELEMS].copy_from_slice(&left);
        node_input[WIDE_DIGEST_ELEMS..].copy_from_slice(&right);

        cells.extend_from_slice(&running);
        cells.extend_from_slice(&sib);
        cells.push(if dir { BabyBear::ONE } else { zero });
        cells.extend_from_slice(&node_input); // stored direction-selected node input (degree-7 opt)
        let (node_cells, parent) = generate_wide_sponge_bb_cells(&node_input);
        cells.extend_from_slice(&node_cells);

        if level == 0 {
            cells.extend_from_slice(t);
            let (leaf_cells, _l) = generate_wide_sponge_bb_cells(t);
            cells.extend_from_slice(&leaf_cells);
            cells.extend_from_slice(ctx);
            let mut null_input = Vec::with_capacity(NULL_INPUT_LEN);
            null_input.extend_from_slice(&membership_domain_bb());
            null_input.extend_from_slice(t);
            null_input.extend_from_slice(ctx);
            let (null_cells, _n) = generate_wide_sponge_bb_cells(&null_input);
            cells.extend_from_slice(&null_cells);
        } else {
            cells.extend_from_slice(&zero_t);
            cells.extend_from_slice(&pad_leaf_cells);
            cells.extend_from_slice(&zero_ctx);
            cells.extend_from_slice(&pad_null_cells);
        }
        running = parent;
    }

    debug_assert_eq!(cells.len(), depth * MEMBERSHIP_ROW_WIDTH);
    RowMajorMatrix::new(cells, MEMBERSHIP_ROW_WIDTH)
}

/// Public values `[ root(9) ‖ ctx(4) ‖ N(9) ]` for the membership AIR.
pub fn membership_public_values_bb(
    root: &WideDigestBb,
    ctx: &[BabyBear; CTX_ELEMS],
    nullifier: &WideDigestBb,
) -> Vec<BabyBear> {
    let mut out: Vec<BabyBear> = Vec::with_capacity(MEMBERSHIP_NUM_PUBLIC);
    out.extend_from_slice(root);
    out.extend_from_slice(ctx);
    out.extend_from_slice(nullifier);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::wide_merkle_path_baby_bear::compress_bb;
    use crate::check_constraints;

    const P: u32 = 2_013_265_921;

    fn digest_from_seed(seed: u32) -> WideDigestBb {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(7);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }

    fn t_from_seed(seed: u32) -> [BabyBear; SECRET_T_ELEMS] {
        let mut x = seed.wrapping_mul(40_503).wrapping_add(11);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }

    fn ctx_from_seed(seed: u32) -> [BabyBear; CTX_ELEMS] {
        let mut x = seed.wrapping_mul(2_246_822_519).wrapping_add(5);
        core::array::from_fn(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            BabyBear::new(x % P)
        })
    }

    /// Place `leaf` at `leaf_index` in a depth-`depth` tree; return `(path_bits, siblings, root)`.
    fn path_for(
        leaf: WideDigestBb,
        depth: usize,
        leaf_index: usize,
    ) -> (Vec<bool>, Vec<WideDigestBb>, WideDigestBb) {
        let n = 1usize << depth;
        let mut level: Vec<WideDigestBb> =
            (0..n as u32).map(|i| if i as usize == leaf_index { leaf } else { digest_from_seed(i + 100) }).collect();
        let mut idx = leaf_index;
        let mut bits = Vec::new();
        let mut sibs = Vec::new();
        while level.len() > 1 {
            sibs.push(level[idx ^ 1]);
            bits.push((idx & 1) == 1);
            let mut next = Vec::with_capacity(level.len() / 2);
            let mut j = 0;
            while j < level.len() {
                next.push(compress_bb(&level[j], &level[j + 1]));
                j += 2;
            }
            level = next;
            idx /= 2;
        }
        (bits, sibs, level[0])
    }

    #[test]
    fn row_width_and_publics() {
        assert_eq!(MEMBERSHIP_ROW_WIDTH, 1661);
        assert_eq!(MEMBERSHIP_NUM_PUBLIC, 22);
        // domain constant is deterministic and nonzero.
        let d = membership_domain_bb();
        assert!(d.iter().any(|x| *x != BabyBear::ZERO));
        assert_eq!(d, membership_domain_bb());
    }

    #[test]
    fn honest_roundtrip_all_depths() {
        for depth in [1usize, 2, 4, 8] {
            let t = t_from_seed(depth as u32);
            let ctx = ctx_from_seed(depth as u32 + 1);
            let leaf = membership_leaf_bb(&t);
            let (bits, sibs, root) = path_for(leaf, depth, (1 << depth) / 3);
            let trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
            let null = membership_nullifier_bb(&t, &ctx);
            let pubs = membership_public_values_bb(&root, &ctx, &null);
            check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
        }
    }

    /// Unlinkability ACROSS ctx: same `t`, different `ctx` ⇒ different nullifier.
    #[test]
    fn unlinkability_across_ctx() {
        let t = t_from_seed(42);
        let ctx1 = ctx_from_seed(1);
        let ctx2 = ctx_from_seed(2);
        let n1 = membership_nullifier_bb(&t, &ctx1);
        let n2 = membership_nullifier_bb(&t, &ctx2);
        assert_ne!(n1, n2, "nullifier must differ across ctx (unlinkable)");
    }

    /// Linkability WITHIN ctx: same `t`, same `ctx` ⇒ identical nullifier (double-use detectable).
    #[test]
    fn linkability_within_ctx() {
        let t = t_from_seed(42);
        let ctx = ctx_from_seed(7);
        assert_eq!(
            membership_nullifier_bb(&t, &ctx),
            membership_nullifier_bb(&t, &ctx),
            "nullifier must be deterministic within ctx (linkable)"
        );
        // Different t, same ctx ⇒ different nullifier.
        let t2 = t_from_seed(43);
        assert_ne!(membership_nullifier_bb(&t, &ctx), membership_nullifier_bb(&t2, &ctx));
    }

    /// Circuit-level: the SAME member proves under two ctx; both verify, with DIFFERENT public N.
    #[test]
    fn circuit_nullifier_binds_to_ctx() {
        let depth = 4;
        let t = t_from_seed(9);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, depth, 5);
        for ctx_seed in [10u32, 20] {
            let ctx = ctx_from_seed(ctx_seed);
            let trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
            let null = membership_nullifier_bb(&t, &ctx);
            let pubs = membership_public_values_bb(&root, &ctx, &null);
            check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
        }
    }

    // --- Corruption rejections ---
    fn setup() -> (
        [BabyBear; SECRET_T_ELEMS],
        [BabyBear; CTX_ELEMS],
        Vec<bool>,
        Vec<WideDigestBb>,
        WideDigestBb,
    ) {
        let t = t_from_seed(3);
        let ctx = ctx_from_seed(4);
        let leaf = membership_leaf_bb(&t);
        let (bits, sibs, root) = path_for(leaf, 4, 6);
        (t, ctx, bits, sibs, root)
    }

    #[test]
    #[should_panic]
    fn corrupt_public_nullifier_rejected() {
        let (t, ctx, bits, sibs, root) = setup();
        let trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
        let null = membership_nullifier_bb(&t, &ctx);
        let mut pubs = membership_public_values_bb(&root, &ctx, &null);
        pubs[PUB_NULL_START] = pubs[PUB_NULL_START] + BabyBear::ONE;
        check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn corrupt_public_ctx_rejected() {
        let (t, ctx, bits, sibs, root) = setup();
        let trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
        let null = membership_nullifier_bb(&t, &ctx);
        let mut pubs = membership_public_values_bb(&root, &ctx, &null);
        pubs[PUB_CTX_START] = pubs[PUB_CTX_START] + BabyBear::ONE;
        check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn corrupt_public_root_rejected() {
        let (t, ctx, bits, sibs, root) = setup();
        let trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
        let null = membership_nullifier_bb(&t, &ctx);
        let mut pubs = membership_public_values_bb(&root, &ctx, &null);
        pubs[PUB_ROOT_START] = pubs[PUB_ROOT_START] + BabyBear::ONE;
        check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn corrupt_sibling_rejected() {
        let (t, ctx, bits, mut sibs, root) = setup();
        sibs[1][0] = sibs[1][0] + BabyBear::ONE; // wrong authentication-path sibling
        let trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
        let null = membership_nullifier_bb(&t, &ctx);
        let pubs = membership_public_values_bb(&root, &ctx, &null);
        check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
    }

    /// Degree-7 optimization: the stored node-input column is pinned by the degree-2 selection
    /// constraint; corrupting it must be rejected (under-constrained-column hunt).
    #[test]
    #[should_panic]
    fn corrupt_node_input_rejected() {
        let (t, ctx, bits, sibs, root) = setup();
        let mut trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
        trace.values[M_NODE_INPUT_START + 3] = trace.values[M_NODE_INPUT_START + 3] + BabyBear::ONE;
        let null = membership_nullifier_bb(&t, &ctx);
        let pubs = membership_public_values_bb(&root, &ctx, &null);
        check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
    }

    /// Corrupt the secret `t` column in row 0: leaf no longer matches the path's first running.
    #[test]
    #[should_panic]
    fn corrupt_secret_t_rejected() {
        let (t, ctx, bits, sibs, root) = setup();
        let mut trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
        trace.values[T_START] = trace.values[T_START] + BabyBear::ONE;
        let null = membership_nullifier_bb(&t, &ctx);
        let pubs = membership_public_values_bb(&root, &ctx, &null);
        check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);
    }

    /// EXHAUSTIVE under-constraint audit. For an otherwise-valid trace, mutate EVERY column
    /// (trying each row) by +1 and require `check_constraints` to reject. A column whose
    /// mutation is never rejected is unconstrained by the AIR — a malicious prover could set it
    /// freely, the classic STARK soundness hole. This complements the hand-picked corruption
    /// tests above by covering all 1661 columns, not a representative sample. The depth-4
    /// witness (leaf_index 6) exercises both direction-bit branches and the first/transition/last
    /// boundary rows. NOTE (honest scope): this proves every column is read by *some* satisfied
    /// constraint that the +1 perturbation breaks; it is not a completeness proof of the relation.
    #[test]
    fn under_constraint_audit_every_column() {
        use std::panic::{
            AssertUnwindSafe,
            catch_unwind,
        };
        let (t, ctx, bits, sibs, root) = setup();
        let trace = generate_membership_trace_bb(&t, &ctx, &bits, &sibs);
        let null = membership_nullifier_bb(&t, &ctx);
        let pubs = membership_public_values_bb(&root, &ctx, &null);
        let width = MEMBERSHIP_ROW_WIDTH;
        let height = trace.values.len() / width;

        // Sanity: the honest trace passes before we start mutating.
        check_constraints(&UnlinkableMembershipBbAir, &trace, &pubs);

        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // silence expected per-mutation panics
        let mut survived = Vec::new();
        for col in 0..width {
            let mut rejected = false;
            for row in 0..height {
                let mut tr = trace.clone();
                let idx = row * width + col;
                tr.values[idx] = tr.values[idx] + BabyBear::ONE;
                if catch_unwind(AssertUnwindSafe(|| {
                    check_constraints(&UnlinkableMembershipBbAir, &tr, &pubs)
                }))
                .is_err()
                {
                    rejected = true;
                    break;
                }
            }
            if !rejected {
                survived.push(col);
            }
        }
        std::panic::set_hook(prev);
        assert!(
            survived.is_empty(),
            "UNCONSTRAINED columns (+1 mutation rejected at no row): {survived:?}"
        );
    }
}
