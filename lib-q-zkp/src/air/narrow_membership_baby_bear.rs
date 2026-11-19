//! Narrow-trace unlinkable-membership AIR over Poseidon2-BabyBear (the tracked task, step S1).
//!
//! Proves the SAME frozen statement as [`super::unlinkable_membership_baby_bear`]
//! (`libq.zkfri.membership.v0`, public values `root(9) ‖ ctx(4) ‖ N(9)`, identical hash
//! functions, identical leaf / nullifier / node sponges) but lays the computation out
//! **one Poseidon2 round per row** instead of one Merkle level per row:
//!
//! * the wide AIR is 1661 columns × `depth` rows; FRI opens `num_queries × width` cells;
//! * this AIR is [`NARROW_ROW_WIDTH`] columns × `22 · (3 + 3·depth) → next pow2` rows.
//!
//! RED / research. Nothing here is a soundness claim; see the crate docs for the open
//! Poseidon2 round-count obligations, which are unchanged by this re-layout.
//!
//! # Layout
//!
//! One permutation = 22 rows (`phase` 0..=21). Row `phase` holds the state *before* round
//! `phase` (already passed through the initial external linear layer); rows 0..=20 each carry
//! one round (4 full, 13 partial, 4 full), row 21 holds the permutation output.
//!
//! The schedule of permutations is: `LEAF`, `NULL0`, `NULL1`, then per tree level
//! `NODE0, NODE1, NODE2`, then `PAD` until the (power-of-two) height. The round index and the
//! stage are one-hot **rings in the main trace** (not preprocessed columns: the STARK prover
//! rejects preprocessed columns in zero-knowledge mode, and the membership statement needs ZK).
//!
//! | cols | meaning |
//! |---|---|
//! | 0..16 | state before this row's round |
//! | 16..38 | one-hot phase ring (22) |
//! | 38..45 | one-hot stage (LEAF, NULL0, NULL1, NODE0, NODE1, NODE2, PAD) |
//! | 45..51 | secret trapdoor `t` (constant on all rows) |
//! | 51..60 | `R` running digest (captured at the end of LEAF and of every NODE2) |
//! | 60..69 | `SIB` sibling of the current level (changes only at a NODE2 boundary) |
//! | 69 | `dir` direction bit |
//! | 70..73 | `rem` levels remaining, `isz = (rem == 0)`, `inv` |
//!
//! Max constraint degree is 9 (gated x⁷ round + transition selector).

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_poseidon::poseidon2_baby_bear::{
    PARTIAL_ROUNDS, RC_EXTERNAL_FINAL, RC_EXTERNAL_INITIAL, RC_INTERNAL, WIDTH, internal_diag,
};
use lib_q_stark_air::{Air, AirBuilder, BaseAir, WindowAccess};
use lib_q_stark_baby_bear::BabyBear;
use lib_q_stark_field::{Field, PrimeCharacteristicRing};
use lib_q_stark_matrix::dense::RowMajorMatrix;

use crate::air::poseidon2_gadget::external_linear_expr;
use crate::air::unlinkable_membership_baby_bear::{
    CTX_ELEMS, MEMBERSHIP_NUM_PUBLIC, SECRET_T_ELEMS, membership_domain_bb,
};
use crate::air::wide_merkle_path_baby_bear::WideDigestBb;
use crate::air::wide_sponge_baby_bear::WIDE_DIGEST_ELEMS;

/// Rows per permutation.
pub const ROWS_PER_PERM: usize = 22;

const STATE: usize = 0;
const RING: usize = STATE + WIDTH; // 16
const STAGE: usize = RING + ROWS_PER_PERM; // 38
const T: usize = STAGE + 7; // 45
const R: usize = T + SECRET_T_ELEMS; // 51
const SIB: usize = R + WIDE_DIGEST_ELEMS; // 60
const DIR: usize = SIB + WIDE_DIGEST_ELEMS; // 69
const REM: usize = DIR + 1; // 70
const ISZ: usize = REM + 1; // 71
const INV: usize = ISZ + 1; // 72
/// Trace width (73 columns, versus 1661 for the one-level-per-row layout).
pub const NARROW_ROW_WIDTH: usize = INV + 1;

const S_LEAF: usize = 0;
const S_NULL0: usize = 1;
const S_NULL1: usize = 2;
const S_NODE0: usize = 3;
const S_NODE1: usize = 4;
const S_NODE2: usize = 5;
const S_PAD: usize = 6;

const PUB_CTX: usize = WIDE_DIGEST_ELEMS; // 9
const PUB_NULL: usize = PUB_CTX + CTX_ELEMS; // 13

/// Number of real (non-padding) permutations for a tree of `depth` levels.
pub const fn narrow_num_perms(depth: usize) -> usize {
    3 + 3 * depth
}

/// Trace height for `depth` levels: next power of two ≥ `22·perms + 1` (at least one PAD row).
pub const fn narrow_trace_height(depth: usize) -> usize {
    (ROWS_PER_PERM * narrow_num_perms(depth) + 1).next_power_of_two()
}

/// The narrow-trace membership AIR for a tree of exactly `depth` levels (`depth ≥ 1`).
#[derive(Debug, Clone, Copy)]
pub struct NarrowMembershipBbAir {
    /// Number of Merkle levels the statement proves.
    pub depth: usize,
}

impl<F: Field> BaseAir<F> for NarrowMembershipBbAir {
    fn width(&self) -> usize {
        NARROW_ROW_WIDTH
    }
}

#[inline]
fn pow7<E: PrimeCharacteristicRing + Clone>(x: E) -> E {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x2 * x
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for NarrowMembershipBbAir {
    fn eval(&self, b: &mut AB) {
        assert!(self.depth >= 1, "narrow membership needs depth >= 1");
        let (l, n): (Vec<AB::Expr>, Vec<AB::Expr>) = {
            let main = b.main();
            let to_e = |v: &AB::Var| -> AB::Expr { (*v).into() };
            (
                main.current_slice().iter().map(to_e).collect(),
                main.next_slice().iter().map(to_e).collect(),
            )
        };
        let pubs: Vec<AB::Expr> = {
            let p = b.public_values();
            p.iter().map(|v| (*v).into()).collect()
        };
        let cst = |x: BabyBear| -> AB::Expr { AB::Expr::from(x) };
        let one = AB::Expr::ONE;
        let zero = AB::Expr::ZERO;

        let st = &l[STATE..STATE + WIDTH];
        let nst = &n[STATE..STATE + WIDTH];
        let ring = &l[RING..RING + ROWS_PER_PERM];
        let nring = &n[RING..RING + ROWS_PER_PERM];
        let stage = &l[STAGE..STAGE + 7];
        let nstage = &n[STAGE..STAGE + 7];
        let t = &l[T..T + SECRET_T_ELEMS];
        let nt = &n[T..T + SECRET_T_ELEMS];
        let r = &l[R..R + WIDE_DIGEST_ELEMS];
        let nr = &n[R..R + WIDE_DIGEST_ELEMS];
        let sib = &l[SIB..SIB + WIDE_DIGEST_ELEMS];
        let nsib = &n[SIB..SIB + WIDE_DIGEST_ELEMS];
        let dir = &l[DIR];
        let ndir = &n[DIR];
        let rem = &l[REM];
        let nrem = &n[REM];
        let isz = &l[ISZ];
        let inv = &l[INV];
        let ring21 = ring[ROWS_PER_PERM - 1].clone();

        // ---------------- first row ----------------
        {
            let mut fb = b.when_first_row();
            let mut leaf_in: Vec<AB::Expr> = vec![zero.clone(); WIDTH];
            for i in 0..SECRET_T_ELEMS {
                leaf_in[i] = t[i].clone();
            }
            leaf_in[SECRET_T_ELEMS] = one.clone(); // 10*1 pad: absorbed = 6, 6+1 == RATE
            let exp = external_linear_expr(&leaf_in);
            for i in 0..WIDTH {
                fb.assert_eq(st[i].clone(), exp[i].clone());
            }
            fb.assert_one(ring[0].clone());
            for k in 1..ROWS_PER_PERM {
                fb.assert_zero(ring[k].clone());
            }
            for j in 0..7 {
                if j == S_LEAF {
                    fb.assert_one(stage[j].clone());
                } else {
                    fb.assert_zero(stage[j].clone());
                }
            }
            fb.assert_eq(rem.clone(), cst(BabyBear::new((self.depth - 1) as u32)));
        }
        // ---------------- last row ----------------
        b.when_last_row().assert_one(stage[S_PAD].clone());

        // ---------------- every row ----------------
        b.assert_bool(dir.clone());
        b.assert_zero(rem.clone() * isz.clone());
        b.assert_eq(isz.clone(), one.clone() - rem.clone() * inv.clone());
        for i in 0..WIDE_DIGEST_ELEMS {
            // Nullifier revealed at the end of NULL1.
            b.assert_zero(
                ring21.clone()
                    * stage[S_NULL1].clone()
                    * (st[i].clone() - pubs[PUB_NULL + i].clone()),
            );
            // Root revealed at the end of the last level's NODE2.
            b.assert_zero(
                ring21.clone()
                    * stage[S_NODE2].clone()
                    * isz.clone()
                    * (st[i].clone() - pubs[i].clone()),
            );
        }

        // ---------------- transitions ----------------
        let mut cs: Vec<AB::Expr> = Vec::new();

        // Phase ring rotates.
        for k in 0..ROWS_PER_PERM {
            cs.push(nring[(k + 1) % ROWS_PER_PERM].clone() - ring[k].clone());
        }

        // Within-permutation round (phase 0..=20 -> next).
        {
            let mut full_gate = zero.clone();
            let mut part_gate = zero.clone();
            let mut rc_full: Vec<AB::Expr> = vec![zero.clone(); WIDTH];
            let mut rc_part = zero.clone();
            for k in 0..4 {
                full_gate = full_gate + ring[k].clone();
                full_gate = full_gate + ring[17 + k].clone();
                for i in 0..WIDTH {
                    rc_full[i] = rc_full[i].clone()
                        + ring[k].clone() * cst(RC_EXTERNAL_INITIAL[k][i])
                        + ring[17 + k].clone() * cst(RC_EXTERNAL_FINAL[k][i]);
                }
            }
            for k in 0..PARTIAL_ROUNDS {
                part_gate = part_gate + ring[4 + k].clone();
                rc_part = rc_part + ring[4 + k].clone() * cst(RC_INTERNAL[k]);
            }
            // Full round: next = M_E(sbox(state + rc)).
            let v: Vec<AB::Expr> = (0..WIDTH)
                .map(|i| pow7(st[i].clone() + rc_full[i].clone()))
                .collect();
            let full_next = external_linear_expr(&v);
            // Partial round: sbox on lane 0 only, then M_I = diag + all-ones.
            let w0 = pow7(st[0].clone() + rc_part);
            let mut sum = w0.clone();
            for i in 1..WIDTH {
                sum = sum + st[i].clone();
            }
            let diag = internal_diag();
            for i in 0..WIDTH {
                let wi = if i == 0 { w0.clone() } else { st[i].clone() };
                let part_next = cst(diag[i]) * wi + sum.clone();
                cs.push(
                    full_gate.clone() * (nst[i].clone() - full_next[i].clone())
                        + part_gate.clone() * (nst[i].clone() - part_next),
                );
            }
        }

        // Permutation boundary (phase 21 -> next phase 0).
        {
            let cont = nstage[S_NULL1].clone() + nstage[S_NODE1].clone() + nstage[S_NODE2].clone();
            // Direction-selected node input `left ‖ right`, read from the NEXT row.
            let mut node: Vec<AB::Expr> = Vec::with_capacity(2 * WIDE_DIGEST_ELEMS);
            for i in 0..WIDE_DIGEST_ELEMS {
                node.push(nr[i].clone() + ndir.clone() * (nsib[i].clone() - nr[i].clone()));
            }
            for i in 0..WIDE_DIGEST_ELEMS {
                node.push(nsib[i].clone() + ndir.clone() * (nr[i].clone() - nsib[i].clone()));
            }
            let dom = membership_domain_bb();
            let mut block: Vec<AB::Expr> = vec![zero.clone(); WIDTH];
            // NULL0 block: d0 d1 t0..t4.
            block[0] = block[0].clone() + nstage[S_NULL0].clone() * cst(dom[0]);
            block[1] = block[1].clone() + nstage[S_NULL0].clone() * cst(dom[1]);
            for k in 0..5 {
                block[2 + k] = block[2 + k].clone() + nstage[S_NULL0].clone() * nt[k].clone();
            }
            // NULL1 block: t5 c0..c3 1 1 (public ctx).
            block[0] = block[0].clone() + nstage[S_NULL1].clone() * nt[5].clone();
            for k in 0..CTX_ELEMS {
                block[1 + k] =
                    block[1 + k].clone() + nstage[S_NULL1].clone() * pubs[PUB_CTX + k].clone();
            }
            block[5] = block[5].clone() + nstage[S_NULL1].clone();
            block[6] = block[6].clone() + nstage[S_NULL1].clone();
            // NODE blocks: node[0..7], node[7..14], node[14..18] ‖ pad bits at lanes 4 and 6.
            for k in 0..7 {
                block[k] = block[k].clone()
                    + nstage[S_NODE0].clone() * node[k].clone()
                    + nstage[S_NODE1].clone() * node[7 + k].clone();
            }
            for k in 0..4 {
                block[k] = block[k].clone() + nstage[S_NODE2].clone() * node[14 + k].clone();
            }
            block[4] = block[4].clone() + nstage[S_NODE2].clone();
            block[6] = block[6].clone() + nstage[S_NODE2].clone();

            let pre: Vec<AB::Expr> = (0..WIDTH)
                .map(|i| cont.clone() * st[i].clone() + block[i].clone())
                .collect();
            let target = external_linear_expr(&pre);
            for i in 0..WIDTH {
                cs.push(ring21.clone() * (nst[i].clone() - target[i].clone()));
            }
        }

        // Stage successor at the boundary; hold elsewhere.
        {
            let nz = one.clone() - isz.clone();
            let succ = [
                zero.clone(),
                stage[S_LEAF].clone(),
                stage[S_NULL0].clone(),
                stage[S_NULL1].clone() + stage[S_NODE2].clone() * nz,
                stage[S_NODE0].clone(),
                stage[S_NODE1].clone(),
                stage[S_PAD].clone() + stage[S_NODE2].clone() * isz.clone(),
            ];
            for j in 0..7 {
                cs.push(
                    nstage[j].clone()
                        - ((one.clone() - ring21.clone()) * stage[j].clone()
                            + ring21.clone() * succ[j].clone()),
                );
            }
        }

        // Registers.
        let cap = ring21.clone() * (stage[S_LEAF].clone() + stage[S_NODE2].clone());
        for i in 0..WIDE_DIGEST_ELEMS {
            cs.push(nr[i].clone() - (r[i].clone() + cap.clone() * (st[i].clone() - r[i].clone())));
        }
        for k in 0..SECRET_T_ELEMS {
            cs.push(nt[k].clone() - t[k].clone());
        }
        let chg = ring21.clone() * stage[S_NODE2].clone();
        let keep = one.clone() - chg.clone();
        for i in 0..WIDE_DIGEST_ELEMS {
            cs.push(keep.clone() * (nsib[i].clone() - sib[i].clone()));
        }
        cs.push(keep * (ndir.clone() - dir.clone()));
        cs.push(nrem.clone() - (rem.clone() - chg));

        let mut tb = b.when_transition();
        for c in cs {
            tb.assert_zero(c);
        }
    }
}

// ============================= trace generation =============================

fn pow7_v(x: BabyBear) -> BabyBear {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}

fn me_v(s: [BabyBear; WIDTH]) -> [BabyBear; WIDTH] {
    let v = external_linear_expr::<BabyBear>(&s);
    core::array::from_fn(|i| v[i])
}

/// The 22 row-states of one permutation whose (pre-mix) input is `input`.
fn perm_states(input: [BabyBear; WIDTH]) -> [[BabyBear; WIDTH]; ROWS_PER_PERM] {
    let diag = internal_diag();
    let mut rows = [[BabyBear::ZERO; WIDTH]; ROWS_PER_PERM];
    let mut s = me_v(input);
    rows[0] = s;
    for p in 0..ROWS_PER_PERM - 1 {
        if p < 4 || p >= 17 {
            let rc = if p < 4 {
                &RC_EXTERNAL_INITIAL[p]
            } else {
                &RC_EXTERNAL_FINAL[p - 17]
            };
            let v: [BabyBear; WIDTH] = core::array::from_fn(|i| pow7_v(s[i] + rc[i]));
            s = me_v(v);
        } else {
            let w0 = pow7_v(s[0] + RC_INTERNAL[p - 4]);
            let mut sum = w0;
            for x in s.iter().skip(1) {
                sum = sum + *x;
            }
            let mut ns = [BabyBear::ZERO; WIDTH];
            ns[0] = diag[0] * w0 + sum;
            for i in 1..WIDTH {
                ns[i] = diag[i] * s[i] + sum;
            }
            s = ns;
        }
        rows[p + 1] = s;
    }
    rows
}

struct PermSpec {
    stage: usize,
    input: [BabyBear; WIDTH],
    r: WideDigestBb,
    sib: WideDigestBb,
    dir: bool,
    rem: BabyBear,
}

/// Generate the narrow trace. Returns `(trace, nullifier, root)` where `root` is the value the
/// honest path reaches (the caller compares it with the public root).
pub fn generate_narrow_trace_bb(
    t: &[BabyBear; SECRET_T_ELEMS],
    ctx: &[BabyBear; CTX_ELEMS],
    path_bits: &[bool],
    siblings: &[WideDigestBb],
) -> (RowMajorMatrix<BabyBear>, WideDigestBb, WideDigestBb) {
    let depth = path_bits.len();
    assert!(depth >= 1 && depth == siblings.len());
    let zero = BabyBear::ZERO;
    let one = BabyBear::ONE;
    let digest = |o: &[BabyBear; WIDTH]| -> WideDigestBb { core::array::from_fn(|i| o[i]) };
    let out_of = |input: [BabyBear; WIDTH]| perm_states(input)[ROWS_PER_PERM - 1];

    let zero_d = [zero; WIDE_DIGEST_ELEMS];
    let mut specs: Vec<PermSpec> = Vec::new();

    // LEAF
    let mut leaf_in = [zero; WIDTH];
    leaf_in[..SECRET_T_ELEMS].copy_from_slice(t);
    leaf_in[SECRET_T_ELEMS] = one;
    let leaf = digest(&out_of(leaf_in));
    let (sib0, dir0) = (siblings[0], path_bits[0]);
    let rem0 = BabyBear::new((depth - 1) as u32);
    specs.push(PermSpec {
        stage: S_LEAF,
        input: leaf_in,
        r: zero_d,
        sib: sib0,
        dir: dir0,
        rem: rem0,
    });

    // NULL0
    let dom = membership_domain_bb();
    let mut n0 = [zero; WIDTH];
    n0[0] = dom[0];
    n0[1] = dom[1];
    n0[2..7].copy_from_slice(&t[..5]);
    let o0 = out_of(n0);
    specs.push(PermSpec {
        stage: S_NULL0,
        input: n0,
        r: leaf,
        sib: sib0,
        dir: dir0,
        rem: rem0,
    });
    // NULL1
    let mut n1 = o0;
    n1[0] = n1[0] + t[5];
    for k in 0..CTX_ELEMS {
        n1[1 + k] = n1[1 + k] + ctx[k];
    }
    n1[5] = n1[5] + one;
    n1[6] = n1[6] + one;
    let nullifier = digest(&out_of(n1));
    specs.push(PermSpec {
        stage: S_NULL1,
        input: n1,
        r: leaf,
        sib: sib0,
        dir: dir0,
        rem: rem0,
    });

    // Levels
    let mut running = leaf;
    for lvl in 0..depth {
        let (sib, dir) = (siblings[lvl], path_bits[lvl]);
        let rem = BabyBear::new((depth - 1 - lvl) as u32);
        let (left, right) = if dir { (sib, running) } else { (running, sib) };
        let mut node = [zero; 2 * WIDE_DIGEST_ELEMS];
        node[..WIDE_DIGEST_ELEMS].copy_from_slice(&left);
        node[WIDE_DIGEST_ELEMS..].copy_from_slice(&right);

        let mut i0 = [zero; WIDTH];
        i0[..7].copy_from_slice(&node[..7]);
        let o0 = out_of(i0);
        let mut i1 = o0;
        for k in 0..7 {
            i1[k] = i1[k] + node[7 + k];
        }
        let o1 = out_of(i1);
        let mut i2 = o1;
        for k in 0..4 {
            i2[k] = i2[k] + node[14 + k];
        }
        i2[4] = i2[4] + one;
        i2[6] = i2[6] + one;
        let o2 = out_of(i2);
        for (stage, input) in [(S_NODE0, i0), (S_NODE1, i1), (S_NODE2, i2)] {
            specs.push(PermSpec {
                stage,
                input,
                r: running,
                sib,
                dir,
                rem,
            });
        }
        running = digest(&o2);
    }
    let root = running;
    let (last_sib, last_dir) = (siblings[depth - 1], path_bits[depth - 1]);
    let height = narrow_trace_height(depth);
    let real = specs.len();
    let total_perms = height.div_ceil(ROWS_PER_PERM);
    for _ in real..total_perms {
        specs.push(PermSpec {
            stage: S_PAD,
            input: [zero; WIDTH],
            r: root,
            sib: last_sib,
            dir: last_dir,
            rem: -one,
        });
    }

    let mut cells: Vec<BabyBear> = Vec::with_capacity(height * NARROW_ROW_WIDTH);
    'outer: for spec in &specs {
        let states = perm_states(spec.input);
        for (p, state) in states.iter().enumerate() {
            if cells.len() == height * NARROW_ROW_WIDTH {
                break 'outer;
            }
            let mut row = [zero; NARROW_ROW_WIDTH];
            row[STATE..STATE + WIDTH].copy_from_slice(state);
            row[RING + p] = one;
            row[STAGE + spec.stage] = one;
            row[T..T + SECRET_T_ELEMS].copy_from_slice(t);
            row[R..R + WIDE_DIGEST_ELEMS].copy_from_slice(&spec.r);
            row[SIB..SIB + WIDE_DIGEST_ELEMS].copy_from_slice(&spec.sib);
            row[DIR] = if spec.dir { one } else { zero };
            row[REM] = spec.rem;
            if spec.rem == zero {
                row[ISZ] = one;
                row[INV] = zero;
            } else {
                row[ISZ] = zero;
                row[INV] = spec.rem.inverse();
            }
            cells.extend_from_slice(&row);
        }
    }
    debug_assert_eq!(cells.len(), height * NARROW_ROW_WIDTH);
    (
        RowMajorMatrix::new(cells, NARROW_ROW_WIDTH),
        nullifier,
        root,
    )
}

/// Prove the membership statement with the narrow-trace AIR (transparent config).
pub fn prove_narrow_membership_bb(
    config: &crate::stark_baby_bear::BbConfig,
    t: &[BabyBear; SECRET_T_ELEMS],
    ctx: &[BabyBear; CTX_ELEMS],
    path_bits: &[bool],
    siblings: &[WideDigestBb],
) -> Result<
    (
        WideDigestBb,
        lib_q_stark::Proof<crate::stark_baby_bear::BbConfig>,
    ),
    lib_q_stark::ProverError,
> {
    let (trace, null, root) = generate_narrow_trace_bb(t, ctx, path_bits, siblings);
    let pubs =
        super::unlinkable_membership_baby_bear::membership_public_values_bb(&root, ctx, &null);
    let proof = lib_q_stark::prove(
        config,
        &NarrowMembershipBbAir {
            depth: path_bits.len(),
        },
        trace,
        &pubs,
    )?;
    Ok((null, proof))
}

/// Verify a narrow-trace membership proof for a tree of `depth` levels.
pub fn verify_narrow_membership_bb(
    config: &crate::stark_baby_bear::BbConfig,
    depth: usize,
    proof: &lib_q_stark::Proof<crate::stark_baby_bear::BbConfig>,
    root: &WideDigestBb,
    ctx: &[BabyBear; CTX_ELEMS],
    nullifier: &WideDigestBb,
) -> bool {
    let pubs =
        super::unlinkable_membership_baby_bear::membership_public_values_bb(root, ctx, nullifier);
    lib_q_stark::verify(config, &NarrowMembershipBbAir { depth }, proof, &pubs).is_ok()
}

/// Number of public values (same layout as the wide membership AIR).
pub const NARROW_NUM_PUBLIC: usize = MEMBERSHIP_NUM_PUBLIC;

#[cfg(test)]
mod tests {
    use lib_q_poseidon::poseidon2_baby_bear::permute;
    use lib_q_stark_matrix::Matrix;

    use super::*;
    use crate::air::unlinkable_membership_baby_bear::{
        membership_leaf_bb, membership_nullifier_bb, membership_public_values_bb,
    };
    use crate::air::wide_merkle_path_baby_bear::compress_bb;
    use crate::check_constraints;

    const P: u32 = 2_013_265_921;

    fn lcg(seed: u32, n: usize) -> Vec<BabyBear> {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(7);
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                BabyBear::new(x % P)
            })
            .collect()
    }

    pub(crate) struct Fixture {
        pub t: [BabyBear; SECRET_T_ELEMS],
        pub ctx: [BabyBear; CTX_ELEMS],
        pub bits: Vec<bool>,
        pub sibs: Vec<WideDigestBb>,
        pub root: WideDigestBb,
    }

    pub(crate) fn fixture(depth: usize, seed: u32) -> Fixture {
        let t: [BabyBear; SECRET_T_ELEMS] = lcg(seed, SECRET_T_ELEMS).try_into().unwrap();
        let ctx: [BabyBear; CTX_ELEMS] = lcg(seed + 1, CTX_ELEMS).try_into().unwrap();
        let mut running = membership_leaf_bb(&t);
        let (mut bits, mut sibs) = (Vec::new(), Vec::new());
        for lvl in 0..depth {
            let sib: WideDigestBb = lcg(seed * 1009 + lvl as u32 + 3, WIDE_DIGEST_ELEMS)
                .try_into()
                .unwrap();
            let dir = (seed as usize + lvl) & 1 == 1;
            bits.push(dir);
            sibs.push(sib);
            running = if dir {
                compress_bb(&sib, &running)
            } else {
                compress_bb(&running, &sib)
            };
        }
        Fixture {
            t,
            ctx,
            bits,
            sibs,
            root: running,
        }
    }

    #[test]
    fn perm_states_match_reference_permutation() {
        for s in 0..8u32 {
            let input: [BabyBear; WIDTH] = lcg(s, WIDTH).try_into().unwrap();
            assert_eq!(perm_states(input)[ROWS_PER_PERM - 1], permute(input));
        }
    }

    #[test]
    fn honest_trace_matches_wide_statement_and_satisfies_constraints() {
        for depth in [1usize, 2, 3, 4] {
            let f = fixture(depth, depth as u32 + 10);
            let (trace, null, root) = generate_narrow_trace_bb(&f.t, &f.ctx, &f.bits, &f.sibs);
            assert_eq!(root, f.root, "root equals the wide-AIR reference");
            assert_eq!(null, membership_nullifier_bb(&f.t, &f.ctx));
            let pubs = membership_public_values_bb(&f.root, &f.ctx, &null);
            check_constraints(&NarrowMembershipBbAir { depth }, &trace, &pubs);
        }
    }

    #[test]
    #[should_panic]
    fn wrong_nullifier_rejected() {
        let f = fixture(3, 5);
        let (trace, null, _) = generate_narrow_trace_bb(&f.t, &f.ctx, &f.bits, &f.sibs);
        let mut bad = null;
        bad[0] = bad[0] + BabyBear::ONE;
        let pubs = membership_public_values_bb(&f.root, &f.ctx, &bad);
        check_constraints(&NarrowMembershipBbAir { depth: 3 }, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn wrong_root_rejected() {
        let f = fixture(3, 6);
        let (trace, null, _) = generate_narrow_trace_bb(&f.t, &f.ctx, &f.bits, &f.sibs);
        let mut bad = f.root;
        bad[3] = bad[3] + BabyBear::ONE;
        let pubs = membership_public_values_bb(&bad, &f.ctx, &null);
        check_constraints(&NarrowMembershipBbAir { depth: 3 }, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn wrong_ctx_rejected() {
        let f = fixture(3, 7);
        let (trace, null, _) = generate_narrow_trace_bb(&f.t, &f.ctx, &f.bits, &f.sibs);
        let mut bad = f.ctx;
        bad[0] = bad[0] + BabyBear::ONE;
        let pubs = membership_public_values_bb(&f.root, &bad, &null);
        check_constraints(&NarrowMembershipBbAir { depth: 3 }, &trace, &pubs);
    }

    #[test]
    #[should_panic]
    fn depth_mismatch_rejected() {
        // A depth-3 path presented to a depth-4 statement must not satisfy the constraints.
        let f = fixture(3, 8);
        let (trace, null, _) = generate_narrow_trace_bb(&f.t, &f.ctx, &f.bits, &f.sibs);
        let pubs = membership_public_values_bb(&f.root, &f.ctx, &null);
        check_constraints(&NarrowMembershipBbAir { depth: 4 }, &trace, &pubs);
    }

    /// Corrupt every column class in turn at a mid-trace row; each must be rejected.
    #[test]
    fn corruption_of_any_column_is_rejected() {
        let depth = 3;
        let f = fixture(depth, 9);
        let (trace, null, _) = generate_narrow_trace_bb(&f.t, &f.ctx, &f.bits, &f.sibs);
        let pubs = membership_public_values_bb(&f.root, &f.ctx, &null);
        let air = NarrowMembershipBbAir { depth };
        let h = trace.height();
        // Row 30 is inside NULL0..NULL1 region; row 22*8+3 inside level 1.
        for &row in &[30usize, 22 * 8 + 3, h - 2] {
            for col in 0..NARROW_ROW_WIDTH {
                let mut bad = trace.clone();
                bad.values[row * NARROW_ROW_WIDTH + col] += BabyBear::ONE;
                let res = std::panic::catch_unwind(|| check_constraints(&air, &bad, &pubs));
                assert!(
                    res.is_err(),
                    "corrupting row {row} col {col} was not rejected"
                );
            }
        }
    }

    #[test]
    fn narrow_prove_verify_roundtrip_and_tamper() {
        use crate::stark_baby_bear::default_config_bb;
        let cfg = default_config_bb();
        let depth = 4;
        let f = fixture(depth, 21);
        let (null, proof) =
            prove_narrow_membership_bb(&cfg, &f.t, &f.ctx, &f.bits, &f.sibs).expect("prove");
        assert!(verify_narrow_membership_bb(
            &cfg, depth, &proof, &f.root, &f.ctx, &null
        ));
        let mut bad = null;
        bad[0] = bad[0] + BabyBear::ONE;
        assert!(!verify_narrow_membership_bb(
            &cfg, depth, &proof, &f.root, &f.ctx, &bad
        ));
        assert!(!verify_narrow_membership_bb(
            &cfg,
            depth + 1,
            &proof,
            &f.root,
            &f.ctx,
            &null
        ));
    }

    /// `cargo test -p lib-q-zkp --release --lib narrow_membership_baby_bear::tests::measure_narrow -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn measure_narrow() {
        use std::time::Instant;

        use crate::stark_baby_bear::default_config_bb;
        let cfg = default_config_bb();
        println!("NARROW,depth,width,height,prove_ms,verify_ms,proof_bytes");
        for depth in [4usize, 20, 32] {
            let f = fixture(depth, 31 + depth as u32);
            let t0 = Instant::now();
            let (null, proof) =
                prove_narrow_membership_bb(&cfg, &f.t, &f.ctx, &f.bits, &f.sibs).unwrap();
            let pm = t0.elapsed().as_secs_f64() * 1e3;
            let bytes = postcard::to_allocvec(&proof).unwrap().len();

            let c = postcard::to_allocvec(&proof.commitments).unwrap().len();
            let o = postcard::to_allocvec(&proof.opened_values).unwrap().len();
            let q = postcard::to_allocvec(&proof.opening_proof).unwrap().len();
            println!(
                "NARROW_BREAKDOWN,{depth},commitments={c},opened_values={o},opening_proof={q}"
            );
            let t1 = Instant::now();
            assert!(verify_narrow_membership_bb(
                &cfg, depth, &proof, &f.root, &f.ctx, &null
            ));
            let vm = t1.elapsed().as_secs_f64() * 1e3;
            println!(
                "NARROW,{depth},{NARROW_ROW_WIDTH},{},{pm:.0},{vm:.1},{bytes}",
                narrow_trace_height(depth)
            );
        }
    }
}
