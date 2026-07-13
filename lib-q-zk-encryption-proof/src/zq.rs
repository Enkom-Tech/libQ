//! Non-native `Z_q` arithmetic foundation for the lattice-relation check (design §4.3, R3).
//!
//! The STARK field is Mersenne31 (`p = 2^31 − 1`); the lattice modulus is
//! `q = 281474976694273 = 2^48 − 2^14 + 1`. This module provides the **atomic reduction primitive**
//! every fold step needs: [`ModReduceAir`] proves, per row, the exact Euclidean reduction
//!
//! ```text
//!     V = κ·q + r,        0 ≤ r < q,   0 ≤ κ < 2^48,        V < 2^96
//! ```
//!
//! for a witnessed non-negative integer `V`. In the R3 Horner fold `acc ← acc·ζ + w` the challenge
//! `ζ` is a *public* Fiat-Shamir scalar, so `acc·ζ + w = V` is a public-coefficient-linear function
//! of the witness limbs (no witness×witness product); the **only** non-native nonlinearity is this
//! reduction, which is why it is factored out and reviewed on its own.
//!
//! ## Limb choice (why 12 bits)
//! A limb product `a_i·b_j` must stay below `p` so that field-equality implies integer-equality.
//! With `n = ⌈48/L⌉` limbs the widest schoolbook group has `n` partials, so `n·2^{2L} < 2^31` is
//! required. `L = 12` gives `n = 4` (48 bits exactly), partials `< 2^24`, the 4-term middle group
//! `< 2^26`, and carries `< 2^15` — every carry-chain term stays `< 2^28 < p` with headroom. (`L =
//! 14` also fits but leaves the reduction carries closer to the field boundary; 12 is the safe pick.)
//!
//! ## Soundness sketch
//! `κ·q` is public-linear in `κ`'s limbs (`q`'s limbs are constants). The identity `κ·q + r = V` is
//! checked by an unsigned base-`2^12` carry chain (both sides ≥ 0), with `carry_8 = 0` bounding
//! `κ·q + r < 2^96` and hence `κ < 2^48`. `r < q` is enforced by a 4-limb borrow subtraction against
//! the public constant `q − 1` (final borrow forced to 0). Given the range checks, each carry-chain
//! digit `(v_g, carry_{g+1})` is the unique quotient/remainder of the bounded `S_g + carry_g`, so the
//! chain composes to the exact integer identity; with `0 ≤ r < q` Euclidean division is unique, so
//! `κ, r` are forced to be the true quotient/remainder of `V`.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::array;

use lib_q_plonky_lookup::{
    Direction,
    Kind,
    Lookup,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::stark::ConfigVal;

use crate::error::EncProofError;
use crate::logup_join::{
    mcol,
    sconst,
};

/// Lattice modulus `q = 2^48 − 2^14 + 1`.
pub const Q: u64 = 281474976694273;
/// Limb size in bits.
const LIMB_BITS: usize = 12;
/// Limb radix `B = 2^12`.
const B: u64 = 1 << LIMB_BITS;
/// Low-limb mask `B − 1`.
const LIMB_MASK: u64 = B - 1;
/// Number of 12-bit limbs in a `Z_q` element (`4·12 = 48`).
const NLIMB: usize = 4;
/// Number of 12-bit limbs in the wide value `V < 2^96` (`8·12 = 96`).
const VLIMB: usize = 8;
/// Carry range-check width (honest carries `< 2^14`; `2^12·2^15 + 2^12 < p`).
const CARRY_BITS: usize = 15;

/// 12-bit limbs of `q`, low to high: `[1, 4092, 4095, 4095]`. Also used by join 2's bounded lift
/// derivation ([`crate::sampler::bounded_coeff_send_lookups_at`]) as the `neg·q` addend limbs.
pub(crate) const Q_LIMBS: [u64; NLIMB] = [
    Q & LIMB_MASK,
    (Q >> 12) & LIMB_MASK,
    (Q >> 24) & LIMB_MASK,
    (Q >> 36) & LIMB_MASK,
];
/// 12-bit limbs of `q − 1` (the strict-`<`-comparison constant): `[0, 4092, 4095, 4095]`. Also the
/// mod-q lift limbs of the ternary coefficient `−1` (join 2's ternary Send value; see
/// [`crate::sampler::ternary_coeff_send_lookups_at`]).
pub(crate) const QM1_LIMBS: [u64; NLIMB] = [
    (Q - 1) & LIMB_MASK,
    ((Q - 1) >> 12) & LIMB_MASK,
    ((Q - 1) >> 24) & LIMB_MASK,
    ((Q - 1) >> 36) & LIMB_MASK,
];

// Column layout (width [`MODREDUCE_WIDTH`]).
const ZW_V: usize = 0; // 8 V limbs (value):        0 .. 8
const ZW_K: usize = 8; // 4 κ limbs (value):        8 .. 12
const ZW_R: usize = 12; // 4 r limbs (value):       12 .. 16
const ZW_CARRY: usize = 16; // 7 carries c_1..c_7:  16 .. 23
const ZW_VBIT: usize = 23; // V bits (8·12):         23 .. 119   (limb g bit b at ZW_VBIT+12g+b)
const ZW_KBIT: usize = 119; // κ bits (4·12):       119 .. 167
const ZW_RBIT: usize = 167; // r bits (4·12):       167 .. 215
const ZW_CBIT: usize = 215; // carry bits (7·15):   215 .. 320  (carry g bit b at ZW_CBIT+15g+b)
const ZW_BORROW: usize = 320; // borrow bits bo_1..bo_4: 320 .. 324
const ZW_DBIT: usize = 324; // subtraction digit bits (4·12): 324 .. 372

/// Trace width of [`ModReduceAir`].
pub const MODREDUCE_WIDTH: usize = 372;

/// Build the field element for a `u64` constant `< p` by Horner evaluation of its bits (only
/// `ZERO`/`ONE`/`double`/`+` are used, so no field-constant constructor is assumed).
fn konst<AB: AirBuilder>(x: u64) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    for shift in (0..64).rev() {
        acc = acc.double();
        if (x >> shift) & 1 == 1 {
            acc += AB::Expr::ONE;
        }
    }
    acc
}

/// AIR proving each row is an exact reduction `V = κ·q + r`, `0 ≤ r < q`, `0 ≤ κ < 2^48`.
#[derive(Debug, Clone, Default)]
pub struct ModReduceAir;

impl<F> BaseAir<F> for ModReduceAir {
    fn width(&self) -> usize {
        MODREDUCE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        0
    }
}

impl<AB: AirBuilder> Air<AB> for ModReduceAir {
    fn eval(&self, builder: &mut AB) {
        let loc: Vec<AB::Expr> = {
            let main = builder.main();
            let local = main.current_slice();
            (0..MODREDUCE_WIDTH).map(|i| local[i].into()).collect()
        };

        // Helper: recompose `nbits` boolean columns starting at `base` into their integer value,
        // asserting each bit is boolean.
        let recompose = |builder: &mut AB, base: usize, nbits: usize| -> AB::Expr {
            let mut horner = AB::Expr::ZERO;
            for b in (0..nbits).rev() {
                let bit = loc[base + b].clone();
                builder.assert_bool(bit.clone());
                horner = horner.double() + bit;
            }
            horner
        };

        // --- range checks: every value column equals the Horner sum of its bit columns ---
        for g in 0..VLIMB {
            let val = recompose(builder, ZW_VBIT + LIMB_BITS * g, LIMB_BITS);
            builder.assert_zero(loc[ZW_V + g].clone() - val);
        }
        for i in 0..NLIMB {
            let val = recompose(builder, ZW_KBIT + LIMB_BITS * i, LIMB_BITS);
            builder.assert_zero(loc[ZW_K + i].clone() - val);
        }
        for i in 0..NLIMB {
            let val = recompose(builder, ZW_RBIT + LIMB_BITS * i, LIMB_BITS);
            builder.assert_zero(loc[ZW_R + i].clone() - val);
        }
        for g in 0..7 {
            let val = recompose(builder, ZW_CBIT + CARRY_BITS * g, CARRY_BITS);
            builder.assert_zero(loc[ZW_CARRY + g].clone() - val);
        }
        for g in 0..NLIMB {
            builder.assert_bool(loc[ZW_BORROW + g].clone());
            for b in 0..LIMB_BITS {
                builder.assert_bool(loc[ZW_DBIT + LIMB_BITS * g + b].clone());
            }
        }

        // --- reduction identity  κ·q + r = V  (unsigned base-2^12 carry chain) ---
        let radix = konst::<AB>(B);
        for g in 0..VLIMB {
            // P_g = Σ_{i+j=g, i,j<NLIMB} κ_i · q_j   (public-linear in κ; q_j constant).
            let mut p_g = AB::Expr::ZERO;
            for i in 0..NLIMB {
                if g >= i && g - i < NLIMB {
                    p_g += loc[ZW_K + i].clone() * konst::<AB>(Q_LIMBS[g - i]);
                }
            }
            // S_g = P_g + r_g (r has only NLIMB limbs).
            let s_g = if g < NLIMB {
                p_g + loc[ZW_R + g].clone()
            } else {
                p_g
            };
            let carry_in = if g == 0 {
                AB::Expr::ZERO
            } else {
                loc[ZW_CARRY + (g - 1)].clone()
            };
            // carry_8 (out of the top limb) is fixed to 0 ⇒ κ·q + r < 2^96.
            let carry_out = if g < 7 {
                loc[ZW_CARRY + g].clone()
            } else {
                AB::Expr::ZERO
            };
            builder.assert_zero(
                (s_g + carry_in) - (loc[ZW_V + g].clone() + radix.clone() * carry_out),
            );
        }

        // --- strict comparison  r < q  (borrow subtraction (q−1) − r, final borrow forced 0) ---
        for g in 0..NLIMB {
            let mut d_g = AB::Expr::ZERO;
            for b in (0..LIMB_BITS).rev() {
                d_g = d_g.double() + loc[ZW_DBIT + LIMB_BITS * g + b].clone();
            }
            let zc_g = konst::<AB>(QM1_LIMBS[g]);
            let borrow_in = if g == 0 {
                AB::Expr::ZERO
            } else {
                loc[ZW_BORROW + (g - 1)].clone()
            };
            let borrow_out = loc[ZW_BORROW + g].clone();
            // d_g = (q−1)_g − r_g − borrow_in + 2^12·borrow_out,  d_g ∈ [0, 2^12), borrow ∈ {0,1}.
            builder.assert_zero(
                d_g - (zc_g - loc[ZW_R + g].clone() - borrow_in + radix.clone() * borrow_out),
            );
        }
        // r ≤ q − 1  ⇔  r < q.
        builder.assert_zero(loc[ZW_BORROW + (NLIMB - 1)].clone());
    }
}

/// Lift a small non-negative integer into the STARK value field.
fn cv(x: u64) -> ConfigVal {
    ConfigVal::from_basis_coefficients_fn(|i| {
        if i == 0 {
            Mersenne31::new(x as u32)
        } else {
            Mersenne31::ZERO
        }
    })
}

/// Lift a single bit (`0`/`1`) into the STARK value field.
fn bit_cv(b: u64) -> ConfigVal {
    if b == 1 {
        ConfigVal::ONE
    } else {
        ConfigVal::ZERO
    }
}

/// Build one [`ModReduceAir`] row proving `v = κ·q + r`. Every column is set (in particular the
/// `r < q` comparison digits, which are nonzero even for `r = 0`), so a `v = 0` row is a valid
/// padding row — an all-zero row would *not* satisfy the comparison constraint.
fn modreduce_row(v: u128) -> [ConfigVal; MODREDUCE_WIDTH] {
    // κ < 2^48 and r < q both fit in u64; V may be up to 2^96 (a Horner accumulator `acc·ζ+w`).
    let kappa = (v / u128::from(Q)) as u64;
    let r = (v % u128::from(Q)) as u64;

    let vlimbs: [u64; VLIMB] =
        array::from_fn(|g| ((v >> (LIMB_BITS * g)) & u128::from(LIMB_MASK)) as u64);
    let klimbs: [u64; NLIMB] = array::from_fn(|i| (kappa >> (LIMB_BITS * i)) & LIMB_MASK);
    let rlimbs: [u64; NLIMB] = array::from_fn(|i| (r >> (LIMB_BITS * i)) & LIMB_MASK);

    let mut row = [ConfigVal::ZERO; MODREDUCE_WIDTH];
    for g in 0..VLIMB {
        row[ZW_V + g] = cv(vlimbs[g]);
        for b in 0..LIMB_BITS {
            row[ZW_VBIT + LIMB_BITS * g + b] = bit_cv((vlimbs[g] >> b) & 1);
        }
    }
    for i in 0..NLIMB {
        row[ZW_K + i] = cv(klimbs[i]);
        row[ZW_R + i] = cv(rlimbs[i]);
        for b in 0..LIMB_BITS {
            row[ZW_KBIT + LIMB_BITS * i + b] = bit_cv((klimbs[i] >> b) & 1);
            row[ZW_RBIT + LIMB_BITS * i + b] = bit_cv((rlimbs[i] >> b) & 1);
        }
    }

    // carry chain (recomputed exactly as the AIR verifies it).
    let mut carry = 0u64;
    for g in 0..VLIMB {
        let mut p_g = 0u64;
        for i in 0..NLIMB {
            if g >= i && g - i < NLIMB {
                p_g += klimbs[i] * Q_LIMBS[g - i];
            }
        }
        let s_g = if g < NLIMB { p_g + rlimbs[g] } else { p_g };
        let acc = s_g + carry;
        debug_assert_eq!(
            acc & LIMB_MASK,
            vlimbs[g],
            "modreduce carry-chain limb mismatch"
        );
        carry = acc >> LIMB_BITS;
        if g < 7 {
            row[ZW_CARRY + g] = cv(carry);
            for b in 0..CARRY_BITS {
                row[ZW_CBIT + CARRY_BITS * g + b] = bit_cv((carry >> b) & 1);
            }
        }
    }
    debug_assert_eq!(carry, 0, "modreduce carry chain must fully vanish");

    // comparison borrow chain (q−1) − r.
    let mut borrow = 0i64;
    for g in 0..NLIMB {
        let t = QM1_LIMBS[g] as i64 - rlimbs[g] as i64 - borrow;
        let (d, bo) = if t < 0 {
            (t + B as i64, 1i64)
        } else {
            (t, 0i64)
        };
        for b in 0..LIMB_BITS {
            row[ZW_DBIT + LIMB_BITS * g + b] = bit_cv(((d as u64) >> b) & 1);
        }
        row[ZW_BORROW + g] = bit_cv(bo as u64);
        borrow = bo;
    }
    debug_assert_eq!(borrow, 0, "r = V mod q is always < q");

    row
}

/// Generate a [`ModReduceAir`] trace: one row per input value `V` (`V < 2^96`), each proving
/// `V = κ·q + r`. Pads to a power-of-two height with `V = 0` reduction rows.
pub fn generate_modreduce_trace(
    values: &[u128],
) -> Result<RowMajorMatrix<ConfigVal>, EncProofError> {
    if values.is_empty() {
        return Err(EncProofError::TraceGeneration("modreduce: no values"));
    }
    let mut rows: Vec<[ConfigVal; MODREDUCE_WIDTH]> =
        values.iter().map(|&v| modreduce_row(v)).collect();

    // Pad to a power-of-two height (≥ 2) with valid `0 = 0·q + 0` rows.
    let height = rows.len().next_power_of_two().max(2);
    let zero_row = modreduce_row(0);
    while rows.len() < height {
        rows.push(zero_row);
    }

    let mut vals = Vec::with_capacity(height * MODREDUCE_WIDTH);
    for row in rows {
        vals.extend_from_slice(&row);
    }
    Ok(RowMajorMatrix::new(vals, MODREDUCE_WIDTH))
}

// ===========================================================================================
// Horner polynomial-evaluation fold  E = Σ_i c_i·ζ^i (mod q)   (design §4.1, R3 fold layer).
// ===========================================================================================
//
// Each row performs one Horner step `acc ← (acc·ζ + w) mod q` and chains to the next: `next.acc =
// this.r`, `first.acc = 0`. Feeding the coefficients high-order-first (`w = c_{M-1}, …, c_0`) makes
// the final row's `r` equal `E = Σ_i c_i ζ^i (mod q)` — the witness fold value the relation check
// (§4) consumes (`E_r = e_r(ζ)`, `F_k = f_k(ζ)`, quotients `H_k(ζ)`, …).
//
// **Public-linear, single fused signed carry chain.** `ζ` is a *public* Fiat-Shamir scalar, so both
// `acc·ζ` and `κ·q` are public-coefficient-linear schoolbooks (no witness×witness). The identity
// `acc·ζ + w = κ·q + r` is verified WITHOUT materializing the product: a single carry chain over the
// signed per-limb difference `net_g = L_g + w_g − R_g − r_g` (`L_g = Σ_{i+j=g} acc_i·ζ_j`,
// `R_g = Σ_{i+j=g} κ_i·q_j`). With `c_0 = c_8 = 0` hardcoded, `net_g + c_g = 2^12·c_{g+1}` telescopes
// to `Σ_g net_g·2^{12g} = 0`, i.e. `acc·ζ + w = κ·q + r`, for ANY carries satisfying the per-limb
// equations — so a false statement cannot pass. Carries are signed; each is stored offset by `2^17`
// and range-checked to 18 bits, keeping every term `< 2^30 < p` (field-eq ⇔ integer-eq). `r < q` is
// the same borrow comparison as [`ModReduceAir`]; `κ < 2^48` is structural (4 limbs). `w`'s limbs are
// range-checked (`< 2^12`); its canonical bound `w < q` is supplied by LogUp join 2 (the sampler).
//
// **Composition obligations (adversarial review, 2026-07-10 — the fold's *internal* arithmetic is
// sound; these are the boundary bindings the R3 relation-check / composition layer MUST supply):**
//  1. *Expose the result.* The final row's `r` is `E` but is NOT a public value of this AIR, so a
//     standalone `HornerFoldAir` proof only attests "some Horner chain is internally consistent." The
//     relation-check AIR must READ the last-row `r` (boundary opening / shared LogUp column) and feed
//     it into the scalar equations (§4.1); otherwise a prover could evaluate a *different* polynomial.
//  2. *Bind the coefficients.* `w`'s per-row values must be tied to the real sampler coefficients via
//     LogUp join 2 (only `w < 2^48` is local here). Absent the join, the polynomial is unconstrained.
//  3. *Canonical `ζ`.* The 4 public `ζ` limbs must each be `< 2^12` (a 12-bit-canonical decomposition
//     of a `< q` challenge) — the verifier obligation the [`horner_public_values`] constructor meets.
//     A non-canonical `ζ` limb could breach the §4.2 field-fit bound; do not hand-build the pubs.

// Column layout (width [`HORNER_WIDTH`]).
const HW_ACC: usize = 0; // 4 accumulator-in limbs:   0 .. 4
const HW_W: usize = 4; // 4 coefficient limbs:       4 .. 8
const HW_K: usize = 8; // 4 quotient κ limbs:         8 .. 12
const HW_R: usize = 12; // 4 remainder r = acc-out:  12 .. 16
const HW_CARRY: usize = 16; // 7 signed carries (offset by 2^17): 16 .. 23
const HW_ACCBIT: usize = 23; // acc bits (4·12):      23 .. 71
const HW_WBIT: usize = 71; // w bits (4·12):          71 .. 119
const HW_KBIT: usize = 119; // κ bits (4·12):        119 .. 167
const HW_RBIT: usize = 167; // r bits (4·12):        167 .. 215
const HW_CBIT: usize = 215; // carry bits (7·18):    215 .. 341
const HW_BORROW: usize = 341; // borrow bits (r<q):  341 .. 345
const HW_DBIT: usize = 345; // r<q digit bits (4·12): 345 .. 393
/// Descending ζ-power index of the coefficient processed at this row (`p−1` on the first row down to
/// `0` on the last). This is the coefficient's degree (the power of ζ it multiplies in the Horner
/// chain); join 2 keys its Receive position on `4·idx + base`, so each `w`-limb binds to the sampler
/// coefficient of the matching global index. Anchored at the last row (`idx = 0`) and forced to
/// descend by one per transition, so its value is exactly `p − 1 − row` — a verifier-checkable
/// position axis, not a free label. Consumed only by the composition-time Receive lookup, not by
/// `eval`'s arithmetic; a standalone fold proof carries it inertly.
const HW_IDX: usize = 393; // coefficient ζ-power index (descending): 393
/// Boolean flag, `1` only on the last row. Join 3 (the fold → relation boundary opening) gates its
/// Send of the fold result `E` (= the last row's `r`) by this, so exactly one copy of `E` is exposed.
/// Pinned to the last row by `when_last_row (1 − is_last) = 0` and to `0` elsewhere by `is_last·idx = 0`
/// (`idx ≥ 1` off the last row); consumed only by the composition-time Send lookup, inert to `eval`.
const HW_ISLAST: usize = 394; // last-row indicator (join 3): 394

/// Trace width of [`HornerFoldAir`].
pub const HORNER_WIDTH: usize = 395;
/// Signed-carry offset (`cc = c + 2^17 ∈ [0, 2^18)`); honest `|c| < 2^15`.
const CARRY_OFFSET: u64 = 1 << 17;
/// Signed-carry range-check width.
const HORNER_CARRY_BITS: usize = 18;

/// AIR evaluating `E = Σ_i c_i·ζ^i (mod q)` by chained Horner steps. `ζ`'s four 12-bit limbs are the
/// public values; the final row's `r` is the fold result.
#[derive(Debug, Clone, Default)]
pub struct HornerFoldAir;

impl<F> BaseAir<F> for HornerFoldAir {
    fn width(&self) -> usize {
        HORNER_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NLIMB // ζ's four 12-bit limbs
    }
}

impl<AB: AirBuilder> Air<AB> for HornerFoldAir {
    fn eval(&self, builder: &mut AB) {
        let (loc, nxt_acc, nxt_idx): (Vec<AB::Expr>, [AB::Expr; NLIMB], AB::Expr) = {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let loc: Vec<AB::Expr> = (0..HORNER_WIDTH).map(|i| local[i].into()).collect();
            let nxt_acc = array::from_fn(|i| next[HW_ACC + i].into());
            (loc, nxt_acc, next[HW_IDX].into())
        };
        let zeta: [AB::Expr; NLIMB] = array::from_fn(|j| builder.public_values()[j].into());

        let recompose = |builder: &mut AB, base: usize, nbits: usize| -> AB::Expr {
            let mut horner = AB::Expr::ZERO;
            for b in (0..nbits).rev() {
                let bit = loc[base + b].clone();
                builder.assert_bool(bit.clone());
                horner = horner.double() + bit;
            }
            horner
        };

        // --- range checks (value column == Horner of its bits) ---
        for i in 0..NLIMB {
            let a = recompose(builder, HW_ACCBIT + LIMB_BITS * i, LIMB_BITS);
            builder.assert_zero(loc[HW_ACC + i].clone() - a);
            let w = recompose(builder, HW_WBIT + LIMB_BITS * i, LIMB_BITS);
            builder.assert_zero(loc[HW_W + i].clone() - w);
            let k = recompose(builder, HW_KBIT + LIMB_BITS * i, LIMB_BITS);
            builder.assert_zero(loc[HW_K + i].clone() - k);
            let r = recompose(builder, HW_RBIT + LIMB_BITS * i, LIMB_BITS);
            builder.assert_zero(loc[HW_R + i].clone() - r);
        }
        for g in 0..7 {
            let c = recompose(builder, HW_CBIT + HORNER_CARRY_BITS * g, HORNER_CARRY_BITS);
            builder.assert_zero(loc[HW_CARRY + g].clone() - c);
        }
        for g in 0..NLIMB {
            builder.assert_bool(loc[HW_BORROW + g].clone());
            for b in 0..LIMB_BITS {
                builder.assert_bool(loc[HW_DBIT + LIMB_BITS * g + b].clone());
            }
        }

        // --- fused signed carry chain:  acc·ζ + w − κ·q − r = 0 ---
        let radix = konst::<AB>(B);
        let offset = konst::<AB>(CARRY_OFFSET);
        for g in 0..VLIMB {
            let mut l_g = AB::Expr::ZERO; // Σ_{i+j=g} acc_i·ζ_j   (ζ public)
            let mut r_g = AB::Expr::ZERO; // Σ_{i+j=g} κ_i·q_j     (q constant)
            for i in 0..NLIMB {
                if g >= i && g - i < NLIMB {
                    l_g += loc[HW_ACC + i].clone() * zeta[g - i].clone();
                    r_g += loc[HW_K + i].clone() * konst::<AB>(Q_LIMBS[g - i]);
                }
            }
            let mut net = l_g - r_g;
            if g < NLIMB {
                net = net + loc[HW_W + g].clone() - loc[HW_R + g].clone();
            }
            let c_in = if g == 0 {
                AB::Expr::ZERO
            } else {
                loc[HW_CARRY + (g - 1)].clone() - offset.clone()
            };
            let c_out = if g == 7 {
                AB::Expr::ZERO
            } else {
                loc[HW_CARRY + g].clone() - offset.clone()
            };
            builder.assert_zero(net + c_in - radix.clone() * c_out);
        }

        // --- r < q  (borrow subtraction (q−1) − r, final borrow forced 0) ---
        for g in 0..NLIMB {
            let mut d_g = AB::Expr::ZERO;
            for b in (0..LIMB_BITS).rev() {
                d_g = d_g.double() + loc[HW_DBIT + LIMB_BITS * g + b].clone();
            }
            let zc_g = konst::<AB>(QM1_LIMBS[g]);
            let borrow_in = if g == 0 {
                AB::Expr::ZERO
            } else {
                loc[HW_BORROW + (g - 1)].clone()
            };
            let borrow_out = loc[HW_BORROW + g].clone();
            builder.assert_zero(
                d_g - (zc_g - loc[HW_R + g].clone() - borrow_in + radix.clone() * borrow_out),
            );
        }
        builder.assert_zero(loc[HW_BORROW + (NLIMB - 1)].clone());

        // --- Horner chaining: next.acc = this.r ;  first.acc = 0 ---
        for i in 0..NLIMB {
            builder
                .when_transition()
                .assert_zero(nxt_acc[i].clone() - loc[HW_R + i].clone());
            builder
                .when_first_row()
                .assert_zero(loc[HW_ACC + i].clone());
        }

        // --- coefficient ζ-power index: descends by one per row, anchored at the last row (idx=0) ---
        // so `idx = p−1−row` exactly. Join 2's Receive keys its position on this, binding each row's
        // `w` to the sampler coefficient of degree `idx`. Inert to the fold arithmetic above.
        builder.when_last_row().assert_zero(loc[HW_IDX].clone());
        builder
            .when_transition()
            .assert_zero(nxt_idx - loc[HW_IDX].clone() + AB::Expr::ONE);

        // --- last-row indicator: 1 on the last row (idx=0), 0 elsewhere (idx≥1) ---
        // Join 3's Send of `E` (the last-row `r`) is gated by this so exactly one copy is exposed.
        builder.assert_bool(loc[HW_ISLAST].clone());
        builder
            .when_last_row()
            .assert_zero(AB::Expr::ONE - loc[HW_ISLAST].clone());
        builder.assert_zero(loc[HW_ISLAST].clone() * loc[HW_IDX].clone());
    }
}

/// Split a `< 2^48` value into four 12-bit limbs.
fn limbs4(x: u64) -> [u64; NLIMB] {
    array::from_fn(|i| (x >> (LIMB_BITS * i)) & LIMB_MASK)
}

/// Build one [`HornerFoldAir`] row for `acc ← (acc·ζ + w) mod q` with `κ = quot`, `r = rem`.
fn horner_row(acc: u64, w: u64, kappa: u64, r: u64, zeta: u64) -> [ConfigVal; HORNER_WIDTH] {
    let acc_l = limbs4(acc);
    let w_l = limbs4(w);
    let k_l = limbs4(kappa);
    let r_l = limbs4(r);
    let z_l = limbs4(zeta);

    let mut row = [ConfigVal::ZERO; HORNER_WIDTH];
    for i in 0..NLIMB {
        row[HW_ACC + i] = cv(acc_l[i]);
        row[HW_W + i] = cv(w_l[i]);
        row[HW_K + i] = cv(k_l[i]);
        row[HW_R + i] = cv(r_l[i]);
        for b in 0..LIMB_BITS {
            row[HW_ACCBIT + LIMB_BITS * i + b] = bit_cv((acc_l[i] >> b) & 1);
            row[HW_WBIT + LIMB_BITS * i + b] = bit_cv((w_l[i] >> b) & 1);
            row[HW_KBIT + LIMB_BITS * i + b] = bit_cv((k_l[i] >> b) & 1);
            row[HW_RBIT + LIMB_BITS * i + b] = bit_cv((r_l[i] >> b) & 1);
        }
    }

    // fused signed carry chain (recomputed exactly as the AIR verifies it).
    let mut c: i64 = 0;
    for g in 0..VLIMB {
        let (mut l_g, mut rr_g) = (0i64, 0i64);
        for i in 0..NLIMB {
            if g >= i && g - i < NLIMB {
                l_g += (acc_l[i] * z_l[g - i]) as i64;
                rr_g += (k_l[i] * Q_LIMBS[g - i]) as i64;
            }
        }
        let mut net = l_g - rr_g;
        if g < NLIMB {
            net += w_l[g] as i64 - r_l[g] as i64;
        }
        let s = net + c;
        debug_assert_eq!(s.rem_euclid(B as i64), 0, "horner fused digit must be 0");
        c = s.div_euclid(B as i64);
        if g < 7 {
            let cc = (c + CARRY_OFFSET as i64) as u64;
            row[HW_CARRY + g] = cv(cc);
            for b in 0..HORNER_CARRY_BITS {
                row[HW_CBIT + HORNER_CARRY_BITS * g + b] = bit_cv((cc >> b) & 1);
            }
        }
    }
    debug_assert_eq!(c, 0, "horner fused carry must fully vanish");

    // r < q borrow chain.
    let mut borrow = 0i64;
    for g in 0..NLIMB {
        let t = QM1_LIMBS[g] as i64 - r_l[g] as i64 - borrow;
        let (d, bo) = if t < 0 {
            (t + B as i64, 1i64)
        } else {
            (t, 0i64)
        };
        for b in 0..LIMB_BITS {
            row[HW_DBIT + LIMB_BITS * g + b] = bit_cv(((d as u64) >> b) & 1);
        }
        row[HW_BORROW + g] = bit_cv(bo as u64);
        borrow = bo;
    }
    debug_assert_eq!(borrow, 0, "r = (acc·ζ+w) mod q is always < q");

    row
}

/// Generate a [`HornerFoldAir`] trace evaluating `E = Σ_i coeffs[i]·ζ^i (mod q)`. `coeffs` are the
/// polynomial coefficients low-order first (each `< q`); `zeta < q`. Returns the trace and `E` (the
/// final row's `r`). The trace height is `coeffs.len().next_power_of_two()`; when padding is needed
/// the extra high-order coefficients are zero (leading `acc = 0` rows that do not disturb `E`).
pub fn generate_horner_trace(
    coeffs: &[u64],
    zeta: u64,
) -> Result<(RowMajorMatrix<ConfigVal>, u64), EncProofError> {
    if coeffs.is_empty() {
        return Err(EncProofError::TraceGeneration(
            "horner fold: no coefficients",
        ));
    }
    let m = coeffs.len();
    let p = m.next_power_of_two().max(2);
    // Horner order (high-order first), zero-padded at the front to a power-of-two height.
    let mut wseq = alloc::vec![0u64; p];
    for (idx, &c) in coeffs.iter().rev().enumerate() {
        wseq[p - m + idx] = c;
    }

    let q128 = u128::from(Q);
    let mut acc = 0u64;
    let mut rows: Vec<[ConfigVal; HORNER_WIDTH]> = Vec::with_capacity(p);
    for (t, &w) in wseq.iter().enumerate() {
        let prod = u128::from(acc) * u128::from(zeta) + u128::from(w);
        let kappa = (prod / q128) as u64;
        let r = (prod % q128) as u64;
        let mut row = horner_row(acc, w, kappa, r, zeta);
        // ζ-power index: descends p−1 → 0 (see [`HW_IDX`]); the coefficient in row t has degree p−1−t.
        row[HW_IDX] = cv((p - 1 - t) as u64);
        row[HW_ISLAST] = if t == p - 1 {
            ConfigVal::ONE
        } else {
            ConfigVal::ZERO
        };
        rows.push(row);
        acc = r;
    }
    let e = acc;

    let mut vals = Vec::with_capacity(p * HORNER_WIDTH);
    for row in rows {
        vals.extend_from_slice(&row);
    }
    Ok((RowMajorMatrix::new(vals, HORNER_WIDTH), e))
}

/// The four 12-bit ζ-limbs a [`HornerFoldAir`] proof binds as public values.
pub fn horner_public_values(zeta: u64) -> Vec<ConfigVal> {
    limbs4(zeta).iter().map(|&l| cv(l)).collect()
}

/// Join-2 **Receive** lookups the fold contributes (design §5, coefficient binding): four single-limb
/// `(position, w_limb)` tuples per row on `bus`, at absolute coefficient-limb position
/// `base + 4·idx + j` where `idx` is [`HW_IDX`] (this row's ζ-power / coefficient degree) and
/// `base = 4·r·N` locates ring element `r` on the component's coefficient axis (`base = 0` for a lone
/// ring element). One single-tuple lookup per limb (degree-3 constraint) rather than one 4-tuple
/// lookup. **Every row Receives** (no gate): the fold height must equal its coefficient count `N`
/// (a power of two — no front padding), so every row is a real coefficient and the `N` Receives match
/// the sampler's `N` Sends exactly. The fold's own `w`-limb range checks (`< 2^12`) and `w < q`
/// comparison make the received limbs canonical, back-propagating (via multiset equality) to pin the
/// sampler's Sent lift limbs.
pub fn horner_coeff_receive_lookups_at(bus: &str, base: u64) -> Vec<Lookup<ConfigVal>> {
    let idx = mcol(HW_IDX);
    (0..NLIMB)
        .map(|j| {
            let pos = sconst(base) + sconst(4) * idx.clone() + sconst(j as u64);
            Lookup::new(
                Kind::Global(bus.into()),
                Vec::from([Vec::from([pos, mcol(HW_W + j)])]),
                Vec::from([Direction::Receive.multiplicity(sconst(1))]),
                Vec::from([j]),
            )
        })
        .collect()
}

/// Join-3 **Send** lookups the fold contributes (design §4.1, the boundary opening): four single-limb
/// `(position, r_limb)` tuples exposing the fold RESULT `E` (the last row's remainder `r` = the fold
/// value) on `bus`, at position `base + 4·term + limb`, gated by [`HW_ISLAST`] (so exactly one copy of
/// `E` is Sent). `term` is this fold's index `j` among the relation's witness terms; `base`
/// distinguishes relation instances on the shared bus. The matching [`RelationCheckAir`] Receives it
/// into `w_term` ([`relation_w_receive_lookups_at`]). Single-tuple lookups (degree-3). This closes the
/// "expose the result" composition obligation the standalone fold cannot self-supply.
///
/// `col_base` is the first **permutation aux-column index** these four lookups occupy; a fold that also
/// carries other lookups (e.g. its join-2 coefficient *receive* on cols `0..4`, or sends to several
/// relations) passes `col_base` past those so the aux columns don't collide within the instance. A
/// lone send uses `col_base = 0`.
pub fn horner_e_send_lookups_at(
    bus: &str,
    base: u64,
    term: usize,
    col_base: usize,
) -> Vec<Lookup<ConfigVal>> {
    (0..NLIMB)
        .map(|limb| {
            Lookup::new(
                Kind::Global(bus.into()),
                Vec::from([Vec::from([
                    sconst(base + 4 * term as u64 + limb as u64),
                    mcol(HW_R + limb),
                ])]),
                Vec::from([Direction::Send.multiplicity(mcol(HW_ISLAST))]),
                Vec::from([col_base + limb]),
            )
        })
        .collect()
}

// ===========================================================================================
// encode(μ) fold with boolean-μ binding   (design §4.4, closes the R3b vacuity trap).
// ===========================================================================================
//
// The message μ ∈ {0,1}^256 is embedded in R_q by the tkem `encode_msg` as
//     encode(μ) = Σ_{i<256} ⌊q/2⌋·μ_i·X^i          (bit i → coefficient i = ⌊q/2⌋, else 0;
//                                                    coefficients 256..N are 0),
// so its evaluation at the public challenge ζ is the 256-term Horner sum
//     E_encode = encode(μ)(ζ) = Σ_{i<256} ⌊q/2⌋·μ_i·ζ^i (mod q).
// R3b (`v = ⟨t0,e⟩ + g + encode(μ)`) needs `E_encode` as one of its fold witnesses. If `encode(μ)`
// were folded as a *free* ring element the prover could set it to `v − ⟨t0,e⟩ − g` and R3b would pass
// vacuously (§4.4). [`EncodeMuFoldAir`] closes that: it reuses the [`HornerFoldAir`] arithmetic
// VERBATIM (delegated `eval`) and adds, per row, a boolean μ-bit column plus the *derivation*
// constraint
//     w_j = HALFQ_j · μ_bit        (j ∈ 0..NLIMB, HALFQ = ⌊q/2⌋ a public constant),
// so the coefficient is not free but the select `0 / ⌊q/2⌋` of a boolean μ-bit. Consequences:
//  * the folded polynomial ranges only over the 2^256 valid encodings (no free ring element);
//  * `w < q` is STRUCTURAL (HALFQ < q) — unlike the generic fold, no join-2 coefficient bound needed.
//
// **Composition obligations (same category as the fold's; internal arithmetic is the fuzzer-checked
// HornerFold — a STANDALONE proof here attests only "some binary μ′ folds to encode(μ′)(ζ) with the
// result in the last-row r", NOT which μ′ nor that r is consumed):** (1) expose the last-row
// `r = E_encode` to R3b's [`RelationCheckAir`] (boundary opening) — the LOAD-BEARING one; (2) canonical
// ζ limbs (met by the shared [`horner_public_values`] / [`encode_mu_public_values`]); (3) bind these
// μ-bits to the sponge's μ — done TRANSITIVELY through the (e,g)-pinning and the R3b fold (§4.4), NOT a
// third LogUp join; (4) SAME ζ across all fold AIRs (e/g/encode) — all must evaluate at one Fiat-Shamir
// challenge or the §4.1 polynomial identity is checked at mixed points and does not certify the relation.

/// `⌊q/2⌋ = 2^47 − 2^13 = 140737488347136`, the tkem `encode_msg` constant (message bit → coefficient
/// value). Integer floor division, matching `let half = Q / 2` in `lib-q-threshold-kem-lattice`.
pub const HALFQ: u64 = Q / 2;
/// `HALFQ` as four 12-bit limbs (verified in tests): `2^47 − 2^13 = 2^12·(2^35 − 2)` ⇒ `[0,4094,4095,2047]`.
const HALFQ_LIMBS: [u64; NLIMB] = [0, 4094, 4095, 2047];
/// Number of message bits (= tkem `MESSAGE_BITS`); the encode fold has exactly this many terms, and
/// `256` is a power of two so the [`HornerFoldAir`] trace needs no front padding.
const MSG_BITS: usize = 256;

/// Extra μ-bit column appended after the [`HornerFoldAir`] columns.
const EMW_MUBIT: usize = HORNER_WIDTH;
/// Trace width of [`EncodeMuFoldAir`] (all [`HornerFoldAir`] columns + one boolean μ-bit).
pub const ENCODE_MU_WIDTH: usize = HORNER_WIDTH + 1;

/// AIR proving `E = encode(μ)(ζ) (mod q)` for a boolean message μ: the [`HornerFoldAir`] fold with each
/// coefficient constrained to `⌊q/2⌋·μ_i` via a per-row boolean μ-bit. `ζ`'s four 12-bit limbs are the
/// public values (shared with [`horner_public_values`]); the final row's `r` is `E_encode`.
#[derive(Debug, Clone, Default)]
pub struct EncodeMuFoldAir;

impl<F> BaseAir<F> for EncodeMuFoldAir {
    fn width(&self) -> usize {
        ENCODE_MU_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NLIMB // ζ's four 12-bit limbs (same as HornerFoldAir)
    }
}

impl<AB: AirBuilder> Air<AB> for EncodeMuFoldAir {
    fn eval(&self, builder: &mut AB) {
        // (1) All HornerFold fold / range-check / chaining constraints over columns 0..HORNER_WIDTH.
        HornerFoldAir.eval(builder);

        // (2) Boolean μ-bit + coefficient derivation  w_j = HALFQ_j · μ_bit  (public-linear select).
        let (mu, w): (AB::Expr, [AB::Expr; NLIMB]) = {
            let main = builder.main();
            let local = main.current_slice();
            let mu = local[EMW_MUBIT].into();
            let w = array::from_fn(|j| local[HW_W + j].into());
            (mu, w)
        };
        builder.assert_bool(mu.clone());
        for (j, wj) in w.iter().enumerate() {
            builder.assert_zero(wj.clone() - konst::<AB>(HALFQ_LIMBS[j]) * mu.clone());
        }
    }
}

/// Generate an [`EncodeMuFoldAir`] trace proving `E = encode(μ)(ζ) (mod q)`. `mu` is the 32-byte
/// message with bit `i` = `(mu[i/8] >> (i%8)) & 1` (matching tkem `encode_msg`); `zeta < q`. Trace
/// height is exactly `MSG_BITS = 256` (a power of two — no padding). Returns the trace and `E_encode`
/// (the final row's `r`).
pub fn generate_encode_mu_trace(
    mu: &[u8; 32],
    zeta: u64,
) -> Result<(RowMajorMatrix<ConfigVal>, u64), EncProofError> {
    let q128 = u128::from(Q);
    let mut acc = 0u64;
    let mut vals = Vec::with_capacity(MSG_BITS * ENCODE_MU_WIDTH);
    // High-order first: row j processes coefficient index (MSG_BITS − 1 − j).
    for j in 0..MSG_BITS {
        let idx = MSG_BITS - 1 - j;
        let bit = (mu[idx / 8] >> (idx % 8)) & 1;
        let w = if bit == 1 { HALFQ } else { 0 };
        let prod = u128::from(acc) * u128::from(zeta) + u128::from(w);
        let kappa = (prod / q128) as u64;
        let r = (prod % q128) as u64;
        let base = horner_row(acc, w, kappa, r, zeta);
        let mut row = [ConfigVal::ZERO; ENCODE_MU_WIDTH];
        row[..HORNER_WIDTH].copy_from_slice(&base);
        // ζ-power index (= coefficient degree) for the delegated HornerFold descent constraint.
        row[HW_IDX] = cv(idx as u64);
        row[HW_ISLAST] = if j == MSG_BITS - 1 {
            ConfigVal::ONE
        } else {
            ConfigVal::ZERO
        };
        row[EMW_MUBIT] = bit_cv(u64::from(bit));
        vals.extend_from_slice(&row);
        acc = r;
    }
    Ok((RowMajorMatrix::new(vals, ENCODE_MU_WIDTH), acc))
}

/// The public values (ζ's four 12-bit limbs) an [`EncodeMuFoldAir`] proof binds — identical to
/// [`horner_public_values`] (the encode fold shares the challenge ζ).
pub fn encode_mu_public_values(zeta: u64) -> Vec<ConfigVal> {
    horner_public_values(zeta)
}

// ===========================================================================================
// Non-native Z_q linear-relation check  Σ_j a_j·w_j + c ≡ 0 (mod q)   (design §4.1, R3 relation).
// ===========================================================================================
//
// The scalar equations the fold reduces to (design §4.1) all have the shape
//   Σ_r B0_{r,k}(ζ)·E_r + F_k − p_k(ζ) − (ζ^N+1)·H_k(ζ) ≡ 0 (mod q)     [and the R3b analogue],
// i.e. a Z_q linear combination of the WITNESS fold values (`E_r, F_k, HK_k, …`) with PUBLIC
// coefficients (`B0_{r,k}(ζ)`, `ζ^N+1`, …), equal to a public constant, all mod q. [`RelationCheckAir`]
// proves the canonical form `Σ_{j<L} a_j·w_j + c ≡ 0 (mod q)`: negative terms are folded into the
// public coefficients as `q − x` (so every `a_j, c ∈ [0,q)`), which makes `LHS = Σ a_j w_j + c ≥ 0`
// and `LHS ≡ 0 (mod q) ⇔ LHS = κ·q` for a non-negative integer quotient `κ`.
//
// **Same fused signed carry chain as the fold, telescoping `LHS − κ·q = 0`.** `a_j` public ⇒ each
// product `a_j·w_j` is public-linear in `w_j` (no witness×witness). Per limb position `g ∈ 0..8`:
//   LHS_g = Σ_j Σ_{i+k=g} a_{j,i}·w_{j,k} + (c_g if g<4)      (un-carried partial-product digit)
//   RHS_g = Σ_{i+k=g} κ_i·q_k
//   net_g = LHS_g − RHS_g,  and  net_g + c_g^carry = 2^12·c_{g+1}^carry, with c_0 = c_8 = 0.
// Because `Σ_g LHS_g·2^{12g} = LHS` and `Σ_g RHS_g·2^{12g} = κ·q` EXACTLY (the digits may exceed
// 2^12; the carries absorb the excess), the telescoping forces `LHS = κ·q`, i.e. `LHS ≡ 0 (mod q)`,
// for ANY carries satisfying the per-limb equations. `κ` is 5×12-bit range-checked (`κ < 2^60`; for
// `L ≤ 15`, `κ = LHS/q < L·q < 2^52`). Signed carries are offset by `2^18`, 19-bit range-checked;
// every term stays `< 2^31 = p` (field-eq ⇔ integer-eq) for `L ≤ 15` (the whole-group partial sum is
// `≤ 4L·2^24 < p`). `w_j`'s limbs are range-checked (`< 2^12`); `w_j < q` and the tie to the real fold
// values come from the composition (join 2 / the fold's last-row opening). The relation is checked in
// EVERY row (rows are identical replicas); `a_j, c` are the public values.

const REL_WLIMB: usize = 8; // limb positions in the LHS/κ·q carry chain (LHS < 2^96·L)
const REL_KLIMB: usize = 5; // κ limbs (κ < 2^60)
const REL_CARRY_OFFSET: u64 = 1 << 18; // signed-carry offset; honest |c| < 2^18
const REL_CARRY_BITS: usize = 19; // signed-carry range-check width
const REL_MAX_TERMS: usize = 15; // completeness bound: honest carries `4L·2^12` must fit `2^18`

/// AIR proving the Z_q relation `Σ_{j<L} a_j·w_j + c ≡ 0 (mod q)` where `a_0..a_{L-1}` and `c` are the
/// public values (4 limbs each) and `w_0..w_{L-1}` are witness `Z_q` values.
#[derive(Debug, Clone)]
pub struct RelationCheckAir {
    /// Number of witness terms `L`.
    pub num_terms: usize,
}

impl RelationCheckAir {
    fn rw_w(&self) -> usize {
        0
    }
    fn rw_k(&self) -> usize {
        NLIMB * self.num_terms
    }
    fn rw_carry(&self) -> usize {
        NLIMB * self.num_terms + REL_KLIMB
    }
    fn rw_wbit(&self) -> usize {
        NLIMB * self.num_terms + REL_KLIMB + (REL_WLIMB - 1)
    }
    fn rw_kbit(&self) -> usize {
        self.rw_wbit() + LIMB_BITS * NLIMB * self.num_terms
    }
    fn rw_cbit(&self) -> usize {
        self.rw_kbit() + LIMB_BITS * REL_KLIMB
    }
    /// Boolean first-row indicator (join 3): `1` on row 0, `0` on row 1. Gates the Receive of the fold
    /// results `E_j` into `w_j` so each is bound exactly once, on a single row whose replica of the
    /// relation is then the one over the true fold outputs.
    fn rw_isfirst(&self) -> usize {
        self.rw_cbit() + REL_CARRY_BITS * (REL_WLIMB - 1)
    }
    fn trace_width(&self) -> usize {
        self.rw_isfirst() + 1
    }

    /// Join-3 **Receive** lookups (design §4.1, the boundary opening): for each witness term `j` and
    /// limb, Receive `(base + 4·j + limb, w_j_limb)` on `bus`, gated by the first-row indicator, binding
    /// each `w_j` to the fold that Sends its result `E_j` at term `j` ([`horner_e_send_lookups_at`]).
    /// `base` must match the folds' Send `base` (the relation instance's offset). `4·L` single-tuple
    /// lookups (degree-3); the bound `w_j` are exactly the fold outputs the relation constrains.
    pub fn relation_w_receive_lookups_at(&self, bus: &str, base: u64) -> Vec<Lookup<ConfigVal>> {
        let rw_w = self.rw_w();
        let is_first = mcol(self.rw_isfirst());
        let mut lookups = Vec::with_capacity(NLIMB * self.num_terms);
        let mut col = 0usize;
        for j in 0..self.num_terms {
            for limb in 0..NLIMB {
                lookups.push(Lookup::new(
                    Kind::Global(bus.into()),
                    Vec::from([Vec::from([
                        sconst(base + 4 * j as u64 + limb as u64),
                        mcol(rw_w + NLIMB * j + limb),
                    ])]),
                    Vec::from([Direction::Receive.multiplicity(is_first.clone())]),
                    Vec::from([col]),
                ));
                col += 1;
            }
        }
        lookups
    }
}

impl<F> BaseAir<F> for RelationCheckAir {
    fn width(&self) -> usize {
        self.trace_width()
    }

    fn num_public_values(&self) -> usize {
        NLIMB * (self.num_terms + 1) // a_0..a_{L-1} and c, 4 limbs each
    }
}

impl<AB: AirBuilder> Air<AB> for RelationCheckAir {
    fn eval(&self, builder: &mut AB) {
        let l = self.num_terms;
        let (rw_w, rw_k, rw_carry) = (self.rw_w(), self.rw_k(), self.rw_carry());
        let (rw_wbit, rw_kbit, rw_cbit) = (self.rw_wbit(), self.rw_kbit(), self.rw_cbit());
        let width = self.trace_width();

        let loc: Vec<AB::Expr> = {
            let main = builder.main();
            let local = main.current_slice();
            (0..width).map(|i| local[i].into()).collect()
        };
        // public coefficients: a_j limbs at 4j.., c limbs at 4L..
        let pubs: Vec<AB::Expr> = {
            let pv = builder.public_values();
            (0..NLIMB * (l + 1)).map(|i| pv[i].into()).collect()
        };
        let a = |j: usize, i: usize| pubs[NLIMB * j + i].clone();
        let c = |g: usize| pubs[NLIMB * l + g].clone();

        let recompose = |builder: &mut AB, base: usize, nbits: usize| -> AB::Expr {
            let mut horner = AB::Expr::ZERO;
            for b in (0..nbits).rev() {
                let bit = loc[base + b].clone();
                builder.assert_bool(bit.clone());
                horner = horner.double() + bit;
            }
            horner
        };

        // --- range checks ---
        for j in 0..l {
            for k in 0..NLIMB {
                let v = recompose(builder, rw_wbit + LIMB_BITS * (NLIMB * j + k), LIMB_BITS);
                builder.assert_zero(loc[rw_w + NLIMB * j + k].clone() - v);
            }
        }
        for i in 0..REL_KLIMB {
            let v = recompose(builder, rw_kbit + LIMB_BITS * i, LIMB_BITS);
            builder.assert_zero(loc[rw_k + i].clone() - v);
        }
        for g in 0..(REL_WLIMB - 1) {
            let v = recompose(builder, rw_cbit + REL_CARRY_BITS * g, REL_CARRY_BITS);
            builder.assert_zero(loc[rw_carry + g].clone() - v);
        }

        // --- fused signed carry chain:  Σ_j a_j·w_j + c − κ·q = 0 ---
        let radix = konst::<AB>(B);
        let offset = konst::<AB>(REL_CARRY_OFFSET);
        for g in 0..REL_WLIMB {
            let mut lhs_g = AB::Expr::ZERO;
            for j in 0..l {
                for i in 0..NLIMB {
                    for k in 0..NLIMB {
                        if i + k == g {
                            lhs_g += a(j, i) * loc[rw_w + NLIMB * j + k].clone();
                        }
                    }
                }
            }
            if g < NLIMB {
                lhs_g += c(g);
            }
            let mut rhs_g = AB::Expr::ZERO;
            for i in 0..REL_KLIMB {
                if g >= i && g - i < NLIMB {
                    rhs_g += loc[rw_k + i].clone() * konst::<AB>(Q_LIMBS[g - i]);
                }
            }
            let c_in = if g == 0 {
                AB::Expr::ZERO
            } else {
                loc[rw_carry + (g - 1)].clone() - offset.clone()
            };
            let c_out = if g == REL_WLIMB - 1 {
                AB::Expr::ZERO
            } else {
                loc[rw_carry + g].clone() - offset.clone()
            };
            builder.assert_zero(lhs_g - rhs_g + c_in - radix.clone() * c_out);
        }

        // --- first-row indicator (join 3): 1 on row 0, 0 on the other replica row ---
        // Gates join 3's Receive of the fold results E_j into w_j, so each is bound exactly once, on the
        // single row whose replica of the relation then holds over the true fold outputs.
        let nxt_isfirst: AB::Expr = {
            let main = builder.main();
            let next = main.next_slice();
            next[self.rw_isfirst()].into()
        };
        let is_first = loc[self.rw_isfirst()].clone();
        builder.assert_bool(is_first.clone());
        builder
            .when_first_row()
            .assert_zero(AB::Expr::ONE - is_first);
        builder.when_transition().assert_zero(nxt_isfirst);
    }
}

/// Split a `< 2^60` value into five 12-bit limbs.
fn limbs5(x: u64) -> [u64; REL_KLIMB] {
    array::from_fn(|i| (x >> (LIMB_BITS * i)) & LIMB_MASK)
}

/// Build one [`RelationCheckAir`] row for `Σ_j a[j]·w[j] + c ≡ 0 (mod q)` (all inputs `< q`).
/// Requires the relation to actually hold (`LHS` a multiple of `q`); returns `None` otherwise.
#[allow(clippy::needless_range_loop)] // indices drive column-offset arithmetic
fn relation_row(a: &[u64], w: &[u64], c: u64, width: usize) -> Option<Vec<ConfigVal>> {
    let l = a.len();
    let q128 = u128::from(Q);
    let mut lhs: u128 = u128::from(c);
    for j in 0..l {
        lhs += u128::from(a[j]) * u128::from(w[j]);
    }
    if !lhs.is_multiple_of(q128) {
        return None;
    }
    let kappa = (lhs / q128) as u64;

    let a_l: Vec<[u64; NLIMB]> = a.iter().map(|&x| limbs4(x)).collect();
    let w_l: Vec<[u64; NLIMB]> = w.iter().map(|&x| limbs4(x)).collect();
    let k_l = limbs5(kappa);
    let c_l = limbs4(c);

    // column offsets (mirror RelationCheckAir::rw_*)
    let rw_w = 0usize;
    let rw_k = NLIMB * l;
    let rw_carry = NLIMB * l + REL_KLIMB;
    let rw_wbit = NLIMB * l + REL_KLIMB + (REL_WLIMB - 1);
    let rw_kbit = rw_wbit + LIMB_BITS * NLIMB * l;
    let rw_cbit = rw_kbit + LIMB_BITS * REL_KLIMB;

    let mut row = alloc::vec![ConfigVal::ZERO; width];
    for j in 0..l {
        for k in 0..NLIMB {
            row[rw_w + NLIMB * j + k] = cv(w_l[j][k]);
            for b in 0..LIMB_BITS {
                row[rw_wbit + LIMB_BITS * (NLIMB * j + k) + b] = bit_cv((w_l[j][k] >> b) & 1);
            }
        }
    }
    for i in 0..REL_KLIMB {
        row[rw_k + i] = cv(k_l[i]);
        for b in 0..LIMB_BITS {
            row[rw_kbit + LIMB_BITS * i + b] = bit_cv((k_l[i] >> b) & 1);
        }
    }

    // fused signed carry chain (recomputed exactly as the AIR verifies it).
    let mut carry: i64 = 0;
    for g in 0..REL_WLIMB {
        let mut lhs_g: i64 = 0;
        for j in 0..l {
            for i in 0..NLIMB {
                for k in 0..NLIMB {
                    if i + k == g {
                        lhs_g += (a_l[j][i] * w_l[j][k]) as i64;
                    }
                }
            }
        }
        if g < NLIMB {
            lhs_g += c_l[g] as i64;
        }
        let mut rhs_g: i64 = 0;
        for i in 0..REL_KLIMB {
            if g >= i && g - i < NLIMB {
                rhs_g += (k_l[i] * Q_LIMBS[g - i]) as i64;
            }
        }
        let s = lhs_g - rhs_g + carry;
        debug_assert_eq!(s.rem_euclid(B as i64), 0, "relation fused digit must be 0");
        carry = s.div_euclid(B as i64);
        if g < REL_WLIMB - 1 {
            let cc = (carry + REL_CARRY_OFFSET as i64) as u64;
            row[rw_carry + g] = cv(cc);
            for b in 0..REL_CARRY_BITS {
                row[rw_cbit + REL_CARRY_BITS * g + b] = bit_cv((cc >> b) & 1);
            }
        }
    }
    debug_assert_eq!(carry, 0, "relation fused carry must fully vanish");

    Some(row)
}

/// Generate a [`RelationCheckAir`] trace proving `Σ_j a[j]·w[j] + c ≡ 0 (mod q)`. The relation is
/// replicated across a height-2 trace (each row is an identical, independently-checked instance).
/// Returns the trace and the public values (`a`'s limbs then `c`'s limbs). `a.len() == w.len()`, all
/// `< q`, and the relation must hold.
pub fn generate_relation_trace(
    a: &[u64],
    w: &[u64],
    c: u64,
) -> Result<(RowMajorMatrix<ConfigVal>, Vec<ConfigVal>), EncProofError> {
    if a.len() != w.len() || a.is_empty() {
        return Err(EncProofError::TraceGeneration("relation: bad term count"));
    }
    // Completeness bound: honest carries are `≤ 4L·2^12`, which must fit the `2^18` signed-carry
    // offset (⇒ `L ≤ 15`). Field-fit (soundness) actually holds to `L ≤ 31`, but we cap at the
    // tighter completeness limit so a valid relation always yields a provable trace.
    if a.len() > REL_MAX_TERMS {
        return Err(EncProofError::TraceGeneration(
            "relation: too many terms (L must be ≤ 15)",
        ));
    }
    let air = RelationCheckAir { num_terms: a.len() };
    let width = air.trace_width();
    let row = relation_row(a, w, c, width).ok_or(EncProofError::TraceGeneration(
        "relation does not hold mod q",
    ))?;

    // Two replica rows; the first-row indicator (join 3's Receive gate) is 1 on row 0, 0 on row 1.
    let isfirst = air.rw_isfirst();
    let mut row0 = row.clone();
    row0[isfirst] = ConfigVal::ONE;
    let mut row1 = row;
    row1[isfirst] = ConfigVal::ZERO;

    let mut vals = Vec::with_capacity(2 * width);
    vals.extend_from_slice(&row0);
    vals.extend_from_slice(&row1);

    let mut pubs: Vec<ConfigVal> = Vec::new();
    for &x in a {
        pubs.extend(limbs4(x).iter().map(|&li| cv(li)));
    }
    pubs.extend(limbs4(c).iter().map(|&li| cv(li)));

    Ok((RowMajorMatrix::new(vals, width), pubs))
}

#[cfg(test)]
mod tests {
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    use super::*;
    use crate::test_macros::assert_air_rejects;

    #[test]
    fn q_limbs_are_correct() {
        // q = 2^48 − 2^14 + 1, recomposed from its 12-bit limbs.
        let recomposed: u64 = Q_LIMBS
            .iter()
            .enumerate()
            .map(|(i, &l)| l << (12 * i))
            .sum();
        assert_eq!(recomposed, Q);
        assert_eq!(Q, (1u64 << 48) - (1u64 << 14) + 1);
        assert_eq!(Q_LIMBS, [1, 4092, 4095, 4095]);
    }

    #[test]
    fn modreduce_proves_and_verifies() {
        // A spread of values: small, near q, multiples, and large (< 2^96, exercising limbs 6–7).
        let q = u128::from(Q);
        let values = [
            0u128,
            1,
            q - 1,
            q,
            q + 1,
            2 * q + 12345,
            1234567890123456789,
            u128::from(u64::MAX),
            (1u128 << 90) + 7,       // exercises high limbs (κ ≈ 2^42)
            q * ((1u128 << 47) - 1), // κ = 2^47 − 1, near the κ < 2^48 ceiling
        ];
        let trace = generate_modreduce_trace(&values).expect("trace generation");
        let proof = StarkProver::new(default_config())
            .prove(&ModReduceAir, trace, &[])
            .expect("prove modreduce");
        StarkVerifier::new(default_config())
            .verify(&ModReduceAir, &proof, &[])
            .expect("verify modreduce");
    }

    #[test]
    fn modreduce_rejects_tampered_remainder() {
        let values = [2 * u128::from(Q) + 987654];
        let mut trace = generate_modreduce_trace(&values).expect("trace generation");
        // Bump r's low limb by 1 without fixing the carry chain: breaks κ·q + r = V.
        trace.values[ZW_R] += ConfigVal::ONE;
        assert_air_rejects!(&ModReduceAir, trace, &[], "a tampered remainder must not verify");
    }

    #[test]
    fn modreduce_rejects_noncanonical_remainder() {
        // Forge r' = r + q, κ' = κ − 1 (so κ'·q + r' = V still holds) and re-decompose every affected
        // column *including the borrow chain*, so the reduction identity stays satisfied and the ONLY
        // violated constraint is the final `borrow_4 = 0` (i.e. r < q). For r' = r + q to fit in the
        // 4 limbs (< 2^48) the remainder must be small: r < 2^48 − q = 16383, so pick r = 100.
        let v = 5u128 * u128::from(Q) + 100;
        let kappa = (v / u128::from(Q)) as u64;
        let r = (v % u128::from(Q)) as u64;
        assert!(kappa >= 1 && r < (1u64 << 48) - Q);
        let kappa2 = kappa - 1;
        let r2 = r + Q; // ∈ [q, 2^48) ⇒ ≥ q ⇒ must be rejected by the r < q check

        let mut trace = generate_modreduce_trace(&[v]).expect("trace generation");
        let klimbs: [u64; NLIMB] = array::from_fn(|i| (kappa2 >> (LIMB_BITS * i)) & LIMB_MASK);
        let rlimbs: [u64; NLIMB] = array::from_fn(|i| (r2 >> (LIMB_BITS * i)) & LIMB_MASK);
        for i in 0..NLIMB {
            trace.values[ZW_K + i] = cv(klimbs[i]);
            trace.values[ZW_R + i] = cv(rlimbs[i]);
            for b in 0..LIMB_BITS {
                trace.values[ZW_KBIT + LIMB_BITS * i + b] = bit_cv((klimbs[i] >> b) & 1);
                trace.values[ZW_RBIT + LIMB_BITS * i + b] = bit_cv((rlimbs[i] >> b) & 1);
            }
        }
        // recompute the carry chain for (κ', r') so the reduction identity κ'·q + r' = V holds.
        let vlimbs: [u64; VLIMB] =
            array::from_fn(|g| ((v >> (LIMB_BITS * g)) & u128::from(LIMB_MASK)) as u64);
        let mut carry = 0u64;
        for g in 0..VLIMB {
            let mut p_g = 0u64;
            for i in 0..NLIMB {
                if g >= i && g - i < NLIMB {
                    p_g += klimbs[i] * Q_LIMBS[g - i];
                }
            }
            let s_g = if g < NLIMB { p_g + rlimbs[g] } else { p_g };
            let acc = s_g + carry;
            debug_assert_eq!(acc & LIMB_MASK, vlimbs[g]);
            carry = acc >> LIMB_BITS;
            if g < 7 {
                trace.values[ZW_CARRY + g] = cv(carry);
                for b in 0..CARRY_BITS {
                    trace.values[ZW_CBIT + CARRY_BITS * g + b] = bit_cv((carry >> b) & 1);
                }
            }
        }
        // recompute the borrow chain for r' too (it now underflows ⇒ borrow_4 = 1), so the d_g
        // relations stay consistent and the sole failing constraint is `borrow_4 = 0`.
        let mut borrow = 0i64;
        for g in 0..NLIMB {
            let t = QM1_LIMBS[g] as i64 - rlimbs[g] as i64 - borrow;
            let (d, bo) = if t < 0 {
                (t + B as i64, 1i64)
            } else {
                (t, 0i64)
            };
            for b in 0..LIMB_BITS {
                trace.values[ZW_DBIT + LIMB_BITS * g + b] = bit_cv(((d as u64) >> b) & 1);
            }
            trace.values[ZW_BORROW + g] = bit_cv(bo as u64);
            borrow = bo;
        }
        assert_eq!(borrow, 1, "forged r' ≥ q must underflow the borrow chain");

        assert_air_rejects!(
            &ModReduceAir,
            trace,
            &[],
            "a non-canonical remainder (r ≥ q) must not verify"
        );
    }

    /// Reference polynomial evaluation `Σ_i c_i·ζ^i (mod q)` (Horner, high-order first).
    fn eval_reference(coeffs: &[u64], zeta: u64) -> u64 {
        let q128 = u128::from(Q);
        let mut e = 0u128;
        for &c in coeffs.iter().rev() {
            e = (e * u128::from(zeta) + u128::from(c)) % q128;
        }
        e as u64
    }

    #[test]
    fn horner_fold_matches_reference_and_proves() {
        let coeffs: [u64; 16] = [
            1,
            2,
            100,
            Q - 1,
            12345,
            0,
            7,
            Q - 12345,
            999999,
            3,
            Q - 2,
            42,
            1 << 20,
            1 << 40,
            123,
            Q - 7,
        ];
        let zeta = 987654321012345u64 % Q;
        let expected = eval_reference(&coeffs, zeta);

        let (trace, e) = generate_horner_trace(&coeffs, zeta).expect("trace generation");
        assert_eq!(
            e, expected,
            "trace fold value must equal the reference evaluation"
        );

        let pubs = horner_public_values(zeta);
        let proof = StarkProver::new(default_config())
            .prove(&HornerFoldAir, trace, &pubs)
            .expect("prove horner fold");
        StarkVerifier::new(default_config())
            .verify(&HornerFoldAir, &proof, &pubs)
            .expect("verify horner fold");
    }

    #[test]
    fn horner_fold_rejects_tampered_result() {
        let coeffs: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let zeta = 424242424242u64 % Q;
        let (mut trace, _e) = generate_horner_trace(&coeffs, zeta).expect("trace generation");

        // Corrupt the last row's remainder (the fold result) low limb: breaks acc·ζ + w = κ·q + r
        // on that row (and the chaining to nowhere, but the fused identity alone already fails).
        let p = trace.values.len() / HORNER_WIDTH;
        let last = (p - 1) * HORNER_WIDTH;
        trace.values[last + HW_R] += ConfigVal::ONE;

        let pubs = horner_public_values(zeta);
        assert_air_rejects!(&HornerFoldAir, trace, &pubs, "a tampered fold result must not verify");
    }

    #[test]
    fn relation_check_proves_and_verifies() {
        // Build a genuine relation  Σ_j a_j·w_j + c ≡ 0 (mod q)  with L = 8 (R3a slot shape:
        // MU=6 e-folds + F_k + one quotient term). Choose a_j, w_j < q, then set c = (−Σ) mod q.
        let a: [u64; 8] = [123456789, Q - 5, 2, 999999999999, 42, Q - 100000, 7, 1];
        let w: [u64; 8] = [11, 22222222, Q - 1, 5, 314159265358, 8, Q - 42, 123123123];
        let q128 = u128::from(Q);
        let s: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let c = ((q128 - (s % q128)) % q128) as u64; // Σ a_j w_j + c ≡ 0 (mod q)

        let air = RelationCheckAir { num_terms: 8 };
        let (trace, pubs) = generate_relation_trace(&a, &w, c).expect("relation holds");
        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &pubs)
            .expect("prove relation");
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pubs)
            .expect("verify relation");
    }

    #[test]
    fn relation_check_rejects_tampered_witness() {
        let a: [u64; 4] = [7, Q - 3, 1000, 55];
        let w: [u64; 4] = [123, 456, Q - 789, 1];
        let q128 = u128::from(Q);
        let s: u128 = a
            .iter()
            .zip(w.iter())
            .map(|(&ai, &wi)| u128::from(ai) * u128::from(wi))
            .sum();
        let c = ((q128 - (s % q128)) % q128) as u64;

        let air = RelationCheckAir { num_terms: 4 };
        let (mut trace, pubs) = generate_relation_trace(&a, &w, c).expect("relation holds");
        // Corrupt w_0's low limb: the relation no longer holds mod q.
        trace.values[0] += ConfigVal::ONE;

        assert_air_rejects!(&air, trace, &pubs, "a tampered witness must not verify");
    }

    #[test]
    fn relation_check_rejects_false_relation() {
        // A relation that does NOT hold mod q must be unprovable at trace-gen (LHS not a multiple).
        let a: [u64; 3] = [2, 3, 5];
        let w: [u64; 3] = [7, 11, 13];
        // c chosen so Σ a_j w_j + c is NOT ≡ 0 (mod q).
        let c = 1u64;
        assert!(generate_relation_trace(&a, &w, c).is_err());
    }

    #[test]
    fn halfq_limbs_are_correct() {
        // ⌊q/2⌋ = 2^47 − 2^13, recomposed from its 12-bit limbs.
        assert_eq!(HALFQ, 140737488347136);
        assert_eq!(HALFQ, (1u64 << 47) - (1u64 << 13));
        assert_eq!(HALFQ, Q / 2);
        assert_eq!(limbs4(HALFQ), HALFQ_LIMBS);
        let recomposed: u64 = HALFQ_LIMBS
            .iter()
            .enumerate()
            .map(|(i, &l)| l << (12 * i))
            .sum();
        assert_eq!(recomposed, HALFQ);
    }

    #[test]
    fn encode_mu_fold_matches_reference_and_proves() {
        // The tkem KAT message μ = (0, 1, 2, …, 31).
        let mut mu = [0u8; 32];
        for (i, b) in mu.iter_mut().enumerate() {
            *b = i as u8;
        }
        let zeta = 987654321012345u64 % Q;

        let (trace, e) = generate_encode_mu_trace(&mu, zeta).expect("trace generation");

        // Reference: E = Σ_{i<256} ⌊q/2⌋·μ_i·ζ^i (mod q), high-order-first Horner.
        let q128 = u128::from(Q);
        let z = u128::from(zeta);
        let mut e_ref = 0u128;
        for i in (0..MSG_BITS).rev() {
            let bit = (mu[i / 8] >> (i % 8)) & 1;
            let c = if bit == 1 { u128::from(HALFQ) } else { 0 };
            e_ref = (e_ref * z + c) % q128;
        }
        assert_eq!(
            u128::from(e),
            e_ref,
            "fold result must equal encode(μ)(ζ) mod q"
        );

        let pubs = encode_mu_public_values(zeta);
        let proof = StarkProver::new(default_config())
            .prove(&EncodeMuFoldAir, trace, &pubs)
            .expect("prove encode-mu fold");
        StarkVerifier::new(default_config())
            .verify(&EncodeMuFoldAir, &proof, &pubs)
            .expect("verify encode-mu fold");
    }

    #[test]
    fn encode_mu_fold_rejects_tampered_mu_bit() {
        let mut mu = [0u8; 32];
        for (i, b) in mu.iter_mut().enumerate() {
            *b = i as u8;
        }
        let zeta = 424242424242u64 % Q;
        let (mut trace, _e) = generate_encode_mu_trace(&mu, zeta).expect("trace generation");
        let pubs = encode_mu_public_values(zeta);

        // Row 0 processes coefficient index 255 (bit = μ[31]>>7 = 0), so its μ-bit is 0. Flip it to 1
        // WITHOUT touching the coefficient limbs: the derivation constraint w_1 = HALFQ_1·μ_bit is now
        // violated (w_1 stayed 0 but HALFQ_1·1 = 4094 ≠ 0).
        trace.values[EMW_MUBIT] += ConfigVal::ONE;

        assert_air_rejects!(&EncodeMuFoldAir, trace, &pubs, "a tampered μ-bit must not verify");
    }
}
