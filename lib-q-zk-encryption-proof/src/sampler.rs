//! Ternary rejection-sampling AIR (design §5, R2 for the `e` component).
//!
//! Proves that a stream of ternary coefficients `∈ {-1, 0, +1}` is the **exact** 2-bit rejection
//! sampling of a byte stream, matching the constant-time `lib-q-threshold-kem-lattice::kem` ternary
//! sampler byte-for-byte: read one byte, `two = byte & 0b11`; if `two < 3` the byte is *acceptable*
//! (coefficient `two − 1`), else it is rejected and the next byte is read.
//!
//! Arithmetic is native `Mersenne31` — ternary coefficients are `{-1, 0, 1}` (the `mod q` lift is
//! deferred to `LatticeCheckAir`). Three properties are load-bearing and are enforced by *explicit*
//! constraints, not by the (later) LogUp join to the sponge:
//! - **Forced accept/reject:** on every active row `accepted = active · (1 − bit0·bit1)`, so a
//!   prover cannot skip a valid byte or accept a rejected one.
//! - **Emission quota (fixed-budget constant-time sampler):** the KEM draws a *fixed* byte budget and
//!   compacts the first `num_coeffs` accepts, draining the rest. The trace mirrors this: `still`
//!   (monotone 1→0) marks the emitting prefix, `emit = accepted · still` fires on exactly the first
//!   `num_coeffs` accepts (pinned by `Σ emit = num_coeffs`), and only `emit` feeds the coefficient
//!   bus. Every active row — emitted *or drained* — still Receives its consumed byte, so the sponge
//!   join stays balanced over the whole fixed budget.
//! - **Ordered consumption:** `stream_pos` is a monotone counter (`+active` per row); LogUp multiset
//!   equality alone does not order the stream (design §5.1).
//!
//! Row = one byte-read attempt. Padding rows (`active = 0`) freeze the counters so the trace height
//! is a power of two; the emitted coefficient count is pinned to the public value `num_coeffs`.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::array;

use lib_q_plonky_lookup::{
    Direction,
    Kind,
    Lookup,
    LookupAir,
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
    COEFF_E_BUS,
    XOF_STREAM_BUS,
    mcol,
    sconst,
};
use crate::zq::{
    Q,
    Q_LIMBS,
    QM1_LIMBS,
};

// Column layout.
const C_ACTIVE: usize = 0; // 1 = real attempt, 0 = padding
const C_STREAM_POS: usize = 1; // absolute byte-stream position consumed at this row
const C_COEFF_IDX: usize = 2; // running count of coefficients emitted so far
const C_BYTE: usize = 3; // the consumed byte
const C_BIT0: usize = 4; // bits 0..8 occupy columns 4..12
const C_ACCEPTED: usize = 12; // 1 = this attempt's byte is acceptable (two < 3)
const C_COEFF_VAL: usize = 13; // the accepted signed coefficient (-1/0/1), else 0
const C_STILL: usize = 14; // 1 while fewer than num_coeffs coeffs have been emitted (monotone 1→0)
const C_EMIT: usize = 15; // 1 = this row emits a coefficient (= accepted · still); first N accepts only

/// Trace width of [`TernarySamplerAir`].
pub const SAMPLER_WIDTH: usize = 16;

/// AIR proving `num_coeffs` ternary coefficients are the exact 2-bit rejection sampling of a byte
/// stream, consumed in order. `num_coeffs` is bound as the single public value.
#[derive(Debug, Clone)]
pub struct TernarySamplerAir {
    /// Number of coefficients the trace must emit (e.g. `MU · N` for the full `e`).
    pub num_coeffs: usize,
}

impl<F> BaseAir<F> for TernarySamplerAir {
    fn width(&self) -> usize {
        SAMPLER_WIDTH
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for TernarySamplerAir {
    fn eval(&self, builder: &mut AB) {
        #[allow(clippy::type_complexity)]
        let (
            active,
            byte,
            bits,
            accepted,
            coeff_val,
            still,
            emit,
            stream_pos,
            coeff_idx,
            n_active,
            n_still,
            n_stream_pos,
            n_coeff_idx,
        ): (
            AB::Expr,
            AB::Expr,
            [AB::Expr; 8],
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
        ) = {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            (
                local[C_ACTIVE].into(),
                local[C_BYTE].into(),
                array::from_fn(|i| local[C_BIT0 + i].into()),
                local[C_ACCEPTED].into(),
                local[C_COEFF_VAL].into(),
                local[C_STILL].into(),
                local[C_EMIT].into(),
                local[C_STREAM_POS].into(),
                local[C_COEFF_IDX].into(),
                next[C_ACTIVE].into(),
                next[C_STILL].into(),
                next[C_STREAM_POS].into(),
                next[C_COEFF_IDX].into(),
            )
        };
        let pub_num_coeffs: AB::Expr = {
            let pubs = builder.public_values();
            pubs[0].into()
        };

        // --- per-row structural constraints ---
        builder.assert_bool(active.clone());
        for b in &bits {
            builder.assert_bool(b.clone());
        }

        // byte = Σ bit_i · 2^i  (Horner, MSB first — no field-constant construction needed).
        let recomposed = (0..8)
            .rev()
            .fold(AB::Expr::ZERO, |acc, i| acc.double() + bits[i].clone());
        builder.assert_zero(byte.clone() - recomposed);
        // padding rows carry no byte.
        builder.assert_zero((AB::Expr::ONE - active.clone()) * byte);

        // accepted = active · (1 − bit0·bit1). `bit0·bit1 = 1` iff `two == 3` (the rejection case),
        // so a valid byte is always accepted and a rejected byte never is. NOTE: with the fixed-budget
        // constant-time sampler, MORE than `num_coeffs` bytes may be acceptable; `accepted` marks every
        // such byte, but only the first `num_coeffs` are *emitted* (see `emit` below). Padding rows
        // (`active = 0`) have `accepted = 0`.
        builder.assert_bool(accepted.clone());
        let two_is_three = bits[0].clone() * bits[1].clone();
        builder.assert_zero(accepted.clone() - active.clone() * (AB::Expr::ONE - two_is_three));

        // coeff_val = (two − 1) when accepted, else 0.  two − 1 = bit0 + 2·bit1 − 1.
        let two_minus_one = bits[0].clone() + bits[1].clone().double() - AB::Expr::ONE;
        builder.assert_zero(accepted.clone() * (coeff_val.clone() - two_minus_one));
        builder.assert_zero((AB::Expr::ONE - accepted.clone()) * coeff_val);

        // --- emission quota (fixed-budget constant-time sampler) ---
        // `still` (monotone 1→0) marks the prefix of rows before `num_coeffs` coefficients have been
        // emitted; `emit = accepted · still` fires on exactly the first `num_coeffs` acceptable rows.
        // The coefficient bus is fed by `emit` (below), so the drained tail (acceptable rows past the
        // quota) contributes no coefficient, while every active row still Receives its consumed byte —
        // keeping the sponge join balanced over the full fixed budget.
        builder.assert_bool(still.clone());
        builder.assert_bool(emit.clone());
        builder.assert_zero(emit.clone() - accepted.clone() * still.clone());

        // --- boundary + transition constraints ---
        builder.when_first_row().assert_zero(stream_pos.clone());
        builder.when_first_row().assert_zero(coeff_idx.clone());

        // active is non-increasing (real rows first, then padding).
        builder
            .when_transition()
            .assert_zero(n_active * (AB::Expr::ONE - active.clone()));
        // `still` is non-increasing (emitting prefix, then drained/padding tail): it may go 1→0 but
        // never 0→1, so `emit` marks a genuine prefix of the accepts.
        builder
            .when_transition()
            .assert_zero(n_still * (AB::Expr::ONE - still.clone()));
        // stream_pos advances by one byte per active row (rejections and drained accepts consume a byte too).
        builder
            .when_transition()
            .assert_zero(n_stream_pos - stream_pos - active);
        // coeff_idx advances only when a coefficient is *emitted*.
        builder
            .when_transition()
            .assert_zero(n_coeff_idx - coeff_idx.clone() - emit.clone());

        // exactly `num_coeffs` coefficients were emitted over the whole trace. Combined with the
        // monotone `still` and `emit = accepted · still`, this forces `emit` onto the first
        // `num_coeffs` accepts (no earlier, no later).
        builder
            .when_last_row()
            .assert_zero(coeff_idx + emit - pub_num_coeffs);
    }
}

/// Lift a small non-negative integer into the STARK value field.
fn cv(x: u32) -> ConfigVal {
    ConfigVal::from_basis_coefficients_fn(|i| {
        if i == 0 {
            Mersenne31::new(x)
        } else {
            Mersenne31::ZERO
        }
    })
}

/// Generate a [`TernarySamplerAir`] trace over a **fixed budget**: process *every* byte of `bytes`
/// under the 2-bit rejection rule (matching the constant-time KEM sampler, which draws a fixed budget
/// and compacts the first `num_coeffs` accepts), emitting the first `num_coeffs` accepted coefficients
/// and *draining* any further accepts, then pad to a power-of-two height. The caller sizes `bytes` to
/// the KEM's fixed budget (`kem::E_TERNARY_ATTEMPTS` for the full `e`). Fails if fewer than
/// `num_coeffs` bytes are acceptable in the whole budget (probability `< 2^-128` for a real stream).
pub fn generate_ternary_trace(
    bytes: &[u8],
    num_coeffs: usize,
) -> Result<RowMajorMatrix<ConfigVal>, EncProofError> {
    let mut rows: Vec<[ConfigVal; SAMPLER_WIDTH]> = Vec::new();
    let mut stream_pos: u32 = 0;
    let mut coeff_idx: u32 = 0; // count of *emitted* coefficients
    let mut still = true; // still within the first-`num_coeffs`-accepts prefix

    for &byte in bytes {
        let two = byte & 0b11;
        let accepted = two < 3;
        let emit = accepted && still;

        let mut row = [ConfigVal::ZERO; SAMPLER_WIDTH];
        row[C_ACTIVE] = ConfigVal::ONE;
        row[C_STREAM_POS] = cv(stream_pos);
        row[C_COEFF_IDX] = cv(coeff_idx);
        row[C_BYTE] = cv(u32::from(byte));
        for (b, slot) in row.iter_mut().enumerate().skip(C_BIT0).take(8) {
            let bit = (byte >> (b - C_BIT0)) & 1;
            *slot = if bit == 1 {
                ConfigVal::ONE
            } else {
                ConfigVal::ZERO
            };
        }
        if accepted {
            row[C_ACCEPTED] = ConfigVal::ONE;
            row[C_COEFF_VAL] = cv(u32::from(two)) - ConfigVal::ONE; // two − 1 ∈ {-1,0,1}
        }
        if still {
            row[C_STILL] = ConfigVal::ONE;
        }
        if emit {
            row[C_EMIT] = ConfigVal::ONE;
        }
        rows.push(row);

        stream_pos += 1;
        if emit {
            coeff_idx += 1;
            if coeff_idx as usize == num_coeffs {
                still = false;
            }
        }
    }
    if (coeff_idx as usize) < num_coeffs {
        return Err(EncProofError::TraceGeneration(
            "ternary sampler: fewer than num_coeffs acceptable bytes in the budget",
        ));
    }

    // Pad to a power-of-two height (≥ 2 for transition constraints); freeze the counters.
    // Padding rows have active = still = emit = 0.
    let height = rows.len().next_power_of_two().max(2);
    while rows.len() < height {
        let mut row = [ConfigVal::ZERO; SAMPLER_WIDTH];
        row[C_STREAM_POS] = cv(stream_pos);
        row[C_COEFF_IDX] = cv(coeff_idx);
        rows.push(row);
    }

    let mut values = Vec::with_capacity(height * SAMPLER_WIDTH);
    for row in rows {
        values.extend_from_slice(&row);
    }
    Ok(RowMajorMatrix::new(values, SAMPLER_WIDTH))
}

/// The single public value a [`TernarySamplerAir`] proof binds: the emitted coefficient count.
pub fn ternary_public_values(num_coeffs: usize) -> Vec<ConfigVal> {
    Vec::from([cv(num_coeffs as u32)])
}

// ===========================================================================================
// Bounded rejection-sampling AIR (design §5.2 / §5.2a, R2 for the `f, g` components).
// ===========================================================================================
//
// Proves that a stream of *centered* bounded coefficients `∈ [-BOUND, BOUND]` is the **exact**
// 64-bit rejection sampling of a byte stream, matching
// `lib-q-threshold-kem-lattice::kem::xof_bounded_poly` byte-for-byte:
//
//   read 8 bytes → `r = u64::from_le_bytes(b)`; if `r < zone` emit `(r mod span) − BOUND`,
//   else reject and read the next 8 bytes.  `span = 2·BOUND + 1`,
//   `zone = u64::MAX − (u64::MAX mod span)` (the unbiased acceptance region).
//
// Unlike the ternary sampler this needs **64-bit non-native arithmetic** (`r`, `zone` exceed the
// `~2^31` Mersenne31 field). The two soundness-critical facts and how they are pinned:
//
//   * **Canonical remainder.** `coeff = (r mod span) − BOUND` must use the *canonical* remainder
//     `R = r mod span ∈ [0, span)`. `Q·span + R = r` alone does NOT pin `R` (any `R' = R + k·span`
//     works with `Q' = Q − k`); the coefficient would then be free. So `R` is bit-decomposed as a
//     21-bit low limb plus a top bit with `top·R_lo = 0`, forcing `R ∈ [0, 2^21] = [0, span − 1]`
//     — exactly the canonical range (`span = 2^21 + 1`).
//   * **Ordered / non-skippable acceptance.** `accepted = active·(1 − borrow_8)` where `borrow_8`
//     is the final borrow of the byte-wise subtraction `Z − r` with `Z = zone − 1`. This proves
//     `accepted ⇔ r ≤ Z ⇔ r < zone`, so a prover can neither claim a reject on a valid draw (to
//     skip a coefficient and misalign the byte stream) nor claim an accept on a rejected draw.
//
// **Field-fit invariant (why field-eq ⇔ integer-eq here).** The division identity is verified by a
// byte-position carry chain `acc_k = carry_k + Q_k·span (+ R at k=0) = r_k + 256·carry_{k+1}`,
// carrying a *wide* carry (< 2^22) rather than sub-decomposing each `Q_k·span < 2^30`. Every
// `acc_k < 2^22 + 2^30 + 2^21 < 2^31 < p` and every RHS `< 256 + 2^30 < 2^31 < p`, so the field
// equation is the integer equation. `Q_k` (byte), the carries (22-bit) and `R` are all
// bit-range-checked, so the per-byte identities compose to the exact integer identity `Q·span+R=r`
// with `Q, R ≥ 0`, `R < span`, `carry_8 = 0` (⇒ `r < 2^64`), which is unique Euclidean division.
//
// **Range of `r`'s bytes** (`r_k ∈ [0,256)`) is supplied by LogUp *join 1* to the sponge (design
// §5.1), exactly as the ternary sampler's byte provenance is — it is not re-checked locally.

/// Symmetric bound `B` on the uniform coefficients (`ENC_ERROR_BOUND = 2^20` in the KEM).
const BOUND: u64 = 1 << 20;
/// Rejection-sampling span `2·B + 1 = 2^21 + 1`.
const SPAN: u64 = 2 * BOUND + 1;
/// Unbiased acceptance region: `r` is accepted iff `r < ZONE`.
const ZONE: u64 = u64::MAX - (u64::MAX % SPAN);
/// `r < ZONE ⇔ r ≤ Z`; the borrow chain compares against `Z`.
const Z: u64 = ZONE - 1;
/// Little-endian bytes of `Z`, the per-position comparison constants.
const Z_BYTES: [u8; 8] = Z.to_le_bytes();

// Column layout (width [`BOUNDED_WIDTH`]).
const W_ACTIVE: usize = 0; // 1 = real 8-byte attempt, 0 = padding
const W_ACCEPTED: usize = 1; // 1 = this attempt's draw is acceptable (r < zone)
const W_STREAM: usize = 2; // absolute byte-stream position consumed at this row
const W_CIDX: usize = 3; // running count of coefficients *emitted* so far
const W_COEFF: usize = 4; // emitted centered coefficient (R − BOUND), else 0
const W_R: usize = 5; // remainder R = r mod span
const W_RBYTE: usize = 6; // r's 8 little-endian bytes: W_RBYTE .. W_RBYTE+8
const W_Q: usize = 14; // quotient Q's 6 byte-limbs: W_Q .. W_Q+6
const W_QBIT: usize = 20; // Q limb bits: bit j of limb k at W_QBIT + 8*k + j   (6*8 = 48)
const W_RBIT: usize = 68; // R bits: low 21 at W_RBIT+0..21, top bit at W_RBIT+21   (22)
const W_CARRY: usize = 90; // carries c_{k+1} (k=0..6): W_CARRY .. W_CARRY+7   (7)
const W_CARRYBIT: usize = 97; // carry bits: bit j of carry k at W_CARRYBIT + 22*k + j   (7*22 = 154)
const W_BORROW: usize = 251; // borrow-out bits bo_{k+1} (k=0..7): W_BORROW .. W_BORROW+8   (8)
const W_DBIT: usize = 259; // subtraction digit bits: bit j of d_k at W_DBIT + 8*k + j   (8*8 = 64)
// --- join-2 mod-q lift derivation (design §5, coefficient binding) ---
const W_LIFT: usize = 323; // mod-q lift limbs (4·12-bit): W_LIFT .. W_LIFT+4   (4)
const W_LIFTBIT: usize = 327; // lift limb bits: bit j of limb k at W_LIFTBIT + 12*k + j   (4*12 = 48)
const W_NEG: usize = 375; // neg = [R < BOUND] (1 iff the centered coeff is negative)   (1)
const W_LCARRY: usize = 376; // lift-chain signed carries c_1..c_3 (offset by 2^15): W_LCARRY .. +3   (3)
const W_LCARRYBIT: usize = 379; // lift-chain carry bits: bit j of carry k at W_LCARRYBIT + 16*k + j   (3*16 = 48)
// --- emission quota (fixed-budget constant-time sampler), see the ternary sampler for the rationale ---
const W_STILL: usize = 427; // 1 while fewer than num_coeffs coeffs emitted (monotone 1→0)   (1)
const W_EMIT: usize = 428; // 1 = this row emits a coefficient (= accepted · still)   (1)

/// Trace width of [`BoundedSamplerAir`].
pub const BOUNDED_WIDTH: usize = 429;
/// Lift-chain signed-carry range-check width (honest `|c| < 2`, offset-encoded; loose bound keeps every
/// carry-chain term `< 2^27 < p`).
const LCARRY_BITS: usize = 16;
/// Lift-chain signed-carry offset (`cc = c + 2^15 ∈ [0, 2^16)`).
const LCARRY_OFFSET: u64 = 1 << 15;
/// 12-bit limbs of `BOUND = 2^20`: `[0, 256, 0, 0]` (verified in tests). Only limbs 0..4 of `lift`,
/// `R`, `BOUND`, `neg·Q` are populated, so the `lift + BOUND = R + neg·Q` net-difference carry chain
/// runs over the 4 digit positions 0..3 with the top carry (out of position 3) forced to 0.
const BOUND_LIMBS: [u64; 4] = [0, 256, 0, 0];

/// Build the field element for a `u64` constant `< p` by Horner evaluation of its bits (avoids
/// relying on a field-constant constructor; only `ZERO`/`ONE`/`double`/`+` are used).
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

/// AIR proving `num_coeffs` bounded coefficients are the exact 64-bit rejection sampling of a byte
/// stream, consumed in order (8 bytes per attempt). `num_coeffs` is bound as the single public value.
#[derive(Debug, Clone)]
pub struct BoundedSamplerAir {
    /// Number of coefficients the trace must emit (e.g. `N` per `f`/`g` ring element).
    pub num_coeffs: usize,
}

impl<F> BaseAir<F> for BoundedSamplerAir {
    fn width(&self) -> usize {
        BOUNDED_WIDTH
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB: AirBuilder> Air<AB> for BoundedSamplerAir {
    fn eval(&self, builder: &mut AB) {
        // Read all current-row cells into owned `AB::Expr` (releases the `&self` borrow from
        // `builder.main()` before the `&mut builder` assertions), plus the three next-row counters.
        #[allow(clippy::type_complexity)]
        let (loc, nxt_active, nxt_still, nxt_stream, nxt_cidx): (
            Vec<AB::Expr>,
            AB::Expr,
            AB::Expr,
            AB::Expr,
            AB::Expr,
        ) = {
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let loc: Vec<AB::Expr> = (0..BOUNDED_WIDTH).map(|i| local[i].into()).collect();
            (
                loc,
                next[W_ACTIVE].into(),
                next[W_STILL].into(),
                next[W_STREAM].into(),
                next[W_CIDX].into(),
            )
        };
        let pub_num: AB::Expr = builder.public_values()[0].into();

        let active = loc[W_ACTIVE].clone();
        let accepted = loc[W_ACCEPTED].clone();
        let still = loc[W_STILL].clone();
        let emit = loc[W_EMIT].clone();
        builder.assert_bool(active.clone());
        builder.assert_bool(accepted.clone());
        // Emission quota (fixed-budget constant-time sampler): `emit = accepted · still`, `still`
        // monotone 1→0 (enforced on transition below). The coefficient bus is fed by `emit` (first
        // `num_coeffs` accepts); every active row still Receives its 8 bytes, so the drained tail
        // keeps the sponge join balanced. See the ternary sampler for the full rationale.
        builder.assert_bool(still.clone());
        builder.assert_bool(emit.clone());
        builder.assert_zero(emit.clone() - accepted.clone() * still.clone());

        // --- range checks via bit decomposition (values are the prover's; nothing else pins them) ---
        // Q limbs: value = Σ bit_i·2^i over 8 boolean bits (⇒ Q_k ∈ [0,256)).
        for k in 0..6 {
            let mut horner = AB::Expr::ZERO;
            for j in (0..8).rev() {
                let bit = loc[W_QBIT + 8 * k + j].clone();
                builder.assert_bool(bit.clone());
                horner = horner.double() + bit;
            }
            builder.assert_zero(loc[W_Q + k].clone() - horner);
        }
        // Carries: value = Σ bit_i·2^i over 22 boolean bits (⇒ carry ∈ [0, 2^22); honest ≤ ~2^21).
        for k in 0..7 {
            let mut horner = AB::Expr::ZERO;
            for j in (0..22).rev() {
                let bit = loc[W_CARRYBIT + 22 * k + j].clone();
                builder.assert_bool(bit.clone());
                horner = horner.double() + bit;
            }
            builder.assert_zero(loc[W_CARRY + k].clone() - horner);
        }
        // Remainder R = R_lo + top·2^21 with R_lo ∈ [0,2^21) and top·R_lo = 0 ⇒ R ∈ [0, 2^21] =
        // [0, span). This tight bound is what makes R the *canonical* remainder (see module note).
        let mut r_lo = AB::Expr::ZERO;
        for j in (0..21).rev() {
            let bit = loc[W_RBIT + j].clone();
            builder.assert_bool(bit.clone());
            r_lo = r_lo.double() + bit;
        }
        let top = loc[W_RBIT + 21].clone();
        builder.assert_bool(top.clone());
        let two_pow_21 = konst::<AB>(1 << 21);
        builder.assert_zero(loc[W_R].clone() - (r_lo.clone() + top.clone() * two_pow_21));
        builder.assert_zero(top * r_lo);
        // Borrow bits and subtraction-digit bits are boolean.
        for k in 0..8 {
            builder.assert_bool(loc[W_BORROW + k].clone());
            for j in 0..8 {
                builder.assert_bool(loc[W_DBIT + 8 * k + j].clone());
            }
        }

        // --- division identity  Q·span + R = r  (byte-position carry chain) ---
        let span = konst::<AB>(SPAN);
        let two56 = konst::<AB>(256);
        for k in 0..8 {
            let carry_in = if k == 0 {
                AB::Expr::ZERO
            } else {
                loc[W_CARRY + (k - 1)].clone()
            };
            let q_term = if k < 6 {
                loc[W_Q + k].clone() * span.clone()
            } else {
                AB::Expr::ZERO
            };
            let r_add = if k == 0 {
                loc[W_R].clone()
            } else {
                AB::Expr::ZERO
            };
            let acc = carry_in + q_term + r_add;
            // carry_8 (out of the top byte) is fixed to 0 ⇒ Q·span + R = r < 2^64.
            let carry_out = if k < 7 {
                loc[W_CARRY + k].clone()
            } else {
                AB::Expr::ZERO
            };
            builder.assert_zero(acc - (loc[W_RBYTE + k].clone() + two56.clone() * carry_out));
        }

        // --- acceptance comparison  r ≤ Z  (byte-wise borrow subtraction Z − r), gated by `active` ---
        for k in 0..8 {
            let mut d_k = AB::Expr::ZERO;
            for j in (0..8).rev() {
                d_k = d_k.double() + loc[W_DBIT + 8 * k + j].clone();
            }
            let zk = konst::<AB>(u64::from(Z_BYTES[k]));
            let borrow_in = if k == 0 {
                AB::Expr::ZERO
            } else {
                loc[W_BORROW + (k - 1)].clone()
            };
            let borrow_out = loc[W_BORROW + k].clone();
            // d_k = Z_k − r_k − borrow_in + 256·borrow_out, with d_k ∈ [0,256), borrow ∈ {0,1}.
            let rel =
                d_k - (zk - loc[W_RBYTE + k].clone() - borrow_in + two56.clone() * borrow_out);
            builder.assert_zero(active.clone() * rel);
        }
        // accepted = active·(1 − bo_8): the final borrow is 1 iff r > Z (reject), 0 iff r ≤ Z (accept).
        let bo8 = loc[W_BORROW + 7].clone();
        builder.assert_zero(accepted.clone() - active.clone() * (AB::Expr::ONE - bo8));

        // --- emitted coefficient ---
        let bound = konst::<AB>(BOUND);
        builder.assert_zero(accepted.clone() * (loc[W_COEFF].clone() - (loc[W_R].clone() - bound)));
        builder.assert_zero((AB::Expr::ONE - accepted.clone()) * loc[W_COEFF].clone());

        // --- join-2 mod-q lift derivation:  lift + BOUND = R + neg·Q  (gated by `accepted`) ---
        // Join 2's Send side needs the coefficient's canonical mod-q lift `lift = (R − BOUND) mod Q ∈
        // [0, Q)`, which equals `R − BOUND + neg·Q` with `neg = [R < BOUND]`. We pin it by the integer
        // identity `lift + BOUND = R + neg·Q`: a fused signed base-2^12 net-difference carry chain
        // (same technique as the Horner fold), with `lift`'s four limbs range-checked `< 2^12` (so
        // `lift ≥ 0`). `neg` is a boolean; the two spurious `(neg, lift)` branches are excluded by
        // `lift ≥ 0` (kills `neg = 0` when `R < BOUND`, whose `lift` would be negative) and by
        // **`lift < Q`** — a composition obligation supplied by the fold's own `w < Q` check,
        // back-propagated through join 2's multiset equality. (A standalone bounded proof does NOT
        // enforce `lift < Q`; the composed sampler+fold proof does. See module note + `zq::HornerFoldAir`.)
        let neg = loc[W_NEG].clone();
        builder.assert_bool(neg.clone());
        // lift limbs: value == Horner of its 12 boolean bits (⇒ each limb ∈ [0, 2^12), lift ∈ [0, 2^48)).
        for k in 0..4 {
            let mut horner = AB::Expr::ZERO;
            for j in (0..12).rev() {
                let bit = loc[W_LIFTBIT + 12 * k + j].clone();
                builder.assert_bool(bit.clone());
                horner = horner.double() + bit;
            }
            builder.assert_zero(loc[W_LIFT + k].clone() - horner);
        }
        // lift-chain carries: value == Horner of its 16 boolean bits (offset-encoded signed carry).
        for k in 0..3 {
            let mut horner = AB::Expr::ZERO;
            for j in (0..LCARRY_BITS).rev() {
                let bit = loc[W_LCARRYBIT + LCARRY_BITS * k + j].clone();
                builder.assert_bool(bit.clone());
                horner = horner.double() + bit;
            }
            builder.assert_zero(loc[W_LCARRY + k].clone() - horner);
        }
        // R's two 12-bit limbs recomposed from its existing bit columns (R ≤ 2^21 ⇒ only limbs 0, 1).
        // R_lo0 = Σ_{b<12} bit_b·2^b ;  R_lo1 = Σ_{b=12}^{20} bit_b·2^{b−12} + top·2^9  (top = bit 21).
        let mut r_limb0 = AB::Expr::ZERO;
        for b in (0..12).rev() {
            r_limb0 = r_limb0.double() + loc[W_RBIT + b].clone();
        }
        let mut r_limb1 = loc[W_RBIT + 21].clone(); // top bit (2^21) contributes 2^9 to limb 1
        for b in (12..21).rev() {
            r_limb1 = r_limb1.double() + loc[W_RBIT + b].clone();
        }
        // fused signed net-difference carry chain over the 4 digit positions 0..3 (top carry forced 0).
        let radix = konst::<AB>(1 << 12);
        let loff = konst::<AB>(LCARRY_OFFSET);
        for g in 0..4 {
            // LHS digit g = lift_limb_g + BOUND_g ;  RHS digit g = R_limb_g + neg·Q_g  (all limbs < 2^12).
            let lhs_g = loc[W_LIFT + g].clone() + konst::<AB>(BOUND_LIMBS[g]);
            let r_limb_g = match g {
                0 => r_limb0.clone(),
                1 => r_limb1.clone(),
                _ => AB::Expr::ZERO,
            };
            let rhs_g = r_limb_g + neg.clone() * konst::<AB>(Q_LIMBS[g]);
            let c_in = if g == 0 {
                AB::Expr::ZERO
            } else {
                loc[W_LCARRY + (g - 1)].clone() - loff.clone()
            };
            let c_out = if g == 3 {
                AB::Expr::ZERO
            } else {
                loc[W_LCARRY + g].clone() - loff.clone()
            };
            builder.assert_zero(accepted.clone() * (lhs_g - rhs_g + c_in - radix.clone() * c_out));
        }

        // --- boundary + transition constraints (mirror the ternary sampler; 8 bytes / attempt) ---
        builder.when_first_row().assert_zero(loc[W_STREAM].clone());
        builder.when_first_row().assert_zero(loc[W_CIDX].clone());
        // active is non-increasing (real rows first, then padding).
        builder
            .when_transition()
            .assert_zero(nxt_active * (AB::Expr::ONE - active.clone()));
        // `still` is non-increasing (emitting prefix, then drained/padding tail).
        builder
            .when_transition()
            .assert_zero(nxt_still * (AB::Expr::ONE - still.clone()));
        // stream_pos advances by 8 bytes per active attempt (accept, reject and drain all consume 8).
        let eight = konst::<AB>(8);
        builder
            .when_transition()
            .assert_zero(nxt_stream - loc[W_STREAM].clone() - eight * active);
        // coeff_idx advances only when a coefficient is *emitted*.
        builder
            .when_transition()
            .assert_zero(nxt_cidx - loc[W_CIDX].clone() - emit.clone());
        // exactly `num_coeffs` coefficients *emitted* over the whole trace (forces `emit` onto the
        // first `num_coeffs` accepts, as in the ternary sampler).
        builder
            .when_last_row()
            .assert_zero(loc[W_CIDX].clone() + emit - pub_num);
    }
}

/// Generate a [`BoundedSamplerAir`] trace over a **fixed budget**: process *every* 8-byte draw in
/// `bytes` under the 64-bit rejection rule (matching the constant-time KEM sampler), emitting the
/// first `num_coeffs` accepted coefficients and *draining* any further accepts, then pad to a
/// power-of-two height. The caller sizes `bytes` to the KEM's fixed budget
/// (`kem::bounded_attempts(n) · 8` for a flat `n`-coefficient draw). Fails if fewer than `num_coeffs` draws are acceptable
/// in the whole budget (probability `< 2^-128` for a real stream).
pub fn generate_bounded_trace(
    bytes: &[u8],
    num_coeffs: usize,
) -> Result<RowMajorMatrix<ConfigVal>, EncProofError> {
    let mut rows: Vec<[ConfigVal; BOUNDED_WIDTH]> = Vec::new();
    let mut stream_pos: u32 = 0;
    let mut coeff_idx: u32 = 0; // count of *emitted* coefficients
    let mut still = true; // still within the first-`num_coeffs`-accepts prefix

    let attempts = bytes.len() / 8;
    for a in 0..attempts {
        let i = a * 8;
        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&bytes[i..i + 8]);
        let r = u64::from_le_bytes(b8);
        let accepted = r < ZONE;
        let emit = accepted && still;
        let q = r / SPAN;
        let rem = r % SPAN;

        let mut row = [ConfigVal::ZERO; BOUNDED_WIDTH];
        row[W_ACTIVE] = ConfigVal::ONE;
        row[W_ACCEPTED] = if accepted {
            ConfigVal::ONE
        } else {
            ConfigVal::ZERO
        };
        row[W_STILL] = if still { ConfigVal::ONE } else { ConfigVal::ZERO };
        row[W_EMIT] = if emit { ConfigVal::ONE } else { ConfigVal::ZERO };
        row[W_STREAM] = cv(stream_pos);
        row[W_CIDX] = cv(coeff_idx);
        row[W_R] = cv(rem as u32);
        row[W_COEFF] = if accepted {
            cv(rem as u32) - cv(BOUND as u32)
        } else {
            ConfigVal::ZERO
        };

        // r bytes.
        for (k, byte) in b8.iter().enumerate() {
            row[W_RBYTE + k] = cv(u32::from(*byte));
        }

        // quotient limbs + bits.
        let qbytes: [u64; 6] = array::from_fn(|k| (q >> (8 * k)) & 0xFF);
        for k in 0..6 {
            row[W_Q + k] = cv(qbytes[k] as u32);
            for j in 0..8 {
                row[W_QBIT + 8 * k + j] = bit_cv((qbytes[k] >> j) & 1);
            }
        }

        // remainder bits: 21 low + top.
        for j in 0..21 {
            row[W_RBIT + j] = bit_cv((rem >> j) & 1);
        }
        row[W_RBIT + 21] = bit_cv((rem >> 21) & 1);

        // carry chain (recomputed exactly as the AIR verifies it).
        let mut carry = 0u64;
        for k in 0..8 {
            let qk = if k < 6 { qbytes[k] } else { 0 };
            let r_add = if k == 0 { rem } else { 0 };
            let acc = carry + qk * SPAN + r_add;
            debug_assert_eq!(
                acc & 0xFF,
                u64::from(b8[k]),
                "bounded carry chain byte mismatch"
            );
            carry = acc >> 8;
            if k < 7 {
                row[W_CARRY + k] = cv(carry as u32);
                for j in 0..22 {
                    row[W_CARRYBIT + 22 * k + j] = bit_cv((carry >> j) & 1);
                }
            }
        }
        debug_assert_eq!(carry, 0, "bounded carry chain must fully vanish");

        // borrow subtraction  Z − r  (little-endian), digit + borrow bits.
        let mut borrow = 0i64;
        for k in 0..8 {
            let t = i64::from(Z_BYTES[k]) - i64::from(b8[k]) - borrow;
            let (d, bo) = if t < 0 { (t + 256, 1i64) } else { (t, 0i64) };
            for j in 0..8 {
                row[W_DBIT + 8 * k + j] = bit_cv(((d as u64) >> j) & 1);
            }
            row[W_BORROW + k] = bit_cv(bo as u64);
            borrow = bo;
        }
        debug_assert_eq!(borrow == 0, accepted, "borrow-chain accept mismatch");

        // join-2 mod-q lift of the emitted coefficient (accepted rows only; others Send nothing).
        if accepted {
            let neg = u64::from(rem < BOUND); // 1 ⇔ R < BOUND ⇔ centered coeff negative
            // lift = (R − BOUND) mod Q = R − BOUND + neg·Q ∈ [0, Q).
            let lift = (rem as i64 - BOUND as i64).rem_euclid(Q as i64) as u64;
            let lift_limbs: [u64; 4] = array::from_fn(|k| (lift >> (12 * k)) & 0xFFF);
            for k in 0..4 {
                row[W_LIFT + k] = cv(lift_limbs[k] as u32);
                for j in 0..12 {
                    row[W_LIFTBIT + 12 * k + j] = bit_cv((lift_limbs[k] >> j) & 1);
                }
            }
            row[W_NEG] = bit_cv(neg);
            // net-difference carry chain  lift + BOUND − R − neg·Q = 0 (recomputed as the AIR checks).
            let r_limbs = [rem & 0xFFF, (rem >> 12) & 0xFFF, 0u64, 0u64];
            let mut lcarry: i64 = 0;
            for g in 0..4 {
                let lhs = lift_limbs[g] as i64 + BOUND_LIMBS[g] as i64;
                let rhs = r_limbs[g] as i64 + neg as i64 * Q_LIMBS[g] as i64;
                let net = lhs - rhs + lcarry;
                debug_assert_eq!(
                    net.rem_euclid(4096),
                    0,
                    "bounded lift-chain digit must be 0"
                );
                lcarry = net.div_euclid(4096);
                if g < 3 {
                    let cc = (lcarry + LCARRY_OFFSET as i64) as u64;
                    row[W_LCARRY + g] = cv(cc as u32);
                    for j in 0..LCARRY_BITS {
                        row[W_LCARRYBIT + LCARRY_BITS * g + j] = bit_cv((cc >> j) & 1);
                    }
                }
            }
            debug_assert_eq!(lcarry, 0, "bounded lift-chain carry must fully vanish");
        }

        rows.push(row);
        stream_pos += 8;
        if emit {
            coeff_idx += 1;
            if coeff_idx as usize == num_coeffs {
                still = false;
            }
        }
    }
    if (coeff_idx as usize) < num_coeffs {
        return Err(EncProofError::TraceGeneration(
            "bounded sampler: fewer than num_coeffs acceptable draws in the budget",
        ));
    }

    // Pad to a power-of-two height (≥ 2 for transition constraints); freeze the counters.
    // Padding rows have active = still = emit = 0.
    let height = rows.len().next_power_of_two().max(2);
    while rows.len() < height {
        let mut row = [ConfigVal::ZERO; BOUNDED_WIDTH];
        row[W_STREAM] = cv(stream_pos);
        row[W_CIDX] = cv(coeff_idx);
        rows.push(row);
    }

    let mut values = Vec::with_capacity(height * BOUNDED_WIDTH);
    for row in rows {
        values.extend_from_slice(&row);
    }
    Ok(RowMajorMatrix::new(values, BOUNDED_WIDTH))
}

/// Lift a single bit (`0`/`1`) into the STARK value field.
fn bit_cv(b: u64) -> ConfigVal {
    if b == 1 {
        ConfigVal::ONE
    } else {
        ConfigVal::ZERO
    }
}

/// The single public value a [`BoundedSamplerAir`] proof binds: the emitted coefficient count.
pub fn bounded_public_values(num_coeffs: usize) -> Vec<ConfigVal> {
    Vec::from([cv(num_coeffs as u32)])
}

// ===========================================================================================
// LogUp squeeze join (join 1) — the samplers' Receive side (design §5.1, see `crate::logup_join`).
// ===========================================================================================
//
// Each sampler consumes the XOF byte stream and Receives its `(stream_pos, byte)` tuples on the shared
// [`XOF_STREAM_BUS`], gated by the row's `active` flag (padding rows Receive nothing). Positional: the
// tuple carries the absolute byte position, so a byte at the wrong position cannot cross-match. These
// balance against the byte-stream source's Send side (`crate::logup_join::xof_stream_send_lookup`).
//
// NOTE (composition obligation): `stream_pos` here is the sampler's LOCAL position (from 0). The full
// pipeline draws `e`, then each `f`, then `g` from ONE XOF, so each instance's tuples must be shifted
// by the byte offset where its sub-draw begins to share one absolute axis — added at composition time.

/// The ternary sampler's Receive lookup at **absolute XOF offset 0** — see
/// [`ternary_receive_lookup_at`]. Use the `_at` form for any sampler whose sub-draw does not start
/// at the beginning of the XOF stream.
pub fn ternary_receive_lookup() -> Lookup<ConfigVal> {
    ternary_receive_lookup_at(0)
}

/// The ternary sampler's Receive lookup shifted to **absolute XOF byte offset** `offset`: one
/// `(offset + stream_pos, byte)` tuple per row, multiplicity `active`, on [`XOF_STREAM_BUS`]. One
/// byte consumed per active row. `stream_pos` is the sampler's LOCAL counter (from 0); the offset
/// places its consumed bytes on the single absolute axis shared by the sponge's byte-Send and every
/// other sampler drawn from the same XOF (design §5.1: `e` at 0, then each `f`, then `g`).
pub fn ternary_receive_lookup_at(offset: u64) -> Lookup<ConfigVal> {
    Lookup::new(
        Kind::Global(XOF_STREAM_BUS.into()),
        Vec::from([Vec::from([
            mcol(C_STREAM_POS) + sconst(offset),
            mcol(C_BYTE),
        ])]),
        Vec::from([Direction::Receive.multiplicity(mcol(C_ACTIVE))]),
        Vec::from([0]),
    )
}

/// Join-2 **Send** lookups the ternary sampler contributes (design §5, coefficient binding): on every
/// **accepted** row, Send the mod-q lift of the emitted coefficient (`∈ {−1, 0, +1}`) as four 12-bit
/// limbs on [`COEFF_E_BUS`], at position `base + 4·coeff_idx + j`. `base` locates this ring element on
/// `e`'s coefficient axis (`4·r·N` for `e_r`; `0` for a lone element); `coeff_idx` ([`C_COEFF_IDX`]) is
/// the emitted coefficient's global index. The lift limbs are pure expressions in the two low byte
/// bits — no new trace columns:
/// * `sel_neg = (1−bit0)(1−bit1)` (`two = 0` ⇒ coeff `−1` ⇒ limbs = `q−1`'s limbs [`QM1_LIMBS`]);
/// * `sel_one = (1−bit0)·bit1`   (`two = 2` ⇒ coeff `+1` ⇒ limb₀ = 1);
/// * coeff `0` (`two = 1`) ⇒ all-zero limbs.
///
/// Gated by [`C_EMIT`] (the first `num_coeffs` accepts only), so rejected, drained and padding rows
/// Send nothing. The four limbs Receive into the
/// matching [`crate::zq::HornerFoldAir`] fold's `w` limbs ([`crate::zq::horner_coeff_receive_lookups_at`]);
/// the fold's canonicity + `w < q` checks make the binding sound (the lift is `−1 ↦ q−1`, `0 ↦ 0`,
/// `+1 ↦ 1`, each `< q`). One single-tuple lookup per limb (degree-3 constraint) to keep the quotient
/// domain small, mirroring the sponge limb Sends.
pub fn ternary_coeff_send_lookups_at(base: u64, col_base: usize) -> Vec<Lookup<ConfigVal>> {
    let b0 = mcol(C_BIT0);
    let b1 = mcol(C_BIT0 + 1);
    let sel_neg = (sconst(1) - b0.clone()) * (sconst(1) - b1.clone());
    let sel_one = (sconst(1) - b0) * b1;
    let pos_base = sconst(base) + sconst(4) * mcol(C_COEFF_IDX);
    (0..4)
        .map(|j| {
            // lift limb j = sel_neg·QM1_LIMBS[j]  (+ sel_one at j = 0, since QM1_LIMBS[0] = 0).
            let mut limb = sel_neg.clone() * sconst(QM1_LIMBS[j]);
            if j == 0 {
                limb += sel_one.clone();
            }
            Lookup::new(
                Kind::Global(COEFF_E_BUS.into()),
                Vec::from([Vec::from([pos_base.clone() + sconst(j as u64), limb])]),
                Vec::from([Direction::Send.multiplicity(mcol(C_EMIT))]),
                Vec::from([col_base + j]),
            )
        })
        .collect()
}

/// The bounded sampler's Receive lookups at **absolute XOF offset 0** — see
/// [`bounded_receive_lookup_at`].
pub fn bounded_receive_lookup() -> Vec<Lookup<ConfigVal>> {
    bounded_receive_lookup_at(0)
}

/// The bounded sampler's Receive lookups shifted to **absolute XOF byte offset** `offset`: eight
/// **single-tuple** lookups, one per consumed byte `k = 0..8`, each Receiving
/// `(offset + stream_pos + k, r_byte_k)` with multiplicity `active` on [`XOF_STREAM_BUS`]. Eight bytes
/// are consumed per active row. **Single-tuple (degree-3) — NOT one 8-tuple lookup:** an 8-tuple has an
/// 8-fold product denominator ⇒ a degree-~9 LogUp constraint whose quotient domain overflows the
/// standard FRI blowup (it would force an ~8× blowup on the whole batch); splitting into eight
/// degree-3 lookups keeps the batch at blowup 2, mirroring the sponge-limb / join-2 / join-3 Sends. See
/// [`ternary_receive_lookup_at`] for the shared-absolute-axis rationale.
pub fn bounded_receive_lookup_at(offset: u64) -> Vec<Lookup<ConfigVal>> {
    let active = mcol(W_ACTIVE);
    (0..8)
        .map(|k| {
            Lookup::new(
                Kind::Global(XOF_STREAM_BUS.into()),
                Vec::from([Vec::from([
                    mcol(W_STREAM) + sconst(offset + k as u64),
                    mcol(W_RBYTE + k),
                ])]),
                Vec::from([Direction::Receive.multiplicity(active.clone())]),
                Vec::from([k]),
            )
        })
        .collect()
}

/// Join-2 **Send** lookups the bounded sampler contributes (design §5, coefficient binding): on every
/// **accepted** row, Send the emitted coefficient's mod-q lift (`= (R − BOUND) mod Q`) as its four
/// witnessed 12-bit [`W_LIFT`] limbs on `bus`, at position `base + 4·coeff_idx + j`. `bus` is the
/// component's coefficient bus ([`COEFF_F_BUS`](crate::logup_join::COEFF_F_BUS) for `f`,
/// [`COEFF_G_BUS`](crate::logup_join::COEFF_G_BUS) for `g`); `base` locates this ring element on that
/// axis (`4·k·N` for `f_k`; `0` for a lone `g`); `coeff_idx` ([`W_CIDX`]) is the coefficient's global
/// index. Gated by [`W_EMIT`] (the first `num_coeffs` accepts only). The lift value and `neg` are pinned by the in-AIR
/// `lift + BOUND = R + neg·Q` chain; the `lift < Q` bound (hence the correct `neg`) is the matching
/// [`crate::zq::HornerFoldAir`] fold's `w < Q`, back-propagated through the multiset equality. Four
/// single-tuple lookups (degree-3 each), mirroring the ternary and sponge-limb Sends.
pub fn bounded_coeff_send_lookups_at(bus: &str, base: u64) -> Vec<Lookup<ConfigVal>> {
    bounded_coeff_send_lookups_col(bus, base, 0)
}

/// As [`bounded_coeff_send_lookups_at`], but placing the four Send lookups' aux columns at
/// `col_base..col_base + 4` instead of `0..4`. Needed when the bounded sampler ALSO carries its eight
/// byte-Receive lookups (join 1) on aux columns `0..8` in the same instance: the coeff-Send must then
/// use `col_base = 8` to avoid an aux-column collision (the composition of join 1 + join 2 on one
/// bounded sampler — the `f`/`g` analogue of the ternary sampler's `col_base = 1`).
pub fn bounded_coeff_send_lookups_col(
    bus: &str,
    base: u64,
    col_base: usize,
) -> Vec<Lookup<ConfigVal>> {
    let pos_base = sconst(base) + sconst(4) * mcol(W_CIDX);
    (0..4)
        .map(|j| {
            Lookup::new(
                Kind::Global(bus.into()),
                Vec::from([Vec::from([
                    pos_base.clone() + sconst(j as u64),
                    mcol(W_LIFT + j),
                ])]),
                Vec::from([Direction::Send.multiplicity(mcol(W_EMIT))]),
                Vec::from([col_base + j]),
            )
        })
        .collect()
}

impl LookupAir<ConfigVal> for TernarySamplerAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        Vec::from([0])
    }

    fn get_lookups(&mut self) -> Vec<Lookup<ConfigVal>> {
        Vec::from([ternary_receive_lookup()])
    }
}

impl LookupAir<ConfigVal> for BoundedSamplerAir {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        (0..8).collect()
    }

    fn get_lookups(&mut self) -> Vec<Lookup<ConfigVal>> {
        bounded_receive_lookup()
    }
}

#[cfg(test)]
mod tests {
    use lib_q_sha3::{
        ExtendableOutput,
        Update,
        XofReader,
    };
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    use super::*;
    use crate::test_macros::assert_air_rejects;

    fn xof_bytes(seed: &[u8], n: usize) -> Vec<u8> {
        let mut h = lib_q_sha3::Shake256::default();
        h.update(seed);
        let mut rd = h.finalize_xof();
        let mut out = vec![0u8; n];
        rd.read(&mut out);
        out
    }

    /// Reference ternary sampler (the signed values `xof_ternary_poly` emits before `rem_euclid`).
    fn ternary_reference(bytes: &[u8], num: usize) -> Vec<i8> {
        let mut out = Vec::new();
        let mut i = 0;
        while out.len() < num {
            let two = bytes[i] & 0b11;
            i += 1;
            if two < 3 {
                out.push(two as i8 - 1);
            }
        }
        out
    }

    fn extract(trace: &RowMajorMatrix<ConfigVal>, num: usize) -> Vec<i8> {
        let height = trace.values.len() / SAMPLER_WIDTH;
        let mut out = Vec::new();
        for r in 0..height {
            let base = r * SAMPLER_WIDTH;
            if trace.values[base + C_ACTIVE] == ConfigVal::ONE &&
                trace.values[base + C_ACCEPTED] == ConfigVal::ONE
            {
                let v = trace.values[base + C_COEFF_VAL];
                let s = if v == ConfigVal::ZERO {
                    0
                } else if v == ConfigVal::ONE {
                    1
                } else {
                    -1
                };
                out.push(s);
            }
        }
        out.truncate(num);
        out
    }

    #[test]
    fn ternary_sampler_matches_reference_and_proves() {
        let bytes = xof_bytes(b"lib-q-zk-encryption-proof/ternary-sampler", 4096);
        let num = 1024usize; // one full ring element's worth of coefficients
        let air = TernarySamplerAir { num_coeffs: num };
        let trace = generate_ternary_trace(&bytes, num).expect("trace generation");

        assert_eq!(
            extract(&trace, num),
            ternary_reference(&bytes, num),
            "AIR trace coefficients must equal the reference sampler"
        );

        let pubs = ternary_public_values(num);
        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &pubs)
            .expect("prove ternary sampler");
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pubs)
            .expect("verify ternary sampler");
    }

    #[test]
    fn ternary_sampler_rejects_tampered_coefficient() {
        let bytes = xof_bytes(b"lib-q-zk-encryption-proof/ternary-tamper", 256);
        let num = 32usize;
        let air = TernarySamplerAir { num_coeffs: num };
        let mut trace = generate_ternary_trace(&bytes, num).expect("trace generation");

        // Corrupt the first emitted coefficient to a different (still valid-looking) ternary value;
        // this violates `accepted · (coeff_val − (two−1)) = 0`.
        let height = trace.values.len() / SAMPLER_WIDTH;
        for r in 0..height {
            let base = r * SAMPLER_WIDTH;
            if trace.values[base + C_ACCEPTED] == ConfigVal::ONE {
                let cur = trace.values[base + C_COEFF_VAL];
                trace.values[base + C_COEFF_VAL] = if cur == ConfigVal::ZERO {
                    ConfigVal::ONE
                } else {
                    ConfigVal::ZERO
                };
                break;
            }
        }

        let pubs = ternary_public_values(num);
        assert_air_rejects!(&air, trace, &pubs, "a tampered coefficient must not verify");
    }

    /// Reference bounded sampler (the centered values `xof_bounded_poly` emits before `rem_euclid`).
    fn bounded_reference(bytes: &[u8], num: usize) -> Vec<i64> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while out.len() < num {
            let mut b8 = [0u8; 8];
            b8.copy_from_slice(&bytes[i..i + 8]);
            i += 8;
            let r = u64::from_le_bytes(b8);
            if r < ZONE {
                out.push((r % SPAN) as i64 - BOUND as i64);
            }
        }
        out
    }

    /// The centered coefficient a bounded trace row emits, as a field element.
    fn bounded_expected_field(coeff: i64) -> ConfigVal {
        if coeff >= 0 {
            cv(coeff as u32)
        } else {
            ConfigVal::ZERO - cv((-coeff) as u32)
        }
    }

    fn extract_bounded(trace: &RowMajorMatrix<ConfigVal>, num: usize) -> Vec<ConfigVal> {
        let height = trace.values.len() / BOUNDED_WIDTH;
        let mut out = Vec::new();
        for r in 0..height {
            let base = r * BOUNDED_WIDTH;
            if trace.values[base + W_ACTIVE] == ConfigVal::ONE &&
                trace.values[base + W_ACCEPTED] == ConfigVal::ONE
            {
                out.push(trace.values[base + W_COEFF]);
            }
        }
        out.truncate(num);
        out
    }

    #[test]
    fn bounded_sampler_matches_reference_and_proves() {
        // 8 bytes/coeff; rejects are ~2^-43 so a small slack over 8·num is ample.
        let num = 256usize;
        let bytes = xof_bytes(b"lib-q-zk-encryption-proof/bounded-sampler", num * 8 + 512);
        let air = BoundedSamplerAir { num_coeffs: num };
        let trace = generate_bounded_trace(&bytes, num).expect("trace generation");

        let expected: Vec<ConfigVal> = bounded_reference(&bytes, num)
            .into_iter()
            .map(bounded_expected_field)
            .collect();
        assert_eq!(
            extract_bounded(&trace, num),
            expected,
            "AIR trace coefficients must equal the reference bounded sampler"
        );

        let pubs = bounded_public_values(num);
        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &pubs)
            .expect("prove bounded sampler");
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pubs)
            .expect("verify bounded sampler");
    }

    #[test]
    fn bounded_sampler_rejects_tampered_coefficient() {
        let num = 64usize;
        let bytes = xof_bytes(b"lib-q-zk-encryption-proof/bounded-tamper", num * 8 + 512);
        let air = BoundedSamplerAir { num_coeffs: num };
        let mut trace = generate_bounded_trace(&bytes, num).expect("trace generation");

        // Shift the first emitted coefficient by +1 without touching R: this breaks
        // `accepted · (coeff − (R − BOUND)) = 0`.
        let height = trace.values.len() / BOUNDED_WIDTH;
        for r in 0..height {
            let base = r * BOUNDED_WIDTH;
            if trace.values[base + W_ACCEPTED] == ConfigVal::ONE {
                trace.values[base + W_COEFF] += ConfigVal::ONE;
                break;
            }
        }

        let pubs = bounded_public_values(num);
        assert_air_rejects!(&air, trace, &pubs, "a tampered coefficient must not verify");
    }

    #[test]
    fn bounded_sampler_rejects_noncanonical_remainder() {
        // Forge R' = R + span (still satisfies Q'·span + R' = r with Q' = Q − 1) to try to shift
        // the coefficient by +span. The top-bit / `top·R_lo = 0` range check must forbid R' ≥ span.
        let num = 8usize;
        let bytes = xof_bytes(b"lib-q-zk-encryption-proof/bounded-noncanon", num * 8 + 512);
        let air = BoundedSamplerAir { num_coeffs: num };
        let mut trace = generate_bounded_trace(&bytes, num).expect("trace generation");

        // Directly overwrite an accepted row's R to R + SPAN and re-decompose its bits so the
        // internal `R = R_lo + top·2^21` link still holds; only `top·R_lo = 0` (R < span) is
        // violated. Choose a row whose forged value stays `< 2^22` so it is fully representable in
        // the 21-low-plus-top-bit layout (else a *different* constraint would fire, still rejecting
        // but for the wrong reason).
        let height = trace.values.len() / BOUNDED_WIDTH;
        let mut forged_one = false;
        for r in 0..height {
            let base = r * BOUNDED_WIDTH;
            if trace.values[base + W_ACCEPTED] != ConfigVal::ONE {
                continue;
            }
            // recover R from the low/top bits currently present
            let mut rem = 0u64;
            for j in 0..21 {
                if trace.values[base + W_RBIT + j] == ConfigVal::ONE {
                    rem |= 1 << j;
                }
            }
            if trace.values[base + W_RBIT + 21] == ConfigVal::ONE {
                rem |= 1 << 21;
            }
            let forged = rem + SPAN; // ≥ span ⇒ must be rejected by the range check
            if forged >= (1 << 22) {
                continue; // keep the forgery representable; only top·R_lo=0 should break
            }
            trace.values[base + W_R] = cv(forged as u32);
            for j in 0..21 {
                trace.values[base + W_RBIT + j] = bit_cv((forged >> j) & 1);
            }
            trace.values[base + W_RBIT + 21] = bit_cv((forged >> 21) & 1);
            forged_one = true;
            break;
        }
        assert!(forged_one, "expected at least one forgeable accepted row");

        let pubs = bounded_public_values(num);
        assert_air_rejects!(&air, trace, &pubs, "a non-canonical remainder must not verify");
    }

    #[test]
    fn bound_limbs_are_correct() {
        // BOUND_LIMBS must recompose to BOUND = 2^20 (they drive the join-2 lift carry chain).
        let recomposed: u64 = BOUND_LIMBS
            .iter()
            .enumerate()
            .map(|(k, &l)| l << (12 * k))
            .sum();
        assert_eq!(recomposed, BOUND);
        assert_eq!(BOUND_LIMBS, [0, 256, 0, 0]);
    }

    #[test]
    fn bounded_sampler_rejects_tampered_lift() {
        // Isolate the join-2 lift chain: toggle bit 0 of an accepted row's lift limb 0 AND its value
        // column together (so the `W_LIFT ↔ bits` link still holds), changing `lift` by ±1. This leaves
        // every other constraint satisfied but breaks `lift + BOUND = R + neg·Q`, so the proof must fail.
        let num = 32usize;
        let bytes = xof_bytes(
            b"lib-q-zk-encryption-proof/bounded-lift-tamper",
            num * 8 + 512,
        );
        let air = BoundedSamplerAir { num_coeffs: num };
        let mut trace = generate_bounded_trace(&bytes, num).expect("trace generation");

        let height = trace.values.len() / BOUNDED_WIDTH;
        let mut tampered = false;
        for r in 0..height {
            let base = r * BOUNDED_WIDTH;
            if trace.values[base + W_ACCEPTED] == ConfigVal::ONE {
                let bit0 = trace.values[base + W_LIFTBIT]; // bit 0 of lift limb 0
                if bit0 == ConfigVal::ONE {
                    trace.values[base + W_LIFTBIT] = ConfigVal::ZERO;
                    trace.values[base + W_LIFT] -= ConfigVal::ONE;
                } else {
                    trace.values[base + W_LIFTBIT] = ConfigVal::ONE;
                    trace.values[base + W_LIFT] += ConfigVal::ONE;
                }
                tampered = true;
                break;
            }
        }
        assert!(tampered, "expected at least one accepted row to tamper");

        let pubs = bounded_public_values(num);
        assert_air_rejects!(&air, trace, &pubs, "a tampered lift limb must not verify");
    }
}
