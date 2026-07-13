//! `ShakeSpongeAir` — the SHAKE-256 sponge boundary constraints (design §3.2) layered on top of the
//! audited Keccak-f\[1600\] permutation AIR (`lib-q-plonky-keccak-air`).
//!
//! The permutation AIR proves each 24-row block is a valid Keccak-f, but **not** the sponge around it.
//! `ShakeSpongeAir` delegates to `KeccakAir::eval` and adds exactly two boundary-constraint groups,
//! specialised to the frozen encap shape — a **single 102-byte absorb block followed by squeeze-only
//! permutations** (`DOM_FO_SEED ‖ pk_digest ‖ μ` is 38+32+32 = 102 bytes, which fits one 136-byte
//! rate block; no multi-block / XOR-absorb chaining is needed):
//!
//! - **(A) First absorb block = `pad10*1` with the SHAKE domain suffix + zero capacity, plus the input
//!   partition.** On the global first row, the permutation input `preimage` must carry, on the rate,
//!   the padded bytes: rate limb 51 = `0x1F` (byte 102 = the `0001 1111` XOF suffix + first pad bit;
//!   byte 103 = 0), rate limbs 52..=66 = 0 (bytes 104..133), rate limb 67 = `0x8000` (byte 135 = the
//!   trailing pad bit); and the 8 capacity lanes = 0. The 102 message bytes (rate limbs 0..=50) are
//!   partitioned: **label** (limbs 0..=18) pinned to the frozen [`DOM_FO_SEED`] constant, **pk_digest**
//!   (limbs 19..=34) pinned to the 16 public values (binds the proof to a specific public key), and
//!   **μ** (limbs 35..=50) left a free witness (the zero-knowledge secret).
//! - **(B) Squeeze chaining (full-state carry).** At each inter-block boundary (a final-step row in a
//!   transition), the next permutation's input state equals this permutation's output state, for all
//!   25 lanes: `next.preimage(y,x,·) = local.a_prime_prime_prime(y,x,·)`. Together with `KeccakAir`'s
//!   `first_step: preimage == a`, this threads the running sponge state across permutations.
//!
//! ## Soundness scope / status (RED)
//! Both constraint groups are validated by [`check_constraints`](lib_q_stark::check_constraints) on
//! the **truncated** (exactly `24·num_perms`-row, unpadded) trace produced by [`generate_sponge_air_trace`]:
//! every `step_flags[23]` boundary there is a *real* inter-block boundary, and the final one is
//! excluded by `is_transition`. A STARK `prove`/`verify` runs over the power-of-two-height trace from
//! [`generate_provable_sponge_trace`], which squeezes extra (ignored) continuation permutations so
//! *every* boundary is a real sponge step and constraint (B) holds uniformly — no boundary selector or
//! preprocessed column is needed. The `label`/`pk_digest`/`μ` input partition is now enforced by group
//! (A) (see below); the only remaining composition step for this AIR is the LogUp squeeze join (join
//! 1), which exposes the output rate bytes to the sampler AIR. This module lands, validates, and proves
//! the **constraint logic**.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::array;

use lib_q_plonky_keccak_air::{
    KeccakAir,
    KeccakColsRef,
    NUM_KECCAK_COLS,
    NUM_ROUNDS,
    U64_LIMBS,
    generate_trace_rows,
    output_limb,
};
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

use crate::logup_join::{
    SQUEEZE_LIMB_BUS,
    mcol,
    pcol,
    sconst,
};
use crate::sponge::{
    RATE_BYTES,
    RATE_LANES,
    generate_sponge_trace,
    num_permutations,
    sponge_permutation_states,
};

/// Number of 16-bit rate limbs squeezed per Keccak-f permutation (`RATE_LANES · U64_LIMBS = 68`,
/// = `RATE_BYTES / 2`). One limb-Send lookup is contributed per rate limb (see
/// [`sponge_limb_send_lookups`]).
const RATE_LIMBS: usize = RATE_LANES * U64_LIMBS;

/// Main-trace column index of the final-round selector `step_flags[NUM_ROUNDS-1]`. In the audited
/// `KeccakCols` layout the `step_flags` array occupies the first `NUM_ROUNDS` columns
/// (`KECCAK_COL_MAP.step_flags[i] == i`), so the final-step flag is column `NUM_ROUNDS-1`. It is 1
/// exactly on final-step rows (pinned by `eval_round_flags`), so it is a sound, non-prover-forgeable
/// Send selector — unlike the `export` column, which is prover-controlled on final-step rows.
const STEP_LAST_COL: usize = NUM_ROUNDS - 1;

/// Build a small field constant (`< 2^16`) as an `AB::Expr` via bit-Horner (no field-constant ctor).
fn konst<AB: AirBuilder>(x: u64) -> AB::Expr {
    let mut acc = AB::Expr::ZERO;
    for b in (0..16).rev() {
        acc = acc.double();
        if (x >> b) & 1 == 1 {
            acc += AB::Expr::ONE;
        }
    }
    acc
}

/// Map a rate-limb index `i ∈ [0, 68)` to its `(y, x, limb)` position in the Keccak state (matches
/// `lib_q_plonky_keccak_air::input_limb`/`output_limb`: 2 bytes/limb, 4 limbs/lane, lane = 5y+x).
fn rate_limb_yxl(i: usize) -> (usize, usize, usize) {
    let i_u64 = i / U64_LIMBS;
    (i_u64 / 5, i_u64 % 5, i % U64_LIMBS)
}

/// The frozen FO-seed domain label. **Must stay byte-identical** to
/// `lib-q-threshold-kem-lattice::kem::DOM_FO_SEED` (that constant is crate-private and tkem depends on
/// *this* crate, so it cannot be imported without a dependency cycle; the duplication is guarded by the
/// `dom_fo_seed_layout_is_frozen` test and the length assertions below). Occupies the first 38 input
/// bytes = rate limbs `0..LABEL_LIMBS`.
pub const DOM_FO_SEED: &[u8] = b"lib-q-threshold-kem-lattice/fo-seed/v1";

/// Rate-limb count spanned by [`DOM_FO_SEED`] (38 bytes ÷ 2 bytes/limb = 19 limbs, `0..=18`).
const LABEL_LIMBS: usize = 19;

/// First rate-limb index of `pk_digest` (byte 38 = limb 19; 38 is even so the boundary is limb-aligned).
pub const PK_DIGEST_LIMB_LO: usize = 19;

/// Rate-limb count spanned by `pk_digest` (32 bytes = 16 limbs, `19..=34`). These are the public values.
pub const PK_DIGEST_LIMBS: usize = 16;

/// First rate-limb index of `μ` (byte 70 = limb 35). `μ` spans limbs `35..=50` (16 limbs) and is left a
/// **free witness** (the zero-knowledge secret) — see the input-partition constraint in [`ShakeSpongeAir`].
const MU_LIMB_LO: usize = 35;

// Compile-time layout guards: the three fields must exactly tile the 102-byte (51-limb) rate prefix.
const _: () = assert!(DOM_FO_SEED.len() == 2 * LABEL_LIMBS); // 38 bytes = 19 limbs
const _: () = assert!(PK_DIGEST_LIMB_LO == LABEL_LIMBS); // pk_digest starts where the label ends
const _: () = assert!(MU_LIMB_LO == PK_DIGEST_LIMB_LO + PK_DIGEST_LIMBS); // μ starts where pk_digest ends
const _: () = assert!(MU_LIMB_LO + PK_DIGEST_LIMBS == 51); // μ ends at limb 50; 51 limbs = 102 bytes

/// The little-endian 16-bit value of the label's rate limb `i` (`i < LABEL_LIMBS`):
/// `DOM_FO_SEED[2i] | DOM_FO_SEED[2i+1] << 8`, matching the sponge rate byte order (2 bytes/limb).
const fn label_limb(i: usize) -> u64 {
    (DOM_FO_SEED[2 * i] as u64) | ((DOM_FO_SEED[2 * i + 1] as u64) << 8)
}

/// The SHAKE-256 sponge AIR for the frozen encap shape (single 102-byte absorb + squeeze-only), built
/// on the audited `KeccakAir`. Width is [`NUM_KECCAK_COLS`] (no added columns — the boundary
/// constraints read the existing `preimage`/`a_prime_prime_prime` maps).
///
/// **Public values** ([`PK_DIGEST_LIMBS`] = 16): the ciphertext's `pk_digest`, packed as little-endian
/// 16-bit limbs (limb `j` = `pk_digest[2j] | pk_digest[2j+1] << 8`), built by [`sponge_public_values`].
/// Constraint group (A) pins them onto the first absorb block's rate, binding the proof to a specific
/// public key. The 38-byte domain label is pinned to the [`DOM_FO_SEED`] constant; `μ` is left free.
///
/// **Composition obligations** (outside this AIR — the binding is only meaningful if these hold):
/// 1. **pk wiring (load-bearing).** The *verifier* must build the public values itself as
///    `sponge_public_values(&ciphertext.pk_digest)` and pass those to `verify`; it must NOT accept
///    prover-supplied public values. Otherwise the AIR only proves "a sponge over *some* pk_digest",
///    which is vacuous. (Adversarially reviewed 2026-07-11: this is the single most important external
///    obligation.)
/// 2. **LogUp squeeze join (join 1).** The squeezed output rate bytes must be exported to the sampler
///    AIR via LogUp, or the correctly-bound sponge output is never consumed downstream.
/// 3. **Label sync.** [`DOM_FO_SEED`] duplicates the crate-private tkem constant; the CI test
///    `dom_fo_seed_layout_is_frozen` must stay green — a silent tkem-side change would make this AIR
///    prove a sponge over a stale domain with no compile error.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShakeSpongeAir {
    /// Trace height (rows) — needed only to size the preprocessed squeeze-position column that keys
    /// the limb-Send join (see [`sponge_limb_send_lookups`]). `0` disables the preprocessed trace
    /// (standalone `check_constraints` / single-AIR proving with no limb-Send).
    pub height: usize,
}

// `BaseAir` is implemented concretely over the STARK value field `ConfigVal` (not generic `F`)
// because `preprocessed_trace` materialises a `RowMajorMatrix<ConfigVal>`, and `RowMajorMatrix::new`
// requires `Clone + Send + Sync` — bounds that `AirBuilder::F` (only `PrimeCharacteristicRing +
// Sync`) does not carry. Every builder used with this AIR has `F = ConfigVal`, so the `Air` impl
// below is likewise pinned to `AB::F = ConfigVal`.
impl BaseAir<ConfigVal> for ShakeSpongeAir {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }

    fn num_public_values(&self) -> usize {
        PK_DIGEST_LIMBS
    }

    /// One preprocessed column: the absolute byte offset of squeeze-block `perm = row / NUM_ROUNDS`,
    /// i.e. `RATE_BYTES · perm`. The limb-Send lookups read it only on final-step rows (where
    /// `row / NUM_ROUNDS = perm` exactly); other rows are don't-care (Send multiplicity is 0). It is
    /// a fixed function of the row index, so the verifier commits it independently of the prover
    /// (sound). Returns `None` when `height == 0` (no join).
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<ConfigVal>> {
        if self.height == 0 {
            return None;
        }
        let col: Vec<ConfigVal> = (0..self.height)
            .map(|r| ConfigVal::from_usize(RATE_BYTES * (r / NUM_ROUNDS)))
            .collect();
        Some(RowMajorMatrix::new(col, 1))
    }
}

impl<AB: AirBuilder<F = ConfigVal>> Air<AB> for ShakeSpongeAir {
    fn eval(&self, builder: &mut AB) {
        // (0) The audited permutation + round-flag constraints (each 24-row block is a valid Keccak-f).
        KeccakAir {}.eval(builder);

        // Read the pk_digest public values into owned exprs before borrowing the main trace / taking
        // the `when_first_row` mutable borrow.
        let pk_pv: [AB::Expr; PK_DIGEST_LIMBS] =
            array::from_fn(|j| builder.public_values()[j].into());

        let main = builder.main();
        let local = KeccakColsRef::from_row_slice(main.current_slice());
        let next = KeccakColsRef::from_row_slice(main.next_slice());
        let step_last = local.step_flags(NUM_ROUNDS - 1);

        // (A) First absorb block = pad10*1(input ‖ 0x1F … 0x80) with zero capacity (102-byte block),
        // plus the input partition of the 102 message bytes (51 rate limbs):
        //   • label  (limbs 0..=18)  pinned to the frozen `DOM_FO_SEED` constant;
        //   • pk_digest (limbs 19..=34) pinned to the 16 public values — binds the proof to this pk;
        //   • μ       (limbs 35..=50) left FREE — the zero-knowledge witness.
        {
            let mut fb = builder.when_first_row();

            // Domain label → frozen constant.
            for i in 0..LABEL_LIMBS {
                let (y, x, limb) = rate_limb_yxl(i);
                fb.assert_zero(local.preimage(y, x, limb).into() - konst::<AB>(label_limb(i)));
            }
            // pk_digest → public values (ciphertext binding).
            for (j, pv) in pk_pv.iter().enumerate() {
                let (y, x, limb) = rate_limb_yxl(PK_DIGEST_LIMB_LO + j);
                fb.assert_zero(local.preimage(y, x, limb).into() - pv.clone());
            }
            // μ (limbs MU_LIMB_LO..=50) intentionally unconstrained here — it is the secret witness,
            // threaded through the permutation by KeccakAir's preimage-constancy + round constraints.

            for i in 51..=67 {
                let (y, x, limb) = rate_limb_yxl(i);
                let target: AB::Expr = match i {
                    51 => konst::<AB>(0x1F), // byte 102 = XOF suffix + first pad bit; byte 103 = 0
                    67 => konst::<AB>(0x8000), // byte 135 = trailing pad bit; byte 134 = 0
                    _ => AB::Expr::ZERO,     // bytes 104..133 = 0
                };
                fb.assert_zero(local.preimage(y, x, limb).into() - target);
            }
            // Capacity lanes (17..25) are zero on the first absorb (initial state was all-zero).
            for lane in RATE_LANES..25 {
                let (y, x) = (lane / 5, lane % 5);
                for limb in 0..U64_LIMBS {
                    fb.assert_zero(local.preimage(y, x, limb));
                }
            }
        }

        // (B) Squeeze chaining: at each inter-block boundary (final step + transition), the next
        // permutation's input equals this permutation's output (full 25-lane carry; squeeze-only, so
        // no rate XOR). On the trace's last row `is_transition = 0`, so the final squeeze is not
        // chained forward.
        {
            let mut tb = builder.when_transition();
            let mut cb = tb.when(step_last);
            for y in 0..5 {
                for x in 0..5 {
                    for limb in 0..U64_LIMBS {
                        cb.assert_zero(
                            next.preimage(y, x, limb).into() -
                                local.a_prime_prime_prime(y, x, limb).into(),
                        );
                    }
                }
            }
        }
    }
}

/// The [`RATE_LIMBS`] (= 68) per-rate-limb **Send** lookups the sponge contributes on
/// [`SQUEEZE_LIMB_BUS`] — the limb half of design join 1. For each rate limb `i`, Send
/// `(RATE_BYTES·perm + 2·i, a‴_limb_i)` gated by the final-step selector `step_flags[NUM_ROUNDS-1]`:
///   * `RATE_BYTES·perm` is the preprocessed position column (col 0) — the squeeze-block byte offset;
///   * `2·i` is the per-limb constant offset (rate limb `i` covers output bytes `2i, 2i+1`);
///   * the sent value is the output-limb column `output_limb(i)` (the 16-bit `a‴` limb);
///   * the multiplicity is main column [`STEP_LAST_COL`] (1 only on final-step rows).
///
/// Each lookup uses its own aux column `i`, so the sponge's permutation trace has [`RATE_LIMBS`]
/// columns. They are deliberately **single-tuple** (degree 3): one bundled 68-tuple lookup would
/// have a 68-fold product denominator (degree ~69), blowing up the quotient domain.
///
/// [`crate::squeeze_byte::squeeze_byte_limb_receive_lookup`] is the matching Receive side; the two
/// balance iff the squeeze-byte table's reconstructed limbs equal the sponge's true squeezed output
/// at each byte position.
pub fn sponge_limb_send_lookups() -> Vec<Lookup<ConfigVal>> {
    let step_last = mcol(STEP_LAST_COL);
    (0..RATE_LIMBS)
        .map(|i| {
            Lookup::new(
                Kind::Global(SQUEEZE_LIMB_BUS.into()),
                Vec::from([Vec::from([
                    pcol(0) + sconst(2 * i as u64),
                    mcol(output_limb(i)),
                ])]),
                Vec::from([Direction::Send.multiplicity(step_last.clone())]),
                Vec::from([i]),
            )
        })
        .collect()
}

/// Lift a `Mersenne31` base-field element into the STARK value field `Complex<Mersenne31>`
/// (`real = m`, `imag = 0`) — the same ring embedding `air::embed_sponge_trace` uses.
fn lift(m: Mersenne31) -> ConfigVal {
    ConfigVal::from_basis_coefficients_fn(|i| if i == 0 { m } else { Mersenne31::ZERO })
}

/// Assemble the exact 102-byte FO-seed preimage `DOM_FO_SEED ‖ pk_digest ‖ μ` the tkem `encapsulate`
/// XOF absorbs (`kem.rs`: `update(DOM_FO_SEED); update(pk_dig); update(mu)`). This is the sponge input
/// whose partition [`ShakeSpongeAir`] constrains.
pub fn encap_preimage(pk_digest: &[u8; 32], mu: &[u8; 32]) -> [u8; 102] {
    let mut p = [0u8; 102];
    p[..DOM_FO_SEED.len()].copy_from_slice(DOM_FO_SEED);
    p[DOM_FO_SEED.len()..DOM_FO_SEED.len() + 32].copy_from_slice(pk_digest);
    p[DOM_FO_SEED.len() + 32..].copy_from_slice(mu);
    p
}

/// The [`PK_DIGEST_LIMBS`] public values a [`ShakeSpongeAir`] proof binds: `pk_digest`'s 32 bytes packed
/// as little-endian 16-bit rate limbs (`limb j = pk_digest[2j] | pk_digest[2j+1] << 8`), embedded in the
/// STARK value field. Pass these as the `public_values` to `prove`/`verify`/`check_constraints`.
pub fn sponge_public_values(pk_digest: &[u8; 32]) -> Vec<ConfigVal> {
    (0..PK_DIGEST_LIMBS)
        .map(|j| {
            let v = u32::from(pk_digest[2 * j]) | (u32::from(pk_digest[2 * j + 1]) << 8);
            lift(Mersenne31::new(v))
        })
        .collect()
}

/// Generate the **truncated** SHAKE-256 sponge trace — exactly `24·num_perms` rows, with no
/// power-of-two zero-input padding — embedded into the STARK value field, for [`check_constraints`]
/// validation of [`ShakeSpongeAir`]. (The `prove`-time padded trace additionally needs the boundary
/// selector; see the module docs.)
pub fn generate_sponge_air_trace(input: &[u8], out_len: usize) -> RowMajorMatrix<ConfigVal> {
    let k = num_permutations(input.len(), out_len);
    let base = generate_sponge_trace(input, out_len); // Mersenne31, power-of-two-padded
    let real_rows = k * NUM_ROUNDS;
    let vals: Vec<ConfigVal> = base.values[..real_rows * NUM_KECCAK_COLS]
        .iter()
        .copied()
        .map(lift)
        .collect();
    RowMajorMatrix::new(vals, NUM_KECCAK_COLS)
}

/// Generate a **power-of-two-height, prove-ready** sponge trace embedded in the STARK value field.
///
/// The audited `generate_trace_rows` pads to a power-of-two height with *zero-input* permutations,
/// and `24·k` is never a power of two, so a naive [`ShakeSpongeAir`] proof over that padded trace
/// would fail constraint (B) at the last-real → padding boundary. Instead we **squeeze extra
/// (ignored) continuation permutations**: for a power-of-two height `H = next_pow2(24·k_real)`, we
/// generate `l+1` real sponge-continuation input states (`l = ⌊H/24⌋`) and truncate the resulting
/// trace to `H` rows. Every one of the `H`-row trace's permutation boundaries is then a genuine
/// sponge step (`next.preimage = Keccak-f(prev)`), so constraint (B) holds *uniformly* — no padding
/// selector or preprocessed column is needed, and the AIR is unchanged from the `check_constraints`
/// milestone. The extra squeezed output bytes are discarded; the first `out_len` bytes are unaffected.
///
/// Single-absorb encap shape only (`input.len() ≤ 135`, one rate block). Returns a trace of height
/// `H` (power of two) provable/verifiable by `StarkProver`/`StarkVerifier`.
pub fn generate_provable_sponge_trace(input: &[u8], out_len: usize) -> RowMajorMatrix<ConfigVal> {
    let k_real = num_permutations(input.len(), out_len);
    let h = (NUM_ROUNDS * k_real).next_power_of_two();
    let l = h / NUM_ROUNDS; // full permutation-chunks that fit in H (⌊H/24⌋)
    // `l+1` continuation states → the final (partial) chunk is backed by a real continuation input,
    // so no zero-padding permutation appears within the first H rows.
    let states = sponge_permutation_states(input, l + 1);
    let base = generate_trace_rows::<Mersenne31>(states, 0); // height = next_pow2(24·(l+1)) ≥ 2H
    let vals: Vec<ConfigVal> = base.values[..h * NUM_KECCAK_COLS]
        .iter()
        .copied()
        .map(lift)
        .collect();
    RowMajorMatrix::new(vals, NUM_KECCAK_COLS)
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use lib_q_stark::check_constraints;
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    use super::*;
    use crate::sponge::RATE_BYTES;

    /// Build the correctly-padded first-block input state for a `≤ 102`-byte input (rate = padded
    /// bytes, capacity = 0).
    fn padded_block_state(input: &[u8]) -> [u64; 25] {
        assert!(input.len() <= 102);
        let mut block = [0u8; RATE_BYTES];
        block[..input.len()].copy_from_slice(input);
        block[input.len()] = 0x1F;
        block[RATE_BYTES - 1] |= 0x80;
        let mut state = [0u64; 25];
        for (lane, s) in state.iter_mut().enumerate().take(RATE_LANES) {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[lane * 8..lane * 8 + 8]);
            *s = u64::from_le_bytes(b);
        }
        state
    }

    /// Run `check_constraints` (with the given public values) under a silenced panic hook; return
    /// whether it rejected (panicked).
    fn rejects<A>(air: &A, trace: &RowMajorMatrix<ConfigVal>, pubs: &[ConfigVal]) -> bool
    where
        A: for<'a> Air<lib_q_stark::DebugConstraintBuilder<'a, ConfigVal>>,
    {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_constraints(air, trace, pubs);
        }));
        std::panic::set_hook(prev);
        r.is_err()
    }

    /// An honest single-absorb, multi-squeeze SHAKE-256 sponge trace over the real encap preimage
    /// (`DOM_FO_SEED ‖ pk_digest ‖ μ`) satisfies all sponge constraints when checked with the matching
    /// `pk_digest` public values.
    #[test]
    fn sponge_air_accepts_honest_shake() {
        let pk = [0xABu8; 32];
        let mu = [0x5Cu8; 32];
        let input = encap_preimage(&pk, &mu);
        let trace = generate_sponge_air_trace(&input, 300); // 3 squeeze blocks → 3 permutations
        check_constraints(
            &ShakeSpongeAir::default(),
            &trace,
            &sponge_public_values(&pk),
        ); // panics on violation
    }

    /// A wrong-length input pads at the wrong byte, so the pad constraint (A) rejects it. (The
    /// public-value length must still be correct so the rejection is a genuine constraint failure, not
    /// an out-of-bounds read.)
    #[test]
    fn sponge_air_rejects_wrong_length_pad() {
        // 50-byte input → 0x1F lands at byte 50 (rate limb 25), so rate limb 51 ≠ 0x1F → (A) fails.
        let input = [0x42u8; 50];
        let trace = generate_sponge_air_trace(&input, 300);
        assert!(
            rejects(
                &ShakeSpongeAir::default(),
                &trace,
                &sponge_public_values(&[0u8; 32])
            ),
            "pad constraint (A) must reject an input that is not a 102-byte block"
        );
    }

    /// Isolate constraint (B): two permutations whose block-0 input is correctly padded (so (A)
    /// passes) but whose block-1 input is UNRELATED to block-0's output. The trace passes `KeccakAir`
    /// (both permutations are individually valid) yet `ShakeSpongeAir` rejects it — the rejection is
    /// therefore due to the squeeze-chaining constraint (B) alone.
    #[test]
    fn sponge_air_rejects_broken_chaining_isolating_b() {
        // Block-0 is a correctly-partitioned encap preimage, so groups (A)/(A2) all pass; only (B) can
        // fire.
        let pk = [0xABu8; 32];
        let mu = [0x5Cu8; 32];
        let state_a = padded_block_state(&encap_preimage(&pk, &mu));
        let state_b = [7u64; 25]; // deterministically != Keccak-f(state_a)
        let base = generate_trace_rows::<Mersenne31>(vec![state_a, state_b], 0);
        let real_rows = 2 * NUM_ROUNDS;
        let vals: Vec<ConfigVal> = base.values[..real_rows * NUM_KECCAK_COLS]
            .iter()
            .copied()
            .map(lift)
            .collect();
        let trace = RowMajorMatrix::new(vals, NUM_KECCAK_COLS);
        let pubs = sponge_public_values(&pk);

        // KeccakAir alone accepts (both permutations are valid Keccak-f).
        check_constraints(&KeccakAir {}, &trace, &[]);

        // ShakeSpongeAir rejects: block-1 input != block-0 output (constraint B) — with the correct
        // pk_digest public values, so (A2) is satisfied and the rejection is (B) alone.
        assert!(
            rejects(&ShakeSpongeAir::default(), &trace, &pubs),
            "squeeze-chaining constraint (B) must reject an unrelated block-1 input"
        );
    }

    /// End-to-end: a power-of-two-height, continuation-padded sponge trace PROVES and VERIFIES under
    /// the workspace STARK stack with the pad (A) and squeeze-chaining (B) constraints active — the
    /// milestone that `ShakeSpongeAir` is provable, not just `check_constraints`-valid.
    #[test]
    fn sponge_air_proves_and_verifies() {
        let pk = [0x11u8; 32];
        let mu = [0x22u8; 32];
        let input = encap_preimage(&pk, &mu);
        let trace = generate_provable_sponge_trace(&input, 200); // k_real = 2 → H = 64 rows
        let pubs = sponge_public_values(&pk);
        let proof = StarkProver::new(default_config())
            .prove(&ShakeSpongeAir::default(), trace, &pubs)
            .expect("prove ShakeSpongeAir");
        StarkVerifier::new(default_config())
            .verify(&ShakeSpongeAir::default(), &proof, &pubs)
            .expect("verify ShakeSpongeAir");
    }

    /// True iff `trace` both proves AND verifies cleanly under the given public values. A prove-time
    /// debug-constraint panic, a prove error, or a verify error all count as "rejected" → `false`. The
    /// panic hook is silenced around the (expected-panic) prove call.
    fn proves_and_verifies(trace: RowMajorMatrix<ConfigVal>, pubs: &[ConfigVal]) -> bool {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let proof = StarkProver::new(default_config())
                .prove(&ShakeSpongeAir::default(), trace, pubs)
                .ok()?;
            StarkVerifier::new(default_config())
                .verify(&ShakeSpongeAir::default(), &proof, pubs)
                .ok()
        }));
        std::panic::set_hook(prev);
        matches!(r, Ok(Some(())))
    }

    /// A tampered provable trace (a corrupted pad byte on the first block) must not yield a verifying
    /// proof. (`StarkProver::prove` runs `check_constraints` internally, so a tampered trace makes
    /// `prove` panic — [`proves_and_verifies`] treats that panic as a rejection.)
    #[test]
    fn sponge_air_tampered_provable_trace_rejected() {
        let pk = [0x11u8; 32];
        let mu = [0x22u8; 32];
        let input = encap_preimage(&pk, &mu);
        let mut trace = generate_provable_sponge_trace(&input, 200);
        let pubs = sponge_public_values(&pk);
        // Corrupt rate limb 51 (should be 0x1F) on row 0's preimage — breaks pad (A) (and the Keccak
        // first_step/constancy). `input_limb(51)` is the flat column index of that limb.
        let col = lib_q_plonky_keccak_air::input_limb(51);
        trace.values[col] += ConfigVal::ONE;

        assert!(
            !proves_and_verifies(trace, &pubs),
            "a tampered sponge trace must not produce a verifying proof"
        );
    }

    /// **Ciphertext binding (the point of this milestone).** An honest trace for `pk = A` must NOT be
    /// accepted under `pk_digest` public values for a different `pk = B`: the pk-digest pinning in (A)
    /// ties the proof to one public key. The same trace *is* accepted under the correct public values.
    #[test]
    fn sponge_air_rejects_wrong_pk_digest_public_value() {
        let pk_a = [0xA1u8; 32];
        let mu = [0x33u8; 32];
        let trace = generate_sponge_air_trace(&encap_preimage(&pk_a, &mu), 300);

        // Correct pk → accepts.
        check_constraints(
            &ShakeSpongeAir::default(),
            &trace,
            &sponge_public_values(&pk_a),
        );

        // Different pk (single byte differs) → the pk-digest binding rejects.
        let mut pk_b = pk_a;
        pk_b[0] ^= 0x01;
        assert!(
            rejects(
                &ShakeSpongeAir::default(),
                &trace,
                &sponge_public_values(&pk_b)
            ),
            "a proof for pk_A must not accept mismatched pk_digest public values (pk_B)"
        );
    }

    /// The 38-byte domain label is pinned to the frozen constant: tampering with any label byte in the
    /// input makes constraint (A) reject, independent of the (correct) public values.
    #[test]
    fn sponge_air_rejects_tampered_label() {
        let pk = [0x01u8; 32];
        let mu = [0x02u8; 32];
        let mut input = encap_preimage(&pk, &mu);
        input[0] ^= 0x01; // flip a label byte (byte 0, rate limb 0)
        let trace = generate_sponge_air_trace(&input, 300);
        assert!(
            rejects(
                &ShakeSpongeAir::default(),
                &trace,
                &sponge_public_values(&pk)
            ),
            "a tampered domain label must be rejected by the label-pinning constraint"
        );
    }

    /// μ is a free witness: two different messages under the *same* pk both satisfy the AIR with the
    /// same public values (the proof reveals nothing about μ through the pinned columns).
    #[test]
    fn sponge_air_mu_is_free_witness() {
        let pk = [0x77u8; 32];
        let pubs = sponge_public_values(&pk);
        for mu in [[0x00u8; 32], [0xFFu8; 32]] {
            let trace = generate_sponge_air_trace(&encap_preimage(&pk, &mu), 300);
            check_constraints(&ShakeSpongeAir::default(), &trace, &pubs);
        }
    }

    /// Guard the duplicated [`DOM_FO_SEED`] and the field partition against silent drift: the label must
    /// be 38 bytes and the three fields must tile the 102-byte / 51-limb rate prefix exactly.
    #[test]
    fn dom_fo_seed_layout_is_frozen() {
        assert_eq!(DOM_FO_SEED, b"lib-q-threshold-kem-lattice/fo-seed/v1");
        assert_eq!(DOM_FO_SEED.len(), 38);
        assert_eq!(LABEL_LIMBS, 19);
        assert_eq!(PK_DIGEST_LIMB_LO, 19);
        assert_eq!(PK_DIGEST_LIMBS, 16);
        assert_eq!(MU_LIMB_LO, 35);
        assert_eq!(MU_LIMB_LO + PK_DIGEST_LIMBS, 51); // μ ends at limb 50 → 51 limbs = 102 bytes
        // The public-value packing round-trips the pk_digest limb values.
        let pk: [u8; 32] = array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let pv = sponge_public_values(&pk);
        assert_eq!(pv.len(), PK_DIGEST_LIMBS);
        for (j, cell) in pv.iter().enumerate() {
            let want = u32::from(pk[2 * j]) | (u32::from(pk[2 * j + 1]) << 8);
            assert_eq!(*cell, lift(Mersenne31::new(want)));
        }
    }
}
