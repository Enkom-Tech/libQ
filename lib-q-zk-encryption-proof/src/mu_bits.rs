//! μ limb→bit bridge (card `t_a73aaed2`, GAP 2) — the join that makes `encode(μ)` mean the *same* μ
//! the FO expansion used.
//!
//! ## Why this exists
//! The proof's claim has two halves that both mention `μ`:
//! 1. `(e, f, g) = XOF(DOM_FO_SEED ‖ pk_digest ‖ μ)` — enforced by [`crate::sponge_air`], whose
//!    preimage carries `μ` in rate limbs `35..=50`;
//! 2. `v = Σ_r t0_r·e_r + g + encode(μ)` — whose `encode(μ)` term comes from
//!    [`crate::zq::EncodeMuFoldAir`], which took `μ`'s 256 bits as FREE boolean trace columns.
//!
//! Nothing tied those two `μ`s together. That was not merely a message-binding gap: because the
//! relation is a *linear* form `⟨encode(μ), κ⟩ = ⌊q/2⌋·Σ_i μ_i·κ_i` with `κ` a PUBLIC function of the
//! statement, a prover could compute `κ` first and then solve the modular subset-sum
//! `Σ_i κ_i·μ_i ≡ T·⌊q/2⌋^{-1} (mod q)` over 256 free bits — meet-in-the-middle over `q ≈ 2^48`, so
//! roughly `2^24` work — and hit whatever value made an **arbitrary malformed `v`** verify. That is
//! structurally the same defect as the free quotient fold this card removed: a prover-chosen operand
//! entering the checked relation after the challenge is known. Boolean-constrained is not bound.
//!
//! ## The bridge
//! [`MuBitsAir`] is 16 rows, one per μ preimage limb. Each row Receives the 16-bit limb from the
//! sponge on [`MU_LIMB_BUS`] (the sponge Sends them once, gated on its first row — the only row whose
//! preimage is the FO seed) and Sends that limb's 16 bits on [`MU_BIT_BUS`], keyed by absolute bit
//! index `16·j + b`. [`crate::zq::EncodeMuFoldAir`] Receives bit `i` at the row whose coefficient
//! index is `i`. Both buses then balance iff the encode fold's bits are exactly the sponge's μ.
//!
//! Bit order: sponge rate limb `j` is the little-endian 16-bit value of preimage bytes `2j, 2j+1`, and
//! `encode_msg` reads bit `i` as `(mu[i/8] >> (i%8)) & 1`. So μ's bit `i` is bit `i % 16` of μ-limb
//! `i / 16` — which is exactly the keying below. Get this wrong and honest proofs stop verifying
//! (loudly), not silently; `mu_bits_trace_matches_encode_msg_bit_order` pins it anyway.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_zkp::stark::ConfigVal;

use crate::logup_join::{
    MU_BIT_BUS,
    MU_LIMB_BUS,
    fc,
    mcol,
    pcol,
    sconst,
};

/// Bits per μ preimage limb (a Keccak rate limb is 16 bits).
pub const MU_BITS_PER_LIMB: usize = 16;
/// Number of μ limbs in the FO-seed preimage (`32` message bytes ÷ 2 bytes per limb).
pub const MU_LIMBS: usize = 16;

/// Column 0 is the limb value; columns `1..=16` are its little-endian bits.
const MB_LIMB: usize = 0;
const MB_BIT: usize = 1;
/// Trace width of [`MuBitsAir`].
pub const MU_BITS_WIDTH: usize = 1 + MU_BITS_PER_LIMB;

/// AIR decomposing each of the `MU_LIMBS` μ preimage limbs into 16 booleans. One row per limb; height
/// is `MU_LIMBS = 16`, already a power of two.
#[derive(Debug, Clone, Copy, Default)]
pub struct MuBitsAir;

impl BaseAir<ConfigVal> for MuBitsAir {
    fn width(&self) -> usize {
        MU_BITS_WIDTH
    }

    fn num_public_values(&self) -> usize {
        0
    }

    /// One preprocessed column: this row's limb index `j`. It keys both the limb Receive and the
    /// per-bit Sends, so the bus positions are a verifier-committed function of the row rather than
    /// a prover-supplied label.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<ConfigVal>> {
        let col: Vec<ConfigVal> = (0..MU_LIMBS).map(|j| fc(j as u64)).collect();
        Some(RowMajorMatrix::new(col, 1))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl<AB: AirBuilder<F = ConfigVal>> Air<AB> for MuBitsAir {
    fn eval(&self, builder: &mut AB) {
        let (limb, bits): (AB::Expr, Vec<AB::Expr>) = {
            let main = builder.main();
            let local = main.current_slice();
            (
                local[MB_LIMB].into(),
                (0..MU_BITS_PER_LIMB)
                    .map(|b| local[MB_BIT + b].into())
                    .collect(),
            )
        };
        // Booleanity, and the limb is exactly the little-endian recomposition of its bits. Without
        // BOTH, a prover could Send bits that do not sum to the limb the sponge committed.
        let mut recomposed = AB::Expr::ZERO;
        for b in (0..MU_BITS_PER_LIMB).rev() {
            builder.assert_bool(bits[b].clone());
            recomposed = recomposed.double() + bits[b].clone();
        }
        builder.assert_zero(limb - recomposed);
    }
}

/// Build the bridge trace for `mu`: row `j` holds the little-endian 16-bit value of `mu[2j], mu[2j+1]`
/// and its bits. Matches the sponge preimage's limb packing exactly.
#[must_use]
pub fn generate_mu_bits_trace(mu: &[u8; 32]) -> RowMajorMatrix<ConfigVal> {
    let mut vals = Vec::with_capacity(MU_LIMBS * MU_BITS_WIDTH);
    for j in 0..MU_LIMBS {
        let limb = u64::from(mu[2 * j]) | (u64::from(mu[2 * j + 1]) << 8);
        vals.push(fc(limb));
        for b in 0..MU_BITS_PER_LIMB {
            vals.push(fc((limb >> b) & 1));
        }
    }
    RowMajorMatrix::new(vals, MU_BITS_WIDTH)
}

/// The bridge's lookups: Receive each limb from the sponge ONCE, and Send its 16 bits `m` times —
/// once per Fiat–Shamir challenge, because each challenge has its own `EncodeMuFoldAir` instance and
/// each of those Receives all 256 bits. Mirrors how the samplers repeat their coefficient Sends.
/// Getting `m` wrong unbalances [`MU_BIT_BUS`] and `verify_batch` rejects, so this is load-bearing
/// rather than bookkeeping.
///
/// Aux columns: `0` for the limb Receive, then `1 + 16·i + b` for challenge `i`'s bit Sends.
#[must_use]
pub fn mu_bits_lookups(m: usize) -> Vec<Lookup<ConfigVal>> {
    let idx = pcol(0);
    let mut lookups = Vec::with_capacity(1 + m * MU_BITS_PER_LIMB);
    lookups.push(Lookup::new(
        Kind::Global(MU_LIMB_BUS.into()),
        Vec::from([Vec::from([idx.clone(), mcol(MB_LIMB)])]),
        Vec::from([Direction::Receive.multiplicity(sconst(1))]),
        Vec::from([0]),
    ));
    for i in 0..m {
        for b in 0..MU_BITS_PER_LIMB {
            lookups.push(Lookup::new(
                Kind::Global(MU_BIT_BUS.into()),
                Vec::from([Vec::from([
                    sconst(MU_BITS_PER_LIMB as u64) * idx.clone() + sconst(b as u64),
                    mcol(MB_BIT + b),
                ])]),
                Vec::from([Direction::Send.multiplicity(sconst(1))]),
                Vec::from([1 + MU_BITS_PER_LIMB * i + b]),
            ));
        }
    }
    lookups
}

#[cfg(test)]
mod tests {
    use lib_q_threshold_kem_lattice::kem::encode_msg;

    use super::*;
    use crate::relation_assembly::rq_coeffs_zq;
    use crate::zq::HALFQ;

    /// The bridge's bit order must equal the order `encode_msg` reads μ in, or the encode fold would
    /// receive the right bits at the wrong coefficients. Checked against the KEM's own encoding.
    #[test]
    fn mu_bits_trace_matches_encode_msg_bit_order() {
        let mu: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let trace = generate_mu_bits_trace(&mu);
        let encoded = rq_coeffs_zq(&encode_msg(&mu));

        for i in 0..256 {
            let (j, b) = (i / MU_BITS_PER_LIMB, i % MU_BITS_PER_LIMB);
            let bit = trace.values[j * MU_BITS_WIDTH + MB_BIT + b];
            let expected = u64::from((mu[i / 8] >> (i % 8)) & 1);
            assert_eq!(bit, fc(expected), "bridge bit {i} disagrees with μ");
            // …and that bit is what encode_msg puts at coefficient i.
            assert_eq!(
                encoded[i],
                if expected == 1 { HALFQ } else { 0 },
                "encode_msg coefficient {i} disagrees with μ's bit"
            );
        }
    }

    /// Each row's limb is the little-endian recomposition of its bits — the constraint the AIR
    /// enforces, checked on the generated trace so a generator/AIR divergence shows up here.
    #[test]
    fn mu_bits_limb_is_the_recomposition_of_its_bits() {
        let mu: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(91).wrapping_add(3));
        let trace = generate_mu_bits_trace(&mu);
        for j in 0..MU_LIMBS {
            let mut acc = 0u64;
            for b in (0..MU_BITS_PER_LIMB).rev() {
                let bit = trace.values[j * MU_BITS_WIDTH + MB_BIT + b];
                assert!(
                    bit == fc(0) || bit == fc(1),
                    "bit {b} of limb {j} not boolean"
                );
                acc = acc * 2 + u64::from(bit == fc(1));
            }
            assert_eq!(trace.values[j * MU_BITS_WIDTH + MB_LIMB], fc(acc));
        }
    }
}
