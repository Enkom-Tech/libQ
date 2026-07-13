//! Proving-pipeline milestone and shared trace embedding for the sponge AIR.
//!
//! This module establishes the two pieces the full `ShakeSpongeAir` prover (design §3) builds on,
//! and validates them with a real STARK prove/verify roundtrip:
//!
//! 1. **Field embedding.** The Keccak trace is generated over the base field `Mersenne31` (the
//!    permutation trace generator is `PrimeField64`-bound). The STARK value field is
//!    `Complex<Mersenne31>` (`GF(p²)`). [`embed_sponge_trace`] lifts the base trace into the value
//!    field by the canonical ring embedding `m ↦ m + 0·i`. Because that embedding is a ring
//!    homomorphism, every Keccak AIR constraint that holds over `Mersenne31` holds over the lifted
//!    trace, so the lifted trace is a valid witness for the *unchanged* `KeccakAir` constraints.
//! 2. **Prove/verify wiring.** The workspace `DefaultConfig` (FRI over `Complex<Mersenne31>`,
//!    SHAKE-256 Merkle commitment, SHAKE-256 challenger) proves and verifies the permutation AIR.
//!
//! The sponge/sampler/lattice AIRs (design §§3–5) reuse exactly this embedding and, under
//! `batch-stark` composition, this prove/verify path.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The audited Keccak-f\[1600\] permutation AIR, ready to prove/verify (re-export for callers).
pub use lib_q_plonky_keccak_air::KeccakAir;
use lib_q_plonky_keccak_air::NUM_KECCAK_COLS;
use lib_q_stark_field::{
    BasedVectorSpace,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::stark::ConfigVal;

use crate::sponge::generate_sponge_trace;

/// Lift a `Mersenne31` base-field element into the STARK value field `Complex<Mersenne31>`
/// (`real = m`, `imag = 0`). This is a ring homomorphism.
#[inline]
fn lift(m: Mersenne31) -> ConfigVal {
    ConfigVal::from_basis_coefficients_fn(|i| if i == 0 { m } else { Mersenne31::ZERO })
}

/// Generate the SHAKE-256 sponge trace for `input`/`out_len` (design §3) and embed it into the STARK
/// value field so it can be proven with the workspace `DefaultConfig`.
///
/// The width is [`NUM_KECCAK_COLS`]; the height is the padded permutation-block count times 24.
pub fn embed_sponge_trace(input: &[u8], out_len: usize) -> RowMajorMatrix<ConfigVal> {
    let base = generate_sponge_trace(input, out_len);
    let values: Vec<ConfigVal> = base.values.iter().copied().map(lift).collect();
    RowMajorMatrix::new(values, NUM_KECCAK_COLS)
}

#[cfg(test)]
mod tests {
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    use super::*;

    /// End-to-end milestone: prove and verify a real Keccak-f permutation through the workspace
    /// STARK stack, over a trace produced by this crate's sponge generator and value-field embedding.
    /// This is the prove/verify path the full encryption-correctness proof composes over.
    #[test]
    fn keccak_permutation_proves_and_verifies() {
        // Short input -> one absorb block; 32-byte output -> one squeeze block -> one permutation.
        let trace = embed_sponge_trace(b"lib-q-zk-encryption-proof/milestone", 32);
        let air = KeccakAir {};
        let public_values: Vec<ConfigVal> = Vec::new();

        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &public_values)
            .expect("prove a Keccak-f permutation");

        StarkVerifier::new(default_config())
            .verify(&air, &proof, &public_values)
            .expect("verify a Keccak-f permutation");
    }

    /// A tampered proof must not verify (soundness smoke test).
    #[test]
    fn tampered_public_values_rejected() {
        // Two absorb blocks (136-byte input overflows the pad) still prove/verify honestly.
        let trace = embed_sponge_trace(&[0x5Au8; 136], 32);
        let air = KeccakAir {};
        let public_values: Vec<ConfigVal> = Vec::new();

        let proof = StarkProver::new(default_config())
            .prove(&air, trace, &public_values)
            .expect("prove");
        // KeccakAir declares no public values; supplying one makes verification reject.
        let bogus = alloc::vec![ConfigVal::ONE];
        assert!(
            StarkVerifier::new(default_config())
                .verify(&air, &proof, &bogus)
                .is_err(),
            "verifier must reject a public-value-count mismatch"
        );
    }
}
