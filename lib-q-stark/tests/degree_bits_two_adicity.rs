//! Regression tests for the `degree_bits` / field-two-adicity verifier defect (B2).
//!
//! `MAX_DEGREE_BITS` (30, in `verifier.rs`) is field-independent, but every concrete field used in
//! this workspace has a two-adicity below 30 -- BabyBear's is 27 (`Complex<Mersenne31>`'s is 32,
//! which is why `dos_protection_tests.rs`'s Mersenne31-based tests can't reproduce this: 30 never
//! exceeds 32). A `degree_bits` anywhere in the resulting gap -- combined with a nonzero
//! `log_num_quotient_chunks` (or `is_zk`) -- drives `Pcs::natural_domain_for_degree` /
//! `PolynomialSpace::create_disjoint_domain` past the field's two-adicity. Both are implemented as
//! `TwoAdicMultiplicativeCoset::new(...).unwrap()` and `.unwrap()` on `None` panics
//! (`lib-q-stark-fri/src/two_adic_pcs.rs:227`, `lib-q-stark-commit/src/domain.rs:175`), and this
//! was reachable BEFORE any shape validation (`valid_shape`) in `verify_with_preprocessed`,
//! `initial_fri_eval_for_query`, and `all_fri_reduced_openings_for_query` -- an unauthenticated,
//! deserialization-only remote DoS (the audit reproduced it with an 84-byte and a 111-byte proof
//! via `lib_q_zkp`/`lib_q_mve`, which both route into `verify_with_preprocessed`).
//!
//! These tests build one real, honestly-generated small proof (`degree_bits` small enough to be
//! valid) and then tamper only the `degree_bits` field before re-verifying -- the cheapest way to
//! reach the vulnerable code path without needing an actual large trace.

#![allow(clippy::clone_on_copy)]

use lib_q_stark::{
    StarkConfig,
    VerificationError,
    prove,
    verify,
    verify_with_preprocessed,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_baby_bear::{
    BabyBear,
    BabyBearDft,
};
use lib_q_stark_challenger::Shake256Challenger32;
use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_fri::{
    FriParameters,
    TwoAdicFriPcs,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_merkle::MerkleTreeMmcs;
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    SerializingHasher,
};
use rand::distr::{
    Distribution,
    StandardUniform,
};

// BabyBear (TWO_ADICITY = 27), scalar-field config -- mirrors
// `lib-q-zkp/src/stark_baby_bear.rs::BbConfig`'s proven-working type wiring (leaf type is the
// scalar `BabyBear`, not `<BabyBear as Field>::Packing`, for cross-architecture SIMD-packing
// reasons documented there), simplified to use `BabyBear` itself as the challenge field (no
// extension needed -- this test doesn't care about FRI soundness, only about the verifier
// rejecting/panicking on a malformed `degree_bits`).
type Val = BabyBear;
type Challenge = Val;
type Dft = BabyBearDft;
type MyHash = SerializingHasher<Shake256Hash>;
type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
type ValMmcs = MerkleTreeMmcs<Val, u8, MyHash, MyCompress, 32>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Challenger = Shake256Challenger32<Val>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Minimal AIR for testing: asserts that column 0 equals column 1 and increments by one each row
/// (same shape as `dos_protection_tests.rs::SimpleAir`, just over BabyBear instead of Mersenne31).
#[derive(Default, Clone)]
struct SimpleAir;

impl<F> BaseAir<F> for SimpleAir {
    fn width(&self) -> usize {
        2
    }
}

impl<AB: AirBuilder> Air<AB> for SimpleAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        builder.assert_zero(local[0].clone() - local[1].clone());
        builder
            .when_transition()
            .assert_eq(local[0].clone() + AB::Expr::ONE, next[0].clone());
    }
}

fn create_test_config() -> MyConfig {
    let shake = Shake256Hash {};
    let hash = MyHash::new(shake);
    let compress = MyCompress::new(shake);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 3,
        num_queries: 8,
        proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::from_hasher(Vec::new(), Shake256Hash);
    StarkConfig::new(pcs, challenger)
}

/// A real, honestly-generated small proof: `degree_bits` will be tiny (height 32 => `degree_bits =
/// 5`). We only care about tampering `degree_bits` afterwards; everything else in the proof is
/// exactly what a legitimate prover would produce.
fn create_valid_proof() -> (MyConfig, SimpleAir, lib_q_stark::Proof<MyConfig>)
where
    StandardUniform: Distribution<Val>,
{
    let config = create_test_config();
    let air = SimpleAir;

    let height = 32;
    let mut trace_values = Vec::new();
    for i in 0..height {
        let val = Val::from_usize(i);
        trace_values.push(val);
        trace_values.push(val);
    }
    let trace = RowMajorMatrix::new(trace_values, 2);

    let proof = prove(&config, &air, trace, &[]).expect("prove");
    (config, air, proof)
}

/// Sanity check: the untampered proof verifies (confirms the config/AIR/proof plumbing above is
/// actually correct, so a later `Err`/panic is caused by the `degree_bits` tamper, not by a setup
/// bug in this test file).
#[test]
fn baseline_proof_verifies()
where
    StandardUniform: Distribution<Val>,
{
    let (config, air, proof) = create_valid_proof();
    assert_eq!(
        proof.degree_bits, 5,
        "sanity: expected height-32 trace to give degree_bits = 5"
    );
    assert!(
        verify(&config, &air, &proof, &[]).is_ok(),
        "untampered proof must verify"
    );
}

/// `degree_bits = 27` is exactly BabyBear's TWO_ADICITY. For this minimal (all-degree-1-constraint)
/// AIR, `log_num_quotient_chunks` is small enough that `27 + log_num_quotient_chunks + is_zk` does
/// NOT exceed 27, so the two-adicity guard correctly does NOT reject this one -- it must not be so
/// aggressive that it rejects a `degree_bits` that fits the field. The proof still fails, because
/// `degree_bits` was tampered after proving (so the reconstructed domains no longer match the
/// proof's actual commitments/openings) -- but it fails with a normal opening-argument mismatch,
/// not `InvalidProofShape` from the guard, and (this is the point of this test) not a panic.
#[test]
fn degree_bits_27_at_two_adicity_boundary_does_not_panic()
where
    StandardUniform: Distribution<Val>,
{
    let (config, air, mut proof) = create_valid_proof();
    proof.degree_bits = 27;

    let result = verify(&config, &air, &proof, &[]);
    assert!(
        result.is_err(),
        "a proof tampered to a mismatched (if in-range) degree_bits must not verify: {result:?}"
    );
}

/// `degree_bits = 30` is `MAX_DEGREE_BITS` exactly -- passes the field-independent cap but is far
/// beyond BabyBear's two-adicity (27) even before adding `log_num_quotient_chunks`.
#[test]
fn degree_bits_30_rejected_not_panicking()
where
    StandardUniform: Distribution<Val>,
{
    let (config, air, mut proof) = create_valid_proof();
    proof.degree_bits = 30;

    let result = verify(&config, &air, &proof, &[]);
    assert!(
        result.is_err(),
        "degree_bits = 30 must be rejected, not accepted: {result:?}"
    );
    assert!(
        matches!(result, Err(VerificationError::InvalidProofShape)),
        "degree_bits = 30 must reject with InvalidProofShape, got: {result:?}"
    );
}

/// `degree_bits` just past `TWO_ADICITY` alone (28 > 27) with a minimal-degree AIR still rejects
/// cleanly -- pins the boundary rather than only testing comfortably-over-the-line values.
#[test]
fn degree_bits_28_rejected_not_panicking()
where
    StandardUniform: Distribution<Val>,
{
    let (config, air, mut proof) = create_valid_proof();
    proof.degree_bits = 28;

    let result = verify(&config, &air, &proof, &[]);
    assert!(
        matches!(result, Err(VerificationError::InvalidProofShape)),
        "degree_bits = 28 must reject with InvalidProofShape, got: {result:?}"
    );
}

/// `verify_with_preprocessed` directly (the function named in the audit/brief), not just the
/// `verify()` convenience wrapper.
#[test]
fn verify_with_preprocessed_degree_bits_30_rejected_not_panicking()
where
    StandardUniform: Distribution<Val>,
{
    let (config, air, mut proof) = create_valid_proof();
    proof.degree_bits = 30;

    let result = verify_with_preprocessed(&config, &air, &proof, &[], None);
    assert!(
        matches!(result, Err(VerificationError::InvalidProofShape)),
        "degree_bits = 30 must reject with InvalidProofShape, got: {result:?}"
    );
}

/// A `degree_bits` that is comfortably small and valid must still verify -- the guard must not be
/// so aggressive that it rejects legitimate proofs.
#[test]
fn small_degree_bits_still_verifies()
where
    StandardUniform: Distribution<Val>,
{
    let (config, air, proof) = create_valid_proof();
    // degree_bits = 5 (from the height-32 trace) + log_num_quotient_chunks (small, this AIR is
    // degree 2) is nowhere near BabyBear's TWO_ADICITY = 27.
    assert!(
        verify(&config, &air, &proof, &[]).is_ok(),
        "small, legitimate degree_bits must still verify"
    );
}
