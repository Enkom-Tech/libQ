//! Security parameter tests: enforce minimum query counts, blowup, and proof-of-work
//! for production configs; ensure test params are obviously insecure.

#![cfg(feature = "zkp")]

use lib_q_stark_commit::ExtensionMmcs;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_fri::{
    FriParameters,
    create_test_fri_params,
};
use lib_q_stark_merkle::MerkleTreeMmcs;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_stark_shake256::Shake256Hash;
use lib_q_stark_symmetric::{
    CompressionFunctionFromHasher,
    SerializingHasher,
};
use lib_q_zkp::stark::default_fri_params_for_tests;

// HONEST proof-system soundness = min over ALL terms, not just the FRI query phase:
//   - challenge field (Fiat–Shamir / DEEP): cannot exceed |F_challenge|, minus a small
//     Schwartz–Zippel degree·domain term (~11 bits);
//   - FRI query phase (conjectured / deployed regime): log_blowup·num_queries + PoW;
//   - hash commitment: SHAKE256/256 → 128-bit collision (NIST Cat-2).
// The earlier tests omitted the challenge-field term and so FALSELY certified `default_config`
// (whose challenge field is the ~62-bit value field `Complex<Mersenne31>`) at ≥200/≥100 bits.
const M31_BITS: f64 = 31.0;
const DEEP_TERM_BITS: f64 = 11.0; // ~log2(max_constraint_degree · LDE_domain), conservative
const HASH_COLLISION_BITS: f64 = 128.0; // SHAKE256/256

fn min_soundness_bits(
    challenge_field_bits: f64,
    log_blowup: usize,
    num_queries: usize,
    pow_bits: usize,
) -> f64 {
    let field = challenge_field_bits - DEEP_TERM_BITS;
    let query_conjectured = (log_blowup * num_queries + pow_bits) as f64;
    field.min(query_conjectured).min(HASH_COLLISION_BITS)
}

/// `default_config` (the SHARED Arm A config used by recursion / auth / credential) uses the value
/// field `Complex<Mersenne31>` (~62 bits) as its FRI challenge field, which HARD-CAPS its
/// Fiat–Shamir/DEEP soundness near 62 bits regardless of query count. This test documents that
/// honestly — it is NOT a 128-bit config and must not be presented as one. (Membership uses the
/// separate degree-3-challenge-field config; see below.)
#[test]
fn test_default_config_is_challenge_field_bound_below_128() {
    let (log_blowup, num_queries, pow_bits) = default_fri_params_for_tests();
    let challenge_field_bits = 2.0 * M31_BITS; // Complex<Mersenne31> = GF(p^2)
    let bits = min_soundness_bits(challenge_field_bits, log_blowup, num_queries, pow_bits);
    assert!(
        bits < 128.0,
        "default_config is challenge-field-bound; expected < 128-bit, got {bits}"
    );
    assert!(
        bits >= 50.0,
        "default_config soundness sanity floor (~62-bit field minus DEEP), got {bits}"
    );
}

/// The Arm A **membership** config raises the FRI challenge field to the degree-3 extension over
/// `Complex<Mersenne31>` = `GF(p^6)` (~186 bits) with FRI `log_blowup 3 / q 96 / PoW 20`, so the
/// FS/DEEP term is no longer the binder and the proof-system soundness reaches the 128-bit hash
/// floor (classical AND post-quantum, mainstream/deployed QROM model). Mirrors the Arm B
/// `fri_soundness.py` accounting.
#[test]
fn test_membership_config_reaches_128bit_classical_and_pq() {
    let challenge_field_bits = 6.0 * M31_BITS; // BinomialExtensionField<Complex<Mersenne31>, 3> = GF(p^6)
    let bits = min_soundness_bits(challenge_field_bits, 3, 96, 20);
    assert!(
        bits >= 128.0,
        "membership_config must reach >= 128-bit, got {bits}"
    );
    // PQ (mainstream model): IOP soundness preserved in QROM; SHAKE256/256 = NIST Cat-2 128-bit
    // collision; only the PoW grinding is Grover-halved. The binding term is the hash at 128, so the
    // PQ level equals the classical here.
    assert!(
        bits >= 128.0,
        "membership_config must reach >= 128-bit post-quantum, got {bits}"
    );
}

#[test]
fn test_default_config_num_queries_minimum() {
    let (_log_blowup, num_queries, _pow_bits) = default_fri_params_for_tests();
    assert!(
        num_queries >= 80,
        "default_config num_queries must be >= 80, got {}",
        num_queries
    );
}

#[test]
fn test_default_config_proof_of_work_bits_minimum() {
    let (_log_blowup, _num_queries, pow_bits) = default_fri_params_for_tests();
    assert!(
        pow_bits >= 16,
        "default_config proof_of_work_bits must be >= 16, got {}",
        pow_bits
    );
}

#[test]
fn test_default_config_log_blowup_minimum() {
    let (log_blowup, _num_queries, _pow_bits) = default_fri_params_for_tests();
    assert!(
        log_blowup >= 1,
        "default_config log_blowup must be >= 1, got {}",
        log_blowup
    );
}

#[test]
fn test_test_fri_params_are_obviously_insecure() {
    type Val = Complex<Mersenne31>;
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    type ValMmcs =
        MerkleTreeMmcs<<Val as lib_q_stark_field::Field>::Packing, u8, MyHash, MyCompress, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Val, ValMmcs>;

    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs);

    let p = create_test_fri_params(challenge_mmcs, 2);
    let soundness = p.log_blowup * p.num_queries + p.proof_of_work_bits;
    assert!(
        soundness < 20,
        "test FRI params must be obviously insecure (soundness < 20), got {}",
        soundness
    );
}

#[test]
fn test_zero_queries_is_rejected() {
    type Val = Complex<Mersenne31>;
    type MyHash = SerializingHasher<Shake256Hash>;
    type MyCompress = CompressionFunctionFromHasher<Shake256Hash, 2, 32>;
    type ValMmcs =
        MerkleTreeMmcs<<Val as lib_q_stark_field::Field>::Packing, u8, MyHash, MyCompress, 32>;
    type ChallengeMmcs = ExtensionMmcs<Val, Val, ValMmcs>;

    let shake256 = Shake256Hash {};
    let hash = MyHash::new(shake256);
    let compress = MyCompress::new(shake256);
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs);

    let params = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        num_queries: 0,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let result = params.validate();
    assert!(
        result.is_err(),
        "FriParameters with num_queries=0 must be rejected"
    );
}
