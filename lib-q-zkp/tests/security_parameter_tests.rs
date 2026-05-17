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

#[test]
fn test_default_config_classical_soundness_minimum() {
    let (log_blowup, num_queries, pow_bits) = default_fri_params_for_tests();
    let classical = log_blowup * num_queries + pow_bits;
    assert!(
        classical >= 200,
        "default_config must provide >= 200 bits classical soundness, got {}",
        classical
    );
}

#[test]
fn test_default_config_pq_soundness_minimum() {
    let (log_blowup, num_queries, pow_bits) = default_fri_params_for_tests();
    let classical = log_blowup * num_queries + pow_bits;
    let pq = classical / 2;
    assert!(
        pq >= 100,
        "default_config must provide >= 100 bits PQ soundness, got {}",
        pq
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
