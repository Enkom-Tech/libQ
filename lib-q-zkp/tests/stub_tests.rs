//! Constraint soundness tests for TransactionAir and StateTransitionAir.
//!
//! TransactionAir enforces tx_type ∈ {0,1,2}. StateTransitionAir uses a hash-commitment
//! approach for ML-DSA: the verifier checks the signature outside the STARK and the AIR
//! constrains the trace's signature-commitment column to match.

#![cfg(feature = "zkp")]

use lib_q_stark_matrix::Matrix;
use lib_q_zkp::air::TraceGenerator;
use lib_q_zkp::air::state_transition::{
    MAX_TRANSACTION_SIZE,
    STATE_HASH_SIZE,
    StateTransitionAir,
    StateTransitionInput,
    TransitionConstraints,
};
use lib_q_zkp::air::transaction::{
    SignatureMode,
    TransactionAir,
    TransactionInput,
    TransactionType,
};
use lib_q_zkp::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
};

/// TransactionAir constrains column 0 (tx_type) to ∈ {0, 1, 2}. Corrupting it to 100 must fail verify.
#[test]
#[cfg(not(debug_assertions))]
fn test_transaction_constraint_soundness() {
    let air = TransactionAir::new(TransactionType::Payment, SignatureMode::None);
    let input = TransactionInput {
        transaction_data: vec![1, 2, 3],
        signatures: vec![],
    };
    let trace = air.generate_trace(&input).unwrap();
    let pv = air.public_values(&input);

    let mut bad_trace = trace;
    if !bad_trace.values.is_empty() {
        bad_trace.values[0] += lib_q_stark_field::extension::Complex::from(
            lib_q_stark_mersenne31::Mersenne31::new(100),
        );
    }

    let proof = StarkProver::new(default_config()).prove(&air, bad_trace, &pv);
    let verify_result = StarkVerifier::new(default_config()).verify(&air, &proof, &pv);
    assert!(
        verify_result.is_err(),
        "Corrupting tx_type column must cause verify to fail"
    );
}

/// StateTransitionAir with signature commitment: valid trace (commitment matches) must verify.
#[test]
fn test_state_transition_signature_commitment_valid() {
    let mut constraints = TransitionConstraints::default();
    constraints.verify_balances = false;
    constraints.verify_signatures = true;
    constraints.signature_commitment = Some([7u8; 32]);
    let air = StateTransitionAir::new([0u8; 32], [1u8; 32], constraints);
    let input = StateTransitionInput {
        transaction_data: vec![1, 2, 3, 4, 5],
    };
    let trace = air.generate_trace(&input).unwrap();
    let pv = air.public_values(&input);

    let proof = StarkProver::new(default_config()).prove(&air, trace, &pv);
    let verify_result = StarkVerifier::new(default_config()).verify(&air, &proof, &pv);
    assert!(
        verify_result.is_ok(),
        "Valid trace with matching signature commitment must verify"
    );
}

/// StateTransitionAir with signature commitment: mutating the commitment region must fail verify.
#[test]
#[cfg(not(debug_assertions))]
fn test_state_transition_signature_commitment_soundness() {
    let mut constraints = TransitionConstraints::default();
    constraints.verify_balances = false;
    constraints.verify_signatures = true;
    constraints.signature_commitment = Some([7u8; STATE_HASH_SIZE]);
    let air = StateTransitionAir::new([0u8; 32], [1u8; 32], constraints);
    let input = StateTransitionInput {
        transaction_data: vec![1, 2, 3, 4, 5],
    };
    let trace = air.generate_trace(&input).unwrap();
    let pv = air.public_values(&input);

    let proof_start = STATE_HASH_SIZE + MAX_TRANSACTION_SIZE + STATE_HASH_SIZE;
    let mut bad_trace = trace;
    if proof_start < bad_trace.width() && !bad_trace.values.is_empty() {
        bad_trace.values[proof_start] +=
            lib_q_stark_field::extension::Complex::from(lib_q_stark_mersenne31::Mersenne31::new(1));
    }

    let proof = StarkProver::new(default_config()).prove(&air, bad_trace, &pv);
    let verify_result = StarkVerifier::new(default_config()).verify(&air, &proof, &pv);
    assert!(
        verify_result.is_err(),
        "Corrupting signature commitment column must cause verify to fail"
    );
}
