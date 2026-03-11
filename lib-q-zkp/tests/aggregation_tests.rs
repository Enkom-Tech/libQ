//! Aggregation tests: single proof, batch aggregation, Merkle root, and rejection of invalid batches.

#![cfg(feature = "zkp")]

#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_mersenne31::Mersenne31;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::aggregation::{
    AggregationConfig,
    verify_aggregated_proof,
};
use lib_q_zkp::aggregation::{
    ProofAggregator,
    verify_batch,
};
use lib_q_zkp::air::{
    ArithmeticAir,
    TraceGenerator,
};
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::stark::poseidon_config;
use lib_q_zkp::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
};

type Val = lib_q_stark_field::extension::Complex<Mersenne31>;

const MIN_TRACE_ROWS: usize = 64;

fn make_arithmetic_trace_and_pv(
    a: u32,
    b: u32,
) -> (lib_q_stark_matrix::dense::RowMajorMatrix<Val>, Vec<Val>) {
    let air = ArithmeticAir::new(1).unwrap();
    let product = a * b;
    let inputs = vec![(Val::from(Mersenne31::new(a)), Val::from(Mersenne31::new(b)))];
    let trace = air.generate_trace(&inputs).unwrap();
    let width = trace.width();
    let current_height = trace.height();
    let mut padded_values = trace.values.clone();
    if current_height < MIN_TRACE_ROWS {
        let row: Vec<Val> = (0..width)
            .map(|i| {
                if i % 3 == 0 {
                    Val::from(Mersenne31::new(a))
                } else if i % 3 == 1 {
                    Val::from(Mersenne31::new(b))
                } else {
                    Val::from(Mersenne31::new(product))
                }
            })
            .collect();
        for _ in current_height..MIN_TRACE_ROWS {
            padded_values.extend_from_slice(&row);
        }
    }
    let trace = lib_q_stark_matrix::dense::RowMajorMatrix::new(padded_values, width);
    let pv = vec![Val::from(Mersenne31::new(product))];
    (trace, pv)
}

#[test]
fn test_verify_batch_single_proof() {
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);
    let proof = StarkProver::new(default_config()).prove(&air, trace, &pv);
    let verifier = StarkVerifier::new(default_config());
    assert!(verify_batch(&[proof], &verifier, &air, &[pv]).is_ok());
}

#[test]
fn test_verify_batch_three_proofs() {
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(default_config());
    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);
    let (trace3, pv3) = make_arithmetic_trace_and_pv(7, 8);
    let p1 = StarkProver::new(default_config()).prove(&air, trace1, &pv1);
    let p2 = StarkProver::new(default_config()).prove(&air, trace2, &pv2);
    let p3 = StarkProver::new(default_config()).prove(&air, trace3, &pv3);
    assert!(verify_batch(&[p1, p2, p3], &verifier, &air, &[pv1, pv2, pv3]).is_ok());
}

#[test]
fn test_verify_batch_rejects_invalid_second_proof() {
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(default_config());
    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);
    let p1 = StarkProver::new(default_config()).prove(&air, trace1, &pv1);
    let mut p2 = StarkProver::new(default_config()).prove(&air, trace2, &pv2);
    let bytes: [u8; 32] = p2.commitments.trace.into();
    let mut bad = bytes;
    bad[0] ^= 0x01;
    p2.commitments.trace = lib_q_stark_symmetric::Hash::from(bad);
    let result = verify_batch(&[p1, p2], &verifier, &air, &[pv1, pv2]);
    assert!(result.is_err());
}

/// Fiat-Shamir transcript fixed; still fails at check_constraints (constraint eval mismatch in recursive verification).
#[test]
#[cfg(feature = "recursive-proofs-experimental")]
#[ignore = "recursive verification constraint mismatch in check_constraints; see FriVerifierAir/StarkVerifierAir"]
fn test_aggregate_single_proof_verifies() {
    let config = poseidon_config();
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);
    let proof = StarkProver::new(config.clone()).prove(&air, trace, &pv);
    let verifier = StarkVerifier::new(config.clone());

    let agg = ProofAggregator::new(vec![proof], config.clone())
        .unwrap()
        .aggregate_single(&verifier, &air, &[pv.clone()], AggregationConfig::default())
        .unwrap();

    assert_eq!(agg.num_proofs, 1);
    assert!(verify_aggregated_proof(&agg, agg.agg_config.clone(), config).unwrap());
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
#[ignore = "recursive verification constraint mismatch in check_constraints; see FriVerifierAir/StarkVerifierAir"]
fn test_aggregate_three_proofs_all_pass() {
    let config = poseidon_config();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());

    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);
    let (trace3, pv3) = make_arithmetic_trace_and_pv(7, 8);

    let p1 = StarkProver::new(config.clone()).prove(&air, trace1, &pv1);
    let p2 = StarkProver::new(config.clone()).prove(&air, trace2, &pv2);
    let p3 = StarkProver::new(config.clone()).prove(&air, trace3, &pv3);

    let agg = ProofAggregator::new(vec![p1, p2, p3], config.clone())
        .unwrap()
        .aggregate_single(
            &verifier,
            &air,
            &[pv1, pv2, pv3],
            AggregationConfig::default(),
        )
        .unwrap();

    assert_eq!(agg.num_proofs, 3);
    assert!(verify_aggregated_proof(&agg, agg.agg_config.clone(), config).unwrap());
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_aggregate_rejects_invalid_second_proof() {
    let config = poseidon_config();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());

    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);

    let p1 = StarkProver::new(config.clone()).prove(&air, trace1, &pv1);
    let mut p2 = StarkProver::new(config.clone()).prove(&air, trace2, &pv2);
    // Corrupt trace commitment (Poseidon digest is Hash<Complex, Complex, 1>)
    let mut arr: [Val; 1] = p2.commitments.trace.into();
    arr[0] = arr[0] + <Val as PrimeCharacteristicRing>::ONE;
    p2.commitments.trace = lib_q_stark_symmetric::Hash::from(arr);

    let aggregator = ProofAggregator::new(vec![p1, p2], config).unwrap();
    let result =
        aggregator.aggregate_single(&verifier, &air, &[pv1, pv2], AggregationConfig::default());

    assert!(result.is_err());
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
#[ignore = "recursive verification constraint mismatch in check_constraints; see FriVerifierAir/StarkVerifierAir"]
fn test_aggregate_merkle_root_covers_all_proofs() {
    use lib_q_sha3::Shake256;
    use lib_q_sha3::digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };

    let config = poseidon_config();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());

    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);
    let (trace3, pv3) = make_arithmetic_trace_and_pv(7, 8);

    let p1 = StarkProver::new(config.clone()).prove(&air, trace1, &pv1);
    let p2 = StarkProver::new(config.clone()).prove(&air, trace2, &pv2);
    let p3 = StarkProver::new(config.clone()).prove(&air, trace3, &pv3);

    let (z1, zn1, a1, b1) = verifier.derive_challenges(&air, &p1, &pv1).unwrap();
    let serialized =
        lib_q_zkp::air::recursive_types::serialize_stark_proof(&p1, pv1.clone(), z1, zn1, a1, &b1)
            .unwrap();
    let (zeta2, zeta_next2, alpha2, betas2) = verifier.derive_challenges(&air, &p2, &pv2).unwrap();
    let serialized2 = lib_q_zkp::air::recursive_types::serialize_stark_proof(
        &p2,
        pv2.clone(),
        zeta2,
        zeta_next2,
        alpha2,
        &betas2,
    )
    .unwrap();
    let (zeta3, zeta_next3, alpha3, betas3) = verifier.derive_challenges(&air, &p3, &pv3).unwrap();
    let serialized3 = lib_q_zkp::air::recursive_types::serialize_stark_proof(
        &p3,
        pv3.clone(),
        zeta3,
        zeta_next3,
        alpha3,
        &betas3,
    )
    .unwrap();

    let mut hasher = Shake256::default();
    hasher.update(&serialized.trace_commitment_hash);
    hasher.update(&serialized.quotient_commitment_hash);
    if let Some(ref h) = serialized.random_commitment_hash {
        hasher.update(h);
    }
    hasher.update(&serialized2.trace_commitment_hash);
    hasher.update(&serialized2.quotient_commitment_hash);
    if let Some(ref h) = serialized2.random_commitment_hash {
        hasher.update(h);
    }
    hasher.update(&serialized3.trace_commitment_hash);
    hasher.update(&serialized3.quotient_commitment_hash);
    if let Some(ref h) = serialized3.random_commitment_hash {
        hasher.update(h);
    }
    let mut expected_root = [0u8; 32];
    hasher.finalize_xof().read(&mut expected_root);

    let agg = ProofAggregator::new(vec![p1, p2, p3], config)
        .unwrap()
        .aggregate_single(
            &verifier,
            &air,
            &[pv1, pv2, pv3],
            AggregationConfig::default(),
        )
        .unwrap();

    assert_eq!(agg.proofs_root, expected_root);
}

#[test]
fn test_aggregate_rejects_empty_batch() {
    let result = ProofAggregator::new(vec![], default_config());
    assert!(result.is_err());
}
