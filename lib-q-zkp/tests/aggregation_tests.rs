//! Aggregation tests: single proof, batch aggregation, Merkle root, and rejection of invalid batches.
//!
//! Recursive Poseidon tests use [`lib_q_zkp::stark::poseidon_test_config`] with a matching
//! [`AggregationConfig`] (2 FRI queries) so the suite finishes quickly. Triple-inner aggregation
//! plus [`verify_aggregated_proof`] is covered by `test_aggregate_merkle_root_covers_all_proofs`
//! (one expensive pass instead of a duplicate). The ignored
//! `test_aggregate_two_poseidon_proofs_verifies` still uses production-like FRI (100 queries).
//!
//! If you see flaky failures under load, run serially:
//! `cargo test -p lib-q-zkp --all-features --test aggregation_tests -- --test-threads=1`

#![cfg(feature = "zkp")]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::map_clone)]

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
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::air::recursive_types::serialize_stark_proof;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::air::stark_verifier::{
    StarkVerifierAir,
    build_recursive_verification_input_from_proof_with_poseidon,
    debug_one_fri_round,
};
use lib_q_zkp::air::{
    ArithmeticAir,
    TraceGenerator,
};
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::air::{
    MerkleInclusionAir,
    MerkleProofInput,
    merkle_root_from_bytes,
    poseidon_to_field,
};
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::api::{
    build_merkle_tree,
    merkle_path_from_tree,
};
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::check_constraints;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::stark::FriQueryParams;
use lib_q_zkp::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
};
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_zkp::stark::{
    poseidon_config,
    poseidon_test_config,
};

type Val = lib_q_stark_field::extension::Complex<Mersenne31>;

const MIN_TRACE_ROWS: usize = 64;

/// Must match FRI parameters from [`lib_q_zkp::stark::poseidon_test_config`].
#[cfg(feature = "recursive-proofs-experimental")]
fn aggregation_poseidon_test_match() -> AggregationConfig {
    AggregationConfig {
        merkle_tree_depth: 8,
        log_final_poly_len: 0,
        num_fri_queries: 2,
        fri_log_blowup: 2,
        fri_proof_of_work_bits: 1,
    }
}

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
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
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
    let p1 = StarkProver::new(default_config())
        .prove(&air, trace1, &pv1)
        .expect("prove");
    let p2 = StarkProver::new(default_config())
        .prove(&air, trace2, &pv2)
        .expect("prove");
    let p3 = StarkProver::new(default_config())
        .prove(&air, trace3, &pv3)
        .expect("prove");
    assert!(verify_batch(&[p1, p2, p3], &verifier, &air, &[pv1, pv2, pv3]).is_ok());
}

#[test]
fn test_verify_batch_rejects_invalid_second_proof() {
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(default_config());
    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);
    let p1 = StarkProver::new(default_config())
        .prove(&air, trace1, &pv1)
        .expect("prove");
    let mut p2 = StarkProver::new(default_config())
        .prove(&air, trace2, &pv2)
        .expect("prove");
    let bytes: [u8; 32] = p2.commitments.trace.into();
    let mut bad = bytes;
    bad[0] ^= 0x01;
    p2.commitments.trace = lib_q_stark_symmetric::Hash::from(bad);
    let result = verify_batch(&[p1, p2], &verifier, &air, &[pv1, pv2]);
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_aggregate_single_proof_verifies() {
    let config = poseidon_test_config();
    let agg_cfg = aggregation_poseidon_test_match();
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);
    let proof = StarkProver::new(config.clone())
        .prove(&air, trace, &pv)
        .expect("prove");
    let verifier = StarkVerifier::new(config.clone());

    let agg = ProofAggregator::new(vec![proof], config.clone())
        .unwrap()
        .aggregate_single(&verifier, &air, &[pv.clone()], agg_cfg)
        .unwrap();

    assert_eq!(agg.num_proofs, 1);
    assert!(verify_aggregated_proof(&agg, agg.agg_config.clone(), config).unwrap());
}

/// Full batch aggregation (`aggregate`): recursive proof over `BatchStarkVerifierAir` with Poseidon inner proofs.
///
/// Ignored in the default suite: outer batch recursive prove + verify can take many minutes (100 FRI queries).
/// Run: `cargo test -p lib-q-zkp --all-features --test aggregation_tests test_aggregate_two_poseidon_proofs_verifies -- --ignored`
#[test]
#[ignore = "slow: batch recursive STARK prove+verify (many minutes)"]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_aggregate_two_poseidon_proofs_verifies() {
    let config = poseidon_config();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());

    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);

    let p1 = StarkProver::new(config.clone())
        .prove(&air, trace1, &pv1)
        .expect("prove");
    let p2 = StarkProver::new(config.clone())
        .prove(&air, trace2, &pv2)
        .expect("prove");

    let agg = ProofAggregator::new(vec![p1, p2], config.clone())
        .unwrap()
        .aggregate(&verifier, &air, &[pv1, pv2], AggregationConfig::default())
        .unwrap();

    assert_eq!(agg.num_proofs, 2);
    assert!(agg.all_inner_serialized_proofs.is_some());
    assert!(verify_aggregated_proof(&agg, agg.agg_config.clone(), config).unwrap());
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_aggregate_rejects_invalid_second_proof() {
    let config = poseidon_test_config();
    let agg_cfg = aggregation_poseidon_test_match();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());

    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);

    let p1 = StarkProver::new(config.clone())
        .prove(&air, trace1, &pv1)
        .expect("prove");
    let mut p2 = StarkProver::new(config.clone())
        .prove(&air, trace2, &pv2)
        .expect("prove");
    // Corrupt trace commitment (Poseidon digest is Hash<Complex, Complex, 1>)
    let mut arr: [Val; 1] = p2.commitments.trace.into();
    arr[0] = arr[0] + <Val as PrimeCharacteristicRing>::ONE;
    p2.commitments.trace = lib_q_stark_symmetric::Hash::from(arr);

    let aggregator = ProofAggregator::new(vec![p1, p2], config).unwrap();
    let result = aggregator.aggregate_single(&verifier, &air, &[pv1, pv2], agg_cfg);

    assert!(result.is_err());
}

/// Three inner Poseidon proofs: Merkle binding over serialized commitments, `aggregate_single`,
/// and aggregated outer proof verification (same coverage as the former `test_aggregate_three_proofs_all_pass`).
#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_aggregate_merkle_root_covers_all_proofs() {
    use lib_q_sha3::Shake256;
    use lib_q_sha3::digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };

    let config = poseidon_test_config();
    let agg_cfg = aggregation_poseidon_test_match();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());

    let (trace1, pv1) = make_arithmetic_trace_and_pv(3, 4);
    let (trace2, pv2) = make_arithmetic_trace_and_pv(5, 6);
    let (trace3, pv3) = make_arithmetic_trace_and_pv(7, 8);

    let p1 = StarkProver::new(config.clone())
        .prove(&air, trace1, &pv1)
        .expect("prove");
    let p2 = StarkProver::new(config.clone())
        .prove(&air, trace2, &pv2)
        .expect("prove");
    let p3 = StarkProver::new(config.clone())
        .prove(&air, trace3, &pv3)
        .expect("prove");

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

    let agg = ProofAggregator::new(vec![p1, p2, p3], config.clone())
        .unwrap()
        .aggregate_single(&verifier, &air, &[pv1, pv2, pv3], agg_cfg)
        .unwrap();

    assert_eq!(agg.num_proofs, 3);
    assert_eq!(agg.proofs_root, expected_root);
    assert!(verify_aggregated_proof(&agg, agg.agg_config.clone(), config).unwrap());
}

/// Regression test: build recursive verification input, generate verifier trace,
/// run check_constraints on it, then run full prove + verify.
#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_recursive_verifier_trace_satisfies_constraints_then_prove_verify() {
    let config = poseidon_test_config();
    let agg_config = aggregation_poseidon_test_match();
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);
    let proof = StarkProver::new(config.clone())
        .prove(&air, trace, &pv)
        .expect("prove");
    let verifier = StarkVerifier::new(config.clone());

    let (zeta, zeta_next, alpha, betas) = verifier.derive_challenges(&air, &proof, &pv).unwrap();
    let serialized =
        serialize_stark_proof(&proof, pv.clone(), zeta, zeta_next, alpha, &betas).unwrap();
    let fri_params = FriQueryParams {
        num_queries: agg_config.num_fri_queries,
        log_blowup: agg_config.fri_log_blowup,
        log_final_poly_len: agg_config.log_final_poly_len,
        proof_of_work_bits: agg_config.fri_proof_of_work_bits,
    };
    let recursive_input = build_recursive_verification_input_from_proof_with_poseidon(
        &verifier,
        &air,
        &proof,
        &pv,
        &serialized,
        agg_config.merkle_tree_depth,
        &fri_params,
    )
    .expect("build recursive input");

    // Debug FRI folding: compare builder vs verifier-style fold for round 0 and last round
    let fri = &recursive_input.fri_inputs;
    let num_rounds = fri.fri_rounds.len();
    let log_final_height = fri_params.log_blowup + fri_params.log_final_poly_len;
    let query_idx0 = fri.query_indices.first().copied().unwrap_or(0);
    let eval_point = fri.final_poly_eval_point;
    if num_rounds > 0 {
        debug_one_fri_round(
            0,
            query_idx0,
            log_final_height,
            num_rounds,
            &fri.round_current_evals,
            &fri.round_sibling_evals,
            &fri.round_domain_point_inverses,
            &fri.round_betas,
            Some(&fri.round_roll_ins),
            &fri.final_poly,
            eval_point,
        );
        if num_rounds > 1 {
            debug_one_fri_round(
                num_rounds - 1,
                query_idx0,
                log_final_height,
                num_rounds,
                &fri.round_current_evals,
                &fri.round_sibling_evals,
                &fri.round_domain_point_inverses,
                &fri.round_betas,
                Some(&fri.round_roll_ins),
                &fri.final_poly,
                eval_point,
            );
        }
    }

    let verifier_air = StarkVerifierAir::new(
        serialized.clone(),
        agg_config.merkle_tree_depth,
        agg_config.log_final_poly_len,
        agg_config.num_fri_queries,
    )
    .expect("StarkVerifierAir::new");

    let trace_matrix = verifier_air
        .generate_trace(&recursive_input)
        .expect("generate trace");

    // Merkle root consistency check: expected_roots must match root recomputed from path
    {
        let num_commitments = recursive_input.commitment_inputs.expected_roots.len();
        let tree_depth = agg_config.merkle_tree_depth;
        let merkle_air = MerkleInclusionAir::new(tree_depth).expect("MerkleInclusionAir::new");
        for commit_idx in 0..num_commitments {
            let expected_root = recursive_input.commitment_inputs.expected_roots[commit_idx];
            let merkle_proof = &recursive_input.commitment_inputs.merkle_proofs[commit_idx];
            assert!(
                merkle_proof.leaf_hash_direct.is_some(),
                "commit_idx {}: leaf_hash_direct must be set for recursive proofs",
                commit_idx
            );
            let recomputed_pv = merkle_air.public_values(merkle_proof);
            let recomputed_root_field = recomputed_pv.first().copied().unwrap_or(Val::ZERO);
            let expected_root_field = merkle_root_from_bytes(&expected_root[..])
                .map(|pf| poseidon_to_field::<Val>(&pf))
                .expect("expected_roots must be valid Poseidon root encoding");
            assert_eq!(
                expected_root_field,
                recomputed_root_field,
                "commit_idx {}: expected_root (field) != merkle_recomputed_root (field); \
                 expected_roots[{}] first 8 bytes = {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                commit_idx,
                commit_idx,
                expected_root[0],
                expected_root[1],
                expected_root[2],
                expected_root[3],
                expected_root[4],
                expected_root[5],
                expected_root[6],
                expected_root[7]
            );
            #[cfg(feature = "trace-debug")]
            std::println!("✓ commit_idx {}: expected_root == merkle_root", commit_idx);
        }
    }

    // Sanity check: log commitment segment so we can distinguish AIR wiring from leaf/root mismatch
    #[cfg(feature = "std")]
    {
        const METADATA_WIDTH: usize = 4;
        let num_commitments = recursive_input.commitment_inputs.expected_roots.len();
        lib_q_zkp::air::debug_commitment_trace_sanity_check(
            &trace_matrix,
            &recursive_input.commitment_inputs,
            METADATA_WIDTH,
            num_commitments,
            agg_config.merkle_tree_depth,
        );
    }

    check_constraints(
        &verifier_air,
        &trace_matrix,
        &serialized.expected_public_values,
    );

    let agg = ProofAggregator::new(vec![proof], config.clone())
        .unwrap()
        .aggregate_single(&verifier, &air, &[pv], agg_config)
        .unwrap();
    assert!(verify_aggregated_proof(&agg, agg.agg_config.clone(), config).unwrap());
}

/// Merkle-inclusion proof with [`lib_q_zkp::stark::poseidon_test_config`]: create and verify. Validates that Merkle certificates
/// can be produced with the same config used by the recursive pipeline (Poseidon FRI commitments).
/// Full recursive input building (and thus aggregate_single) for Merkle-inclusion inner proofs
/// is a follow-up when FRI opening extraction supports this AIR shape.
#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_merkle_inclusion_proof_with_poseidon_config_creates_and_verifies() {
    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1", b"leaf2"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let path = merkle_path_from_tree(&tree, 0).unwrap();
    let merkle_input = MerkleProofInput {
        leaf: leaves[0].to_vec(),
        leaf_hash_direct: None,
        path_bits: path.path_bits,
        siblings: path.siblings,
    };

    let merkle_air = MerkleInclusionAir::new(tree.depth()).expect("MerkleInclusionAir::new");
    let trace_one: lib_q_stark_matrix::dense::RowMajorMatrix<Val> = merkle_air
        .generate_trace(&merkle_input)
        .expect("generate trace");
    let width = trace_one.width();
    let mut padded_values = Vec::with_capacity(MIN_TRACE_ROWS * width);
    let row0: Vec<Val> = (0..width)
        .map(|c| trace_one.get(0, c).map(|r| r.clone()).unwrap_or(Val::ZERO))
        .collect();
    for _ in 0..MIN_TRACE_ROWS {
        padded_values.extend_from_slice(&row0);
    }
    let trace = lib_q_stark_matrix::dense::RowMajorMatrix::new(padded_values, width);
    let pv = merkle_air.public_values(&merkle_input);

    let config = poseidon_test_config();
    let proof = StarkProver::new(config.clone())
        .prove(&merkle_air, trace, &pv)
        .expect("prove");
    let verifier = StarkVerifier::new(config);
    verifier
        .verify(&merkle_air, &proof, &pv)
        .expect("Merkle-inclusion proof with poseidon_test_config must verify");
}

#[test]
fn test_aggregate_rejects_empty_batch() {
    let result = ProofAggregator::new(vec![], default_config());
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_aggregate_rejects_public_values_length_mismatch_for_batch() {
    let config = poseidon_test_config();
    let agg_cfg = aggregation_poseidon_test_match();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());
    let (t1, pv1) = make_arithmetic_trace_and_pv(2, 3);
    let (t2, pv2) = make_arithmetic_trace_and_pv(4, 5);
    let p1 = StarkProver::new(config.clone())
        .prove(&air, t1, &pv1)
        .expect("prove");
    let p2 = StarkProver::new(config.clone())
        .prove(&air, t2, &pv2)
        .expect("prove");
    let agg = ProofAggregator::new(vec![p1, p2], config).unwrap();
    let err = match agg.aggregate(&verifier, &air, &[pv1], agg_cfg) {
        Ok(_) => panic!("expected length mismatch"),
        Err(e) => e,
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("aggregate") && msg.contains("length"),
        "unexpected error: {}",
        msg
    );
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_aggregate_single_rejects_public_values_length_mismatch() {
    let config = poseidon_test_config();
    let agg_cfg = aggregation_poseidon_test_match();
    let air = ArithmeticAir::new(1).unwrap();
    let verifier = StarkVerifier::new(config.clone());
    let (t1, pv1) = make_arithmetic_trace_and_pv(2, 3);
    let (t2, pv2) = make_arithmetic_trace_and_pv(4, 5);
    let p1 = StarkProver::new(config.clone())
        .prove(&air, t1, &pv1)
        .expect("prove");
    let p2 = StarkProver::new(config.clone())
        .prove(&air, t2, &pv2)
        .expect("prove");
    let agg = ProofAggregator::new(vec![p1, p2], config).unwrap();
    let err = match agg.aggregate_single(&verifier, &air, &[pv1], agg_cfg) {
        Ok(_) => panic!("expected length mismatch"),
        Err(e) => e,
    };
    let msg = format!("{}", err);
    assert!(
        msg.contains("aggregate_single") && msg.contains("length"),
        "unexpected error: {}",
        msg
    );
}

#[test]
#[cfg(feature = "recursive-proofs-experimental")]
fn test_debug_one_fri_round_returns_early_when_round_index_invalid() {
    let rounds = [Val::ZERO];
    debug_one_fri_round(
        99,
        0,
        1,
        1,
        &rounds,
        &rounds,
        &rounds,
        &rounds,
        None,
        &[],
        Val::ZERO,
    );
    debug_one_fri_round(
        0,
        0,
        1,
        1,
        &[],
        &rounds,
        &rounds,
        &rounds,
        None,
        &[Val::ZERO],
        Val::ZERO,
    );
}
