//! Zero-knowledge property tests: proof randomization in ZK mode, determinism in non-ZK mode,
//! and absence of raw witness leakage in serialized proof bytes.

#![cfg(feature = "zkp")]

use std::collections::BTreeSet;

use lib_q_stark_field::extension::Complex;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    ArithmeticAir,
    TraceGenerator,
};
use lib_q_zkp::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
    zk_config,
    zk_config_with_seeds,
};

type Val = Complex<Mersenne31>;

/// Minimum trace height for FRI (log_min_height > log_final_poly_len + log_blowup).
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
fn test_zk_proofs_have_distinct_trace_commitments() {
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);

    let proof1 = StarkProver::new(zk_config_with_seeds(0, 1))
        .prove(&air, trace.clone(), &pv)
        .expect("prove");
    let proof2 = StarkProver::new(zk_config_with_seeds(1, 2))
        .prove(&air, trace, &pv)
        .expect("prove");

    assert_ne!(
        proof1.commitments.trace, proof2.commitments.trace,
        "ZK proofs must have distinct trace commitments"
    );
}

#[test]
fn test_zk_proofs_have_distinct_quotient_commitments() {
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);

    let proof1 = StarkProver::new(zk_config_with_seeds(0, 1))
        .prove(&air, trace.clone(), &pv)
        .expect("prove");
    let proof2 = StarkProver::new(zk_config_with_seeds(1, 2))
        .prove(&air, trace, &pv)
        .expect("prove");

    assert_ne!(
        proof1.commitments.quotient_chunks, proof2.commitments.quotient_chunks,
        "ZK proofs must have distinct quotient commitments"
    );
}

#[test]
fn test_non_zk_proofs_are_deterministic() {
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);

    let proof1 = StarkProver::new(default_config())
        .prove(&air, trace.clone(), &pv)
        .expect("prove");
    let proof2 = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");

    assert_eq!(
        proof1.commitments.trace, proof2.commitments.trace,
        "non-ZK proofs must be deterministic"
    );
}

#[test]
fn test_zk_degree_bits_are_extended() {
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);

    let nozk = StarkProver::new(default_config())
        .prove(&air, trace.clone(), &pv)
        .expect("prove");
    let zk = StarkProver::new(zk_config())
        .prove(&air, trace, &pv)
        .expect("prove");

    assert_eq!(
        zk.degree_bits,
        nozk.degree_bits + 1,
        "ZK mode must use one extra degree bit for randomization"
    );
}

#[test]
fn test_zk_mode_all_5_proofs_verify() {
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);
    let verifier = StarkVerifier::new(zk_config());

    for _ in 0..5 {
        let proof = StarkProver::new(zk_config())
            .prove(&air, trace.clone(), &pv)
            .expect("prove");
        assert!(
            verifier.verify(&air, &proof, &pv).is_ok(),
            "each ZK proof must verify"
        );
    }
}

/// How many independent ZK proofs we check for distinct trace commitments.
/// Full STARK proving is expensive; a modest sample still catches broken ZK randomization.
const STATISTICAL_ZK_DISTINCT_COMMITMENT_SAMPLES: usize = 24;

#[test]
fn test_statistical_zk_no_repeated_commitments_many_proofs() {
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_and_pv(3, 4);
    let n = STATISTICAL_ZK_DISTINCT_COMMITMENT_SAMPLES;

    let hashes: BTreeSet<[u8; 32]> = (0u64..n as u64)
        .map(|i| {
            let proof = StarkProver::new(zk_config_with_seeds(i, i + 100))
                .prove(&air, trace.clone(), &pv)
                .expect("prove");
            let bytes: [u8; 32] = proof.commitments.trace.into();
            bytes
        })
        .collect();

    assert_eq!(
        hashes.len(),
        n,
        "each ZK proof must yield a distinct trace commitment (ZK randomization)"
    );
}

#[test]
fn test_zk_proof_bytes_do_not_contain_raw_witness_value() {
    let air = ArithmeticAir::new(1).unwrap();
    let sentinel = 0x5EAD_BEEFu32;
    let (trace, pv) = make_arithmetic_trace_and_pv(sentinel, 1);

    let proof = StarkProver::new(zk_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    let bytes = postcard::to_allocvec(&proof).unwrap();

    let pattern = sentinel.to_le_bytes();
    assert!(
        !bytes.windows(4).any(|w| w == pattern),
        "serialized proof must not contain raw witness value 0x5EADBEEF"
    );
}
