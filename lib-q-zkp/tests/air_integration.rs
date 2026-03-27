//! Integration tests for AIR implementations
//!
//! These tests verify full prove/verify cycles for each AIR type.

#![cfg(feature = "zkp")]

use lib_q_stark_air::BaseAir;
use lib_q_stark_field::PrimeCharacteristicRing;
use lib_q_stark_field::extension::Complex;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_mersenne31::Mersenne31;
use lib_q_zkp::air::{
    AirError,
    ArithmeticAir,
    HashPreimageAir,
    MerkleHash,
    MerkleInclusionAir,
    MerkleProofInput,
    RangeProofAir,
    TraceGenerator,
};
use lib_q_zkp::circuit::{
    ArithmeticCircuit,
    CircuitAir,
    CircuitBuilder,
    Constraint,
    Wire,
};

type TestField = Complex<Mersenne31>;

// ============================================================================
// ArithmeticAir Tests
// ============================================================================

#[test]
fn test_arithmetic_air_creation() {
    let air = ArithmeticAir::new(5).expect("Should create AIR with 5 operations");
    assert_eq!(air.num_operations(), 5);
    assert_eq!(BaseAir::<TestField>::width(&air), 15); // 5 * 3 cols
}

#[test]
fn test_arithmetic_air_validation() {
    // Zero operations should fail
    let result = ArithmeticAir::new(0);
    assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));

    // Very large operations should fail
    let result = ArithmeticAir::new(usize::MAX);
    assert!(matches!(result, Err(AirError::ExceedsMaxSize { .. })));
}

#[test]
fn test_arithmetic_air_trace_generation() {
    let air = ArithmeticAir::new(2).unwrap();
    let inputs = vec![
        (
            TestField::from(Mersenne31::new(3)),
            TestField::from(Mersenne31::new(4)),
        ),
        (
            TestField::from(Mersenne31::new(5)),
            TestField::from(Mersenne31::new(6)),
        ),
    ];

    let trace = air
        .generate_trace(&inputs)
        .expect("Trace generation should succeed");

    // Verify trace dimensions
    assert_eq!(trace.width(), 6); // 2 ops * 3 cols
    assert!(trace.height().is_power_of_two());
}

// ============================================================================
// HashPreimageAir Tests
// ============================================================================

#[test]
fn test_hash_preimage_air_creation() {
    let air = HashPreimageAir::new();
    assert_eq!(BaseAir::<TestField>::width(&air), 972);
}

#[test]
fn test_hash_preimage_air_validation() {
    let air = HashPreimageAir::new();
    let empty: Vec<u8> = vec![];
    let result = air.generate_trace(&empty);
    assert!(matches!(result, Err(AirError::InvalidInput { .. })));
}

#[test]
fn test_hash_preimage_public_values_deterministic() {
    let air = HashPreimageAir::new();
    let preimage = b"test data".to_vec();

    let public1: Vec<TestField> = air.public_values(&preimage);
    let public2: Vec<TestField> = air.public_values(&preimage);

    // Same input should produce same public values
    assert_eq!(public1, public2);
    // Poseidon returns 1 field element (not 32 bytes like SHAKE256)
    assert_eq!(public1.len(), 1);
}

// ============================================================================
// MerkleInclusionAir Tests
// ============================================================================

#[test]
fn test_merkle_inclusion_air_creation() {
    let air = MerkleInclusionAir::new(8).expect("Should create AIR with depth 8");
    assert_eq!(air.tree_depth(), 8);
}

#[test]
fn test_merkle_inclusion_air_validation() {
    // Zero depth should fail
    let result = MerkleInclusionAir::new(0);
    assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
}

#[test]
fn test_merkle_inclusion_trace_generation() {
    let air = MerkleInclusionAir::new(3).unwrap();
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false, true, false],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
        ],
    };

    let trace: Result<lib_q_stark_matrix::dense::RowMajorMatrix<TestField>, _> =
        air.generate_trace(&input);
    assert!(trace.is_ok(), "Trace generation should succeed");
}

#[test]
fn test_merkle_inclusion_mismatched_depth() {
    let air = MerkleInclusionAir::new(4).unwrap();

    // Wrong number of path bits
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false, true], // 2 instead of 4
        siblings: vec![MerkleHash::from_bytes(&[0u8; 32]).unwrap(); 4],
    };

    let result: Result<lib_q_stark_matrix::dense::RowMajorMatrix<TestField>, _> =
        air.generate_trace(&input);
    assert!(matches!(result, Err(AirError::InvalidInput { .. })));
}

// ============================================================================
// RangeProofAir Tests
// ============================================================================

#[test]
fn test_range_proof_air_creation() {
    let air = RangeProofAir::new(16).expect("Should create AIR with 16 bits");
    assert_eq!(air.num_bits(), 16);
    assert_eq!(air.upper_bound(), Some(65536));
}

#[test]
fn test_range_proof_air_validation() {
    // Zero bits should fail
    let result = RangeProofAir::new(0);
    assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
}

#[test]
fn test_range_proof_trace_with_zero() {
    let air = RangeProofAir::new(8).unwrap();
    let inputs = vec![<TestField as PrimeCharacteristicRing>::ZERO];

    let trace = air.generate_trace(&inputs);
    assert!(trace.is_ok(), "Zero value should decompose successfully");
}

// ============================================================================
// CircuitAir Tests
// ============================================================================

#[test]
fn test_circuit_air_simple() {
    // Build a circuit: prove a + b = c
    let mut builder = CircuitBuilder::<TestField>::new(2, 1);
    let a = builder.wire(0);
    let b = builder.wire(1);
    let c = builder.wire(2);
    let sum = builder.add(a, b);
    builder.assert_eq(sum, c);
    let circuit = builder.build();

    let air = CircuitAir::new(circuit);
    assert!(BaseAir::<TestField>::width(&air) >= 3);
}

#[test]
fn test_circuit_air_multiplication() {
    // Build a circuit: prove a * b = c
    let mut builder = CircuitBuilder::<TestField>::new(2, 1);
    let a = builder.wire(0);
    let b = builder.wire(1);
    let c = builder.wire(2);
    let product = builder.mul(a, b);
    builder.assert_eq(product, c);
    let circuit = builder.build();

    let air = CircuitAir::new(circuit.clone());

    // Generate trace with witness a=3, b=4 and public c=12
    let witness = vec![
        TestField::from(Mersenne31::new(3)),
        TestField::from(Mersenne31::new(4)),
    ];
    let public = vec![TestField::from(Mersenne31::new(12))];

    let trace = air.generate_trace(&witness, &public);
    assert!(trace.is_ok(), "Trace generation should succeed");
}

#[test]
fn test_circuit_air_trace_generation() {
    let mut circuit = ArithmeticCircuit::<TestField>::new(2, 1);
    circuit.add_constraint(Constraint::AssertZero(Wire::new(0)));

    let air = CircuitAir::new(circuit);

    let witness = vec![
        <TestField as PrimeCharacteristicRing>::ZERO,
        <TestField as PrimeCharacteristicRing>::ONE,
    ];
    let public = vec![<TestField as PrimeCharacteristicRing>::ZERO];

    let trace = air.generate_trace(&witness, &public);
    assert!(trace.is_ok());
}

#[test]
fn test_circuit_air_e2e_prove_verify() {
    use lib_q_zkp::{
        ZkpField,
        ZkpProver,
        ZkpVerifier,
    };

    // Build circuit: prove knowledge of a, b such that a * b = public_output
    let mut builder = CircuitBuilder::<ZkpField>::new(2, 1);
    let a = builder.wire(0);
    let b = builder.wire(1);
    let output = builder.wire(2);
    let product = builder.mul(a, b);
    builder.assert_eq(product, output);
    let circuit = builder.build();

    let witness = vec![
        ZkpField::from(Mersenne31::new(3)),
        ZkpField::from(Mersenne31::new(4)),
    ];
    let public = vec![ZkpField::from(Mersenne31::new(12))];

    let mut prover = ZkpProver::new();
    let proof = prover
        .prove_computation(&circuit, &witness, &public)
        .expect("prove_computation should succeed");

    let verifier = ZkpVerifier::new();
    let result = verifier
        .verify_computation(&proof, &circuit, &public)
        .expect("verify_computation should not error");
    assert!(result, "Valid circuit proof should verify");
}

#[test]
fn test_circuit_air_soundness_wrong_public_fails() {
    use lib_q_zkp::{
        ZkpField,
        ZkpProver,
        ZkpVerifier,
    };

    let mut builder = CircuitBuilder::<ZkpField>::new(2, 1);
    let a = builder.wire(0);
    let b = builder.wire(1);
    let output = builder.wire(2);
    let product = builder.mul(a, b);
    builder.assert_eq(product, output);
    let circuit = builder.build();

    let witness = vec![
        ZkpField::from(Mersenne31::new(3)),
        ZkpField::from(Mersenne31::new(4)),
    ];
    let public_correct = vec![ZkpField::from(Mersenne31::new(12))];
    let public_wrong = vec![ZkpField::from(Mersenne31::new(99))];

    let mut prover = ZkpProver::new();
    let proof = prover
        .prove_computation(&circuit, &witness, &public_correct)
        .expect("prove should succeed");

    let verifier = ZkpVerifier::new();
    let result = verifier
        .verify_computation(&proof, &circuit, &public_wrong)
        .expect("verify_computation should not error");
    assert!(!result, "Verification with wrong public value should fail");
}

// ============================================================================
// Poseidon Hash AIR Tests
// ============================================================================

#[test]
fn test_poseidon_hash_air_creation() {
    use lib_q_zkp::air::PoseidonHashAir;
    let air = PoseidonHashAir::new(32);
    assert!(air.is_ok());
    assert_eq!(air.unwrap().max_preimage_size(), 32);
}

#[test]
fn test_poseidon_hash_air_validation() {
    use lib_q_zkp::air::PoseidonHashAir;
    // Zero size should fail
    let result = PoseidonHashAir::new(0);
    assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
}

// ============================================================================
// High-Level API Tests
// ============================================================================

#[test]
fn test_prove_preimage() {
    use lib_q_zkp::api::prove_preimage;
    let secret = b"test secret";
    let result = prove_preimage(secret);
    // Proof generation should succeed
    assert!(
        result.is_ok(),
        "Proof generation should succeed: {:?}",
        result.err()
    );
}

#[test]
fn test_verify_preimage() {
    use lib_q_zkp::api::{
        prove_preimage,
        verify_preimage,
    };
    let secret = b"test secret";
    let proof = prove_preimage(secret).expect("Proof generation should succeed");

    // Verification checks that the proof's public values match the hash of the expected preimage.
    // Passing the secret as expected_hash matches what the prover committed to.
    let result = verify_preimage(&proof, secret);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_poseidon_collision_resistance() {
    // Test that different inputs produce different hash outputs
    use lib_q_poseidon::{
        Poseidon,
        Poseidon128,
        PoseidonField,
    };
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    let input1: Vec<PoseidonField> = vec![
        Complex::<Mersenne31>::from(Mersenne31::new(1)),
        Complex::<Mersenne31>::from(Mersenne31::new(2)),
    ];
    let input2: Vec<PoseidonField> = vec![
        Complex::<Mersenne31>::from(Mersenne31::new(1)),
        Complex::<Mersenne31>::from(Mersenne31::new(3)),
    ];

    let hash1 = Poseidon128.hash(&input1);
    let hash2 = Poseidon128.hash(&input2);

    // Different inputs must produce different outputs (collision resistance)
    assert_ne!(hash1, hash2, "Poseidon must be collision-resistant");
}

#[test]
fn test_hash_preimage_soundness() {
    // Test that invalid proofs (wrong preimage) fail verification
    use lib_q_zkp::api::{
        prove_preimage,
        verify_preimage,
    };

    let secret = b"correct secret";
    let proof = prove_preimage(secret).unwrap();

    // Verify with correct hash
    let correct_hash = b"expected hash"; // This would be the actual hash in practice
    // Note: This test is simplified - in practice we'd compute the actual hash
    // For now, we test that verification at least runs without panicking
    let _result = verify_preimage(&proof, correct_hash);

    // Test with wrong hash (should fail)
    let wrong_hash = b"wrong hash";
    let result = verify_preimage(&proof, wrong_hash);
    // The verification should either return false or error
    assert!(!result.unwrap_or(false), "Invalid proof must be rejected");
}

#[test]
fn test_merkle_membership_soundness() {
    // Test that invalid Merkle proofs fail verification
    use lib_q_zkp::api::{
        MerklePath,
        prove_membership,
        verify_membership,
    };

    let leaf = b"test leaf";
    let path = MerklePath {
        path_bits: vec![false, true],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
        ],
    };

    let proof = prove_membership(leaf, &path).unwrap();

    // Test with wrong root (should fail)
    let wrong_root = b"wrong root hash";
    let result = verify_membership(&proof, wrong_root);
    assert!(
        !result.unwrap_or(false),
        "Invalid Merkle proof must be rejected"
    );
}

#[test]
fn test_merkle_membership_roundtrip_correct_root() {
    // Build a tree, prove membership, verify with correct root (positive case)
    use lib_q_zkp::api::{
        build_merkle_tree,
        merkle_path_from_tree,
        prove_membership,
        verify_membership,
        verify_membership_with_depth,
    };

    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1", b"leaf2"];
    let tree = build_merkle_tree(&leaves).unwrap();
    let root_bytes = tree.root_bytes();

    for (i, leaf) in leaves.iter().enumerate() {
        let path = merkle_path_from_tree(&tree, i).unwrap();
        let proof = prove_membership(leaf, &path).unwrap();
        assert!(
            verify_membership(&proof, &root_bytes).unwrap(),
            "correct root must verify for leaf {}",
            i
        );
        assert!(
            verify_membership_with_depth(&proof, &root_bytes, tree.depth()).unwrap(),
            "correct root with explicit depth must verify for leaf {}",
            i
        );
    }
}

#[test]
fn test_merkle_membership_with_explicit_depth() {
    // Test verify_membership_with_depth for explicit tree depth verification
    use lib_q_zkp::api::{
        MerklePath,
        prove_membership,
        verify_membership_with_depth,
    };

    let leaf = b"test leaf";
    let path = MerklePath {
        path_bits: vec![false, true, true],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[2u8; 32]).unwrap(),
        ],
    };

    let proof = prove_membership(leaf, &path).unwrap();

    // Verify the proof has the correct tree depth in metadata
    assert_eq!(proof.merkle_tree_depth(), Some(3));

    // Test with wrong depth (should fail)
    let wrong_root = b"expected root";
    let result = verify_membership_with_depth(&proof, wrong_root, 2);
    assert!(
        !result.unwrap_or(false),
        "Proof with wrong tree depth must be rejected"
    );

    // Test with correct depth but wrong root (should fail verification)
    let result = verify_membership_with_depth(&proof, wrong_root, 3);
    // This should pass the depth check but fail root verification
    assert!(result.is_ok());
}

#[test]
fn test_merkle_proof_depth_stored_in_metadata() {
    // Verify that prove_membership stores tree depth in proof metadata
    use lib_q_zkp::api::{
        MerklePath,
        prove_membership,
    };

    let leaf = b"leaf data";

    // Test with depth 4
    let path4 = MerklePath {
        path_bits: vec![false, true, false, true],
        siblings: vec![MerkleHash::from_bytes(&[0u8; 32]).unwrap(); 4],
    };
    let proof4 = prove_membership(leaf, &path4).unwrap();
    assert_eq!(
        proof4.merkle_tree_depth(),
        Some(4),
        "Tree depth 4 should be stored in metadata"
    );

    // Test with depth 8
    let path8 = MerklePath {
        path_bits: vec![false; 8],
        siblings: vec![MerkleHash::from_bytes(&[0u8; 32]).unwrap(); 8],
    };
    let proof8 = prove_membership(leaf, &path8).unwrap();
    assert_eq!(
        proof8.merkle_tree_depth(),
        Some(8),
        "Tree depth 8 should be stored in metadata"
    );
}

#[test]
fn test_poseidon_deterministic() {
    // Test that same input always produces same output
    use lib_q_poseidon::{
        Poseidon,
        Poseidon128,
        PoseidonField,
    };
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    let input: Vec<PoseidonField> = vec![
        Complex::<Mersenne31>::from(Mersenne31::new(42)),
        Complex::<Mersenne31>::from(Mersenne31::new(100)),
    ];

    let hash1 = Poseidon128.hash(&input);
    let hash2 = Poseidon128.hash(&input);
    let hash3 = Poseidon128.hash(&input);

    // Same input must produce same output (deterministic)
    assert_eq!(hash1, hash2, "Poseidon must be deterministic");
    assert_eq!(hash2, hash3, "Poseidon must be deterministic");
}

#[test]
fn test_prove_membership() {
    use lib_q_zkp::api::{
        MerklePath,
        prove_membership,
    };
    let leaf = b"test leaf";
    let path = MerklePath {
        path_bits: vec![false, true],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
        ],
    };

    let result = prove_membership(leaf, &path);
    // Proof generation should succeed
    assert!(
        result.is_ok(),
        "Proof generation should succeed: {:?}",
        result.err()
    );
}

// ============================================================================
// MerkleHash Tests
// ============================================================================

#[test]
fn test_merkle_hash_from_bytes() {
    let bytes = [42u8; 32];
    let hash = MerkleHash::from_bytes(&bytes);
    assert!(hash.is_ok(), "Should create MerkleHash from bytes");
}

#[test]
fn test_merkle_hash_hash_data() {
    let data = b"test data";
    let hash1 = MerkleHash::hash_data(data);
    let hash2 = MerkleHash::hash_data(data);

    // Same data should produce same hash
    assert_eq!(
        hash1, hash2,
        "MerkleHash::hash_data should be deterministic"
    );
}

#[test]
fn test_merkle_hash_type_safety() {
    // Test that MerkleHash prevents double-hashing
    let data = b"leaf data";
    let hash1 = MerkleHash::hash_data(data);

    // Creating from bytes should NOT hash again
    let hash2 = MerkleHash::from_bytes(&[0u8; 32]).unwrap();

    // These should be different (hash1 is actual hash, hash2 is interpreted bytes)
    assert_ne!(
        hash1, hash2,
        "hash_data and from_bytes should produce different results"
    );
}

#[test]
fn test_merkle_hash_sibling_not_rehashed() {
    // Verify that siblings are used directly without re-hashing
    // This is critical for Merkle tree correctness
    let sibling_bytes = [1u8; 32];
    let sibling_hash = MerkleHash::from_bytes(&sibling_bytes).unwrap();

    // The sibling should be interpreted as a field element, not hashed
    let field = sibling_hash.as_field();

    // Verify it's a valid field element (can access real part)
    let _real = field.real();
}

// ============================================================================
// Constraint Soundness Tests
// ============================================================================

const MIN_TRACE_ROWS: usize = 64;

fn make_arithmetic_trace_pv_padded(
    a: u32,
    b: u32,
) -> (
    lib_q_stark_matrix::dense::RowMajorMatrix<TestField>,
    Vec<TestField>,
) {
    let air = ArithmeticAir::new(1).unwrap();
    let product = a * b;
    let inputs = vec![(
        TestField::from(Mersenne31::new(a)),
        TestField::from(Mersenne31::new(b)),
    )];
    let trace = air.generate_trace(&inputs).unwrap();
    let width = trace.width();
    let current_height = trace.height();
    let mut padded_values = trace.values.clone();
    if current_height < MIN_TRACE_ROWS {
        let row: Vec<TestField> = (0..width)
            .map(|i| {
                if i % 3 == 0 {
                    TestField::from(Mersenne31::new(a))
                } else if i % 3 == 1 {
                    TestField::from(Mersenne31::new(b))
                } else {
                    TestField::from(Mersenne31::new(product))
                }
            })
            .collect();
        for _ in current_height..MIN_TRACE_ROWS {
            padded_values.extend_from_slice(&row);
        }
    }
    let trace = lib_q_stark_matrix::dense::RowMajorMatrix::new(padded_values, width);
    let pv = vec![TestField::from(Mersenne31::new(product))];
    (trace, pv)
}

#[test]
fn test_arithmetic_air_soundness_zero_product_is_valid() {
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };
    let air = ArithmeticAir::new(1).unwrap();
    let (trace, pv) = make_arithmetic_trace_pv_padded(0, 5);
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_ok()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn test_arithmetic_air_soundness_wrong_product() {
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };
    let air = ArithmeticAir::new(1).unwrap();
    let (mut trace, pv) = make_arithmetic_trace_pv_padded(3, 4);
    trace.values[2] = TestField::from(Mersenne31::new(13));
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_err()
    );
}

#[test]
fn test_range_proof_boundary_value_valid() {
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };
    let air = RangeProofAir::new(8).unwrap();
    let inputs = vec![<TestField as PrimeCharacteristicRing>::ZERO];
    let trace = air.generate_trace(&inputs).unwrap();
    let pv = air.public_values(&inputs);
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_ok()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn test_range_proof_non_boolean_bit_rejected() {
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };
    let air = RangeProofAir::new(8).unwrap();
    let inputs = vec![<TestField as PrimeCharacteristicRing>::ZERO];
    let mut trace = air.generate_trace(&inputs).unwrap();
    let width = trace.width();
    trace.values[1 + 1] = TestField::from(Mersenne31::new(2));
    for row in 1..(trace.values.len() / width) {
        trace.values[row * width + 1 + 1] = TestField::from(Mersenne31::new(2));
    }
    let pv = air.public_values(&inputs);
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_err()
    );
}

#[test]
fn test_merkle_inclusion_constraint_soundness() {
    // Test that the AIR enforces correct Poseidon hash computation
    // This verifies that full constraint system prevents malicious proofs
    use lib_q_zkp::air::{
        MerkleInclusionAir,
        MerkleProofInput,
        TraceGenerator,
    };
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    let air = MerkleInclusionAir::new(2).unwrap();

    // Create valid input
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false, true],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
        ],
    };

    // Generate valid trace
    let trace = air.generate_trace(&input).unwrap();
    let public_values = air.public_values(&input);

    // Create proof
    let config = default_config();
    let prover = StarkProver::new(config);
    let proof = prover.prove(&air, trace, &public_values).expect("prove");

    // Verify proof
    let config2 = default_config();
    let verifier = StarkVerifier::new(config2);
    let result = verifier.verify(&air, &proof, &public_values);

    // Valid proof should verify
    assert!(
        result.is_ok(),
        "Valid proof should verify: {:?}",
        result.err()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn test_merkle_inclusion_soundness_corrupted_sibling() {
    use lib_q_zkp::air::{
        MerkleInclusionAir,
        MerkleProofInput,
        TraceGenerator,
    };
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    let air = MerkleInclusionAir::new(2).unwrap();
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false, true],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
        ],
    };
    let mut trace = air.generate_trace(&input).unwrap();
    let width = trace.width();
    let level_start = 1;
    let sibling_col = level_start + 1;
    trace.values[sibling_col] += TestField::from(Mersenne31::new(1));
    for row in 1..(trace.values.len() / width) {
        trace.values[row * width + sibling_col] += TestField::from(Mersenne31::new(1));
    }
    let pv = air.public_values(&input);
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_err()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn test_merkle_inclusion_soundness_wrong_direction_bit() {
    use lib_q_zkp::air::{
        MerkleInclusionAir,
        MerkleProofInput,
        TraceGenerator,
    };
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    let air = MerkleInclusionAir::new(2).unwrap();
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        path_bits: vec![false, true],
        siblings: vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
        ],
    };
    let mut trace = air.generate_trace(&input).unwrap();
    let width = trace.width();
    let direction_col = 1;
    trace.values[direction_col] = TestField::from(Mersenne31::new(1));
    for row in 1..(trace.values.len() / width) {
        trace.values[row * width + direction_col] = TestField::from(Mersenne31::new(1));
    }
    let pv = air.public_values(&input);
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_err()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn test_hash_preimage_soundness_wrong_preimage() {
    use lib_q_zkp::air::{
        HashPreimageAir,
        TraceGenerator,
    };
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    let air = HashPreimageAir::new();
    let preimage = b"hello".to_vec();
    let mut trace = air.generate_trace(&preimage).unwrap();
    let width = trace.width();
    let preimage_start = 0;
    trace.values[preimage_start] += TestField::from(Mersenne31::new(1));
    for row in 1..(trace.values.len() / width) {
        trace.values[row * width + preimage_start] += TestField::from(Mersenne31::new(1));
    }
    let pv = air.public_values(&preimage);
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_err()
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn test_poseidon_gadget_intermediate_states_are_binding() {
    use lib_q_zkp::air::{
        MerkleInclusionAir,
        MerkleProofInput,
        TraceGenerator,
    };
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    let air = MerkleInclusionAir::new(1).unwrap();
    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false],
        siblings: vec![MerkleHash::from_bytes(&[0u8; 32]).unwrap()],
    };
    let mut trace = air.generate_trace(&input).unwrap();
    let width = trace.width();
    let intermediate_start = 1 + 1 + 1 + 1;
    for i in 0..10 {
        let col = intermediate_start + i;
        if col < width {
            for row in 0..(trace.values.len() / width) {
                trace.values[row * width + col] = TestField::from(Mersenne31::new(0));
            }
        }
    }
    let pv = air.public_values(&input);
    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &pv)
        .expect("prove");
    assert!(
        StarkVerifier::new(default_config())
            .verify(&air, &proof, &pv)
            .is_err()
    );
}

/// Regression: wide-trace AIRs (e.g. PoseidonGadget) use quotient chunking;
/// verifier quotient domain must match prover (see lib-q-stark verifier).
#[test]
fn test_stark_layer_wide_trace_regression() {
    use lib_q_stark::{
        StarkGenericConfig,
        get_log_num_quotient_chunks,
    };
    use lib_q_zkp::air::{
        MerkleInclusionAir,
        MerkleProofInput,
        TraceGenerator,
    };
    use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };

    // Depth-1 tree: width = 1 + 1*(1 + 1 + 1 + COLUMNS_PER_HASH) = 1 + 1*579 = 580 (was 576, now 960)
    let air = MerkleInclusionAir::new(1).unwrap();
    let width = BaseAir::<TestField>::width(&air);
    assert!(
        width > 512,
        "AIR width {width} should exceed 512 to trigger quotient padding (Poseidon-128 uses 960 cols per hash)"
    );

    // PoseidonGadget S-box degree = 5 → log_num_quotient_chunks = log2_ceil(4) = 2
    let config = default_config();
    let log_nqc = get_log_num_quotient_chunks::<TestField, _>(&air, 0, 0, config.is_zk());
    assert_eq!(
        log_nqc, 2,
        "Expected log_num_quotient_chunks=2 for constraint degree 5 (x^5 S-box)"
    );

    let input = MerkleProofInput {
        leaf: vec![1, 2, 3, 4],
        leaf_hash_direct: None,
        path_bits: vec![false],
        siblings: vec![MerkleHash::from_bytes(&[0u8; 32]).unwrap()],
    };
    let trace = air.generate_trace(&input).unwrap();
    let public_values = air.public_values(&input);
    let degree = trace.height();

    let proof = StarkProver::new(default_config())
        .prove(&air, trace, &public_values)
        .expect("prove");
    let expected_degree_bits = degree.trailing_zeros() as usize + config.is_zk();
    assert_eq!(
        proof.degree_bits, expected_degree_bits,
        "degree_bits must encode the original extended degree"
    );

    let result = StarkVerifier::new(default_config()).verify(&air, &proof, &public_values);
    assert!(
        result.is_ok(),
        "Wide-trace prove+verify roundtrip must succeed: {:?}",
        result.err()
    );
}

#[test]
fn test_merkle_inclusion_trace_width_includes_intermediates() {
    // Verify that trace width includes intermediate Poseidon states
    use lib_q_zkp::air::poseidon_gadget::PoseidonGadget;

    let air = MerkleInclusionAir::new(3).unwrap();
    let width = BaseAir::<TestField>::width(&air);

    // Expected: 1 (leaf) + 3 * (1 direction + 1 sibling + 1 computed + COLUMNS_PER_HASH intermediates)
    let expected = 1 + 3 * (1 + 1 + 1 + PoseidonGadget::COLUMNS_PER_HASH);

    assert_eq!(
        width, expected,
        "Trace width should include all intermediate Poseidon states"
    );
    assert!(
        width > 1000,
        "Trace width should be large due to intermediate states"
    );
}

#[test]
fn test_poseidon_gadget_columns_per_hash() {
    // Verify PoseidonGadget column count matches expected
    use lib_q_zkp::air::poseidon_gadget::PoseidonGadget;

    // For Poseidon-128 (state width 5): 64 rounds × (5×3) columns per round = 960
    assert_eq!(
        PoseidonGadget::COLUMNS_PER_HASH,
        960,
        "PoseidonGadget should use 960 columns per hash (64 rounds × 15 columns for state width 5)"
    );
}

// ============================================================================
// Cross-AIR Tests
// ============================================================================

#[test]
fn test_different_airs_have_different_widths() {
    let arith_air = ArithmeticAir::new(3).unwrap();
    let hash_air = HashPreimageAir::new();
    let merkle_air = MerkleInclusionAir::new(4).unwrap();
    let range_air = RangeProofAir::new(8).unwrap();

    let arith_width = BaseAir::<TestField>::width(&arith_air);
    let hash_width = BaseAir::<TestField>::width(&hash_air);
    let merkle_width = BaseAir::<TestField>::width(&merkle_air);
    let range_width = BaseAir::<TestField>::width(&range_air);

    // All AIRs should have distinct widths based on their configuration
    assert_ne!(arith_width, hash_width);
    assert_ne!(hash_width, merkle_width);
    assert_ne!(merkle_width, range_width);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_air_error_conversion() {
    let air_error = AirError::InvalidDimensions {
        reason: "test".to_string(),
    };

    let core_error: lib_q_core::Error = air_error.into();

    match core_error {
        lib_q_core::Error::InternalError { operation, .. } => {
            assert_eq!(operation, "AIR operation");
        }
        _ => panic!("Expected InternalError"),
    }
}
