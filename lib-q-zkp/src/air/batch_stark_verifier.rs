//! Batch STARK Verifier AIR — verifies N inner STARK proofs in one trace.
//!
//! Trace layout: N rows × StarkVerifierAir::trace_width columns.
//! Row i applies StarkVerifierAir constraints to the i-th inner proof.
//! No cross-row transition constraints.
//!
//! Public value: single Poseidon hash of all inner proof public values.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::Field;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;

use super::recursive_types::SerializedStarkProof;
use super::stark_verifier::RecursiveStarkVerificationInput;
use super::{
    AirError,
    StarkVerifierAir,
    TraceGenerator,
    validate_trace_dimensions,
};

/// Input for batch recursive verification: one RecursiveStarkVerificationInput per proof.
pub type BatchRecursiveStarkVerificationInput<F: Field, Ch: Field> =
    Vec<RecursiveStarkVerificationInput<F, Ch>>;

/// Outer public values for [`BatchStarkVerifierAir`]: `Poseidon128` over all inner
/// `expected_public_values` concatenated (same as [`TraceGenerator::public_values`]).
///
/// Used when verifying an outer recursive proof without rebuilding full
/// [`RecursiveStarkVerificationInput`] witnesses.
pub fn batch_recursive_verifier_public_values<F, Ch>(
    serialized: &[SerializedStarkProof<F, Ch>],
) -> Vec<F>
where
    F: Field
        + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>
        + From<lib_q_poseidon::PoseidonField>
        + Into<lib_q_poseidon::PoseidonField>,
    Ch: Field,
{
    let flattened: Vec<F> = serialized
        .iter()
        .flat_map(|s| s.expected_public_values.iter().cloned())
        .collect();
    if flattened.is_empty() {
        return vec![F::ZERO];
    }
    use lib_q_poseidon::{
        Poseidon,
        Poseidon128,
        PoseidonField,
    };
    let hash_input: Vec<PoseidonField> = flattened.into_iter().map(|f| f.into()).collect();
    let hash_output = Poseidon128.hash(&hash_input);
    vec![hash_output[0].into()]
}

/// AIR that verifies N inner STARK proofs. Each row independently verifies one proof.
/// Public value is Poseidon128(flatten(inner_public_values)).
#[derive(Debug, Clone)]
pub struct BatchStarkVerifierAir<F: Field, Ch: Field = F> {
    /// One StarkVerifierAir per proof (all must have the same trace_width)
    airs: Vec<StarkVerifierAir<F, Ch>>,
}

impl<F: Field, Ch: Field> BatchStarkVerifierAir<F, Ch> {
    /// Build a batch verifier from N serialized proofs and shared parameters.
    /// All proofs must have the same trace_width, degree_bits, num_quotient_chunks, etc.
    pub fn new(
        serialized_proofs: Vec<SerializedStarkProof<F, Ch>>,
        merkle_tree_depth: usize,
        log_final_poly_len: usize,
        num_fri_queries: usize,
    ) -> Result<Self, AirError> {
        if serialized_proofs.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "BatchStarkVerifierAir requires at least one proof".to_string(),
            });
        }
        let airs: Vec<StarkVerifierAir<F, Ch>> = serialized_proofs
            .into_iter()
            .map(|p| {
                StarkVerifierAir::new(p, merkle_tree_depth, log_final_poly_len, num_fri_queries)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let width0 = airs[0].width();
        for (i, air) in airs.iter().enumerate().skip(1) {
            if air.width() != width0 {
                return Err(AirError::InvalidInput {
                    reason: format!(
                        "Proof {} has width {} but proof 0 has {}",
                        i,
                        air.width(),
                        width0
                    ),
                });
            }
        }
        Ok(Self { airs })
    }

    /// Number of inner proofs in the batch.
    pub fn num_proofs(&self) -> usize {
        self.airs.len()
    }
}

impl<F: Field, Ch: Field> BaseAir<F> for BatchStarkVerifierAir<F, Ch> {
    fn width(&self) -> usize {
        self.airs[0].width()
    }
}

impl<AB: AirBuilder> Air<AB> for BatchStarkVerifierAir<AB::F, AB::F>
where
    AB::F: Field + Sized + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        for air in &self.airs {
            air.eval_on_slice(builder, local);
        }
    }
}

impl<F, Ch> TraceGenerator<F, BatchRecursiveStarkVerificationInput<F, Ch>>
    for BatchStarkVerifierAir<F, Ch>
where
    F: Field
        + lib_q_stark_field::BasedVectorSpace<lib_q_stark_mersenne31::Mersenne31>
        + From<lib_q_poseidon::PoseidonField>
        + Into<lib_q_poseidon::PoseidonField>,
    Ch: Field,
{
    fn generate_trace(
        &self,
        inputs: &BatchRecursiveStarkVerificationInput<F, Ch>,
    ) -> Result<RowMajorMatrix<F>, AirError> {
        if inputs.len() != self.airs.len() {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Batch input len {} does not match num_proofs {}",
                    inputs.len(),
                    self.airs.len()
                ),
            });
        }
        let width = self.width();
        let mut all_rows = Vec::with_capacity(self.airs.len() * width);
        for (air, input) in self.airs.iter().zip(inputs.iter()) {
            let one_row = air.generate_trace(input)?;
            if one_row.width() != width {
                return Err(AirError::InvalidInput {
                    reason: format!(
                        "Generated row width {} does not match batch width {}",
                        one_row.width(),
                        width
                    ),
                });
            }
            for r in 0..one_row.height() {
                for c in 0..width {
                    if let Some(v) = one_row.get(r, c) {
                        all_rows.push(v);
                    }
                }
            }
        }
        let num_rows = all_rows.len() / width;
        validate_trace_dimensions(width, num_rows)?;
        Ok(RowMajorMatrix::new(all_rows, width))
    }

    fn public_values(&self, inputs: &BatchRecursiveStarkVerificationInput<F, Ch>) -> Vec<F> {
        let serialized: Vec<SerializedStarkProof<F, Ch>> = inputs
            .iter()
            .map(|inp| inp.serialized_proof.clone())
            .collect();
        batch_recursive_verifier_public_values(&serialized)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_stark::check_constraints;
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_matrix::Matrix;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::super::{
        CommitmentVerificationInput,
        ConstraintVerificationInput,
        FriVerificationInput,
        MerkleHash,
        MerkleProofInput,
        OpeningVerificationInput,
        SerializedFriRound,
    };
    use super::*;
    use crate::air::{
        MerkleInclusionAir,
        merkle_root_to_bytes,
    };

    type TestField = Complex<Mersenne31>;

    fn sample_serialized_proof() -> SerializedStarkProof<TestField, TestField> {
        SerializedStarkProof::<TestField, TestField> {
            degree_bits: 8,
            num_quotient_chunks: 2,
            trace_width: 4,
            is_zk: false,
            trace_commitment_hash: [0u8; 32],
            quotient_commitment_hash: [1u8; 32],
            random_commitment_hash: None,
            trace_local: vec![TestField::ZERO; 4],
            trace_next: vec![TestField::ZERO; 4],
            quotient_chunks: vec![vec![TestField::ZERO; 1]; 2],
            random_values: None,
            fri_rounds: vec![SerializedFriRound {
                commitment_hash: [2u8; 32],
                beta: vec![0u8; 8],
            }],
            final_poly: vec![TestField::ZERO; 2],
            pow_witness: vec![],
            zeta: TestField::ZERO,
            zeta_next: TestField::ZERO,
            alpha: TestField::ZERO,
            expected_public_values: vec![TestField::ZERO],
        }
    }

    fn sample_recursive_input(
        serialized: &SerializedStarkProof<TestField, TestField>,
    ) -> RecursiveStarkVerificationInput<TestField, TestField> {
        let tree_depth = 4;
        let zero_hash = MerkleHash::hash_data(b"z");
        let merkle_proof = MerkleProofInput {
            leaf: b"leaf".to_vec(),
            leaf_hash_direct: None,
            path_bits: vec![false; tree_depth],
            siblings: vec![zero_hash; tree_depth],
        };

        let merkle_air = MerkleInclusionAir::new(tree_depth).expect("MerkleInclusionAir");
        let root_field = merkle_air.public_values(&merkle_proof)[0];
        let root_bytes = merkle_root_to_bytes(&root_field);

        RecursiveStarkVerificationInput {
            serialized_proof: serialized.clone(),
            commitment_inputs: CommitmentVerificationInput {
                expected_roots: vec![root_bytes, root_bytes],
                merkle_proofs: vec![merkle_proof.clone(), merkle_proof.clone()],
            },
            fri_inputs: FriVerificationInput {
                fri_rounds: serialized.fri_rounds.clone(),
                round_betas: vec![TestField::ZERO],
                final_poly: vec![TestField::ZERO; 2],
                query_indices: vec![0, 0],
                query_evaluations: vec![TestField::ZERO, TestField::ZERO],
                round_current_evals: vec![TestField::ZERO],
                round_sibling_evals: vec![TestField::ZERO],
                round_domain_point_inverses: vec![TestField::ZERO],
                round_domain_point_x0: vec![TestField::ZERO],
                round_parity: vec![TestField::ZERO],
                final_poly_eval_point: TestField::ZERO,
                round_roll_ins: vec![TestField::ZERO],
            },
            constraint_inputs: ConstraintVerificationInput {
                quotient_chunks: vec![TestField::ZERO; serialized.num_quotient_chunks],
                trace_local: vec![TestField::ZERO; serialized.trace_width],
                trace_next: vec![TestField::ZERO; serialized.trace_width],
                zeta: TestField::ZERO,
                alpha: TestField::ZERO,
                public_values: serialized.expected_public_values.clone(),
            },
            opening_inputs: OpeningVerificationInput {
                opened_values: vec![
                    TestField::ZERO;
                    serialized.trace_width * 2 + serialized.num_quotient_chunks
                ],
                domain_points: vec![
                    TestField::ZERO;
                    serialized.trace_width * 2 + serialized.num_quotient_chunks
                ],
                merkle_proofs: vec![
                    merkle_proof;
                    serialized.trace_width * 2 + serialized.num_quotient_chunks
                ],
                expected_roots: vec![
                    TestField::ZERO;
                    serialized.trace_width * 2 + serialized.num_quotient_chunks
                ],
            },
        }
    }

    #[test]
    fn test_batch_air_new_rejects_empty_proofs() {
        let result = BatchStarkVerifierAir::<TestField, TestField>::new(vec![], 4, 1, 2);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }

    #[test]
    fn test_batch_air_generate_trace_rejects_input_length_mismatch() {
        let serialized = sample_serialized_proof();
        let batch_air =
            BatchStarkVerifierAir::<TestField, TestField>::new(vec![serialized], 4, 1, 2).unwrap();

        let result = batch_air.generate_trace(&vec![]);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }

    #[test]
    fn test_batch_air_generate_trace_and_public_values() {
        let proof_a = sample_serialized_proof();
        let mut proof_b = sample_serialized_proof();
        proof_b.expected_public_values = vec![TestField::ONE];

        let input_a = sample_recursive_input(&proof_a);
        let input_b = sample_recursive_input(&proof_b);
        let batch_air =
            BatchStarkVerifierAir::<TestField, TestField>::new(vec![proof_a, proof_b], 4, 1, 2)
                .unwrap();

        let trace = batch_air
            .generate_trace(&vec![input_a.clone(), input_b.clone()])
            .expect("batch trace should generate");

        assert_eq!(batch_air.num_proofs(), 2);
        assert_eq!(trace.height(), 2);
        assert_eq!(trace.width(), BaseAir::<TestField>::width(&batch_air));

        let pvs = batch_air.public_values(&vec![input_a, input_b]);
        assert_eq!(pvs.len(), 1);
    }

    #[test]
    fn test_batch_public_values_empty_flattened_returns_zero() {
        let mut serialized = sample_serialized_proof();
        serialized.expected_public_values = vec![];
        let input = sample_recursive_input(&serialized);
        let batch_air =
            BatchStarkVerifierAir::<TestField, TestField>::new(vec![serialized], 4, 1, 2).unwrap();

        let public_values = batch_air.public_values(&vec![input]);
        assert_eq!(public_values, vec![TestField::ZERO]);
    }

    #[test]
    #[should_panic(expected = "constraints had nonzero value")]
    fn test_batch_constraints_detect_placeholder_trace() {
        let proof_a = sample_serialized_proof();
        let mut proof_b = sample_serialized_proof();
        proof_b.expected_public_values = vec![TestField::ONE];

        let input_a = sample_recursive_input(&proof_a);
        let input_b = sample_recursive_input(&proof_b);
        let batch_air =
            BatchStarkVerifierAir::<TestField, TestField>::new(vec![proof_a, proof_b], 4, 1, 2)
                .unwrap();

        let trace = batch_air
            .generate_trace(&vec![input_a.clone(), input_b.clone()])
            .expect("batch trace should generate");
        let public_values = batch_air.public_values(&vec![input_a, input_b]);

        check_constraints(&batch_air, &trace, &public_values);
    }
}
