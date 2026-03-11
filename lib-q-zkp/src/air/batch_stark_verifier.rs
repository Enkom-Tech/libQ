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
        let flattened: Vec<F> = inputs
            .iter()
            .flat_map(|inp| inp.serialized_proof.expected_public_values.iter().cloned())
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
}
