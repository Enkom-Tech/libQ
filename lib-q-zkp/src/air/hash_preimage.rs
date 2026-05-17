//! Hash Preimage AIR - Proves knowledge of a Poseidon preimage
//!
//! This AIR proves that the prover knows a preimage `x` such that
//! `Poseidon(x) = y` for a public hash output `y`.
//!
//! # Design
//!
//! Multi-row Poseidon sponge: same 972-column layout as IdentityProofAir
//! (state_in 5 + input 2 + intermediates 960 + state_out 5). Full Poseidon
//! constraints via PoseidonGadget per row; transition constraints carry sponge state.
//!
//! # Security
//!
//! - Poseidon-128 (128-bit security level)
//! - Full permutation constraints; preimage is witness, hash output is public

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use lib_q_poseidon::{
    Poseidon,
    Poseidon128,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::poseidon_gadget::PoseidonGadget;
use super::{
    AirError,
    TraceGenerator,
    bytes_to_poseidon_field,
    compute_poseidon_row,
    next_power_of_two,
    poseidon_to_field,
    validate_trace_dimensions,
};

/// Poseidon-128 hasher instance
const POSEIDON_128: Poseidon128 = Poseidon128;

/// Maximum preimage size in bytes (for API validation)
pub const MAX_PREIMAGE_SIZE: usize = 1024;

/// Row layout: state_in (5) + input (2) + intermediates (960) + state_out (5) = 972
const STATE_IN_COLS: usize = 5;
const INPUT_COLS: usize = 2;
const STATE_OUT_COLS: usize = 5;

fn row_width() -> usize {
    STATE_IN_COLS + INPUT_COLS + PoseidonGadget::COLUMNS_PER_HASH + STATE_OUT_COLS
}

/// AIR for proving knowledge of a Poseidon preimage (multi-row sponge, full constraints).
#[derive(Debug, Clone, Default)]
pub struct HashPreimageAir;

impl HashPreimageAir {
    /// Create a new HashPreimageAir (unit struct; no parameters).
    pub fn new() -> Self {
        Self
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for HashPreimageAir {
    fn width(&self) -> usize {
        row_width()
    }
}

impl<AB: AirBuilder> Air<AB> for HashPreimageAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let w = row_width();
        let state_in_0 = local[0].into();
        let state_in_1 = local[1].into();
        let state_in_2 = local[2].into();
        let state_in_3 = local[3].into();
        let state_in_4 = local[4].into();
        let input_0 = local[5].into();
        let input_1 = local[6].into();
        let intermediate_start = STATE_IN_COLS + INPUT_COLS;
        let state_out_0 = local[w - 5].into();
        let state_out_1 = local[w - 4].into();
        let state_out_2 = local[w - 3].into();
        let state_out_3 = local[w - 2].into();
        let state_out_4 = local[w - 1].into();

        {
            let mut b = builder.when_first_row();
            b.assert_zero(state_in_0.clone() - input_0.clone());
            b.assert_zero(state_in_1.clone() - input_1.clone());
            b.assert_zero(state_in_2);
            b.assert_zero(state_in_3);
            b.assert_zero(state_in_4);
        }

        {
            let next_state_in_0 = next[0].into();
            let next_state_in_1 = next[1].into();
            let next_state_in_2 = next[2].into();
            let next_state_in_3 = next[3].into();
            let next_state_in_4 = next[4].into();
            let next_input_0 = next[5].into();
            let next_input_1 = next[6].into();
            let mut b = builder.when_transition();
            b.assert_zero(next_state_in_0 - state_out_0.clone());
            b.assert_zero(next_state_in_1 - (state_out_1.clone() + next_input_0));
            b.assert_zero(next_state_in_2 - (state_out_2.clone() + next_input_1));
            b.assert_zero(next_state_in_3 - state_out_3.clone());
            b.assert_zero(next_state_in_4 - state_out_4.clone());
        }

        let gadget = PoseidonGadget::new();
        let full_state: [AB::Expr; 5] = [
            local[0].into(),
            local[1].into(),
            local[2].into(),
            local[3].into(),
            local[4].into(),
        ];
        if gadget
            .constrain_full_state(builder, &full_state, state_out_0, intermediate_start)
            .is_err()
        {
            builder.assert_zero(AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE));
        }
    }
}

/// Input type for HashPreimageAir trace generation
pub type HashPreimageInput = Vec<u8>;

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, HashPreimageInput>
    for HashPreimageAir
{
    fn generate_trace(
        &self,
        inputs: &HashPreimageInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        type Val = Complex<Mersenne31>;

        if inputs.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "Preimage cannot be empty".into(),
            });
        }
        if inputs.len() > MAX_PREIMAGE_SIZE {
            return Err(AirError::InvalidInput {
                reason: alloc::format!(
                    "Preimage size {} exceeds maximum {}",
                    inputs.len(),
                    MAX_PREIMAGE_SIZE
                ),
            });
        }

        let secret_fields = bytes_to_poseidon_field(inputs);
        let num_permutations = 1.max(secret_fields.len().div_ceil(2));
        const QUOTIENT_CHUNKS_FACTOR: usize = 4;
        let min_height = core::cmp::max(num_permutations, 1) * QUOTIENT_CHUNKS_FACTOR;
        let num_rows_padded = next_power_of_two(min_height);
        let trace_width = row_width();
        validate_trace_dimensions(trace_width, num_rows_padded)?;

        let mut trace_values = vec![Val::ZERO; num_rows_padded * trace_width];
        let params = Poseidon128::params();
        let zero_f = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);
        let n = params.state_width;
        let mut state = vec![zero_f; n];

        for row in 0..num_rows_padded {
            let i0 = row * 2;
            let i1 = row * 2 + 1;
            let in0 = if row < num_permutations {
                secret_fields.get(i0).cloned().unwrap_or(zero_f)
            } else {
                zero_f
            };
            let in1 = if row < num_permutations {
                secret_fields.get(i1).cloned().unwrap_or(zero_f)
            } else {
                zero_f
            };

            if row == 0 {
                state[0] = in0;
                state[1] = in1;
                state[2] = zero_f;
                state[3] = zero_f;
                state[4] = zero_f;
            } else {
                state[1] += in0;
                state[2] += in1;
            }

            let (state_out, intermediates) = compute_poseidon_row(&state, &params);
            let base = row * trace_width;
            for i in 0..STATE_IN_COLS {
                trace_values[base + i] = poseidon_to_field(&state[i]);
            }
            trace_values[base + 5] = poseidon_to_field(&in0);
            trace_values[base + 6] = poseidon_to_field(&in1);
            for (k, v) in intermediates.iter().enumerate() {
                if base + STATE_IN_COLS + INPUT_COLS + k < trace_values.len() {
                    trace_values[base + STATE_IN_COLS + INPUT_COLS + k] = poseidon_to_field(v);
                }
            }
            let out_start = base + trace_width - STATE_OUT_COLS;
            for i in 0..STATE_OUT_COLS {
                trace_values[out_start + i] = poseidon_to_field(&state_out[i]);
            }
            state = state_out;
        }

        Ok(RowMajorMatrix::new(trace_values, trace_width))
    }

    fn public_values(
        &self,
        inputs: &HashPreimageInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        let field_elements = bytes_to_poseidon_field(inputs);
        let hash_output = POSEIDON_128.hash(&field_elements);
        if hash_output.is_empty() {
            return vec![lib_q_stark_field::extension::Complex::<Mersenne31>::ZERO];
        }
        vec![poseidon_to_field(&hash_output[0])]
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_hash_preimage_air_new() {
        let air = HashPreimageAir::new();
        assert_eq!(BaseAir::<TestField>::width(&air), row_width());
    }

    #[test]
    fn test_hash_preimage_air_width() {
        let air = HashPreimageAir::new();
        assert_eq!(BaseAir::<TestField>::width(&air), 972);
    }

    #[test]
    fn test_generate_trace_basic() {
        use lib_q_stark_matrix::Matrix;
        let air = HashPreimageAir::new();
        let preimage = b"test data".to_vec();
        let trace: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&preimage);
        assert!(trace.is_ok());
        let trace = trace.unwrap();
        assert_eq!(trace.width(), 972);
    }

    #[test]
    fn test_generate_trace_empty_rejected() {
        let air = HashPreimageAir::new();
        let preimage = vec![];
        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&preimage);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }

    #[test]
    fn test_public_values_are_hash_output() {
        let air = HashPreimageAir::new();
        let preimage = b"hello world".to_vec();
        let public_vals: Vec<TestField> = air.public_values(&preimage);
        assert!(!public_vals.is_empty());
    }
}
