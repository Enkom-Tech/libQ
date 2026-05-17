//! Identity Proof AIR - Proves knowledge of ML-DSA key ownership
//!
//! This AIR proves that the prover knows a private key that corresponds to
//! an Identity Token (IT) without revealing the private key.
//!
//! # Design
//!
//! Uses a multi-row Poseidon sponge trace: each row encodes one permutation
//! with state_in, absorbed inputs, intermediates, and state_out. Transition
//! constraints link consecutive rows. The final row's state_out_0 is the GIT.
//!
//! # Security
//!
//! - Full Poseidon constraints via PoseidonGadget per row
//! - Private key material is kept secret in the witness
//! - Only the IT (hash output) is public

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

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

/// Columns per row: state_in (5) + input (2) + intermediates (960) + state_out (5) + is_final_row (1) = 973
const STATE_IN_COLS: usize = 5;
const INPUT_COLS: usize = 2;
const STATE_OUT_COLS: usize = 5;
/// Selector column: 1 on the last row (padding row), 0 elsewhere. Used for conditional transition.
const IS_FINAL_ROW_COL: usize = 1;

fn row_width() -> usize {
    STATE_IN_COLS +
        INPUT_COLS +
        PoseidonGadget::COLUMNS_PER_HASH +
        STATE_OUT_COLS +
        IS_FINAL_ROW_COL
}

/// ML-DSA security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaLevel {
    /// ML-DSA-44 (Security Level 2)
    Level44,
    /// ML-DSA-65 (Security Level 3, recommended)
    Level65,
    /// ML-DSA-87 (Security Level 5)
    Level87,
}

impl MlDsaLevel {
    /// Get the expected GIT size in bytes (always 16 bytes = 128 bits)
    pub const fn git_size_bytes() -> usize {
        16
    }

    /// Get the maximum private key size in bytes for this level
    pub const fn max_private_key_size(&self) -> usize {
        match self {
            MlDsaLevel::Level44 => 2528,
            MlDsaLevel::Level65 => 4000,
            MlDsaLevel::Level87 => 4864,
        }
    }
}

/// Maximum secret size in bytes
pub const MAX_SECRET_SIZE: usize = 5000;

/// AIR for proving knowledge of ML-DSA key ownership via Poseidon sponge.
///
/// Multi-row trace: each row = one Poseidon permutation (state_in, inputs,
/// intermediates, state_out). Transition constraints carry the sponge state.
#[derive(Debug, Clone)]
pub struct IdentityProofAir {
    dsa_level: MlDsaLevel,
    max_secret_size: usize,
}

impl IdentityProofAir {
    pub fn new(dsa_level: MlDsaLevel) -> Result<Self, AirError> {
        let max_secret_size = dsa_level.max_private_key_size();
        if max_secret_size > MAX_SECRET_SIZE {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Secret size {} exceeds maximum {}",
                    max_secret_size, MAX_SECRET_SIZE
                ),
            });
        }
        Ok(Self {
            dsa_level,
            max_secret_size,
        })
    }

    pub fn dsa_level(&self) -> MlDsaLevel {
        self.dsa_level
    }

    pub fn max_secret_size(&self) -> usize {
        self.max_secret_size
    }

    pub fn git_size_bytes(&self) -> usize {
        MlDsaLevel::git_size_bytes()
    }

    fn trace_width(&self) -> usize {
        row_width()
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for IdentityProofAir {
    fn width(&self) -> usize {
        self.trace_width()
    }
}

impl<AB: AirBuilder> Air<AB> for IdentityProofAir
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
        let intermediate_start = STATE_IN_COLS + INPUT_COLS; // 7
        // state_out at w-6..w-2, is_final_row at w-1
        let state_out_0 = local[w - 6].into();
        let state_out_1 = local[w - 5].into();
        let state_out_2 = local[w - 4].into();
        let state_out_3 = local[w - 3].into();
        let state_out_4 = local[w - 2].into();
        let is_final_row = local[w - 1].into();

        // First row: state_in = (input_0, input_1, 0, 0, 0)
        {
            let mut b = builder.when_first_row();
            b.assert_zero(state_in_0.clone() - input_0.clone());
            b.assert_zero(state_in_1.clone() - input_1.clone());
            b.assert_zero(state_in_2);
            b.assert_zero(state_in_3);
            b.assert_zero(state_in_4);
        }

        // Transition: rate (positions 0, 1) absorbs input; capacity (2, 3, 4) passes through.
        // On the padding row, state_in = state_out_prev + 10*1 in rate only: (1, 1, 0, 0, 0) for rate=2.
        {
            let next_state_in_0 = next[0].into();
            let next_state_in_1 = next[1].into();
            let next_state_in_2 = next[2].into();
            let next_state_in_3 = next[3].into();
            let next_state_in_4 = next[4].into();
            let next_input_0 = next[5].into();
            let next_input_1 = next[6].into();
            let next_is_final: AB::Expr = next[w - 1].into();
            let one_expr = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);
            let mut b = builder.when_transition();
            b.assert_bool(next_is_final.clone());
            // Normal: next_state_in = state_out + (next_input_0, next_input_1, 0, 0, 0).
            // Padding (10*1 in rate): next_state_in = state_out + (1, 1, 0, 0, 0).
            let norm_0 = next_state_in_0.clone() - (state_out_0.clone() + next_input_0.clone());
            let pad_0 = next_state_in_0.clone() - (state_out_0.clone() + one_expr.clone());
            b.assert_zero(
                (one_expr.clone() - next_is_final.clone()) * norm_0 + next_is_final.clone() * pad_0,
            );
            let norm_1 = next_state_in_1.clone() - (state_out_1.clone() + next_input_1.clone());
            let pad_1 = next_state_in_1.clone() - (state_out_1.clone() + one_expr.clone());
            b.assert_zero(
                (one_expr.clone() - next_is_final.clone()) * norm_1 + next_is_final.clone() * pad_1,
            );
            let norm_2 = next_state_in_2.clone() - state_out_2.clone();
            let pad_2 = next_state_in_2.clone() - state_out_2.clone();
            b.assert_zero(
                (one_expr.clone() - next_is_final.clone()) * norm_2 + next_is_final.clone() * pad_2,
            );
            let norm_3 = next_state_in_3.clone() - state_out_3.clone();
            let pad_3 = next_state_in_3.clone() - state_out_3.clone();
            b.assert_zero(
                (one_expr.clone() - next_is_final.clone()) * norm_3 + next_is_final.clone() * pad_3,
            );
            let norm_4 = next_state_in_4.clone() - state_out_4.clone();
            let pad_4 = next_state_in_4.clone() - state_out_4.clone();
            b.assert_zero(
                (one_expr.clone() - next_is_final.clone()) * norm_4 + next_is_final.clone() * pad_4,
            );
        }

        // Poseidon permutation with full 5-element state (multi-row sponge capacity carry).
        let gadget = PoseidonGadget::new();
        let full_state: [AB::Expr; 5] = [
            local[0].into(),
            local[1].into(),
            local[2].into(),
            local[3].into(),
            local[4].into(),
        ];
        if gadget
            .constrain_full_state(
                builder,
                &full_state,
                state_out_0.clone(),
                intermediate_start,
            )
            .is_err()
        {
            use lib_q_stark_field::PrimeCharacteristicRing;
            builder.assert_zero(AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE));
        }
        // Last row has is_final_row = 0 (padding row is at index num_permutations, not last).
        builder.when_last_row().assert_zero(is_final_row.clone());
        // On the padding row, bind state_out[0] to the public value (IT).
        let pubs = builder.public_values();
        if !pubs.is_empty() {
            let expected_it: AB::Expr = pubs[0].into();
            builder
                .when(is_final_row)
                .assert_eq(state_out_0, expected_it);
        }
    }
}

/// Input for identity proof trace generation
#[derive(Debug, Clone)]
pub struct IdentityProofInput {
    /// Secret value (private key or commitment) that hashes to the GIT
    pub secret: Vec<u8>,
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, IdentityProofInput>
    for IdentityProofAir
{
    fn generate_trace(
        &self,
        inputs: &IdentityProofInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        type Val = Complex<Mersenne31>;

        if inputs.secret.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "Secret cannot be empty".to_string(),
            });
        }
        if inputs.secret.len() > self.max_secret_size {
            return Err(AirError::ExceedsMaxSize {
                parameter: "secret".to_string(),
                max: self.max_secret_size,
                actual: inputs.secret.len(),
            });
        }

        use lib_q_stark_field::PrimeCharacteristicRing;
        let zero_f = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);

        let mut secret_fields = bytes_to_poseidon_field(&inputs.secret);
        if !secret_fields.len().is_multiple_of(2) {
            secret_fields.push(zero_f);
        }
        let num_permutations = core::cmp::max(1, secret_fields.len() / 2);
        // Need at least num_permutations + 1 rows (last row = padding + final permute, output = hash).
        // STARK requires power-of-2 height; quotient needs degree >= 2^log_num_quotient_chunks.
        const QUOTIENT_CHUNKS_FACTOR: usize = 4;
        let min_height = core::cmp::max(
            num_permutations + 1,
            core::cmp::max(num_permutations, 1) * QUOTIENT_CHUNKS_FACTOR,
        );
        let num_rows_padded = next_power_of_two(min_height);
        let trace_width = self.trace_width();
        validate_trace_dimensions(trace_width, num_rows_padded)?;

        let mut trace_values = vec![Val::ZERO; num_rows_padded * trace_width];
        let params = Poseidon128::params();
        let one_f = Complex::<Mersenne31>::new_complex(Mersenne31::ONE, Mersenne31::ZERO);

        let n = params.state_width;
        let padding_row = num_permutations; // padding row immediately after last secret row (no zero-absorb in between)
        let absorbed_padding = 0usize; // we pad secret to even length so next rate index is always 0
        let mut state = vec![zero_f; n];
        for row in 0..num_rows_padded {
            let (in0, in1, state_before_permute): (Val, Val, Vec<Val>) = if row == padding_row {
                // Padding row: match PoseidonSponge::finish_absorbing (10*1 in rate only; absorbed=0 when secret is even-length)
                let mut padded = state.clone();
                padded[absorbed_padding] += one_f;
                if absorbed_padding + 1 < params.rate {
                    padded[params.rate - 1] += one_f;
                }
                (zero_f, zero_f, padded)
            } else {
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
                    state[0] += in0;
                    state[1] += in1;
                }
                (in0, in1, state.clone())
            };

            let (state_out, intermediates) = compute_poseidon_row(&state_before_permute, &params);
            let base = row * trace_width;
            for i in 0..STATE_IN_COLS {
                trace_values[base + i] = poseidon_to_field(&state_before_permute[i]);
            }
            trace_values[base + 5] = poseidon_to_field(&in0);
            trace_values[base + 6] = poseidon_to_field(&in1);
            for (k, v) in intermediates.iter().enumerate() {
                if base + STATE_IN_COLS + INPUT_COLS + k < trace_values.len() {
                    trace_values[base + STATE_IN_COLS + INPUT_COLS + k] = poseidon_to_field(v);
                }
            }
            let out_start = base + trace_width - STATE_OUT_COLS - IS_FINAL_ROW_COL;
            for i in 0..STATE_OUT_COLS {
                trace_values[out_start + i] = poseidon_to_field(&state_out[i]);
            }
            trace_values[base + trace_width - 1] = if row == padding_row { one_f } else { zero_f };
            state = state_out;
        }

        Ok(RowMajorMatrix::new(trace_values, trace_width))
    }

    fn public_values(
        &self,
        inputs: &IdentityProofInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        type Val = Complex<Mersenne31>;
        use lib_q_stark_field::PrimeCharacteristicRing;
        let zero_f = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);

        let mut secret_fields = bytes_to_poseidon_field(&inputs.secret);
        if !secret_fields.len().is_multiple_of(2) {
            secret_fields.push(zero_f);
        }
        let hash_output = POSEIDON_128.hash(&secret_fields);
        if hash_output.is_empty() {
            return vec![Val::ZERO];
        }
        // Public value is the hash output (first squeezed element) so the trace can bind to it.
        vec![poseidon_to_field(&hash_output[0])]
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_matrix::Matrix;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    #[test]
    fn test_identity_proof_air_creation() {
        let air = IdentityProofAir::new(MlDsaLevel::Level65).unwrap();
        assert_eq!(air.dsa_level(), MlDsaLevel::Level65);
        assert_eq!(air.git_size_bytes(), 16);
    }

    #[test]
    fn test_identity_proof_air_validation() {
        assert!(IdentityProofAir::new(MlDsaLevel::Level44).is_ok());
        assert!(IdentityProofAir::new(MlDsaLevel::Level65).is_ok());
        assert!(IdentityProofAir::new(MlDsaLevel::Level87).is_ok());
    }

    #[test]
    fn test_identity_proof_trace_generation() {
        let air = IdentityProofAir::new(MlDsaLevel::Level65).unwrap();
        let input = IdentityProofInput {
            secret: b"test secret key".to_vec(),
        };
        let trace = air.generate_trace(&input);
        assert!(trace.is_ok(), "Trace generation should succeed");
    }

    #[test]
    fn test_identity_proof_public_values() {
        let air = IdentityProofAir::new(MlDsaLevel::Level65).unwrap();
        let input = IdentityProofInput {
            secret: b"test secret".to_vec(),
        };
        let public1 = air.public_values(&input);
        let public2 = air.public_values(&input);
        assert_eq!(public1, public2);
        assert!(!public1.is_empty());
    }

    #[test]
    fn test_identity_proof_trace_width() {
        let air = IdentityProofAir::new(MlDsaLevel::Level65).unwrap();
        assert_eq!(
            <IdentityProofAir as BaseAir<Complex<Mersenne31>>>::width(&air),
            row_width()
        );
    }

    /// Padding row state_out[0] must match Poseidon128::hash(secret)[0] (sponge alignment).
    #[test]
    fn test_identity_proof_trace_final_matches_poseidon_hash() {
        let air = IdentityProofAir::new(MlDsaLevel::Level65).unwrap();
        let input = IdentityProofInput {
            secret: b"test secret for sponge alignment".to_vec(),
        };
        let trace = air.generate_trace(&input).unwrap();
        let public_vals = air.public_values(&input);
        assert!(
            !public_vals.is_empty(),
            "identity proof must have one public value (IT)"
        );
        let expected_it = public_vals[0];
        let mut secret_fields = bytes_to_poseidon_field(&input.secret);
        if secret_fields.len() % 2 != 0 {
            use lib_q_stark_field::PrimeCharacteristicRing;
            let z = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);
            secret_fields.push(z);
        }
        let num_permutations = core::cmp::max(1, secret_fields.len() / 2);
        let padding_row = num_permutations; // padding row index
        let w = row_width();
        let state_out_0_col = w - STATE_OUT_COLS - IS_FINAL_ROW_COL;
        let trace_final_out_0 = trace.get(padding_row, state_out_0_col).unwrap().clone();
        assert_eq!(
            trace_final_out_0, expected_it,
            "trace padding row state_out[0] must equal Poseidon128::hash(secret)[0] (IT)"
        );
    }
}
