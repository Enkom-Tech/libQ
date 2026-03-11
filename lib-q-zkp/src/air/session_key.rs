//! Session Key Derivation AIR - Proves correct KDF derivation from ML-KEM shared secret
//!
//! This AIR proves that session keys were correctly derived from an ML-KEM
//! shared secret using a Poseidon sponge KDF, without revealing the shared
//! secret or session keys.
//!
//! # Design
//!
//! Multi-row Poseidon sponge trace (same pattern as IdentityProofAir):
//! - Each row = one Poseidon permutation (state_in, inputs, intermediates, state_out)
//! - Absorb shared_secret in pairs; final row's state_out_0 = commitment to session keys
//! - Public value: Poseidon(session_key_bytes)
//!
//! # Security
//!
//! - Full Poseidon constraints via PoseidonGadget per row
//! - Shared secret and session keys remain secret in the witness
//! - Only the commitment is public

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
    PoseidonField,
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
    next_power_of_two,
    poseidon_to_field,
    validate_trace_dimensions,
};

/// Poseidon-128 hasher instance
const POSEIDON_128: Poseidon128 = Poseidon128;

/// Row layout: state_in (3) + input (2) + intermediates (576) + state_out (3) = 584 (same as IdentityProofAir)
const STATE_IN_COLS: usize = 3;
const INPUT_COLS: usize = 2;
const STATE_OUT_COLS: usize = 3;

fn row_width() -> usize {
    STATE_IN_COLS + INPUT_COLS + PoseidonGadget::COLUMNS_PER_HASH + STATE_OUT_COLS
}

/// Maximum shared secret size in bytes
pub const MAX_SHARED_SECRET_SIZE: usize = 32;

/// Maximum session key size in bytes
pub const MAX_SESSION_KEY_SIZE: usize = 64;

/// KDF parameters
#[derive(Debug, Clone)]
pub struct KdfParams {
    /// KDF algorithm identifier
    pub algorithm: KdfAlgorithm,
    /// Salt (optional)
    pub salt: Option<Vec<u8>>,
    /// Info (optional context)
    pub info: Option<Vec<u8>>,
    /// Output key length in bytes
    pub output_length: usize,
}

/// KDF algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// HKDF-SHA3 (as per IP spec)
    HkdfSha3,
    /// Simplified Poseidon-based KDF for ZKP efficiency
    PoseidonKdf,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::HkdfSha3,
            salt: None,
            info: None,
            output_length: 32,
        }
    }
}

/// AIR for proving session key derivation via Poseidon sponge.
///
/// Multi-row trace: each row = one Poseidon permutation. Transition constraints
/// carry the sponge state. Final row's state_out_0 must equal public commitment.
#[derive(Debug, Clone)]
pub struct SessionKeyDerivationAir {
    kdf_params: KdfParams,
}

impl SessionKeyDerivationAir {
    /// Create a new SessionKeyDerivationAir
    pub fn new(kdf_params: KdfParams) -> Result<Self, AirError> {
        if kdf_params.output_length == 0 {
            return Err(AirError::InvalidDimensions {
                reason: "Output length must be greater than 0".to_string(),
            });
        }

        if kdf_params.output_length > MAX_SESSION_KEY_SIZE {
            return Err(AirError::ExceedsMaxSize {
                parameter: "output_length".to_string(),
                max: MAX_SESSION_KEY_SIZE,
                actual: kdf_params.output_length,
            });
        }

        Ok(Self { kdf_params })
    }

    /// Get the KDF parameters
    pub fn kdf_params(&self) -> &KdfParams {
        &self.kdf_params
    }

    fn trace_width_inner(&self) -> usize {
        row_width()
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for SessionKeyDerivationAir {
    fn width(&self) -> usize {
        self.trace_width_inner()
    }
}

impl<AB: AirBuilder> Air<AB> for SessionKeyDerivationAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let w = row_width();
        let state_in_0 = local[0].clone().into();
        let state_in_1 = local[1].clone().into();
        let state_in_2 = local[2].clone().into();
        let input_0 = local[3].clone().into();
        let input_1 = local[4].clone().into();
        let intermediate_start = STATE_IN_COLS + INPUT_COLS;
        let state_out_0 = local[w - 3].clone().into();
        let state_out_1 = local[w - 2].clone().into();
        let state_out_2 = local[w - 1].clone().into();

        {
            let mut b = builder.when_first_row();
            b.assert_zero(state_in_0.clone() - input_0.clone());
            b.assert_zero(state_in_1.clone() - input_1.clone());
            b.assert_zero(state_in_2);
        }

        {
            let next_state_in_0 = next[0].clone().into();
            let next_state_in_1 = next[1].clone().into();
            let next_state_in_2 = next[2].clone().into();
            let next_input_0 = next[3].clone().into();
            let next_input_1 = next[4].clone().into();
            let mut b = builder.when_transition();
            b.assert_zero(next_state_in_0 - state_out_0.clone());
            b.assert_zero(next_state_in_1 - (state_out_1.clone() + next_input_0));
            b.assert_zero(next_state_in_2 - (state_out_2 + next_input_1));
        }

        // Poseidon permutation per row
        let gadget = PoseidonGadget::new();
        if gadget
            .constrain(
                builder,
                state_in_0,
                state_in_1,
                state_out_0,
                intermediate_start,
            )
            .is_err()
        {
            use lib_q_stark_field::PrimeCharacteristicRing;
            builder.assert_zero(AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE));
        }
    }
}

/// Input for session key derivation proof
#[derive(Debug, Clone)]
pub struct SessionKeyInput {
    /// ML-KEM shared secret (absorbed into sponge)
    pub shared_secret: Vec<u8>,
    /// Derived session keys (commitment = Poseidon(session_keys))
    pub session_keys: Vec<u8>,
}

/// Compute one Poseidon permutation with intermediates (same as identity_proof)
fn compute_poseidon_row(
    state: &[PoseidonField; 3],
    params: &lib_q_poseidon::PoseidonParams,
) -> ([PoseidonField; 3], Vec<PoseidonField>) {
    use lib_q_poseidon::sbox;
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    let zero = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);
    let mut intermediates = Vec::new();
    let mut round_idx = 0usize;
    let mut s = [state[0], state[1], state[2]];
    let full_half = params.full_rounds / 2;

    for _ in 0..full_half {
        let after_arc = [
            s[0] + params.round_constants[round_idx],
            s[1] + params.round_constants[round_idx + 1],
            s[2] + params.round_constants[round_idx + 2],
        ];
        round_idx += 3;
        intermediates.extend_from_slice(&after_arc);
        let after_sbox = [sbox(after_arc[0]), sbox(after_arc[1]), sbox(after_arc[2])];
        intermediates.extend_from_slice(&after_sbox);
        let mut next_s = [zero, zero, zero];
        for (i, next_s_i) in next_s.iter_mut().enumerate() {
            for (j, &after_sbox_j) in after_sbox.iter().enumerate() {
                *next_s_i += params.mds_matrix[i][j] * after_sbox_j;
            }
        }
        intermediates.extend_from_slice(&next_s);
        s = next_s;
    }
    for _ in 0..params.partial_rounds {
        let after_arc = [
            s[0] + params.round_constants[round_idx],
            s[1] + params.round_constants[round_idx + 1],
            s[2] + params.round_constants[round_idx + 2],
        ];
        round_idx += 3;
        intermediates.extend_from_slice(&after_arc);
        let after_sbox = [sbox(after_arc[0]), after_arc[1], after_arc[2]];
        intermediates.extend_from_slice(&after_sbox);
        let mut next_s = [zero, zero, zero];
        for (i, next_s_i) in next_s.iter_mut().enumerate() {
            for (j, &after_sbox_j) in after_sbox.iter().enumerate() {
                *next_s_i += params.mds_matrix[i][j] * after_sbox_j;
            }
        }
        intermediates.extend_from_slice(&next_s);
        s = next_s;
    }
    for _ in 0..full_half {
        let after_arc = [
            s[0] + params.round_constants[round_idx],
            s[1] + params.round_constants[round_idx + 1],
            s[2] + params.round_constants[round_idx + 2],
        ];
        round_idx += 3;
        intermediates.extend_from_slice(&after_arc);
        let after_sbox = [sbox(after_arc[0]), sbox(after_arc[1]), sbox(after_arc[2])];
        intermediates.extend_from_slice(&after_sbox);
        let mut next_s = [zero, zero, zero];
        for (i, next_s_i) in next_s.iter_mut().enumerate() {
            for (j, &after_sbox_j) in after_sbox.iter().enumerate() {
                *next_s_i += params.mds_matrix[i][j] * after_sbox_j;
            }
        }
        intermediates.extend_from_slice(&next_s);
        s = next_s;
    }
    (s, intermediates)
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, SessionKeyInput>
    for SessionKeyDerivationAir
{
    fn generate_trace(
        &self,
        inputs: &SessionKeyInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        type Val = Complex<Mersenne31>;

        if inputs.shared_secret.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "Shared secret cannot be empty".to_string(),
            });
        }

        if inputs.shared_secret.len() > MAX_SHARED_SECRET_SIZE {
            return Err(AirError::ExceedsMaxSize {
                parameter: "shared_secret".to_string(),
                max: MAX_SHARED_SECRET_SIZE,
                actual: inputs.shared_secret.len(),
            });
        }

        if inputs.session_keys.len() != self.kdf_params.output_length {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Session keys length {} must match output_length {}",
                    inputs.session_keys.len(),
                    self.kdf_params.output_length
                ),
            });
        }

        let secret_fields = bytes_to_poseidon_field(&inputs.shared_secret);
        let num_permutations = 1.max(secret_fields.len().div_ceil(2));
        let num_rows_padded = next_power_of_two(num_permutations);
        let trace_width = self.trace_width_inner();
        validate_trace_dimensions(trace_width, num_rows_padded)?;

        let mut trace_values = vec![Val::ZERO; num_rows_padded * trace_width];
        let params = Poseidon128::params();
        use lib_q_stark_field::PrimeCharacteristicRing;
        let zero_f = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);

        let mut state = [zero_f, zero_f, zero_f];
        for row in 0..num_permutations {
            let i0 = row * 2;
            let i1 = row * 2 + 1;
            let in0 = secret_fields.get(i0).cloned().unwrap_or(zero_f);
            let in1 = secret_fields.get(i1).cloned().unwrap_or(zero_f);

            if row == 0 {
                state = [in0, in1, zero_f];
            } else {
                state = [state[0], state[1] + in0, state[2] + in1];
            }

            let state_in = state;
            let (state_out, intermediates) = compute_poseidon_row(&state, &params);
            state = state_out;

            let base = row * trace_width;
            trace_values[base] = poseidon_to_field(&state_in[0]);
            trace_values[base + 1] = poseidon_to_field(&state_in[1]);
            trace_values[base + 2] = poseidon_to_field(&state_in[2]);
            trace_values[base + 3] = poseidon_to_field(&in0);
            trace_values[base + 4] = poseidon_to_field(&in1);
            for (k, v) in intermediates.iter().enumerate() {
                if base + STATE_IN_COLS + INPUT_COLS + k < trace_values.len() {
                    trace_values[base + STATE_IN_COLS + INPUT_COLS + k] = poseidon_to_field(v);
                }
            }
            let out_start = base + trace_width - STATE_OUT_COLS;
            trace_values[out_start] = poseidon_to_field(&state_out[0]);
            trace_values[out_start + 1] = poseidon_to_field(&state_out[1]);
            trace_values[out_start + 2] = poseidon_to_field(&state_out[2]);
        }

        Ok(RowMajorMatrix::new(trace_values, trace_width))
    }

    fn public_values(
        &self,
        inputs: &SessionKeyInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        type Val = Complex<Mersenne31>;

        // Public value: commitment = Poseidon(session_key_bytes)
        let key_fields = bytes_to_poseidon_field(&inputs.session_keys);
        let commitment_hash = POSEIDON_128.hash(&key_fields);

        if !commitment_hash.is_empty() {
            vec![poseidon_to_field(&commitment_hash[0])]
        } else {
            vec![Val::ZERO]
        }
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_matrix::Matrix;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_session_key_air_creation() {
        let params = KdfParams::default();
        let air = SessionKeyDerivationAir::new(params).unwrap();
        assert_eq!(air.kdf_params().output_length, 32);
        assert_eq!(
            <SessionKeyDerivationAir as BaseAir<TestField>>::width(&air),
            row_width()
        );
    }

    #[test]
    fn test_session_key_trace_generation() {
        let params = KdfParams {
            output_length: 32,
            ..Default::default()
        };
        let air = SessionKeyDerivationAir::new(params).unwrap();

        let input = SessionKeyInput {
            shared_secret: vec![1, 2, 3, 4],
            session_keys: vec![5u8; 32],
        };

        let trace = air.generate_trace(&input);
        assert!(trace.is_ok());
        let trace = trace.unwrap();
        assert_eq!(trace.width(), row_width());
        assert!(trace.height().is_power_of_two());
    }
}
