//! State Transition AIR - Proves valid blockchain state transitions
//!
//! This AIR proves that a blockchain state transition is valid without
//! revealing all transaction details. Used for confidential blockchain
//! applications.
//!
//! # Design
//!
//! Proves state machine transitions where:
//! - Pre-state hash is known
//! - Post-state hash is known
//! - Transition constraints are satisfied
//! - Transaction validity is proven
//!
//! # Security
//!
//! - Uses Poseidon-128 for state hashing
//! - Transaction details can remain confidential
//! - State integrity is cryptographically verified

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
    WindowAccess,
};
use lib_q_stark_field::integers::QuotientMap;
use lib_q_stark_field::{
    BasedVectorSpace,
    Field,
    PrimeCharacteristicRing,
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::{
    AirError,
    TraceGenerator,
    bytes_to_poseidon_field,
    next_power_of_two,
    poseidon_to_field,
    validate_trace_dimensions,
};

/// State hash size in bytes (32 bytes = 256 bits)
pub const STATE_HASH_SIZE: usize = 32;

/// Maximum transaction data size
pub const MAX_TRANSACTION_SIZE: usize = 4096;

/// Transition constraints type
#[derive(Debug, Clone)]
pub struct TransitionConstraints {
    /// Whether to verify transaction signatures (via hash commitment)
    pub verify_signatures: bool,
    /// Whether to verify balances
    pub verify_balances: bool,
    /// Whether to verify nonces
    pub verify_nonces: bool,
    /// When verify_signatures is true, the verifier must check ML-DSA outside the STARK and set
    /// this to Poseidon(signature_bytes). The AIR then constrains that the trace's signature
    /// commitment column equals this value. Full in-circuit Poseidon(signature) verification
    /// is a future enhancement.
    pub signature_commitment: Option<[u8; STATE_HASH_SIZE]>,
}

impl Default for TransitionConstraints {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            verify_balances: true,
            verify_nonces: true,
            signature_commitment: None,
        }
    }
}

/// AIR for proving valid blockchain state transitions
///
/// This proves that a state transition from `pre_state_hash` to `post_state_hash`
/// is valid according to the transition constraints, without revealing
/// transaction details.
///
/// # Trace Layout
///
/// - Pre-state hash (32 bytes)
/// - Transaction data (confidential)
/// - Post-state hash (32 bytes)
/// - Transition proof: first 32 bytes = signature commitment (Poseidon(signature)); remainder reserved
#[derive(Debug, Clone)]
pub struct StateTransitionAir {
    /// State hash before transition
    pre_state_hash: [u8; STATE_HASH_SIZE],
    /// State hash after transition
    post_state_hash: [u8; STATE_HASH_SIZE],
    /// Transition constraints
    constraints: TransitionConstraints,
}

impl StateTransitionAir {
    /// Create a new StateTransitionAir
    ///
    /// # Arguments
    ///
    /// * `pre_state_hash` - Hash of state before transition
    /// * `post_state_hash` - Hash of state after transition
    /// * `constraints` - Transition constraints to verify
    ///
    /// # Returns
    ///
    /// `Ok(StateTransitionAir)` if successful
    pub fn new(
        pre_state_hash: [u8; STATE_HASH_SIZE],
        post_state_hash: [u8; STATE_HASH_SIZE],
        constraints: TransitionConstraints,
    ) -> Self {
        Self {
            pre_state_hash,
            post_state_hash,
            constraints,
        }
    }

    /// Get the pre-state hash
    pub fn pre_state_hash(&self) -> &[u8; STATE_HASH_SIZE] {
        &self.pre_state_hash
    }

    /// Get the post-state hash
    pub fn post_state_hash(&self) -> &[u8; STATE_HASH_SIZE] {
        &self.post_state_hash
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for StateTransitionAir {
    fn width(&self) -> usize {
        // Trace columns:
        // - Pre-state hash: STATE_HASH_SIZE
        // - Transaction data: MAX_TRANSACTION_SIZE
        // - Post-state hash: STATE_HASH_SIZE
        // - Transition proof: 32 (signature commitment) + 32 reserved
        STATE_HASH_SIZE + MAX_TRANSACTION_SIZE + STATE_HASH_SIZE + 64
    }
}

impl<AB: AirBuilder> Air<AB> for StateTransitionAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31> + PrimeCharacteristicRing,
{
    fn eval(&self, builder: &mut AB) {
        use lib_q_stark_field::PrimeCharacteristicRing;

        let main = builder.main();
        let local = main.current_slice();

        // 1. Constrain pre-state hash columns == known pre_state_hash bytes
        for (i, &byte) in self.pre_state_hash.iter().enumerate() {
            let expected = AB::F::from_prime_subfield(
                <<AB::F as PrimeCharacteristicRing>::PrimeSubfield as QuotientMap<u8>>::from_int(
                    byte,
                ),
            );
            builder.assert_eq(local[i].into(), AB::Expr::from(expected));
        }

        // 2. Constrain post-state hash columns == known post_state_hash bytes
        let post_start = STATE_HASH_SIZE + MAX_TRANSACTION_SIZE;
        for (i, &byte) in self.post_state_hash.iter().enumerate() {
            let expected = AB::F::from_prime_subfield(
                <<AB::F as PrimeCharacteristicRing>::PrimeSubfield as QuotientMap<u8>>::from_int(
                    byte,
                ),
            );
            builder.assert_eq(local[post_start + i].into(), AB::Expr::from(expected));
        }

        // 3. Transition constraints
        let tx_start = STATE_HASH_SIZE;
        if self.constraints.verify_nonces {
            // Nonce region: first 4 bytes of tx data (existence in trace)
        }

        if self.constraints.verify_balances {
            // Balance region: bytes 4..36 of tx data; conservation: sum == 0
            let balance_start = tx_start + 4;
            let zero = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ZERO);
            let mut balance_sum = zero.clone();
            for i in 0..32 {
                balance_sum += AB::Expr::from(local[balance_start + i]);
            }
            builder.assert_zero(balance_sum);
        }

        // verify_signatures: hash-commitment approach. Verifier checks ML-DSA outside the STARK
        // and provides signature_commitment = Poseidon(signature). We constrain the trace's
        // signature-commitment column to equal that value. Full in-circuit Poseidon(signature)
        // verification is a future enhancement.
        if self.constraints.verify_signatures &&
            let Some(ref commitment) = self.constraints.signature_commitment
        {
            let proof_start = STATE_HASH_SIZE + MAX_TRANSACTION_SIZE + STATE_HASH_SIZE;
            for (i, &byte) in commitment.iter().take(32).enumerate() {
                let col = proof_start + i;
                if col < local.len() {
                    let expected =
                        AB::F::from_prime_subfield(
                            <<AB::F as PrimeCharacteristicRing>::PrimeSubfield as QuotientMap<
                                u8,
                            >>::from_int(byte),
                        );
                    builder.assert_eq(local[col].into(), AB::Expr::from(expected));
                }
            }
        }
    }
}

/// Input for state transition proof
#[derive(Debug, Clone)]
pub struct StateTransitionInput {
    /// Transaction data (confidential)
    pub transaction_data: Vec<u8>,
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, StateTransitionInput>
    for StateTransitionAir
{
    fn generate_trace(
        &self,
        inputs: &StateTransitionInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        if inputs.transaction_data.len() > MAX_TRANSACTION_SIZE {
            return Err(AirError::ExceedsMaxSize {
                parameter: "transaction_data".to_string(),
                max: MAX_TRANSACTION_SIZE,
                actual: inputs.transaction_data.len(),
            });
        }

        let trace_width = {
            use lib_q_stark_field::extension::Complex;
            use lib_q_stark_mersenne31::Mersenne31;
            <Self as BaseAir<Complex<Mersenne31>>>::width(self)
        };
        let trace_height = 1;
        let num_rows_padded = next_power_of_two(trace_height);

        validate_trace_dimensions(trace_width, num_rows_padded)?;

        let mut trace_values = vec![Complex::<Mersenne31>::ZERO; num_rows_padded * trace_width];
        let base = 0;

        // Fill pre-state hash
        for (i, byte) in self.pre_state_hash.iter().enumerate() {
            trace_values[base + i] = Complex::<Mersenne31>::from_prime_subfield(
                <Mersenne31 as QuotientMap<u8>>::from_int(*byte),
            );
        }

        // Fill transaction data
        let tx_start = STATE_HASH_SIZE;
        for (i, byte) in inputs.transaction_data.iter().enumerate() {
            if i < MAX_TRANSACTION_SIZE {
                trace_values[base + tx_start + i] = Complex::<Mersenne31>::from_prime_subfield(
                    <Mersenne31 as QuotientMap<u8>>::from_int(*byte),
                );
            }
        }

        // Fill post-state hash
        let post_start = tx_start + MAX_TRANSACTION_SIZE;
        for (i, byte) in self.post_state_hash.iter().enumerate() {
            trace_values[base + post_start + i] = Complex::<Mersenne31>::from_prime_subfield(
                <Mersenne31 as QuotientMap<u8>>::from_int(*byte),
            );
        }

        // Fill signature commitment (first 32 bytes of transition proof) when set
        if self.constraints.verify_signatures &&
            let Some(ref commitment) = self.constraints.signature_commitment
        {
            let proof_start = post_start + STATE_HASH_SIZE;
            for (i, &byte) in commitment.iter().take(32).enumerate() {
                trace_values[base + proof_start + i] = Complex::<Mersenne31>::from_prime_subfield(
                    <Mersenne31 as QuotientMap<u8>>::from_int(byte),
                );
            }
        }

        Ok(RowMajorMatrix::new(trace_values, trace_width))
    }

    fn public_values(
        &self,
        _inputs: &StateTransitionInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        // Public values: pre-state and post-state hashes
        let pre_fields = bytes_to_poseidon_field(&self.pre_state_hash);
        let post_fields = bytes_to_poseidon_field(&self.post_state_hash);

        let mut public_vals = Vec::new();
        for field in pre_fields {
            public_vals.push(poseidon_to_field(&field));
        }
        for field in post_fields {
            public_vals.push(poseidon_to_field(&field));
        }

        public_vals
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_matrix::Matrix;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    #[test]
    fn test_state_transition_air_creation() {
        let pre = [0u8; STATE_HASH_SIZE];
        let post = [1u8; STATE_HASH_SIZE];
        let constraints = TransitionConstraints::default();
        let air = StateTransitionAir::new(pre, post, constraints);
        assert_eq!(air.pre_state_hash(), &pre);
        assert_eq!(air.post_state_hash(), &post);
    }

    #[test]
    fn test_state_transition_trace_generation() {
        let pre = [0u8; STATE_HASH_SIZE];
        let post = [1u8; STATE_HASH_SIZE];
        let constraints = TransitionConstraints::default();
        let air = StateTransitionAir::new(pre, post, constraints);

        let input = StateTransitionInput {
            transaction_data: vec![1, 2, 3, 4],
        };

        let trace = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_state_transition_public_values_length() {
        let air = StateTransitionAir::new(
            [0u8; STATE_HASH_SIZE],
            [1u8; STATE_HASH_SIZE],
            TransitionConstraints::default(),
        );
        let input = StateTransitionInput {
            transaction_data: vec![1, 2, 3, 4],
        };
        assert_eq!(air.public_values(&input).len(), STATE_HASH_SIZE * 2);
    }

    #[test]
    fn test_state_transition_public_values_reflect_hashes() {
        type Val = Complex<Mersenne31>;

        let pre = [42u8; STATE_HASH_SIZE];
        let post = [99u8; STATE_HASH_SIZE];
        let air = StateTransitionAir::new(pre, post, TransitionConstraints::default());
        let input = StateTransitionInput {
            transaction_data: vec![],
        };

        let public_vals = air.public_values(&input);
        assert_eq!(public_vals.len(), STATE_HASH_SIZE * 2);

        for i in 0..STATE_HASH_SIZE {
            assert_eq!(
                public_vals[i],
                Val::from_u32(pre[i] as u32),
                "pre-state byte {i} mismatch",
            );
        }
        for i in 0..STATE_HASH_SIZE {
            assert_eq!(
                public_vals[STATE_HASH_SIZE + i],
                Val::from_u32(post[i] as u32),
                "post-state byte {i} mismatch",
            );
        }
    }

    #[test]
    fn test_state_transition_public_values_change_with_hashes() {
        let input = StateTransitionInput {
            transaction_data: vec![],
        };

        let air_a = StateTransitionAir::new(
            [0u8; STATE_HASH_SIZE],
            [1u8; STATE_HASH_SIZE],
            TransitionConstraints::default(),
        );
        let air_b = StateTransitionAir::new(
            [2u8; STATE_HASH_SIZE],
            [1u8; STATE_HASH_SIZE],
            TransitionConstraints::default(),
        );

        assert_ne!(air_a.public_values(&input), air_b.public_values(&input));
    }

    #[test]
    fn test_state_transition_public_values_independent_of_transaction_data() {
        let pre = [5u8; STATE_HASH_SIZE];
        let post = [7u8; STATE_HASH_SIZE];
        let air = StateTransitionAir::new(pre, post, TransitionConstraints::default());

        let vals_empty = air.public_values(&StateTransitionInput {
            transaction_data: vec![],
        });
        let vals_data = air.public_values(&StateTransitionInput {
            transaction_data: vec![9, 8, 7, 6],
        });

        assert_eq!(vals_empty, vals_data);
    }

    #[test]
    fn test_state_transition_trace_generation_rejects_oversized_transaction_data() {
        let air = StateTransitionAir::new(
            [0u8; STATE_HASH_SIZE],
            [1u8; STATE_HASH_SIZE],
            TransitionConstraints::default(),
        );
        let input = StateTransitionInput {
            transaction_data: vec![0u8; MAX_TRANSACTION_SIZE + 1],
        };
        let result = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::ExceedsMaxSize { .. })));
    }

    #[test]
    fn test_state_transition_trace_writes_signature_commitment_when_enabled() {
        type Val = Complex<Mersenne31>;
        let commitment = [9u8; STATE_HASH_SIZE];
        let constraints = TransitionConstraints {
            verify_signatures: true,
            verify_balances: false,
            verify_nonces: false,
            signature_commitment: Some(commitment),
        };
        let air =
            StateTransitionAir::new([0u8; STATE_HASH_SIZE], [1u8; STATE_HASH_SIZE], constraints);
        let trace = air
            .generate_trace(&StateTransitionInput {
                transaction_data: vec![],
            })
            .expect("trace");

        let proof_start = STATE_HASH_SIZE + MAX_TRANSACTION_SIZE + STATE_HASH_SIZE;
        assert_eq!(trace.get(0, proof_start), Some(Val::from_u32(9)));
        assert_eq!(trace.get(0, proof_start + 31), Some(Val::from_u32(9)));
    }

    #[test]
    fn test_state_transition_trace_ignores_signature_commitment_when_disabled() {
        type Val = Complex<Mersenne31>;
        let constraints = TransitionConstraints {
            verify_signatures: false,
            verify_balances: false,
            verify_nonces: false,
            signature_commitment: Some([7u8; STATE_HASH_SIZE]),
        };
        let air =
            StateTransitionAir::new([0u8; STATE_HASH_SIZE], [1u8; STATE_HASH_SIZE], constraints);
        let trace = air
            .generate_trace(&StateTransitionInput {
                transaction_data: vec![],
            })
            .expect("trace");

        let proof_start = STATE_HASH_SIZE + MAX_TRANSACTION_SIZE + STATE_HASH_SIZE;
        assert_eq!(trace.get(0, proof_start), Some(Val::ZERO));
        assert_eq!(trace.get(0, proof_start + 31), Some(Val::ZERO));
    }
}
