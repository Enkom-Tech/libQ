//! Credential AIR - Proves attributes from a credential without revealing full credential
//!
//! This AIR enables selective disclosure of credential attributes, allowing
//! the prover to reveal only specific attributes while keeping others secret.
//!
//! # Design
//!
//! Hash-then-commit using a single-row trace with multiple Poseidon blocks:
//! - Phase 1 blocks (one per attribute): Poseidon(attr_left, attr_right) = attr_hash_i
//! - Phase 2 blocks (aggregation): Poseidon(prev_hash, attr_hash) = next_hash; final block = commitment
//!
//! # Security
//!
//! - Full Poseidon constraints via PoseidonGadget per block
//! - Hidden attributes remain secret in the witness
//! - Commitment binding ensures credential integrity

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

use lib_q_poseidon::PoseidonField;
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

use super::merkle_inclusion::compute_poseidon_with_intermediates;
use super::poseidon_gadget::PoseidonGadget;
use super::{
    AirError,
    TraceGenerator,
    bytes_to_poseidon_field,
    next_power_of_two,
    poseidon_to_field,
    validate_trace_dimensions,
};

/// Columns per hash block: left (1) + right (1) + output (1) + intermediates (576) = 579
const COLS_PER_BLOCK: usize = 3 + PoseidonGadget::COLUMNS_PER_HASH;

/// Maximum number of attributes in a credential
pub const MAX_ATTRIBUTES: usize = 64;

/// Maximum size per attribute in bytes
pub const MAX_ATTRIBUTE_SIZE: usize = 256;

/// Credential schema defining attribute structure
#[derive(Debug, Clone)]
pub struct CredentialSchema {
    /// Number of attributes
    pub num_attributes: usize,
    /// Size of each attribute in bytes
    pub attribute_sizes: Vec<usize>,
}

impl CredentialSchema {
    /// Create a new credential schema
    pub fn new(attribute_sizes: Vec<usize>) -> Result<Self, AirError> {
        if attribute_sizes.is_empty() {
            return Err(AirError::InvalidDimensions {
                reason: "Credential must have at least one attribute".to_string(),
            });
        }

        if attribute_sizes.len() > MAX_ATTRIBUTES {
            return Err(AirError::ExceedsMaxSize {
                parameter: "num_attributes".to_string(),
                max: MAX_ATTRIBUTES,
                actual: attribute_sizes.len(),
            });
        }

        for (i, size) in attribute_sizes.iter().enumerate() {
            if *size > MAX_ATTRIBUTE_SIZE {
                return Err(AirError::ExceedsMaxSize {
                    parameter: format!("attribute_{}", i),
                    max: MAX_ATTRIBUTE_SIZE,
                    actual: *size,
                });
            }
        }

        Ok(Self {
            num_attributes: attribute_sizes.len(),
            attribute_sizes,
        })
    }
}

/// AIR for proving credential attributes with selective disclosure
///
/// Single-row trace: num_attributes attribute-hash blocks plus (num_attributes - 1)
/// aggregation blocks. Each block: left, right, output, 576 intermediates.
/// Equality constraints bind aggregation inputs to previous block outputs.
#[derive(Debug, Clone)]
pub struct CredentialAir {
    schema: CredentialSchema,
    revealed_mask: Vec<bool>,
}

impl CredentialAir {
    /// Create a new CredentialAir
    pub fn new(schema: CredentialSchema, revealed_mask: Vec<bool>) -> Result<Self, AirError> {
        if revealed_mask.len() != schema.num_attributes {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Revealed mask length {} must match schema attributes {}",
                    revealed_mask.len(),
                    schema.num_attributes
                ),
            });
        }

        Ok(Self {
            schema,
            revealed_mask,
        })
    }

    /// Get the credential schema
    pub fn schema(&self) -> &CredentialSchema {
        &self.schema
    }

    /// Get the revealed mask
    pub fn revealed_mask(&self) -> &[bool] {
        &self.revealed_mask
    }

    /// Number of hash blocks: n attribute hashes + (n-1) aggregation = 2n - 1
    fn num_blocks(&self) -> usize {
        let n = self.schema.num_attributes;
        n + n.saturating_sub(1)
    }

    /// Trace width: one block per attribute hash plus aggregation blocks
    fn trace_width_inner(&self) -> usize {
        self.num_blocks() * COLS_PER_BLOCK
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for CredentialAir {
    fn width(&self) -> usize {
        self.trace_width_inner()
    }
}

impl<AB: AirBuilder> Air<AB> for CredentialAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        use super::poseidon_gadget::PoseidonGadget;

        let main = builder.main();
        let local = main.current_slice();

        let n = self.schema.num_attributes;
        let num_blocks = self.num_blocks();
        let gadget = PoseidonGadget::new();

        // Helper: get (left, right, output, intermediate_start) for block i
        let block_cols = |i: usize| {
            let base = i * COLS_PER_BLOCK;
            let left = local[base].clone().into();
            let right = local[base + 1].clone().into();
            let out = local[base + 2].clone().into();
            let intermed_start = base + 3;
            (left, right, out, intermed_start)
        };

        // Constrain each block's Poseidon
        for i in 0..num_blocks {
            let (left, right, out, intermed_start) = block_cols(i);
            if gadget
                .constrain(builder, left, right, out, intermed_start)
                .is_err()
            {
                use lib_q_stark_field::PrimeCharacteristicRing;
                builder.assert_zero(AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE));
            }
        }

        // Bind aggregation block inputs to previous block outputs
        // Block n (k=0): left = output_0, right = output_1
        // Block n+k (k>=1): left = output_{n+k-1}, right = output_{k+1}
        if n >= 2 {
            for k in 0..(n - 1) {
                let agg_block = n + k;
                let prev_out_col = if k == 0 {
                    2 // block 0 output column
                } else {
                    (n + k - 1) * COLS_PER_BLOCK + 2
                };
                let next_out_col = (k + 1) * COLS_PER_BLOCK + 2;
                let agg_left = agg_block * COLS_PER_BLOCK;
                let agg_right = agg_block * COLS_PER_BLOCK + 1;
                builder.assert_zero(
                    local[agg_left].clone().into() - local[prev_out_col].clone().into(),
                );
                builder.assert_zero(
                    local[agg_right].clone().into() - local[next_out_col].clone().into(),
                );
            }
        }
    }
}

/// Input for credential proof trace generation
#[derive(Debug, Clone)]
pub struct CredentialInput {
    /// All attribute values (both revealed and hidden)
    pub attributes: Vec<Vec<u8>>,
}

pub(crate) fn attr_to_left_right(attr: &[u8]) -> (PoseidonField, PoseidonField) {
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    let fields = bytes_to_poseidon_field(attr);
    let zero = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);
    let left = fields.first().cloned().unwrap_or(zero);
    let right = fields.get(1).cloned().unwrap_or(zero);
    (left, right)
}

impl TraceGenerator<lib_q_stark_field::extension::Complex<Mersenne31>, CredentialInput>
    for CredentialAir
{
    fn generate_trace(
        &self,
        inputs: &CredentialInput,
    ) -> Result<RowMajorMatrix<lib_q_stark_field::extension::Complex<Mersenne31>>, AirError> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        type Val = Complex<Mersenne31>;

        if inputs.attributes.len() != self.schema.num_attributes {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Number of attributes {} must match schema {}",
                    inputs.attributes.len(),
                    self.schema.num_attributes
                ),
            });
        }

        for (i, (attr, expected_size)) in inputs
            .attributes
            .iter()
            .zip(self.schema.attribute_sizes.iter())
            .enumerate()
        {
            if attr.len() > *expected_size {
                return Err(AirError::InvalidInput {
                    reason: format!(
                        "Attribute {} size {} exceeds maximum {}",
                        i,
                        attr.len(),
                        expected_size
                    ),
                });
            }
        }

        let n = self.schema.num_attributes;
        let trace_width = self.trace_width_inner();
        let trace_height = 1;
        let num_rows_padded = next_power_of_two(trace_height);

        validate_trace_dimensions(trace_width, num_rows_padded)?;

        let mut trace_values = vec![Val::ZERO; num_rows_padded * trace_width];

        // Phase 1: attribute hashes
        let mut attr_hashes = Vec::with_capacity(n);
        for (i, attr) in inputs.attributes.iter().enumerate() {
            let (left, right) = attr_to_left_right(attr);
            let input_vec = vec![left, right];
            let (hash_out, intermediates) = compute_poseidon_with_intermediates(&input_vec);

            let base = i * COLS_PER_BLOCK;
            trace_values[base] = poseidon_to_field(&left);
            trace_values[base + 1] = poseidon_to_field(&right);
            trace_values[base + 2] = poseidon_to_field(&hash_out);
            for (j, inter) in intermediates.iter().enumerate() {
                if base + 3 + j < trace_values.len() {
                    trace_values[base + 3 + j] = poseidon_to_field(inter);
                }
            }
            attr_hashes.push(hash_out);
        }

        // Phase 2: aggregation blocks
        if n >= 2 {
            let mut running = attr_hashes[0];
            for (k, right) in attr_hashes.iter().enumerate().take(n).skip(1) {
                let right = *right;
                let input_vec = vec![running, right];
                let (hash_out, intermediates) = compute_poseidon_with_intermediates(&input_vec);

                let agg_block = n + k - 1;
                let base = agg_block * COLS_PER_BLOCK;
                trace_values[base] = poseidon_to_field(&running);
                trace_values[base + 1] = poseidon_to_field(&right);
                trace_values[base + 2] = poseidon_to_field(&hash_out);
                for (j, inter) in intermediates.iter().enumerate() {
                    if base + 3 + j < trace_values.len() {
                        trace_values[base + 3 + j] = poseidon_to_field(inter);
                    }
                }
                running = hash_out;
            }
        }

        Ok(RowMajorMatrix::new(trace_values, trace_width))
    }

    fn public_values(
        &self,
        inputs: &CredentialInput,
    ) -> Vec<lib_q_stark_field::extension::Complex<Mersenne31>> {
        let n = self.schema.num_attributes;
        let mut public_vals = Vec::new();

        // Commitment = final aggregation output; compute from inputs to match trace
        let mut attr_hashes = Vec::with_capacity(n);
        for attr in &inputs.attributes {
            let (left, right) = attr_to_left_right(attr);
            let input_vec = vec![left, right];
            let (hash_out, _) = compute_poseidon_with_intermediates(&input_vec);
            attr_hashes.push(hash_out);
        }
        let commitment = if n == 1 {
            poseidon_to_field(&attr_hashes[0])
        } else {
            let mut running = attr_hashes[0];
            for right in attr_hashes.iter().take(n).skip(1) {
                let right = *right;
                let input_vec = vec![running, right];
                let (hash_out, _) = compute_poseidon_with_intermediates(&input_vec);
                running = hash_out;
            }
            poseidon_to_field(&running)
        };
        public_vals.push(commitment);

        // Revealed attribute hashes (in order)
        for (i, revealed) in self.revealed_mask.iter().enumerate() {
            if *revealed {
                public_vals.push(poseidon_to_field(&attr_hashes[i]));
            }
        }

        public_vals
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
    fn test_credential_schema_creation() {
        let schema = CredentialSchema::new(vec![32, 16, 8]).unwrap();
        assert_eq!(schema.num_attributes, 3);
    }

    #[test]
    fn test_credential_air_creation() {
        let schema = CredentialSchema::new(vec![32, 16]).unwrap();
        let revealed = vec![true, false];
        let air = CredentialAir::new(schema, revealed).unwrap();
        assert_eq!(air.schema().num_attributes, 2);
    }

    #[test]
    fn test_credential_trace_generation() {
        let schema = CredentialSchema::new(vec![16, 8]).unwrap();
        let revealed = vec![true, false];
        let air = CredentialAir::new(schema, revealed).unwrap();

        let input = CredentialInput {
            attributes: vec![b"attr1".to_vec(), b"attr2".to_vec()],
        };

        let trace = air.generate_trace(&input);
        assert!(trace.is_ok());
        let trace = trace.unwrap();
        assert_eq!(
            trace.width(),
            <CredentialAir as BaseAir<TestField>>::width(&air)
        );
        assert_eq!(trace.height(), 1);
    }

    #[test]
    fn test_credential_single_attribute() {
        let schema = CredentialSchema::new(vec![8]).unwrap();
        let revealed = vec![true];
        let air = CredentialAir::new(schema, revealed).unwrap();
        assert_eq!(
            <CredentialAir as BaseAir<TestField>>::width(&air),
            COLS_PER_BLOCK
        );
        let input = CredentialInput {
            attributes: vec![b"single".to_vec()],
        };
        let trace = air.generate_trace(&input).unwrap();
        assert_eq!(trace.width(), COLS_PER_BLOCK);
    }
}
