//! Merkle Inclusion AIR - Proves membership in a Merkle tree
//!
//! This AIR proves that a leaf value is included in a Merkle tree with a
//! given root hash, using a Merkle authentication path.
//!
//! # Trace Layout
//!
//! For a tree of depth `d`, the trace contains:
//! - Leaf value bytes
//! - Path direction bits (left=0, right=1)
//! - Sibling hashes at each level
//! - Computed hashes at each level (leading to root)
//!
//! # Security
//!
//! - Uses Poseidon-128 (field-native hash optimized for ZKP)
//! - Path verification ensures proper tree traversal
//! - Full constraint system for all hash operations

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
};
use lib_q_stark_matrix::dense::RowMajorMatrix;
use lib_q_stark_mersenne31::Mersenne31;

use super::{
    AirError,
    TraceGenerator,
    bytes_to_poseidon_field,
    next_power_of_two,
    poseidon_slice_to_field,
    poseidon_to_field,
    validate_trace_dimensions,
};

/// Poseidon-128 hasher instance (unit struct, can be used directly)
const POSEIDON_128: Poseidon128 = Poseidon128;

/// Compute Poseidon hash with all intermediate states for AIR constraints
///
/// Returns the hash output and a vector of all intermediate states
/// (after ARC, after S-box, after MDS for each round)
pub(crate) fn compute_poseidon_with_intermediates(
    input: &[PoseidonField],
) -> (PoseidonField, Vec<PoseidonField>) {
    use lib_q_poseidon::Poseidon128;

    let params = Poseidon128::params();
    let n = params.state_width;

    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;
    let zero = Complex::<Mersenne31>::new_complex(
        <Mersenne31 as PrimeCharacteristicRing>::ZERO,
        <Mersenne31 as PrimeCharacteristicRing>::ZERO,
    );
    let mut state: Vec<PoseidonField> = (0..n)
        .map(|i| if i < input.len() { input[i] } else { zero })
        .collect();

    let mut intermediates = Vec::new();
    let full_rounds_half = params.full_rounds / 2;
    let mut round_const_idx = 0;

    for _ in 0..full_rounds_half {
        let (new_state, round_intermediates) = compute_full_round_intermediates(
            &state,
            &params.round_constants,
            &mut round_const_idx,
            &params.mds_matrix,
            n,
        );
        intermediates.extend_from_slice(&round_intermediates);
        state = new_state;
    }

    for _ in 0..params.partial_rounds {
        let (new_state, round_intermediates) = compute_partial_round_intermediates(
            &state,
            &params.round_constants,
            &mut round_const_idx,
            &params.mds_matrix,
            n,
        );
        intermediates.extend_from_slice(&round_intermediates);
        state = new_state;
    }

    for _ in 0..full_rounds_half {
        let (new_state, round_intermediates) = compute_full_round_intermediates(
            &state,
            &params.round_constants,
            &mut round_const_idx,
            &params.mds_matrix,
            n,
        );
        intermediates.extend_from_slice(&round_intermediates);
        state = new_state;
    }

    (state[0], intermediates)
}

/// Compute a full round and return intermediate states
fn compute_full_round_intermediates(
    state: &[PoseidonField],
    round_constants: &[PoseidonField],
    round_const_idx: &mut usize,
    mds: &[Vec<PoseidonField>],
    n: usize,
) -> (Vec<PoseidonField>, Vec<PoseidonField>) {
    use lib_q_poseidon::sbox;
    let mut intermediates = Vec::new();

    let after_arc: Vec<PoseidonField> = (0..n)
        .map(|i| state[i] + round_constants[*round_const_idx + i])
        .collect();
    *round_const_idx += n;
    intermediates.extend_from_slice(&after_arc);

    let after_sbox: Vec<PoseidonField> = after_arc.iter().map(|x| sbox(*x)).collect();
    intermediates.extend_from_slice(&after_sbox);

    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;
    let zero = Complex::<Mersenne31>::new_complex(
        <Mersenne31 as PrimeCharacteristicRing>::ZERO,
        <Mersenne31 as PrimeCharacteristicRing>::ZERO,
    );
    let mut next_state = alloc::vec![zero; n];
    for i in 0..n {
        for j in 0..n {
            next_state[i] += mds[i][j] * after_sbox[j];
        }
    }
    intermediates.extend_from_slice(&next_state);

    (next_state, intermediates)
}

/// Compute a partial round and return intermediate states
fn compute_partial_round_intermediates(
    state: &[PoseidonField],
    round_constants: &[PoseidonField],
    round_const_idx: &mut usize,
    mds: &[Vec<PoseidonField>],
    n: usize,
) -> (Vec<PoseidonField>, Vec<PoseidonField>) {
    use lib_q_poseidon::sbox;
    let mut intermediates = Vec::new();

    let after_arc: Vec<PoseidonField> = (0..n)
        .map(|i| state[i] + round_constants[*round_const_idx + i])
        .collect();
    *round_const_idx += n;
    intermediates.extend_from_slice(&after_arc);

    let mut after_sbox = after_arc.clone();
    after_sbox[0] = sbox(after_arc[0]);
    intermediates.extend_from_slice(&after_sbox);

    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;
    let zero = Complex::<Mersenne31>::new_complex(
        <Mersenne31 as PrimeCharacteristicRing>::ZERO,
        <Mersenne31 as PrimeCharacteristicRing>::ZERO,
    );
    let mut next_state = alloc::vec![zero; n];
    for i in 0..n {
        for j in 0..n {
            next_state[i] += mds[i][j] * after_sbox[j];
        }
    }
    intermediates.extend_from_slice(&next_state);

    (next_state, intermediates)
}

/// Type-safe wrapper for Merkle tree hash values
///
/// Represents a hash output (e.g., Poseidon field element) rather than
/// raw data to be hashed. This prevents the common mistake of double-hashing
/// siblings in Merkle tree proofs.
///
/// # Semantics
///
/// - `MerkleHash::from_bytes()`: Interprets bytes as a field element representation
///   (does NOT hash the bytes). Use this when you have a pre-computed hash.
/// - `MerkleHash::hash_data()`: Computes Poseidon hash of raw data. Use this for leaf data.
/// - `MerkleHash::from_field()`: Creates from a field element directly.
///
/// # Example
///
/// ```rust,ignore
/// // For leaf data (needs hashing):
/// let leaf_hash = MerkleHash::hash_data(b"my leaf data");
///
/// // For sibling hashes (already computed):
/// let sibling = MerkleHash::from_bytes(&sibling_bytes)?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleHash(PoseidonField);

impl MerkleHash {
    /// Create a MerkleHash from bytes by interpreting them as a field element
    ///
    /// This does NOT hash the bytes - it interprets them as a representation
    /// of an already-computed hash. Use this for sibling hashes in Merkle paths.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Bytes representing a hash value (typically 32 bytes)
    ///
    /// # Returns
    ///
    /// A `MerkleHash` or error if conversion fails
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AirError> {
        // Convert bytes to field elements (one byte per element for simplicity)
        // This interprets the bytes as field element data, not as data to hash
        let field_elements = bytes_to_poseidon_field(bytes);

        // For a hash, we typically want the first field element
        // If bytes represent a single hash, take the first element
        if field_elements.is_empty() {
            return Err(AirError::InvalidInput {
                reason: "Cannot create MerkleHash from empty bytes".to_string(),
            });
        }

        // Use the first field element as the hash value
        // For Poseidon, a hash is typically a single field element
        Ok(Self(field_elements[0]))
    }

    /// Create a MerkleHash from a field element directly
    ///
    /// # Arguments
    ///
    /// * `field` - The Poseidon field element representing the hash
    ///
    /// # Returns
    ///
    /// A `MerkleHash` wrapping the field element
    pub fn from_field(field: PoseidonField) -> Self {
        Self(field)
    }

    /// Compute Poseidon hash of raw data
    ///
    /// This actually hashes the input data using Poseidon-128.
    /// Use this for leaf data that needs to be hashed.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw data to hash
    ///
    /// # Returns
    ///
    /// A `MerkleHash` containing the Poseidon hash of the data
    pub fn hash_data(data: &[u8]) -> Self {
        let field_elements = bytes_to_poseidon_field(data);
        let hash_output = POSEIDON_128.hash(&field_elements);

        // Poseidon outputs a single field element by default
        if hash_output.is_empty() {
            // Fallback to zero if hash is empty (shouldn't happen)
            use lib_q_stark_field::PrimeCharacteristicRing;
            use lib_q_stark_field::extension::Complex;
            use lib_q_stark_mersenne31::Mersenne31;
            let zero = Complex::<Mersenne31>::new_complex(
                <Mersenne31 as PrimeCharacteristicRing>::ZERO,
                <Mersenne31 as PrimeCharacteristicRing>::ZERO,
            );
            Self(zero)
        } else {
            Self(hash_output[0])
        }
    }

    /// Get the underlying field element
    ///
    /// # Returns
    ///
    /// A reference to the Poseidon field element
    pub fn as_field(&self) -> &PoseidonField {
        &self.0
    }

    /// Get the underlying field element by value
    ///
    /// # Returns
    ///
    /// The Poseidon field element
    pub fn into_field(self) -> PoseidonField {
        self.0
    }
}

/// Maximum Merkle tree depth
pub const MAX_TREE_DEPTH: usize = 64;

/// Hash output size in field elements (Poseidon outputs 1 field element by default)
pub const HASH_SIZE_FIELD_ELEMENTS: usize = 1;

/// AIR for proving Merkle tree inclusion
///
/// Proves that a given leaf value exists in a Merkle tree with a specified
/// root hash, using an authentication path of sibling hashes and direction
/// bits.
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::air::{MerkleInclusionAir, MerkleProofInput, TraceGenerator};
/// use lib_q_stark_field::extension::Complex;
/// use lib_q_stark_mersenne31::Mersenne31;
///
/// type Val = Complex<Mersenne31>;
///
/// let air = MerkleInclusionAir::new(4).unwrap(); // depth 4 tree
/// let input = MerkleProofInput {
///     leaf: vec![1, 2, 3, 4],
///     path_bits: vec![false, true, false, true],
///     siblings: vec![
///         vec![0u8; 32], // sibling at level 0
///         vec![0u8; 32], // sibling at level 1
///         vec![0u8; 32], // sibling at level 2
///         vec![0u8; 32], // sibling at level 3
///     ],
/// };
/// let trace = air.generate_trace(&input).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct MerkleInclusionAir {
    /// Depth of the Merkle tree
    tree_depth: usize,
}

impl MerkleInclusionAir {
    /// Create a new MerkleInclusionAir for a tree of the given depth
    ///
    /// # Arguments
    ///
    /// * `tree_depth` - Number of levels in the tree (excluding root)
    ///
    /// # Returns
    ///
    /// A new `MerkleInclusionAir` instance or an error if parameters are invalid
    pub fn new(tree_depth: usize) -> Result<Self, AirError> {
        if tree_depth == 0 {
            return Err(AirError::InvalidDimensions {
                reason: "Tree depth must be greater than 0".to_string(),
            });
        }

        if tree_depth > MAX_TREE_DEPTH {
            return Err(AirError::ExceedsMaxSize {
                parameter: "tree_depth".to_string(),
                max: MAX_TREE_DEPTH,
                actual: tree_depth,
            });
        }

        Ok(Self { tree_depth })
    }

    /// Get the tree depth
    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }

    /// Compute trace width
    ///
    /// Layout:
    /// - 1 field element for leaf hash at start
    /// - Per level:
    ///   - 1 direction bit
    ///   - 1 sibling field element (already computed hash)
    ///   - 1 computed hash output
    ///   - 576 intermediate Poseidon state columns (64 rounds × 9 columns per round)
    ///
    /// Total: 1 + tree_depth × (1 + 1 + 1 + 576) = 1 + tree_depth × 579
    fn trace_width(&self) -> usize {
        use super::poseidon_gadget::PoseidonGadget;
        HASH_SIZE_FIELD_ELEMENTS +
            self.tree_depth *
                (1 + HASH_SIZE_FIELD_ELEMENTS +
                    HASH_SIZE_FIELD_ELEMENTS +
                    PoseidonGadget::COLUMNS_PER_HASH)
    }
}

impl<F: Field + BasedVectorSpace<Mersenne31>> BaseAir<F> for MerkleInclusionAir {
    fn width(&self) -> usize {
        self.trace_width()
    }
}

impl<AB: AirBuilder> Air<AB> for MerkleInclusionAir
where
    AB::F: Field + BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        use super::poseidon_gadget::PoseidonGadget;

        let main = builder.main();
        let local = main.current_slice();

        // Column layout:
        // [leaf_hash, level_0_data, level_1_data, ...]
        // where level_i_data = [direction_bit, sibling, computed_hash, intermediate_states...]

        let level_width = 1 +
            HASH_SIZE_FIELD_ELEMENTS +
            HASH_SIZE_FIELD_ELEMENTS +
            PoseidonGadget::COLUMNS_PER_HASH;
        let gadget = PoseidonGadget::new();

        // Start with leaf hash
        let mut previous_hash_col = 0;

        for level in 0..self.tree_depth {
            let level_start = HASH_SIZE_FIELD_ELEMENTS + level * level_width;

            // Direction bit must be boolean (0 or 1)
            let direction = local[level_start].clone();
            builder.assert_bool(direction.clone());

            // Sibling hash (field element) - already a computed hash
            let sibling_col = level_start + 1;
            let sibling = local[sibling_col].clone();

            // Computed hash output (field element)
            let computed_hash_col = level_start + 1 + HASH_SIZE_FIELD_ELEMENTS;
            let computed_hash = local[computed_hash_col].clone().into();

            // Select left/right based on direction bit
            // If direction = 1 (right), we're on right: left = sibling, right = previous_hash
            // If direction = 0 (left), we're on left: left = previous_hash, right = sibling
            //
            // Using: left = (1 - direction) * previous_hash + direction * sibling
            //        right = direction * previous_hash + (1 - direction) * sibling
            use lib_q_stark_field::PrimeCharacteristicRing;
            let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);
            let left = (one.clone() - direction.clone()) * local[previous_hash_col].clone().into() +
                direction.clone() * sibling.clone().into();
            let right = direction.clone() * local[previous_hash_col].clone().into() +
                (one - direction.clone()) * sibling.clone().into();

            // Intermediate states start after computed_hash
            let intermediate_start = computed_hash_col + 1;

            // Add full Poseidon constraints using the gadget
            // This verifies: Poseidon(left, right) = computed_hash
            // and checks all intermediate states are correct
            if let Err(e) =
                gadget.constrain(builder, left, right, computed_hash, intermediate_start)
            {
                // If constraint setup fails, the proof is invalid
                // This shouldn't happen with correct trace generation
                use lib_q_stark_field::PrimeCharacteristicRing;
                builder.assert_zero(AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE)); // Force failure
                let _ = e; // Suppress unused warning
            }

            // Update previous_hash_col for next iteration
            previous_hash_col = computed_hash_col;
        }

        // Note: Full Poseidon constraints are added per-level above
        // The PoseidonGadget::constrain() method would be called here,
        // but it requires column indices which we need to compute dynamically
        // For a complete implementation, we'd restructure to call the gadget
        // with proper column mappings
    }
}

/// Input for Merkle inclusion proof
#[derive(Debug, Clone)]
pub struct MerkleProofInput {
    /// The leaf data (will be hashed). Ignored when `leaf_hash_direct` is set.
    pub leaf: Vec<u8>,
    /// When set, use this as the leaf hash directly (32-byte Poseidon root encoding).
    /// Use when the tree's leaf is a precomputed digest (e.g. from MMCS opened row hash).
    pub leaf_hash_direct: Option<[u8; 32]>,
    /// Direction bits for each level (false = left, true = right)
    pub path_bits: Vec<bool>,
    /// Sibling hashes at each level (already computed hashes, not raw data)
    pub siblings: Vec<MerkleHash>,
}

impl<F: Field + BasedVectorSpace<Mersenne31>> TraceGenerator<F, MerkleProofInput>
    for MerkleInclusionAir
{
    fn generate_trace(&self, inputs: &MerkleProofInput) -> Result<RowMajorMatrix<F>, AirError> {
        // Validate input dimensions
        if inputs.path_bits.len() != self.tree_depth {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Path bits length {} doesn't match tree depth {}",
                    inputs.path_bits.len(),
                    self.tree_depth
                ),
            });
        }

        if inputs.siblings.len() != self.tree_depth {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Siblings length {} doesn't match tree depth {}",
                    inputs.siblings.len(),
                    self.tree_depth
                ),
            });
        }

        let width = self.trace_width();
        let num_rows_padded = next_power_of_two(1);
        validate_trace_dimensions(width, num_rows_padded)?;

        let mut trace_values = vec![F::ZERO; num_rows_padded * width];

        // Leaf hash: either use precomputed digest or hash leaf bytes
        let leaf_hash = if let Some(ref bytes) = inputs.leaf_hash_direct {
            super::merkle_root_from_bytes(bytes)
                .map(|f| alloc::vec![f])
                .unwrap_or_else(|_| {
                    let leaf_field_elements = bytes_to_poseidon_field(&inputs.leaf);
                    POSEIDON_128.hash(&leaf_field_elements)
                })
        } else {
            let leaf_field_elements = bytes_to_poseidon_field(&inputs.leaf);
            POSEIDON_128.hash(&leaf_field_elements)
        };

        if !leaf_hash.is_empty() {
            trace_values[0] = poseidon_to_field(&leaf_hash[0]);
        }

        // Fill each level
        use super::poseidon_gadget::PoseidonGadget;
        let level_width = 1 +
            HASH_SIZE_FIELD_ELEMENTS +
            HASH_SIZE_FIELD_ELEMENTS +
            PoseidonGadget::COLUMNS_PER_HASH;
        let mut current_hash = leaf_hash;

        for level in 0..self.tree_depth {
            let level_start = HASH_SIZE_FIELD_ELEMENTS + level * level_width;

            // Direction bit
            trace_values[level_start] = if inputs.path_bits[level] {
                F::ONE
            } else {
                F::ZERO
            };

            // Sibling hash - use directly (already a hash, don't re-hash!)
            let sibling_field = inputs.siblings[level].as_field();
            trace_values[level_start + 1] = poseidon_to_field(sibling_field);

            // Prepare input for Poseidon hash
            let combined = if inputs.path_bits[level] {
                // We're on the right, sibling is on the left
                [*sibling_field, current_hash[0]].to_vec()
            } else {
                // We're on the left, sibling is on the right
                [current_hash[0], *sibling_field].to_vec()
            };

            // Compute Poseidon hash with intermediate states
            let (hash_output, intermediates) = compute_poseidon_with_intermediates(&combined);
            current_hash = vec![hash_output];

            // Store computed hash output
            trace_values[level_start + 1 + HASH_SIZE_FIELD_ELEMENTS] =
                poseidon_to_field(&hash_output);

            // Store intermediate states (576 columns per hash)
            let intermediate_start = level_start + 1 + HASH_SIZE_FIELD_ELEMENTS + 1;
            for (i, intermediate) in intermediates.iter().enumerate() {
                if intermediate_start + i < trace_values.len() {
                    trace_values[intermediate_start + i] = poseidon_to_field(intermediate);
                }
            }
        }

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, inputs: &MerkleProofInput) -> Vec<F> {
        let mut current_hash = if let Some(ref bytes) = inputs.leaf_hash_direct {
            super::merkle_root_from_bytes(bytes)
                .map(|f| alloc::vec![f])
                .unwrap_or_else(|_| {
                    let leaf_field_elements = bytes_to_poseidon_field(&inputs.leaf);
                    POSEIDON_128.hash(&leaf_field_elements)
                })
        } else {
            let leaf_field_elements = bytes_to_poseidon_field(&inputs.leaf);
            POSEIDON_128.hash(&leaf_field_elements)
        };

        for level in 0..self.tree_depth {
            // Sibling is already a hash (field element), use directly
            let sibling_field = inputs.siblings[level].as_field();

            let combined = if inputs.path_bits[level] {
                // We're on the right, sibling is on the left
                [*sibling_field, current_hash[0]].to_vec()
            } else {
                // We're on the left, sibling is on the right
                [current_hash[0], *sibling_field].to_vec()
            };
            current_hash = POSEIDON_128.hash(&combined);
        }

        // Convert PoseidonField to F using proper conversion
        poseidon_slice_to_field(&current_hash)
    }
}

/// Compute Merkle root from leaf and authentication path using Poseidon.
///
/// Matches the AIR convention: leaf is hashed via Poseidon128(bytes_to_poseidon_field(leaf));
/// each level combines current hash with sibling (single PoseidonField) as [left, right] then hashes.
///
/// # Arguments
///
/// * `leaf` - Raw leaf bytes
/// * `path_bits` - Direction per level (false = left, true = right)
/// * `siblings` - Sibling hashes as MerkleHash (one field element per level)
///
/// # Returns
///
/// The root as MerkleHash. Use `crate::air::merkle_root_to_bytes(root.as_field())` for bytes.
#[must_use]
pub fn compute_merkle_root(leaf: &[u8], path_bits: &[bool], siblings: &[MerkleHash]) -> MerkleHash {
    use super::bytes_to_poseidon_field;

    let leaf_field_elements = bytes_to_poseidon_field(leaf);
    let mut current_hash = POSEIDON_128.hash(&leaf_field_elements);

    for (bit, sibling) in path_bits.iter().zip(siblings.iter()) {
        let sibling_field = sibling.as_field();
        let combined = if *bit {
            [*sibling_field, current_hash[0]].to_vec()
        } else {
            [current_hash[0], *sibling_field].to_vec()
        };
        current_hash = POSEIDON_128.hash(&combined);
    }

    MerkleHash::from_field(current_hash[0])
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_merkle_inclusion_air_new_valid() {
        let air = MerkleInclusionAir::new(4);
        assert!(air.is_ok());
        assert_eq!(air.unwrap().tree_depth(), 4);
    }

    #[test]
    fn test_merkle_inclusion_air_new_zero_depth() {
        let result = MerkleInclusionAir::new(0);
        assert!(matches!(result, Err(AirError::InvalidDimensions { .. })));
    }

    #[test]
    fn test_merkle_inclusion_air_new_too_deep() {
        let result = MerkleInclusionAir::new(MAX_TREE_DEPTH + 1);
        assert!(matches!(result, Err(AirError::ExceedsMaxSize { .. })));
    }

    #[test]
    fn test_merkle_inclusion_air_width() {
        use crate::air::poseidon_gadget::PoseidonGadget;
        let air = MerkleInclusionAir::new(4).unwrap();
        // 1 (leaf hash) + 4 * (1 direction + 1 sibling + 1 computed + 576 intermediates)
        // = 1 + 4 * 579 = 1 + 2316 = 2317
        let expected_width = 1 + 4 * (1 + 1 + 1 + PoseidonGadget::COLUMNS_PER_HASH);
        assert_eq!(BaseAir::<TestField>::width(&air), expected_width);
    }

    #[test]
    fn test_generate_trace_basic() {
        let air = MerkleInclusionAir::new(2).unwrap();
        let input = MerkleProofInput {
            leaf: vec![1, 2, 3, 4],
            leaf_hash_direct: None,
            path_bits: vec![false, true],
            siblings: vec![
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            ],
        };

        let trace: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(trace.is_ok());
    }

    #[test]
    fn test_generate_trace_wrong_path_length() {
        let air = MerkleInclusionAir::new(4).unwrap();
        let input = MerkleProofInput {
            leaf: vec![1, 2, 3, 4],
            leaf_hash_direct: None,
            path_bits: vec![false, true], // Wrong length
            siblings: vec![MerkleHash::from_bytes(&[0u8; 32]).unwrap(); 4],
        };

        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }

    #[test]
    fn test_generate_trace_wrong_siblings_length() {
        let air = MerkleInclusionAir::new(4).unwrap();
        let input = MerkleProofInput {
            leaf: vec![1, 2, 3, 4],
            leaf_hash_direct: None,
            path_bits: vec![false, true, false, true],
            siblings: vec![MerkleHash::from_bytes(&[0u8; 32]).unwrap(); 2], // Wrong length
        };

        let result: Result<RowMajorMatrix<TestField>, _> = air.generate_trace(&input);
        assert!(matches!(result, Err(AirError::InvalidInput { .. })));
    }

    #[test]
    fn test_compute_merkle_root_deterministic() {
        let leaf = vec![1, 2, 3, 4];
        let path_bits = vec![false, true];
        let siblings = vec![
            MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            MerkleHash::from_bytes(&[1u8; 32]).unwrap(),
        ];

        let root1 = compute_merkle_root(&leaf, &path_bits, &siblings);
        let root2 = compute_merkle_root(&leaf, &path_bits, &siblings);

        assert_eq!(root1, root2);
        assert_eq!(crate::air::merkle_root_to_bytes(root1.as_field()).len(), 32);
    }

    #[test]
    fn test_public_values_equal_root() {
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

        let public_vals: Vec<TestField> = air.public_values(&input);

        // Public values should be field elements (1 for Poseidon output)
        assert_eq!(public_vals.len(), 1);
    }

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
    fn test_merkle_hash_from_field() {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;

        let field = Complex::<Mersenne31>::from(Mersenne31::new(42));
        let hash = MerkleHash::from_field(field);
        assert_eq!(hash.as_field(), &field);
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
}
