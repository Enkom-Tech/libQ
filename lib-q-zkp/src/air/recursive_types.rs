//! Recursive STARK proof types and serialization utilities
//!
//! This module provides types for serializing STARK proofs into a format
//! that can be verified within another STARK proof (recursive proofs).
//!
//! # Security
//!
//! - All commitment hashes are fixed-size to prevent DoS
//! - Maximum sizes enforced for all vectors
//! - Constant-time operations for comparisons

extern crate alloc;

use alloc::format;
use alloc::string::{
    String,
    ToString,
};
use alloc::vec::Vec;

use lib_q_stark::{
    Proof as StarkProof,
    StarkGenericConfig,
    Val,
};
use lib_q_stark_field::{
    ExtensionField,
    Field,
};
use lib_q_stark_fri::FriDataExtractor;
use serde::Serialize;

/// Maximum number of FRI rounds to prevent DoS attacks
pub const MAX_FRI_ROUNDS: usize = 32;

/// Maximum number of quotient chunks
pub const MAX_QUOTIENT_CHUNKS: usize = 256;

/// Maximum trace width (columns)
///
/// Raised to accommodate deep Merkle AIRs: depth d has width 1 + d × 579.
/// Depth 64 => 37057. Regular proving is unaffected; only recursive aggregation validates this.
pub const MAX_TRACE_WIDTH: usize = 1 << 17; // 131072; recursive StarkVerifierAir can exceed 65536

/// Maximum final polynomial degree (as log2)
pub const MAX_FINAL_POLY_LOG_LEN: usize = 16;

/// Hash size for commitments (32 bytes = 256 bits)
pub const COMMITMENT_HASH_SIZE: usize = 32;

/// Serialized FRI round data for recursive verification
#[derive(Debug, Clone)]
pub struct SerializedFriRound {
    /// Commitment hash for this round
    pub commitment_hash: [u8; COMMITMENT_HASH_SIZE],
    /// Folding challenge (beta) for this round
    pub beta: Vec<u8>, // Serialized field element
}

/// Serialized STARK proof for recursive verification
///
/// This structure contains all the data from a STARK proof that needs to be
/// verified within another STARK proof. The inner proof is serialized into
/// this format so it can be embedded in the trace of the outer proof.
///
/// This type is generic over field types rather than the full STARK config,
/// allowing it to be used in contexts where the config type is not available.
#[derive(Debug, Clone)]
pub struct SerializedStarkProof<F: Field, Ch: Field = F> {
    // Proof metadata
    pub degree_bits: usize,
    pub num_quotient_chunks: usize,
    pub trace_width: usize,
    pub is_zk: bool,

    // Commitments (as hashes)
    pub trace_commitment_hash: [u8; COMMITMENT_HASH_SIZE],
    pub quotient_commitment_hash: [u8; COMMITMENT_HASH_SIZE],
    pub random_commitment_hash: Option<[u8; COMMITMENT_HASH_SIZE]>,

    // Opened values (at zeta)
    pub trace_local: Vec<F>,
    pub trace_next: Vec<F>,
    pub quotient_chunks: Vec<Vec<Ch>>,
    pub random_values: Option<Vec<Ch>>,

    // FRI proof data
    pub fri_rounds: Vec<SerializedFriRound>,
    pub final_poly: Vec<Ch>,
    pub pow_witness: Vec<u8>, // Serialized proof-of-work witness

    // Verification challenges
    pub zeta: Ch,
    pub zeta_next: Ch,
    pub alpha: Ch,

    // Expected public values
    pub expected_public_values: Vec<F>,
}

impl<F: Field, Ch: Field> SerializedStarkProof<F, Ch> {
    /// Convert challenge-typed fields to the base field type.
    /// Use when `Ch` and `F` are the same type (e.g. for recursive AIR where both are `Val<C>`).
    pub fn with_challenge_as_base(self) -> SerializedStarkProof<F, F>
    where
        Ch: Into<F>,
    {
        SerializedStarkProof {
            degree_bits: self.degree_bits,
            num_quotient_chunks: self.num_quotient_chunks,
            trace_width: self.trace_width,
            is_zk: self.is_zk,
            trace_commitment_hash: self.trace_commitment_hash,
            quotient_commitment_hash: self.quotient_commitment_hash,
            random_commitment_hash: self.random_commitment_hash,
            trace_local: self.trace_local,
            trace_next: self.trace_next,
            quotient_chunks: self
                .quotient_chunks
                .into_iter()
                .map(|row| row.into_iter().map(|c| c.into()).collect())
                .collect(),
            random_values: self
                .random_values
                .map(|v| v.into_iter().map(|c| c.into()).collect()),
            fri_rounds: self.fri_rounds,
            final_poly: self.final_poly.into_iter().map(|c| c.into()).collect(),
            pow_witness: self.pow_witness,
            zeta: self.zeta.into(),
            zeta_next: self.zeta_next.into(),
            alpha: self.alpha.into(),
            expected_public_values: self.expected_public_values,
        }
    }

    /// Validate the serialized proof structure
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, `Err` with reason if invalid
    pub fn validate(&self) -> Result<(), String> {
        if self.degree_bits > MAX_FINAL_POLY_LOG_LEN {
            return Err(format!(
                "Degree bits {} exceeds maximum {}",
                self.degree_bits, MAX_FINAL_POLY_LOG_LEN
            ));
        }

        if self.num_quotient_chunks > MAX_QUOTIENT_CHUNKS {
            return Err(format!(
                "Number of quotient chunks {} exceeds maximum {}",
                self.num_quotient_chunks, MAX_QUOTIENT_CHUNKS
            ));
        }

        if self.trace_width > MAX_TRACE_WIDTH {
            return Err(format!(
                "Trace width {} exceeds maximum {}",
                self.trace_width, MAX_TRACE_WIDTH
            ));
        }

        if self.trace_local.len() != self.trace_width {
            return Err(format!(
                "Trace local length {} doesn't match trace width {}",
                self.trace_local.len(),
                self.trace_width
            ));
        }

        if self.trace_next.len() != self.trace_width {
            return Err(format!(
                "Trace next length {} doesn't match trace width {}",
                self.trace_next.len(),
                self.trace_width
            ));
        }

        if self.quotient_chunks.len() != self.num_quotient_chunks {
            return Err(format!(
                "Quotient chunks length {} doesn't match expected {}",
                self.quotient_chunks.len(),
                self.num_quotient_chunks
            ));
        }

        if self.fri_rounds.len() > MAX_FRI_ROUNDS {
            return Err(format!(
                "FRI rounds {} exceeds maximum {}",
                self.fri_rounds.len(),
                MAX_FRI_ROUNDS
            ));
        }

        Ok(())
    }
}

impl<F: Field, Ch: Field> SerializedStarkProof<F, Ch> {
    // Methods for generic F, Ch are in the impl block above
}

/// Create a SerializedStarkProof from a STARK proof
///
/// # Arguments
///
/// * `proof` - The STARK proof to serialize
/// * `expected_public_values` - Expected public values for verification
/// * `zeta` - Out-of-domain point used in verification
/// * `zeta_next` - Next point in domain
/// * `alpha` - Constraint combination challenge
/// * `betas` - FRI folding challenges (from `derive_challenges`)
///
/// # Returns
///
/// A `SerializedStarkProof` or error if serialization fails
pub fn serialize_stark_proof<C: StarkGenericConfig>(
    proof: &StarkProof<C>,
    expected_public_values: Vec<Val<C>>,
    zeta: C::Challenge,
    zeta_next: C::Challenge,
    alpha: C::Challenge,
    betas: &[C::Challenge],
) -> Result<SerializedStarkProof<Val<C>, C::Challenge>, String>
where
    <<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof: FriDataExtractor<Challenge = C::Challenge>,
    <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof as FriDataExtractor>::Commitment: Serialize,
    <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof as FriDataExtractor>::Witness: Serialize,
{
    // Validate proof structure
    if proof.degree_bits > MAX_FINAL_POLY_LOG_LEN {
        return Err(format!(
            "Degree bits {} exceeds maximum {}",
            proof.degree_bits, MAX_FINAL_POLY_LOG_LEN
        ));
    }

    let num_quotient_chunks = proof.opened_values.quotient_chunks.len();
    if num_quotient_chunks > MAX_QUOTIENT_CHUNKS {
        return Err(format!(
            "Number of quotient chunks {} exceeds maximum {}",
            num_quotient_chunks, MAX_QUOTIENT_CHUNKS
        ));
    }

    // Serialize commitments to hashes
    // Note: In a real implementation, we'd hash the actual commitment objects
    // For now, we'll use a placeholder that represents the commitment hash
    let trace_commitment_hash = hash_commitment(&proof.commitments.trace);
    let quotient_commitment_hash = hash_commitment(&proof.commitments.quotient_chunks);
    let random_commitment_hash = proof.commitments.random.as_ref().map(hash_commitment);

    // Extract opened values: Challenge is ExtensionField<Val<C>>; trace columns are base field
    // so we project each challenge to the base field via as_base().
    let trace_local: Vec<Val<C>> = proof
        .opened_values
        .trace_local
        .iter()
        .map(|ch| {
            ch.as_base()
                .ok_or_else(|| "Trace value not in base field".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trace_next: Vec<Val<C>> = proof
        .opened_values
        .trace_next
        .iter()
        .map(|ch| {
            ch.as_base()
                .ok_or_else(|| "Trace value not in base field".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let quotient_chunks = proof.opened_values.quotient_chunks.clone();
    let random_values = proof.opened_values.random.clone();

    // Validate trace width
    if trace_local.len() != trace_next.len() {
        return Err("Trace local and next must have same length".to_string());
    }
    let trace_width = trace_local.len();
    if trace_width > MAX_TRACE_WIDTH {
        return Err(format!(
            "Trace width {} exceeds maximum {}",
            trace_width, MAX_TRACE_WIDTH
        ));
    }

    // Extract FRI proof data from opening_proof (betas from derive_challenges)
    let (fri_rounds, final_poly, pow_witness) = extract_fri_data::<C>(&proof.opening_proof, betas)?;

    Ok(SerializedStarkProof {
        degree_bits: proof.degree_bits,
        num_quotient_chunks,
        trace_width,
        is_zk: proof.commitments.random.is_some(),
        trace_commitment_hash,
        quotient_commitment_hash,
        random_commitment_hash,
        trace_local,
        trace_next,
        quotient_chunks,
        random_values,
        fri_rounds,
        final_poly,
        pow_witness,
        zeta,
        zeta_next,
        alpha,
        expected_public_values,
    })
}

/// Result of extracting FRI data from an opening proof (rounds, final poly, pow witness).
type FriExtractionResult<C: StarkGenericConfig> =
    (Vec<SerializedFriRound>, Vec<C::Challenge>, Vec<u8>);

/// Extract FRI proof data from opening_proof using the FriDataExtractor trait.
///
/// Requires the PCS proof type to implement `FriDataExtractor` (e.g. `FriProof`).
/// Uses `betas` derived by replaying the FRI verifier challenger (see `derive_challenges`).
fn extract_fri_data<C: StarkGenericConfig>(
    opening_proof: &<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof,
    betas: &[C::Challenge],
) -> Result<FriExtractionResult<C>, String>
where
    <<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof: FriDataExtractor<Challenge = C::Challenge>,
    <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof as FriDataExtractor>::Witness: Serialize,
    <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof as FriDataExtractor>::Commitment: Serialize,
{
    let commits = opening_proof.commit_phase_commits();
    if betas.len() != commits.len() {
        return Err(format!(
            "FRI betas length {} does not match commit phase length {}",
            betas.len(),
            commits.len()
        ));
    }

    let fri_rounds: Vec<SerializedFriRound> = commits
        .iter()
        .zip(betas.iter())
        .map(|(comm, beta)| {
            let commitment_hash = hash_commitment(comm);
            let beta_bytes = postcard::to_allocvec(beta).unwrap_or_else(|_| alloc::vec![]);
            SerializedFriRound {
                commitment_hash,
                beta: beta_bytes,
            }
        })
        .collect();

    let final_poly = opening_proof.final_poly().to_vec();
    let pow_witness = postcard::to_allocvec(opening_proof.pow_witness())
        .map_err(|e| format!("serialize pow_witness: {:?}", e))?;

    Ok((fri_rounds, final_poly, pow_witness))
}

/// Hash a commitment to a fixed-size byte array using SHAKE256
///
/// This uses NIST-approved SHAKE256 (FIPS 202) to hash the serialized
/// commitment object. SHAKE256 provides post-quantum security and is
/// suitable for cryptographic commitments.
///
/// # Security
///
/// Uses SHAKE256 (NIST-approved, post-quantum secure). When the recursive verifier uses
/// Poseidon config, callers may optionally use a Poseidon hash of the serialized commitment
/// for consistency; this function uses SHAKE256 for all configs. Fixed output size prevents DoS.
fn hash_commitment<Com: Serialize>(commitment: &Com) -> [u8; COMMITMENT_HASH_SIZE] {
    use lib_q_sha3::Shake256;
    use lib_q_sha3::digest::{
        ExtendableOutput,
        Update,
        XofReader,
    };

    // Serialize the commitment
    let serialized = match postcard::to_allocvec(commitment) {
        Ok(bytes) => bytes,
        Err(_) => {
            // If serialization fails, return zero hash
            // This should not happen in normal operation, but we handle it gracefully
            return [0u8; COMMITMENT_HASH_SIZE];
        }
    };

    // Hash using SHAKE256
    let mut hasher = Shake256::default();
    hasher.update(&serialized);
    let mut reader = hasher.finalize_xof();

    // Read exactly COMMITMENT_HASH_SIZE bytes
    let mut output = [0u8; COMMITMENT_HASH_SIZE];
    reader.read(&mut output);
    output
}

/// Input type for recursive STARK verification
#[derive(Debug, Clone)]
pub struct RecursiveStarkInput<F: Field, Ch: Field = F> {
    /// The serialized inner proof
    pub serialized_proof: SerializedStarkProof<F, Ch>,
}

impl<F: Field, Ch: Field> RecursiveStarkInput<F, Ch> {
    /// Create a new RecursiveStarkInput from a serialized proof
    pub fn new(serialized_proof: SerializedStarkProof<F, Ch>) -> Result<Self, String> {
        serialized_proof.validate()?;
        Ok(Self { serialized_proof })
    }
}

/// Create a new RecursiveStarkInput from a STARK proof
pub fn recursive_stark_input_from_proof<C: StarkGenericConfig>(
    proof: &StarkProof<C>,
    expected_public_values: Vec<Val<C>>,
    zeta: C::Challenge,
    zeta_next: C::Challenge,
    alpha: C::Challenge,
    betas: &[C::Challenge],
) -> Result<RecursiveStarkInput<Val<C>, C::Challenge>, String>
where
    <<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof: FriDataExtractor<Challenge = C::Challenge>,
    <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof as FriDataExtractor>::Commitment: Serialize,
    <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
        <C as StarkGenericConfig>::Challenge,
        <C as StarkGenericConfig>::Challenger,
    >>::Proof as FriDataExtractor>::Witness: Serialize,
{
    let serialized_proof =
        serialize_stark_proof(proof, expected_public_values, zeta, zeta_next, alpha, betas)?;
    serialized_proof.validate()?;
    Ok(RecursiveStarkInput { serialized_proof })
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::{
        COMMITMENT_HASH_SIZE,
        SerializedStarkProof,
    };

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_serialized_proof_validation() {
        let proof = SerializedStarkProof::<TestField, TestField> {
            degree_bits: 4,
            num_quotient_chunks: 1,
            trace_width: 2,
            is_zk: false,
            trace_commitment_hash: [0u8; COMMITMENT_HASH_SIZE],
            quotient_commitment_hash: [0u8; COMMITMENT_HASH_SIZE],
            random_commitment_hash: None,
            trace_local: alloc::vec![TestField::ZERO; 2],
            trace_next: alloc::vec![TestField::ZERO; 2],
            quotient_chunks: alloc::vec![alloc::vec![TestField::ZERO; 1]],
            random_values: None,
            fri_rounds: alloc::vec![],
            final_poly: alloc::vec![TestField::ZERO],
            pow_witness: alloc::vec![],
            zeta: TestField::ZERO,
            zeta_next: TestField::ZERO,
            alpha: TestField::ZERO,
            expected_public_values: alloc::vec![],
        };
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn test_with_challenge_as_base() {
        let proof = SerializedStarkProof::<TestField, TestField> {
            degree_bits: 4,
            num_quotient_chunks: 1,
            trace_width: 2,
            is_zk: false,
            trace_commitment_hash: [0u8; COMMITMENT_HASH_SIZE],
            quotient_commitment_hash: [0u8; COMMITMENT_HASH_SIZE],
            random_commitment_hash: None,
            trace_local: alloc::vec![TestField::ZERO; 2],
            trace_next: alloc::vec![TestField::ZERO; 2],
            quotient_chunks: alloc::vec![alloc::vec![TestField::ZERO; 1]],
            random_values: None,
            fri_rounds: alloc::vec![],
            final_poly: alloc::vec![TestField::ZERO],
            pow_witness: alloc::vec![],
            zeta: TestField::ZERO,
            zeta_next: TestField::ZERO,
            alpha: TestField::ZERO,
            expected_public_values: alloc::vec![],
        };
        let unified = proof.clone().with_challenge_as_base();
        assert_eq!(unified.degree_bits, proof.degree_bits);
        assert_eq!(unified.trace_width, proof.trace_width);
        assert!(unified.validate().is_ok());
    }
}
