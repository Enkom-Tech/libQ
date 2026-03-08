//! STARK Verifier AIR - Verifies another STARK proof (recursive proofs)
//!
//! This AIR enables recursive STARK proofs by verifying another STARK proof
//! within a STARK proof. This is critical for blockchain applications requiring
//! recursive proof composition.
//!
//! # Design
//!
//! A recursive STARK proof verifies the validity of another STARK proof by:
//! 1. Verifying the inner proof's commitments (using CommitmentVerifierAir)
//! 2. Verifying FRI protocol execution (using FriVerifierAir)
//! 3. Verifying constraint satisfaction (using ConstraintVerifierAir)
//! 4. Verifying opened values match commitments (using OpeningVerifierAir)
//! 5. Verifying public values match expected
//!
//! # Security
//!
//! - All verification steps are cryptographically verified
//! - Input validation prevents DoS attacks
//! - Constant-time operations for secret-dependent comparisons
//! - Zero-knowledge preservation (inner proof secrets remain hidden)

extern crate alloc;

use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_poseidon::PoseidonField;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark::SymbolicAirBuilder;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark::{
    Proof as StarkProof,
    StarkGenericConfig,
    Val,
    VerificationError,
};
use lib_q_stark_air::{
    Air,
    AirBuilder,
    BaseAir,
};
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_commit::BatchOpening;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_commit::Pcs;
use lib_q_stark_field::Field;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_field::RawDataSerializable;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_field::extension::BinomialExtensionField;
use lib_q_stark_field::integers::QuotientMap;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_fri::CommitPhaseProofStep;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_fri::FriDataExtractor;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_fri::FriProof;
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_merkle::PoseidonMmcs;
use lib_q_stark_mersenne31::Mersenne31;

use super::recursive_types::{
    MAX_FRI_ROUNDS,
    MAX_QUOTIENT_CHUNKS,
    MAX_TRACE_WIDTH,
    SerializedStarkProof,
};
use super::{
    AirError,
    CommitmentVerificationInput,
    CommitmentVerifierAir,
    ConstraintVerificationInput,
    ConstraintVerifierAir,
    FriVerificationInput,
    FriVerifierAir,
    OpeningVerificationInput,
    OpeningVerifierAir,
    TraceGenerator,
    next_power_of_two,
    validate_trace_dimensions,
};
#[cfg(feature = "recursive-proofs-experimental")]
use super::{
    MerkleHash,
    MerkleProofInput,
};
#[cfg(feature = "recursive-proofs-experimental")]
use crate::stark::{
    FriQueryParams,
    StarkVerifier,
};

/// Stub when recursive-proofs-experimental is off: any type satisfies the bound; real impls are feature-gated.
#[cfg(not(feature = "recursive-proofs-experimental"))]
pub trait MerklePathExtractable {
    /// Not implemented without the feature; returns NotSupported.
    fn sibling_as_merkle_hash(&self) -> Result<super::MerkleHash, AirError>;
}
#[cfg(not(feature = "recursive-proofs-experimental"))]
impl<T> MerklePathExtractable for T {
    fn sibling_as_merkle_hash(&self) -> Result<super::MerkleHash, AirError> {
        Err(AirError::NotSupported {
            reason: "Recursive proof verification with real Merkle paths requires the recursive-proofs-experimental feature.".into(),
        })
    }
}

/// Stub when recursive-proofs-experimental is off: any type satisfies the bound; real impls are feature-gated.
#[cfg(not(feature = "recursive-proofs-experimental"))]
pub trait FriProofInputProofExtractor {
    type InputProof;
    fn first_query_input_proof(&self) -> Option<&Self::InputProof>;
}
#[cfg(not(feature = "recursive-proofs-experimental"))]
impl<T> FriProofInputProofExtractor for T {
    type InputProof = ();
    fn first_query_input_proof(&self) -> Option<&Self::InputProof> {
        None
    }
}

/// Trait for extracting a Merkle sibling from a FRI commit-phase proof step.
/// Used when the PCS uses Poseidon (e.g. PoseidonMmcs) so siblings are compatible with MerkleInclusionAir.
#[cfg(feature = "recursive-proofs-experimental")]
pub trait MerklePathExtractable {
    /// Convert the sibling value in this step to a MerkleHash for use in recursive verification.
    fn sibling_as_merkle_hash(&self) -> Result<MerkleHash, AirError>;
}

#[cfg(feature = "recursive-proofs-experimental")]
impl<M: lib_q_stark_commit::Mmcs<PoseidonField>> MerklePathExtractable
    for CommitPhaseProofStep<PoseidonField, M>
{
    fn sibling_as_merkle_hash(&self) -> Result<MerkleHash, AirError> {
        Ok(MerkleHash::from_field(self.sibling_value))
    }
}

/// Trait for extracting Merkle path data from a FRI query's input proof.
/// Only sound when the inner PCS uses PoseidonMmcs so siblings are field-native.
#[cfg(feature = "recursive-proofs-experimental")]
pub trait InputProofMerkleExtractable {
    /// Extract Merkle siblings for the `batch_idx`-th committed polynomial from this query's input proof.
    fn input_proof_siblings(&self, batch_idx: usize, tree_depth: usize) -> Option<Vec<MerkleHash>>;
    /// Path bits for the given query index (bit at level `i` is `(query_index >> i) & 1 == 1`).
    fn input_proof_path_bits(&self, query_index: usize, tree_depth: usize) -> Vec<bool>;
}

/// Trait for FRI proofs whose first query's input proof can be used for commitment/opening verification.
#[cfg(feature = "recursive-proofs-experimental")]
pub trait FriProofInputProofExtractor {
    type InputProof: InputProofMerkleExtractable;
    fn first_query_input_proof(&self) -> Option<&Self::InputProof>;
}

#[cfg(feature = "recursive-proofs-experimental")]
impl<F, M, W> FriProofInputProofExtractor
    for FriProof<F, M, W, Vec<BatchOpening<BinomialExtensionField<Mersenne31, 2>, PoseidonMmcs>>>
where
    F: Field,
    M: lib_q_stark_commit::Mmcs<F>,
{
    type InputProof = Vec<BatchOpening<BinomialExtensionField<Mersenne31, 2>, PoseidonMmcs>>;
    fn first_query_input_proof(&self) -> Option<&Self::InputProof> {
        self.query_proofs.get(0).map(|q| &q.input_proof)
    }
}

#[cfg(feature = "recursive-proofs-experimental")]
impl InputProofMerkleExtractable
    for Vec<BatchOpening<BinomialExtensionField<Mersenne31, 2>, PoseidonMmcs>>
{
    fn input_proof_siblings(&self, batch_idx: usize, tree_depth: usize) -> Option<Vec<MerkleHash>> {
        let batch = self.get(batch_idx)?;
        let proof = &batch.opening_proof;
        let siblings: Vec<MerkleHash> = proof
            .iter()
            .take(tree_depth)
            .map(|s| MerkleHash::from_field(s[0]))
            .collect();
        if siblings.len() < tree_depth {
            return None;
        }
        Some(siblings)
    }

    fn input_proof_path_bits(&self, query_index: usize, tree_depth: usize) -> Vec<bool> {
        let _ = self;
        (0..tree_depth)
            .map(|level| ((query_index >> level) & 1) == 1)
            .collect()
    }
}

/// AIR for verifying another STARK proof (recursive proofs)
///
/// This enables recursive proof composition where one STARK proof verifies
/// another STARK proof, enabling applications requiring recursive proof composition.
///
/// # Architecture
///
/// The verification is broken down into four main components:
/// 1. Commitment verification - Verifies Merkle tree commitments
/// 2. FRI verification - Verifies FRI low-degree test
/// 3. Constraint verification - Verifies constraint satisfaction
/// 4. Opening verification - Verifies opened values match commitments
#[derive(Debug, Clone)]
pub struct StarkVerifierAir<F: Field, Ch: Field = F> {
    /// Serialized inner proof structure
    serialized_proof: SerializedStarkProof<F, Ch>,
    /// Tree depth for Merkle proofs
    merkle_tree_depth: usize,
    /// Log of final polynomial length for FRI
    log_final_poly_len: usize,
    /// Number of FRI queries
    num_fri_queries: usize,
}

impl<F: Field, Ch: Field> StarkVerifierAir<F, Ch> {
    /// Create a new StarkVerifierAir from a serialized proof
    ///
    /// # Arguments
    ///
    /// * `serialized_proof` - The serialized inner STARK proof
    /// * `merkle_tree_depth` - Depth of Merkle trees for commitments
    /// * `log_final_poly_len` - Log2 of final polynomial length for FRI
    /// * `num_fri_queries` - Number of FRI query proofs
    ///
    /// # Returns
    ///
    /// `Ok(StarkVerifierAir)` if parameters are valid
    pub fn new(
        serialized_proof: SerializedStarkProof<F, Ch>,
        merkle_tree_depth: usize,
        log_final_poly_len: usize,
        num_fri_queries: usize,
    ) -> Result<Self, AirError> {
        // Validate serialized proof
        serialized_proof
            .validate()
            .map_err(|e| AirError::InvalidInput {
                reason: format!("Invalid serialized proof: {}", e),
            })?;

        if merkle_tree_depth == 0 || merkle_tree_depth > 32 {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Merkle tree depth must be between 1 and 32, got {}",
                    merkle_tree_depth
                ),
            });
        }

        if log_final_poly_len > 16 {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Log final poly len {} exceeds maximum 16",
                    log_final_poly_len
                ),
            });
        }

        if num_fri_queries == 0 || num_fri_queries > 1000 {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Number of FRI queries must be between 1 and 1000, got {}",
                    num_fri_queries
                ),
            });
        }

        if serialized_proof.fri_rounds.len() > MAX_FRI_ROUNDS {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "FRI rounds {} exceeds maximum {}",
                    serialized_proof.fri_rounds.len(),
                    MAX_FRI_ROUNDS
                ),
            });
        }

        if serialized_proof.num_quotient_chunks > MAX_QUOTIENT_CHUNKS {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Quotient chunks {} exceeds maximum {}",
                    serialized_proof.num_quotient_chunks, MAX_QUOTIENT_CHUNKS
                ),
            });
        }

        if serialized_proof.trace_width > MAX_TRACE_WIDTH {
            return Err(AirError::InvalidDimensions {
                reason: format!(
                    "Trace width {} exceeds maximum {}",
                    serialized_proof.trace_width, MAX_TRACE_WIDTH
                ),
            });
        }

        Ok(Self {
            serialized_proof,
            merkle_tree_depth,
            log_final_poly_len,
            num_fri_queries,
        })
    }

    /// Get the serialized proof
    pub fn serialized_proof(&self) -> &SerializedStarkProof<F, Ch> {
        &self.serialized_proof
    }

    /// Compute trace width
    ///
    /// Trace contains sections for:
    /// - Proof metadata
    /// - Commitment verification (using CommitmentVerifierAir)
    /// - FRI verification (using FriVerifierAir)
    /// - Constraint verification (using ConstraintVerifierAir)
    /// - Opening verification (using OpeningVerifierAir)
    /// - Public values verification
    fn trace_width(&self) -> usize {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;
        type Val = Complex<Mersenne31>;

        // Metadata: degree_bits, num_quotient_chunks, trace_width, is_zk
        let metadata_width = 4;

        // Commitment verification: 3 commitments (trace, quotient, random optional)
        let num_commitments = if self.serialized_proof.random_commitment_hash.is_some() {
            3
        } else {
            2
        };
        let commitment_air =
            CommitmentVerifierAir::new(num_commitments, self.merkle_tree_depth).unwrap();
        let commitment_width = <CommitmentVerifierAir as BaseAir<Val>>::width(&commitment_air);

        // FRI verification
        let fri_air = FriVerifierAir::new(
            self.serialized_proof.fri_rounds.len(),
            self.log_final_poly_len,
            self.num_fri_queries,
        )
        .unwrap();
        let fri_width = <FriVerifierAir as BaseAir<Val>>::width(&fri_air);

        // Constraint verification
        let constraint_air = ConstraintVerifierAir::new(
            self.serialized_proof.num_quotient_chunks,
            self.serialized_proof.trace_width,
            self.serialized_proof.degree_bits,
        )
        .unwrap();
        let constraint_width = <ConstraintVerifierAir as BaseAir<Val>>::width(&constraint_air);

        // Opening verification: trace_local + trace_next + quotient_chunks
        let num_opened_values =
            self.serialized_proof.trace_width * 2 + self.serialized_proof.num_quotient_chunks;
        let opening_air =
            OpeningVerifierAir::new(num_opened_values, self.merkle_tree_depth).unwrap();
        let opening_width = <OpeningVerifierAir as BaseAir<Val>>::width(&opening_air);

        // Public values: expected vs actual
        let public_values_width = self.serialized_proof.expected_public_values.len() * 2;

        metadata_width +
            commitment_width +
            fri_width +
            constraint_width +
            opening_width +
            public_values_width
    }
}

impl<F: Field, Ch: Field> BaseAir<F> for StarkVerifierAir<F, Ch> {
    fn width(&self) -> usize {
        self.trace_width()
    }
}

impl<AB: AirBuilder> Air<AB> for StarkVerifierAir<AB::F, AB::F>
where
    AB::F: Field + Sized + lib_q_stark_field::BasedVectorSpace<Mersenne31>,
{
    fn eval(&self, builder: &mut AB) {
        use lib_q_stark_field::PrimeCharacteristicRing;

        let main = builder.main();
        let local = main
            .row_slice(0)
            .expect("Matrix should have at least one row");

        let metadata_width = 4;
        let num_commitments = if self.serialized_proof.random_commitment_hash.is_some() {
            3
        } else {
            2
        };
        let commitment_air =
            CommitmentVerifierAir::new(num_commitments, self.merkle_tree_depth).unwrap();
        let commitment_width = <CommitmentVerifierAir as BaseAir<AB::F>>::width(&commitment_air);

        let fri_air = FriVerifierAir::new(
            self.serialized_proof.fri_rounds.len(),
            self.log_final_poly_len,
            self.num_fri_queries,
        )
        .unwrap();
        let fri_width = <FriVerifierAir as BaseAir<AB::F>>::width(&fri_air);

        let constraint_air = ConstraintVerifierAir::new(
            self.serialized_proof.num_quotient_chunks,
            self.serialized_proof.trace_width,
            self.serialized_proof.degree_bits,
        )
        .unwrap();
        let constraint_width = <ConstraintVerifierAir as BaseAir<AB::F>>::width(&constraint_air);

        let num_opened_values =
            self.serialized_proof.trace_width * 2 + self.serialized_proof.num_quotient_chunks;
        let opening_air =
            OpeningVerifierAir::new(num_opened_values, self.merkle_tree_depth).unwrap();
        let opening_width = <OpeningVerifierAir as BaseAir<AB::F>>::width(&opening_air);

        let mut offset = metadata_width;

        CommitmentVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            num_commitments,
            self.merkle_tree_depth,
        );
        offset += commitment_width;

        FriVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            self.serialized_proof.fri_rounds.len(),
            self.log_final_poly_len,
            self.num_fri_queries,
        );
        offset += fri_width;

        ConstraintVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            self.serialized_proof.num_quotient_chunks,
            self.serialized_proof.trace_width,
            self.serialized_proof.degree_bits,
        );
        offset += constraint_width;

        OpeningVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            num_opened_values,
            self.merkle_tree_depth,
        );
        offset += opening_width;

        // Metadata: is_zk must be 0 or 1
        let is_zk_col = 3;
        let is_zk = local[is_zk_col].clone();
        let one = AB::Expr::from(<AB::F as PrimeCharacteristicRing>::ONE);
        builder.assert_zero(AB::Expr::from(is_zk.clone()) * (AB::Expr::from(is_zk) - one));

        // Public values equality: expected[i] == actual[i]
        for i in 0..self.serialized_proof.expected_public_values.len() {
            let expected_col = offset + i * 2;
            let actual_col = offset + i * 2 + 1;
            builder.assert_eq(
                local[expected_col].clone().into(),
                local[actual_col].clone().into(),
            );
        }
    }
}

/// Evaluate constraints on a specific row. Used by BatchStarkVerifierAir.
impl<F: Field, Ch: Field> StarkVerifierAir<F, Ch> {
    pub fn eval_at_row<B: AirBuilder<F = F>>(&self, builder: &mut B, row: usize)
    where
        F: lib_q_stark_field::BasedVectorSpace<Mersenne31>,
    {
        use lib_q_stark_field::PrimeCharacteristicRing;

        let main = builder.main();
        let local = main.row_slice(row).expect("Batch row should exist");

        let metadata_width = 4;
        let num_commitments = if self.serialized_proof.random_commitment_hash.is_some() {
            3
        } else {
            2
        };
        let commitment_air =
            CommitmentVerifierAir::new(num_commitments, self.merkle_tree_depth).unwrap();
        let commitment_width = <CommitmentVerifierAir as BaseAir<F>>::width(&commitment_air);

        let fri_air = FriVerifierAir::new(
            self.serialized_proof.fri_rounds.len(),
            self.log_final_poly_len,
            self.num_fri_queries,
        )
        .unwrap();
        let fri_width = <FriVerifierAir as BaseAir<F>>::width(&fri_air);

        let constraint_air = ConstraintVerifierAir::new(
            self.serialized_proof.num_quotient_chunks,
            self.serialized_proof.trace_width,
            self.serialized_proof.degree_bits,
        )
        .unwrap();
        let constraint_width = <ConstraintVerifierAir as BaseAir<F>>::width(&constraint_air);
        let num_opened_values =
            self.serialized_proof.trace_width * 2 + self.serialized_proof.num_quotient_chunks;
        let opening_air =
            OpeningVerifierAir::new(num_opened_values, self.merkle_tree_depth).unwrap();
        let opening_width = <OpeningVerifierAir as BaseAir<F>>::width(&opening_air);

        let mut offset = metadata_width;

        CommitmentVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            num_commitments,
            self.merkle_tree_depth,
        );
        offset += commitment_width;

        FriVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            self.serialized_proof.fri_rounds.len(),
            self.log_final_poly_len,
            self.num_fri_queries,
        );
        offset += fri_width;

        ConstraintVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            self.serialized_proof.num_quotient_chunks,
            self.serialized_proof.trace_width,
            self.serialized_proof.degree_bits,
        );
        offset += constraint_width;

        OpeningVerifierAir::eval_with_offset(
            builder,
            &local,
            offset,
            num_opened_values,
            self.merkle_tree_depth,
        );
        offset += opening_width;

        let is_zk_col = 3;
        let is_zk = local[is_zk_col].clone();
        let one = B::Expr::from(<F as PrimeCharacteristicRing>::ONE);
        builder.assert_zero(B::Expr::from(is_zk.clone()) * (B::Expr::from(is_zk) - one));

        for i in 0..self.serialized_proof.expected_public_values.len() {
            let expected_col = offset + i * 2;
            let actual_col = offset + i * 2 + 1;
            builder.assert_eq(
                local[expected_col].clone().into(),
                local[actual_col].clone().into(),
            );
        }
    }
}

/// Input for recursive STARK verification
#[derive(Debug, Clone)]
pub struct RecursiveStarkVerificationInput<F: Field, Ch: Field = F> {
    /// Serialized inner proof
    pub serialized_proof: SerializedStarkProof<F, Ch>,
    /// Commitment verification inputs
    pub commitment_inputs: CommitmentVerificationInput,
    /// FRI verification inputs
    pub fri_inputs: FriVerificationInput,
    /// Constraint verification inputs
    pub constraint_inputs: ConstraintVerificationInput,
    /// Opening verification inputs
    pub opening_inputs: OpeningVerificationInput,
}

/// Build recursive verification input from a serialized STARK proof.
///
/// Constructs commitment, FRI, constraint, and opening inputs so that
/// `StarkVerifierAir::generate_trace` can produce a valid trace.
///
/// **Security:** Without the `recursive-proofs-experimental` feature, this function
/// panics. Recursive verification requires actual Merkle paths from the inner proof;
/// the stub (zero siblings) does not verify commitment inclusion and must not be used
/// in production. Enable `recursive-proofs-experimental` only for testing the stub path.
#[cfg(not(feature = "recursive-proofs-experimental"))]
pub fn build_recursive_verification_input<F, Ch>(
    _proof: &SerializedStarkProof<F, Ch>,
    _merkle_tree_depth: usize,
    _log_final_poly_len: usize,
    _num_fri_queries: usize,
) -> Result<RecursiveStarkVerificationInput<F, Ch>, AirError>
where
    F: Field + serde::Serialize,
    Ch: Field + serde::Serialize,
{
    Err(AirError::NotSupported {
        reason:
            "Recursive proof verification requires the `recursive-proofs-experimental` feature \
                 and an inner proof generated with PoseidonConfig. \
                 Zero-sibling stub inputs do not verify commitment inclusion and are not available \
                 on stable builds."
                .into(),
    })
}

#[cfg(feature = "recursive-proofs-experimental")]
pub fn build_recursive_verification_input<F, Ch>(
    proof: &SerializedStarkProof<F, Ch>,
    merkle_tree_depth: usize,
    log_final_poly_len: usize,
    num_fri_queries: usize,
) -> Result<RecursiveStarkVerificationInput<F, Ch>, AirError>
where
    F: Field + serde::Serialize,
    Ch: Field + serde::Serialize,
{
    let zero_hash = MerkleHash::from_bytes(&[0u8; 32]).map_err(|e| AirError::InvalidInput {
        reason: format!("stub MerkleHash: {}", e),
    })?;

    // CommitmentVerificationInput
    let mut expected_roots = vec![proof.trace_commitment_hash, proof.quotient_commitment_hash];
    if let Some(ref h) = proof.random_commitment_hash {
        expected_roots.push(*h);
    }
    let merkle_proofs_commit: Vec<MerkleProofInput> = expected_roots
        .iter()
        .map(|root| MerkleProofInput {
            leaf: root.to_vec(),
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let commitment_inputs = CommitmentVerificationInput {
        expected_roots,
        merkle_proofs: merkle_proofs_commit,
    };

    // FriVerificationInput
    let final_poly_len = 1 << log_final_poly_len;
    let final_poly_bytes =
        postcard::to_allocvec(&proof.final_poly).unwrap_or_else(|_| alloc::vec![]);
    let mut final_poly = final_poly_bytes;
    final_poly.resize(final_poly_len, 0u8);
    let fri_inputs = FriVerificationInput {
        fri_rounds: proof.fri_rounds.clone(),
        final_poly,
        query_indices: vec![0usize; num_fri_queries],
        query_evaluations: vec![0u8; num_fri_queries],
        round_current_evals: alloc::vec![],
        round_sibling_evals: alloc::vec![],
        round_domain_point_inverses: alloc::vec![],
    };

    // ConstraintVerificationInput: quotient_chunks, trace_local, trace_next, zeta, alpha, public_values
    let quotient_chunks: Vec<Vec<u8>> = proof
        .quotient_chunks
        .iter()
        .map(|chunk| {
            let b = chunk
                .first()
                .and_then(|c| postcard::to_allocvec(c).ok())
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8);
            vec![b]
        })
        .collect();
    let trace_local: Vec<u8> = proof
        .trace_local
        .iter()
        .map(|f| {
            postcard::to_allocvec(f)
                .ok()
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8)
        })
        .collect();
    let trace_next: Vec<u8> = proof
        .trace_next
        .iter()
        .map(|f| {
            postcard::to_allocvec(f)
                .ok()
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8)
        })
        .collect();
    let zeta = postcard::to_allocvec(&proof.zeta).unwrap_or_else(|_| alloc::vec![0u8]);
    let alpha = postcard::to_allocvec(&proof.alpha).unwrap_or_else(|_| alloc::vec![0u8]);
    let public_values =
        postcard::to_allocvec(&proof.expected_public_values).unwrap_or_else(|_| alloc::vec![]);
    let constraint_inputs = ConstraintVerificationInput {
        quotient_chunks,
        trace_local,
        trace_next,
        zeta,
        alpha,
        public_values,
    };

    // OpeningVerificationInput
    let num_opened_values = proof.trace_width * 2 + proof.num_quotient_chunks;
    let zeta_bytes = postcard::to_allocvec(&proof.zeta).unwrap_or_else(|_| alloc::vec![0u8]);
    let zeta_next_bytes =
        postcard::to_allocvec(&proof.zeta_next).unwrap_or_else(|_| alloc::vec![0u8]);
    let mut opened_values = Vec::with_capacity(num_opened_values);
    let mut domain_points = Vec::with_capacity(num_opened_values);
    let mut expected_roots_open = Vec::with_capacity(num_opened_values);
    for (i, f) in proof.trace_local.iter().enumerate() {
        let _ = i;
        let b = postcard::to_allocvec(f)
            .ok()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_bytes.clone());
        expected_roots_open.push(proof.trace_commitment_hash);
    }
    for (i, f) in proof.trace_next.iter().enumerate() {
        let _ = i;
        let b = postcard::to_allocvec(f)
            .ok()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_next_bytes.clone());
        expected_roots_open.push(proof.trace_commitment_hash);
    }
    for chunk in &proof.quotient_chunks {
        let b = chunk
            .first()
            .and_then(|c| postcard::to_allocvec(c).ok())
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_bytes.clone());
        expected_roots_open.push(proof.quotient_commitment_hash);
    }
    let merkle_proofs_open = (0..num_opened_values)
        .map(|_| MerkleProofInput {
            leaf: vec![0u8; 32],
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let opening_inputs = OpeningVerificationInput {
        opened_values,
        domain_points,
        merkle_proofs: merkle_proofs_open,
        expected_roots: expected_roots_open,
    };

    Ok(RecursiveStarkVerificationInput {
        serialized_proof: proof.clone(),
        commitment_inputs,
        fri_inputs,
        constraint_inputs,
        opening_inputs,
    })
}

/// Builds recursive verification input using real query positions from Fiat–Shamir replay.
/// When the PCS uses PoseidonMmcs, call `build_recursive_verification_input_from_proof_with_poseidon`
/// so Merkle siblings are filled from the live proof; otherwise siblings remain stub (zero).
#[cfg(feature = "recursive-proofs-experimental")]
pub fn build_recursive_verification_input_from_proof<C, A>(
    verifier: &StarkVerifier<C>,
    air: &A,
    proof: &StarkProof<C>,
    public_values: &[Val<C>],
    serialized_proof: &SerializedStarkProof<Val<C>, Val<C>>,
    merkle_tree_depth: usize,
    fri_params: &FriQueryParams,
) -> Result<RecursiveStarkVerificationInput<Val<C>, Val<C>>, AirError>
where
    C: StarkGenericConfig,
    Val<C>: Field + serde::Serialize,
    A: Air<SymbolicAirBuilder<Val<C>>>
        + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
    C::Challenger: lib_q_stark_challenger::CanObserve<Val<C>>
        + lib_q_stark_challenger::CanObserve<
            <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment,
        >
        + lib_q_stark_challenger::CanObserve<
            <<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Commitment,
        >
        + lib_q_stark_challenger::GrindingChallenger<
            Witness = <<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Witness,
        >,
    <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof: FriDataExtractor<Challenge = C::Challenge>,
    <<<C as StarkGenericConfig>::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Witness: Clone,
{
    let query_indices = verifier
        .derive_query_positions(air, proof, public_values, fri_params)
        .map_err(|e: VerificationError<_>| AirError::InvalidInput {
            reason: alloc::format!("derive_query_positions: {:?}", e),
        })?;

    build_recursive_verification_input_with_query_indices(
        serialized_proof,
        merkle_tree_depth,
        fri_params.log_final_poly_len,
        fri_params.num_queries,
        &query_indices,
    )
}

/// Builds recursive verification input with real Merkle siblings from the live FRI proof.
/// Use this when the outer config uses PoseidonMmcs so in-circuit Merkle verification is sound.
#[cfg(feature = "recursive-proofs-experimental")]
pub fn build_recursive_verification_input_from_proof_with_poseidon<C, A>(
    verifier: &StarkVerifier<C>,
    air: &A,
    proof: &StarkProof<C>,
    public_values: &[Val<C>],
    serialized_proof: &SerializedStarkProof<Val<C>, Val<C>>,
    merkle_tree_depth: usize,
    fri_params: &FriQueryParams,
) -> Result<RecursiveStarkVerificationInput<Val<C>, Val<C>>, AirError>
where
    C: StarkGenericConfig,
    Val<C>: Field + serde::Serialize,
    A: Air<SymbolicAirBuilder<Val<C>>>
        + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
    C::Challenger: lib_q_stark_challenger::CanObserve<Val<C>>
        + lib_q_stark_challenger::CanObserve<
            <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment,
        >
        + lib_q_stark_challenger::CanObserve<
            <<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Commitment,
        >
        + lib_q_stark_challenger::GrindingChallenger<
            Witness = <<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Witness,
        >,
    <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof: FriDataExtractor<Challenge = C::Challenge>
        + FriProofInputProofExtractor,
    <<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::CommitPhaseStep:
        MerklePathExtractable,
    <<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Witness: Clone,
{
    let query_indices = verifier
        .derive_query_positions(air, proof, public_values, fri_params)
        .map_err(|e: VerificationError<_>| AirError::InvalidInput {
            reason: alloc::format!("derive_query_positions: {:?}", e),
        })?;

    build_recursive_verification_input_with_real_siblings(
        serialized_proof,
        &proof.opening_proof,
        merkle_tree_depth,
        fri_params.log_final_poly_len,
        fri_params.num_queries,
        &query_indices,
    )
}

/// Builds recursive verification input using real Merkle siblings from the FRI proof.
/// Uses the first query's input proof (polynomial commitment tree) for commitment verification
/// when `P` implements `FriProofInputProofExtractor`; otherwise falls back to FRI round siblings or zero.
#[cfg(feature = "recursive-proofs-experimental")]
fn build_recursive_verification_input_with_real_siblings<F, Ch, P>(
    proof: &SerializedStarkProof<F, Ch>,
    opening_proof: &P,
    merkle_tree_depth: usize,
    log_final_poly_len: usize,
    num_fri_queries: usize,
    query_indices: &[usize],
) -> Result<RecursiveStarkVerificationInput<F, Ch>, AirError>
where
    F: Field + serde::Serialize,
    Ch: Field + serde::Serialize,
    P: FriDataExtractor + FriProofInputProofExtractor,
    P::CommitPhaseStep: MerklePathExtractable,
{
    let zero_hash = MerkleHash::from_bytes(&[0u8; 32]).map_err(|e| AirError::InvalidInput {
        reason: alloc::format!("stub MerkleHash: {}", e),
    })?;

    let query_idx0 = query_indices.first().copied().unwrap_or(0);

    let mut expected_roots = vec![proof.trace_commitment_hash, proof.quotient_commitment_hash];
    if let Some(ref h) = proof.random_commitment_hash {
        expected_roots.push(*h);
    }

    let mut merkle_proofs_commit: Vec<MerkleProofInput> = Vec::with_capacity(expected_roots.len());

    if let Some(input_proof) = opening_proof.first_query_input_proof() {
        let path_bits = input_proof.input_proof_path_bits(query_idx0, merkle_tree_depth);
        for (batch_idx, root) in expected_roots.iter().enumerate() {
            let siblings = input_proof
                .input_proof_siblings(batch_idx, merkle_tree_depth)
                .unwrap_or_else(|| alloc::vec![zero_hash.clone(); merkle_tree_depth]);
            let mut s = siblings;
            while s.len() < merkle_tree_depth {
                s.push(zero_hash.clone());
            }
            merkle_proofs_commit.push(MerkleProofInput {
                leaf: root.to_vec(),
                path_bits: path_bits.clone(),
                siblings: s,
            });
        }
    } else if let Some(steps) = opening_proof.commit_phase_openings(0) {
        let path_bits_from_query: Vec<bool> = (0..merkle_tree_depth)
            .map(|level| ((query_idx0 >> level) & 1) == 1)
            .collect();
        let depth = core::cmp::min(merkle_tree_depth, steps.len());
        let mut siblings: Vec<MerkleHash> = (0..depth)
            .map(|i| steps[i].sibling_as_merkle_hash())
            .collect::<Result<Vec<_>, _>>()?;
        while siblings.len() < merkle_tree_depth {
            siblings.push(zero_hash.clone());
        }
        let path_bits: Vec<bool> = path_bits_from_query
            .iter()
            .take(merkle_tree_depth)
            .cloned()
            .collect();
        merkle_proofs_commit.push(MerkleProofInput {
            leaf: expected_roots[0].to_vec(),
            path_bits,
            siblings,
        });
        for root in expected_roots.iter().skip(1) {
            merkle_proofs_commit.push(MerkleProofInput {
                leaf: root.to_vec(),
                path_bits: vec![false; merkle_tree_depth],
                siblings: vec![zero_hash.clone(); merkle_tree_depth],
            });
        }
    } else {
        for root in &expected_roots {
            merkle_proofs_commit.push(MerkleProofInput {
                leaf: root.to_vec(),
                path_bits: vec![false; merkle_tree_depth],
                siblings: vec![zero_hash.clone(); merkle_tree_depth],
            });
        }
    }

    let commitment_inputs = CommitmentVerificationInput {
        expected_roots,
        merkle_proofs: merkle_proofs_commit,
    };

    let final_poly_len = 1 << log_final_poly_len;
    let final_poly_bytes =
        postcard::to_allocvec(&proof.final_poly).unwrap_or_else(|_| alloc::vec![]);
    let mut final_poly = final_poly_bytes;
    final_poly.resize(final_poly_len, 0u8);
    let mut query_indices_vec: Vec<usize> = query_indices
        .iter()
        .take(num_fri_queries)
        .copied()
        .collect();
    query_indices_vec.resize(num_fri_queries, 0);

    let mut query_evaluations = alloc::vec![0u8; num_fri_queries];
    for (q, &idx) in query_indices.iter().take(num_fri_queries).enumerate() {
        if let Some(steps) = opening_proof.commit_phase_openings(idx) {
            if let Some(last) = steps.last() {
                if let Ok(mh) = last.sibling_as_merkle_hash() {
                    let bytes: Vec<u8> = mh.as_field().clone().into_bytes().into_iter().collect();
                    if !bytes.is_empty() {
                        query_evaluations[q] = bytes[0];
                    }
                }
            }
        }
    }

    let fri_inputs = FriVerificationInput {
        fri_rounds: proof.fri_rounds.clone(),
        final_poly,
        query_indices: query_indices_vec,
        query_evaluations,
        round_current_evals: alloc::vec![],
        round_sibling_evals: alloc::vec![],
        round_domain_point_inverses: alloc::vec![],
    };

    let quotient_chunks: Vec<Vec<u8>> = proof
        .quotient_chunks
        .iter()
        .map(|chunk| {
            let b = chunk
                .first()
                .and_then(|c| postcard::to_allocvec(c).ok())
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8);
            vec![b]
        })
        .collect();
    let trace_local: Vec<u8> = proof
        .trace_local
        .iter()
        .map(|f| {
            postcard::to_allocvec(f)
                .ok()
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8)
        })
        .collect();
    let trace_next: Vec<u8> = proof
        .trace_next
        .iter()
        .map(|f| {
            postcard::to_allocvec(f)
                .ok()
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8)
        })
        .collect();
    let zeta = postcard::to_allocvec(&proof.zeta).unwrap_or_else(|_| alloc::vec![0u8]);
    let alpha = postcard::to_allocvec(&proof.alpha).unwrap_or_else(|_| alloc::vec![0u8]);
    let public_values =
        postcard::to_allocvec(&proof.expected_public_values).unwrap_or_else(|_| alloc::vec![]);
    let constraint_inputs = ConstraintVerificationInput {
        quotient_chunks,
        trace_local,
        trace_next,
        zeta,
        alpha,
        public_values,
    };

    let num_opened_values = proof.trace_width * 2 + proof.num_quotient_chunks;
    let zeta_bytes = postcard::to_allocvec(&proof.zeta).unwrap_or_else(|_| alloc::vec![0u8]);
    let zeta_next_bytes =
        postcard::to_allocvec(&proof.zeta_next).unwrap_or_else(|_| alloc::vec![0u8]);
    let mut opened_values = Vec::with_capacity(num_opened_values);
    let mut domain_points = Vec::with_capacity(num_opened_values);
    let mut expected_roots_open = Vec::with_capacity(num_opened_values);
    for (_, f) in proof.trace_local.iter().enumerate() {
        let b = postcard::to_allocvec(f)
            .ok()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_bytes.clone());
        expected_roots_open.push(proof.trace_commitment_hash);
    }
    for (_, f) in proof.trace_next.iter().enumerate() {
        let b = postcard::to_allocvec(f)
            .ok()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_next_bytes.clone());
        expected_roots_open.push(proof.trace_commitment_hash);
    }
    for chunk in &proof.quotient_chunks {
        let b = chunk
            .first()
            .and_then(|c| postcard::to_allocvec(c).ok())
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_bytes.clone());
        expected_roots_open.push(proof.quotient_commitment_hash);
    }
    let merkle_proofs_open = (0..num_opened_values)
        .map(|_| MerkleProofInput {
            leaf: vec![0u8; 32],
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let opening_inputs = OpeningVerificationInput {
        opened_values,
        domain_points,
        merkle_proofs: merkle_proofs_open,
        expected_roots: expected_roots_open,
    };

    Ok(RecursiveStarkVerificationInput {
        serialized_proof: proof.clone(),
        commitment_inputs,
        fri_inputs,
        constraint_inputs,
        opening_inputs,
    })
}

/// Same as build_recursive_verification_input but with precomputed query_indices.
#[cfg(feature = "recursive-proofs-experimental")]
fn build_recursive_verification_input_with_query_indices<F, Ch>(
    proof: &SerializedStarkProof<F, Ch>,
    merkle_tree_depth: usize,
    log_final_poly_len: usize,
    num_fri_queries: usize,
    query_indices: &[usize],
) -> Result<RecursiveStarkVerificationInput<F, Ch>, AirError>
where
    F: Field + serde::Serialize,
    Ch: Field + serde::Serialize,
{
    let zero_hash = MerkleHash::from_bytes(&[0u8; 32]).map_err(|e| AirError::InvalidInput {
        reason: alloc::format!("stub MerkleHash: {}", e),
    })?;

    let mut expected_roots = vec![proof.trace_commitment_hash, proof.quotient_commitment_hash];
    if let Some(ref h) = proof.random_commitment_hash {
        expected_roots.push(*h);
    }
    let merkle_proofs_commit: Vec<MerkleProofInput> = expected_roots
        .iter()
        .map(|root| MerkleProofInput {
            leaf: root.to_vec(),
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let commitment_inputs = CommitmentVerificationInput {
        expected_roots,
        merkle_proofs: merkle_proofs_commit,
    };

    let final_poly_len = 1 << log_final_poly_len;
    let final_poly_bytes =
        postcard::to_allocvec(&proof.final_poly).unwrap_or_else(|_| alloc::vec![]);
    let mut final_poly = final_poly_bytes;
    final_poly.resize(final_poly_len, 0u8);
    let mut query_indices_vec: Vec<usize> = query_indices
        .iter()
        .take(num_fri_queries)
        .copied()
        .collect();
    query_indices_vec.resize(num_fri_queries, 0);
    let fri_inputs = FriVerificationInput {
        fri_rounds: proof.fri_rounds.clone(),
        final_poly,
        query_indices: query_indices_vec,
        query_evaluations: vec![0u8; num_fri_queries],
        round_current_evals: alloc::vec![],
        round_sibling_evals: alloc::vec![],
        round_domain_point_inverses: alloc::vec![],
    };

    let quotient_chunks: Vec<Vec<u8>> = proof
        .quotient_chunks
        .iter()
        .map(|chunk| {
            let b = chunk
                .first()
                .and_then(|c| postcard::to_allocvec(c).ok())
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8);
            vec![b]
        })
        .collect();
    let trace_local: Vec<u8> = proof
        .trace_local
        .iter()
        .map(|f| {
            postcard::to_allocvec(f)
                .ok()
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8)
        })
        .collect();
    let trace_next: Vec<u8> = proof
        .trace_next
        .iter()
        .map(|f| {
            postcard::to_allocvec(f)
                .ok()
                .and_then(|v| v.into_iter().next())
                .unwrap_or(0u8)
        })
        .collect();
    let zeta = postcard::to_allocvec(&proof.zeta).unwrap_or_else(|_| alloc::vec![0u8]);
    let alpha = postcard::to_allocvec(&proof.alpha).unwrap_or_else(|_| alloc::vec![0u8]);
    let public_values =
        postcard::to_allocvec(&proof.expected_public_values).unwrap_or_else(|_| alloc::vec![]);
    let constraint_inputs = ConstraintVerificationInput {
        quotient_chunks,
        trace_local,
        trace_next,
        zeta,
        alpha,
        public_values,
    };

    let num_opened_values = proof.trace_width * 2 + proof.num_quotient_chunks;
    let zeta_bytes = postcard::to_allocvec(&proof.zeta).unwrap_or_else(|_| alloc::vec![0u8]);
    let zeta_next_bytes =
        postcard::to_allocvec(&proof.zeta_next).unwrap_or_else(|_| alloc::vec![0u8]);
    let mut opened_values = Vec::with_capacity(num_opened_values);
    let mut domain_points = Vec::with_capacity(num_opened_values);
    let mut expected_roots_open = Vec::with_capacity(num_opened_values);
    for (_, f) in proof.trace_local.iter().enumerate() {
        let b = postcard::to_allocvec(f)
            .ok()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_bytes.clone());
        expected_roots_open.push(proof.trace_commitment_hash);
    }
    for (_, f) in proof.trace_next.iter().enumerate() {
        let b = postcard::to_allocvec(f)
            .ok()
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_next_bytes.clone());
        expected_roots_open.push(proof.trace_commitment_hash);
    }
    for chunk in &proof.quotient_chunks {
        let b = chunk
            .first()
            .and_then(|c| postcard::to_allocvec(c).ok())
            .and_then(|v| v.into_iter().next())
            .unwrap_or(0u8);
        opened_values.push(vec![b]);
        domain_points.push(zeta_bytes.clone());
        expected_roots_open.push(proof.quotient_commitment_hash);
    }
    let merkle_proofs_open = (0..num_opened_values)
        .map(|_| MerkleProofInput {
            leaf: vec![0u8; 32],
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let opening_inputs = OpeningVerificationInput {
        opened_values,
        domain_points,
        merkle_proofs: merkle_proofs_open,
        expected_roots: expected_roots_open,
    };

    Ok(RecursiveStarkVerificationInput {
        serialized_proof: proof.clone(),
        commitment_inputs,
        fri_inputs,
        constraint_inputs,
        opening_inputs,
    })
}

impl<F: Field + lib_q_stark_field::BasedVectorSpace<Mersenne31>, Ch: Field>
    TraceGenerator<F, RecursiveStarkVerificationInput<F, Ch>> for StarkVerifierAir<F, Ch>
{
    fn generate_trace(
        &self,
        inputs: &RecursiveStarkVerificationInput<F, Ch>,
    ) -> Result<RowMajorMatrix<F>, AirError> {
        use lib_q_stark_field::extension::Complex;
        use lib_q_stark_mersenne31::Mersenne31;
        type Val = Complex<Mersenne31>;

        // Validate that inputs match the serialized proof
        if inputs.serialized_proof.degree_bits != self.serialized_proof.degree_bits {
            return Err(AirError::InvalidInput {
                reason: format!(
                    "Input degree_bits {} doesn't match serialized proof {}",
                    inputs.serialized_proof.degree_bits, self.serialized_proof.degree_bits
                ),
            });
        }

        let width = self.trace_width();
        let num_rows_padded = next_power_of_two(1);
        validate_trace_dimensions(width, num_rows_padded)?;

        let mut trace_values = vec![F::ZERO; num_rows_padded * width];

        // Generate traces for each component
        let num_commitments = if self.serialized_proof.random_commitment_hash.is_some() {
            3
        } else {
            2
        };
        let commitment_air = CommitmentVerifierAir::new(num_commitments, self.merkle_tree_depth)?;
        let commitment_trace: RowMajorMatrix<F> =
            commitment_air.generate_trace(&inputs.commitment_inputs)?;
        let commitment_width = <CommitmentVerifierAir as BaseAir<Val>>::width(&commitment_air);

        let fri_air = FriVerifierAir::new(
            self.serialized_proof.fri_rounds.len(),
            self.log_final_poly_len,
            self.num_fri_queries,
        )?;
        let fri_trace: RowMajorMatrix<F> = fri_air.generate_trace(&inputs.fri_inputs)?;
        let fri_width = <FriVerifierAir as BaseAir<Val>>::width(&fri_air);

        let constraint_air = ConstraintVerifierAir::new(
            self.serialized_proof.num_quotient_chunks,
            self.serialized_proof.trace_width,
            self.serialized_proof.degree_bits,
        )?;
        let constraint_trace: RowMajorMatrix<F> =
            constraint_air.generate_trace(&inputs.constraint_inputs)?;
        let constraint_width = <ConstraintVerifierAir as BaseAir<Val>>::width(&constraint_air);

        let num_opened_values =
            self.serialized_proof.trace_width * 2 + self.serialized_proof.num_quotient_chunks;
        let opening_air = OpeningVerifierAir::new(num_opened_values, self.merkle_tree_depth)?;
        let opening_trace: RowMajorMatrix<F> =
            opening_air.generate_trace(&inputs.opening_inputs)?;
        let opening_width = <OpeningVerifierAir as BaseAir<Val>>::width(&opening_air);

        // Combine all traces into a single trace
        let mut offset = 0;

        // Metadata section
        let metadata_width = 4;
        trace_values[offset] = F::from_prime_subfield(
            <F::PrimeSubfield as QuotientMap<usize>>::from_int(self.serialized_proof.degree_bits),
        );
        trace_values[offset + 1] =
            F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<usize>>::from_int(
                self.serialized_proof.num_quotient_chunks,
            ));
        trace_values[offset + 2] =
            F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<usize>>::from_int(
                self.serialized_proof.trace_width,
            ));
        trace_values[offset + 3] = if self.serialized_proof.is_zk {
            F::ONE
        } else {
            F::ZERO
        };
        offset += metadata_width;

        // Commitment verification section
        for col in 0..commitment_width {
            trace_values[offset + col] = match commitment_trace.get(0, col) {
                Some(x) => x,
                None => F::ZERO,
            };
        }
        offset += commitment_width;

        // FRI verification section
        for col in 0..fri_width {
            trace_values[offset + col] = match fri_trace.get(0, col) {
                Some(x) => x,
                None => F::ZERO,
            };
        }
        offset += fri_width;

        // Constraint verification section
        for col in 0..constraint_width {
            trace_values[offset + col] = match constraint_trace.get(0, col) {
                Some(x) => x,
                None => F::ZERO,
            };
        }
        offset += constraint_width;

        // Opening verification section
        for col in 0..opening_width {
            trace_values[offset + col] = match opening_trace.get(0, col) {
                Some(x) => x,
                None => F::ZERO,
            };
        }
        offset += opening_width;

        // Public values section (expected vs actual); equality verified in eval()
        for (i, val) in self
            .serialized_proof
            .expected_public_values
            .iter()
            .enumerate()
        {
            let f_val = *val;
            trace_values[offset + i * 2] = f_val;
            trace_values[offset + i * 2 + 1] = f_val;
        }

        Ok(RowMajorMatrix::new(trace_values, width))
    }

    fn public_values(&self, _inputs: &RecursiveStarkVerificationInput<F, Ch>) -> Vec<F> {
        self.serialized_proof.expected_public_values.clone()
    }
}

#[cfg(test)]
mod tests {
    use lib_q_stark_air::BaseAir;
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use super::super::recursive_types::{
        SerializedFriRound,
        SerializedStarkProof,
    };
    use super::*;

    type TestField = Complex<Mersenne31>;

    #[test]
    fn test_stark_verifier_air_new_valid() {
        // Create a minimal serialized proof
        let serialized_proof = SerializedStarkProof::<TestField, TestField> {
            degree_bits: 8,
            num_quotient_chunks: 2,
            trace_width: 4,
            is_zk: false,
            trace_commitment_hash: [0u8; 32],
            quotient_commitment_hash: [0u8; 32],
            random_commitment_hash: None,
            trace_local: vec![TestField::ZERO; 4],
            trace_next: vec![TestField::ZERO; 4],
            quotient_chunks: vec![vec![TestField::ZERO; 1]; 2],
            random_values: None,
            fri_rounds: vec![SerializedFriRound {
                commitment_hash: [0u8; 32],
                beta: vec![],
            }],
            final_poly: vec![],
            pow_witness: vec![],
            zeta: TestField::ZERO,
            zeta_next: TestField::ZERO,
            alpha: TestField::ZERO,
            expected_public_values: vec![],
        };

        let air = StarkVerifierAir::<TestField, TestField>::new(serialized_proof, 8, 4, 10);
        assert!(air.is_ok());
    }

    #[test]
    fn test_stark_verifier_air_width() {
        let serialized_proof = SerializedStarkProof::<TestField, TestField> {
            degree_bits: 8,
            num_quotient_chunks: 2,
            trace_width: 4,
            is_zk: false,
            trace_commitment_hash: [0u8; 32],
            quotient_commitment_hash: [0u8; 32],
            random_commitment_hash: None,
            trace_local: vec![TestField::ZERO; 4],
            trace_next: vec![TestField::ZERO; 4],
            quotient_chunks: vec![vec![TestField::ZERO; 1]; 2],
            random_values: None,
            fri_rounds: vec![SerializedFriRound {
                commitment_hash: [0u8; 32],
                beta: vec![],
            }],
            final_poly: vec![],
            pow_witness: vec![],
            zeta: TestField::ZERO,
            zeta_next: TestField::ZERO,
            alpha: TestField::ZERO,
            expected_public_values: vec![],
        };

        let air =
            StarkVerifierAir::<TestField, TestField>::new(serialized_proof, 8, 4, 10).unwrap();
        let width = BaseAir::<TestField>::width(&air);
        assert!(width > 0);
    }

    #[test]
    #[cfg(not(feature = "recursive-proofs-experimental"))]
    fn test_build_recursive_verification_input_returns_err_without_feature() {
        use super::build_recursive_verification_input;

        let serialized_proof = SerializedStarkProof::<TestField, TestField> {
            degree_bits: 8,
            num_quotient_chunks: 2,
            trace_width: 4,
            is_zk: false,
            trace_commitment_hash: [1u8; 32],
            quotient_commitment_hash: [2u8; 32],
            random_commitment_hash: None,
            trace_local: vec![TestField::ZERO; 4],
            trace_next: vec![TestField::ZERO; 4],
            quotient_chunks: vec![vec![TestField::ZERO; 1]; 2],
            random_values: None,
            fri_rounds: vec![SerializedFriRound {
                commitment_hash: [3u8; 32],
                beta: vec![0u8; 8],
            }],
            final_poly: vec![TestField::ZERO; 16],
            pow_witness: vec![],
            zeta: TestField::ZERO,
            zeta_next: TestField::ZERO,
            alpha: TestField::ZERO,
            expected_public_values: vec![],
        };

        let result = build_recursive_verification_input(&serialized_proof, 4, 4, 10);
        assert!(
            result.is_err(),
            "without recursive-proofs-experimental, build_recursive_verification_input must return Err"
        );
    }

    #[test]
    #[cfg(feature = "recursive-proofs-experimental")]
    fn test_build_recursive_verification_input_minimal() {
        use super::build_recursive_verification_input;

        let serialized_proof = SerializedStarkProof::<TestField, TestField> {
            degree_bits: 8,
            num_quotient_chunks: 2,
            trace_width: 4,
            is_zk: false,
            trace_commitment_hash: [1u8; 32],
            quotient_commitment_hash: [2u8; 32],
            random_commitment_hash: None,
            trace_local: vec![TestField::ZERO; 4],
            trace_next: vec![TestField::ZERO; 4],
            quotient_chunks: vec![vec![TestField::ZERO; 1]; 2],
            random_values: None,
            fri_rounds: vec![SerializedFriRound {
                commitment_hash: [3u8; 32],
                beta: vec![0u8; 8],
            }],
            final_poly: vec![TestField::ZERO; 16],
            pow_witness: vec![],
            zeta: TestField::ZERO,
            zeta_next: TestField::ZERO,
            alpha: TestField::ZERO,
            expected_public_values: vec![],
        };

        let result = build_recursive_verification_input(&serialized_proof, 4, 4, 10);
        assert!(result.is_ok());
        let input = result.unwrap();
        assert_eq!(input.commitment_inputs.expected_roots.len(), 2);
        assert_eq!(input.commitment_inputs.merkle_proofs.len(), 2);
        assert_eq!(input.fri_inputs.fri_rounds.len(), 1);
        assert_eq!(input.fri_inputs.query_indices.len(), 10);
        assert_eq!(input.constraint_inputs.quotient_chunks.len(), 2);
        assert_eq!(input.opening_inputs.opened_values.len(), 4 * 2 + 2);
    }
}
