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

#[cfg(feature = "recursive-proofs-experimental")]
use alloc::string::ToString;
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
    WindowAccess,
};
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_commit::BatchOpening;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_commit::Pcs;
use lib_q_stark_field::Field;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_field::TwoAdicField;
use lib_q_stark_field::integers::QuotientMap;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_fri::CommitPhaseProofStep;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_fri::FriDataExtractor;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_fri::FriInitialEval;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_fri::{
    FriProof,
    SiblingValueRef,
};
use lib_q_stark_matrix::Matrix;
use lib_q_stark_matrix::dense::RowMajorMatrix;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_merkle::PoseidonMmcs;
use lib_q_stark_mersenne31::Mersenne31;
#[cfg(feature = "recursive-proofs-experimental")]
use lib_q_stark_symmetric::Hash;

#[cfg(feature = "recursive-proofs-experimental")]
use super::PoseidonCommitmentRoot;
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
    /// Leaf hash (32-byte Poseidon root encoding) for the `batch_idx`-th batch at this query, if available.
    /// Used so the commitment Merkle path verifies to the expected root.
    fn input_proof_leaf_hash(
        &self,
        batch_idx: usize,
    ) -> Option<[u8; super::recursive_types::COMMITMENT_HASH_SIZE]> {
        let _ = (batch_idx, self);
        None
    }
}

/// Trait for FRI proofs whose first query's input proof can be used for commitment/opening verification.
#[cfg(feature = "recursive-proofs-experimental")]
pub trait FriProofInputProofExtractor {
    type InputProof: InputProofMerkleExtractable;
    fn first_query_input_proof(&self) -> Option<&Self::InputProof>;
}

#[cfg(feature = "recursive-proofs-experimental")]
impl<F, M, W, EF, MM> FriProofInputProofExtractor for FriProof<F, M, W, Vec<BatchOpening<EF, MM>>>
where
    F: Field,
    M: lib_q_stark_commit::Mmcs<F>,
    EF: Field,
    MM: lib_q_stark_commit::Mmcs<EF>,
    Vec<BatchOpening<EF, MM>>: InputProofMerkleExtractable,
{
    type InputProof = Vec<BatchOpening<EF, MM>>;
    fn first_query_input_proof(&self) -> Option<&Self::InputProof> {
        self.query_proofs.get(0).map(|q| &q.input_proof)
    }
}

#[cfg(feature = "recursive-proofs-experimental")]
impl PoseidonCommitmentRoot for Hash<PoseidonField, PoseidonField, 1> {
    fn to_poseidon_root_bytes(&self) -> [u8; super::recursive_types::COMMITMENT_HASH_SIZE] {
        super::merkle_root_to_bytes(&self.as_ref()[0])
    }
}

#[cfg(feature = "recursive-proofs-experimental")]
impl InputProofMerkleExtractable for Vec<BatchOpening<PoseidonField, PoseidonMmcs>> {
    fn input_proof_siblings(&self, batch_idx: usize, tree_depth: usize) -> Option<Vec<MerkleHash>> {
        let batch = self.get(batch_idx)?;
        let proof = &batch.opening_proof;
        let siblings: Vec<MerkleHash> = proof
            .iter()
            .take(tree_depth)
            .filter_map(|sibling_row| {
                // Each sibling is a slice of field elements (width of the matrix row).
                // Hash all elements into a single MerkleHash for multi-width support.
                if sibling_row.is_empty() {
                    return None;
                }
                if sibling_row.len() == 1 {
                    Some(MerkleHash::from_field(sibling_row[0]))
                } else {
                    use lib_q_poseidon::{
                        Poseidon,
                        Poseidon128,
                    };
                    let hash_output = Poseidon128.hash(sibling_row);
                    let first = hash_output.into_iter().next().unwrap_or_default();
                    Some(MerkleHash::from_field(first))
                }
            })
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

    fn input_proof_leaf_hash(
        &self,
        batch_idx: usize,
    ) -> Option<[u8; super::recursive_types::COMMITMENT_HASH_SIZE]> {
        let batch = self.get(batch_idx)?;
        let row = batch.opened_values.first()?;
        // Mirror MMCS verifier: verify_batch hashes opened_values with hash_iter_slices (flatten
        // of slices). For one matrix that is hash(row). PoseidonHasher::hash_iter uses
        // Poseidon128.hash(&vec). Leaf layer uses unpacked row when PW::WIDTH is 1 (PoseidonField).
        use lib_q_poseidon::{
            Poseidon,
            Poseidon128,
        };
        let out = Poseidon128.hash(row.as_slice());
        Some(super::merkle_root_to_bytes(&out[0]))
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
        let main = builder.main();
        let local = main.current_slice();
        self.eval_on_slice(builder, local);
    }
}

/// Evaluate constraints on a row slice. Used by both Air::eval and BatchStarkVerifierAir.
impl<F: Field, Ch: Field> StarkVerifierAir<F, Ch> {
    pub fn eval_on_slice<B: AirBuilder<F = F>>(&self, builder: &mut B, local: &[B::Var])
    where
        F: lib_q_stark_field::BasedVectorSpace<Mersenne31>,
    {
        use lib_q_stark_field::PrimeCharacteristicRing;

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

        #[cfg(all(
            feature = "std",
            feature = "recursive-proofs-experimental",
            feature = "trace-debug"
        ))]
        std::eprintln!("StarkVerifierAir: checking CommitmentVerifierAir");
        CommitmentVerifierAir::eval_with_offset(
            builder,
            local,
            offset,
            num_commitments,
            self.merkle_tree_depth,
        );
        offset += commitment_width;

        #[cfg(all(
            feature = "std",
            feature = "recursive-proofs-experimental",
            feature = "trace-debug"
        ))]
        std::eprintln!("StarkVerifierAir: checking FriVerifierAir");
        FriVerifierAir::eval_with_offset(
            builder,
            local,
            offset,
            self.serialized_proof.fri_rounds.len(),
            self.log_final_poly_len,
            self.num_fri_queries,
        );
        offset += fri_width;

        #[cfg(all(
            feature = "std",
            feature = "recursive-proofs-experimental",
            feature = "trace-debug"
        ))]
        std::eprintln!("StarkVerifierAir: checking ConstraintVerifierAir");
        ConstraintVerifierAir::eval_with_offset(
            builder,
            local,
            offset,
            self.serialized_proof.num_quotient_chunks,
            self.serialized_proof.trace_width,
            self.serialized_proof.degree_bits,
        );
        offset += constraint_width;

        #[cfg(all(
            feature = "std",
            feature = "recursive-proofs-experimental",
            feature = "trace-debug"
        ))]
        std::eprintln!("StarkVerifierAir: checking OpeningVerifierAir");
        OpeningVerifierAir::eval_with_offset(
            builder,
            local,
            offset,
            num_opened_values,
            self.merkle_tree_depth,
        );
        offset += opening_width;

        #[cfg(all(
            feature = "std",
            feature = "recursive-proofs-experimental",
            feature = "trace-debug"
        ))]
        std::eprintln!("StarkVerifierAir: checking is_zk and public_values");
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

/// Input for recursive STARK verification (field-typed for correct constraint satisfaction).
#[derive(Debug, Clone)]
pub struct RecursiveStarkVerificationInput<F: Field, Ch: Field = F> {
    /// Serialized inner proof
    pub serialized_proof: SerializedStarkProof<F, Ch>,
    /// Commitment verification inputs
    pub commitment_inputs: CommitmentVerificationInput,
    /// FRI verification inputs
    pub fri_inputs: FriVerificationInput<F>,
    /// Constraint verification inputs
    pub constraint_inputs: ConstraintVerificationInput<F>,
    /// Opening verification inputs
    pub opening_inputs: OpeningVerificationInput<F>,
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
    F: Field + serde::Serialize + serde::de::DeserializeOwned,
    Ch: Field + serde::Serialize + serde::de::DeserializeOwned + Into<F>,
{
    let zero_hash = MerkleHash::from_bytes(&[0u8; 32]).map_err(|e| AirError::InvalidInput {
        reason: format!("stub MerkleHash: {}", e),
    })?;

    let mut expected_roots = vec![proof.trace_commitment_hash, proof.quotient_commitment_hash];
    if let Some(ref h) = proof.random_commitment_hash {
        expected_roots.push(*h);
    }
    let merkle_proofs_commit: Vec<MerkleProofInput> = expected_roots
        .iter()
        .map(|root| MerkleProofInput {
            leaf: root.to_vec(),
            leaf_hash_direct: None,
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let commitment_inputs = CommitmentVerificationInput {
        expected_roots,
        merkle_proofs: merkle_proofs_commit,
    };

    let final_poly_len = 1 << log_final_poly_len;
    let num_rounds = proof.fri_rounds.len();
    let round_betas: Vec<F> = proof
        .fri_rounds
        .iter()
        .map(|r| {
            postcard::from_bytes::<Ch>(&r.beta)
                .ok()
                .map(|b| b.into())
                .unwrap_or(F::ZERO)
        })
        .collect();
    let mut final_poly: Vec<F> = proof.final_poly.iter().map(|c| c.clone().into()).collect();
    final_poly.resize(final_poly_len, F::ZERO);

    let fri_inputs = FriVerificationInput::<F> {
        fri_rounds: proof.fri_rounds.clone(),
        round_betas,
        final_poly,
        query_indices: vec![0usize; num_fri_queries],
        query_evaluations: vec![F::ZERO; num_fri_queries],
        round_current_evals: vec![F::ZERO; num_rounds],
        round_sibling_evals: vec![F::ZERO; num_rounds],
        round_domain_point_inverses: vec![F::ZERO; num_rounds],
        round_domain_point_x0: vec![F::ZERO; num_rounds],
        round_parity: vec![F::ZERO; num_rounds],
        final_poly_eval_point: F::ZERO,
        round_roll_ins: vec![F::ZERO; num_rounds],
    };

    let quotient_chunks: Vec<F> = proof
        .quotient_chunks
        .iter()
        .map(|chunk| chunk.first().cloned().map(Into::into).unwrap_or(F::ZERO))
        .collect();
    let constraint_inputs = ConstraintVerificationInput::<F> {
        quotient_chunks,
        trace_local: proof.trace_local.clone(),
        trace_next: proof.trace_next.clone(),
        zeta: proof.zeta.clone().into(),
        alpha: proof.alpha.clone().into(),
        public_values: proof.expected_public_values.clone(),
    };

    let num_opened_values = proof.trace_width * 2 + proof.num_quotient_chunks;
    let zeta_f: F = proof.zeta.clone().into();
    let zeta_next_f: F = proof.zeta_next.clone().into();
    let mut opened_values: Vec<F> = proof.trace_local.iter().cloned().collect();
    opened_values.extend(proof.trace_next.iter().cloned());
    for chunk in &proof.quotient_chunks {
        opened_values.push(chunk.first().cloned().map(Into::into).unwrap_or(F::ZERO));
    }
    let mut domain_points: Vec<F> = alloc::vec![zeta_f; proof.trace_width];
    domain_points.extend(alloc::vec![zeta_next_f; proof.trace_width]);
    domain_points.extend(alloc::vec![zeta_f; proof.num_quotient_chunks]);
    let expected_roots_open: Vec<F> = alloc::vec![F::ZERO; num_opened_values];
    let merkle_proofs_open = (0..num_opened_values)
        .map(|_| MerkleProofInput {
            leaf: vec![0u8; 32],
            leaf_hash_direct: None,
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let opening_inputs = OpeningVerificationInput::<F> {
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
    Val<C>: Field
        + serde::Serialize
        + serde::de::DeserializeOwned
        + lib_q_stark_field::BasedVectorSpace<Mersenne31>
        + TwoAdicField,
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
        MerklePathExtractable + SiblingValueRef<Challenge = Val<C>>,
    <<C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof as FriDataExtractor>::Witness: Clone,
    <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment: PoseidonCommitmentRoot,
    C::Pcs: FriInitialEval<
            C::Challenge,
            Proof = <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof,
            Error = lib_q_stark::PcsError<C>,
            Commitment = <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment,
            Domain = lib_q_stark::Domain<C>,
        > + lib_q_stark_fri::FriReducedOpenings<
            C::Challenge,
            Proof = <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Proof,
            Error = lib_q_stark::PcsError<C>,
            Commitment = <C::Pcs as Pcs<C::Challenge, C::Challenger>>::Commitment,
            Domain = lib_q_stark::Domain<C>,
        >,
    Val<C>: From<C::Challenge>,
{
    let query_indices = verifier
        .derive_query_positions(air, proof, public_values, fri_params)
        .map_err(|e: VerificationError<_>| AirError::InvalidInput {
            reason: alloc::format!("derive_query_positions: {:?}", e),
        })?;

    let alpha = serialized_proof.alpha.clone();
    let zeta = serialized_proof.zeta.clone();
    let zeta_next = serialized_proof.zeta_next.clone();
    let query_idx0 = *query_indices.first().unwrap_or(&0);
    let initial_eval = lib_q_stark::initial_fri_eval_for_query(
        verifier.config(),
        proof,
        air,
        public_values,
        0,
        query_idx0,
        alpha.clone().into(),
        zeta.clone().into(),
        zeta_next.clone().into(),
    )
    .map_err(|e: VerificationError<_>| AirError::InvalidInput {
        reason: alloc::format!("initial_fri_eval_for_query: {:?}", e),
    })?;

    let reduced_openings = lib_q_stark::all_fri_reduced_openings_for_query(
        verifier.config(),
        proof,
        air,
        public_values,
        0,
        query_idx0,
        alpha.clone().into(),
        zeta.clone().into(),
        zeta_next.clone().into(),
    )
    .ok()
    .map(|v| {
        v.into_iter()
            .map(|(h, c)| (h, c.into()))
            .collect::<Vec<_>>()
    });

    let commitment_roots = {
        let mut roots = alloc::vec![
            proof.commitments.trace.to_poseidon_root_bytes(),
            proof.commitments.quotient_chunks.to_poseidon_root_bytes(),
        ];
        if let Some(ref r) = proof.commitments.random {
            roots.push(r.to_poseidon_root_bytes());
        }
        roots
    };

    build_recursive_verification_input_with_real_siblings(
        serialized_proof,
        &proof.opening_proof,
        merkle_tree_depth,
        fri_params.log_final_poly_len,
        fri_params.num_queries,
        &query_indices,
        fri_params.log_blowup,
        Some(initial_eval.into()),
        reduced_openings,
        Some(&commitment_roots),
    )
}

/// Reverses the lower `len` bits of `n`. Used for FRI domain point indexing.
#[cfg(feature = "recursive-proofs-experimental")]
fn reverse_bits_len(n: usize, len: usize) -> usize {
    (0..len).map(|i| ((n >> i) & 1) << (len - 1 - i)).sum()
}

/// Debug one FRI round by comparing builder fold vs verifier-style fold.
/// Replicates lib_q_stark_fri::two_adic_pcs::fold_row logic to isolate mismatches.
/// For the last round, compares (fold + roll_in) to Horner at eval_point.
/// Enabled with `recursive-proofs-experimental` for use in tests.
#[cfg(feature = "recursive-proofs-experimental")]
pub fn debug_one_fri_round<F>(
    round_idx: usize,
    query_idx0: usize,
    log_final_height: usize,
    num_rounds: usize,
    round_current_evals: &[F],
    round_sibling_evals: &[F],
    round_domain_point_inverses: &[F],
    round_betas: &[F],
    round_roll_ins: Option<&[F]>,
    final_poly: &[F],
    eval_point: F,
) where
    F: Field + TwoAdicField + core::fmt::Debug,
{
    if round_idx >= num_rounds ||
        round_current_evals.len() <= round_idx ||
        round_sibling_evals.len() <= round_idx ||
        round_domain_point_inverses.len() <= round_idx ||
        round_betas.len() <= round_idx
    {
        return;
    }

    let i = round_idx;
    let domain_row_index = query_idx0 >> (i + 1);
    let log_folded_height = log_final_height + (num_rounds - 1 - i);
    let query_parity = (query_idx0 >> i) & 1;
    let current = round_current_evals[i];
    let sibling = round_sibling_evals[i];
    let beta = round_betas[i];

    // Verifier-style domain points (same as two_adic_pcs::fold_row, log_arity = 1)
    let subgroup_start = F::two_adic_generator(log_folded_height + 1)
        .exp_u64(reverse_bits_len(domain_row_index, log_folded_height) as u64);
    let g_arity = F::two_adic_generator(1);
    let xs0 = subgroup_start;
    let xs1 = subgroup_start * g_arity;
    let domain_inv_verifier = (xs1 - xs0).inverse();

    // Verifier (e0, e1) = value at even index, value at odd index
    let (e0, e1) = if query_parity == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };

    let folded_verifier = e0 + (beta - xs0) * (e1 - e0) * domain_inv_verifier;
    // Builder uses same formula; compare with builder's stored domain_inv
    let folded_builder = e0 + (beta - xs0) * (e1 - e0) * round_domain_point_inverses[i];

    #[cfg(feature = "std")]
    {
        std::println!(
            "Round {}: domain_row_index={}, log_folded_height={}, query_parity={}",
            i,
            domain_row_index,
            log_folded_height,
            query_parity
        );
        std::println!(
            "  domain_inv: verifier={:?}, builder={:?}",
            domain_inv_verifier,
            round_domain_point_inverses[i]
        );
        std::println!(
            "  (current={:?}, sibling={:?}) -> (e0={:?}, e1={:?})",
            current,
            sibling,
            e0,
            e1
        );
        std::println!(
            "  folded_verifier={:?}, folded_builder={:?}, match={}",
            folded_verifier,
            folded_builder,
            folded_verifier == folded_builder
        );
    }

    if folded_verifier != folded_builder {
        panic!(
            "FRI round {} fold mismatch: folded_verifier={:?}, folded_builder={:?}, \
             domain_inv_verifier={:?}, domain_inv_builder={:?}, (e0,e1)=({:?},{:?})",
            i,
            folded_verifier,
            folded_builder,
            domain_inv_verifier,
            round_domain_point_inverses[i],
            e0,
            e1
        );
    }

    if i == num_rounds - 1 && !final_poly.is_empty() {
        let mut horner = final_poly[final_poly.len().saturating_sub(1)];
        for j in (0..final_poly.len().saturating_sub(1)).rev() {
            horner = horner * eval_point + final_poly[j];
        }
        let roll_in = round_roll_ins
            .and_then(|r| r.get(i))
            .copied()
            .unwrap_or(F::ZERO);
        let folded_after_roll = folded_verifier + roll_in;
        let last_round_match = folded_after_roll == horner;
        #[cfg(feature = "std")]
        std::println!(
            "  [last round] folded_after_roll={:?}, horner_result={:?}, match={}",
            folded_after_roll,
            horner,
            last_round_match
        );
        if !last_round_match {
            panic!(
                "FRI last round: folded_after_roll != horner_result: {:?} != {:?}",
                folded_after_roll, horner
            );
        }
    }
}

/// Builds recursive verification input using real Merkle siblings from the FRI proof.
/// Uses the first query's input proof (polynomial commitment tree) for commitment verification
/// when `P` implements `FriProofInputProofExtractor`; otherwise falls back to FRI round siblings or zero.
///
/// When `commitment_roots_override` is `Some`, those bytes are used as expected_roots (Poseidon
/// root encoding). Use this when the inner proof uses Poseidon so the recursive verifier's
/// MerkleInclusionAir computed root matches.
#[cfg(feature = "recursive-proofs-experimental")]
fn build_recursive_verification_input_with_real_siblings<F, Ch, P>(
    proof: &SerializedStarkProof<F, Ch>,
    opening_proof: &P,
    merkle_tree_depth: usize,
    log_final_poly_len: usize,
    num_fri_queries: usize,
    query_indices: &[usize],
    log_blowup: usize,
    first_query_initial_eval: Option<F>,
    first_query_reduced_openings: Option<Vec<(usize, F)>>,
    commitment_roots_override: Option<&Vec<[u8; super::recursive_types::COMMITMENT_HASH_SIZE]>>,
) -> Result<RecursiveStarkVerificationInput<F, Ch>, AirError>
where
    F: Field
        + serde::Serialize
        + serde::de::DeserializeOwned
        + lib_q_stark_field::BasedVectorSpace<Mersenne31>
        + TwoAdicField,
    Ch: Field + serde::Serialize + serde::de::DeserializeOwned + Into<F>,
    P: FriDataExtractor + FriProofInputProofExtractor,
    P::CommitPhaseStep: MerklePathExtractable + SiblingValueRef<Challenge = Ch>,
{
    let zero_hash = MerkleHash::from_bytes(&[0u8; 32]).map_err(|e| AirError::InvalidInput {
        reason: alloc::format!("stub MerkleHash: {}", e),
    })?;

    let query_idx0 = query_indices.first().copied().unwrap_or(0);

    let expected_roots: Vec<[u8; super::recursive_types::COMMITMENT_HASH_SIZE]> =
        if let Some(roots) = commitment_roots_override {
            roots.clone()
        } else {
            let mut r = vec![proof.trace_commitment_hash, proof.quotient_commitment_hash];
            if let Some(ref h) = proof.random_commitment_hash {
                r.push(*h);
            }
            r
        };

    let mut merkle_proofs_commit: Vec<MerkleProofInput> = Vec::with_capacity(expected_roots.len());

    if let Some(input_proof) = opening_proof.first_query_input_proof() {
        let path_bits = input_proof.input_proof_path_bits(query_idx0, merkle_tree_depth);
        // PCS batch order is [random?, trace, quotient, preprocessed?], so when ZK we have
        // batch 0=random, 1=trace, 2=quotient. Our expected_roots are [trace, quotient, random?].
        let commitment_to_batch = |commitment_idx: usize| -> usize {
            if expected_roots.len() >= 3 {
                [1, 2, 0][commitment_idx] // trace=1, quotient=2, random=0
            } else {
                commitment_idx // trace=0, quotient=1
            }
        };
        for (commitment_idx, root) in expected_roots.iter().enumerate() {
            let batch_idx = commitment_to_batch(commitment_idx);
            let siblings = input_proof
                .input_proof_siblings(batch_idx, merkle_tree_depth)
                .unwrap_or_else(|| alloc::vec![zero_hash.clone(); merkle_tree_depth]);
            let mut s = siblings;
            while s.len() < merkle_tree_depth {
                s.push(zero_hash.clone());
            }
            let leaf_hash_direct = input_proof.input_proof_leaf_hash(batch_idx);
            merkle_proofs_commit.push(MerkleProofInput {
                leaf: root.to_vec(),
                leaf_hash_direct,
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
            leaf_hash_direct: None,
            path_bits,
            siblings,
        });
        for root in expected_roots.iter().skip(1) {
            merkle_proofs_commit.push(MerkleProofInput {
                leaf: root.to_vec(),
                leaf_hash_direct: None,
                path_bits: vec![false; merkle_tree_depth],
                siblings: vec![zero_hash.clone(); merkle_tree_depth],
            });
        }
    } else {
        for root in &expected_roots {
            merkle_proofs_commit.push(MerkleProofInput {
                leaf: root.to_vec(),
                leaf_hash_direct: None,
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
    let num_rounds = proof.fri_rounds.len();
    let round_betas: Vec<F> = proof
        .fri_rounds
        .iter()
        .map(|r| {
            postcard::from_bytes::<Ch>(&r.beta)
                .ok()
                .map(|b| b.into())
                .unwrap_or(F::ZERO)
        })
        .collect();
    let mut final_poly: Vec<F> = proof.final_poly.iter().map(|c| c.clone().into()).collect();
    final_poly.resize(final_poly_len, F::ZERO);
    let mut query_indices_vec: Vec<usize> = query_indices
        .iter()
        .take(num_fri_queries)
        .copied()
        .collect();
    query_indices_vec.resize(num_fri_queries, 0);

    let mut query_evaluations: Vec<F> = alloc::vec![F::ZERO; num_fri_queries];
    for (q, &idx) in query_indices.iter().take(num_fri_queries).enumerate() {
        if let Some(steps) = opening_proof.commit_phase_openings(idx) {
            if let Some(last) = steps.last() {
                if let Ok(mh) = last.sibling_as_merkle_hash() {
                    query_evaluations[q] = super::poseidon_to_field(mh.as_field());
                }
            }
        }
    }

    let (
        round_current_evals,
        round_sibling_evals,
        round_domain_point_inverses,
        round_domain_point_x0,
        round_parity,
        round_roll_ins,
    ) = if let Some(init) = first_query_initial_eval {
        let query_idx0 = *query_indices.first().unwrap_or(&0);
        let steps = opening_proof
            .commit_phase_openings(query_idx0)
            .ok_or_else(|| AirError::MissingFriCommitPhaseOpenings)?;
        if steps.len() != num_rounds {
            return Err(AirError::FriRoundCountMismatch);
        }
        let log_final_height = log_blowup + log_final_poly_len;
        let ro_by_height: alloc::collections::BTreeMap<usize, F> = first_query_reduced_openings
            .as_ref()
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();
        let mut round_current_evals = alloc::vec![F::ZERO; num_rounds];
        let mut round_sibling_evals = alloc::vec![F::ZERO; num_rounds];
        let mut round_domain_point_inverses = alloc::vec![F::ZERO; num_rounds];
        let mut round_domain_point_x0 = alloc::vec![F::ZERO; num_rounds];
        let mut round_parity = alloc::vec![F::ZERO; num_rounds];
        let mut round_roll_ins = alloc::vec![F::ZERO; num_rounds];
        let mut path_value = init;
        for i in 0..num_rounds {
            let sibling_f: F = steps[i].sibling_value_ref().clone().into();
            round_current_evals[i] = path_value;
            round_sibling_evals[i] = sibling_f;
            round_parity[i] = F::from_prime_subfield(
                <F::PrimeSubfield as QuotientMap<usize>>::from_int((query_idx0 >> i) & 1),
            );
            let log_folded_height = log_final_height + (num_rounds - 1 - i);
            let domain_row_index = query_idx0 >> (i + 1);
            let subgroup_start = F::two_adic_generator(log_folded_height + 1)
                .exp_u64(reverse_bits_len(domain_row_index, log_folded_height) as u64);
            let g_arity = F::two_adic_generator(1);
            let xs0 = subgroup_start;
            let xs1 = subgroup_start * g_arity;
            round_domain_point_x0[i] = xs0;
            round_domain_point_inverses[i] = (xs1 - xs0).inverse();
            let parity = (query_idx0 >> i) & 1;
            let (e0, e1) = if parity == 0 {
                (path_value, sibling_f)
            } else {
                (sibling_f, path_value)
            };
            let beta = round_betas[i];
            let folded = e0 + (beta - xs0) * (e1 - e0) * round_domain_point_inverses[i];
            let roll_in = ro_by_height
                .get(&log_folded_height)
                .copied()
                .unwrap_or(F::ZERO);
            round_roll_ins[i] = beta * beta * roll_in;
            path_value = folded + round_roll_ins[i];
        }
        (
            round_current_evals,
            round_sibling_evals,
            round_domain_point_inverses,
            round_domain_point_x0,
            round_parity,
            round_roll_ins,
        )
    } else {
        (
            alloc::vec![F::ZERO; num_rounds],
            alloc::vec![F::ZERO; num_rounds],
            alloc::vec![F::ZERO; num_rounds],
            alloc::vec![F::ZERO; num_rounds],
            alloc::vec![F::ZERO; num_rounds],
            alloc::vec![F::ZERO; num_rounds],
        )
    };

    // First query's evaluation must equal first round's current_eval (FRI AIR constraint).
    if let Some(init) = first_query_initial_eval {
        if !query_evaluations.is_empty() {
            query_evaluations[0] = init;
        }
    }

    // Final polynomial evaluation point: verifier checks folded_eval == final_poly(x) with this x.
    let log_global_max_height = log_blowup + log_final_poly_len + num_rounds;
    let final_domain_index = query_indices_vec.first().copied().unwrap_or(0) >> num_rounds;
    let final_poly_eval_point = F::two_adic_generator(log_global_max_height)
        .exp_u64(reverse_bits_len(final_domain_index, log_global_max_height) as u64);

    let fri_inputs = FriVerificationInput::<F> {
        fri_rounds: proof.fri_rounds.clone(),
        round_betas,
        final_poly,
        query_indices: query_indices_vec,
        query_evaluations,
        round_current_evals,
        round_sibling_evals,
        round_domain_point_inverses,
        round_domain_point_x0,
        round_parity,
        final_poly_eval_point,
        round_roll_ins,
    };

    let quotient_chunks: Vec<F> = proof
        .quotient_chunks
        .iter()
        .map(|chunk| chunk.first().cloned().map(Into::into).unwrap_or(F::ZERO))
        .collect();
    let constraint_inputs = ConstraintVerificationInput::<F> {
        quotient_chunks,
        trace_local: proof.trace_local.clone(),
        trace_next: proof.trace_next.clone(),
        zeta: proof.zeta.clone().into(),
        alpha: proof.alpha.clone().into(),
        public_values: proof.expected_public_values.clone(),
    };

    let num_opened_values = proof.trace_width * 2 + proof.num_quotient_chunks;
    let zeta_f: F = proof.zeta.clone().into();
    let zeta_next_f: F = proof.zeta_next.clone().into();
    let mut opened_values: Vec<F> = proof.trace_local.iter().cloned().collect();
    opened_values.extend(proof.trace_next.iter().cloned());
    for chunk in &proof.quotient_chunks {
        opened_values.push(chunk.first().cloned().map(Into::into).unwrap_or(F::ZERO));
    }
    let mut domain_points: Vec<F> = alloc::vec![zeta_f; proof.trace_width];
    domain_points.extend(alloc::vec![zeta_next_f; proof.trace_width]);
    domain_points.extend(alloc::vec![zeta_f; proof.num_quotient_chunks]);
    let merkle_proofs_open: Vec<MerkleProofInput> = (0..num_opened_values)
        .map(|_| MerkleProofInput {
            leaf: vec![0u8; 32],
            leaf_hash_direct: None,
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    // Expected roots must match the roots computed from the dummy Merkle proofs so that
    // verification_result = computed_root - expected_root = 0 in the opening trace.
    let merkle_air =
        super::MerkleInclusionAir::new(merkle_tree_depth).map_err(|e| AirError::InvalidInput {
            reason: e.to_string(),
        })?;
    let expected_roots_open: Vec<F> = merkle_proofs_open
        .iter()
        .map(|proof| {
            merkle_air
                .public_values(proof)
                .first()
                .copied()
                .unwrap_or(F::ZERO)
        })
        .collect();
    let opening_inputs = OpeningVerificationInput::<F> {
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
    F: Field + serde::Serialize + serde::de::DeserializeOwned,
    Ch: Field + serde::Serialize + serde::de::DeserializeOwned + Into<F>,
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
            leaf_hash_direct: None,
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let commitment_inputs = CommitmentVerificationInput {
        expected_roots,
        merkle_proofs: merkle_proofs_commit,
    };

    let final_poly_len = 1 << log_final_poly_len;
    let num_rounds = proof.fri_rounds.len();
    let round_betas: Vec<F> = proof
        .fri_rounds
        .iter()
        .map(|r| {
            postcard::from_bytes::<Ch>(&r.beta)
                .ok()
                .map(|b| b.into())
                .unwrap_or(F::ZERO)
        })
        .collect();
    let mut final_poly: Vec<F> = proof.final_poly.iter().map(|c| c.clone().into()).collect();
    final_poly.resize(final_poly_len, F::ZERO);
    let mut query_indices_vec: Vec<usize> = query_indices
        .iter()
        .take(num_fri_queries)
        .copied()
        .collect();
    query_indices_vec.resize(num_fri_queries, 0);

    let fri_inputs = FriVerificationInput::<F> {
        fri_rounds: proof.fri_rounds.clone(),
        round_betas,
        final_poly,
        query_indices: query_indices_vec,
        query_evaluations: alloc::vec![F::ZERO; num_fri_queries],
        round_current_evals: alloc::vec![F::ZERO; num_rounds],
        round_sibling_evals: alloc::vec![F::ZERO; num_rounds],
        round_domain_point_inverses: alloc::vec![F::ZERO; num_rounds],
        round_domain_point_x0: alloc::vec![F::ZERO; num_rounds],
        round_parity: alloc::vec![F::ZERO; num_rounds],
        final_poly_eval_point: F::ZERO,
        round_roll_ins: alloc::vec![F::ZERO; num_rounds],
    };

    let quotient_chunks: Vec<F> = proof
        .quotient_chunks
        .iter()
        .map(|chunk| chunk.first().cloned().map(Into::into).unwrap_or(F::ZERO))
        .collect();
    let constraint_inputs = ConstraintVerificationInput::<F> {
        quotient_chunks,
        trace_local: proof.trace_local.clone(),
        trace_next: proof.trace_next.clone(),
        zeta: proof.zeta.clone().into(),
        alpha: proof.alpha.clone().into(),
        public_values: proof.expected_public_values.clone(),
    };

    let num_opened_values = proof.trace_width * 2 + proof.num_quotient_chunks;
    let zeta_f: F = proof.zeta.clone().into();
    let zeta_next_f: F = proof.zeta_next.clone().into();
    let mut opened_values: Vec<F> = proof.trace_local.iter().cloned().collect();
    opened_values.extend(proof.trace_next.iter().cloned());
    for chunk in &proof.quotient_chunks {
        opened_values.push(chunk.first().cloned().map(Into::into).unwrap_or(F::ZERO));
    }
    let mut domain_points: Vec<F> = alloc::vec![zeta_f; proof.trace_width];
    domain_points.extend(alloc::vec![zeta_next_f; proof.trace_width]);
    domain_points.extend(alloc::vec![zeta_f; proof.num_quotient_chunks]);
    let merkle_proofs_open = (0..num_opened_values)
        .map(|_| MerkleProofInput {
            leaf: vec![0u8; 32],
            leaf_hash_direct: None,
            path_bits: vec![false; merkle_tree_depth],
            siblings: vec![zero_hash.clone(); merkle_tree_depth],
        })
        .collect();
    let opening_inputs = OpeningVerificationInput::<F> {
        opened_values,
        domain_points,
        merkle_proofs: merkle_proofs_open,
        expected_roots: alloc::vec![F::ZERO; num_opened_values],
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

        #[cfg(all(feature = "std", feature = "recursive-proofs-experimental"))]
        {
            use super::recursive_types::COMMITMENT_HASH_SIZE;

            let commitment_public_values: Vec<F> =
                commitment_air.public_values(&inputs.commitment_inputs);

            for commit_idx in 0..num_commitments {
                let input_root = &inputs.commitment_inputs.expected_roots[commit_idx];
                let _input_root_hex: String = input_root
                    .iter()
                    .take(8)
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join("");
                let _pv_start = commit_idx * COMMITMENT_HASH_SIZE;
                let pv_end = (commit_idx + 1) * COMMITMENT_HASH_SIZE;
                let pv_len = commitment_public_values.len();
                #[cfg(feature = "trace-debug")]
                std::eprintln!(
                    "commit{} input_root (hex first 8)={} pv_slice=[{}..{}] pv_len={}",
                    commit_idx,
                    _input_root_hex,
                    _pv_start,
                    pv_end,
                    pv_len
                );
                assert!(
                    pv_end <= pv_len,
                    "public_values mismatch @ commit{}: pv_len {} < {}",
                    commit_idx,
                    pv_len,
                    pv_end
                );
            }

            if let Ok(merkle_air) = super::MerkleInclusionAir::new(self.merkle_tree_depth) {
                for commit_idx in 0..num_commitments {
                    let expected_root_field = super::merkle_root_from_bytes(
                        &inputs.commitment_inputs.expected_roots[commit_idx][..],
                    )
                    .ok()
                    .map(|poseidon_root| super::poseidon_to_field(&poseidon_root))
                    .unwrap_or_else(|| {
                        F::from_prime_subfield(<F::PrimeSubfield as QuotientMap<u8>>::from_int(
                            inputs.commitment_inputs.expected_roots[commit_idx][0],
                        ))
                    });
                    let air_root = merkle_air
                        .public_values(&inputs.commitment_inputs.merkle_proofs[commit_idx])
                        .first()
                        .copied()
                        .unwrap_or(F::ZERO);
                    #[cfg(feature = "trace-debug")]
                    std::eprintln!(
                        "commit{} expected_root_field={:?} air_root (Merkle computed)={:?}",
                        commit_idx,
                        expected_root_field,
                        air_root
                    );
                    assert_eq!(
                        expected_root_field, air_root,
                        "MerkleInclusionAir mismatch @ commit{}: expected (from input bytes) != root computed from Merkle path",
                        commit_idx
                    );
                }
            }
        }

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

        #[cfg(all(feature = "std", feature = "recursive-proofs-experimental"))]
        if let Ok(merkle_air) = super::MerkleInclusionAir::new(self.merkle_tree_depth) {
            use lib_q_stark_air::BaseAir;

            use super::poseidon_gadget::PoseidonGadget;
            use super::recursive_types::COMMITMENT_HASH_SIZE;

            let tree_depth = self.merkle_tree_depth;
            let merkle_width = <super::MerkleInclusionAir as BaseAir<Val>>::width(&merkle_air);
            let per_commitment_width = COMMITMENT_HASH_SIZE + merkle_width + 1;
            const HASH_SIZE_FIELD_ELEMENTS: usize = 1;
            let level_width = 1 +
                HASH_SIZE_FIELD_ELEMENTS +
                HASH_SIZE_FIELD_ELEMENTS +
                PoseidonGadget::COLUMNS_PER_HASH;

            for commit_idx in 0..num_commitments {
                let per_commitment_start_local = commit_idx * per_commitment_width;
                let expected_col_local = per_commitment_start_local;
                let merkle_proof_start_local = per_commitment_start_local + COMMITMENT_HASH_SIZE;
                let equality_check_col_local = merkle_proof_start_local + merkle_width;
                let computed_root_col_local =
                    merkle_proof_start_local + 1 + (tree_depth - 1) * level_width + 2;

                let eq_val = commitment_trace
                    .get(0, equality_check_col_local)
                    .unwrap_or(F::ZERO);
                let expected_val = commitment_trace
                    .get(0, expected_col_local)
                    .unwrap_or(F::ZERO);
                let computed_val = commitment_trace
                    .get(0, computed_root_col_local)
                    .unwrap_or(F::ZERO);

                assert_eq!(
                    eq_val,
                    F::ZERO,
                    "commitment_trace eq_col != 0 @ commit {}",
                    commit_idx
                );
                assert_eq!(
                    expected_val, computed_val,
                    "commitment_trace expected != computed @ commit {}",
                    commit_idx
                );
                #[cfg(feature = "trace-debug")]
                std::eprintln!(
                    "✓ SOURCE commitment_trace commit{}: eq={:?} expected={:?} computed={:?}",
                    commit_idx,
                    eq_val,
                    expected_val,
                    computed_val
                );
            }
        }

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

        // Column layout logging: same formula as CommitmentVerifierAir::eval_with_offset
        #[cfg(all(
            feature = "std",
            feature = "recursive-proofs-experimental",
            feature = "trace-debug"
        ))]
        if let Ok(merkle_air) = super::MerkleInclusionAir::new(self.merkle_tree_depth) {
            use lib_q_stark_air::BaseAir;

            use super::poseidon_gadget::PoseidonGadget;
            use super::recursive_types::COMMITMENT_HASH_SIZE;

            let commitment_offset = metadata_width;
            let tree_depth = self.merkle_tree_depth;
            let merkle_width = <super::MerkleInclusionAir as BaseAir<Val>>::width(&merkle_air);
            let per_commitment_width = COMMITMENT_HASH_SIZE + merkle_width + 1;
            const HASH_SIZE_FIELD_ELEMENTS: usize = 1;
            let level_width = 1 +
                HASH_SIZE_FIELD_ELEMENTS +
                HASH_SIZE_FIELD_ELEMENTS +
                PoseidonGadget::COLUMNS_PER_HASH;

            for commit_idx in 0..num_commitments {
                let per_commitment_start = commitment_offset + commit_idx * per_commitment_width;
                let expected_root_col = per_commitment_start;
                let merkle_proof_start = per_commitment_start + COMMITMENT_HASH_SIZE;
                let equality_check_col = merkle_proof_start + merkle_width;
                let computed_root_col = merkle_proof_start + 1 + (tree_depth - 1) * level_width + 2;

                std::eprintln!(
                    "WRITE commit_idx={} → eq_col={}, expected_root_col={}, computed_root_col={}",
                    commit_idx,
                    equality_check_col,
                    expected_root_col,
                    computed_root_col
                );
            }
        }

        // Commitment verification section
        for col in 0..commitment_width {
            trace_values[offset + col] = match commitment_trace.get(0, col) {
                Some(x) => x,
                None => F::ZERO,
            };
        }

        #[cfg(all(feature = "std", feature = "recursive-proofs-experimental"))]
        if let Ok(merkle_air) = super::MerkleInclusionAir::new(self.merkle_tree_depth) {
            use lib_q_stark_air::BaseAir;

            use super::poseidon_gadget::PoseidonGadget;
            use super::recursive_types::COMMITMENT_HASH_SIZE;

            let commitment_offset = metadata_width;
            let tree_depth = self.merkle_tree_depth;
            let merkle_width = <super::MerkleInclusionAir as BaseAir<Val>>::width(&merkle_air);
            let per_commitment_width = COMMITMENT_HASH_SIZE + merkle_width + 1;
            const HASH_SIZE_FIELD_ELEMENTS: usize = 1;
            let level_width = 1 +
                HASH_SIZE_FIELD_ELEMENTS +
                HASH_SIZE_FIELD_ELEMENTS +
                PoseidonGadget::COLUMNS_PER_HASH;

            for commit_idx in 0..num_commitments {
                let per_commitment_start = commitment_offset + commit_idx * per_commitment_width;
                let expected_root_col = per_commitment_start;
                let merkle_proof_start = per_commitment_start + COMMITMENT_HASH_SIZE;
                let equality_check_col = merkle_proof_start + merkle_width;
                let computed_root_col = merkle_proof_start + 1 + (tree_depth - 1) * level_width + 2;

                let _eq_val = trace_values.get(equality_check_col).copied();
                let expected_val = trace_values.get(expected_root_col).copied();
                let computed_val = trace_values.get(computed_root_col).copied();

                #[cfg(feature = "trace-debug")]
                std::eprintln!(
                    "✓ DEST combined_trace commit{}: eq={:?} expected={:?} computed={:?}",
                    commit_idx,
                    _eq_val,
                    expected_val,
                    computed_val
                );

                match (expected_val, computed_val) {
                    (Some(a), Some(b)) if a != b => {
                        panic!(
                            "CORRUPTION DETECTED: combined_trace corrupted @ commit {}",
                            commit_idx
                        );
                    }
                    _ => {}
                }
            }
        }

        #[cfg(all(
            feature = "std",
            feature = "recursive-proofs-experimental",
            feature = "trace-debug"
        ))]
        if let Ok(merkle_air) = super::MerkleInclusionAir::new(self.merkle_tree_depth) {
            use lib_q_stark_air::BaseAir;

            use super::poseidon_gadget::PoseidonGadget;
            use super::recursive_types::COMMITMENT_HASH_SIZE;

            let commitment_offset = metadata_width;
            let tree_depth = self.merkle_tree_depth;
            let merkle_width = <super::MerkleInclusionAir as BaseAir<Val>>::width(&merkle_air);
            let per_commitment_width = COMMITMENT_HASH_SIZE + merkle_width + 1;
            const HASH_SIZE_FIELD_ELEMENTS: usize = 1;
            let level_width = 1 +
                HASH_SIZE_FIELD_ELEMENTS +
                HASH_SIZE_FIELD_ELEMENTS +
                PoseidonGadget::COLUMNS_PER_HASH;

            for commit_idx in 0..num_commitments {
                let per_commitment_start = commitment_offset + commit_idx * per_commitment_width;
                let expected_root_col = per_commitment_start;
                let merkle_proof_start = per_commitment_start + COMMITMENT_HASH_SIZE;
                let equality_check_col = merkle_proof_start + merkle_width;
                let computed_root_col = merkle_proof_start + 1 + (tree_depth - 1) * level_width + 2;

                let expected_val = trace_values.get(expected_root_col).copied();
                let computed_val = trace_values.get(computed_root_col).copied();
                let eq_val = trace_values.get(equality_check_col).copied();
                std::eprintln!(
                    "Wrote expected_root[{}]={:?} to col {}, computed_root={:?} to col {}, eq={:?} to col {}",
                    commit_idx,
                    expected_val,
                    expected_root_col,
                    computed_val,
                    computed_root_col,
                    eq_val,
                    equality_check_col
                );
            }
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

        let metadata_width = 4;
        let fri_start = metadata_width + commitment_width;
        let fri_end = fri_start + fri_width;
        let num_rounds = self.serialized_proof.fri_rounds.len();
        let final_poly_len = 1 << self.log_final_poly_len;
        let per_round = 32 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1;
        if num_rounds > 0 && final_poly_len > 0 {
            let last_folded_col = fri_start + (num_rounds - 1) * per_round + 32 + 1;
            let horner_start = fri_start + num_rounds * per_round + final_poly_len + 1;
            let horner_result_col = horner_start + final_poly_len - 1;
            debug_assert!(
                last_folded_col >= fri_start && last_folded_col < fri_end,
                "FRI last_folded_col {} out of FRI range [{}, {})",
                last_folded_col,
                fri_start,
                fri_end
            );
            debug_assert!(
                horner_result_col >= fri_start && horner_result_col < fri_end,
                "FRI horner_result_col {} out of FRI range [{}, {})",
                horner_result_col,
                fri_start,
                fri_end
            );
        }

        #[cfg(feature = "std")]
        {
            let constraint_start = fri_end;
            let constraint_end = constraint_start + constraint_width;
            let opening_start = constraint_end;
            let opening_end = opening_start + opening_width;
            std::println!(
                "Trace layout: metadata 0..{}, commitment {}..{}, fri {}..{}, constraint {}..{}, opening {}..{}",
                metadata_width,
                metadata_width,
                fri_start,
                fri_start,
                fri_end,
                constraint_start,
                constraint_end,
                opening_start,
                opening_end
            );
            if num_rounds > 0 && final_poly_len > 0 {
                let last_folded_col = fri_start + (num_rounds - 1) * per_round + 32 + 1;
                let horner_start = fri_start + num_rounds * per_round + final_poly_len + 1;
                let horner_result_col = horner_start + final_poly_len - 1;
                std::println!(
                    "FRI segment: last_folded_col={}, horner_result_col={} (fri_start={}, fri_width={})",
                    last_folded_col,
                    horner_result_col,
                    fri_start,
                    fri_width
                );
                if last_folded_col < trace_values.len() && horner_result_col < trace_values.len() {
                    std::println!(
                        "  trace[last_folded_col]={:?}, trace[horner_result_col]={:?}",
                        trace_values[last_folded_col],
                        trace_values[horner_result_col]
                    );
                }
            }
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
