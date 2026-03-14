//! Proof aggregation — recursive STARK over one or all proofs
//!
//! This module provides:
//! - **`aggregate_single`**: Takes N STARK proofs, verifies all N with the standard verifier,
//!   then produces a recursive STARK proof that attests only to proof\[0\]. The Merkle root
//!   over all N serialized proofs is included for binding.
//! - **`aggregate`**: Uses `BatchStarkVerifierAir` to produce a single recursive STARK proof
//!   that attests to all N inner proofs. All N are verified with the standard verifier first.

extern crate alloc;

#[cfg(feature = "recursive-proofs-experimental")]
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use lib_q_core::Result;
use lib_q_stark::{
    Proof as StarkProof,
    StarkGenericConfig,
    SymbolicAirBuilder,
    Val,
};
use lib_q_stark_air::Air;
use lib_q_stark_mersenne31::Mersenne31;

#[cfg(feature = "recursive-proofs-experimental")]
use crate::air::TraceGenerator;
#[cfg(feature = "recursive-proofs-experimental")]
use crate::air::batch_stark_verifier::{
    BatchRecursiveStarkVerificationInput,
    BatchStarkVerifierAir,
};
use crate::air::recursive_types::{
    SerializedStarkProof,
    serialize_stark_proof,
};
use crate::air::stark_verifier::StarkVerifierAir;
#[cfg(feature = "recursive-proofs-experimental")]
use crate::air::stark_verifier::{
    FriProofInputProofExtractor,
    MerklePathExtractable,
    build_recursive_verification_input,
    build_recursive_verification_input_from_proof,
    build_recursive_verification_input_from_proof_with_poseidon,
};
#[cfg(feature = "recursive-proofs-experimental")]
use crate::stark::FriQueryParams;
#[cfg(feature = "recursive-proofs-experimental")]
use crate::stark::StarkProver;
use crate::stark::StarkVerifier;

/// When `recursive-proofs-experimental` is enabled, builds recursive verification input using
/// real Merkle siblings from the proof (Poseidon path). Requires Proof to implement
/// FriProofInputProofExtractor and CommitPhaseStep to implement MerklePathExtractable.
#[cfg(feature = "recursive-proofs-experimental")]
fn build_recursive_input_with_poseidon<C, A>(
    verifier: &StarkVerifier<C>,
    air: &A,
    proof: &StarkProof<C>,
    public_values: &[Val<C>],
    serialized_proof: &SerializedStarkProof<Val<C>, Val<C>>,
    merkle_tree_depth: usize,
    fri_params: &FriQueryParams,
) -> core::result::Result<
    crate::air::RecursiveStarkVerificationInput<Val<C>, Val<C>>,
    crate::air::AirError,
>
where
    C: StarkGenericConfig,
    Val<C>: lib_q_stark_field::Field
        + serde::Serialize
        + serde::de::DeserializeOwned
        + lib_q_stark_field::BasedVectorSpace<Mersenne31>
        + lib_q_stark_field::TwoAdicField
        + From<C::Challenge>,
    A: Air<SymbolicAirBuilder<Val<C>>>
        + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
    C::Challenger: lib_q_stark_challenger::CanObserve<Val<C>>
        + lib_q_stark_challenger::CanObserve<
            <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Commitment,
        >
        + lib_q_stark_challenger::CanObserve<
            <<C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof
                as lib_q_stark_fri::FriDataExtractor>::Commitment,
        >
        + lib_q_stark_challenger::GrindingChallenger<
            Witness = <<C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof
                as lib_q_stark_fri::FriDataExtractor>::Witness,
        >,
    <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof:
        lib_q_stark_fri::FriDataExtractor<Challenge = C::Challenge> + FriProofInputProofExtractor,
    <<C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof
        as lib_q_stark_fri::FriDataExtractor>::CommitPhaseStep: MerklePathExtractable
        + lib_q_stark_fri::SiblingValueRef<Challenge = Val<C>>,
    <<C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof
        as lib_q_stark_fri::FriDataExtractor>::Witness: Clone,
    <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Commitment:
        crate::air::PoseidonCommitmentRoot,
    C::Pcs: lib_q_stark_fri::FriInitialEval<
            C::Challenge,
            Proof = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof,
            Error = lib_q_stark::PcsError<C>,
            Commitment = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Commitment,
            Domain = lib_q_stark::Domain<C>,
        > + lib_q_stark_fri::FriReducedOpenings<
            C::Challenge,
            Proof = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof,
            Error = lib_q_stark::PcsError<C>,
            Commitment = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Commitment,
            Domain = lib_q_stark::Domain<C>,
        >,
{
    build_recursive_verification_input_from_proof_with_poseidon(
        verifier,
        air,
        proof,
        public_values,
        serialized_proof,
        merkle_tree_depth,
        fri_params,
    )
}

/// Sealed trait used to require Val<C> = C::Challenge at type-check time.
/// Only implemented for (T, T), so (Val<C>, C::Challenge): SameFieldOnly holds only when they are the same type.
#[doc(hidden)]
pub trait SameFieldOnly {}
impl<T> SameFieldOnly for (T, T) {}

/// Configuration for recursive proof aggregation
#[derive(Debug, Clone)]
pub struct AggregationConfig {
    /// Merkle tree depth for proof commitments
    pub merkle_tree_depth: usize,
    /// Log of final polynomial length for inner FRI
    pub log_final_poly_len: usize,
    /// Number of FRI queries for inner proofs
    pub num_fri_queries: usize,
    /// FRI log blowup (for derive_query_positions replay)
    pub fri_log_blowup: usize,
    /// FRI proof-of-work bits (for derive_query_positions replay)
    pub fri_proof_of_work_bits: usize,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            merkle_tree_depth: 8,
            log_final_poly_len: 0, // must match poseidon_config/default_config FRI parameters
            num_fri_queries: 100,
            fri_log_blowup: 2,
            fri_proof_of_work_bits: 16,
        }
    }
}

/// Result of aggregate_single
///
/// Contains a recursive STARK proof for the first inner proof only,
/// plus a Merkle root over all N serialized proofs and metadata.
///
/// Note: This struct doesn't derive Debug/Clone because StarkProof<C> doesn't
/// implement these traits (it contains generic commitment/PCS types).
pub struct AggregatedProof<C: StarkGenericConfig> {
    /// Recursive STARK proof attesting only to proof\[0\]
    pub proof: StarkProof<C>,
    /// Merkle root of inner proof commitments (for binding)
    pub proofs_root: [u8; 32],
    /// Number of proofs aggregated
    pub num_proofs: usize,
    /// First serialized proof and config used to reconstruct the outer AIR for verification
    pub first_serialized_proof: SerializedStarkProof<Val<C>, C::Challenge>,
    /// Aggregation configuration used during aggregation
    pub agg_config: AggregationConfig,
}

/// Builds an aggregated proof that recursively attests only to the first proof.
///
/// All N proofs are verified with the standard verifier before the recursive
/// step. The output recursive proof proves verification of proof\[0\] only.
pub struct ProofAggregator<C: StarkGenericConfig> {
    /// Inner proofs to aggregate
    proofs: Vec<StarkProof<C>>,
    /// STARK configuration (will be used in full recursive implementation)
    #[allow(dead_code)]
    config: C,
}

impl<C: StarkGenericConfig> ProofAggregator<C>
where
    C: Clone,
{
    /// Create a new ProofAggregator
    ///
    /// # Arguments
    ///
    /// * `proofs` - The proofs to aggregate
    /// * `config` - STARK configuration to use
    ///
    /// # Returns
    ///
    /// `Ok(ProofAggregator)` if successful, `Err` if invalid
    pub fn new(proofs: Vec<StarkProof<C>>, config: C) -> Result<Self> {
        if proofs.is_empty() {
            return Err(lib_q_core::Error::InvalidState {
                operation: "ProofAggregator::new".to_string(),
                reason: "Cannot aggregate empty proof list".to_string(),
            });
        }

        Ok(Self { proofs, config })
    }

    /// Produces a recursive STARK proof for the first proof only.
    ///
    /// All proofs are verified with the standard verifier first. The recursive
    /// proof then attests only to proof\[0\]. For a single proof attesting to all N,
    /// use [`aggregate`](Self::aggregate) instead (requires `recursive-proofs-experimental`).
    ///
    /// # Arguments
    ///
    /// * `verifier` - STARK verifier used to derive challenges for serialization
    /// * `air` - AIR shared by all proofs (all proofs must use the same AIR type)
    /// * `public_values_per_proof` - Public values for each proof; length must equal number of proofs
    /// * `agg_config` - Aggregation configuration
    ///
    /// # Returns
    ///
    /// An aggregated proof whose recursive component proves only verification of the first proof.
    #[cfg(feature = "recursive-proofs-experimental")]
    pub fn aggregate_single<A>(
        &self,
        verifier: &StarkVerifier<C>,
        air: &A,
        public_values_per_proof: &[Vec<Val<C>>],
        agg_config: AggregationConfig,
    ) -> Result<AggregatedProof<C>>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
        (Val<C>, C::Challenge): SameFieldOnly,
        C::Challenge: Into<Val<C>>,
        Val<C>: lib_q_stark_field::Field
            + lib_q_stark_field::BasedVectorSpace<Mersenne31>
            + lib_q_stark_field::TwoAdicField
            + From<C::Challenge>,
        StarkVerifierAir<Val<C>, Val<C>>: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::ProverConstraintFolder<'a, C>>,
        <<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof: lib_q_stark_fri::FriDataExtractor<Challenge = C::Challenge>,
        <<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof: FriProofInputProofExtractor,
        <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof as lib_q_stark_fri::FriDataExtractor>::CommitPhaseStep: MerklePathExtractable
            + lib_q_stark_fri::SiblingValueRef<Challenge = Val<C>>,
        <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof as lib_q_stark_fri::FriDataExtractor>::Commitment: serde::Serialize,
        <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof as lib_q_stark_fri::FriDataExtractor>::Witness: serde::Serialize + Clone,
        <C as StarkGenericConfig>::Challenger: lib_q_stark_challenger::CanObserve<
                <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
                    <C as StarkGenericConfig>::Challenge,
                    <C as StarkGenericConfig>::Challenger,
                >>::Proof as lib_q_stark_fri::FriDataExtractor>::Commitment,
            > + lib_q_stark_challenger::GrindingChallenger<
                Witness = <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
                    <C as StarkGenericConfig>::Challenge,
                    <C as StarkGenericConfig>::Challenger,
                >>::Proof as lib_q_stark_fri::FriDataExtractor>::Witness,
            >,
        <C as StarkGenericConfig>::Pcs: lib_q_stark_fri::FriInitialEval<
                <C as StarkGenericConfig>::Challenge,
                Proof = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof,
                Error = lib_q_stark::PcsError<C>,
                Commitment = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Commitment,
                Domain = lib_q_stark::Domain<C>,
            > + lib_q_stark_fri::FriReducedOpenings<
                <C as StarkGenericConfig>::Challenge,
                Proof = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Proof,
                Error = lib_q_stark::PcsError<C>,
                Commitment = <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Commitment,
                Domain = lib_q_stark::Domain<C>,
            >,
        <C::Pcs as lib_q_stark_commit::Pcs<C::Challenge, C::Challenger>>::Commitment:
            crate::air::PoseidonCommitmentRoot,
    {
        if public_values_per_proof.len() != self.proofs.len() {
            return Err(lib_q_core::Error::InvalidState {
                operation: "aggregate_single".to_string(),
                reason: format!(
                    "public_values_per_proof length {} must equal proofs length {}",
                    public_values_per_proof.len(),
                    self.proofs.len()
                ),
            });
        }

        // 1. Verify every proof before aggregating (reject invalid batches)
        for (proof, pv) in self.proofs.iter().zip(public_values_per_proof) {
            verifier
                .verify(air, proof, pv)
                .map_err(|e| lib_q_core::Error::InternalError {
                    operation: "aggregate_single".to_string(),
                    details: alloc::format!("inner proof verification failed: {:?}", e),
                })?;
        }

        // 2. Serialize all proofs with real challenges
        let serialized_proofs =
            self.serialize_all_proofs(verifier, air, public_values_per_proof)?;

        // 3. Create Merkle tree of commitments
        let proofs_root = self.compute_proofs_merkle_root(&serialized_proofs)?;

        if serialized_proofs.is_empty() {
            return Err(lib_q_core::Error::InvalidState {
                operation: "aggregate_single".to_string(),
                reason: "No proofs to aggregate".to_string(),
            });
        }

        // 4. Recursively prove verification of the first proof only (use aggregate() for all N)
        let first_serialized = serialized_proofs[0].clone();
        let first_serialized_unified: SerializedStarkProof<Val<C>, Val<C>> =
            first_serialized.clone().with_challenge_as_base();

        let recursive_air = StarkVerifierAir::new(
            first_serialized_unified.clone(),
            agg_config.merkle_tree_depth,
            agg_config.log_final_poly_len,
            agg_config.num_fri_queries,
        )
        .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
            operation: "aggregate_single".to_string(),
            details: e.to_string(),
        })?;

        let recursive_input = {
            #[cfg(feature = "recursive-proofs-experimental")]
            {
                let fri_params = FriQueryParams {
                    num_queries: agg_config.num_fri_queries,
                    log_blowup: agg_config.fri_log_blowup,
                    log_final_poly_len: agg_config.log_final_poly_len,
                    proof_of_work_bits: agg_config.fri_proof_of_work_bits,
                };
                build_recursive_input_with_poseidon(
                    verifier,
                    air,
                    &self.proofs[0],
                    &public_values_per_proof[0],
                    &first_serialized_unified,
                    agg_config.merkle_tree_depth,
                    &fri_params,
                )
            }
            #[cfg(not(feature = "recursive-proofs-experimental"))]
            {
                build_recursive_verification_input(
                    &first_serialized_unified,
                    agg_config.merkle_tree_depth,
                    agg_config.log_final_poly_len,
                    agg_config.num_fri_queries,
                )
            }
        }
        .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
            operation: "aggregate_single".to_string(),
            details: e.to_string(),
        })?;

        let trace =
            recursive_air
                .generate_trace(&recursive_input)
                .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
                    operation: "aggregate_single".to_string(),
                    details: e.to_string(),
                })?;

        let public_values = recursive_air.public_values(&recursive_input);

        let prover = StarkProver::new(self.config.clone());
        let proof = prover
            .prove(&recursive_air, trace, &public_values)
            .map_err(|e| lib_q_core::Error::InternalError {
                operation: "STARK proof generation".to_string(),
                details: e.to_string(),
            })?;

        Ok(AggregatedProof {
            proof,
            proofs_root,
            num_proofs: self.proofs.len(),
            first_serialized_proof: first_serialized,
            agg_config,
        })
    }

    /// Produces a single recursive STARK proof attesting to all N inner proofs.
    /// Uses BatchStarkVerifierAir; requires the same bounds as `aggregate_single`.
    #[cfg(feature = "recursive-proofs-experimental")]
    pub fn aggregate<A>(
        &self,
        verifier: &StarkVerifier<C>,
        air: &A,
        public_values_per_proof: &[Vec<Val<C>>],
        agg_config: AggregationConfig,
    ) -> Result<AggregatedProof<C>>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
        (Val<C>, C::Challenge): SameFieldOnly,
        C::Challenge: Into<Val<C>>,
        Val<C>: lib_q_stark_field::Field
            + lib_q_stark_field::BasedVectorSpace<Mersenne31>
            + From<lib_q_poseidon::PoseidonField>
            + Into<lib_q_poseidon::PoseidonField>,
        StarkVerifierAir<Val<C>, Val<C>>: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::ProverConstraintFolder<'a, C>>,
        <<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof: lib_q_stark_fri::FriDataExtractor<Challenge = C::Challenge>,
        <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof as lib_q_stark_fri::FriDataExtractor>::Commitment: serde::Serialize,
        <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof as lib_q_stark_fri::FriDataExtractor>::Witness: serde::Serialize + Clone,
        <C as StarkGenericConfig>::Challenger: lib_q_stark_challenger::CanObserve<
                <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
                    <C as StarkGenericConfig>::Challenge,
                    <C as StarkGenericConfig>::Challenger,
                >>::Proof as lib_q_stark_fri::FriDataExtractor>::Commitment,
            > + lib_q_stark_challenger::GrindingChallenger<
                Witness = <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
                    <C as StarkGenericConfig>::Challenge,
                    <C as StarkGenericConfig>::Challenger,
                >>::Proof as lib_q_stark_fri::FriDataExtractor>::Witness,
            >,
    {
        if public_values_per_proof.len() != self.proofs.len() {
            return Err(lib_q_core::Error::InvalidState {
                operation: "aggregate".to_string(),
                reason: format!(
                    "public_values_per_proof length {} must equal proofs length {}",
                    public_values_per_proof.len(),
                    self.proofs.len()
                ),
            });
        }

        for (proof, pv) in self.proofs.iter().zip(public_values_per_proof) {
            verifier
                .verify(air, proof, pv)
                .map_err(|e| lib_q_core::Error::InternalError {
                    operation: "aggregate".to_string(),
                    details: alloc::format!("inner proof verification failed: {:?}", e),
                })?;
        }

        let serialized_proofs =
            self.serialize_all_proofs(verifier, air, public_values_per_proof)?;
        let proofs_root = self.compute_proofs_merkle_root(&serialized_proofs)?;

        if serialized_proofs.is_empty() {
            return Err(lib_q_core::Error::InvalidState {
                operation: "aggregate".to_string(),
                reason: "No proofs to aggregate".to_string(),
            });
        }

        let serialized_unified: Vec<SerializedStarkProof<Val<C>, Val<C>>> = serialized_proofs
            .iter()
            .map(|p| p.clone().with_challenge_as_base())
            .collect();

        let batch_air = BatchStarkVerifierAir::new(
            serialized_unified.clone(),
            agg_config.merkle_tree_depth,
            agg_config.log_final_poly_len,
            agg_config.num_fri_queries,
        )
        .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
            operation: "aggregate".to_string(),
            details: e.to_string(),
        })?;

        let mut batch_inputs: BatchRecursiveStarkVerificationInput<Val<C>, Val<C>> =
            Vec::with_capacity(self.proofs.len());
        for (proof, pv) in self.proofs.iter().zip(public_values_per_proof) {
            let serialized = serialized_proofs
                .get(batch_inputs.len())
                .ok_or_else(|| lib_q_core::Error::InvalidState {
                    operation: "aggregate".to_string(),
                    reason: "proof index out of range".to_string(),
                })?
                .clone()
                .with_challenge_as_base();
            let fri_params = FriQueryParams {
                num_queries: agg_config.num_fri_queries,
                log_blowup: agg_config.fri_log_blowup,
                log_final_poly_len: agg_config.log_final_poly_len,
                proof_of_work_bits: agg_config.fri_proof_of_work_bits,
            };
            let recursive_input = build_recursive_verification_input_from_proof(
                verifier,
                air,
                proof,
                pv,
                &serialized,
                agg_config.merkle_tree_depth,
                &fri_params,
            )
            .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
                operation: "aggregate".to_string(),
                details: e.to_string(),
            })?;
            batch_inputs.push(recursive_input);
        }

        let trace =
            batch_air
                .generate_trace(&batch_inputs)
                .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
                    operation: "aggregate".to_string(),
                    details: e.to_string(),
                })?;

        let public_values = batch_air.public_values(&batch_inputs);

        let prover = StarkProver::new(self.config.clone());
        let proof = prover
            .prove(&batch_air, trace, &public_values)
            .map_err(|e| lib_q_core::Error::InternalError {
                operation: "STARK proof generation".to_string(),
                details: e.to_string(),
            })?;

        Ok(AggregatedProof {
            proof,
            proofs_root,
            num_proofs: self.proofs.len(),
            first_serialized_proof: serialized_proofs[0].clone(),
            agg_config,
        })
    }

    /// Serialize all proofs for aggregation using real challenges from verifier replay
    #[allow(dead_code)]
    fn serialize_all_proofs<A>(
        &self,
        verifier: &StarkVerifier<C>,
        air: &A,
        public_values_per_proof: &[Vec<Val<C>>],
    ) -> Result<Vec<SerializedStarkProof<Val<C>, C::Challenge>>>
    where
        A: Air<SymbolicAirBuilder<Val<C>>>
            + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
        <<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof: lib_q_stark_fri::FriDataExtractor<Challenge = C::Challenge>,
        <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof as lib_q_stark_fri::FriDataExtractor>::Commitment: serde::Serialize,
        <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
            <C as StarkGenericConfig>::Challenge,
            <C as StarkGenericConfig>::Challenger,
        >>::Proof as lib_q_stark_fri::FriDataExtractor>::Witness: serde::Serialize,
        <C as StarkGenericConfig>::Challenger: lib_q_stark_challenger::CanObserve<
                <<<C as StarkGenericConfig>::Pcs as lib_q_stark_commit::Pcs<
                    <C as StarkGenericConfig>::Challenge,
                    <C as StarkGenericConfig>::Challenger,
                >>::Proof as lib_q_stark_fri::FriDataExtractor>::Commitment,
            >,
    {
        let mut serialized = Vec::new();

        for (proof, expected_public_values) in self.proofs.iter().zip(public_values_per_proof) {
            let (zeta, zeta_next, alpha, betas) = verifier
                .derive_challenges(air, proof, expected_public_values)
                .map_err(|e| lib_q_core::Error::InternalError {
                    operation: "serialize_all_proofs".to_string(),
                    details: alloc::format!("{:?}", e),
                })?;

            let serialized_proof = serialize_stark_proof(
                proof,
                expected_public_values.clone(),
                zeta,
                zeta_next,
                alpha,
                &betas,
            )
            .map_err(|e| lib_q_core::Error::InternalError {
                operation: "serialize_all_proofs".to_string(),
                details: e,
            })?;

            serialized.push(serialized_proof);
        }

        Ok(serialized)
    }

    /// Compute Merkle root of proof commitment hashes
    #[allow(dead_code)]
    fn compute_proofs_merkle_root(
        &self,
        serialized_proofs: &[SerializedStarkProof<Val<C>, C::Challenge>],
    ) -> Result<[u8; 32]> {
        use lib_q_sha3::Shake256;
        use lib_q_sha3::digest::{
            ExtendableOutput,
            Update,
            XofReader,
        };

        // For now, hash all commitment hashes together
        // A full implementation would build a proper Merkle tree
        let mut hasher = Shake256::default();

        for proof in serialized_proofs {
            hasher.update(&proof.trace_commitment_hash);
            hasher.update(&proof.quotient_commitment_hash);
            if let Some(ref random_hash) = proof.random_commitment_hash {
                hasher.update(random_hash);
            }
        }

        let mut reader = hasher.finalize_xof();
        let mut root = [0u8; 32];
        reader.read(&mut root);

        Ok(root)
    }

    /// Get the number of proofs being aggregated
    pub fn num_proofs(&self) -> usize {
        self.proofs.len()
    }
}

/// Verify an aggregated proof
///
/// This verifies that an aggregated proof correctly verifies all inner proofs.
/// Requires the `recursive-proofs-experimental` feature; otherwise returns `Err`.
///
/// # Arguments
///
/// * `aggregated` - The aggregated proof to verify
/// * `_agg_config` - Aggregation configuration (use aggregated.agg_config when calling)
/// * `stark_config` - STARK configuration
///
/// # Returns
///
/// `Ok(true)` if the aggregated proof is valid, `Ok(false)` or `Err` otherwise
#[cfg(not(feature = "recursive-proofs-experimental"))]
pub fn verify_aggregated_proof<C: StarkGenericConfig + Clone>(
    _aggregated: &AggregatedProof<C>,
    _agg_config: AggregationConfig,
    _stark_config: C,
) -> Result<bool>
where
    (Val<C>, C::Challenge): SameFieldOnly,
    C::Challenge: Into<Val<C>> + serde::Serialize,
    Val<C>: lib_q_stark_field::Field
        + lib_q_stark_field::BasedVectorSpace<Mersenne31>
        + serde::Serialize,
    StarkVerifierAir<Val<C>, Val<C>>:
        Air<SymbolicAirBuilder<Val<C>>> + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
{
    Err(crate::air::AirError::NotSupported {
        reason:
            "Recursive proof verification requires the `recursive-proofs-experimental` feature."
                .into(),
    }
    .into())
}

#[cfg(feature = "recursive-proofs-experimental")]
pub fn verify_aggregated_proof<C: StarkGenericConfig + Clone>(
    aggregated: &AggregatedProof<C>,
    _agg_config: AggregationConfig,
    stark_config: C,
) -> Result<bool>
where
    (Val<C>, C::Challenge): SameFieldOnly,
    C::Challenge: Into<Val<C>> + serde::Serialize,
    Val<C>: lib_q_stark_field::Field
        + lib_q_stark_field::BasedVectorSpace<Mersenne31>
        + serde::Serialize,
    StarkVerifierAir<Val<C>, Val<C>>:
        Air<SymbolicAirBuilder<Val<C>>> + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
{
    let first_serialized_unified: SerializedStarkProof<Val<C>, Val<C>> = aggregated
        .first_serialized_proof
        .clone()
        .with_challenge_as_base();

    let recursive_air = StarkVerifierAir::new(
        first_serialized_unified.clone(),
        aggregated.agg_config.merkle_tree_depth,
        aggregated.agg_config.log_final_poly_len,
        aggregated.agg_config.num_fri_queries,
    )
    .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
        operation: "verify_aggregated_proof".to_string(),
        details: e.to_string(),
    })?;

    let recursive_input = build_recursive_verification_input(
        &first_serialized_unified,
        aggregated.agg_config.merkle_tree_depth,
        aggregated.agg_config.log_final_poly_len,
        aggregated.agg_config.num_fri_queries,
    )
    .map_err(|e: crate::air::AirError| lib_q_core::Error::InternalError {
        operation: "verify_aggregated_proof".to_string(),
        details: e.to_string(),
    })?;

    let public_values = recursive_air.public_values(&recursive_input);
    let verifier = StarkVerifier::new(stark_config);

    verifier
        .verify(&recursive_air, &aggregated.proof, &public_values)
        .map(|()| true)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "verify_aggregated_proof".to_string(),
            details: alloc::format!("{:?}", e),
        })
}

/// Verify all proofs in a batch using the standard STARK verifier.
///
/// Does not produce a recursive proof. Use `aggregate_single` or `aggregate`
/// if a proof of the batch is required.
///
/// # Errors
///
/// Returns the first verification failure if any proof is invalid.
pub fn verify_batch<C, A>(
    proofs: &[StarkProof<C>],
    verifier: &StarkVerifier<C>,
    air: &A,
    public_values_per_proof: &[Vec<Val<C>>],
) -> Result<()>
where
    C: StarkGenericConfig,
    A: Air<SymbolicAirBuilder<Val<C>>> + for<'a> Air<lib_q_stark::VerifierConstraintFolder<'a, C>>,
{
    if public_values_per_proof.len() != proofs.len() {
        return Err(lib_q_core::Error::InvalidState {
            operation: "verify_batch".to_string(),
            reason: alloc::format!(
                "public_values_per_proof length {} must equal proofs length {}",
                public_values_per_proof.len(),
                proofs.len()
            ),
        });
    }
    for (i, (proof, pv)) in proofs.iter().zip(public_values_per_proof).enumerate() {
        verifier
            .verify(air, proof, pv)
            .map_err(|e| lib_q_core::Error::InternalError {
                operation: "verify_batch".to_string(),
                details: alloc::format!("proof {} verification failed: {:?}", i, e),
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregation_config_default() {
        let config = AggregationConfig::default();
        assert_eq!(config.merkle_tree_depth, 8);
        assert_eq!(config.log_final_poly_len, 0);
        assert_eq!(config.num_fri_queries, 100);
        assert_eq!(config.fri_log_blowup, 2);
        assert_eq!(config.fri_proof_of_work_bits, 16);
    }
}
