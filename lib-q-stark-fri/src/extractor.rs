//! FRI proof data extraction for recursive verification
//!
//! This module provides a trait to extract FRI proof data (commit phase commitments,
//! final polynomial, PoW witness) from a generic PCS proof so that recursive STARK
//! verification can serialize and verify inner FRI proofs without downcasting.

use lib_q_stark_commit::Mmcs;
use lib_q_stark_field::Field;

/// Extracts FRI-specific data from a proof for recursive verification.
///
/// Implemented by the concrete `FriProof` type. Callers (e.g. lib-q-zkp) use this
/// to build `SerializedStarkProof` and to replay the FRI challenger for betas.
pub trait FriDataExtractor {
    /// Challenge field (extension field used in FRI)
    type Challenge: Field;
    /// Commitment type for commit phase (hashed by caller for serialization)
    type Commitment: Clone;
    /// Proof-of-work witness type (serialized by caller for storage)
    type Witness;
    /// One query proof (commit-phase openings per round). Used for Merkle path extraction.
    type QueryProofData;
    /// One commit-phase proof step (sibling value + opening proof). Used for Merkle path extraction.
    type CommitPhaseStep;

    /// Commit phase commitments (one per fold round). Caller hashes these for storage.
    fn commit_phase_commits(&self) -> &[Self::Commitment];

    /// Final low-degree polynomial coefficients
    fn final_poly(&self) -> &[Self::Challenge];

    /// Proof-of-work witness (caller serializes for storage, e.g. via postcard)
    fn pow_witness(&self) -> &Self::Witness;

    /// Number of FRI query proofs (for validation)
    fn query_proofs_len(&self) -> usize;

    /// Raw query proofs (one per query). Exposes Merkle siblings for each commit-phase round.
    /// Only sound for recursive verification when the commitment scheme uses Poseidon hashing
    /// so that siblings are compatible with MerkleInclusionAir.
    fn query_proofs_raw(&self) -> &[Self::QueryProofData];

    /// Commit-phase Merkle proof for a specific query. Returns the slice of proof steps
    /// (one per FRI round) for that query, or `None` if `query_idx >= query_proofs_len()`.
    fn commit_phase_openings(&self, query_idx: usize) -> Option<&[Self::CommitPhaseStep]>;
}

use crate::proof::{
    CommitPhaseProofStep,
    FriProof,
    QueryProof,
};

impl<F: Field, M: Mmcs<F>, Witness, InputProof> FriDataExtractor
    for FriProof<F, M, Witness, InputProof>
{
    type Challenge = F;
    type Commitment = M::Commitment;
    type Witness = Witness;
    type QueryProofData = QueryProof<F, M, InputProof>;
    type CommitPhaseStep = CommitPhaseProofStep<F, M>;

    fn commit_phase_commits(&self) -> &[M::Commitment] {
        &self.commit_phase_commits
    }

    fn final_poly(&self) -> &[F] {
        &self.final_poly
    }

    fn pow_witness(&self) -> &Witness {
        &self.pow_witness
    }

    fn query_proofs_len(&self) -> usize {
        self.query_proofs.len()
    }

    fn query_proofs_raw(&self) -> &[QueryProof<F, M, InputProof>] {
        &self.query_proofs
    }

    fn commit_phase_openings(&self, query_idx: usize) -> Option<&[CommitPhaseProofStep<F, M>]> {
        self.query_proofs
            .get(query_idx)
            .map(|q| q.commit_phase_openings.as_slice())
    }
}
