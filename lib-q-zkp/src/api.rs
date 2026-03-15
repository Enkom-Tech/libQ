//! High-level lib-Q API for zero-knowledge proofs
//!
//! This module provides easy-to-use functions for common ZKP operations,
//! following lib-Q's design principles: simple functions for common problems,
//! secure by default, and consistent naming while allowing advanced users
//! to access lower-level APIs.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use lib_q_core::Result;

use crate::{
    ZkpProof,
    ZkpProver,
    ZkpVerifier,
};

/// Merkle path for inclusion proofs
#[derive(Debug, Clone)]
pub struct MerklePath {
    /// Direction bits for each level (false = left, true = right)
    pub path_bits: Vec<bool>,
    /// Sibling hashes at each level (already computed hashes, not raw data)
    pub siblings: Vec<crate::air::merkle_inclusion::MerkleHash>,
}

/// Build a Poseidon Merkle tree from leaf data.
///
/// The tree uses the same hashing as `MerkleInclusionAir`. Use `tree.path(index)`
/// to get `(path_bits, siblings)` and construct `MerklePath { path_bits, siblings }`
/// for `prove_membership`. Use `tree.root_bytes()` for `verify_membership`.
///
/// # Errors
///
/// Returns error if `leaves` is empty or padded size exceeds 2^64.
pub fn build_merkle_tree(leaves: &[&[u8]]) -> Result<crate::merkle::PoseidonMerkleTree> {
    crate::merkle::PoseidonMerkleTree::from_leaves(leaves)
}

/// Build a MerklePath for a leaf index from a built tree.
///
/// Convenience for `prove_membership(leaves[leaf_index], &path)`.
pub fn merkle_path_from_tree(
    tree: &crate::merkle::PoseidonMerkleTree,
    leaf_index: usize,
) -> Result<MerklePath> {
    let (path_bits, siblings) = tree.path(leaf_index)?;
    Ok(MerklePath {
        path_bits,
        siblings,
    })
}

/// Prove membership in a Merkle tree
///
/// This is a high-level function that proves a leaf value is included
/// in a Merkle tree with a given root hash.
///
/// # Arguments
///
/// * `leaf` - The leaf value to prove membership of
/// * `path` - The Merkle authentication path
///
/// # Returns
///
/// A zero-knowledge proof of membership with embedded tree depth metadata.
/// The proof is self-describing and can be verified without knowing the
/// tree depth in advance.
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::api::{prove_membership, MerklePath};
///
/// use lib_q_zkp::air::merkle_inclusion::MerkleHash;
///
/// let leaf = b"my leaf data";
/// let path = MerklePath {
///     path_bits: vec![false, true, false],
///     siblings: vec![
///         MerkleHash::from_bytes(&[0u8; 32])?,
///         MerkleHash::from_bytes(&[0u8; 32])?,
///         MerkleHash::from_bytes(&[0u8; 32])?,
///     ],
/// };
///
/// let proof = prove_membership(leaf, &path)?;
/// // Tree depth (3) is stored in proof.metadata
/// ```
pub fn prove_membership(leaf: &[u8], path: &MerklePath) -> Result<ZkpProof> {
    use crate::ProofMetadata;
    use crate::air::{
        MerkleInclusionAir,
        MerkleProofInput,
        TraceGenerator,
    };
    use crate::stark::{
        StarkProver,
        default_config,
    };

    if path.path_bits.len() > 64 {
        return Err(lib_q_core::Error::InvalidState {
            operation: "prove_membership".into(),
            reason: "Tree depth exceeds maximum of 64".into(),
        });
    }

    let tree_depth = path.path_bits.len();
    let air =
        MerkleInclusionAir::new(tree_depth).map_err(|e| lib_q_core::Error::InternalError {
            operation: "prove_membership".into(),
            details: e.to_string(),
        })?;

    let input = MerkleProofInput {
        leaf: leaf.to_vec(),
        leaf_hash_direct: None,
        path_bits: path.path_bits.clone(),
        siblings: path.siblings.clone(),
    };

    let trace = air
        .generate_trace(&input)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "prove_membership".into(),
            details: e.to_string(),
        })?;

    let public_values = air.public_values(&input);

    let config = default_config();
    let prover = StarkProver::new(config);
    let proof = prover.prove(&air, trace, &public_values).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "STARK proof generation".to_string(),
            details: e.to_string(),
        }
    })?;

    // Store tree depth in proof metadata for self-describing verification
    let metadata = ProofMetadata::MerkleInclusion {
        tree_depth: tree_depth as u8,
    };

    ZkpProof::from_stark_proof(&proof, metadata)
}

/// Verify membership in a Merkle tree with explicit tree depth
///
/// This is the recommended verification function when the tree depth is known.
/// It provides O(1) verification and prevents potential depth confusion attacks.
///
/// # Arguments
///
/// * `proof` - The proof to verify
/// * `root` - The expected Merkle root hash (bytes)
/// * `expected_tree_depth` - The expected tree depth (must match proof)
///
/// # Returns
///
/// `Ok(true)` if the proof is valid and tree depth matches, `Ok(false)` otherwise
///
/// # Security
///
/// Using explicit tree depth verification prevents depth confusion attacks where
/// a malicious prover might craft proofs that validate at unexpected depths.
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::api::verify_membership_with_depth;
///
/// let root = b"expected root hash";
/// let expected_depth = 4; // Known tree depth
/// let is_valid = verify_membership_with_depth(&proof, root, expected_depth)?;
/// ```
pub fn verify_membership_with_depth(
    proof: &ZkpProof,
    root: &[u8],
    expected_tree_depth: usize,
) -> Result<bool> {
    use crate::ProofMetadata;
    use crate::air::{
        MerkleInclusionAir,
        poseidon_slice_to_field,
    };
    use crate::stark::{
        StarkVerifier,
        default_config,
    };

    if proof.proof_type != crate::ProofType::Stark {
        return Ok(false);
    }

    if proof.data.is_empty() {
        return Ok(false);
    }

    // Validate tree depth against proof metadata if present
    if let ProofMetadata::MerkleInclusion { tree_depth } = &proof.metadata &&
        *tree_depth as usize != expected_tree_depth
    {
        // Tree depth mismatch - reject to prevent depth confusion
        return Ok(false);
    }

    // Validate tree depth bounds
    if expected_tree_depth == 0 || expected_tree_depth > 64 {
        return Err(lib_q_core::Error::InvalidState {
            operation: "verify_membership_with_depth".into(),
            reason: "Tree depth must be between 1 and 64".into(),
        });
    }

    // Create AIR with the specified depth
    let air = MerkleInclusionAir::new(expected_tree_depth).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "verify_membership_with_depth".into(),
            details: e.to_string(),
        }
    })?;

    // Deserialize root bytes to the single PoseidonField (no extra hash)
    let root_poseidon =
        crate::air::merkle_root_from_bytes(root).map_err(|e| lib_q_core::Error::InternalError {
            operation: "verify_membership_with_depth".into(),
            details: e.to_string(),
        })?;
    let expected_public_values = poseidon_slice_to_field(&[root_poseidon]);

    // Deserialize and verify the STARK proof
    let stark_proof = proof.to_stark_proof()?;
    let config = default_config();
    let verifier = StarkVerifier::new(config);

    match verifier.verify(&air, &stark_proof, &expected_public_values) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify membership in a Merkle tree
///
/// This verifies a proof generated by `prove_membership`.
///
/// The proof must contain tree depth metadata. Proofs created with
/// `prove_membership()` automatically include this metadata.
///
/// # Arguments
///
/// * `proof` - The proof to verify (must contain MerkleInclusion metadata)
/// * `root` - The expected Merkle root hash (bytes)
///
/// # Returns
///
/// `Ok(true)` if the proof is valid, `Ok(false)` if invalid or missing metadata
///
/// # Security Note
///
/// For maximum security and explicit depth validation, prefer
/// `verify_membership_with_depth` when you know the expected tree depth.
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::api::verify_membership;
///
/// let root = b"expected root hash";
/// let is_valid = verify_membership(&proof, root)?;
/// ```
pub fn verify_membership(proof: &ZkpProof, root: &[u8]) -> Result<bool> {
    use crate::ProofMetadata;
    use crate::air::{
        MerkleInclusionAir,
        poseidon_slice_to_field,
    };
    use crate::stark::{
        StarkVerifier,
        default_config,
    };

    if proof.proof_type != crate::ProofType::Stark {
        return Ok(false);
    }

    if proof.data.is_empty() {
        return Ok(false);
    }

    // Proof must contain tree depth metadata
    let ProofMetadata::MerkleInclusion { tree_depth } = &proof.metadata else {
        // Missing metadata - proof is invalid
        return Ok(false);
    };

    let depth = *tree_depth as usize;

    // Validate depth bounds
    if depth == 0 || depth > 64 {
        return Ok(false);
    }

    // Deserialize root bytes to the single PoseidonField (no extra hash)
    let root_poseidon = match crate::air::merkle_root_from_bytes(root) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    let expected_public_values = poseidon_slice_to_field(&[root_poseidon]);

    // Create AIR with the metadata depth
    let air = MerkleInclusionAir::new(depth).map_err(|e| lib_q_core::Error::InternalError {
        operation: "verify_membership".into(),
        details: e.to_string(),
    })?;

    // Deserialize and verify the STARK proof
    let stark_proof = proof.to_stark_proof()?;
    let config = default_config();
    let verifier = StarkVerifier::new(config);

    match verifier.verify(&air, &stark_proof, &expected_public_values) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Prove knowledge of a preimage without revealing it
///
/// This generates a proof that the prover knows a secret value that hashes
/// to a given output, without revealing the secret.
///
/// # Arguments
///
/// * `secret` - The secret preimage to prove knowledge of
///
/// # Returns
///
/// A zero-knowledge proof of preimage knowledge
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::api::prove_preimage;
///
/// let secret = b"my secret password";
/// let proof = prove_preimage(secret)?;
/// ```
pub fn prove_preimage(secret: &[u8]) -> Result<ZkpProof> {
    let mut prover = ZkpProver::new();
    let public_statement = b""; // Empty for preimage proof
    prover.prove_secret_value(secret, public_statement)
}

/// Verify a preimage proof
///
/// This verifies a proof generated by `prove_preimage`.
///
/// # Arguments
///
/// * `proof` - The proof to verify
/// * `expected_hash` - The expected hash output (bytes)
///
/// # Returns
///
/// `Ok(true)` if the proof is valid, `Ok(false)` or `Err` otherwise
pub fn verify_preimage(proof: &ZkpProof, expected_hash: &[u8]) -> Result<bool> {
    let verifier = ZkpVerifier::new();
    verifier.verify_secret_value(proof, expected_hash)
}

/// Prove knowledge of a preimage using NIST cSHAKE256
///
/// Same as [`prove_preimage`] but uses cSHAKE256 (domain `b"HashPreimageNistAir"`).
/// Use when 100% NIST compliance is required; prover cost is higher than Poseidon-based proofs.
///
/// # Arguments
///
/// * `secret` - The secret preimage
///
/// # Returns
///
/// A zero-knowledge proof (NIST variant)
pub fn prove_preimage_nist(secret: &[u8]) -> Result<ZkpProof> {
    let mut prover = ZkpProver::new();
    prover.prove_secret_value_nist(secret, b"")
}

/// Verify a NIST (cSHAKE256) preimage proof
///
/// Verifies a proof from [`prove_preimage_nist`]. `expected_hash` is the 32-byte cSHAKE256 output.
pub fn verify_preimage_nist(proof: &ZkpProof, expected_hash: &[u8]) -> Result<bool> {
    let verifier = ZkpVerifier::new();
    verifier.verify_secret_value_nist(proof, expected_hash)
}
