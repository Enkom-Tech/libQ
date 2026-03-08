//! IP Authentication Module - Anonymous group membership authentication
//!
//! This module provides functions for anonymous authentication in an Identity Protocol,
//! allowing users to prove group membership without revealing identity.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use lib_q_core::Result;

use crate::ZkpProof;
use crate::air::{
    AnonymousAuthAir,
    AnonymousAuthInput,
    MerkleProofInput,
    TraceGenerator,
};
use crate::api::MerklePath;
use crate::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
};

/// Merkle root hash (32 bytes)
pub type MerkleRoot = [u8; 32];

/// ML-DSA private key (simplified)
pub type MlDsaPrivateKey = Vec<u8>;

/// Prove group membership without revealing identity
///
/// This generates a zero-knowledge proof that the prover is a member of
/// a group (represented as a Merkle tree) without revealing which specific
/// member they are.
///
/// # Arguments
///
/// * `member_key` - The member's ML-DSA private key
/// * `group_root` - The Merkle root of the group
/// * `membership_path` - The Merkle authentication path
///
/// # Returns
///
/// A zero-knowledge proof of anonymous group membership
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::ip::auth::prove_group_membership;
///
/// let member_key = b"private-key".to_vec();
/// let group_root = [0u8; 32];
/// let path = MerklePath { ... };
/// let proof = prove_group_membership(&member_key, &group_root, &path)?;
/// ```
pub fn prove_group_membership(
    member_key: &MlDsaPrivateKey,
    _group_root: &MerkleRoot,
    membership_path: &MerklePath,
) -> Result<ZkpProof> {
    use crate::ProofMetadata;

    let group_depth = membership_path.path_bits.len();
    let air = AnonymousAuthAir::new(group_depth, false).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "prove_group_membership".to_string(),
            details: e.to_string(),
        }
    })?;

    // Convert member key to bytes for leaf value
    let member_identity = member_key.clone();

    // Convert MerklePath to MerkleProofInput
    let merkle_input = MerkleProofInput {
        leaf: member_identity,
        path_bits: membership_path.path_bits.clone(),
        siblings: membership_path.siblings.clone(),
    };

    let input = AnonymousAuthInput {
        member_identity: member_key.clone(),
        membership_path: merkle_input,
    };

    // Generate trace
    let trace = air
        .generate_trace(&input)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "prove_group_membership".to_string(),
            details: e.to_string(),
        })?;

    // Get public values (Merkle root)
    let public_values = air.public_values(&input);

    // Generate STARK proof
    let config = default_config();
    let prover = StarkProver::new(config);
    let stark_proof = prover.prove(&air, trace, &public_values);

    // Create ZkpProof with metadata
    let metadata = ProofMetadata::MerkleInclusion {
        tree_depth: group_depth as u8,
    };
    ZkpProof::from_stark_proof(&stark_proof, metadata)
}

/// Verify an anonymous group membership proof
///
/// This verifies that a proof demonstrates membership in a group with
/// the given Merkle root.
///
/// # Arguments
///
/// * `proof` - The proof to verify
/// * `group_root` - The expected Merkle root of the group
///
/// # Returns
///
/// `Ok(true)` if the proof is valid, `Ok(false)` or `Err` otherwise
pub fn verify_group_membership(proof: &ZkpProof, group_root: &MerkleRoot) -> Result<bool> {
    use crate::ProofMetadata;
    use crate::air::AnonymousAuthAir;

    if proof.proof_type != crate::ProofType::Stark {
        return Ok(false);
    }

    if proof.data.is_empty() {
        return Ok(false);
    }

    // Get tree depth from metadata
    let tree_depth = match &proof.metadata {
        ProofMetadata::MerkleInclusion { tree_depth } => *tree_depth as usize,
        _ => return Ok(false),
    };

    // Create AIR
    let air =
        AnonymousAuthAir::new(tree_depth, false).map_err(|e| lib_q_core::Error::InternalError {
            operation: "verify_group_membership".to_string(),
            details: e.to_string(),
        })?;

    // Deserialize STARK proof
    let stark_proof = proof.to_stark_proof()?;

    // Convert group root to public values
    use lib_q_poseidon::{
        Poseidon,
        Poseidon128,
    };

    use crate::air::{
        bytes_to_poseidon_field,
        poseidon_slice_to_field,
    };
    let root_fields = bytes_to_poseidon_field(group_root);
    let poseidon_root = Poseidon128.hash(&root_fields);
    let public_values = poseidon_slice_to_field(&poseidon_root);

    // Verify proof
    let config = default_config();
    let verifier = StarkVerifier::new(config);
    match verifier.verify(&air, &stark_proof, &public_values) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::air::MerkleHash;
    use crate::api::MerklePath;

    #[test]
    fn test_prove_group_membership() {
        let member_key = b"member-key".to_vec();
        let group_root = [0u8; 32];
        let path = MerklePath {
            path_bits: vec![false, true],
            siblings: vec![
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            ],
        };
        let result = prove_group_membership(&member_key, &group_root, &path);
        assert!(result.is_ok());
    }
}
