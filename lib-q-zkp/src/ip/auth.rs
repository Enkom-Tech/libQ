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
        leaf_hash_direct: None,
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
    let stark_proof = prover.prove(&air, trace, &public_values).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "STARK proof generation".to_string(),
            details: e.to_string(),
        }
    })?;

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

    // Deserialize group root bytes to single PoseidonField (no extra hash)
    let root_poseidon = match crate::air::merkle_root_from_bytes(group_root) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    let public_values = crate::air::poseidon_slice_to_field(&[root_poseidon]);

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
    use crate::{
        ProofMetadata,
        ProofType,
    };

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

    #[test]
    fn test_verify_group_membership_rejects_empty_data_or_wrong_metadata() {
        let root = [0u8; 32];
        let empty = ZkpProof {
            data: vec![],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::MerkleInclusion { tree_depth: 2 },
        };
        assert!(!verify_group_membership(&empty, &root).unwrap());

        let wrong_metadata = ZkpProof {
            data: vec![1u8; 8],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Identity { dsa_level: 44 },
        };
        assert!(!verify_group_membership(&wrong_metadata, &root).unwrap());
    }

    #[test]
    fn test_verify_group_membership_wrong_root_fails() {
        let member_key = b"member-key".to_vec();
        let group_root = [0u8; 32];
        let path = MerklePath {
            path_bits: vec![false, true],
            siblings: vec![
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            ],
        };
        let proof = prove_group_membership(&member_key, &group_root, &path).expect("proof");
        let wrong_root = [1u8; 32];
        assert!(!verify_group_membership(&proof, &wrong_root).unwrap());
    }

    #[test]
    fn test_verify_group_membership_rejects_invalid_tree_depth_metadata() {
        let member_key = b"member-key".to_vec();
        let group_root = [0u8; 32];
        let path = MerklePath {
            path_bits: vec![false, true],
            siblings: vec![
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            ],
        };
        let mut proof = prove_group_membership(&member_key, &group_root, &path).expect("proof");
        proof.metadata = ProofMetadata::MerkleInclusion { tree_depth: 0 };

        let result = verify_group_membership(&proof, &group_root);
        assert!(result.is_err());
    }

    #[test]
    fn test_prove_group_membership_rejects_bad_membership_path_lengths() {
        let member_key = b"member-key".to_vec();
        let group_root = [0u8; 32];
        let bad_path = MerklePath {
            path_bits: vec![false, true, false],
            siblings: vec![
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
                MerkleHash::from_bytes(&[0u8; 32]).unwrap(),
            ],
        };

        let result = prove_group_membership(&member_key, &group_root, &bad_path);
        assert!(result.is_err());
    }
}
