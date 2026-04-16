//! IP Identity Module - Proves IT ownership
//!
//! This module provides functions for proving ownership of an Identity Token (IT)
//! without revealing the ML-DSA private key.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

use lib_q_core::Result;

use crate::ZkpProof;
use crate::air::{
    IdentityProofAir,
    IdentityProofInput,
    MlDsaLevel,
    TraceGenerator,
};
use crate::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
};

/// Identity Token (IT) - 128-bit identifier
pub type IdentityToken = [u8; 16];

// Re-export MlDsaPrivateKey from auth module to avoid duplicate type
pub use super::auth::MlDsaPrivateKey;

/// Derive the Identity Token (16 bytes) from a secret, using the same derivation
/// as IdentityProofAir public values. Use this to obtain the correct IT for
/// verification after proving with that secret.
#[doc(hidden)]
pub fn identity_token_from_secret(secret: &[u8]) -> IdentityToken {
    use lib_q_poseidon::{
        Poseidon,
        Poseidon128,
    };
    use lib_q_stark_field::PrimeCharacteristicRing;
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use crate::air::{
        bytes_to_poseidon_field,
        poseidon_field_to_bytes,
    };

    let mut secret_fields = bytes_to_poseidon_field(secret);
    if !secret_fields.len().is_multiple_of(2) {
        let zero_f = Complex::<Mersenne31>::new_complex(Mersenne31::ZERO, Mersenne31::ZERO);
        secret_fields.push(zero_f);
    }
    let hash_output = Poseidon128.hash(&secret_fields);
    let hash_bytes = poseidon_field_to_bytes(&hash_output);
    let mut it = [0u8; 16];
    let len = hash_bytes.len().min(16);
    it[..len].copy_from_slice(&hash_bytes[..len]);
    it
}

/// Prove ownership of a IT without revealing the private key
///
/// This generates a zero-knowledge proof that the prover knows an ML-DSA
/// private key that corresponds to the given IT.
///
/// # Arguments
///
/// * `it` - The Identity Token to prove ownership of
/// * `private_key` - The ML-DSA private key (kept secret)
///
/// # Returns
///
/// A zero-knowledge proof of IT ownership
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::ip::identity::{prove_it_ownership, verify_it_ownership};
///
/// let it = [0u8; 16]; // IT value
/// let private_key = b"ml-dsa-private-key".to_vec();
/// let proof = prove_it_ownership(&it, &private_key)?;
/// ```
pub fn prove_it_ownership(_it: &IdentityToken, private_key: &MlDsaPrivateKey) -> Result<ZkpProof> {
    use crate::ProofMetadata;

    // Determine ML-DSA level from private key size
    let dsa_level = if private_key.len() <= 2528 {
        MlDsaLevel::Level44
    } else if private_key.len() <= 4000 {
        MlDsaLevel::Level65
    } else {
        MlDsaLevel::Level87
    };

    // Create identity proof AIR
    let air = IdentityProofAir::new(dsa_level).map_err(|e| lib_q_core::Error::InternalError {
        operation: "prove_it_ownership".to_string(),
        details: e.to_string(),
    })?;

    // Create input
    let input = IdentityProofInput {
        secret: private_key.clone(),
    };

    // Generate trace
    let trace = air
        .generate_trace(&input)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "prove_it_ownership".to_string(),
            details: e.to_string(),
        })?;

    // Get public values (should match the IT)
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

    // Create ZkpProof with metadata (store DSA level for verification)
    let level_u8 = match dsa_level {
        MlDsaLevel::Level44 => 44,
        MlDsaLevel::Level65 => 65,
        MlDsaLevel::Level87 => 87,
    };
    let metadata = ProofMetadata::Identity {
        dsa_level: level_u8,
    };
    ZkpProof::from_stark_proof(&stark_proof, metadata)
}

/// Verify a IT ownership proof
///
/// This verifies that a proof demonstrates knowledge of a private key
/// that corresponds to the given IT.
///
/// # Arguments
///
/// * `proof` - The proof to verify
/// * `it` - The expected Identity Token
///
/// # Returns
///
/// `Ok(true)` if the proof is valid, `Ok(false)` or `Err` otherwise
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::ip::identity::verify_it_ownership;
///
/// let it = [0u8; 16];
/// let is_valid = verify_it_ownership(&proof, &it)?;
/// ```
pub fn verify_it_ownership(proof: &ZkpProof, it: &IdentityToken) -> Result<bool> {
    use crate::ProofMetadata;
    use crate::air::IdentityProofAir;

    if proof.proof_type != crate::ProofType::Stark {
        return Ok(false);
    }

    if proof.data.is_empty() {
        return Ok(false);
    }

    // Deserialize STARK proof
    let stark_proof = proof.to_stark_proof()?;

    // Determine ML-DSA level from proof metadata
    let dsa_level = match &proof.metadata {
        ProofMetadata::Identity { dsa_level: 44 } => MlDsaLevel::Level44,
        ProofMetadata::Identity { dsa_level: 87 } => MlDsaLevel::Level87,
        ProofMetadata::Identity { .. } => MlDsaLevel::Level65,
        _ => return Ok(false), // wrong proof type
    };
    let air = IdentityProofAir::new(dsa_level).map_err(|e| lib_q_core::Error::InternalError {
        operation: "verify_it_ownership".to_string(),
        details: e.to_string(),
    })?;

    // IT is the first 16 bytes of the encoding of the hash output; decode first 8 bytes to expected public value.
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use crate::air::it_bytes_to_public_value;
    type Val = Complex<Mersenne31>;
    let expected = it_bytes_to_public_value::<Val>(it);
    let public_values = vec![expected];

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
    use super::*;
    use crate::{
        ProofMetadata,
        ProofType,
        ZkpProof,
    };

    #[test]
    fn test_prove_it_ownership() {
        let it = [42u8; 16];
        let private_key = b"test-private-key".to_vec();
        let result = prove_it_ownership(&it, &private_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_it_ownership() {
        let it = [42u8; 16];
        let private_key = b"test-private-key".to_vec();
        let proof = prove_it_ownership(&it, &private_key).unwrap();
        let result = verify_it_ownership(&proof, &it);
        assert!(result.is_ok());
    }

    #[test]
    fn test_identity_token_from_secret_is_deterministic() {
        let a = identity_token_from_secret(b"deterministic-secret");
        let b = identity_token_from_secret(b"deterministic-secret");
        assert_eq!(a, b);
    }

    #[test]
    fn test_verify_it_ownership_rejects_empty_or_wrong_metadata() {
        let it = [7u8; 16];
        let empty = ZkpProof {
            data: vec![],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Identity { dsa_level: 44 },
        };
        assert!(!verify_it_ownership(&empty, &it).unwrap());

        let mut wrong_metadata =
            prove_it_ownership(&it, &b"test-private-key".to_vec()).expect("valid proof");
        wrong_metadata.metadata = ProofMetadata::None;
        assert!(!verify_it_ownership(&wrong_metadata, &it).unwrap());
    }

    #[test]
    fn test_prove_it_ownership_sets_identity_level_metadata() {
        let it = [42u8; 16];
        let proof_44 = prove_it_ownership(&it, &vec![0u8; 128]).expect("44");
        let proof_65 = prove_it_ownership(&it, &vec![0u8; 2600]).expect("65");

        assert!(matches!(
            proof_44.metadata,
            ProofMetadata::Identity { dsa_level: 44 }
        ));
        assert!(matches!(
            proof_65.metadata,
            ProofMetadata::Identity { dsa_level: 65 }
        ));

        let mut level_87_metadata_proof = proof_65.clone();
        level_87_metadata_proof.metadata = ProofMetadata::Identity { dsa_level: 87 };
        assert!(!verify_it_ownership(&level_87_metadata_proof, &it).unwrap());
    }
}
