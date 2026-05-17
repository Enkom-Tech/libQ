//! IP Credential Module - Selective attribute disclosure
//!
//! This module provides functions for selective disclosure of credential
//! attributes in an Identity Protocol, allowing users to reveal only specific attributes
//! while keeping others secret.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{
    format,
    vec,
};

use lib_q_core::Result;

use crate::ZkpProof;
use crate::air::credential::attr_to_left_right;
use crate::air::{
    CredentialAir,
    CredentialInput,
    CredentialSchema,
    TraceGenerator,
};
use crate::stark::{
    StarkProver,
    StarkVerifier,
    default_config,
};

/// IP credential structure
#[derive(Debug, Clone)]
pub struct IpCredential {
    /// All credential attributes
    pub attributes: Vec<Vec<u8>>,
}

/// Prove credential attributes with selective disclosure
///
/// This generates a zero-knowledge proof that the prover knows a credential
/// with specific attributes, revealing only those attributes marked in
/// `reveal_mask`.
///
/// # Arguments
///
/// * `credential` - The credential with all attributes
/// * `reveal_mask` - Boolean mask indicating which attributes to reveal
///
/// # Returns
///
/// A zero-knowledge proof of credential attributes
///
/// # Example
///
/// ```rust,ignore
/// use lib_q_zkp::ip::credential::{prove_credential_attributes, IpCredential};
///
/// let credential = IpCredential {
///     attributes: vec![
///         b"name".to_vec(),
///         b"age".to_vec(),
///         b"ssn".to_vec(),
///     ],
/// };
/// let reveal_mask = vec![true, true, false]; // Reveal name and age, hide SSN
/// let proof = prove_credential_attributes(&credential, &reveal_mask)?;
/// ```
pub fn prove_credential_attributes(
    credential: &IpCredential,
    reveal_mask: &[bool],
) -> Result<ZkpProof> {
    if credential.attributes.is_empty() {
        return Err(lib_q_core::Error::InvalidState {
            operation: "prove_credential_attributes".to_string(),
            reason: "Credential must have at least one attribute".to_string(),
        });
    }

    if reveal_mask.len() != credential.attributes.len() {
        return Err(lib_q_core::Error::InvalidState {
            operation: "prove_credential_attributes".to_string(),
            reason: format!(
                "Reveal mask length {} must match credential attributes {}",
                reveal_mask.len(),
                credential.attributes.len()
            ),
        });
    }

    // Create schema from attribute sizes
    let attribute_sizes: Vec<usize> = credential
        .attributes
        .iter()
        .map(|attr| attr.len())
        .collect();

    let schema =
        CredentialSchema::new(attribute_sizes).map_err(|e| lib_q_core::Error::InternalError {
            operation: "prove_credential_attributes".to_string(),
            details: e.to_string(),
        })?;

    // Create credential AIR
    let air = CredentialAir::new(schema, reveal_mask.to_vec()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "prove_credential_attributes".to_string(),
            details: e.to_string(),
        }
    })?;

    // Create input
    let input = CredentialInput {
        attributes: credential.attributes.clone(),
    };

    // Generate trace
    let trace = air
        .generate_trace(&input)
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "prove_credential_attributes".to_string(),
            details: e.to_string(),
        })?;

    // Get public values (commitment + revealed attributes)
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

    // Create ZkpProof with credential-specific metadata
    let metadata = crate::ProofMetadata::Credential {
        attribute_sizes: credential
            .attributes
            .iter()
            .map(|a| a.len().min(u16::MAX as usize) as u16)
            .collect(),
        reveal_mask: reveal_mask.to_vec(),
    };
    ZkpProof::from_stark_proof(&stark_proof, metadata)
}

/// Compute the credential commitment from all attributes.
///
/// This produces the same commitment that the prover embeds in the proof,
/// allowing a verifier (or issuer) to derive `expected_commitment` from the
/// full attribute set without needing the proof itself.
///
/// The commitment is computed by Poseidon-hashing each attribute individually,
/// then aggregating all per-attribute hashes via an iterated Poseidon chain.
///
/// Returns 8 bytes: 4 LE bytes for the real part, 4 LE bytes for the imaginary
/// part of the `Complex<Mersenne31>` commitment field element. Pass these bytes
/// to `verify_credential_proof` as `expected_commitment`.
pub fn compute_credential_commitment(attributes: &[Vec<u8>]) -> Result<Vec<u8>> {
    if attributes.is_empty() {
        return Err(lib_q_core::Error::InvalidState {
            operation: "compute_credential_commitment".to_string(),
            reason: "Credential must have at least one attribute".to_string(),
        });
    }

    use lib_q_poseidon::PoseidonField;

    use crate::air::merkle_inclusion::compute_poseidon_with_intermediates;

    let n = attributes.len();
    let mut attr_hashes: Vec<PoseidonField> = Vec::with_capacity(n);
    for attr in attributes {
        let (left, right) = attr_to_left_right(attr);
        let input_vec = vec![left, right];
        let (hash_out, _) = compute_poseidon_with_intermediates(&input_vec);
        attr_hashes.push(hash_out);
    }

    let commitment_field = if n == 1 {
        attr_hashes[0]
    } else {
        let mut running = attr_hashes[0];
        for right in attr_hashes.iter().take(n).skip(1) {
            let input_vec = vec![running, *right];
            let (hash_out, _) = compute_poseidon_with_intermediates(&input_vec);
            running = hash_out;
        }
        running
    };

    Ok(commitment_field_to_bytes(commitment_field))
}

/// Serialize a `Complex<Mersenne31>` to 8 LE bytes (4 real + 4 imag).
fn commitment_field_to_bytes(f: lib_q_poseidon::PoseidonField) -> Vec<u8> {
    use lib_q_stark_field::{
        BasedVectorSpace,
        PrimeField32,
    };
    use lib_q_stark_mersenne31::Mersenne31;
    let coords: &[Mersenne31] = f.as_basis_coefficients_slice();
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&coords[0].as_canonical_u32().to_le_bytes());
    bytes.extend_from_slice(&coords[1].as_canonical_u32().to_le_bytes());
    bytes
}

/// Deserialize 8 LE bytes into a `Complex<Mersenne31>`.
fn commitment_field_from_bytes(bytes: &[u8]) -> Option<lib_q_poseidon::PoseidonField> {
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;
    if bytes.len() < 8 {
        return None;
    }
    let real = Mersenne31::new(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    let imag = Mersenne31::new(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    Some(Complex::new_complex(real, imag))
}

/// Verify a credential proof
///
/// This verifies that a proof demonstrates knowledge of a credential
/// with the expected commitment and revealed attributes.
///
/// # Arguments
///
/// * `proof` - The proof to verify
/// * `expected_commitment` - The expected credential commitment
/// * `revealed_attributes` - The revealed attribute values
///
/// # Returns
///
/// `Ok(true)` if the proof is valid, `Ok(false)` or `Err` otherwise
pub fn verify_credential_proof(
    proof: &ZkpProof,
    expected_commitment: &[u8],
    revealed_attributes: &[Vec<u8>],
) -> Result<bool> {
    if proof.proof_type != crate::ProofType::Stark {
        return Ok(false);
    }

    if proof.data.is_empty() {
        return Ok(false);
    }

    // Extract credential metadata
    let crate::ProofMetadata::Credential {
        attribute_sizes,
        reveal_mask,
    } = &proof.metadata
    else {
        return Ok(false);
    };

    // Validate metadata consistency
    if attribute_sizes.len() != reveal_mask.len() {
        return Ok(false);
    }

    if revealed_attributes.len() != reveal_mask.iter().filter(|&&r| r).count() {
        return Ok(false);
    }

    // Reconstruct credential schema
    let schema = CredentialSchema::new(attribute_sizes.iter().map(|&s| s as usize).collect())
        .map_err(|e| lib_q_core::Error::InternalError {
            operation: "verify_credential_proof".to_string(),
            details: e.to_string(),
        })?;

    // Reconstruct AIR with the same reveal mask used during proving
    let air = CredentialAir::new(schema, reveal_mask.clone()).map_err(|e| {
        lib_q_core::Error::InternalError {
            operation: "verify_credential_proof".to_string(),
            details: e.to_string(),
        }
    })?;

    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use crate::air::poseidon_to_field;
    type Val = Complex<Mersenne31>;

    // Deserialize commitment from bytes (8 LE bytes → single Complex<Mersenne31>)
    let commitment_poseidon =
        commitment_field_from_bytes(expected_commitment).ok_or_else(|| {
            lib_q_core::Error::InvalidState {
                operation: "verify_credential_proof".to_string(),
                reason: "expected_commitment must be at least 8 bytes".to_string(),
            }
        })?;
    let mut public_values: Vec<Val> = vec![poseidon_to_field::<Val>(&commitment_poseidon)];

    // Add revealed attribute hashes (same order as during proving)
    let mut revealed_idx = 0;
    for (attr_size, &revealed) in attribute_sizes.iter().zip(reveal_mask.iter()) {
        if revealed {
            if revealed_idx >= revealed_attributes.len() {
                return Ok(false);
            }
            let attr = &revealed_attributes[revealed_idx];
            if attr.len() > *attr_size as usize {
                return Ok(false);
            }
            let (left, right) = attr_to_left_right(attr);
            let input_vec = vec![left, right];
            let (hash_out, _) =
                crate::air::merkle_inclusion::compute_poseidon_with_intermediates(&input_vec);
            public_values.push(poseidon_to_field::<Val>(&hash_out));
            revealed_idx += 1;
        }
    }

    // Deserialize STARK proof
    let stark_proof = proof
        .to_stark_proof()
        .map_err(|_| lib_q_core::Error::InternalError {
            operation: "verify_credential_proof".to_string(),
            details: "Failed to deserialize STARK proof".to_string(),
        })?;

    // Verify the proof using the same AIR and public values
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
    use crate::{
        ProofMetadata,
        ProofType,
        ZkpProof,
    };

    #[test]
    fn test_prove_credential_attributes() {
        let credential = IpCredential {
            attributes: vec![b"John Doe".to_vec(), b"30".to_vec()],
        };
        let reveal_mask = vec![true, false];
        let result = prove_credential_attributes(&credential, &reveal_mask);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_credential_commitment_empty_attributes() {
        let result = compute_credential_commitment(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_credential_commitment_deterministic() {
        let attrs = vec![b"Alice".to_vec(), b"42".to_vec()];
        let c1 = compute_credential_commitment(&attrs).unwrap();
        let c2 = compute_credential_commitment(&attrs).unwrap();
        assert_eq!(c1, c2, "commitment must be deterministic");
        assert_eq!(c1.len(), 8, "commitment is 8 bytes (Complex<Mersenne31>)");
    }

    #[test]
    fn test_credential_prove_verify_roundtrip() {
        let credential = IpCredential {
            attributes: vec![b"Alice".to_vec(), b"42".to_vec(), b"secret".to_vec()],
        };
        let reveal_mask = vec![true, true, false];

        let commitment = compute_credential_commitment(&credential.attributes).expect("commitment");
        let proof = prove_credential_attributes(&credential, &reveal_mask).expect("prove");

        let revealed = vec![b"Alice".to_vec(), b"42".to_vec()];
        let result = verify_credential_proof(&proof, &commitment, &revealed)
            .expect("verify should not error");
        assert!(result, "valid credential proof must verify");
    }

    #[test]
    fn test_credential_soundness_wrong_commitment() {
        let credential = IpCredential {
            attributes: vec![b"Alice".to_vec(), b"42".to_vec()],
        };
        let reveal_mask = vec![true, false];

        let proof = prove_credential_attributes(&credential, &reveal_mask).expect("prove");

        let wrong_commitment = vec![0u8; 8];
        let revealed = vec![b"Alice".to_vec()];
        let result = verify_credential_proof(&proof, &wrong_commitment, &revealed)
            .expect("verify should not error");
        assert!(!result, "wrong commitment must fail verification");
    }

    #[test]
    fn test_credential_soundness_wrong_revealed_attribute() {
        let credential = IpCredential {
            attributes: vec![b"Alice".to_vec(), b"42".to_vec()],
        };
        let reveal_mask = vec![true, false];

        let commitment = compute_credential_commitment(&credential.attributes).expect("commitment");
        let proof = prove_credential_attributes(&credential, &reveal_mask).expect("prove");

        let wrong_revealed = vec![b"Bob".to_vec()];
        let result = verify_credential_proof(&proof, &commitment, &wrong_revealed)
            .expect("verify should not error");
        assert!(!result, "wrong revealed attribute must fail verification");
    }

    #[test]
    fn test_prove_credential_attributes_rejects_empty_credential() {
        let credential = IpCredential { attributes: vec![] };
        let result = prove_credential_attributes(&credential, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_prove_credential_attributes_rejects_reveal_mask_length_mismatch() {
        let credential = IpCredential {
            attributes: vec![b"A".to_vec(), b"B".to_vec()],
        };
        let result = prove_credential_attributes(&credential, &[true]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_credential_proof_rejects_empty_data() {
        let proof = ZkpProof {
            data: vec![],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Credential {
                attribute_sizes: vec![1],
                reveal_mask: vec![true],
            },
        };
        let result = verify_credential_proof(&proof, &[0u8; 8], &[b"A".to_vec()]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_credential_proof_rejects_non_credential_metadata() {
        let proof = ZkpProof {
            data: vec![1u8; 16],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::None,
        };
        let result = verify_credential_proof(&proof, &[0u8; 8], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_credential_proof_rejects_inconsistent_metadata_lengths() {
        let proof = ZkpProof {
            data: vec![1u8; 16],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Credential {
                attribute_sizes: vec![4, 4],
                reveal_mask: vec![true],
            },
        };
        let result = verify_credential_proof(&proof, &[0u8; 8], &[b"A".to_vec()]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_credential_proof_rejects_revealed_count_mismatch() {
        let proof = ZkpProof {
            data: vec![1u8; 16],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Credential {
                attribute_sizes: vec![4, 4],
                reveal_mask: vec![true, false],
            },
        };
        let result = verify_credential_proof(&proof, &[0u8; 8], &[]).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_verify_credential_proof_rejects_short_expected_commitment() {
        let credential = IpCredential {
            attributes: vec![b"Alice".to_vec(), b"42".to_vec()],
        };
        let reveal_mask = vec![true, false];
        let proof = prove_credential_attributes(&credential, &reveal_mask).expect("proof");
        let result = verify_credential_proof(&proof, &[1u8; 7], &[b"Alice".to_vec()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_credential_proof_rejects_revealed_attribute_too_long() {
        let credential = IpCredential {
            attributes: vec![b"A".to_vec(), b"42".to_vec()],
        };
        let reveal_mask = vec![true, false];
        let commitment = compute_credential_commitment(&credential.attributes).expect("commitment");
        let proof = prove_credential_attributes(&credential, &reveal_mask).expect("proof");
        let result = verify_credential_proof(&proof, &commitment, &[b"TOO-LONG".to_vec()]).unwrap();
        assert!(!result);
    }
}
