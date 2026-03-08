//! IP Credential Module - Selective attribute disclosure
//!
//! This module provides functions for selective disclosure of credential
//! attributes in an Identity Protocol, allowing users to reveal only specific attributes
//! while keeping others secret.

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use lib_q_core::Result;

use crate::ZkpProof;
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
    let stark_proof = prover.prove(&air, trace, &public_values);

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

    // Compute expected public values
    // Public values = commitment + revealed attributes
    use lib_q_stark_field::extension::Complex;
    use lib_q_stark_mersenne31::Mersenne31;

    use crate::air::{
        bytes_to_poseidon_field,
        poseidon_to_field,
    };
    type Val = Complex<Mersenne31>;

    // Compute commitment from expected_commitment bytes
    let commitment_fields = bytes_to_poseidon_field(expected_commitment);
    let mut public_values: Vec<Val> = commitment_fields
        .iter()
        .map(poseidon_to_field::<Val>)
        .collect();

    // Add revealed attributes to public values (in the same order as during proving)
    let mut revealed_idx = 0;
    for (attr_size, &revealed) in attribute_sizes.iter().zip(reveal_mask.iter()) {
        if revealed {
            if revealed_idx >= revealed_attributes.len() {
                return Ok(false);
            }
            let attr = &revealed_attributes[revealed_idx];
            // Validate attribute size matches schema
            if attr.len() > *attr_size as usize {
                return Ok(false);
            }
            let attr_fields = bytes_to_poseidon_field(attr);
            for field in attr_fields {
                public_values.push(poseidon_to_field::<Val>(&field));
            }
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

    #[test]
    fn test_prove_credential_attributes() {
        let credential = IpCredential {
            attributes: vec![b"John Doe".to_vec(), b"30".to_vec()],
        };
        let reveal_mask = vec![true, false];
        let result = prove_credential_attributes(&credential, &reveal_mask);
        assert!(result.is_ok());
    }
}
