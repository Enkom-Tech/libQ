//! lib-Q ZKP - Post-quantum Zero-Knowledge Proofs
//!
//! This crate provides implementations of post-quantum zero-knowledge proofs.
//!
//! # zk-STARK Implementation
//!
//! This crate provides a high-level API for creating and verifying zk-STARK proofs.
//! The underlying implementation is based on Plonky3, adapted for lib-Q's post-quantum
//! security requirements using SHAKE256.
//!
//! ## Field Configuration
//!
//! The implementation uses **Complex<Mersenne31>** as the base field, which provides:
//! - **TWO_ADICITY = 32**: Sufficient for FRI protocol and efficient FFT operations
//! - **Post-quantum security**: All operations use NIST-approved primitives
//! - **Efficient arithmetic**: Optimized field operations for STARK proofs
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use lib_q_zkp::stark::{StarkProver, StarkVerifier, default_config};
//! use lib_q_stark_field::extension::Complex;
//! use lib_q_stark_mersenne31::Mersenne31;
//!
//! type Val = Complex<Mersenne31>;
//!
//! // Create prover and verifier with default configuration
//! let config = default_config();
//! let prover = StarkProver::new(config.clone());
//! let verifier = StarkVerifier::new(config);
//!
//! // Generate proof (requires AIR implementation)
//! // let proof = prover.prove(&air, trace, &public_values);
//!
//! // Verify proof
//! // verifier.verify(&air, &proof, &public_values)?;
//! ```

#![no_std]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

// Re-export core types for public use
pub use lib_q_core::Result;

/// zk-STARK implementation
#[cfg(feature = "zkp")]
pub mod stark;

/// Circuit builder for arithmetic constraints
#[cfg(feature = "zkp")]
pub mod circuit;

#[cfg(feature = "zkp")]
pub use lib_q_stark::{
    Proof as StarkProof,
    StarkConfig,
    StarkGenericConfig,
    Val,
    prove,
    verify,
};
#[cfg(feature = "zkp")]
pub use lib_q_stark_air::Air;
#[cfg(feature = "zkp")]
use lib_q_stark_matrix::dense::RowMajorMatrix;
#[cfg(feature = "zkp")]
use serde::{
    Deserialize,
    Serialize,
};

/// A zero-knowledge proof
#[derive(Debug, Clone)]
pub struct ZkpProof {
    /// The proof data (serialized STARK proof)
    pub data: Vec<u8>,
    /// The proof type
    pub proof_type: ProofType,
    /// Security level
    pub security_level: u32,
}

#[cfg(feature = "zkp")]
impl ZkpProof {
    /// Serialize a STARK proof into a ZkpProof
    pub fn from_stark_proof<C: StarkGenericConfig>(proof: &StarkProof<C>) -> Result<Self>
    where
        StarkProof<C>: Serialize,
    {
        let data = postcard::to_allocvec(proof).map_err(|_| lib_q_core::Error::InternalError {
            operation: "ZKP proof serialization".to_string(),
            details: "Failed to serialize STARK proof".to_string(),
        })?;
        Ok(Self {
            data,
            proof_type: ProofType::Stark,
            security_level: 1,
        })
    }

    /// Deserialize a ZkpProof into a STARK proof
    pub fn to_stark_proof<C: StarkGenericConfig>(&self) -> Result<StarkProof<C>>
    where
        StarkProof<C>: for<'de> Deserialize<'de>,
    {
        postcard::from_bytes(&self.data).map_err(|_| lib_q_core::Error::InternalError {
            operation: "ZKP proof deserialization".to_string(),
            details: "Failed to deserialize STARK proof".to_string(),
        })
    }
}

/// Types of zero-knowledge proofs supported by lib-Q
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofType {
    /// zk-STARK proof
    Stark,
    /// Future: zk-SNARK proof
    Snark,
    /// Future: Bulletproofs
    Bulletproof,
}

/// Prover for creating zero-knowledge proofs
#[cfg(feature = "zkp")]
pub struct ZkpProver {
    // Using default config for now - can be extended to support custom configs
}

#[cfg(not(feature = "zkp"))]
pub struct ZkpProver;

/// Verifier for verifying zero-knowledge proofs
#[cfg(feature = "zkp")]
pub struct ZkpVerifier {
    // Using default config for now - can be extended to support custom configs
}

#[cfg(not(feature = "zkp"))]
pub struct ZkpVerifier;

#[cfg(feature = "zkp")]
impl ZkpProver {
    /// Create a new ZKP prover
    pub fn new() -> Self {
        Self {}
    }

    /// Prove knowledge of a secret value without revealing it
    ///
    /// This is a placeholder implementation. For a full implementation, you would:
    /// 1. Convert bytes to field elements
    /// 2. Build a trace for a hash preimage proof or other constraint
    /// 3. Generate STARK proof using default config
    ///
    /// # Arguments
    ///
    /// * `secret_value` - The secret value to prove knowledge of
    /// * `public_statement` - The public statement to prove
    ///
    /// # Returns
    ///
    /// A zero-knowledge proof
    pub fn prove_secret_value(
        &mut self,
        _secret_value: &[u8],
        _public_statement: &[u8],
    ) -> Result<ZkpProof> {
        // TODO: Implement actual ZKP generation with proper AIR
        // For now, return an error indicating this needs to be implemented
        Err(lib_q_core::Error::NotImplemented {
            feature: "prove_secret_value - requires AIR implementation for secret value proofs"
                .to_string(),
        })
    }

    /// Prove a computation using a circuit
    ///
    /// # Arguments
    ///
    /// * `circuit` - The arithmetic circuit to prove
    /// * `witness` - The witness values (private inputs)
    /// * `public` - The public input values
    ///
    /// # Returns
    ///
    /// A zero-knowledge proof
    pub fn prove_computation<F: lib_q_stark_field::Field>(
        &mut self,
        _circuit: &crate::circuit::ArithmeticCircuit<F>,
        _witness: &[F],
        _public: &[F],
    ) -> Result<ZkpProof> {
        // TODO: Implement circuit-based proof generation
        Err(lib_q_core::Error::NotImplemented {
            feature: "prove_computation - requires circuit trace generation".to_string(),
        })
    }
}

#[cfg(not(feature = "zkp"))]
impl ZkpProver {
    /// Create a new ZKP prover
    pub fn new() -> Self {
        Self {}
    }

    /// Prove knowledge of a secret value without revealing it
    pub fn prove_secret_value(
        &mut self,
        _secret_value: &[u8],
        _public_statement: &[u8],
    ) -> Result<ZkpProof> {
        Err(lib_q_core::Error::NotImplemented {
            feature: "ZKP feature not enabled".to_string(),
        })
    }
}

#[cfg(feature = "zkp")]
impl ZkpVerifier {
    /// Create a new ZKP verifier
    pub fn new() -> Self {
        Self {}
    }

    /// Verify a zero-knowledge proof
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `public_statement` - The public statement that was proven
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify(&self, proof: ZkpProof, _public_statement: &[u8]) -> Result<bool> {
        // TODO: Implement actual ZKP verification with proper AIR
        // For now, check that proof can be deserialized
        if proof.proof_type != ProofType::Stark {
            return Ok(false);
        }

        // Try to deserialize - if it fails, proof is invalid
        // Note: We can't fully verify without the AIR, so this is a basic check
        if proof.data.is_empty() {
            return Ok(false);
        }

        // For now, return an error indicating full verification needs AIR
        Err(lib_q_core::Error::NotImplemented {
            feature: "verify - requires AIR implementation for proof verification".to_string(),
        })
    }

    /// Batch verify multiple proofs
    ///
    /// # Arguments
    ///
    /// * `proofs` - The proofs to verify
    /// * `publics` - The public statements for each proof
    ///
    /// # Returns
    ///
    /// `true` if all proofs are valid, `false` otherwise
    pub fn batch_verify(&self, proofs: &[ZkpProof], publics: &[&[u8]]) -> Result<bool> {
        if proofs.len() != publics.len() {
            return Err(lib_q_core::Error::InvalidState {
                operation: "batch_verify".to_string(),
                reason: "Number of proofs must match number of public statements".to_string(),
            });
        }

        for (proof, public) in proofs.iter().zip(publics.iter()) {
            match self.verify(proof.clone(), public) {
                Ok(true) => continue,
                Ok(false) => return Ok(false),
                Err(e) => return Err(e),
            }
        }

        Ok(true)
    }
}

#[cfg(not(feature = "zkp"))]
impl ZkpVerifier {
    /// Create a new ZKP verifier
    pub fn new() -> Self {
        Self {}
    }

    /// Verify a zero-knowledge proof
    pub fn verify(&self, _proof: ZkpProof, _public_statement: &[u8]) -> Result<bool> {
        Err(lib_q_core::Error::NotImplemented {
            feature: "ZKP feature not enabled".to_string(),
        })
    }

    /// Batch verify multiple proofs
    pub fn batch_verify(&self, _proofs: &[ZkpProof], _publics: &[&[u8]]) -> Result<bool> {
        Err(lib_q_core::Error::NotImplemented {
            feature: "ZKP feature not enabled".to_string(),
        })
    }
}

impl Default for ZkpProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ZkpVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Get available ZKP algorithms
pub fn available_algorithms() -> Vec<&'static str> {
    let algorithms = vec![
        #[cfg(feature = "stark")]
        "stark",
    ];

    algorithms
}

/// Create a ZKP instance by algorithm name
pub fn create_zkp(algorithm: &str) -> Result<alloc::boxed::Box<dyn core::any::Any>> {
    match algorithm {
        #[cfg(feature = "zkp")]
        "stark" => Ok(alloc::boxed::Box::new(ZkpProver::new())),

        _ => Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: "Unknown ZKP algorithm",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_prover_creation() {
        let _prover = ZkpProver::new();
        // Just check that creation doesn't panic
    }

    #[test]
    fn test_zkp_verifier_creation() {
        let _verifier = ZkpVerifier::new();
        // Just check that creation doesn't panic
    }

    #[test]
    fn test_zkp_proof_creation() {
        let mut prover = ZkpProver::new();
        let secret_value = b"secret_value";
        let public_statement = b"public_statement";

        // This will return NotImplemented error until we implement the actual proof generation
        let result = prover.prove_secret_value(secret_value, public_statement);
        assert!(result.is_err());
        if let Err(lib_q_core::Error::NotImplemented { .. }) = result {
            // Expected
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    fn test_zkp_proof_verification() {
        let verifier = ZkpVerifier::new();
        let public_statement = b"public_statement";

        // Create a placeholder proof
        let proof = ZkpProof {
            data: vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
        };

        // This will return NotImplemented error until we implement the actual verification
        let result = verifier.verify(proof, public_statement);
        assert!(result.is_err());
        if let Err(lib_q_core::Error::NotImplemented { .. }) = result {
            // Expected
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    fn test_batch_verify_mismatched_lengths() {
        let verifier = ZkpVerifier::new();
        let proofs = vec![ZkpProof {
            data: vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
        }];
        let publics: &[&[u8]] = &[b"public1" as &[u8], b"public2" as &[u8]];

        let result = verifier.batch_verify(&proofs, &publics);
        assert!(result.is_err());
        if let Err(lib_q_core::Error::InvalidState { .. }) = result {
            // Expected
        } else {
            panic!("Expected InvalidState error");
        }
    }

    #[test]
    fn test_available_algorithms() {
        let _algorithms = available_algorithms();
        // assert!(!algorithms.is_empty()); // TODO: Implement algorithms
    }

    #[test]
    fn test_create_zkp() {
        // Test with a valid algorithm if any features are enabled
        // if !available_algorithms().is_empty() { // TODO: Implement algorithms
        //     let algorithm = available_algorithms()[0];
        //     assert!(create_zkp(algorithm).is_ok());
        // }
    }
}
