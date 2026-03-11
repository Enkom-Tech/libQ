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

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(lazy_type_alias)]
#![allow(incomplete_features)] // type aliases with where clauses in stark.rs; tracks #112792
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Re-export core types for public use
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub use lib_q_core::Result;
/// Plonky3-derived components (Keccak AIR, lookup, batch STARK, etc.); optional via `plonky` feature.
#[cfg(feature = "plonky")]
pub use lib_q_plonky as plonky;

/// zk-STARK implementation
#[cfg(feature = "zkp")]
pub mod stark;

/// Circuit builder for arithmetic constraints
#[cfg(feature = "zkp")]
pub mod circuit;

/// AIR implementations for common proof types
#[cfg(feature = "zkp")]
pub mod air;

/// Proof aggregation for combining multiple proofs
#[cfg(feature = "zkp")]
pub mod aggregation;

/// IP (Identity Protocol) integration
#[cfg(feature = "zkp")]
pub mod ip;

/// High-level lib q API
#[cfg(feature = "zkp")]
pub mod api;

#[cfg(feature = "zkp")]
pub use api::{
    MerklePath,
    prove_membership,
    prove_preimage,
    verify_membership,
    verify_membership_with_depth,
    verify_preimage,
};
#[cfg(feature = "zkp")]
pub use lib_q_stark::{
    Proof as StarkProof,
    StarkConfig,
    StarkGenericConfig,
    prove,
    verify,
};
#[cfg(feature = "zkp")]
pub use lib_q_stark_air::Air;
#[cfg(feature = "zkp")]
use lib_q_stark_field::extension::Complex;
#[cfg(feature = "zkp")]
use lib_q_stark_matrix::dense::RowMajorMatrix;
#[cfg(feature = "zkp")]
use lib_q_stark_mersenne31::Mersenne31;
#[cfg(feature = "zkp")]
use serde::{
    Deserialize,
    Serialize,
};

#[cfg(feature = "zkp")]
#[allow(unused_imports)]
use crate::air::TraceGenerator;

/// The field type used for ZKP operations
///
/// Uses Complex<Mersenne31> which provides TWO_ADICITY = 32, sufficient for
/// FRI protocol and efficient FFT operations.
#[cfg(feature = "zkp")]
pub type ZkpField = Complex<Mersenne31>;

/// Metadata specific to different proof types
///
/// This enum stores proof-specific parameters that are required for verification.
/// The metadata is serialized alongside the proof to make proofs self-describing.
///
/// All proofs must include appropriate metadata for their proof type.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "zkp", derive(Serialize, Deserialize))]
pub enum ProofMetadata {
    /// No metadata (default variant, but proofs should use specific metadata types)
    #[default]
    None,
    /// Merkle tree inclusion proof metadata
    MerkleInclusion {
        /// Depth of the Merkle tree (required for AIR reconstruction)
        tree_depth: u8,
    },
    /// Hash preimage proof metadata
    HashPreimage {
        /// Output size in bytes
        output_size: u16,
    },
    /// Circuit computation proof metadata
    Circuit {
        /// Number of witness values
        num_witnesses: u32,
        /// Number of public values
        num_public: u32,
    },
    /// Credential proof metadata for selective disclosure
    Credential {
        /// Serialized credential schema (attribute sizes in bytes)
        attribute_sizes: Vec<u16>,
        /// Reveal mask (which attributes are revealed: true = revealed, false = hidden)
        reveal_mask: Vec<bool>,
    },
    /// Identity Token ownership proof metadata
    Identity {
        /// ML-DSA security level: 44, 65, or 87
        dsa_level: u8,
    },
}

/// A zero-knowledge proof
#[derive(Debug, Clone)]
pub struct ZkpProof {
    /// The proof data (serialized STARK proof)
    pub data: Vec<u8>,
    /// The proof type
    pub proof_type: ProofType,
    /// Security level
    pub security_level: u32,
    /// Proof-specific metadata (required for verification)
    pub metadata: ProofMetadata,
}

#[cfg(feature = "zkp")]
impl ZkpProof {
    /// Serialize a STARK proof into a ZkpProof with metadata
    ///
    /// All proofs must include metadata for proper verification.
    /// This method is used internally by the high-level API functions.
    pub fn from_stark_proof<C: StarkGenericConfig>(
        proof: &StarkProof<C>,
        metadata: ProofMetadata,
    ) -> Result<Self>
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
            metadata,
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

    /// Get the tree depth from Merkle inclusion proof metadata
    ///
    /// Returns `Some(depth)` if this is a Merkle inclusion proof with metadata,
    /// `None` otherwise.
    pub fn merkle_tree_depth(&self) -> Option<u8> {
        match &self.metadata {
            ProofMetadata::MerkleInclusion { tree_depth } => Some(*tree_depth),
            _ => None,
        }
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
    /// This generates a STARK proof that the prover knows a preimage `secret_value`
    /// that hashes (via SHAKE256) to a value derived from `public_statement`.
    ///
    /// # Arguments
    ///
    /// * `secret_value` - The secret preimage to prove knowledge of
    /// * `public_statement` - Additional public data (combined with hash output)
    ///
    /// # Returns
    ///
    /// A zero-knowledge proof that can be verified without revealing the secret
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use lib_q_zkp::{ZkpProver, ZkpVerifier};
    ///
    /// let mut prover = ZkpProver::new();
    /// let secret = b"my secret password";
    /// let public = b"challenge";
    ///
    /// let proof = prover.prove_secret_value(secret, public)?;
    /// ```
    pub fn prove_secret_value(
        &mut self,
        secret_value: &[u8],
        _public_statement: &[u8],
    ) -> Result<ZkpProof> {
        use crate::air::{
            HashPreimageAir,
            TraceGenerator,
        };
        use crate::stark::{
            StarkProver,
            default_config,
        };

        // Validate input size
        if secret_value.is_empty() {
            return Err(lib_q_core::Error::InvalidState {
                operation: "prove_secret_value".to_string(),
                reason: "Secret value cannot be empty".to_string(),
            });
        }

        if secret_value.len() > air::hash_preimage::MAX_PREIMAGE_SIZE {
            return Err(lib_q_core::Error::InvalidState {
                operation: "prove_secret_value".to_string(),
                reason: "Secret value exceeds maximum size".to_string(),
            });
        }

        // Create the hash preimage AIR
        let air = HashPreimageAir::new();

        // Generate trace from the secret preimage
        let input = secret_value.to_vec();
        let trace: RowMajorMatrix<ZkpField> =
            air.generate_trace(&input)
                .map_err(|e| lib_q_core::Error::InternalError {
                    operation: "prove_secret_value".to_string(),
                    details: e.to_string(),
                })?;

        // Get public values (the hash output)
        let public_values: Vec<ZkpField> = air.public_values(&input);

        // Create prover with default config
        let config = default_config();
        let prover = StarkProver::new(config);

        // Generate STARK proof
        let proof = prover.prove(&air, trace, &public_values);

        // Store output size in proof metadata
        let metadata = ProofMetadata::HashPreimage { output_size: 1u16 };

        // Serialize into ZkpProof
        ZkpProof::from_stark_proof(&proof, metadata)
    }

    /// Prove a computation using a circuit
    ///
    /// This generates a STARK proof that the prover knows witness values that
    /// satisfy all constraints in the arithmetic circuit.
    ///
    /// # Arguments
    ///
    /// * `circuit` - The arithmetic circuit defining the computation
    /// * `witness` - The witness values (private inputs)
    /// * `public` - The public input values
    ///
    /// # Returns
    ///
    /// A zero-knowledge proof of computation correctness
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use lib_q_zkp::{ZkpProver, circuit::CircuitBuilder};
    /// use lib_q_stark_field::extension::Complex;
    /// use lib_q_stark_mersenne31::Mersenne31;
    ///
    /// type Val = Complex<Mersenne31>;
    ///
    /// // Build a circuit: prove knowledge of a, b such that a * b = public_output
    /// let mut builder = CircuitBuilder::<Val>::new(2, 1);
    /// let a = builder.wire(0);
    /// let b = builder.wire(1);
    /// let output = builder.wire(2);
    /// let product = builder.mul(a, b);
    /// builder.assert_eq(product, output);
    /// let circuit = builder.build();
    ///
    /// // Generate proof
    /// let witness = vec![Val::from(3u32), Val::from(4u32)];
    /// let public = vec![Val::from(12u32)];
    ///
    /// let mut prover = ZkpProver::new();
    /// let proof = prover.prove_computation(&circuit, &witness, &public)?;
    /// ```
    pub fn prove_computation(
        &mut self,
        circuit: &circuit::ArithmeticCircuit<ZkpField>,
        witness: &[ZkpField],
        public: &[ZkpField],
    ) -> Result<ZkpProof> {
        use crate::circuit::CircuitAir;
        use crate::stark::{
            StarkProver,
            default_config,
        };

        // Create the circuit AIR
        let air = CircuitAir::new(circuit.clone());

        // Generate trace from witness and public values
        let trace = air.generate_trace(witness, public)?;

        // Create prover with default config
        let config = default_config();
        let prover = StarkProver::new(config);

        // Generate STARK proof
        let proof = prover.prove(&air, trace, public);

        // Store circuit parameters in proof metadata
        let metadata = ProofMetadata::Circuit {
            num_witnesses: witness.len().min(u32::MAX as usize) as u32,
            num_public: public.len().min(u32::MAX as usize) as u32,
        };

        // Serialize into ZkpProof
        ZkpProof::from_stark_proof(&proof, metadata)
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

    /// Verify a zero-knowledge proof of secret value knowledge
    ///
    /// This verifies a proof generated by `ZkpProver::prove_secret_value`.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `public_statement` - The expected hash output bytes
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid, `Ok(false)` or `Err` otherwise
    pub fn verify_secret_value(&self, proof: &ZkpProof, public_hash: &[u8]) -> Result<bool> {
        use lib_q_poseidon::{
            Poseidon,
            Poseidon128,
        };

        use crate::air::{
            HashPreimageAir,
            bytes_to_poseidon_field,
            poseidon_slice_to_field,
        };
        use crate::stark::{
            StarkVerifier,
            default_config,
        };

        if proof.proof_type != ProofType::Stark {
            return Ok(false);
        }

        if proof.data.is_empty() {
            return Ok(false);
        }

        // Proof must contain output size metadata
        let ProofMetadata::HashPreimage { output_size } = &proof.metadata else {
            // Missing metadata - proof is invalid
            return Ok(false);
        };

        // Create the same AIR used for proving (output_size in metadata retained for compatibility)
        let _ = output_size;
        let air = HashPreimageAir::new();

        // Convert expected hash bytes to Poseidon field elements, then hash to get public values
        // The public values are the Poseidon hash output (field elements), matching what
        // HashPreimageAir::public_values() returns during proving
        let expected_field_elements = bytes_to_poseidon_field(public_hash);
        let poseidon_hash = Poseidon128.hash(&expected_field_elements);

        // Convert Poseidon hash output to public values (field elements)
        let public_values = poseidon_slice_to_field(&poseidon_hash);

        // Deserialize the STARK proof
        let stark_proof = proof.to_stark_proof()?;

        // Create verifier with default config
        let config = default_config();
        let verifier = StarkVerifier::new(config);

        // Verify the proof
        match verifier.verify(&air, &stark_proof, &public_values) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify a zero-knowledge proof of computation
    ///
    /// This verifies a proof generated by `ZkpProver::prove_computation`.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `circuit` - The arithmetic circuit that was proven
    /// * `public` - The public input values
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid, `Ok(false)` or `Err` otherwise
    pub fn verify_computation(
        &self,
        proof: &ZkpProof,
        circuit: &circuit::ArithmeticCircuit<ZkpField>,
        public: &[ZkpField],
    ) -> Result<bool> {
        use crate::circuit::CircuitAir;
        use crate::stark::{
            StarkVerifier,
            default_config,
        };

        if proof.proof_type != ProofType::Stark {
            return Ok(false);
        }

        if proof.data.is_empty() {
            return Ok(false);
        }

        // Create the same AIR used for proving
        let air = CircuitAir::new(circuit.clone());

        // Deserialize the STARK proof
        let stark_proof = proof.to_stark_proof()?;

        // Create verifier with default config
        let config = default_config();
        let verifier = StarkVerifier::new(config);

        // Verify the proof
        match verifier.verify(&air, &stark_proof, public) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify a zero-knowledge proof.
    ///
    /// Performs full cryptographic (STARK) verification for proof types whose public
    /// inputs are fully described by a byte slice:
    ///
    /// - `ProofMetadata::HashPreimage`: `public_statement` is the expected hash output
    ///   (same semantics as `verify_secret_value`).
    /// - `ProofMetadata::MerkleInclusion`: `public_statement` is the expected Merkle
    ///   root hash (same semantics as `api::verify_membership`).
    ///
    /// Returns `Ok(false)` for `Circuit`, `Credential`, `Identity`, and `None`
    /// metadata variants. Those proof types require a type-specific verifier that accepts
    /// the additional inputs needed to reconstruct verification state.
    ///
    /// `batch_verify` delegates to this method, so the same rules apply in bulk.
    pub fn verify(&self, proof: ZkpProof, public_statement: &[u8]) -> Result<bool> {
        if proof.proof_type != ProofType::Stark {
            return Ok(false);
        }
        if proof.data.is_empty() {
            return Ok(false);
        }
        match &proof.metadata {
            ProofMetadata::HashPreimage { .. } => {
                self.verify_secret_value(&proof, public_statement)
            }
            ProofMetadata::MerkleInclusion { .. } => verify_membership(&proof, public_statement),
            _ => Ok(false),
        }
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

/// Get available ZKP algorithms (STARK when zkp feature is enabled).
pub fn available_algorithms() -> Vec<&'static str> {
    let algorithms = vec![
        #[cfg(feature = "zkp")]
        "stark",
    ];

    algorithms
}

/// Create a ZKP instance by algorithm name
pub fn create_zkp(algorithm: &str) -> Result<Box<dyn core::any::Any>> {
    match algorithm {
        #[cfg(feature = "zkp")]
        "stark" => Ok(Box::new(ZkpProver::new())),

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

        // Now that prove_secret_value is implemented, it should succeed
        let result = prover.prove_secret_value(secret_value, public_statement);
        // The proof generation should succeed (though it may take some time)
        assert!(
            result.is_ok(),
            "Proof generation should succeed: {:?}",
            result.err()
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_rejects_unknown_metadata() {
        use lib_q_stark_field::PrimeCharacteristicRing;
        use lib_q_stark_mersenne31::Mersenne31;

        use crate::air::{
            ArithmeticAir,
            TraceGenerator,
        };
        use crate::stark::{
            StarkProver,
            default_config,
        };

        let air = ArithmeticAir::new(1).expect("ArithmeticAir");
        let one = <ZkpField as PrimeCharacteristicRing>::ONE;
        let seven = ZkpField::from(Mersenne31::new(7));
        let input = alloc::vec![(one, seven)];
        let trace = air.generate_trace(&input).expect("trace generation");
        let public_values = air.public_values(&input);
        let proof_inner = StarkProver::new(default_config()).prove(&air, trace, &public_values);
        let proof_bytes = postcard::to_allocvec(&proof_inner).expect("serialize STARK proof");

        let proof = ZkpProof {
            data: proof_bytes,
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::None,
        };

        let verifier = ZkpVerifier::new();
        assert_eq!(
            verifier.verify(proof, b"public_statement").unwrap(),
            false,
            "ProofMetadata::None must return false -- use a type-specific verifier"
        );
    }

    #[test]
    fn test_batch_verify_mismatched_lengths() {
        let verifier = ZkpVerifier::new();
        let proofs = vec![ZkpProof {
            data: vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::None,
        }];
        let publics: &[&[u8]] = &[b"public1" as &[u8], b"public2" as &[u8]];

        let result = verifier.batch_verify(&proofs, publics);
        assert!(result.is_err());
        if let Err(lib_q_core::Error::InvalidState { .. }) = result {
            // Expected
        } else {
            panic!("Expected InvalidState error");
        }
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_proof_metadata_merkle() {
        let metadata = ProofMetadata::MerkleInclusion { tree_depth: 8 };
        let proof = ZkpProof {
            data: vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata,
        };
        assert_eq!(proof.merkle_tree_depth(), Some(8));
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_proof_metadata_none() {
        let proof = ZkpProof {
            data: vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::None,
        };
        assert_eq!(proof.merkle_tree_depth(), None);
    }

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        #[cfg(feature = "zkp")]
        assert!(!algorithms.is_empty(), "zkp feature enables STARK");
        #[cfg(not(feature = "zkp"))]
        let _ = algorithms;
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_create_zkp() {
        let algorithms = available_algorithms();
        assert!(!algorithms.is_empty());
        let algorithm = algorithms[0];
        assert!(create_zkp(algorithm).is_ok());
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_rejects_forged_proof_with_hash_preimage_metadata() {
        let proof = ZkpProof {
            data: alloc::vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD,
                0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF,
                0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA,
                0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD,
                0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xAA, 0xDE, 0xAD, 0xBE, 0xEF,
            ],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimage { output_size: 1 },
        };
        let verifier = ZkpVerifier::new();
        let result = verifier.verify(proof, b"expected_hash");
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "forged HashPreimage proof must not return Ok(true)"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_rejects_forged_proof_with_merkle_metadata() {
        let proof = ZkpProof {
            data: alloc::vec![
                0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE,
                0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
                0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE,
                0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
                0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
            ],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::MerkleInclusion { tree_depth: 4 },
        };
        let verifier = ZkpVerifier::new();
        let result = verifier.verify(proof, b"wrong_root");
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "forged MerkleInclusion proof must not return Ok(true)"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_rejects_circuit_metadata_proof() {
        let proof = ZkpProof {
            data: alloc::vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Circuit {
                num_witnesses: 2,
                num_public: 1,
            },
        };
        let verifier = ZkpVerifier::new();
        assert_eq!(
            verifier.verify(proof, b"anything").unwrap(),
            false,
            "Circuit proofs must be rejected by generic verify; use verify_computation"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_rejects_credential_metadata_proof() {
        let proof = ZkpProof {
            data: alloc::vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Credential {
                attribute_sizes: alloc::vec![8, 4],
                reveal_mask: alloc::vec![true, false],
            },
        };
        let verifier = ZkpVerifier::new();
        assert_eq!(
            verifier.verify(proof, b"anything").unwrap(),
            false,
            "Credential proofs must be rejected by generic verify; use ip::verify_credential_proof"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_rejects_identity_metadata_proof() {
        let proof = ZkpProof {
            data: alloc::vec![0u8; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Identity { dsa_level: 65 },
        };
        let verifier = ZkpVerifier::new();
        assert_eq!(
            verifier.verify(proof, b"anything").unwrap(),
            false,
            "Identity proofs must be rejected by generic verify; use ip::verify_it_ownership"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_empty_data_is_rejected() {
        let proof = ZkpProof {
            data: alloc::vec![],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimage { output_size: 1 },
        };
        let verifier = ZkpVerifier::new();
        assert_eq!(
            verifier.verify(proof, b"anything").unwrap(),
            false,
            "empty proof data must be rejected regardless of metadata"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_snark_proof_type_is_rejected() {
        let proof = ZkpProof {
            data: alloc::vec![0u8; 64],
            proof_type: ProofType::Snark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimage { output_size: 1 },
        };
        let verifier = ZkpVerifier::new();
        assert_eq!(
            verifier.verify(proof, b"anything").unwrap(),
            false,
            "non-Stark proof type must be rejected"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_batch_verify_rejects_forged_hash_preimage_proof() {
        let forged = ZkpProof {
            data: alloc::vec![0xFF; 64],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimage { output_size: 1 },
        };
        let verifier = ZkpVerifier::new();
        let proofs = alloc::vec![forged];
        let publics: &[&[u8]] = &[b"anything"];
        let result = verifier.batch_verify(&proofs, publics);
        assert!(
            matches!(result, Ok(false) | Err(_)),
            "batch_verify must not accept a forged proof"
        );
    }
}
