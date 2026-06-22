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
//! The implementation uses **`Complex<Mersenne31>`** as the base field, which provides:
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
//!
//! ## Testing
//!
//! - **Recursive aggregation**: The test `test_recursive_verifier_trace_satisfies_constraints_then_prove_verify` (in `aggregation_tests`) runs the full prove → aggregate → verify pipeline. It is slow in dev (unoptimized); run with `--release` for completion in a few minutes. CI runs this test in release with a 15-minute timeout.
//! - **Merkle tree builder**: `tests/merkle_tree_builder_tests.rs` uses [`stark::fast_proof_config`] for prove/verify round-trips (fast FRI); wrong-root and cross-tree rejection use [`stark::default_config`] because minimal FRI is not sound for those negatives.
//! - **Merkle tree certificates**: Create/use and security checks (wrong root, wrong depth, cross-tree) are covered by `tests/merkle_certificate_tests.rs`. Additional Merkle and group-membership tests live in `air_integration` and `ip_soundness_tests`.

#![cfg_attr(not(feature = "std"), no_std)]
// Bounds on generic type parameters in aliases are not enforced by the type checker (Rust RFC
// follow-up); we still document constraints via `C: StarkGenericConfig` / `F: Field` on aliases.
#![allow(type_alias_bounds)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::get_first)]
#![allow(clippy::iter_cloned_collect)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_lazy_evaluations)]

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
/// Plonky3-derived components (Keccak AIR, lookup, batch STARK, etc.).
///
/// Enabled when any of `plonky` or the granular `plonky-*` features is on (each pulls in
/// `lib-q-plonky` with the corresponding sub-features; `plonky` enables the full set).
#[cfg(any(
    feature = "plonky",
    feature = "plonky-keccak-air",
    feature = "plonky-lookup",
    feature = "plonky-uni-stark",
    feature = "plonky-batch-stark",
))]
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

/// Poseidon Merkle tree builder (compatible with MerkleInclusionAir)
#[cfg(feature = "zkp")]
pub mod merkle;

/// High-level lib q API
#[cfg(feature = "zkp")]
pub mod api;

#[cfg(feature = "zkp")]
pub mod wire;

/// Unlinkable set-membership proofs (`libq.zkfri.membership.v0`): Semaphore/Tornado
/// nullifier shape over the Poseidon-256 wide-digest Merkle tree. RED (ADR 113 freeze-gate).
#[cfg(feature = "zkp")]
pub mod membership;

#[cfg(feature = "zkp")]
pub use api::{
    MerklePath,
    build_merkle_tree,
    prove_membership,
    prove_membership_with_config,
    prove_preimage,
    prove_preimage_nist,
    verify_membership,
    verify_membership_with_config,
    verify_membership_with_depth,
    verify_membership_with_depth_and_config,
    verify_preimage,
    verify_preimage_nist,
};

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(feature = "zkp")]
pub use lib_q_stark::{
    Proof as StarkProof,
    StarkConfig,
    StarkGenericConfig,
    check_constraints,
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
pub use merkle::PoseidonMerkleTree;
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
/// Uses `Complex<Mersenne31>` which provides TWO_ADICITY = 32, sufficient for
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
    /// Hash preimage proof metadata (Poseidon-128)
    HashPreimage {
        /// Output size in bytes
        output_size: u16,
    },
    /// NIST hash preimage proof metadata (cSHAKE256)
    HashPreimageNist {
        /// Output size in bytes (e.g. 32 for cSHAKE256)
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
    /// Recovery policy threshold proof metadata
    RecoveryPolicy {
        /// Number of keys in policy
        key_count: u32,
        /// Circuit air id
        air_id: u8,
    },
    /// Unlinkable set-membership proof metadata (`libq.zkfri.membership.v0`)
    UnlinkableMembership {
        /// Real Merkle path depth. The verifier authenticates this against the proof's actual
        /// STARK trace height so the declared depth cannot be relabelled (the depth-confusion
        /// guard; see `membership::verify_unlinkable_membership_with_config`).
        tree_depth: u8,
        /// Wide-digest width in field elements (5 for Poseidon-256)
        digest_width: u8,
        /// Whether the proof was produced with the hiding (zero-knowledge) PCS. Selects the
        /// STARK config type at verification — a ZK proof (`StarkProof<ZkConfig>`) and a
        /// transparent proof (`StarkProof<DefaultConfig>`) are distinct serialized types.
        zk: bool,
    },
}

/// A zero-knowledge proof
#[derive(Debug, Clone)]
#[cfg_attr(feature = "zkp", derive(serde::Serialize, serde::Deserialize))]
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
            ProofMetadata::UnlinkableMembership { tree_depth, .. } => Some(*tree_depth),
            _ => None,
        }
    }
}

/// Types of zero-knowledge proofs supported by lib-Q
///
/// Only NIST-approved post-quantum proof systems are included.
/// Classical schemes (SNARKs, Bulletproofs) are intentionally excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zkp", derive(serde::Serialize, serde::Deserialize))]
pub enum ProofType {
    /// zk-STARK proof (transparent, post-quantum secure)
    Stark,
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
    /// whose **Poseidon-128** hash equals the public commitment. The proof uses
    /// Poseidon for constraint encoding (industry-standard for STARKs; e.g. StarkWare,
    /// RISC Zero, Succinct). For a NIST-only hash, use [`prove_secret_value_nist`](ZkpProver::prove_secret_value_nist).
    ///
    /// # Arguments
    ///
    /// * `secret_value` - The secret preimage to prove knowledge of
    /// * `public_statement` - Additional public data (currently unused; reserved for future use)
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
        let proof = prover.prove(&air, trace, &public_values).map_err(|e| {
            lib_q_core::Error::InternalError {
                operation: "STARK proof generation".to_string(),
                details: e.to_string(),
            }
        })?;

        // Store output size in proof metadata
        let metadata = ProofMetadata::HashPreimage { output_size: 1u16 };

        // Serialize into ZkpProof
        ZkpProof::from_stark_proof(&proof, metadata)
    }

    /// Prove knowledge of a secret value using NIST cSHAKE256 (100% NIST compliance)
    ///
    /// Same semantics as [`prove_secret_value`](ZkpProver::prove_secret_value) but uses
    /// cSHAKE256 with domain `b"HashPreimageNistAir"` for the commitment. Use this when
    /// NIST-only hashes are required; prover cost is higher than Poseidon-based proofs.
    ///
    /// # Arguments
    ///
    /// * `secret_value` - The secret preimage to prove knowledge of
    /// * `_public_statement` - Reserved for future use
    ///
    /// # Status
    ///
    /// NOT IMPLEMENTED. The underlying [`HashPreimageNistAir`](crate::air::HashPreimageNistAir)
    /// does not yet encode Keccak-f / cSHAKE256 constraints, so a generated proof would not
    /// soundly bind the secret to the public hash. This function therefore returns
    /// [`Error::NotImplemented`](lib_q_core::Error::NotImplemented) until the constraints exist.
    pub fn prove_secret_value_nist(
        &mut self,
        secret_value: &[u8],
        public_statement: &[u8],
    ) -> Result<ZkpProof> {
        // SOUNDNESS GATE: cSHAKE256/Keccak-f AIR constraints are not implemented yet (see
        // `crate::air::hash_preimage_nist`). A proof from the current AIR would not bind the
        // secret to the public hash, so we refuse rather than emit a proof that proves nothing.
        // Once real Keccak-f constraints exist, replace this with the trace-generation and
        // STARK-proving flow used by `prove_secret_value`.
        let _ = (secret_value, public_statement);
        Err(lib_q_core::Error::NotImplemented {
            feature: "NIST (cSHAKE256) preimage proofs: Keccak-f AIR constraints not implemented"
                .to_string(),
        })
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
        let proof =
            prover
                .prove(&air, trace, public)
                .map_err(|e| lib_q_core::Error::InternalError {
                    operation: "STARK proof generation".to_string(),
                    details: e.to_string(),
                })?;

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

    /// Prove knowledge of a secret value (NIST variant)
    pub fn prove_secret_value_nist(
        &mut self,
        _secret_value: &[u8],
        _public_statement: &[u8],
    ) -> Result<ZkpProof> {
        Err(lib_q_core::Error::NotImplemented {
            feature: "ZKP feature not enabled".to_string(),
        })
    }
}

/// Crate-private helper for NIST secret value verification. Used by both
/// `ZkpVerifier::verify` and `ZkpVerifier::verify_secret_value_nist`.
#[cfg(feature = "zkp")]
fn verify_secret_value_nist_impl(proof: &ZkpProof, expected_hash: &[u8]) -> Result<bool> {
    if proof.proof_type != ProofType::Stark {
        return Ok(false);
    }
    if proof.data.is_empty() {
        return Ok(false);
    }

    let ProofMetadata::HashPreimageNist { .. } = &proof.metadata else {
        return Ok(false);
    };

    // SOUNDNESS GATE: the NIST AIR has no Keccak-f constraints yet (see
    // `crate::air::hash_preimage_nist`), so a "valid" proof would prove nothing. Refuse to
    // verify NIST proofs rather than accept them. Once the constraints exist, restore the
    // StarkVerifier flow against `expected_hash_to_public_values(expected_hash)`.
    let _ = expected_hash;
    Err(lib_q_core::Error::NotImplemented {
        feature: "NIST (cSHAKE256) preimage proofs: Keccak-f AIR constraints not implemented"
            .to_string(),
    })
}

#[cfg(feature = "zkp")]
impl ZkpVerifier {
    /// Create a new ZKP verifier
    pub fn new() -> Self {
        Self {}
    }

    /// Verify a zero-knowledge proof of secret value (preimage) knowledge
    ///
    /// This verifies a proof generated by [`ZkpProver::prove_secret_value`]. The verifier
    /// recomputes the public Poseidon commitment from the **preimage**, so the caller passes
    /// the same secret preimage that was given to the prover (NOT the hash output). The proof
    /// then attests that the prover knew a preimage hashing to that commitment.
    /// For NIST proofs use [`verify_secret_value_nist`](ZkpVerifier::verify_secret_value_nist).
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `preimage` - The secret preimage (same bytes passed to `prove_secret_value`); the
    ///   verifier hashes it with Poseidon-128 to reconstruct the public commitment
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid, `Ok(false)` or `Err` otherwise
    pub fn verify_secret_value(&self, proof: &ZkpProof, preimage: &[u8]) -> Result<bool> {
        use crate::air::{
            HashPreimageAir,
            TraceGenerator,
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

        // Reconstruct the public commitment exactly as the prover did, from the preimage.
        // Using the AIR's own `public_values` guarantees the same padding/encoding rules.
        let public_values: Vec<ZkpField> = air.public_values(&preimage.to_vec());

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

    /// Verify a NIST (cSHAKE256) secret value proof
    ///
    /// Verifies a proof from [`prove_secret_value_nist`](ZkpProver::prove_secret_value_nist).
    /// `expected_hash` is the raw 32-byte cSHAKE256 output (same as used in proving).
    pub fn verify_secret_value_nist(&self, proof: &ZkpProof, expected_hash: &[u8]) -> Result<bool> {
        verify_secret_value_nist_impl(proof, expected_hash)
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
    /// - `ProofMetadata::HashPreimageNist`: `public_statement` is the expected cSHAKE256
    ///   hash output (same semantics as `verify_secret_value_nist`).
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
            ProofMetadata::HashPreimageNist { .. } => {
                verify_secret_value_nist_impl(&proof, public_statement)
            }
            ProofMetadata::MerkleInclusion { .. } => verify_membership(&proof, public_statement),
            ProofMetadata::UnlinkableMembership { .. } => {
                membership::verify_unlinkable_membership_bytes(&proof, public_statement)
            }
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

    /// Verify a NIST secret value proof
    pub fn verify_secret_value_nist(
        &self,
        _proof: &ZkpProof,
        _expected_hash: &[u8],
    ) -> Result<bool> {
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
    fn test_nist_secret_value_not_implemented() {
        // The NIST AIR has no Keccak-f constraints, so prove/verify must refuse rather
        // than emit/accept an unsound proof.
        let secret = b"nist_secret_value";
        let mut prover = ZkpProver::new();
        assert!(
            matches!(
                prover.prove_secret_value_nist(secret, b""),
                Err(lib_q_core::Error::NotImplemented { .. })
            ),
            "NIST prove must return NotImplemented"
        );

        let verifier = ZkpVerifier::new();
        let mut dummy = ZkpProof {
            data: alloc::vec![1u8; 8],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimageNist { output_size: 32 },
        };
        assert!(
            matches!(
                verifier.verify_secret_value_nist(&dummy, &[0u8; 32]),
                Err(lib_q_core::Error::NotImplemented { .. })
            ),
            "NIST verify must return NotImplemented"
        );
        // Generic verify() dispatches to the NIST impl, which must also refuse.
        dummy.data = alloc::vec![1u8; 8];
        assert!(
            matches!(
                verifier.verify(dummy, &[0u8; 32]),
                Err(lib_q_core::Error::NotImplemented { .. })
            ),
            "verify() must return NotImplemented for NIST proofs"
        );
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_poseidon_proof_rejected_by_nist_verifier() {
        let secret = b"poseidon_only";
        let mut prover = ZkpProver::new();
        let proof = prover
            .prove_secret_value(secret, b"")
            .expect("Poseidon prove");
        let verifier = ZkpVerifier::new();
        assert!(
            !verifier
                .verify_secret_value_nist(&proof, &[0u8; 32])
                .unwrap(),
            "Poseidon proof must not be accepted by NIST verifier"
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
        let proof_inner = StarkProver::new(default_config())
            .prove(&air, trace, &public_values)
            .expect("prove");
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
    fn test_proof_type_only_stark_exists() {
        let _stark = ProofType::Stark;
        // ProofType::Snark and ProofType::Bulletproof have been removed.
        // Only NIST-approved post-quantum proof systems are supported.
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

    #[cfg(feature = "zkp")]
    #[test]
    fn test_prove_secret_value_rejects_empty_and_oversized_input() {
        let mut prover = ZkpProver::new();
        let empty = prover.prove_secret_value(b"", b"");
        assert!(empty.is_err());

        let oversized = vec![0u8; air::hash_preimage::MAX_PREIMAGE_SIZE + 1];
        let too_large = prover.prove_secret_value(&oversized, b"");
        assert!(too_large.is_err());
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_prove_secret_value_nist_rejects_empty_and_oversized_input() {
        let mut prover = ZkpProver::new();
        let empty = prover.prove_secret_value_nist(b"", b"");
        assert!(empty.is_err());

        let oversized = vec![0u8; air::hash_preimage_nist::MAX_PREIMAGE_SIZE + 1];
        let too_large = prover.prove_secret_value_nist(&oversized, b"");
        assert!(too_large.is_err());
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_secret_value_rejects_invalid_proof_shape_inputs() {
        let verifier = ZkpVerifier::new();
        let non_stark = ZkpProof {
            data: vec![1u8; 16],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimageNist { output_size: 32 },
        };
        assert!(!verifier.verify_secret_value(&non_stark, b"hash").unwrap());

        let empty = ZkpProof {
            data: vec![],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimage { output_size: 1 },
        };
        assert!(!verifier.verify_secret_value(&empty, b"hash").unwrap());
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_secret_value_nist_rejects_wrong_metadata_and_bad_bytes() {
        let verifier = ZkpVerifier::new();
        let wrong_meta = ZkpProof {
            data: vec![1u8; 16],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimage { output_size: 1 },
        };
        assert!(
            !verifier
                .verify_secret_value_nist(&wrong_meta, &[0u8; 32])
                .unwrap()
        );

        // A proof carrying NIST metadata reaches the soundness gate, which refuses to
        // verify (NIST constraints not implemented) rather than returning a boolean.
        let nist_meta = ZkpProof {
            data: vec![0xAA; 16],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::HashPreimageNist { output_size: 32 },
        };
        assert!(matches!(
            verifier.verify_secret_value_nist(&nist_meta, &[0u8; 32]),
            Err(lib_q_core::Error::NotImplemented { .. })
        ));
    }

    #[cfg(feature = "zkp")]
    #[test]
    fn test_verify_computation_rejects_empty_or_non_stark_data() {
        use crate::circuit::CircuitBuilder;

        let verifier = ZkpVerifier::new();
        let circuit = CircuitBuilder::<ZkpField>::new(1, 0).build();

        let empty = ZkpProof {
            data: vec![],
            proof_type: ProofType::Stark,
            security_level: 1,
            metadata: ProofMetadata::Circuit {
                num_witnesses: 1,
                num_public: 0,
            },
        };
        assert!(!verifier.verify_computation(&empty, &circuit, &[]).unwrap());
    }
}
