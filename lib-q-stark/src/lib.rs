//! A minimal univariate STARK framework.
//!
//! This module provides a complete implementation of zk-STARK (Zero-Knowledge Scalable
//! Transparent Arguments of Knowledge) proofs, adapted from Plonky3 for lib-Q's
//! post-quantum security requirements.
//!
//! # Security Considerations
//!
//! ## Post-Quantum Security
//! This implementation uses only NIST-approved post-quantum cryptographic primitives:
//! - **SHAKE256** for all hash operations (FIPS 202, NIST-approved)
//! - **Complex<Mersenne31>** field for efficient arithmetic (TWO_ADICITY = 32)
//! - **ethSTARK** protocol for strong security guarantees
//!
//! ## Constant-Time Operations
//! Field operations use constant-time implementations where secrets are involved:
//! - Use `constant_time::constant_time_is_zero()` for secret comparisons
//! - Use `constant_time::constant_time_eq()` for secret equality checks
//! - Field implementations that support `ConstantTimeEq` (e.g., `Complex<Mersenne31>`) provide
//!   constant-time equality comparison
//!
//! **Warning**: The default `Field::is_zero()` and `Field::is_one()` methods use
//! standard equality which may leak timing information. Always use constant-time
//! operations for secret values.
//!
//! ## Memory Safety and Zeroization
//! Secret witness data is automatically zeroized when dropped:
//! - `RowMajorMatrix<F: Field + Zeroize>` automatically zeroizes on drop
//! - `SecretWitness` wrapper provides additional protection for witness traces
//! - `SecretFieldElement` ensures individual secret values are cleared
//! - All intermediate values in proof generation are zeroized when dropped
//!
//! **Best Practice**: Wrap sensitive trace data in `SecretWitness` before proof generation:
//! ```ignore
//! use lib_q_stark::secret::SecretWitness;
//! let secret_trace = SecretWitness::new(trace);
//! let proof = prove(config, air, secret_trace.trace(), public_values);
//! // trace is automatically zeroized when secret_trace is dropped
//! ```
//!
//! ## Input Validation
//! All public APIs validate inputs to prevent:
//! - Memory exhaustion attacks (maximum trace dimensions enforced)
//! - DoS attacks (maximum proof size and public values count)
//! - Invalid state errors (power-of-2 checks, dimension consistency)
//!
//! ## Side-Channel Resistance
//! While constant-time operations prevent timing attacks, proof generation may still
//! leak information through:
//! - Memory access patterns
//! - Cache timing
//! - Power consumption
//!
//! For maximum security, consider additional mitigations in production deployments.
//!
//! ## Zero-Knowledge Property
//! The STARK implementation provides zero-knowledge proofs when configured with
//! a hiding polynomial commitment scheme (PCS). The zero-knowledge property ensures
//! that proofs reveal no information about the witness beyond what is implied by
//! the public statement.
//!
//! ## Threat Model Alignment
//! This implementation aligns with lib-Q's security model:
//! - Assumes quantum computers exist (post-quantum security)
//! - Assumes unlimited computational adversaries
//! - Protects against side-channel attacks (constant-time, zeroization)
//! - Ensures memory safety (Rust's ownership model, zeroization)
//!
//! # Secure Usage Guidelines
//!
//! 1. **Witness Protection**: Always use `SecretWitness` for sensitive trace data
//! 2. **Constant-Time Operations**: Use `constant_time` module functions for secret comparisons
//! 3. **Input Validation**: All inputs are validated, but verify dimensions match your AIR
//! 4. **Error Handling**: Error messages are sanitized to prevent information leakage
//! 5. **Never Log Secrets**: Avoid logging or debug-printing secret values
//! 6. **Zeroization**: Trust the automatic zeroization, but be aware of move semantics

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod check_constraints;
mod config;
mod folder;
mod preprocessed;
mod proof;
mod prover;
mod secret;
mod sub_builder;
mod symbolic_builder;
mod symbolic_expression;
mod symbolic_variable;
mod verifier;

pub use check_constraints::*;
pub use config::*;
pub use folder::*;
pub use preprocessed::*;
pub use proof::*;
pub use prover::*;
pub use secret::*;
pub use sub_builder::*;
pub use symbolic_builder::*;
pub use symbolic_expression::*;
pub use symbolic_variable::*;
pub use verifier::{
    VerificationError,
    all_fri_reduced_openings_for_query,
    initial_fri_eval_for_query,
    verify,
    verify_from_bytes,
    verify_with_preprocessed,
};
