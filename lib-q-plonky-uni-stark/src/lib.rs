//! Univariate STARK prover and verifier (single AIR).
//!
//! # Security Considerations
//!
//! ## Post-Quantum Security
//! SHAKE256 and FRI-based transparent PCS; no classical-only primitives.
//! ## Constant-Time
//! Use constant-time field operations for secret witness data.
//! ## Memory and Zeroization
//! Wrap sensitive trace data in a zeroizing wrapper (e.g. `SecretWitness`) before proving.
//! ## Input Validation
//! DoS limits on trace height/width and public values; proof size limits in verifier.
//! ## Side-Channel Resistance
//! Avoid branching on secrets; constant-time comparisons where applicable.
//! ## Threat Model
//! Quantum adversaries; unlimited computation. For multi-instance batching see `lib-q-plonky-batch-stark`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod check_constraints;
pub mod config;
pub mod folder;
pub mod preprocessed;
pub mod proof;
pub mod prover;
pub mod sub_builder;
pub mod symbolic;
pub mod verifier;

pub use check_constraints::{
    DebugConstraintBuilder,
    check_constraints,
};
pub use config::*;
pub use folder::*;
pub use preprocessed::*;
pub use proof::*;
pub use prover::{
    ProverError,
    prove,
    prove_with_preprocessed,
    quotient_values,
};
pub use sub_builder::*;
pub use symbolic::{
    AirLayout,
    ConstraintLayout,
    SymbolicAirBuilder,
    get_constraint_layout,
    get_log_num_quotient_chunks,
    get_symbolic_constraints,
};
pub use verifier::*;
