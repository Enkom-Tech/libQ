//! Batch STARK prover and verifier (multiple AIR instances, shared LogUp).
//!
//! # Security Considerations
//!
//! ## Post-Quantum Security
//! Same as uni-stark: SHAKE256, FRI-based PCS; no classical-only primitives.
//! ## Constant-Time
//! Use constant-time operations for secret witness data in any instance.
//! ## Memory and Zeroization
//! Wrap each instance’s trace in a zeroizing type when sensitive; supports preprocessing.
//! ## Input Validation
//! Per-instance limits inherited from uni-stark; batch structure validated.
//! ## Side-Channel Resistance
//! Same guidance as uni-stark; multi-AIR batching does not weaken resistance.
//! ## Threat Model
//! Quantum adversaries; multi-AIR batching with shared LogUp and optional preprocessing.

#![no_std]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::type_complexity)]

extern crate alloc;

#[cfg(debug_assertions)]
pub mod check_constraints;
pub mod common;
pub mod config;
pub mod folder;
pub mod proof;
pub mod prover;
pub mod symbolic;
pub mod verifier;

pub use common::{
    CommonData,
    ProverData,
    ProverOnlyData,
    get_perm_challenges,
};
pub use config::{
    Challenge,
    Commitment,
    Domain,
    PackedChallenge,
    PackedVal,
    PcsError,
    PcsProof,
    StarkGenericConfig,
    Val,
};
pub use lib_q_plonky_uni_stark::{
    OpenedValues,
    VerificationError,
};
pub use proof::{
    BatchCommitments,
    BatchOpenedValues,
    BatchProof,
};
pub use prover::{
    StarkInstance,
    prove_batch,
};
pub use verifier::verify_batch;
