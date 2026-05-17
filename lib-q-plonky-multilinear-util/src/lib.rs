//! Multilinear utilities for polynomial identity testing (e.g. `eq_batch`).
//!
//! # Security Considerations
//!
//! ## Post-Quantum Security
//! Purely algebraic; no cryptographic assumptions.
//! ## Constant-Time
//! Use constant-time equality when testing on secret values.
//! ## Memory and Zeroization
//! Callers responsible for zeroizing secret polynomial coefficients if needed.
//! ## Input Validation
//! Callers must ensure dimensions and field consistency.
//! ## Side-Channel Resistance
//! `eq_batch` and similar helpers used in polynomial identity testing; avoid leaking intermediate results.
//! ## Threat Model
//! No standalone threat model; security depends on the surrounding proof system.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

extern crate alloc;

pub mod eq_batch;
