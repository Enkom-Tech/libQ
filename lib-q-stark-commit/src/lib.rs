//! A framework for various (not necessarily hiding) cryptographic commitment schemes.

#![no_std]

extern crate alloc;

mod adapters;
mod domain;
mod mmcs;
mod pcs;

/// A mock, non-hiding PCS (`TrivialPcs`) for exercising the `Pcs`/`PolynomialSpace` traits in
/// downstream crates' own tests, ported from upstream Plonky3's `p3-commit::testing`.
///
/// Gated the same way upstream gates it (`test` OR the opt-in `test-utils` feature) so that both
/// this crate's own tests and any downstream crate's tests can reach it.
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use adapters::*;
pub use domain::*;
pub use mmcs::*;
pub use pcs::*;
