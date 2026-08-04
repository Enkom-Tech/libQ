//! A framework for various (not necessarily hiding) cryptographic commitment schemes.

#![no_std]

extern crate alloc;

mod adapters;
mod domain;
mod mmcs;
mod pcs;

/// A mock, non-hiding PCS (`TrivialPcs`) for exercising the `Pcs`/`PolynomialSpace` traits,
/// ported from upstream Plonky3's `p3-commit::testing`.
///
/// `#[cfg(test)]` ONLY, deliberately — do not re-add a `test-utils` feature exposing this to
/// downstream crates without first fixing the publish order. Upstream gates it on `test` OR an
/// opt-in feature, but that feature would need `lib-q-stark-challenger` and `lib-q-stark-dft` as
/// optional dependencies, and `lib-q-stark-challenger` transitively needs `lib-q-stark-mersenne31`
/// and the SHAKE/SHA3 adapters, which publish in LATER tiers than this crate. That ordering is not
/// satisfiable: it broke the v0.0.10 release after 51 crates had already gone to crates.io
/// (`failed to select a version for the requirement lib-q-stark-challenger = "^0.0.10"`).
/// Exposing it downstream requires moving this crate after tier 9 first.
#[cfg(test)]
pub mod testing;

pub use adapters::*;
pub use domain::*;
pub use mmcs::*;
pub use pcs::*;
