//! Lattice trapdoor machinery for the round-optimal GPV-preimage blind signature.
//!
//! Layers (built bottom-up, each independently tested):
//! 1. [`gaussian`] — discrete Gaussian sampler `D_{Z,s,c}`.
//! 2. [`gadget`] — gadget vector `g = (1, b, …, b^{k-1})`, exact decomposition, and the coset
//!    `G`-preimage Gaussian sampler.
//!
//! The whole subtree is **std-gated** (the base sampler needs `f64::exp`) and **research-grade**:
//! samplers are not constant-time. See the crate `LIBQ_API.md` for the scheme choice and the
//! assumptions surfaced for RED-zone review.

// Index-based loops are the natural expression for the matrix/vector/FFT math here.
#![allow(clippy::needless_range_loop)]

pub mod gadget;
pub mod gaussian;
pub mod perturb;
pub mod ring;
mod rngbuf;
pub mod scheme;
pub mod trapdoor;
