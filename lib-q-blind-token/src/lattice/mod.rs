//! Lattice trapdoor machinery for the round-optimal GPV-preimage blind signature.
//!
//! Layers (built bottom-up, each independently tested):
//! 1. [`gaussian`] — discrete Gaussian sampler `D_{Z,s,c}` (branchless fast path for large `σ`).
//! 2. [`gaussian_ct`] — isochronous (constant-time) `D_{Z,s,c}` for the small-width secret-bearing
//!    sites (trapdoor `R`, attribute, gadget coset, perturbation rounding).
//! 3. [`gadget`] — gadget vector `g = (1, b, …, b^{k-1})`, exact decomposition, and the coset
//!    `G`-preimage Gaussian sampler.
//!
//! The whole subtree is **std-gated** (the samplers need `f64`). The small-width samplers are now
//! isochronous ([`gaussian_ct`]); the large-`σ` continuous-rounding path is branchless. See the
//! crate `LIBQ_API.md` §7 for the residual (non-algorithmic) timing assumptions.

// Index-based loops are the natural expression for the matrix/vector/FFT math here.
#![allow(clippy::needless_range_loop)]

pub mod gadget;
pub mod gaussian;
pub mod gaussian_ct;
pub mod perturb;
pub mod ring;
mod rngbuf;
pub mod scheme;
pub mod trapdoor;
