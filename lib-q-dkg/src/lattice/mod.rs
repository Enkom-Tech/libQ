//! Self-contained lattice machinery for the binding dealerless DKG.
//!
//! Layers (built bottom-up, each independently tested):
//! 1. [`gaussian`] — discrete Gaussian sampler `D_{Z,s,c}` (FS-proof mask).
//! 2. [`ring`] — `R_q = Z_q[X]/(X^N+1)` (`N = 1024`, `q ≈ 2^48`) negacyclic NTT.
//! 3. [`bdlop`] — BDLOP commitment (message-in-clear, statistically binding) + the Fiat–Shamir
//!    proof of correct sharing that makes the no-dealer check bind the share *value*.
//!
//! The subtree is `no_std + alloc`-capable (`f64` math comes from `libm` when `std` is off — see
//! [`fmath`]; lazy tables use `once_cell::race`) and **research-grade**: samplers are not
//! constant-time. See the crate `LIBQ_API.md` for the scheme choice and RED-zone caveats.

// Index-based loops are the natural expression for the matrix/vector math here.
#![allow(clippy::needless_range_loop)]

pub mod bdlop;
pub(crate) mod fmath;
pub mod gaussian;
pub mod ring;
pub mod rngbuf;
