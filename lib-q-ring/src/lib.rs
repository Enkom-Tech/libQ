//! Shared ring arithmetic for ML-DSA / module-lattice constructions over
//! \(R_q = \mathbb{Z}_q[X]/(X^{256}+1)\), \(q = 8\,380\,417\).
//!
//! Portable NTT (Cooley–Tukey forward, Gentleman–Sande inverse with Montgomery
//! scaling) is bit-compatible with the non-`hardened` path in `lib-q-ml-dsa`.
#![no_std]
#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod challenge;
pub mod coeff;
pub mod constants;
pub mod encoding;
pub mod field;

mod generated_invntt;
mod generated_ntt;

pub mod ntt;
pub mod params;
pub mod poly;
pub mod uniform;

#[cfg(feature = "alloc")]
pub mod expand;
#[cfg(feature = "alloc")]
pub mod module;

pub use challenge::sample_in_ball;
#[cfg(feature = "alloc")]
pub use expand::expand_a_from_seed;
pub use field::{
    FieldElementTimesMontgomeryR,
    add_coeffs,
    montgomery_multiply_by_constant,
    montgomery_multiply_coeffs,
    montgomery_multiply_fe_by_fer,
    montgomery_reduce_element,
    reduce_element,
    reduce_poly_simd,
    subtract_coeffs,
};
#[cfg(feature = "alloc")]
pub use module::{
    ModuleMatrix,
    ModuleVec,
};
pub use ntt::{
    intt_montgomery,
    ntt_forward_simd,
    ntt_multiply_montgomery,
};
pub use poly::{
    NttPoly,
    Poly,
};
pub use uniform::{
    sample_uniform_coeff_mod_q,
    sample_uniform_field_coefficient,
    try_uniform_coeff_mod_q_from_u32,
    uniform_mod_u32_rejection_threshold,
};
