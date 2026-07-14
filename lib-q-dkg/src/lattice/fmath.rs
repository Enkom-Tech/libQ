//! `f64` transcendental/rounding operations, shimmed for `no_std`.
//!
//! Under `std` these are the standard-library intrinsics (behavior identical to the pre-`no_std`
//! crate); under `no_std` they come from `libm`. The two may differ in the last ulp — the samplers'
//! output *distributions* are unaffected (the affected probabilities are `≲ 2⁻⁵²`), but sampler
//! output streams are therefore not guaranteed bit-identical across the `std`/`no_std` boundary.
//! Nothing wire-frozen depends on sampler streams: proofs/commitments verify by their algebraic
//! relations, and the KEM consumers' FO paths are integer-only by construction.

#[cfg(feature = "std")]
mod imp {
    #[inline]
    pub fn exp(x: f64) -> f64 {
        x.exp()
    }
    #[inline]
    pub fn ln(x: f64) -> f64 {
        x.ln()
    }
    #[inline]
    pub fn sqrt(x: f64) -> f64 {
        x.sqrt()
    }
    #[inline]
    pub fn cos(x: f64) -> f64 {
        x.cos()
    }
    #[inline]
    pub fn floor(x: f64) -> f64 {
        x.floor()
    }
    #[inline]
    pub fn ceil(x: f64) -> f64 {
        x.ceil()
    }
    #[inline]
    pub fn round(x: f64) -> f64 {
        x.round()
    }
}

#[cfg(not(feature = "std"))]
mod imp {
    #[inline]
    pub fn exp(x: f64) -> f64 {
        libm::exp(x)
    }
    #[inline]
    pub fn ln(x: f64) -> f64 {
        libm::log(x)
    }
    #[inline]
    pub fn sqrt(x: f64) -> f64 {
        libm::sqrt(x)
    }
    #[inline]
    pub fn cos(x: f64) -> f64 {
        libm::cos(x)
    }
    #[inline]
    pub fn floor(x: f64) -> f64 {
        libm::floor(x)
    }
    #[inline]
    pub fn ceil(x: f64) -> f64 {
        libm::ceil(x)
    }
    #[inline]
    pub fn round(x: f64) -> f64 {
        libm::round(x)
    }
}

pub(crate) use imp::{
    ceil,
    cos,
    exp,
    floor,
    ln,
    round,
    sqrt,
};
