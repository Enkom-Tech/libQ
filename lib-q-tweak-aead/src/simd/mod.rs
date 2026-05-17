//! SIMD helpers: portable always; AVX2 batched Keccak on x86_64.

pub mod portable;
pub mod runtime;
pub mod traits;

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub mod avx2;
#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub mod avx2_keccak;

pub use portable::Portable;
pub use traits::TweakAeadStreamOps;
