//! SIMD dispatch (portable default; AVX2 delegates to portable for duplex).

pub mod portable;
pub mod runtime;
pub mod traits;

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub mod avx2;

#[cfg(all(target_arch = "x86_64", feature = "simd-avx2"))]
pub use avx2::Avx2;
pub use portable::Portable;
pub use traits::DuplexAeadOps;
