//! The prime field `F_p` where `p = 2^31 - 1`.

#![no_std]

extern crate alloc;

mod complex;
mod dft;
mod extension;
mod mds;
mod mersenne_31;
// mod poseidon2; // Removed: non-NIST hash
mod radix_2_dit;
#[cfg(any(test, feature = "test-utils"))]
mod test_permutation;

pub use dft::Mersenne31Dft;
pub use mds::*;
pub use mersenne_31::*;
// pub use poseidon2::*; // Removed: non-NIST hash
pub use radix_2_dit::Mersenne31ComplexRadix2Dit;
#[cfg(any(test, feature = "test-utils"))]
pub use test_permutation::*;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod aarch64_neon;
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub use aarch64_neon::*;

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
mod x86_64_avx2;
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
pub use x86_64_avx2::*;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
mod x86_64_avx512;
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
pub use x86_64_avx512::*;

// no_packing module removed - was only used for poseidon2
