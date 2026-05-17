#![no_std]

extern crate alloc;

mod data_traits;
pub mod dft;
mod extension;
mod mds;
mod monty_31;
// mod poseidon2; // Removed: non-NIST hash
mod utils;
pub use data_traits::*;
pub use mds::*;
pub use monty_31::*;
// pub use poseidon2::*; // Removed: non-NIST hash

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

#[cfg(not(any(
    all(target_arch = "aarch64", target_feature = "neon"),
    all(target_arch = "x86_64", target_feature = "avx2",),
)))]
mod no_packing;
#[cfg(not(any(
    all(target_arch = "aarch64", target_feature = "neon"),
    all(target_arch = "x86_64", target_feature = "avx2",),
)))]
pub(crate) use no_packing::{
    base_mul_packed,
    octic_mul_packed,
    quartic_mul_packed,
    quintic_mul_packed,
};
