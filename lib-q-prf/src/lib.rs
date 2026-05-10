//! Legendre and Gold (power-residue) PRFs over prime fields \(\mathbb{F}_p\).
//!
//! This crate provides constant-time field arithmetic via [`crypto_bigint::modular::FixedMontyForm`]
//! for pilot safe-prime moduli documented in [`params`]. It is intended as a building block for
//! Fiat–Shamir protocols such as DualRing-PRF (QROM), composed at the [`lib-q-ring-sig`] layer.
//!
//! [`lib-q-ring-sig`]: https://github.com/Enkom-Tech/libQ/tree/main/lib-q-ring-sig
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), any(feature = "alloc", feature = "wasm")))]
extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "no_std_panic_handler"))]
mod no_std_panic_handler {
    use core::panic::PanicInfo;

    #[panic_handler]
    #[allow(clippy::empty_loop)]
    fn panic(_info: &PanicInfo) -> ! {
        loop {}
    }
}

pub mod error;
pub mod field;
pub mod gold;
pub mod legendre;
pub mod params;
mod shake;

#[cfg(feature = "wasm")]
mod wasm;

pub use error::PrfError;
pub use field::{
    fp_add,
    fp_mul,
    fp_pow,
    legendre_symbol_monty,
    legendre_symbol_residue,
    to_monty,
    uint_ct_eq_zero,
};
pub use gold::{
    GoldKey256,
    GoldKey512,
    gold_prf_u256,
    gold_prf_u512,
};
pub use legendre::{
    LegendreKey256,
    LegendreKey512,
    legendre_prf_u256,
    legendre_prf_u512,
};
pub use params::{
    GoldPrfParams256,
    GoldPrfParams512,
    LegendrePrfParams256,
    LegendrePrfParams512,
    P256_BE_HEX,
    P512_BE_HEX,
    u256_from_le_bytes,
    u256_to_le_bytes,
    u512_from_le_bytes,
    u512_to_le_bytes,
};
