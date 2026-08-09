//! Quantum Carter-Wegman MAC (qCW-MAC) targeting **splitting unforgeability (SU)**.
//!
//! Construction: keyed epsilon-AXU hash + quantum PRF (Boneh-Zhandry, ePrint 2026/271).
//! Symmetric primitives only (SHAKE256 via [`lib_q_sha3`]).
#![forbid(unsafe_code)]
// Conventional shape: no_std unless the `std` feature is explicitly on (not gated behind an
// opt-in `no_std` feature) -- so `--no-default-features` alone gives a genuine no_std build,
// matching the rest of the ecosystem's expectation. The `no_std` feature still exists as a
// convenience alias (pulls in `alloc` + the bundled panic handler for embedded targets).
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
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

pub mod axu;
pub mod error;
pub mod profile;
pub mod qcw_mac;
pub mod qprf;
pub mod wire;

pub use error::MacError;
pub use profile::{
    QCW_MAC_KAT_SCHEMA,
    QCW_MAC_KEY_BYTES,
    QCW_MAC_TAG_BYTES,
};
pub use qcw_mac::{
    QcwMac,
    QcwMacKey,
};

#[cfg(feature = "wasm")]
pub mod wasm;
