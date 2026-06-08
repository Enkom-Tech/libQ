//! Quantum Carter-Wegman MAC (qCW-MAC) targeting **splitting unforgeability (SU)**.
//!
//! Construction: keyed epsilon-AXU hash + quantum PRF (Boneh-Zhandry, ePrint 2026/271).
//! Symmetric primitives only (SHAKE256 via [`lib_q_sha3`]).
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

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
