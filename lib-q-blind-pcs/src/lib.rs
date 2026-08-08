//! Experimental blind commitment demo. The commitment hash is SHA3-256; commitments from
//! 0.0.6-0.0.10 used SHA-256 and do not verify here (see README).
#![forbid(unsafe_code)]

#[cfg(feature = "blind-pcs")]
pub mod blind_pcs;

#[cfg(feature = "blind-pcs")]
pub use blind_pcs::{
    BlindOpening,
    blind_commit,
    blind_open,
    verify,
};

#[cfg(feature = "wasm")]
pub mod wasm;
