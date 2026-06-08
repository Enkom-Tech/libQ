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
