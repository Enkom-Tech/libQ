#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(not(feature = "std"))]
compile_error!(
    "lib-q-double-kem currently requires the `std` feature because lib-q-ml-kem \
depends on runtime allocator/panic support in this integration path."
);

pub mod double_kem;
pub mod error;
pub mod profile;
pub mod wire;

pub use double_kem::{
    ck_fo_upgrade,
    double_decap,
    double_encap,
};
pub use error::DoubleKemError;
pub use profile::{
    BASELINE_DOUBLE_ML_KEM_768_CIPHERTEXT_BYTES,
    DOUBLE_KEM_KAT_SCHEMA,
    MAUL_HINT_BYTES,
    MAUL_WIRE_BODY_BYTES,
    MaulProfileV1,
    WIRE_BUDGET_MAUL_ENCAP_BYTES,
};
pub use wire::MaulEncapWire;
