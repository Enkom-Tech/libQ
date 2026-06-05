#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

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
