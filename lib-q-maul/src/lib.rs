#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

extern crate alloc;

pub mod arith;
pub mod codec;
pub mod error;
pub mod hash;
pub mod kem;
pub mod params;
pub mod pke;
pub mod sample;

pub use error::MaulError;
pub use kem::{
    Ciphertext,
    LeftPublicKey,
    LeftSecretKey,
    RightPublicKey,
    RightSecretKey,
    SharedSecret,
    decapsulate,
    encapsulate,
    encapsulate_with_messages,
    generate_left,
    generate_right,
    keygen_left,
    keygen_right,
};
pub use params::{
    ALL,
    MAUL512,
    MAUL768,
    MAUL1024,
    ParamSet,
};
pub use pke::PublicParams;
