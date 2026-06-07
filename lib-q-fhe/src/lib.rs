#![forbid(unsafe_code)]

#[cfg(feature = "fhe")]
pub mod fhe;

#[cfg(feature = "fhe")]
pub use fhe::{
    Ciphertext,
    EvalOp,
    FheParams,
    FheSecretKey,
    decrypt,
    encrypt,
    eval,
    fhe_keygen,
};
