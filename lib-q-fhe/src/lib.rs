//! # WARNING: TOY / NON-PRODUCTION FHE IMPLEMENTATION
//!
//! **This crate is an experimental, educational toy.  It is NOT secure,
//! NOT audited, and MUST NOT be used in production systems or to protect
//! real data.**  The scheme is a simplified lattice construction intended
//! only for demonstration and research scaffolding.  No security guarantees
//! are made or implied.
//!
//! If you need production-grade homomorphic encryption, use a well-audited
//! library (e.g. TFHE-rs, OpenFHE, or Microsoft SEAL) reviewed by
//! qualified cryptographers.

// WARNING: NOT FOR PRODUCTION USE — see crate-level doc comment above.

#![forbid(unsafe_code)]

#[cfg(feature = "fhe")]
pub mod fhe;

#[cfg(feature = "fhe")]
pub use fhe::{
    Ciphertext,
    EvalOp,
    FheError,
    FheParams,
    FheSecretKey,
    decrypt,
    encrypt,
    eval,
    fhe_keygen,
    validate_ciphertext,
};

#[cfg(feature = "wasm")]
pub mod wasm;
