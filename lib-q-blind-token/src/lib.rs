//! `lib-q-blind-token` — a post-quantum blind-signature token (Privacy-Pass-style primitive slot).
//!
//! The construction is an **unlinkable lattice blind token**: the issuer holds a Micciancio–Peikert
//! gadget trapdoor and GPV-signs a hidden attribute; redemption is a fresh, re-randomized
//! zero-knowledge proof of possession (Module-SIS; explicitly **not** the forbidden classical
//! 2HashDH VOPRF or RSA blind signature). It runs over a self-contained ring (`N = 1024`,
//! `q ≈ 2^48`) sized for ≈128-bit security against a BKZ cost model (see [`lattice`]). The
//! operations are [`blind`], [`blind_sign`], [`unblind`], [`redeem`], and [`verify`];
//! `issuer_key_id` selects the issuer parameterization and `(issuer_key_id, epoch)` is the
//! anonymity-set label.
//!
//! See the crate's `LIBQ_API.md` contract for the scheme choice, the blindness /
//! one-more-unforgeability arguments, and the limitations recorded for RED-zone review.
//!
//! This crate is **PROVISIONAL** and libQ-agnostic: it carries no consumer-protocol references.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod blind_token;
pub mod error;
/// Lattice trapdoor machinery (GPV-preimage blind signature). Std-gated: the Gaussian base sampler
/// needs `f64::exp`. Research-grade and not constant-time.
#[cfg(feature = "std")]
pub mod lattice;
pub mod profile;
pub mod wire;

#[cfg(feature = "std")]
pub use blind_token::{
    Credential,
    IssueRequest,
    IssueResponse,
    IssueState,
    IssuerPublic,
    IssuerSecret,
    TokenProof,
    blind,
    blind_sign,
    keygen_issuer,
    redeem,
    unblind,
    verify,
};
pub use error::BlindTokenError;
pub use profile::PROFILE_ID_V1;
pub use wire::{
    WIRE_BUDGET_BLIND_TOKEN_BYTES,
    WIRE_VERSION_V1,
};
#[cfg(feature = "std")]
pub use wire::{
    decode_token_value,
    encode_token_value,
};
