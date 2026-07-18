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
//! Constant-time posture (integer layer): the `R_q` modular arithmetic that carries secret
//! coefficients through the NTT — `modadd`/`modsub`, the Montgomery reduction's conditional
//! subtraction, and `centered_coeffs`' centering — uses **branchless masks**, not value-dependent
//! `if`s, so no secret coefficient steers control flow. The issuer-signature check in [`unblind`]
//! compares the (secret-attribute-derived) coefficient vectors with a **constant-time** equality
//! (`subtle::ConstantTimeEq`) rather than a short-circuiting `!=`.
//!
//! This crate is **PROVISIONAL** and consumer-protocol-agnostic: it carries no consumer-protocol references.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod blind_token;
pub mod error;
/// Lattice trapdoor machinery (GPV-preimage blind signature). Std-gated: the samplers need `f64`.
/// Research-grade constant-time posture: the small-width secret-bearing Gaussians are isochronous
/// (constant-time in the secret center; see `lattice::gaussian_ct`), and the surrounding f64/FFT
/// linear algebra is certified by a numeric-range argument — every online secret-derived intermediate
/// is exactly ±0.0 or a normal f64 (never subnormal), so no denormal-assist channel exists, and the
/// one secret-numerator division was removed (see `lattice::perturb` / `lattice::gadget` module docs).
/// Residual (documented, not closed): Box–Muller libm latency leaks only *ephemeral* per-token
/// randomness; keygen Cholesky is not constant-time (single-execution, outside the online model);
/// and fixed-latency add/mul is a documented assumption for mainstream x86-64 SSE2 / AArch64 (x87 /
/// soft-float targets excluded).
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
