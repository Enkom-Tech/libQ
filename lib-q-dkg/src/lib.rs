//! `lib-q-dkg` — dealerless distributed key generation via a **binding** lattice verifiable secret
//! sharing (VSS) scheme.
//!
//! The construction is a Gennaro-style dealerless DKG in which every party runs a VSS instantiated
//! over **BDLOP commitments** (message-in-the-clear, statistically binding) on the self-contained
//! ring `R_q = Z_q[X]/(X^1024+1)`, `q ≈ 2^48` (see [`lattice`]). Each share carries a Fiat–Shamir
//! proof of correct sharing, so the no-dealer check binds the share *value* — defeating the
//! adaptive-dealer kernel-injection attack that a bare-Ajtai commitment admits. The group secret is
//! never reconstructed.
//!
//! Outputs ([`SigningShare`], [`VerificationKeySet`], [`KeygenSharesOutput`]) mirror the shapes of
//! `lib-q-threshold-sig` so they are drop-in for a future lattice signer; `share_bytes` carry the
//! `R_q` (`Z_q`-coefficient) encodings. See the crate's `LIBQ_API.md` contract for the scheme
//! choice, the 1:1 type mapping, and the assumptions recorded for RED-zone review.
//!
//! This crate is **PROVISIONAL** and GIP-agnostic: it carries no consumer-protocol references.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod dkg;
pub mod error;
pub mod profile;
#[cfg(feature = "std")]
pub mod wire;

/// Self-contained lattice machinery (ring + BDLOP commitment + FS proof of correct sharing).
#[cfg(feature = "std")]
pub mod lattice;

/// WASM bindings (`@lib-q/dkg`), gated behind the `wasm` feature.
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "std")]
pub use dkg::{
    CoeffCommitments,
    Complaint,
    KeygenSharesOutput,
    ReshareRound1,
    SecretPolynomial,
    ShareEvaluation,
    ShareVerifier,
    SigningShare,
    VerificationKeySet,
    dkg_assemble_vk_set,
    dkg_build_complaint,
    dkg_check_complaint,
    dkg_eval_share,
    dkg_finalize_share,
    dkg_reshare,
    dkg_round1_commit,
    dkg_run_honest,
    dkg_verify_share,
    lagrange_coeff_at_zero,
    signing_share_commitment,
};
pub use error::DkgError;
pub use profile::{
    DkgProfileV1,
    PROFILE_ID_V1,
    PROFILE_MAX_PARTIES_V1,
    setup,
};
#[cfg(feature = "std")]
pub use wire::{
    WIRE_BUDGET_DKG_COMPLAINT_BYTES,
    WIRE_BUDGET_DKG_ROUND1_BYTES,
    WIRE_VERSION_V1,
    decode_complaint,
    decode_round1_commitments,
    encode_complaint,
    encode_round1_commitments,
};
