//! Federation “ring” openings over shared Ajtai CRS commitments.
//!
//! This crate provides **opening-proof–based federation signatures**: one issuer proves
//! knowledge of an opening for its public commitment while binding a Fiat–Shamir context
//! to the full member list. Verification without a signer index uses a linear scan
//! ([`verify::verify_federation_opening_scan`]), which is not issuer-hiding toward the
//! verifier. [`dualring_lb`] implements DualRing-LB (CCS 2021, Algorithm 3) aggregated verification on
//! the Ajtai opening relation; see [`DESIGN.md`](./DESIGN.md) for transcript binding and parameter notes.
//! The optional `dualring_prf` module (feature `pilot-insecure-prf-transcript`) defines the
//! DualRing-style PRF transcript wire format; `pilot_insecure_prf_transcript` re-exports the legacy
//! `pilot_*` names. Both are **not** a ring signature: laboratory PRF wiring only; see [`DESIGN.md`](./DESIGN.md) (PRF laboratory transcript) and those modules' docs before enabling.
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod credential;
pub mod dualring_lb;
pub mod keygen;
pub mod params;
pub mod ring;
pub mod sign;
pub mod verify;

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(feature = "pilot-insecure-prf-transcript")]
pub mod dualring_prf;
#[cfg(feature = "pilot-insecure-prf-transcript")]
pub mod pilot_insecure_prf_transcript;

#[cfg(feature = "federation-opening")]
pub use credential::verify_credential_presentation_federation_opening;
pub use credential::{
    CredentialPresentation,
    attribute_message_digest,
    verify_credential_presentation,
};
pub use dualring_lb::{
    DualRingLbChallengeState,
    DualRingLbSignature,
    DualRingOpeningProof,
    dualring_lb_challenge_state,
    dualring_lb_signing_context,
    sign_dualring_lb,
    verify_dualring_lb,
};
pub use keygen::MemberIssuerKey;
pub use params::RingSigParams;
pub use ring::{
    FederationRing,
    federation_digest,
};
pub use sign::{
    federation_signing_context,
    sign_federation_message,
};
pub use verify::{
    verify_federation_opening,
    verify_federation_opening_scan,
};
