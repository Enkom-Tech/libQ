//! Federation “ring” openings over shared Ajtai CRS commitments.
//!
//! This crate provides **opening-proof–based federation signatures**: one issuer proves
//! knowledge of an opening for its public commitment while binding a Fiat–Shamir context
//! to the full member list. Verification without a signer index uses a linear scan
//! ([`verify::verify_federation_opening_scan`]), which is not issuer-hiding toward the
//! verifier. [`dualring_lb`] ships a **pilot** DualRing-LB–oriented transcript with
//! constant-time full-ring verification; see [`DESIGN.md`](./DESIGN.md) for limits vs the CCS 2021 paper.
#![forbid(unsafe_code)]
#![no_std]

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

#[cfg(feature = "dualring-prf")]
pub mod dualring_prf;

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
    dualring_lb_challenge_state,
    dualring_lb_signing_context,
    sign_dualring_lb,
    verify_dualring_lb,
};
#[cfg(feature = "dualring-prf")]
pub use dualring_prf::{
    DualRingPrfError,
    DualRingPrfMemberPublic256,
    DualRingPrfSignature256,
    dualring_prf_ring_digest,
    sign_dualring_prf_u256,
    verify_dualring_prf_batch_u256,
    verify_dualring_prf_u256,
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
