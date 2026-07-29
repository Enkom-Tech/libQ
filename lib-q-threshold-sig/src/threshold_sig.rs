//! Re-exports of the withdrawn threshold-signature surface.
//!
//! Every function re-exported here fails closed with
//! [`ThresholdSigError::SchemeWithdrawn`](crate::ThresholdSigError::SchemeWithdrawn). The types
//! are retained only so legacy structures remain describable. See the crate documentation for
//! why this scheme was withdrawn.

#[allow(deprecated)]
pub use crate::{
    AggregateOutput,
    KeygenSharesOutput,
    Round1Commitment,
    Round1State,
    Round2Partial,
    SecretShare,
    ShareVerifier,
    ThresholdSigError,
    ThresholdSigProfileV1,
    ThresholdSigPublicKey,
    ThresholdSignature,
    aggregate,
    identify_abort,
    keygen_shares,
    proactive_refresh,
    setup,
    sign_round1,
    sign_round2,
    verify,
};
