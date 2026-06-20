//! Public blind-token operations.
//!
//! The token is an **unlinkable lattice blind signature**: the issuer holds an MP gadget trapdoor
//! and produces a GPV preimage credential on a hidden attribute; redemption is a fresh, re-randomized
//! zero-knowledge proof of possession (see [`crate::lattice::scheme`]). The contract operations map
//! as:
//!
//! | contract op   | this crate     | scheme step                              |
//! |---------------|----------------|------------------------------------------|
//! | Blind         | [`blind`]      | sample hidden attribute, build request   |
//! | Evaluate/Sign | [`blind_sign`] | issuer GPV-signs `d·a_tok + d0`          |
//! | Unblind       | [`unblind`]    | check signature → store credential       |
//! | Redeem        | [`redeem`]     | fresh ZK proof of possession (token bytes)|
//! | Verify        | [`verify`]     | verify the ZK proof                       |
//!
//! `(issuer_key_id, epoch)` is the anonymity-set label; redemptions are unlinkable to issuances
//! within one set. The whole API is **std-gated** (the Gaussian samplers need `f64`). See the
//! crate `LIBQ_API.md` for the blindness / one-more-unforgeability arguments and the research-grade
//! parameter caveats recorded for RED-zone review.

#[cfg(feature = "std")]
pub use crate::lattice::scheme::{
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
    unblind,
};

#[cfg(feature = "std")]
mod redeem_verify {
    use alloc::vec::Vec;

    use rand_core::{
        CryptoRng,
        Rng,
    };

    use super::{
        Credential,
        IssuerPublic,
    };
    use crate::error::BlindTokenError;
    use crate::wire;

    /// Redeem a credential into a serialized, unlinkable token value bound to `nonce`.
    ///
    /// Each call produces a freshly randomized proof, so repeated redemptions of the same credential
    /// are mutually unlinkable. Returns [`BlindTokenError::Proof`] only if rejection sampling is
    /// exhausted (vanishingly unlikely).
    pub fn redeem<R: CryptoRng + Rng>(
        rng: &mut R,
        public: &IssuerPublic,
        credential: &Credential,
        nonce: &[u8],
    ) -> Result<Vec<u8>, BlindTokenError> {
        let proof = crate::lattice::scheme::redeem(rng, public, credential, nonce)
            .ok_or(BlindTokenError::Proof)?;
        wire::encode_token_value(&proof)
    }

    /// Verify a serialized token value against `issuer_pub` and the presented `nonce`.
    #[must_use]
    pub fn verify(public: &IssuerPublic, nonce: &[u8], token_value: &[u8]) -> bool {
        match wire::decode_token_value(token_value) {
            Ok(proof) => crate::lattice::scheme::verify(public, nonce, &proof),
            Err(_) => false,
        }
    }
}

#[cfg(feature = "std")]
pub use redeem_verify::{
    redeem,
    verify,
};
