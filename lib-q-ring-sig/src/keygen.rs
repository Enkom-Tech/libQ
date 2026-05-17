//! Issuer key material: Ajtai opening + commitment image.

use lib_q_lattice_zkp::{
    AjtaiCommitment,
    AjtaiCommitmentKey,
    AjtaiOpening,
    ProofError,
    commit,
};

/// Secret issuer state: opening witness and its commitment under the CRS.
#[derive(Clone)]
pub struct MemberIssuerKey {
    pub opening: AjtaiOpening,
    pub commitment: AjtaiCommitment,
}

impl MemberIssuerKey {
    /// Construct from a valid opening; returns `InvalidParameters` if dimensions disagree with `key`.
    pub fn from_opening(
        crs: &AjtaiCommitmentKey,
        opening: AjtaiOpening,
    ) -> Result<Self, ProofError> {
        let p = &crs.params;
        if opening.message.0.len() != p.module_rank ||
            opening.randomness.0.len() != p.randomness_dimension
        {
            return Err(ProofError::InvalidParameters);
        }
        let commitment = commit(crs, &opening);
        Ok(Self {
            opening,
            commitment,
        })
    }
}
