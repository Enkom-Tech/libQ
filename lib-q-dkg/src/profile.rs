//! Profile + fixed public parameters for the `V1` DKG instantiation.
//!
//! The BDLOP commitment matrices `(B0, b1)` are the public CRS, expanded from
//! [`crate::lattice::bdlop::COMMIT_MATRIX_SEED`]. The geometry (`MU`, `KAPPA`) and challenge weight
//! `TAU` live in [`crate::lattice::bdlop`]; the profile id pins them so byte lengths stay stable for
//! KAT fixtures while remaining changeable pre-freeze via a new profile id.

/// Supported profile identifier.
pub const PROFILE_ID_V1: u8 = 1;

/// Maximum number of parties (and therefore the maximum threshold) for `V1`.
pub const PROFILE_MAX_PARTIES_V1: u8 = 16;

/// Frozen DKG profile (`V1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DkgProfileV1 {
    /// Profile identifier (see [`PROFILE_ID_V1`]).
    pub id: u8,
    /// Maximum party / threshold count (see [`PROFILE_MAX_PARTIES_V1`]).
    pub max_parties: u8,
}

impl Default for DkgProfileV1 {
    fn default() -> Self {
        Self {
            id: PROFILE_ID_V1,
            max_parties: PROFILE_MAX_PARTIES_V1,
        }
    }
}

/// Construct the default supported profile.
#[must_use]
pub fn setup() -> DkgProfileV1 {
    DkgProfileV1::default()
}
