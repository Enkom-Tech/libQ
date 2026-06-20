//! Profile + fixed public parameters for the `V1` threshold-signature instantiation.
//!
//! The signer reuses `lib-q-dkg`'s lattice ring + BDLOP commitment (`N = 1024`, `q ≈ 2^48`), so the
//! group key is a BDLOP commitment to a short secret and a signature is a Fiat–Shamir proof of
//! knowledge of its short opening. The profile id pins the geometry so byte lengths are KAT-stable.

/// Supported profile identifier.
pub const PROFILE_ID_V1: u8 = 1;

/// Maximum number of parties (and therefore the maximum threshold) for `V1`.
pub const PROFILE_MAX_PARTIES_V1: u8 = 16;

/// Frozen profile (`V1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThresholdRaccoonProfileV1 {
    /// Profile identifier (see [`PROFILE_ID_V1`]).
    pub id: u8,
    /// Maximum party / threshold count (see [`PROFILE_MAX_PARTIES_V1`]).
    pub max_parties: u8,
}

impl Default for ThresholdRaccoonProfileV1 {
    fn default() -> Self {
        Self {
            id: PROFILE_ID_V1,
            max_parties: PROFILE_MAX_PARTIES_V1,
        }
    }
}

/// Construct the default supported profile.
#[must_use]
pub fn setup() -> ThresholdRaccoonProfileV1 {
    ThresholdRaccoonProfileV1::default()
}
