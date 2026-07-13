//! Frozen `V1` profile and its pinned parameter-set digest.

use lib_q_sha3::sha3_256;

/// Profile id (`V1`).
pub const PROFILE_ID_V1: u8 = 1;

/// Maximum committee size (matches `lib-q-dkg`'s `PROFILE_MAX_PARTIES_V1 = 16`).
pub const PROFILE_MAX_PARTIES_V1: u8 = 16;

/// Wire format version.
pub const WIRE_VERSION_V1: u8 = 1;

/// Canonical parameter blob hashed into [`ThresholdKemLatticeProfileV1::parameter_set_digest`].
///
/// Encodes the load-bearing constants so a decoder can detect a parameter drift: the shared ring
/// (`lib-q-dkg` `N=1024`, the **exact** prime `q = 281474976694273` — a bit-size alone would not
/// distinguish two 48-bit NTT-friendly primes — `MU=6`, `KAPPA=9`), the uniform encryption-error
/// bound (`B = 2^20`), the FO⊥ transform, the flooding bound (`2^40`), and the message field
/// width. See `LIBQ_API.md` §2.
pub const PARAMETER_SET_CANONICAL_BLOB_V1: &str = "libq-threshold-kem-lattice-v1-dualregev-N1024-q281474976694273-MU6-K9-encU20-fo-flood40-mbits256";

/// The frozen `V1` profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThresholdKemLatticeProfileV1 {
    /// Profile id (`= PROFILE_ID_V1`).
    pub id: u8,
    /// Maximum committee size.
    pub max_parties: u8,
    /// SHA3-256 of [`PARAMETER_SET_CANONICAL_BLOB_V1`].
    pub parameter_set_digest: [u8; 32],
}

impl Default for ThresholdKemLatticeProfileV1 {
    fn default() -> Self {
        Self {
            id: PROFILE_ID_V1,
            max_parties: PROFILE_MAX_PARTIES_V1,
            parameter_set_digest: sha3_256(PARAMETER_SET_CANONICAL_BLOB_V1.as_bytes()),
        }
    }
}

/// Construct the frozen `V1` profile.
#[must_use]
pub fn setup() -> ThresholdKemLatticeProfileV1 {
    ThresholdKemLatticeProfileV1::default()
}
