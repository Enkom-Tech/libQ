//! Boneh-Zhandry quantum Carter-Wegman MAC (qCW-MAC).

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::axu::epsilon_axu;
use crate::profile::{
    QCW_MAC_KEY_BYTES,
    QCW_MAC_TAG_BYTES,
};
use crate::qprf::qprf_tag;

const MAC_LABEL: &[u8] = b"tag";

/// Secret key for qCW-MAC.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct QcwMacKey {
    key: [u8; QCW_MAC_KEY_BYTES],
}

impl QcwMacKey {
    /// Generate a fresh key from the supplied CSPRNG.
    #[must_use]
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut key = [0u8; QCW_MAC_KEY_BYTES];
        rng.fill_bytes(&mut key);
        Self { key }
    }

    /// Construct from raw key bytes (for KAT replay).
    #[must_use]
    pub fn from_bytes(bytes: [u8; QCW_MAC_KEY_BYTES]) -> Self {
        Self { key: bytes }
    }

    /// Expose key bytes for deterministic vector export.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; QCW_MAC_KEY_BYTES] {
        &self.key
    }
}

/// qCW-MAC sign/verify operations.
pub struct QcwMac;

impl QcwMac {
    /// Produce an authentication tag for `(msg, ad)`.
    #[must_use]
    pub fn sign(key: &QcwMacKey, msg: &[u8], ad: &[u8]) -> alloc::vec::Vec<u8> {
        let axu = epsilon_axu(&key.key, ad, msg);
        qprf_tag(&key.key, MAC_LABEL, &axu).to_vec()
    }

    /// Constant-time tag verification.
    #[must_use]
    pub fn verify(key: &QcwMacKey, msg: &[u8], ad: &[u8], tag: &[u8]) -> bool {
        if tag.len() != QCW_MAC_TAG_BYTES {
            return false;
        }
        let expected = Self::sign(key, msg, ad);
        bool::from(expected.as_slice().ct_eq(tag))
    }
}
