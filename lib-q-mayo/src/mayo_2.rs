//! MAYO_2 public API (NIST additional-signatures round 2, security level 1).
//!
//! The API mirrors the other lib-q signature crates (lib-q-ml-dsa /
//! lib-q-fn-dsa): fixed-size byte arrays in and out, with the caller
//! supplying randomness. MAYO has no context-string parameter in the round-2
//! specification.
//!
//! Signing is hedged: the 24-byte `randomness` is the spec's randomizer `R`,
//! mixed with the secret seed and message digest to derive the salt. Passing
//! all-zero randomness yields deterministic (but still seed-hedged) signing;
//! passing RNG output yields the randomized mode used by the KATs.

use crate::params::*;
use crate::types::{
    Mayo2KeyPair,
    Mayo2Signature,
    Mayo2SigningKey,
    Mayo2VerificationKey,
};
use crate::{
    SigningError,
    VerificationError,
    mayo_core as core,
};

/// Signing key (compact secret key) size in bytes.
pub const SIGNING_KEY_SIZE: usize = CSK_BYTES;
/// Verification key (compact public key) size in bytes.
pub const VERIFICATION_KEY_SIZE: usize = CPK_BYTES;
/// Signature size in bytes (fixed length).
pub const SIGNATURE_SIZE: usize = SIG_BYTES;
/// Bytes of randomness consumed by [`generate_key_pair`] (it becomes the
/// secret seed).
pub const KEY_GENERATION_RANDOMNESS_SIZE: usize = SK_SEED_BYTES;
/// Bytes of randomness consumed by [`sign`] (the spec's randomizer `R`).
pub const SIGNING_RANDOMNESS_SIZE: usize = SALT_BYTES;

/// Generate a MAYO_2 key pair from `randomness` (which becomes the compact
/// secret key / seed).
pub fn generate_key_pair(randomness: [u8; KEY_GENERATION_RANDOMNESS_SIZE]) -> Mayo2KeyPair {
    let mut verification_key = Mayo2VerificationKey::zero();
    core::keypair_compact(&randomness, verification_key.as_ref_mut());
    Mayo2KeyPair {
        signing_key: Mayo2SigningKey::new(randomness),
        verification_key,
    }
}

/// Generate a MAYO_2 key pair into caller-provided buffers.
pub fn generate_key_pair_mut(
    mut randomness: [u8; KEY_GENERATION_RANDOMNESS_SIZE],
    signing_key: &mut [u8; SIGNING_KEY_SIZE],
    verification_key: &mut [u8; VERIFICATION_KEY_SIZE],
) {
    core::keypair_compact(&randomness, verification_key);
    signing_key.copy_from_slice(&randomness);
    core::wipe_bytes(&mut randomness);
}

/// Generate a MAYO_2 signature.
pub fn sign(
    signing_key: &Mayo2SigningKey,
    message: &[u8],
    mut randomness: [u8; SIGNING_RANDOMNESS_SIZE],
) -> Result<Mayo2Signature, SigningError> {
    let mut signature = Mayo2Signature::zero();
    let result = core::sign_signature(
        signing_key.as_ref(),
        message,
        &randomness,
        signature.as_ref_mut(),
    );
    core::wipe_bytes(&mut randomness);
    result?;
    Ok(signature)
}

/// Generate a MAYO_2 signature into a caller-provided buffer.
pub fn sign_mut(
    signing_key: &[u8; SIGNING_KEY_SIZE],
    message: &[u8],
    mut randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    signature: &mut [u8; SIGNATURE_SIZE],
) -> Result<(), SigningError> {
    let result = core::sign_signature(signing_key, message, &randomness, signature);
    core::wipe_bytes(&mut randomness);
    result
}

/// Verify a MAYO_2 signature.
///
/// Returns `Ok(())` when `signature` is valid for `message` under
/// `verification_key`.
pub fn verify(
    verification_key: &Mayo2VerificationKey,
    message: &[u8],
    signature: &Mayo2Signature,
) -> Result<(), VerificationError> {
    if core::verify(verification_key.as_ref(), message, signature.as_ref()) {
        Ok(())
    } else {
        Err(VerificationError::VerificationFailed)
    }
}

/// Verify a MAYO_2 signature from raw byte arrays.
pub fn verify_raw(
    verification_key: &[u8; VERIFICATION_KEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), VerificationError> {
    if core::verify(verification_key, message, signature) {
        Ok(())
    } else {
        Err(VerificationError::VerificationFailed)
    }
}
