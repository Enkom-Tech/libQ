pub use ml_dsa_65::{
    MLDSA65KeyPair,
    MLDSA65Signature,
    MLDSA65SigningKey,
    MLDSA65VerificationKey,
};
use zeroize::Zeroizing;

use crate::constants::*;
use crate::types::*;
use crate::{
    SigningError,
    VerificationError,
};

// Instantiate the different functions.
macro_rules! instantiate {
    ($modp:ident, $doc:expr) => {
        #[doc = $doc]
        pub mod $modp {
            use super::*;

            /// Generate an ML-DSA-65 Key Pair from a seed held in a zeroizing buffer
            ///
            /// The seed is borrowed, so no copy of it is made on the way into key generation,
            /// and the caller's buffer is cleared when it is dropped.
            pub fn generate_key_pair_from_seed(
                seed: &Zeroizing<[u8; KEY_GENERATION_RANDOMNESS_SIZE]>,
            ) -> MLDSA65KeyPair {
                // Write the signing key in place: a temporary array would leave a copy behind.
                let mut key_pair = MLDSA65KeyPair {
                    signing_key: MLDSASigningKey::zero(),
                    verification_key: MLDSAVerificationKey::zero(),
                };
                crate::ml_dsa_generic::ml_dsa_65::generate_key_pair::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                    crate::hash_functions::portable::Shake256X4,
                >(
                    seed,
                    &mut key_pair.signing_key.value,
                    &mut key_pair.verification_key.value,
                );
                key_pair
            }

            /// Generate an ML-DSA-65 Key Pair into caller-provided buffers
            ///
            /// The seed is borrowed from a zeroizing buffer, as in
            /// [`generate_key_pair_from_seed`].
            pub fn generate_key_pair_mut(
                seed: &Zeroizing<[u8; KEY_GENERATION_RANDOMNESS_SIZE]>,
                signing_key: &mut [u8; ml_dsa_65::SIGNING_KEY_SIZE],
                verification_key: &mut [u8; ml_dsa_65::VERIFICATION_KEY_SIZE],
            ) {
                crate::ml_dsa_generic::ml_dsa_65::generate_key_pair::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                    crate::hash_functions::portable::Shake256X4,
                >(seed, signing_key, verification_key);
            }

            /// Generate an ML-DSA-65 Signature
            ///
            /// The parameter `context` is used for domain separation
            /// and is a byte string of length at most 255 bytes. It
            /// may also be empty.
            pub fn sign(
                signing_key: &MLDSA65SigningKey,
                message: &[u8],
                context: &[u8],
                randomness: [u8; SIGNING_RANDOMNESS_SIZE],
            ) -> Result<MLDSA65Signature, SigningError> {
                crate::ml_dsa_generic::ml_dsa_65::sign::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                    crate::hash_functions::portable::Shake256X4,
                >(signing_key.as_ref(), message, context, randomness)
            }

            /// Generate an ML-DSA-65 Signature
            ///
            /// The parameter `context` is used for domain separation
            /// and is a byte string of length at most 255 bytes. It
            /// may also be empty.
            pub fn sign_mut(
                signing_key: &[u8; ml_dsa_65::SIGNING_KEY_SIZE],
                message: &[u8],
                context: &[u8],
                randomness: [u8; SIGNING_RANDOMNESS_SIZE],
                signature: &mut [u8; ml_dsa_65::SIGNATURE_SIZE],
            ) -> Result<(), SigningError> {
                crate::ml_dsa_generic::ml_dsa_65::sign_mut::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                    crate::hash_functions::portable::Shake256X4,
                >(signing_key, message, context, randomness, signature)
            }

            /// Generate an ML-DSA-65 Signature (Algorithm 7 in FIPS204)
            ///
            /// The message is assumed to be domain-separated.
            #[cfg(feature = "acvp")]
            pub fn sign_internal(
                signing_key: &MLDSA65SigningKey,
                message: &[u8],
                randomness: [u8; SIGNING_RANDOMNESS_SIZE],
            ) -> Result<MLDSA65Signature, SigningError> {
                let mut signature = MLDSA65Signature::zero();
                crate::ml_dsa_generic::ml_dsa_65::sign_internal::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                    crate::hash_functions::portable::Shake256X4,
                >(
                    signing_key.as_ref(),
                    message,
                    None,
                    randomness,
                    signature.as_ref_mut(),
                )?;
                Ok(signature)
            }

            /// Verify an ML-DSA-65 Signature (Algorithm 8 in FIPS204)
            ///
            /// The message is assumed to be domain-separated.
            #[cfg(feature = "acvp")]
            pub fn verify_internal(
                verification_key: &MLDSA65VerificationKey,
                message: &[u8],
                signature: &MLDSA65Signature,
            ) -> Result<(), VerificationError> {
                crate::ml_dsa_generic::ml_dsa_65::verify_internal::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                >(verification_key.as_ref(), message, None, signature.as_ref())
            }

            /// Generate a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing
            ///
            /// The parameter `context` is used for domain separation
            /// and is a byte string of length at most 255 bytes. It
            /// may also be empty.
            pub fn sign_pre_hashed_shake128(
                signing_key: &MLDSA65SigningKey,
                message: &[u8],
                context: &[u8],
                randomness: [u8; SIGNING_RANDOMNESS_SIZE],
            ) -> Result<MLDSA65Signature, SigningError> {
                let mut pre_hash_buffer = [0u8; 256];
                crate::ml_dsa_generic::ml_dsa_65::sign_pre_hashed::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                    crate::hash_functions::portable::Shake256X4,
                    crate::pre_hash::SHAKE128_PH,
                >(
                    signing_key.as_ref(),
                    message,
                    context,
                    &mut pre_hash_buffer,
                    randomness,
                )
            }

            /// Verify an ML-DSA-65 Signature
            ///
            /// The parameter `context` is used for domain separation
            /// and is a byte string of length at most 255 bytes. It
            /// may also be empty.
            pub fn verify(
                verification_key: &MLDSA65VerificationKey,
                message: &[u8],
                context: &[u8],
                signature: &MLDSA65Signature,
            ) -> Result<(), VerificationError> {
                crate::ml_dsa_generic::ml_dsa_65::verify::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                >(
                    verification_key.as_ref(),
                    message,
                    context,
                    signature.as_ref(),
                )
            }

            /// Verify a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing
            ///
            /// The parameter `context` is used for domain separation
            /// and is a byte string of length at most 255 bytes. It
            /// may also be empty.
            pub fn verify_pre_hashed_shake128(
                verification_key: &MLDSA65VerificationKey,
                message: &[u8],
                context: &[u8],
                signature: &MLDSA65Signature,
            ) -> Result<(), VerificationError> {
                let mut pre_hash_buffer = [0u8; 256];
                crate::ml_dsa_generic::ml_dsa_65::verify_pre_hashed::<
                    crate::simd::portable::PortableSIMDUnit,
                    crate::samplex4::portable::PortableSampler,
                    crate::hash_functions::portable::Shake128,
                    crate::hash_functions::portable::Shake128X4,
                    crate::hash_functions::portable::Shake256,
                    crate::hash_functions::portable::Shake256Xof,
                    crate::pre_hash::SHAKE128_PH,
                >(
                    verification_key.as_ref(),
                    message,
                    context,
                    &mut pre_hash_buffer,
                    signature.as_ref(),
                )
            }
        }
    };
}

// Instantiations
instantiate! {portable, "Portable ML-DSA 65"}
#[cfg(all(feature = "simd256", target_arch = "x86_64"))]
instantiate! {avx2, "AVX2 Optimised ML-DSA 65"}
#[cfg(feature = "simd128")]
instantiate! {neon, "Neon Optimised ML-DSA 65"}

/// Generate an ML-DSA 65 Key Pair
///
/// Generate an ML-DSA key pair from a seed of [`KEY_GENERATION_RANDOMNESS_SIZE`] bytes held in a
/// [`Zeroizing`] buffer. The seed is borrowed, so no copy of it is made on the way into key
/// generation, and the caller's buffer is cleared when it is dropped.
///
/// This function returns an [`MLDSA65KeyPair`].
#[cfg(not(eurydice))]
pub fn generate_key_pair_from_seed(
    seed: &Zeroizing<[u8; KEY_GENERATION_RANDOMNESS_SIZE]>,
) -> MLDSA65KeyPair {
    // Write the signing key in place: a temporary array would leave a copy behind.
    let mut key_pair = MLDSA65KeyPair {
        signing_key: MLDSASigningKey::zero(),
        verification_key: MLDSAVerificationKey::zero(),
    };
    crate::ml_dsa_generic::multiplexing::ml_dsa_65::generate_key_pair(
        seed,
        &mut key_pair.signing_key.value,
        &mut key_pair.verification_key.value,
    );
    key_pair
}

/// Sign with ML-DSA 65
///
/// Sign a `message` with the ML-DSA `signing_key`.
///
/// The parameter `context` is used for domain separation
/// and is a byte string of length at most 255 bytes. It
/// may also be empty.
///
/// This function returns an [`MLDSA65Signature`].
#[cfg(not(eurydice))]
pub fn sign(
    signing_key: &MLDSA65SigningKey,
    message: &[u8],
    context: &[u8],
    randomness: [u8; SIGNING_RANDOMNESS_SIZE],
) -> Result<MLDSA65Signature, SigningError> {
    crate::ml_dsa_generic::multiplexing::ml_dsa_65::sign(
        signing_key.as_ref(),
        message,
        context,
        randomness,
    )
}

/// Sign with ML-DSA 65 (Algorithm 7 in FIPS204)
///
/// Sign a `message` (assumed to be domain-separated) with the ML-DSA `signing_key`.
///
/// This function returns an [`MLDSA65Signature`].
#[cfg(all(not(eurydice), feature = "acvp"))]
pub fn sign_internal(
    signing_key: &MLDSA65SigningKey,
    message: &[u8],
    randomness: [u8; SIGNING_RANDOMNESS_SIZE],
) -> Result<MLDSA65Signature, SigningError> {
    crate::ml_dsa_generic::multiplexing::ml_dsa_65::sign_internal(
        signing_key.as_ref(),
        message,
        randomness,
    )
}

/// Verify an ML-DSA-65 Signature (Algorithm 8 in FIPS204)
///
/// Returns `Ok` when the `signature` is valid for the `message` (assumed to be domain-separated) and
/// `verification_key`, and a [`VerificationError`] otherwise.
#[cfg(all(not(eurydice), feature = "acvp"))]
pub fn verify_internal(
    verification_key: &MLDSA65VerificationKey,
    message: &[u8],
    signature: &MLDSA65Signature,
) -> Result<(), VerificationError> {
    crate::ml_dsa_generic::multiplexing::ml_dsa_65::verify_internal(
        verification_key.as_ref(),
        message,
        signature.as_ref(),
    )
}

/// Verify an ML-DSA-65 Signature
///
/// The parameter `context` is used for domain separation
/// and is a byte string of length at most 255 bytes. It
/// may also be empty.
///
/// Returns `Ok` when the `signature` is valid for the `message` and
/// `verification_key`, and a [`VerificationError`] otherwise.
#[cfg(not(eurydice))]
pub fn verify(
    verification_key: &MLDSA65VerificationKey,
    message: &[u8],
    context: &[u8],
    signature: &MLDSA65Signature,
) -> Result<(), VerificationError> {
    crate::ml_dsa_generic::multiplexing::ml_dsa_65::verify(
        verification_key.as_ref(),
        message,
        context,
        signature.as_ref(),
    )
}

/// Sign with HashML-DSA 65, with a SHAKE128 pre-hashing
///
/// Sign a digest of `message` derived using `pre_hash` with the
/// ML-DSA `signing_key`.
///
/// The parameter `context` is used for domain separation
/// and is a byte string of length at most 255 bytes. It
/// may also be empty.
///
/// This function returns an [`MLDSA65Signature`].
#[cfg(not(eurydice))]
pub fn sign_pre_hashed_shake128(
    signing_key: &MLDSA65SigningKey,
    message: &[u8],
    context: &[u8],
    randomness: [u8; SIGNING_RANDOMNESS_SIZE],
) -> Result<MLDSA65Signature, SigningError> {
    let mut pre_hash_buffer = [0u8; 256];
    crate::ml_dsa_generic::ml_dsa_65::sign_pre_hashed::<
        crate::simd::portable::PortableSIMDUnit,
        crate::samplex4::portable::PortableSampler,
        crate::hash_functions::portable::Shake128,
        crate::hash_functions::portable::Shake128X4,
        crate::hash_functions::portable::Shake256,
        crate::hash_functions::portable::Shake256Xof,
        crate::hash_functions::portable::Shake256X4,
        crate::pre_hash::SHAKE128_PH,
    >(
        signing_key.as_ref(),
        message,
        context,
        &mut pre_hash_buffer,
        randomness,
    )
}

/// Verify a HashML-DSA-65 Signature, with a SHAKE128 pre-hashing
///
/// The parameter `context` is used for domain separation
/// and is a byte string of length at most 255 bytes. It
/// may also be empty.
///
/// Returns `Ok` when the `signature` is valid for the `message` and
/// `verification_key`, and a [`VerificationError`] otherwise.
#[cfg(not(eurydice))]
pub fn verify_pre_hashed_shake128(
    verification_key: &MLDSA65VerificationKey,
    message: &[u8],
    context: &[u8],
    signature: &MLDSA65Signature,
) -> Result<(), VerificationError> {
    let mut pre_hash_buffer = [0u8; 256];
    crate::ml_dsa_generic::ml_dsa_65::verify_pre_hashed::<
        crate::simd::portable::PortableSIMDUnit,
        crate::samplex4::portable::PortableSampler,
        crate::hash_functions::portable::Shake128,
        crate::hash_functions::portable::Shake128X4,
        crate::hash_functions::portable::Shake256,
        crate::hash_functions::portable::Shake256Xof,
        crate::pre_hash::SHAKE128_PH,
    >(
        verification_key.as_ref(),
        message,
        context,
        &mut pre_hash_buffer,
        signature.as_ref(),
    )
}
