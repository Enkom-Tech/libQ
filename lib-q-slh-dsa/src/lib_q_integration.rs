//! lib-Q Core Integration for SLH-DSA
//!
//! This module provides integration between the SLH-DSA implementation
//! and lib-q-core's Signature trait and type system.

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{
    string::ToString,
    vec::Vec,
};

use ::signature::rand_core::{
    CryptoRng as SignatureCryptoRng,
    RngCore as SignatureRngCore,
};
use lib_q_core::{
    Error,
    Result,
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
};
use rand_core::{
    CryptoRng,
    RngCore,
};
use sha2::Digest;
use signature::{
    Keypair,
    RandomizedSigner,
    Verifier,
};
use typenum::Unsigned;

use crate::{
    ParameterSet,
    Signature as SlhSignature,
    SigningKey,
    VerifyingKey,
};

/// SLH-DSA implementation of lib-q-core's Signature trait
///
/// This struct provides a bridge between the SLH-DSA implementation
/// and lib-q-core's unified signature interface.
pub struct SlhDsaSignature<P: ParameterSet> {
    _phantom: core::marker::PhantomData<P>,
}

impl<P: ParameterSet> SlhDsaSignature<P> {
    /// Create a new SLH-DSA signature instance
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<P: ParameterSet> Default for SlhDsaSignature<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl<P: ParameterSet> Signature for SlhDsaSignature<P> {
    fn generate_keypair(&self) -> Result<SigKeypair> {
        // SLH-DSA requires external randomness for key generation
        // This method is not supported in no_std environments
        Err(Error::NotImplemented {
            feature: "SLH-DSA keypair generation requires external randomness. Use generate_keypair_with_randomness instead.".to_string(),
        })
    }

    fn sign(&self, secret_key: &SigSecretKey, message: &[u8]) -> Result<Vec<u8>> {
        // Use system RNG when available (std feature)
        #[cfg(feature = "std")]
        {
            use lib_q_random::new_secure_rng;
            let mut rng = new_secure_rng().map_err(|_| Error::RandomGenerationFailed {
                operation: "Failed to create secure RNG".to_string(),
            })?;

            // Generate randomness for signing
            // Use conservative size that works for all parameter sets
            let mut signing_randomness = [0u8; 32]; // 32 bytes, works for all parameter sets
            // Use explicit trait call to avoid ambiguity between rand_core and signature::rand_core
            <_ as RngCore>::fill_bytes(&mut rng, &mut signing_randomness);

            self.sign_with_randomness(secret_key, message, &signing_randomness)
        }
        #[cfg(not(feature = "std"))]
        {
            // In no_std environments, require external randomness
            // Use the parameters to avoid unused variable warnings
            let _ = (secret_key, message);
            Err(Error::NotImplemented {
                feature:
                    "SLH-DSA signing requires external randomness in no_std environment. Use sign_with_randomness instead."
                        .to_string(),
            })
        }
    }

    fn verify(&self, public_key: &SigPublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        // Convert lib-q-core types to SLH-DSA types
        let verifying_key = sig_public_key_to_verifying_key::<P>(public_key)?;
        let slh_signature = bytes_to_slh_signature::<P>(signature)?;

        // Verify the signature
        match verifying_key.verify(message, &slh_signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl<P: ParameterSet> SlhDsaSignature<P> {
    /// Generate a keypair with external randomness
    ///
    /// This method follows the `lib-q` pattern for `no_std` support by requiring
    /// external randomness rather than generating it internally.
    ///
    /// # Errors
    ///
    /// Returns an error if the randomness is insufficient or key generation fails.
    #[cfg(feature = "alloc")]
    pub fn generate_keypair_with_randomness(&self, randomness: &[u8]) -> Result<SigKeypair> {
        // SLH-DSA requires 3 * N bytes of randomness for key generation
        // where N is the security parameter (typically 16, 24, or 32 bytes)
        let expected_size = P::N::USIZE * 3;
        if randomness.len() < expected_size {
            return Err(Error::InvalidRandomnessSize {
                expected: expected_size,
                actual: randomness.len(),
            });
        }

        // Create a deterministic RNG from the provided randomness
        let mut rng = DeterministicRng::new(randomness);

        // Generate the signing key
        let signing_key = SigningKey::<P>::new(&mut rng);
        let verifying_key = signing_key.verifying_key();

        // Convert to lib-q-core types
        let sig_secret_key = signing_key_to_sig_secret_key(&signing_key)?;
        let sig_public_key = verifying_key_to_sig_public_key(&verifying_key)?;

        Ok(SigKeypair {
            public_key: sig_public_key,
            secret_key: sig_secret_key,
        })
    }

    /// Sign a message with external randomness
    ///
    /// This method follows the `lib-q` pattern for `no_std` support by requiring
    /// external randomness rather than generating it internally.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    #[cfg(feature = "alloc")]
    pub fn sign_with_randomness(
        &self,
        secret_key: &SigSecretKey,
        message: &[u8],
        randomness: &[u8],
    ) -> Result<Vec<u8>> {
        // Convert lib-q-core secret key to SLH-DSA signing key
        let signing_key = sig_secret_key_to_signing_key::<P>(secret_key)?;

        // Create a deterministic RNG from the provided randomness
        let mut rng = DeterministicRng::new(randomness);

        // Sign the message
        let signature = signing_key
            .try_sign_with_rng(&mut rng, message)
            .map_err(|_| Error::SigningFailed {
                operation: "SLH-DSA signing failed".to_string(),
            })?;

        // Convert signature to bytes
        Ok(slh_signature_to_bytes(&signature))
    }
}

/// Convert SLH-DSA `SigningKey` to `lib-q-core` `SigSecretKey`
///
/// # Errors
///
/// Returns an error if the conversion fails.
#[cfg(feature = "alloc")]
pub fn signing_key_to_sig_secret_key<P: ParameterSet>(
    signing_key: &SigningKey<P>,
) -> Result<SigSecretKey> {
    let key_bytes = signing_key.to_bytes();
    Ok(SigSecretKey::new(key_bytes.to_vec()))
}

/// Convert SLH-DSA `VerifyingKey` to `lib-q-core` `SigPublicKey`
///
/// # Errors
///
/// Returns an error if the conversion fails.
#[cfg(feature = "alloc")]
pub fn verifying_key_to_sig_public_key<P: ParameterSet>(
    verifying_key: &VerifyingKey<P>,
) -> Result<SigPublicKey> {
    let key_bytes = verifying_key.to_bytes();
    Ok(SigPublicKey::new(key_bytes.to_vec()))
}

/// Convert `lib-q-core` `SigSecretKey` to SLH-DSA `SigningKey`
///
/// # Errors
///
/// Returns an error if the conversion fails.
#[cfg(feature = "alloc")]
pub fn sig_secret_key_to_signing_key<P: ParameterSet>(
    secret_key: &SigSecretKey,
) -> Result<SigningKey<P>> {
    SigningKey::<P>::try_from(secret_key.as_bytes()).map_err(|_| Error::InvalidKey {
        key_type: "SLH-DSA signing key".to_string(),
        reason: "Failed to deserialize signing key".to_string(),
    })
}

/// Convert `lib-q-core` `SigPublicKey` to SLH-DSA `VerifyingKey`
///
/// # Errors
///
/// Returns an error if the conversion fails.
#[cfg(feature = "alloc")]
pub fn sig_public_key_to_verifying_key<P: ParameterSet>(
    public_key: &SigPublicKey,
) -> Result<VerifyingKey<P>> {
    VerifyingKey::<P>::try_from(public_key.as_bytes()).map_err(|_| Error::InvalidKey {
        key_type: "SLH-DSA verifying key".to_string(),
        reason: "Failed to deserialize verifying key".to_string(),
    })
}

/// Convert SLH-DSA Signature to bytes
#[cfg(feature = "alloc")]
pub fn slh_signature_to_bytes<P: ParameterSet>(signature: &SlhSignature<P>) -> Vec<u8> {
    signature.to_bytes().to_vec()
}

/// Convert bytes to SLH-DSA `Signature`
///
/// # Errors
///
/// Returns an error if the bytes are not a valid signature.
#[cfg(feature = "alloc")]
pub fn bytes_to_slh_signature<P: ParameterSet>(bytes: &[u8]) -> Result<SlhSignature<P>> {
    SlhSignature::<P>::try_from(bytes).map_err(|_| Error::InvalidSignatureSize {
        expected: P::SigLen::USIZE,
        actual: bytes.len(),
    })
}

/// Deterministic RNG for testing and deterministic key generation
///
/// This RNG uses SHA-256 to generate deterministic randomness from a seed.
/// It's suitable for testing and scenarios where deterministic behavior is required.
struct DeterministicRng {
    seed: alloc::vec::Vec<u8>,
    counter: u64,
}

impl DeterministicRng {
    /// Create a new deterministic RNG from a seed
    fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
        }
    }
}

impl RngCore for DeterministicRng {
    #[allow(clippy::cast_possible_truncation)]
    fn next_u32(&mut self) -> u32 {
        // Call next_u64 and truncate to u32 - use explicit trait call to avoid ambiguity
        // Note: This truncation is intentional for RngCore compatibility
        <Self as RngCore>::next_u64(self) as u32
    }

    fn next_u64(&mut self) -> u64 {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.seed);
        hasher.update(self.counter.to_be_bytes());
        let hash = hasher.finalize();
        self.counter = self.counter.wrapping_add(1);

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[..8]);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            // Use explicit trait call to avoid ambiguity
            let value = <Self as RngCore>::next_u64(self);
            let bytes = value.to_be_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
}

// Also implement signature::rand_core::RngCore for compatibility
// Delegate to the workspace rand_core::RngCore implementation to ensure consistency
impl SignatureRngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        // Delegate to workspace rand_core::RngCore implementation
        <Self as RngCore>::next_u32(self)
    }

    fn next_u64(&mut self) -> u64 {
        // Delegate to workspace rand_core::RngCore implementation
        <Self as RngCore>::next_u64(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Delegate to workspace rand_core::RngCore implementation
        <Self as RngCore>::fill_bytes(self, dest);
    }
}

impl CryptoRng for DeterministicRng {}

impl SignatureCryptoRng for DeterministicRng {}
