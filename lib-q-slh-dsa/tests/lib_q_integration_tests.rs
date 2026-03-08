//! lib-Q integration tests for SLH-DSA
//!
//! These tests verify that the SLH-DSA implementation works correctly
//! with the lib-Q provider pattern and follows security best practices.
//! These are algorithm-specific tests that should live in the algorithm crate.

#![allow(clippy::needless_range_loop)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;

use lib_q_slh_dsa::{
    ParameterSet,
    Sha2_128f,
    Sha2_192f,
    Sha2_256f,
    Shake128f,
    Shake192f,
    Shake256f,
    Signature,
    SigningKey,
    VerifyingKey,
};
use rand_core::{
    TryCryptoRng,
    TryRng,
};
use sha2::Digest;
use signature::{
    Keypair,
    RandomizedSigner,
    Verifier,
};

/// Simple deterministic RNG for testing
struct TestRng {
    seed: Vec<u8>,
    counter: u64,
}

impl TestRng {
    fn new(seed: &[u8]) -> Self {
        Self {
            seed: seed.to_vec(),
            counter: 0,
        }
    }
}

impl TryRng for TestRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        Ok(self.try_next_u64().unwrap() as u32)
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.seed);
        hasher.update(self.counter.to_be_bytes());
        let hash = hasher.finalize();
        self.counter = self.counter.wrapping_add(1);

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[..8]);
        Ok(u64::from_be_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
        for chunk in dest.chunks_mut(8) {
            let value = self.try_next_u64().unwrap();
            let bytes = value.to_be_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

// TryCryptoRng is automatically implemented by signature crate for types that implement
// signature::rand_core::CryptoRng, so we don't need an explicit implementation

/// Test SLH-DSA key generation with external randomness (no_std compatible)
#[test]
fn test_slh_dsa_key_generation_no_std() {
    // Generate deterministic randomness
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&randomness);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Verify key sizes are reasonable
    assert!(!verifying_key.to_bytes().is_empty());
    assert!(!signing_key.to_bytes().is_empty());

    // Test that same randomness produces same keys
    let mut rng2 = TestRng::new(&randomness);
    let signing_key2 = SigningKey::<Shake128f>::new(&mut rng2);
    let verifying_key2 = signing_key2.verifying_key();

    assert_eq!(verifying_key.to_bytes(), verifying_key2.to_bytes());
    assert_eq!(signing_key.to_bytes(), signing_key2.to_bytes());
}

/// Test SLH-DSA signing and verification
#[test]
fn test_slh_dsa_signing_and_verification() {
    // Generate keypair with external randomness
    let mut key_randomness = [0u8; 32];
    for i in 0..32 {
        key_randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&key_randomness);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Sign with external randomness
    let message = b"Hello, no_std SLH-DSA!";
    let mut signing_randomness = [0u8; 16]; // SLH-DSA uses first 16 bytes
    for i in 0..16 {
        signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut signing_rng = TestRng::new(&signing_randomness);
    let signature = signing_key
        .try_sign_with_rng(&mut signing_rng, message)
        .expect("Signing should succeed");

    // Verify signature
    let is_valid = verifying_key.verify(message, &signature).is_ok();

    assert!(is_valid, "Signature should be valid");

    // Test deterministic signing
    let mut signing_rng2 = TestRng::new(&signing_randomness);
    let signature2 = signing_key
        .try_sign_with_rng(&mut signing_rng2, message)
        .expect("Signing should succeed");

    assert_eq!(
        signature.to_bytes(),
        signature2.to_bytes(),
        "Signatures should be identical with same randomness"
    );
}

/// Test all SLH-DSA parameter sets
#[test]
fn test_all_slh_dsa_parameter_sets() {
    test_parameter_set::<Sha2_128f>("SHA2-128f");
    test_parameter_set::<Sha2_192f>("SHA2-192f");
    test_parameter_set::<Sha2_256f>("SHA2-256f");
    test_parameter_set::<Shake128f>("SHAKE128f");
    test_parameter_set::<Shake192f>("SHAKE192f");
    test_parameter_set::<Shake256f>("SHAKE256f");
}

fn test_parameter_set<P: ParameterSet>(name: &str) {
    // Generate deterministic randomness
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&randomness);
    let signing_key = SigningKey::<P>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message for parameter set";
    // Use appropriate randomness size for each parameter set
    let signing_randomness_size = match name {
        "SHA2-128f" | "SHAKE128f" => 16,
        "SHA2-192f" | "SHAKE192f" => 24,
        "SHA2-256f" | "SHAKE256f" => 32,
        _ => 16,
    };
    let mut signing_randomness = vec![0u8; signing_randomness_size];
    for i in 0..signing_randomness_size {
        signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut signing_rng = TestRng::new(&signing_randomness);
    let signature = signing_key
        .try_sign_with_rng(&mut signing_rng, message)
        .expect("Signing should succeed");

    let is_valid = verifying_key.verify(message, &signature).is_ok();

    assert!(
        is_valid,
        "Signature should be valid for parameter set: {}",
        name
    );
}

/// Test SLH-DSA error handling
#[test]
fn test_slh_dsa_error_handling() {
    // Test with invalid message
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&randomness);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let message = b"Hello, SLH-DSA!";
    let mut signing_randomness = [0u8; 16];
    for i in 0..16 {
        signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut signing_rng = TestRng::new(&signing_randomness);
    let signature = signing_key
        .try_sign_with_rng(&mut signing_rng, message)
        .expect("Signing should succeed");

    // Test verification with wrong message
    let wrong_message = b"Goodbye, SLH-DSA!";
    let is_valid = verifying_key.verify(wrong_message, &signature).is_ok();

    assert!(!is_valid, "Signature should be invalid for wrong message");

    // Test verification with corrupted signature
    let mut corrupted_signature = signature.to_bytes();
    corrupted_signature[0] = corrupted_signature[0].wrapping_add(1);
    let corrupted_sig = Signature::<Shake128f>::try_from(&corrupted_signature[..])
        .expect("Should be able to create signature from bytes");

    let is_valid = verifying_key.verify(message, &corrupted_sig).is_ok();

    assert!(
        !is_valid,
        "Signature should be invalid for corrupted signature"
    );
}

/// Test SLH-DSA key serialization and deserialization
#[test]
fn test_slh_dsa_key_serialization() {
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&randomness);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Test signing key serialization
    let signing_key_bytes = signing_key.to_bytes();
    let deserialized_signing_key = SigningKey::<Shake128f>::try_from(&signing_key_bytes[..])
        .expect("Should be able to deserialize signing key");

    assert_eq!(signing_key.to_bytes(), deserialized_signing_key.to_bytes());

    // Test verifying key serialization
    let verifying_key_bytes = verifying_key.to_bytes();
    let deserialized_verifying_key = VerifyingKey::<Shake128f>::try_from(&verifying_key_bytes[..])
        .expect("Should be able to deserialize verifying key");

    assert_eq!(
        verifying_key.to_bytes(),
        deserialized_verifying_key.to_bytes()
    );
}

/// Test SLH-DSA signature sizes
#[test]
fn test_slh_dsa_signature_sizes() {
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let message = b"Test message for signature size verification";
    let signing_randomness = [0u8; 16];

    // Test SHA2-128f signature size
    let mut rng_128f = TestRng::new(&randomness);
    let signing_key_128f = SigningKey::<Sha2_128f>::new(&mut rng_128f);
    let mut signing_rng_128f = TestRng::new(&signing_randomness);
    let signature_128f = signing_key_128f
        .try_sign_with_rng(&mut signing_rng_128f, message)
        .expect("Signing should succeed");
    assert_eq!(
        signature_128f.to_bytes().len(),
        17088,
        "SHA2-128f signature size should be 17088 bytes"
    );

    // Test SHA2-192f signature size
    let mut rng_192f = TestRng::new(&randomness);
    let signing_key_192f = SigningKey::<Sha2_192f>::new(&mut rng_192f);
    let mut signing_rng_192f = TestRng::new(&signing_randomness);
    let signature_192f = signing_key_192f
        .try_sign_with_rng(&mut signing_rng_192f, message)
        .expect("Signing should succeed");
    assert_eq!(
        signature_192f.to_bytes().len(),
        35664,
        "SHA2-192f signature size should be 35664 bytes"
    );

    // Test SHA2-256f signature size
    let mut rng_256f = TestRng::new(&randomness);
    let signing_key_256f = SigningKey::<Sha2_256f>::new(&mut rng_256f);
    let mut signing_rng_256f = TestRng::new(&signing_randomness);
    let signature_256f = signing_key_256f
        .try_sign_with_rng(&mut signing_rng_256f, message)
        .expect("Signing should succeed");
    assert_eq!(
        signature_256f.to_bytes().len(),
        49856,
        "SHA2-256f signature size should be 49856 bytes"
    );
}
