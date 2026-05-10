//! lib-Q Core Integration Tests for SLH-DSA
//!
//! These tests verify that the SLH-DSA implementation correctly integrates
//! with lib-q-core's Signature trait and type system.

#![allow(clippy::needless_range_loop)]
#![cfg(not(target_arch = "wasm32"))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec;

use lib_q_core::{
    Error,
    SigPublicKey,
    SigSecretKey,
    Signature,
};
use lib_q_slh_dsa::lib_q_integration::{
    SlhDsaSignature,
    bytes_to_slh_signature,
    sig_public_key_to_verifying_key,
    sig_secret_key_to_signing_key,
    signing_key_to_sig_secret_key,
    slh_signature_to_bytes,
    verifying_key_to_sig_public_key,
};
use lib_q_slh_dsa::signature::{
    Keypair,
    RandomizedSigner,
};
use lib_q_slh_dsa::{
    ParameterSet,
    Sha2_128f,
    Sha2_192f,
    Sha2_256f,
    Shake128f,
    Shake192f,
    Shake256f,
    SigningKey,
    VerifyingKey,
};
use rand_core::{
    TryCryptoRng,
    TryRng,
};
use sha2::Digest;

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

/// Test type conversion between SLH-DSA and lib-q-core types
#[test]
fn test_type_conversions() {
    // Generate deterministic randomness
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&randomness);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Test SigningKey -> SigSecretKey conversion
    let sig_secret_key = signing_key_to_sig_secret_key(&signing_key)
        .expect("Should convert SigningKey to SigSecretKey");
    assert!(!sig_secret_key.as_bytes().is_empty());

    // Test VerifyingKey -> SigPublicKey conversion
    let sig_public_key = verifying_key_to_sig_public_key::<Shake128f>(&verifying_key)
        .expect("Should convert VerifyingKey to SigPublicKey");
    assert!(!sig_public_key.as_bytes().is_empty());

    // Test SigSecretKey -> SigningKey conversion
    let converted_signing_key = sig_secret_key_to_signing_key::<Shake128f>(&sig_secret_key)
        .expect("Should convert SigSecretKey to SigningKey");
    assert_eq!(signing_key.to_bytes(), converted_signing_key.to_bytes());

    // Test SigPublicKey -> VerifyingKey conversion
    let converted_verifying_key: VerifyingKey<Shake128f> =
        sig_public_key_to_verifying_key::<Shake128f>(&sig_public_key)
            .expect("Should convert SigPublicKey to VerifyingKey");
    assert_eq!(verifying_key.to_bytes(), converted_verifying_key.to_bytes());
}

/// Test SLH-DSA Signature trait implementation
#[test]
fn test_slh_dsa_signature_trait() {
    let slh_dsa = SlhDsaSignature::<Shake128f>::new();

    // Test that generate_keypair returns NotImplemented (requires external randomness)
    let result = slh_dsa.generate_keypair();
    assert!(result.is_err());
    if let Err(Error::NotImplemented { feature }) = result {
        assert!(feature.contains("external randomness"));
    } else {
        panic!("Expected NotImplemented error for generate_keypair");
    }

    // Test that sign works with system RNG when std feature is enabled
    let dummy_secret_key = SigSecretKey::new(vec![0u8; 100]); // Dummy key
    let result = slh_dsa.sign(&dummy_secret_key, b"test message");

    #[cfg(feature = "std")]
    {
        // With std feature enabled, sign should work (though it may fail due to invalid key)
        // The important thing is that it's not returning NotImplemented
        if let Err(Error::NotImplemented { .. }) = result {
            panic!("sign method should not return NotImplemented when std feature is enabled");
        }
    }

    #[cfg(not(feature = "std"))]
    {
        // With no_std, sign should return NotImplemented since no system RNG is available
        if let Err(Error::NotImplemented { .. }) = result {
            // This is expected in no_std mode
        } else {
            panic!("sign method should return NotImplemented when std feature is disabled");
        }
    }

    // Test that verify works with valid inputs (now implemented)
    // First create a valid keypair and signature
    let mut randomness = [0u8; 48]; // 3 * 16 bytes for Shake128f
    for i in 0..48 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let keypair = slh_dsa
        .generate_keypair_with_randomness(&randomness)
        .expect("Should generate keypair");

    let signing_randomness = [0u8; 16];
    let signature = slh_dsa
        .sign_with_randomness(&keypair.secret_key, b"test message", &signing_randomness)
        .expect("Should sign message");

    // Test verification with valid signature
    let result = slh_dsa.verify(&keypair.public_key, b"test message", &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Test verification with invalid signature
    let invalid_signature = vec![0u8; signature.len()];
    let result = slh_dsa.verify(&keypair.public_key, b"test message", &invalid_signature);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

/// Test signature serialization and deserialization
#[test]
fn test_signature_serialization() {
    // Generate deterministic randomness
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&randomness);
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);

    // Sign a message
    let message = b"Test message for signature serialization";
    let mut signing_randomness = [0u8; 16];
    for i in 0..16 {
        signing_randomness[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
    }

    let mut signing_rng = TestRng::new(&signing_randomness);
    let signature = signing_key
        .try_sign_with_rng(&mut signing_rng, message)
        .expect("Signing should succeed");

    // Test signature -> bytes conversion
    let signature_bytes = slh_signature_to_bytes(&signature);
    assert!(!signature_bytes.is_empty());

    // Test bytes -> signature conversion
    let converted_signature = bytes_to_slh_signature::<Shake128f>(&signature_bytes)
        .expect("Should convert bytes to signature");
    assert_eq!(signature.to_bytes(), converted_signature.to_bytes());
}

/// Test all SLH-DSA parameter sets with type conversions
#[test]
fn test_all_parameter_sets_type_conversions() {
    test_parameter_set_type_conversions::<Sha2_128f>("SHA2-128f");
    test_parameter_set_type_conversions::<Sha2_192f>("SHA2-192f");
    test_parameter_set_type_conversions::<Sha2_256f>("SHA2-256f");
    test_parameter_set_type_conversions::<Shake128f>("SHAKE128f");
    test_parameter_set_type_conversions::<Shake192f>("SHAKE192f");
    test_parameter_set_type_conversions::<Shake256f>("SHAKE256f");
}

fn test_parameter_set_type_conversions<P: ParameterSet>(name: &str) {
    // Generate deterministic randomness
    let mut randomness = [0u8; 32];
    for i in 0..32 {
        randomness[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
    }

    let mut rng = TestRng::new(&randomness);
    let signing_key = SigningKey::<P>::new(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Test type conversions
    let sig_secret_key = signing_key_to_sig_secret_key(&signing_key)
        .expect("Should convert SigningKey to SigSecretKey");
    let sig_public_key = verifying_key_to_sig_public_key(&verifying_key)
        .expect("Should convert VerifyingKey to SigPublicKey");

    // Test round-trip conversions
    let converted_signing_key = sig_secret_key_to_signing_key::<P>(&sig_secret_key)
        .expect("Should convert SigSecretKey to SigningKey");
    let converted_verifying_key: VerifyingKey<P> =
        sig_public_key_to_verifying_key::<P>(&sig_public_key)
            .expect("Should convert SigPublicKey to VerifyingKey");

    // Verify round-trip conversions preserve data
    assert_eq!(
        signing_key.to_bytes(),
        converted_signing_key.to_bytes(),
        "Round-trip conversion should preserve signing key for {}",
        name
    );
    assert_eq!(
        verifying_key.to_bytes(),
        converted_verifying_key.to_bytes(),
        "Round-trip conversion should preserve verifying key for {}",
        name
    );
}

/// Test error handling for invalid key conversions
#[test]
fn test_invalid_key_conversion_errors() {
    // Test with invalid secret key size
    let invalid_secret_key = SigSecretKey::new(vec![0u8; 10]); // Too small
    let result = sig_secret_key_to_signing_key::<Shake128f>(&invalid_secret_key);
    assert!(result.is_err());
    if let Err(Error::InvalidKey { key_type, reason }) = result {
        assert!(key_type.contains("SLH-DSA signing key"));
        assert!(reason.contains("Failed to deserialize"));
    } else {
        panic!("Expected InvalidKey error for invalid secret key");
    }

    // Test with invalid public key size
    let invalid_public_key = SigPublicKey::new(vec![0u8; 10]); // Too small
    let result = sig_public_key_to_verifying_key::<Shake128f>(&invalid_public_key);
    assert!(result.is_err());
    if let Err(Error::InvalidKey { key_type, reason }) = result {
        assert!(key_type.contains("SLH-DSA verifying key"));
        assert!(reason.contains("Failed to deserialize"));
    } else {
        panic!("Expected InvalidKey error for invalid public key");
    }
}

/// Test error handling for invalid signature conversions
#[test]
fn test_invalid_signature_conversion_errors() {
    // Test with invalid signature size
    let invalid_signature_bytes = [0u8; 10]; // Too small
    let result = bytes_to_slh_signature::<Shake128f>(&invalid_signature_bytes);
    assert!(result.is_err());
    if let Err(Error::InvalidSignatureSize { expected, actual }) = result {
        assert_eq!(actual, 10);
        // Validate that we get a reasonable expected size (should be > 0 for a real signature)
        assert!(
            expected > 0,
            "Expected signature size should be greater than 0, got {}",
            expected
        );
    } else {
        panic!("Expected InvalidSignatureSize error for invalid signature");
    }
}

/// Test that SlhDsaSignature implements Default
#[test]
fn test_slh_dsa_signature_default() {
    let _slh_dsa1 = SlhDsaSignature::<Shake128f>::new();
    let _slh_dsa2 = SlhDsaSignature::<Shake128f>::default();

    // Both should be created successfully
    // (We can't easily test equality without implementing PartialEq)
}

/// Test that SlhDsaSignature works with all parameter sets
#[test]
fn test_slh_dsa_signature_all_parameter_sets() {
    let _slh_dsa_sha2_128f = SlhDsaSignature::<Sha2_128f>::new();
    let _slh_dsa_sha2_192f = SlhDsaSignature::<Sha2_192f>::new();
    let _slh_dsa_sha2_256f = SlhDsaSignature::<Sha2_256f>::new();
    let _slh_dsa_shake128f = SlhDsaSignature::<Shake128f>::new();
    let _slh_dsa_shake192f = SlhDsaSignature::<Shake192f>::new();
    let _slh_dsa_shake256f = SlhDsaSignature::<Shake256f>::new();

    // All should be created successfully
}
