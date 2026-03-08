#![no_std]
#![doc = include_str!("../README.md")]
#![warn(clippy::pedantic)] // Be pedantic by default
//#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::module_name_repetitions)] // There are many types of signature and otherwise this gets confusing
#![allow(clippy::similar_names)] // TODO: Consider resolving these
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![deny(missing_docs)] // Require all public interfaces to be documented

#[cfg(feature = "alloc")]
extern crate alloc;

pub use signature;

mod address;
mod fors;
mod hashes;
mod hypertree;
pub mod lib_q_integration;
mod signature_encoding;
mod signing_key;
mod util;
mod verifying_key;
mod wots;
mod xmss;

// no_std RNG implementation
#[cfg(not(feature = "std"))]
mod no_std_rng;

use fors::ForsParams;
pub use hashes::{
    Sha2_128f,
    Sha2_128s,
    Sha2_192f,
    Sha2_192s,
    Sha2_256f,
    Sha2_256s,
    Sha2L1,
    Sha2L35,
    Shake,
    Shake128f,
    Shake128s,
    Shake192f,
    Shake192s,
    Shake256f,
    Shake256s,
};
pub use signature_encoding::{
    Signature,
    SignatureLen,
};
pub use signing_key::{
    SigningKey,
    SigningKeyLen,
};
// Re-export internal types for use by other modules
pub use signing_key::{
    SkPrf,
    SkSeed,
};
pub use verifying_key::{
    PkSeed,
    VerifyingKey,
    VerifyingKeyLen,
};

/// Specific parameters for each of the 12 FIPS parameter sets
///
/// This trait defines the interface for SLH-DSA parameter sets as specified in
/// NIST FIPS-205. Each parameter set provides different security levels and
/// performance characteristics.
///
/// # Security Levels
///
/// - **Level 1 (128-bit)**: SHA256-128f, SHA256-128s, SHAKE256-128f, SHAKE256-128s
/// - **Level 3 (192-bit)**: SHA256-192f, SHA256-192s, SHAKE256-192f, SHAKE256-192s  
/// - **Level 5 (256-bit)**: SHA256-256f, SHA256-256s, SHAKE256-256f, SHAKE256-256s
///
/// # Example Usage
///
/// ```rust
/// use lib_q_random::new_secure_rng;
/// use lib_q_slh_dsa::{
///     ParameterSet,
///     Shake128f,
///     SigningKey,
/// };
/// use signature::*;
///
/// // Create a signing key for the SHAKE256-128f parameter set
/// let mut rng = new_secure_rng().expect("Failed to create RNG");
/// let sk = SigningKey::<Shake128f>::new(&mut rng);
/// let vk = sk.verifying_key();
///
/// // Sign and verify a message
/// let message = b"Hello, SLH-DSA!";
/// let sig = sk.sign_with_rng(&mut rng, message);
/// assert!(vk.verify(message, &sig).is_ok());
/// ```
#[allow(private_bounds)] // Intentionally un-usable type
pub trait ParameterSet:
    ForsParams + SigningKeyLen + VerifyingKeyLen + SignatureLen + PartialEq + Eq
{
    /// Human-readable name for parameter set, matching the FIPS-205 designations
    ///
    /// # Examples
    ///
    /// - `"SLH-DSA-SHA256-128f-Robust"`
    /// - `"SLH-DSA-SHAKE256-192f-Robust"`
    /// - `"SLH-DSA-SHA256-256f-Robust"`
    const NAME: &'static str;

    /// Associated OID with the Parameter
    ///
    /// This OID is used for PKCS#8 key encoding and other cryptographic
    /// protocols that require algorithm identification.
    const ALGORITHM_OID: pkcs8::ObjectIdentifier;
}

#[cfg(test)]
mod tests {
    use ::rand_core::Rng;
    use lib_q_random::new_secure_rng;
    use signature::*;
    use util::macros::test_parameter_sets;

    use super::*;

    fn test_sign_verify<P: ParameterSet>() {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");
        let sk = SigningKey::<P>::new(&mut rng);
        let vk = sk.verifying_key();
        let msg = b"Hello, world!";
        let sig = sk.try_sign(msg).unwrap();
        vk.verify(msg, &sig).unwrap();
    }
    test_parameter_sets!(test_sign_verify);

    // Check signature fails on modified message
    #[test]
    fn test_sign_verify_shake_128f_fail_on_modified_message() {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let msg = b"Hello, world!";
        let modified_msg = b"Goodbye, world!";

        let sig = sk.try_sign(msg).unwrap();
        let vk = sk.verifying_key();
        assert!(vk.verify(msg, &sig).is_ok());
        assert!(vk.verify(modified_msg, &sig).is_err());
    }

    #[test]
    fn test_sign_verify_fail_with_wrong_verifying_key() {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let wrong_sk = SigningKey::<Shake128f>::new(&mut rng); // Generate a different signing key
        let msg = b"Hello, world!";

        let sig = sk.try_sign(msg).unwrap();
        let vk = sk.verifying_key();
        let wrong_vk = wrong_sk.verifying_key(); // Get the verifying key of the wrong signing key
        assert!(vk.verify(msg, &sig).is_ok());
        assert!(wrong_vk.verify(msg, &sig).is_err()); // This should fail because the verifying key does not match the signing key used
    }

    #[test]
    fn test_sign_verify_fail_on_modified_signature() {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let msg = b"Hello, world!";

        let mut sig_bytes = sk.try_sign(msg).unwrap().to_bytes();
        // Randomly modify one byte in the signature
        let sig_len = sig_bytes.len();
        let random_byte_index = rng.next_u32() as usize % sig_len;
        sig_bytes[random_byte_index] ^= 0xFF; // Invert one byte to ensure it's different
        let sig = (&sig_bytes).into();

        let vk = sk.verifying_key();
        assert!(
            vk.verify(msg, &sig).is_err(),
            "Verification should fail with a modified signature"
        );
    }

    #[test]
    fn test_successive_signatures_not_equal() {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let msg = b"Hello, world!";

        let sig1 = sk.try_sign_with_rng(&mut rng, msg).unwrap();
        let sig2 = sk.try_sign_with_rng(&mut rng, msg).unwrap();

        assert_ne!(
            sig1, sig2,
            "Two successive randomized signatures over the same message should not be equal"
        );
    }

    #[test]
    fn test_sign_verify_nonempty_context() {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let vk = sk.verifying_key();
        let msg = b"Hello, world!";
        let ctx = b"Test context";
        let sig = sk.try_sign_with_context(msg, ctx, None).unwrap();
        vk.try_verify_with_context(msg, ctx, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_wrong_context() {
        let mut rng = new_secure_rng().expect("Failed to create secure RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let vk = sk.verifying_key();
        let msg = b"Hello, world!";
        let ctx = b"Test context!";
        let wrong_ctx = b"Wrong context";
        let sig = sk.try_sign_with_context(msg, ctx, None).unwrap();
        assert!(vk.try_verify_with_context(msg, wrong_ctx, &sig).is_err());
    }

    #[test]
    fn test_documentation_example_basic_usage() {
        use lib_q_random::new_secure_rng;
        use signature::*;

        use crate::{
            Shake128f,
            SigningKey,
        };

        let mut rng = new_secure_rng().expect("Failed to create RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let vk = sk.verifying_key();

        let message = b"Hello, SLH-DSA!";
        let sig = sk.sign_with_rng(&mut rng, message);
        assert!(vk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_documentation_example_multiple_messages() {
        use lib_q_random::new_secure_rng;
        use signature::*;

        use crate::{
            Shake128f,
            SigningKey,
        };

        let mut rng = new_secure_rng().expect("Failed to create RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let vk = sk.verifying_key();

        let messages: &[&[u8]] = &[b"First message", b"Second message", b"Third message"];

        for message in messages {
            let sig = sk.sign_with_rng(&mut rng, message);
            assert!(vk.verify(message, &sig).is_ok());
        }
    }

    #[test]
    fn test_documentation_example_no_std_environment() {
        // In no_std environments, you must provide randomness externally
        // Use a proper deterministic RNG to generate valid key randomness
        use lib_q_random::new_deterministic_rng;
        use signature::*;

        use crate::{
            Shake128f,
            SigningKey,
        };
        let mut key_rng = new_deterministic_rng(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut key_randomness = [0u8; 48]; // 3 * 16 bytes for Shake128f
        key_rng.fill_bytes(&mut key_randomness);

        let mut signing_randomness = [0u8; 16]; // 16 bytes for signing
        key_rng.fill_bytes(&mut signing_randomness);

        let sk = SigningKey::<Shake128f>::new(&mut key_rng);
        let vk = sk.verifying_key();

        let message = b"Hello, no_std SLH-DSA!";
        // Use the std RNG for this test since we're in std mode
        let mut rng = new_deterministic_rng(&signing_randomness);
        let sig = sk.sign_with_rng(&mut rng, message);
        assert!(vk.verify(message, &sig).is_ok());
    }

    #[test]
    fn test_parameter_set_documentation_example() {
        use lib_q_random::new_secure_rng;
        use signature::*;

        use crate::{
            Shake128f,
            SigningKey,
        };

        // Create a signing key for the SHAKE256-128f parameter set
        let mut rng = new_secure_rng().expect("Failed to create RNG");
        let sk = SigningKey::<Shake128f>::new(&mut rng);
        let vk = sk.verifying_key();

        // Sign and verify a message
        let message = b"Hello, SLH-DSA!";
        let sig = sk.sign_with_rng(&mut rng, message);
        assert!(vk.verify(message, &sig).is_ok());
    }
}

/// Create a new secure RNG instance for no_std environments
///
/// This function creates a cryptographically secure RNG that works in no_std
/// environments using getrandom for entropy.
///
/// # Errors
///
/// Returns an error if getrandom is not available or fails to initialize.
///
/// # Examples
///
/// ```rust,no_run
/// use lib_q_slh_dsa::new_secure_rng_no_std;
/// use rand_core::Rng;
///
/// let mut rng = new_secure_rng_no_std().unwrap();
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(not(feature = "std"))]
pub fn new_secure_rng_no_std() -> Result<no_std_rng::SlhDsaNoStdRng, no_std_rng::NoStdError> {
    no_std_rng::SlhDsaNoStdRng::new()
}

/// Create a new deterministic RNG instance for no_std environments
///
/// This function creates a deterministic RNG suitable for testing and
/// reproducible operations in no_std environments. **NOT CRYPTOGRAPHICALLY SECURE**.
///
/// # Arguments
///
/// * `seed` - The seed value for deterministic generation
///
/// # Examples
///
/// ```rust,no_run
/// use lib_q_slh_dsa::new_deterministic_rng_no_std;
/// use rand_core::Rng;
///
/// let mut rng = new_deterministic_rng_no_std(&[1, 2, 3, 4]);
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
#[cfg(not(feature = "std"))]
#[must_use]
pub fn new_deterministic_rng_no_std(seed: &[u8]) -> no_std_rng::SlhDsaNoStdRng {
    no_std_rng::SlhDsaNoStdRng::new_deterministic(seed)
}
