//! SHAKE256 PRNG entropy source for KAT compatibility
//!
//! This module provides a SHAKE256-based PRNG that is compatible with the
//! reference HQC implementation's PRNG for Known Answer Test (KAT) validation.

#[cfg(feature = "random")]
use lib_q_random::Result;
#[cfg(feature = "random")]
use lib_q_random::traits::{
    EntropySource,
    EntropySourceType,
};

#[cfg(feature = "random")]
/// SHAKE256 PRNG entropy source for KAT compatibility
///
/// This entropy source uses SHAKE256 XOF to generate deterministic random bytes,
/// compatible with the reference HQC implementation's PRNG.
pub struct Shake256PrngEntropySource {
    /// SHAKE256 XOF context
    xof: crate::internal::shake256::Shake256Xof,
    /// Quality estimate (high for SHAKE256)
    quality: f64,
}

#[cfg(feature = "random")]
impl Shake256PrngEntropySource {
    /// Create a new SHAKE256 PRNG entropy source
    ///
    /// # Arguments
    /// * `entropy_input` - 48-byte entropy input to initialize the PRNG
    ///
    /// # Returns
    /// A new SHAKE256 PRNG entropy source
    ///
    /// # Implementation Notes
    /// This implementation follows the reference HQC implementation exactly:
    /// 1. Initialize SHAKE256 context (shake256_inc_init)
    /// 2. Absorb entropy input (shake256_inc_absorb with entropy_input, enlen=48)
    /// 3. Absorb personalization string (shake256_inc_absorb with NULL, perlen=0)
    /// 4. Absorb domain byte (shake256_inc_absorb with HQC_PRNG_DOMAIN=0)
    /// 5. Finalize absorption phase (shake256_inc_finalize)
    ///
    /// The personalization string absorption step is critical - even when the
    /// personalization string is empty (NULL in C, empty slice in Rust), the
    /// absorption call must be made to match the reference implementation's
    /// state machine exactly.
    pub fn new(entropy_input: [u8; 48]) -> Self {
        let mut xof = crate::internal::shake256::Shake256Xof::new();

        // 1. Absorb entropy input (equivalent to shake256_inc_absorb with entropy_input, enlen=48)
        xof.absorb(&entropy_input)
            .expect("SHAKE256 absorb entropy failed");

        // 2. Absorb personalization string (empty for KAT, but must call)
        // Reference: shake256_inc_absorb(&shake256_prng_ctx, personalization_string, perlen);
        // For KAT: personalization_string=NULL, perlen=0
        // Even though it's 0 bytes, we must call absorb with empty slice to match reference
        xof.absorb(&[])
            .expect("SHAKE256 absorb personalization failed");

        // 3. Absorb domain byte (equivalent to shake256_inc_absorb with domain)
        const HQC_PRNG_DOMAIN: u8 = 0; // From reference implementation
        xof.absorb(&[HQC_PRNG_DOMAIN])
            .expect("SHAKE256 absorb domain failed");

        // 4. Finalize absorption phase (equivalent to shake256_inc_finalize)
        xof.finalize_absorb()
            .expect("SHAKE256 finalize absorb failed");

        Self {
            xof,
            quality: 0.95, // High quality for SHAKE256
        }
    }
}

#[cfg(feature = "random")]
impl EntropySource for Shake256PrngEntropySource {
    fn get_entropy(&mut self, dest: &mut [u8]) -> Result<()> {
        self.xof
            .squeeze(dest)
            .map_err(|_| lib_q_random::Error::entropy_source_unavailable("SHAKE256 squeeze failed"))
    }

    fn is_available(&self) -> bool {
        true
    }

    fn quality(&self) -> f64 {
        self.quality
    }

    fn name(&self) -> &'static str {
        "SHAKE256 PRNG"
    }

    fn source_type(&self) -> EntropySourceType {
        EntropySourceType::Deterministic
    }

    fn max_entropy_per_call(&self) -> Option<usize> {
        None // No limit for SHAKE256
    }
}

#[cfg(feature = "random")]
/// Create a LibQRng instance with SHAKE256 PRNG for KAT compatibility
///
/// This function creates an RNG instance using SHAKE256 XOF for deterministic
/// random number generation, compatible with the reference HQC implementation.
///
/// # Arguments
/// * `entropy_input` - 48-byte entropy input to initialize the PRNG
///
/// # Returns
/// A new LibQRng instance with SHAKE256 PRNG
///
/// # Example
/// ```
/// use lib_q_hqc::shake256_prng::create_shake256_prng_rng;
/// let entropy_input = [0u8; 48]; // Your entropy input
/// let mut rng = create_shake256_prng_rng(entropy_input);
/// let mut bytes = [0u8; 32];
/// rng.fill_bytes(&mut bytes);
/// ```
pub fn create_shake256_prng_rng(entropy_input: [u8; 48]) -> lib_q_random::LibQRng {
    let entropy_source = Shake256PrngEntropySource::new(entropy_input);
    lib_q_random::LibQRng::new_custom(entropy_source)
}
