//! Specialized random number generation implementations for different algorithms
//!
//! This module provides algorithm-specific RNG implementations that are optimized
//! for particular use cases while maintaining the unified libQ random interface.

use core::fmt;

// `Rng` is only referenced on the `all(rand, std)` ThreadRng path (see `FnDsaRng`); allow it to be
// unused whenever that path is off (no `rand`, or `rand` without `std`, e.g. bare-metal builds).
#[cfg_attr(not(all(feature = "rand", feature = "std")), allow(unused_imports))]
use rand_core::{
    Rng,
    TryCryptoRng,
    TryRng,
};

#[cfg(feature = "hash")]
use crate::Error;

/// Classical `McEliece` compatible RNG
///
/// This RNG provides the same interface as the original `AesState` but uses
/// libQ's standard RNG infrastructure instead of AES-based generation.
#[derive(Clone, Debug, PartialEq)]
pub struct ClassicalMcElieceRng {
    /// Internal state for deterministic mode
    state: u64,
    /// Counter for deterministic mode
    counter: u64,
    /// Whether this RNG is in deterministic mode
    deterministic: bool,
    /// Reseed counter for security
    reseed_counter: u32,
}

impl ClassicalMcElieceRng {
    /// Create a new secure RNG using system entropy
    ///
    /// Random output is drawn with `getrandom::fill`. The `classical-mceliece` crate feature
    /// enables the `getrandom` dependency so non-test builds always have OS entropy available
    /// (including `wasm_js` on `wasm32-unknown-unknown` when configured in the dependency graph).
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: 0,
            counter: 0,
            deterministic: false,
            reseed_counter: 0,
        }
    }

    /// Create a new deterministic RNG for testing
    ///
    /// This creates an RNG that produces deterministic output based on the seed.
    /// This is useful for testing and reproducible key generation.
    #[must_use]
    pub fn new_deterministic(seed: u64) -> Self {
        Self {
            state: seed
                .wrapping_mul(6_364_136_223_846_793_005_u64)
                .wrapping_add(1_442_695_040_888_963_407_u64),
            counter: 0,
            deterministic: true,
            reseed_counter: 0,
        }
    }

    /// Create a new deterministic RNG from byte array
    ///
    /// This creates an RNG that produces deterministic output based on the byte array.
    /// The bytes are hashed to create a 64-bit seed.
    #[must_use]
    pub fn new_deterministic_from_bytes(seed_bytes: &[u8]) -> Self {
        let mut hash = 0u64;
        for (i, &byte) in seed_bytes.iter().enumerate() {
            hash = hash.wrapping_add(u64::from(byte) << (i % 8));
        }
        Self::new_deterministic(hash)
    }

    /// Initialize the RNG with entropy (for deterministic mode)
    ///
    /// This method is provided for compatibility with the original `AesState` interface.
    /// In deterministic mode, it updates the internal state.
    /// In secure mode, it's a no-op as the RNG uses system entropy.
    pub fn randombytes_init(&mut self, entropy_input: [u8; 48]) {
        if self.deterministic {
            // Mix the entropy into the state using a simple hash-like function
            let mut hash = 0u64;
            for (i, &byte) in entropy_input.iter().enumerate() {
                hash = hash.wrapping_add(u64::from(byte) << (i % 8));
            }
            self.state = self.state.wrapping_add(hash);
            self.counter = 0;
            self.reseed_counter = 1;
        }
        // In secure mode, we don't need to initialize with entropy
        // as the RNG uses system entropy sources
    }

    /// Generate random bytes using the appropriate method
    fn generate_bytes(&mut self, dest: &mut [u8]) {
        if self.deterministic {
            self.generate_deterministic_bytes(dest);
        } else {
            self.generate_secure_bytes(dest);
        }
    }

    /// Generate deterministic random bytes for testing
    ///
    /// This implementation provides better statistical properties for CB-KEM
    /// by using a more sophisticated deterministic generation approach.
    fn generate_deterministic_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            // Use a more sophisticated deterministic generation
            // that provides better statistical properties for CB-KEM

            // Multiple LCG iterations for better distribution
            for _ in 0..3 {
                self.state = self
                    .state
                    .wrapping_mul(6_364_136_223_846_793_005_u64)
                    .wrapping_add(1_442_695_040_888_963_407_u64);
            }

            self.counter = self.counter.wrapping_add(1);

            // Enhanced entropy mixing for better statistical properties
            // This addresses the specific needs of CB-KEM
            let mut value = self.state ^
                self.counter ^
                (u64::from(self.reseed_counter) << 32) ^
                (u64::from(self.reseed_counter) << 16);

            // Additional mixing for better statistical properties
            // This helps ensure the RNG output has properties suitable for CB-KEM
            value = value.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64); // Golden ratio constant
            value ^= value >> 33;
            value = value.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64);
            value ^= value >> 29;
            value = value.wrapping_mul(0xC4CE_B9FE_1A85_EC53_u64);
            value ^= value >> 32;

            let bytes = value.to_le_bytes();

            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }

        self.reseed_counter = self.reseed_counter.wrapping_add(1);
    }

    /// Generate secure random bytes using system entropy
    ///
    /// If this crate was built without the `getrandom` feature, this function panics instead of
    /// emitting predictable bytes. If `getrandom::fill` fails at runtime, this function also
    /// panics (`TryRng` uses [`core::convert::Infallible`], so errors cannot be propagated).
    fn generate_secure_bytes(&mut self, dest: &mut [u8]) {
        #[cfg(feature = "getrandom")]
        {
            // Never recurse: `TryRng` uses `Infallible`, so refuse OS RNG failure loudly.
            assert!(
                getrandom::fill(dest).is_ok(),
                "lib_q_random::ClassicalMcElieceRng: getrandom::fill failed; \
                 refusing non-OS RNG output (enable `custom-entropy` or fix the environment)"
            );
        }

        #[cfg(not(feature = "getrandom"))]
        {
            let _ = dest;
            // Supported configurations that expose secure `ClassicalMcElieceRng` enable `getrandom`
            // (see the `classical-mceliece` feature). If this path is hit, the crate was built
            // without OS entropy support; do not substitute deterministic or PRNG output.
            panic!(
                "lib_q_random: ClassicalMcElieceRng requires the `getrandom` crate feature for secure output; \
                 enable `getrandom`/`secure`/`classical-mceliece`, or use `new_deterministic` for tests"
            );
        }

        self.reseed_counter = self.reseed_counter.wrapping_add(1);
    }
}

impl Default for ClassicalMcElieceRng {
    fn default() -> Self {
        Self::new()
    }
}

impl Eq for ClassicalMcElieceRng {}

impl fmt::Display for ClassicalMcElieceRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ClassicalMcElieceRng {{")?;
        writeln!(f, "  state = {}", self.state)?;
        writeln!(f, "  counter = {}", self.counter)?;
        writeln!(f, "  deterministic = {}", self.deterministic)?;
        writeln!(f, "  reseed_counter = {}", self.reseed_counter)?;
        writeln!(f, "}}")
    }
}

impl TryRng for ClassicalMcElieceRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.generate_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for ClassicalMcElieceRng {}

/// HPKE-compatible RNG using RFC 9861 **KT128** (`KangarooTwelve` / `TurboSHAKE128`)
///
/// This implementation provides cryptographically secure random number generation
/// using libQ's **KT128** (`KangarooTwelve`) primitive. K12 is significantly
/// faster than SHAKE256 while maintaining the same security properties.
#[cfg(feature = "hash")]
#[derive(Clone, Debug)]
pub struct Kt128Rng {
    expander: crate::kt128_expander::Kt128Expander,
}

#[cfg(feature = "hash")]
impl Kt128Rng {
    /// Create a new secure RNG with system entropy
    ///
    /// # Errors
    ///
    /// Returns an error if entropy source is unavailable or fails to initialize.
    pub fn new() -> crate::Result<Self> {
        #[cfg(feature = "getrandom")]
        {
            // Use system entropy to seed the RNG
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| Error::EntropySourceUnavailable {
                source: "system",
                context: Some("getrandom failed"),
            })?;
            Ok(Self::from_seed(&seed))
        }
        #[cfg(not(feature = "getrandom"))]
        {
            // No insecure fallback - fail fast if getrandom is not available
            Err(Error::FeatureNotAvailable {
                feature: "secure entropy",
                required_features: &["getrandom"],
            })
        }
    }

    /// Create a new secure RNG with explicit seed
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            expander: crate::kt128_expander::Kt128Expander::from_seed(
                crate::kt128_expander::DOMAIN_HPKE_RNG,
                seed,
            ),
        }
    }

    /// Refill the internal buffer with new random data (advances the KT128 chain).
    pub fn refill(&mut self) {
        self.expander.refill();
    }
}

#[cfg(feature = "hash")]
impl TryRng for Kt128Rng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.expander.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(feature = "hash")]
#[cfg(test)]
mod kt128_rng_tests {
    use super::*;
    use crate::kt128_expander::Kt128Expander;

    /// HPKE domain + seed must match the shared expander (regression for refactor).
    #[test]
    fn test_kt128_rng_matches_hpke_domain_expander() {
        let seed = [9u8; 32];
        let mut rng = Kt128Rng::from_seed(&seed);
        let mut exp = Kt128Expander::from_seed(crate::kt128_expander::DOMAIN_HPKE_RNG, &seed);
        let mut a = [0u8; 128];
        let mut b = [0u8; 128];
        rng.fill_bytes(&mut a);
        exp.fill_bytes(&mut b);
        assert_eq!(a, b);
    }
}

#[cfg(feature = "hash")]
impl TryCryptoRng for Kt128Rng {}

// HPKE-specific trait implementation for compatibility
// This will be implemented in the HPKE crate itself to avoid circular dependencies

/// FN-DSA compatible RNG with environment-specific implementations
pub struct FnDsaRng {
    // `rand::rngs::ThreadRng` lives in `std` (it needs `rand`'s `thread_rng`). On `no_std` — even
    // when `rand` is enabled — there is no ThreadRng, so fall back to getrandom/deterministic below.
    #[cfg(all(feature = "rand", feature = "std"))]
    rng: Option<rand::rngs::ThreadRng>,
}

impl Default for FnDsaRng {
    fn default() -> Self {
        Self::new()
    }
}

impl FnDsaRng {
    /// Create a new FN-DSA compatible RNG
    #[must_use]
    pub fn new() -> Self {
        #[cfg(all(feature = "rand", feature = "std"))]
        {
            Self {
                rng: Some(rand::rng()),
            }
        }
        #[cfg(not(all(feature = "rand", feature = "std")))]
        {
            Self {}
        }
    }
}

impl TryRng for FnDsaRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        #[cfg(all(feature = "rand", feature = "std"))]
        {
            if let Some(ref mut rng) = self.rng {
                Ok(rng.next_u32())
            } else {
                let mut bytes = [0u8; 4];
                self.try_fill_bytes(&mut bytes)?;
                Ok(u32::from_le_bytes(bytes))
            }
        }
        #[cfg(not(all(feature = "rand", feature = "std")))]
        {
            #[cfg(feature = "getrandom")]
            {
                let mut bytes = [0u8; 4];
                getrandom::fill(&mut bytes).expect("Failed to get random bytes from getrandom");
                Ok(u32::from_le_bytes(bytes))
            }
            #[cfg(not(feature = "getrandom"))]
            {
                panic!(
                    "FnDsaRng requires the 'std' (ThreadRng) or 'getrandom' feature. \
                       Use deterministic RNG for testing without these features."
                );
            }
        }
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        #[cfg(all(feature = "getrandom", not(all(feature = "rand", feature = "std"))))]
        {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).expect("Failed to get random bytes from getrandom");
            Ok(u64::from_le_bytes(bytes))
        }

        #[cfg(not(all(feature = "getrandom", not(all(feature = "rand", feature = "std")))))]
        {
            let upper = u64::from(self.try_next_u32()?);
            let lower = u64::from(self.try_next_u32()?);
            Ok((upper << 32) | lower)
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        // `rand` disabled + `getrandom` enabled (e.g. WASM with `wasm_js`): fill the whole buffer in
        // one call. The default path uses `try_next_u32` per 4-byte chunk, which would invoke
        // `getrandom::fill` once per chunk and amplify syscall / JS bridge overhead.
        #[cfg(all(feature = "getrandom", not(all(feature = "rand", feature = "std"))))]
        {
            getrandom::fill(dest).expect("Failed to get random bytes from getrandom");
            Ok(())
        }

        #[cfg(not(all(feature = "getrandom", not(all(feature = "rand", feature = "std")))))]
        {
            for chunk in dest.chunks_mut(4) {
                let bytes = self.try_next_u32()?.to_le_bytes();
                let len = chunk.len().min(4);
                chunk[..len].copy_from_slice(&bytes[..len]);
            }
            Ok(())
        }
    }
}

impl TryCryptoRng for FnDsaRng {}

#[cfg(test)]
mod tests {
    use rand_core::Rng;

    use super::*;

    #[test]
    fn test_classical_mceliece_rng_creation() {
        let rng = ClassicalMcElieceRng::new();
        assert!(!rng.deterministic);
        assert_eq!(rng.state, 0);
        assert_eq!(rng.counter, 0);
    }

    #[test]
    fn test_classical_mceliece_deterministic_rng_creation() {
        let rng = ClassicalMcElieceRng::new_deterministic(12345);
        assert!(rng.deterministic);
        // The state is transformed by the LCG, so we check it's not zero
        assert_ne!(rng.state, 0);
        assert_eq!(rng.counter, 0);
    }

    #[test]
    fn test_classical_mceliece_deterministic_rng_consistency() {
        let mut rng1 = ClassicalMcElieceRng::new_deterministic(42);
        let mut rng2 = ClassicalMcElieceRng::new_deterministic(42);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        rng1.fill_bytes(&mut bytes1);
        rng2.fill_bytes(&mut bytes2);

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_classical_mceliece_rng_interface() {
        let mut rng = ClassicalMcElieceRng::new_deterministic(100);

        // Test fill_bytes
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        assert_ne!(bytes, [0u8; 16]); // Should not be all zeros

        // Test next_u32
        let val1 = rng.next_u32();
        let val2 = rng.next_u32();
        assert_ne!(val1, val2); // Should be different

        // Test next_u64
        let val3 = rng.next_u64();
        let val4 = rng.next_u64();
        assert_ne!(val3, val4); // Should be different
    }

    #[test]
    fn test_classical_mceliece_randombytes_init() {
        let mut rng = ClassicalMcElieceRng::new_deterministic(0);
        let entropy = [1u8; 48];

        rng.randombytes_init(entropy);

        // State should be updated
        assert_ne!(rng.state, 0);
        assert_eq!(rng.reseed_counter, 1);
    }

    #[test]
    fn test_fn_dsa_rng_creation() {
        let _rng = FnDsaRng::new();
        // Should create without panicking
        // Test passes if we reach this point
    }

    #[test]
    #[cfg(any(feature = "rand", feature = "getrandom"))]
    fn test_fn_dsa_rng_interface() {
        let mut rng = FnDsaRng::new();

        // Test fill_bytes
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        // Should not panic

        // Test next_u32
        let val1 = rng.next_u32();
        let val2 = rng.next_u32();
        // Should not panic and should be different (very high probability)
        assert_ne!(val1, val2);

        // Test next_u64
        let val3 = rng.next_u64();
        let val4 = rng.next_u64();
        // Should not panic and should be different (very high probability)
        assert_ne!(val3, val4);
    }

    /// Odd-length buffer: `getrandom`-only `try_fill_bytes` must use a single `getrandom::fill`
    /// (not one `fill` per 4-byte chunk via `try_next_u32`).
    #[test]
    #[cfg(all(feature = "getrandom", not(feature = "rand")))]
    fn test_fn_dsa_rng_fill_bytes_getrandom_only_odd_length() {
        let mut rng = FnDsaRng::new();
        let mut buf = [0u8; 1281];
        rng.fill_bytes(&mut buf);
    }
}
