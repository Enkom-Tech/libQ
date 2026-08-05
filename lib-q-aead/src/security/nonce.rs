//! Nonce Management
//!
//! This module provides secure nonce generation and uniqueness checking for AEAD operations.
//! It implements proper nonce management to prevent nonce reuse attacks.

// Only used by the `not(shake256)` arm of `generate_secure_nonce` below. Gated (rather than an
// unconditional import) because under `std` + `shake256` the unqualified `alloc::string::String`
// path is already in scope via the std prelude, and `#![deny(unused_qualifications)]` at the
// crate root flags the fully-qualified spelling as redundant on that combination — but an
// unconditional import here would itself become an unused import under `shake256`-on builds,
// where this arm doesn't compile at all.
#[cfg(not(feature = "shake256"))]
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
#[cfg(all(feature = "alloc", feature = "std"))]
#[allow(clippy::disallowed_types)]
use std::collections::HashSet;

use lib_q_core::{
    Error,
    Nonce,
    Result,
};
use portable_atomic::AtomicU64;

/// Nonce management configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceConfig {
    /// Enable nonce uniqueness checking
    pub check_uniqueness: bool,
    /// Maximum number of nonces to track for uniqueness
    pub max_tracked_nonces: usize,
    /// Enable secure random nonce generation
    pub secure_generation: bool,
    /// Nonce size in bytes
    pub nonce_size: usize,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            check_uniqueness: true,
            max_tracked_nonces: 1000,
            secure_generation: true,
            nonce_size: 16, // 128 bits
        }
    }
}

impl NonceConfig {
    /// Create a strict nonce configuration
    pub fn strict() -> Self {
        Self {
            check_uniqueness: true,
            max_tracked_nonces: 10000,
            secure_generation: true,
            nonce_size: 16,
        }
    }

    /// Create a permissive nonce configuration
    ///
    /// SECURITY (B4c): this used to also set `secure_generation: false`, which routes
    /// [`NonceManager::generate_nonce`] to a counter-derived nonce whose every byte is a
    /// deterministic function of an `AtomicU64` counter that always starts at `0` — so two
    /// independently constructed managers built from this config emitted an *identical* first
    /// nonce in every process, with `check_uniqueness: false` on top so the collision was never
    /// even detected. "Permissive" is kept scoped to what its sibling configs in this crate mean
    /// by the word (`SecurityConfig::permissive()`, `TimingProtection::permissive()`,
    /// `SideChannelProtection::permissive()`: skip extra bookkeeping/overhead, never weaken a core
    /// cryptographic guarantee) — it now only disables nonce-uniqueness *tracking*, not secure
    /// generation itself.
    pub fn permissive() -> Self {
        Self {
            check_uniqueness: false,
            max_tracked_nonces: 0,
            secure_generation: true,
            nonce_size: 16,
        }
    }
}

/// Nonce manager for secure nonce handling
/// with collision detection and secure tracking
pub struct NonceManager {
    config: NonceConfig,
    counter: AtomicU64,
    // Track recently used nonces to prevent collisions (requires std)
    #[cfg(all(feature = "alloc", feature = "std"))]
    #[allow(clippy::disallowed_types)]
    used_nonces: std::sync::RwLock<HashSet<Vec<u8>>>,
    // For no_std or alloc-only environments, use a simple bloom filter approximation
    #[cfg(not(all(feature = "alloc", feature = "std")))]
    used_nonces: AtomicU64,
}

impl NonceManager {
    /// Create a new nonce manager with default configuration
    pub fn new() -> Self {
        Self::with_config(NonceConfig::default())
    }

    /// Create a new nonce manager with custom configuration
    pub fn with_config(config: NonceConfig) -> Self {
        Self {
            config,
            counter: AtomicU64::new(0),
            #[cfg(all(feature = "alloc", feature = "std"))]
            #[allow(clippy::disallowed_types)]
            used_nonces: std::sync::RwLock::new(HashSet::new()),
            #[cfg(not(all(feature = "alloc", feature = "std")))]
            used_nonces: AtomicU64::new(0),
        }
    }

    /// Generate a new nonce
    pub fn generate_nonce(&self) -> Result<Nonce> {
        if self.config.secure_generation {
            self.generate_secure_nonce()
        } else {
            self.generate_counter_nonce()
        }
    }

    /// Generate a secure random nonce with collision detection
    ///
    /// # Errors
    ///
    /// SECURITY (B4): earlier versions filled `nonce_data` from a fixed-key `DefaultHasher` over
    /// wall-clock time + a per-instance counter (std), or a bare LCG over that same
    /// always-zero-at-construction counter (no_std / wasm32). Neither is a cryptographic entropy
    /// source: the std path is fully predictable from public information (the approximate send
    /// time) and the no_std/wasm32 path is 100% deterministic — every fresh `NonceManager` emitted
    /// the same first nonce. This now routes through `lib-q-random` (OS/hardware entropy) and
    /// fails closed — returning [`Error::RandomGenerationFailed`] — rather than falling back to a
    /// non-cryptographic generator when the `shake256` feature (which pulls in `lib-q-random`) is
    /// not enabled or the entropy source itself fails.
    fn generate_secure_nonce(&self) -> Result<Nonce> {
        // The `not(shake256)` arm returns unconditionally, so it must come first and be the only
        // thing that arm does: with the allocation and post-processing below it (as they used to
        // be, pre-cfg-split), rustc correctly flags the collision/zero/all-ones code after it as
        // unreachable, and `nonce_data` as unused/never-needs-`mut`, under that cfg. Splitting the
        // function into two mutually exclusive tail expressions keeps both warning-free without
        // weakening the fail-closed behaviour — the error value and message are unchanged.
        #[cfg(not(feature = "shake256"))]
        {
            // Retained for diagnostics / `get_counter()` back-compat.
            self.counter.fetch_add(1, Ordering::SeqCst);
            Err(Error::RandomGenerationFailed {
                operation: String::from(
                    "lib-q-aead secure nonce generation requires the `shake256` feature (it \
                     pulls in lib-q-random for OS/hardware entropy); there is no \
                     non-cryptographic fallback",
                ),
            })
        }

        #[cfg(feature = "shake256")]
        {
            // Retained for diagnostics / `get_counter()` back-compat; the nonce bytes below come
            // entirely from a real entropy source, never from this counter.
            self.counter.fetch_add(1, Ordering::SeqCst);

            let mut nonce_data = alloc::vec![0u8; self.config.nonce_size];

            lib_q_random::fill_entropy(&mut nonce_data).map_err(|e| {
                Error::RandomGenerationFailed {
                    operation: alloc::format!(
                        "lib-q-aead secure nonce generation: entropy source unavailable: {e}"
                    ),
                }
            })?;

            // Check for collisions and regenerate if necessary
            if self.is_nonce_used(&nonce_data)? {
                // If collision detected, try again with different seed
                return self.generate_secure_nonce();
            }

            // Ensure the nonce is not all zeros or all ones
            if nonce_data.iter().all(|&b| b == 0) {
                nonce_data[0] = 1; // Make it non-zero
            }
            if nonce_data.iter().all(|&b| b == 0xFF) {
                nonce_data[0] = 0xFE; // Make it not all ones
            }

            Ok(Nonce::new(nonce_data))
        }
    }

    /// Generate a counter-based nonce
    fn generate_counter_nonce(&self) -> Result<Nonce> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);

        let mut nonce_data = Vec::with_capacity(self.config.nonce_size);

        // Use the counter in a more distributed way
        for i in 0..self.config.nonce_size {
            let byte = ((counter.wrapping_mul(0x9E3779B9u64.wrapping_add(i as u64))) >> 24) as u8;
            nonce_data.push(byte);
        }

        // Ensure the nonce is not all zeros or all ones
        if nonce_data.iter().all(|&b| b == 0) {
            nonce_data[0] = 1; // Make it non-zero
        }
        if nonce_data.iter().all(|&b| b == 0xFF) {
            nonce_data[0] = 0xFE; // Make it not all ones
        }

        Ok(Nonce::new(nonce_data))
    }

    /// Check if a nonce has been used before
    fn is_nonce_used(&self, nonce_data: &[u8]) -> Result<bool> {
        #[cfg(all(feature = "alloc", feature = "std"))]
        {
            if let Ok(used_nonces) = self.used_nonces.read() {
                Ok(used_nonces.contains(nonce_data))
            } else {
                Err(Error::InvalidNonceSize {
                    expected: 0,
                    actual: 0,
                })
            }
        }

        #[cfg(not(all(feature = "alloc", feature = "std")))]
        {
            // For no_std or alloc-only, use a simple hash-based approximation
            let hash = self.hash_nonce(nonce_data);
            let used_nonces = self.used_nonces.load(Ordering::SeqCst);
            Ok((used_nonces & (1 << (hash % 64))) != 0)
        }
    }

    /// Internal method to mark nonce data as used
    fn mark_nonce_used_internal(&self, nonce_data: &[u8]) -> Result<()> {
        #[cfg(all(feature = "alloc", feature = "std"))]
        {
            if let Ok(mut used_nonces) = self.used_nonces.write() {
                used_nonces.insert(nonce_data.to_vec());

                // Limit the size of the tracking set to prevent memory exhaustion
                if used_nonces.len() > 10000 {
                    // Remove oldest entries (simple FIFO)
                    let to_remove: Vec<_> = used_nonces.iter().take(1000).cloned().collect();
                    for entry in to_remove {
                        used_nonces.remove(&entry);
                    }
                }
                Ok(())
            } else {
                Err(Error::InvalidNonceSize {
                    expected: 0,
                    actual: 0,
                })
            }
        }

        #[cfg(not(all(feature = "alloc", feature = "std")))]
        {
            // For no_std or alloc-only, use a simple hash-based approximation
            let hash = self.hash_nonce(nonce_data);
            let mut used_nonces = self.used_nonces.load(Ordering::SeqCst);
            used_nonces |= 1 << (hash % 64);
            self.used_nonces.store(used_nonces, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Hash a nonce for tracking (simple hash function)
    #[cfg(not(all(feature = "alloc", feature = "std")))]
    fn hash_nonce(&self, nonce_data: &[u8]) -> u64 {
        let mut hash = 0u64;
        for &byte in nonce_data {
            hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
        }
        hash
    }

    /// Validate a nonce for uniqueness
    pub fn validate_nonce(&self, nonce: &Nonce) -> Result<()> {
        if !self.config.check_uniqueness {
            return Ok(());
        }

        // Check format first
        self.validate_nonce_format(nonce)?;

        // Check for uniqueness
        let nonce_data = nonce.as_bytes();
        if self.is_nonce_used(nonce_data)? {
            return Err(Error::InvalidNonceSize {
                expected: 0,
                actual: 0,
            });
        }

        // Mark as used
        self.mark_nonce_used_internal(nonce_data)
    }

    /// Validate nonce format
    fn validate_nonce_format(&self, nonce: &Nonce) -> Result<()> {
        let nonce_bytes = nonce.as_bytes();

        if nonce_bytes.len() != self.config.nonce_size {
            return Err(Error::InvalidNonceSize {
                expected: self.config.nonce_size,
                actual: nonce_bytes.len(),
            });
        }

        // Check for zero nonce
        if nonce_bytes.iter().all(|&b| b == 0) {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        // Check for all-ones nonce
        if nonce_bytes.iter().all(|&b| b == 0xFF) {
            return Err(Error::InvalidNonceSize {
                expected: 1,
                actual: 0,
            });
        }

        Ok(())
    }

    /// Check if a nonce is unique (not used before)
    pub fn is_nonce_unique(&self, nonce: &Nonce) -> bool {
        if !self.config.check_uniqueness {
            return true;
        }

        // Check against our tracking system
        match self.is_nonce_used(nonce.as_bytes()) {
            Ok(used) => !used,
            Err(_) => false, // If we can't check, assume it's not unique for safety
        }
    }

    /// Mark a nonce as used (public interface)
    pub fn mark_nonce_used(&self, nonce: &Nonce) -> Result<()> {
        if !self.config.check_uniqueness {
            return Ok(());
        }

        // Add the nonce to our tracking system
        self.validate_nonce_format(nonce)?;
        self.mark_nonce_used_internal(nonce.as_bytes())
    }

    /// Get the current counter value
    pub fn get_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Reset the counter (use with caution)
    pub fn reset_counter(&self) {
        self.counter.store(0, Ordering::SeqCst);
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global nonce manager (std + alloc: lazy init with HashSet tracking)
#[cfg(all(feature = "alloc", feature = "std"))]
static NONCE_MANAGER: std::sync::LazyLock<NonceManager> =
    std::sync::LazyLock::new(|| NonceManager {
        config: NonceConfig {
            check_uniqueness: true,
            max_tracked_nonces: 1000,
            secure_generation: true,
            nonce_size: 16,
        },
        counter: AtomicU64::new(0),
        #[allow(clippy::disallowed_types)]
        used_nonces: std::sync::RwLock::new(HashSet::new()),
    });

/// Global nonce manager (no_std or alloc-only: static with AtomicU64 fallback)
#[cfg(not(all(feature = "alloc", feature = "std")))]
static NONCE_MANAGER: NonceManager = NonceManager {
    config: NonceConfig {
        check_uniqueness: true,
        max_tracked_nonces: 1000,
        secure_generation: true,
        nonce_size: 16,
    },
    counter: AtomicU64::new(0),
    used_nonces: AtomicU64::new(0),
};

/// Get the global nonce manager
#[cfg(all(feature = "alloc", feature = "std"))]
pub fn get_nonce_manager() -> &'static NonceManager {
    &NONCE_MANAGER
}

#[cfg(not(all(feature = "alloc", feature = "std")))]
pub fn get_nonce_manager() -> &'static NonceManager {
    &NONCE_MANAGER
}

/// Generate a new nonce using the global manager
pub fn generate_nonce() -> Result<Nonce> {
    get_nonce_manager().generate_nonce()
}

/// Validate a nonce using the global manager
pub fn validate_nonce(nonce: &Nonce) -> Result<()> {
    get_nonce_manager().validate_nonce(nonce)
}

/// Check if a nonce is unique using the global manager
pub fn is_nonce_unique(nonce: &Nonce) -> bool {
    get_nonce_manager().is_nonce_unique(nonce)
}

/// Mark a nonce as used using the global manager
pub fn mark_nonce_used(nonce: &Nonce) -> Result<()> {
    get_nonce_manager().mark_nonce_used(nonce)
}

/// Nonce generation utilities
pub mod utils {
    use super::*;

    /// Generate a nonce from a counter value
    pub fn nonce_from_counter(counter: u64, nonce_size: usize) -> Nonce {
        let mut nonce_data = Vec::with_capacity(nonce_size);
        nonce_data.extend_from_slice(&counter.to_le_bytes());
        nonce_data.resize(nonce_size, 0);
        Nonce::new(nonce_data)
    }

    /// Generate a nonce from random data
    pub fn nonce_from_random(random_data: &[u8], nonce_size: usize) -> Result<Nonce> {
        if random_data.len() < nonce_size {
            return Err(Error::InvalidNonceSize {
                expected: nonce_size,
                actual: random_data.len(),
            });
        }

        let nonce_data = random_data[..nonce_size].to_vec();
        Ok(Nonce::new(nonce_data))
    }

    // SECURITY (B4): `nonce_from_key_and_counter` was removed. It copied `key[..nonce_size - 8]`
    // verbatim onto the wire after the counter bytes — for this crate's 16-byte nonce size and a
    // 32-byte key, `key[0..8]` shipped in the clear as part of the nonce. It had no callers
    // anywhere in this workspace (checked via `grep -rn nonce_from_key_and_counter` across all
    // crates); deleting it removes the footgun outright rather than patching a construction with
    // no legitimate use.
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    use super::*;

    #[test]
    fn test_nonce_config_defaults() {
        let config = NonceConfig::default();
        assert!(config.check_uniqueness);
        assert_eq!(config.max_tracked_nonces, 1000);
        assert!(config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    #[test]
    fn test_nonce_config_strict() {
        let config = NonceConfig::strict();
        assert!(config.check_uniqueness);
        assert_eq!(config.max_tracked_nonces, 10000);
        assert!(config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    #[test]
    fn test_nonce_config_permissive() {
        let config = NonceConfig::permissive();
        assert!(!config.check_uniqueness);
        assert_eq!(config.max_tracked_nonces, 0);
        assert!(config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    /// RED-FIRST (B4c), sibling of B4: `NonceConfig::permissive()` used to set
    /// `secure_generation: false`, which routes `generate_nonce` to `generate_counter_nonce` —
    /// every output byte is a deterministic function of `self.counter`, and `with_config` always
    /// starts `counter` at `AtomicU64::new(0)`. So two independently constructed `NonceManager`s
    /// built from `permissive()` emitted an IDENTICAL first nonce in every process, and
    /// `check_uniqueness: false` meant the collision was never even detected. Elsewhere in this
    /// crate `permissive()` means "skip the extra bookkeeping cost" (`SecurityConfig::permissive()`,
    /// `TimingProtection::permissive()`, `SideChannelProtection::permissive()` all disable
    /// belt-and-braces checks, not core cryptographic guarantees) — a public constructor with that
    /// name silently opting into a predictable nonce contradicted the crate's own convention as
    /// well as its fail-closed posture since `32951b4`. Fixed by keeping `secure_generation: true`
    /// in `permissive()`; only the uniqueness-tracking overhead is skipped now.
    #[cfg(feature = "shake256")]
    #[test]
    fn test_permissive_config_first_nonces_differ() {
        let a = NonceManager::with_config(NonceConfig::permissive());
        let b = NonceManager::with_config(NonceConfig::permissive());

        let nonce_a = a.generate_nonce().unwrap();
        let nonce_b = b.generate_nonce().unwrap();

        assert_ne!(
            nonce_a.as_bytes(),
            nonce_b.as_bytes(),
            "NonceConfig::permissive() produced identical first nonces from two independent, \
             freshly constructed NonceManagers — it must not route to the deterministic \
             counter-derived nonce path"
        );
    }

    /// The entropy-less build must FAIL CLOSED. `generate_nonce` has no non-cryptographic
    /// fallback: without `shake256` (which pulls in lib-q-random / getrandom) it must return
    /// `Error::RandomGenerationFailed`, never a counter- or clock-derived nonce. Before B4 this
    /// path emitted an LCG stream seeded from an always-zero counter, so every process replayed
    /// the same nonce sequence. This is the crate's entire fail-closed guarantee on
    /// entropy-less builds, and until now it had zero test coverage.
    #[cfg(not(feature = "shake256"))]
    #[test]
    fn test_secure_nonce_fails_closed_without_entropy_feature() {
        let manager = NonceManager::new();
        let err = manager
            .generate_nonce()
            .expect_err("entropy-less build must not produce a 'secure' nonce");
        assert!(
            matches!(err, Error::RandomGenerationFailed { .. }),
            "expected RandomGenerationFailed, got {err:?}"
        );
    }

    /// Mirror of `test_secure_nonce_fails_closed_without_entropy_feature` for the entropy-backed
    /// build: with `shake256` on, the same call must SUCCEED. Together the pair proves the cfg
    /// split is real and neither arm is dead — an `is_err()`/`is_ok()` check on a path that can
    /// only ever return one outcome would be a can't-fail gate, not evidence.
    #[cfg(feature = "shake256")]
    #[test]
    fn test_secure_nonce_succeeds_with_entropy_feature() {
        let manager = NonceManager::new();
        assert!(manager.generate_nonce().is_ok());
    }

    #[test]
    fn test_nonce_manager_creation() {
        let manager = NonceManager::new();
        assert_eq!(manager.get_counter(), 0);
    }

    #[test]
    fn test_nonce_manager_with_config() {
        let config = NonceConfig::strict();
        let manager = NonceManager::with_config(config);
        assert_eq!(manager.get_counter(), 0);
    }

    // The five tests below all go through `NonceManager::new()` / the global manager, i.e. the
    // default config with `secure_generation: true`, so they require the `shake256` feature to
    // succeed at all (without it `generate_secure_nonce` fails closed — see
    // `test_secure_nonce_fails_closed_without_entropy_feature` above). They were previously
    // ungated, which was never caught because every CI job that compiles this crate's test suite
    // also enables `shake256` (it's a `default` feature); the gap surfaced only when verifying
    // that `--no-default-features --features alloc,std` (no `shake256`) is a viable way to
    // actually execute the fail-closed test on a hosted target. Gating them is a test-only change;
    // no production code path changes here.
    #[cfg(feature = "shake256")]
    #[test]
    fn test_generate_secure_nonce() {
        let manager = NonceManager::new();
        let nonce1 = manager.generate_nonce().unwrap();
        let nonce2 = manager.generate_nonce().unwrap();

        assert_eq!(nonce1.as_bytes().len(), 16);
        assert_eq!(nonce2.as_bytes().len(), 16);
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
    }

    #[test]
    fn test_generate_counter_nonce() {
        let config = NonceConfig {
            secure_generation: false,
            ..Default::default()
        };
        let manager = NonceManager::with_config(config);

        let nonce1 = manager.generate_nonce().unwrap();
        let nonce2 = manager.generate_nonce().unwrap();

        assert_eq!(nonce1.as_bytes().len(), 16);
        assert_eq!(nonce2.as_bytes().len(), 16);
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());

        // Verify that the counter is incrementing
        assert_eq!(manager.get_counter(), 2);
    }

    #[test]
    fn test_validate_nonce_format() {
        let manager = NonceManager::new();

        // Valid nonce
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert!(manager.validate_nonce(&nonce).is_ok());

        // Zero nonce
        let zero_nonce = Nonce::new(vec![0u8; 16]);
        assert!(manager.validate_nonce(&zero_nonce).is_err());

        // All-ones nonce
        let ones_nonce = Nonce::new(vec![0xFFu8; 16]);
        assert!(manager.validate_nonce(&ones_nonce).is_err());

        // Wrong size nonce
        let wrong_size_nonce = Nonce::new(vec![1, 2, 3, 4]);
        assert!(manager.validate_nonce(&wrong_size_nonce).is_err());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let manager = NonceManager::new();
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        assert!(manager.is_nonce_unique(&nonce));
        assert!(manager.mark_nonce_used(&nonce).is_ok());
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_counter_operations() {
        let manager = NonceManager::new();

        assert_eq!(manager.get_counter(), 0);

        let _nonce1 = manager.generate_nonce().unwrap();
        assert_eq!(manager.get_counter(), 1);

        let _nonce2 = manager.generate_nonce().unwrap();
        assert_eq!(manager.get_counter(), 2);

        manager.reset_counter();
        assert_eq!(manager.get_counter(), 0);
    }

    #[cfg(feature = "shake256")]
    #[test]
    fn test_global_nonce_functions() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();

        assert_eq!(nonce1.as_bytes().len(), 16);
        assert_eq!(nonce2.as_bytes().len(), 16);
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());

        // Test that generated nonces are unique
        assert!(validate_nonce(&nonce1).is_ok());
        assert!(validate_nonce(&nonce2).is_ok());

        // Test that we can mark nonces as used
        assert!(mark_nonce_used(&nonce1).is_ok());
        assert!(mark_nonce_used(&nonce2).is_ok());
    }

    #[test]
    fn test_nonce_utils() {
        // Test nonce_from_counter
        let nonce1 = utils::nonce_from_counter(42, 16);
        assert_eq!(nonce1.as_bytes().len(), 16);

        // Test nonce_from_random
        let random_data = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
        ];
        let nonce2 = utils::nonce_from_random(&random_data, 16).unwrap();
        assert_eq!(nonce2.as_bytes().len(), 16);

        // `utils::nonce_from_key_and_counter` was removed (B4): it leaked raw key bytes onto the
        // wire and had no callers. See `test_nonce_from_key_and_counter_does_not_leak_key_bytes`'s
        // (now-deleted) RED evidence in the fix commit for this crate.
    }

    /// Regression sanity check: many independently-constructed `NonceManager`s should not emit
    /// colliding first nonces. This is a statistical smoke test (not the RED-FIRST evidence for
    /// B4a below — on this dev machine's high-resolution clock it already passed even against the
    /// pre-fix generator, since the old std code's only entropy input, `SystemTime::now()`, rarely
    /// repeats across a tight loop here; see `test_secure_nonce_is_predictable_from_public_clock_and_counter`
    /// for the deterministic reproduction).
    #[cfg(feature = "shake256")]
    #[test]
    fn test_fresh_nonce_managers_produce_different_first_nonce() {
        const DRAWS: usize = 2000;
        let mut nonces: Vec<Vec<u8>> = Vec::with_capacity(DRAWS);
        for _ in 0..DRAWS {
            let manager = NonceManager::new();
            let nonce = manager.generate_nonce().unwrap();
            nonces.push(nonce.as_bytes().to_vec());
        }

        nonces.sort();
        let has_collision = nonces.windows(2).any(|pair| pair[0] == pair[1]);
        assert!(
            !has_collision,
            "two fresh NonceManagers produced identical first nonces out of {DRAWS} draws \
             (non-cryptographic/predictable generator)"
        );
    }

    /// RED-FIRST (B4a), deterministic reproduction: before the fix, the std "secure" nonce path
    /// (`generate_secure_nonce`'s `#[cfg(all(feature = "std", not(target_arch = "wasm32")))]`
    /// branch) derived every byte from `SystemTime::now()` (public — an attacker who observes
    /// roughly when a message was sent knows it to within microseconds) hashed with a FIXED-key
    /// `DefaultHasher`, combined with a counter that is provably `0` for a fresh manager's first
    /// call. That means the entire "secure" nonce is brute-forceable from public information: this
    /// test brackets the wall-clock window around the real call, reproduces the exact (broken)
    /// hash chain for every nanosecond in that window with counter fixed at 0, and checks whether
    /// any candidate reproduces the real output byte-for-byte. It does, today — recorded as the
    /// RED observation below — and must stop doing so once real entropy is used.
    #[cfg(all(feature = "std", feature = "shake256", not(target_arch = "wasm32")))]
    #[test]
    fn test_secure_nonce_is_predictable_from_public_clock_and_counter() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{
            Hash,
            Hasher,
        };
        use std::time::{
            SystemTime,
            UNIX_EPOCH,
        };

        let now_before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let manager = NonceManager::new();
        let nonce = manager.generate_nonce().unwrap();
        let now_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // A fresh manager's first call always observes counter == 0.
        let counter: u64 = 0;
        let mut predicted = false;
        for now in now_before..=now_after {
            let mut hasher = DefaultHasher::new();
            now.hash(&mut hasher);
            counter.hash(&mut hasher);
            let seed = hasher.finish();

            let mut candidate = Vec::with_capacity(16);
            for i in 0..16u64 {
                let mut byte_hasher = DefaultHasher::new();
                (seed + i).hash(&mut byte_hasher);
                candidate.push((byte_hasher.finish() & 0xFF) as u8);
            }
            if candidate == nonce.as_bytes() {
                predicted = true;
                break;
            }
        }

        assert!(
            !predicted,
            "the 'secure' nonce was fully reproducible from public information (a wall-clock \
             bracket spanning {} candidate nanoseconds + the always-zero starting counter) — it \
             carries no real entropy",
            now_after.saturating_sub(now_before) + 1
        );
    }

    // RED-FIRST (B4b) evidence, recorded here rather than kept as a live test: before the fix,
    // `utils::nonce_from_key_and_counter(&[0xABu8; 32], 123, 16)` returned a nonce whose bytes
    // [8..16] were `[0xAB; 8]` — the leading 8 bytes of the key, copied verbatim. Observed failing
    // assertion (`cargo test -p lib-q-aead --lib security::nonce`):
    //   assertion `left != right` failed: nonce_from_key_and_counter leaked raw key bytes onto the wire
    //     left: [171, 171, 171, 171, 171, 171, 171, 171]
    //    right: [171, 171, 171, 171, 171, 171, 171, 171]
    // The function had no callers anywhere in the workspace, so the fix deletes it outright (see
    // `pub mod utils` above) instead of keeping a test for code that no longer exists.
}
