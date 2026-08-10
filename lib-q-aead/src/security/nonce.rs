//! Nonce Management
//!
//! This module provides secure nonce **generation** and **format validation** for AEAD
//! operations.
//!
//! # It deliberately does not track used nonces
//!
//! It used to. [`NonceManager`] carried a "collision detection and secure tracking" contract
//! backed by a replay tracker that was unsound in both build configurations, in opposite
//! directions (board card `t_9cd430c2`):
//!
//! * **`std`**: a `HashSet<Vec<u8>>` that, past 10 000 entries, evicted `used_nonces.iter()
//!   .take(1000)`. `HashSet::iter()` yields in unspecified order, so that removed 1000 *arbitrary*
//!   nonces rather than the 1000 oldest, and every evicted nonce silently became replayable. That
//!   is the catastrophic direction for a replay tracker: a false negative on the authentication
//!   path. OBSERVED before removal, by marking 10 001 nonces used and asking about each again:
//!   `1000 of 10001 nonces that were marked used are reported unique again`.
//! * **`no_std`**: a single `AtomicU64` used as a 64-bucket, one-hash, never-cleared Bloom filter.
//!   By the pigeonhole bound every bit is set after at most 64 insertions (far fewer in
//!   expectation), after which *every* nonce — including a freshly generated one — reports as
//!   already used. The tracker degrades to a constant `true`, i.e. a self-inflicted denial of
//!   service. This arm cannot be exercised by a host test (a genuine `no_std` target has no test
//!   harness, and `std`-without-`alloc` does not compile here), so it rests on that bound rather
//!   than on an observed run.
//!
//! Neither is fixable within the shape the API implied. A bounded tracker cannot detect a replay
//! older than its window whatever its eviction policy, and 64 bits of state cannot track nonces at
//! all — so the honest options were a *correct* structure with a much weaker documented contract,
//! or removal. The tracking surface had **no callers** anywhere in this workspace, and a wrong
//! replay tracker in a crypto library is worse than none, because the next consumer assumes it
//! works. It was removed.
//!
//! What replaced it: nothing here. Replay detection is a **protocol-level** property and belongs
//! with the protocol's own state (a monotonic counter/sequence-number discipline, or a sliding
//! window like DTLS/IPsec anti-replay, sized and persisted by the consumer). If you need one,
//! build it there where the ordering and the persistence requirements are actually known.

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

use lib_q_core::{
    Error,
    Nonce,
    Result,
};
use portable_atomic::AtomicU64;

/// Nonce management configuration
///
/// `check_uniqueness` and `max_tracked_nonces` were removed along with the unsound replay tracker
/// they configured (see the module docs). They are not deprecated aliases: keeping them would
/// have left a knob that reads as a security control and no longer switches one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceConfig {
    /// Enable secure random nonce generation
    pub secure_generation: bool,
    /// Nonce size in bytes
    pub nonce_size: usize,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            secure_generation: true,
            nonce_size: 16, // 128 bits
        }
    }
}

impl NonceConfig {
    /// Create a strict nonce configuration
    pub fn strict() -> Self {
        Self {
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
    /// nonce in every process, with the (since-removed) `check_uniqueness: false` on top so the
    /// collision was never even detected. "Permissive" is kept scoped to what its sibling configs
    /// in this crate mean by the word (`SecurityConfig::permissive()`,
    /// `TimingProtection::permissive()`, `SideChannelProtection::permissive()`: skip extra
    /// bookkeeping/overhead, never weaken a core cryptographic guarantee).
    ///
    /// With the uniqueness knobs gone there is now nothing left for it to relax, so it is
    /// identical to [`NonceConfig::default`]. It is kept as a name a caller may already be
    /// spelling, and because deleting it would silently turn a `permissive()` call site into a
    /// compile error whose obvious "fix" is to hand-write a weaker config.
    pub fn permissive() -> Self {
        Self {
            secure_generation: true,
            nonce_size: 16,
        }
    }
}

/// Nonce generator and format validator.
///
/// **Not** a replay detector: it keeps no record of which nonces it has emitted or seen, and
/// [`validate_nonce`](Self::validate_nonce) checks shape only. See the module docs for what was
/// removed and why, and for where replay detection belongs instead.
pub struct NonceManager {
    config: NonceConfig,
    counter: AtomicU64,
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

    /// Generate a secure random nonce from OS/hardware entropy.
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

            // No collision check: the bytes above are 8 * nonce_size bits of OS/hardware entropy
            // (128 bits at the default size), so a repeat is negligible. The check that used to
            // live here consulted the replay tracker removed in `t_9cd430c2` — and on the no_std
            // arm, where that tracker saturated to "everything is used", it would have recursed
            // until the stack ran out.

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

    /// Validate a nonce's **format**: correct length for this manager's configuration, and
    /// neither all-zero nor all-ones.
    ///
    /// This says nothing about whether the nonce has been used before — see the module docs. It
    /// used to also consult a replay tracker and mark the nonce used as a side effect, which is
    /// why the name is bare `validate_nonce` rather than `validate_nonce_format`; that side effect
    /// is gone.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidNonceSize`] if the length differs from [`NonceConfig::nonce_size`], or if
    /// every byte is `0x00` or every byte is `0xFF`.
    pub fn validate_nonce(&self, nonce: &Nonce) -> Result<()> {
        self.validate_nonce_format(nonce)
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

/// Global nonce manager.
///
/// Now that there is no tracking state, this is a plain `static` on every configuration — the
/// `std`-only `LazyLock` arm existed solely to construct the `HashSet`.
static NONCE_MANAGER: NonceManager = NonceManager {
    config: NonceConfig {
        secure_generation: true,
        nonce_size: 16,
    },
    counter: AtomicU64::new(0),
};

/// Get the global nonce manager
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
        assert!(config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    #[test]
    fn test_nonce_config_strict() {
        let config = NonceConfig::strict();
        assert!(config.secure_generation);
        assert_eq!(config.nonce_size, 16);
    }

    /// Every constructor must keep `secure_generation: true` (B4c). With the uniqueness knobs
    /// gone, that is the *only* thing separating these three, so a constructor that regressed it
    /// would otherwise be indistinguishable from its siblings.
    #[test]
    fn test_nonce_config_permissive() {
        let config = NonceConfig::permissive();
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

    /// `validate_nonce` is now stateless: validating the same nonce twice must succeed both times.
    ///
    /// This replaces `test_nonce_uniqueness`, which asserted `is_nonce_unique(&n)` and then
    /// `mark_nonce_used(&n).is_ok()` on a fresh manager — it never re-queried after marking, so it
    /// passed identically against a tracker that remembered nothing. It was the only test the
    /// tracking API had, and it could not have failed for either of the two defects in
    /// `t_9cd430c2`.
    #[test]
    fn validate_nonce_is_stateless_and_does_not_consume_the_nonce() {
        let manager = NonceManager::new();
        let nonce = Nonce::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        assert!(manager.validate_nonce(&nonce).is_ok());
        assert!(
            manager.validate_nonce(&nonce).is_ok(),
            "validate_nonce rejected a nonce it had already accepted — it must check format only, \
             with no memory of what it has seen"
        );
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

        // Format-only, and repeatable: the global validator keeps no state either.
        assert!(validate_nonce(&nonce1).is_ok());
        assert!(validate_nonce(&nonce2).is_ok());
        assert!(validate_nonce(&nonce1).is_ok());
    }

    /// Structural guard, not a behavioural one: `NonceManager` must stay stateless apart from its
    /// diagnostic counter. Its whole size is `NonceConfig` (two `usize`-ish fields) plus one
    /// `AtomicU64`; a reintroduced tracking container (a `HashSet`, a `RwLock`, a bitmap) cannot
    /// fit in that. This is the test the crate lacked — the tracker's own tests could not fail for
    /// either defect in `t_9cd430c2`, because none of them re-queried after marking.
    #[test]
    fn nonce_manager_carries_no_tracking_state() {
        use core::mem::size_of;
        assert_eq!(
            size_of::<NonceManager>(),
            size_of::<NonceConfig>() + size_of::<AtomicU64>(),
            "NonceManager grew a field. If that field is a used-nonce tracker, read the module \
             docs first: a bounded tracker cannot detect a replay older than its window, and the \
             two previous attempts failed in opposite directions."
        );
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
