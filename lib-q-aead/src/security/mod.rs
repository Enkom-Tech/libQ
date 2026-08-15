//! Security enhancements for lib-q-aead
//!
//! This module provides comprehensive security features including:
//! - Constant-time operations
//! - Side-channel attack protection
//! - Secure memory handling
//! - Input validation and sanitization
//! - Constant-time operation wrapper (fixed wall-clock duration)
//!
//! **Fault injection is NOT in that list, and this module does not resist it.** Until 2026-08-15
//! this line read "Fault injection resistance". It was false: `fault_injection_protection` is an
//! advisory `bool` that callers set and read back, and **no call site anywhere in the workspace
//! consumes it** — there is no redundancy, no recomputation, no infective countermeasure, and no
//! detection. Treat it as a caller-declared intent flag for policy plumbing, never as a control.
//! This matters concretely for Saturnin, the default AEAD here: a published ciphertext-only attack
//! recovers its full 256-bit key from 656 nibble faults (Li et al., IEEE TIFS 18 (2023) 1487–1496),
//! and a companion paper does the same to Saturnin-Short with 1 097 ineffective faults
//! (Journal on Communications 44(4) (2023) 167–175). See `lib-q-saturnin/SECURITY.md`.

pub mod constant_time;
pub mod memory;
pub mod nonce;
pub mod side_channel;
pub mod stack_buffer;
pub mod timing;
pub mod validation;

// Re-export commonly used security functions
// Note: Individual modules are available for specific use cases

/// Security configuration for AEAD operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityConfig {
    /// Enable constant-time operations
    pub constant_time: bool,
    /// Enable side-channel protection
    pub side_channel_protection: bool,
    /// Enable secure memory handling
    pub secure_memory: bool,
    /// Enable comprehensive input validation
    pub strict_validation: bool,
    /// Enable constant-time operation wrapper (fixed wall-clock duration)
    pub timing_protection: bool,
    /// Enable fault injection protection
    pub fault_injection_protection: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            constant_time: true,
            side_channel_protection: true,
            secure_memory: true,
            strict_validation: true,
            timing_protection: true,
            fault_injection_protection: true,
        }
    }
}

impl SecurityConfig {
    /// Create a strict security configuration (maximum security)
    pub fn strict() -> Self {
        Self {
            constant_time: true,
            side_channel_protection: true,
            secure_memory: true,
            strict_validation: true,
            timing_protection: true,
            fault_injection_protection: true,
        }
    }

    /// Create a permissive security configuration (performance optimized)
    pub fn permissive() -> Self {
        Self {
            constant_time: false,
            side_channel_protection: false,
            secure_memory: false,
            strict_validation: false,
            timing_protection: false,
            fault_injection_protection: false,
        }
    }

    /// Create a balanced security configuration
    pub fn balanced() -> Self {
        Self {
            constant_time: true,
            side_channel_protection: true,
            secure_memory: true,
            strict_validation: true,
            timing_protection: false,
            fault_injection_protection: false,
        }
    }
}

#[cfg(feature = "std")]
use std::sync::{
    LazyLock,
    RwLock,
};

/// Global security configuration.
///
/// Guarded by a lock (`std::sync::RwLock` when `std` is available, `spin::Mutex` otherwise)
/// so concurrent readers and writers from any thread (including bare-metal `no_std` cores)
/// observe a consistent value. A `static mut` here would be undefined behaviour under
/// concurrent access, which is exactly what this replaces.
///
/// `GLOBAL_VALIDATOR` in `security::validation` and `GLOBAL_TIMING_PROTECTION` in
/// `security::timing` are deliberately kept in this same shape and carry the same invariant;
/// all three moved off `OnceLock<Arc<RwLock<..>>>` together. Do not "restore consistency" by
/// reverting any one of them.
///
/// # Invariant (both `cfg` branches — any edit must preserve this on BOTH)
///
/// After `set_security_config(c)` returns, `get_security_config()` returns `c` until the next
/// `set_security_config` call, on every target and regardless of any prior panic in any
/// thread.
///
/// - **std**: `LazyLock` makes initialisation race-free, so there is no window in which a
///   writer's value can be discarded by a concurrent first reader; poisoned guards are
///   recovered with `PoisonError::into_inner`, so no code path can silently drop a write or
///   invent a value in place of the stored one.
/// - **`no_std`**: `spin` locks cannot poison and `spin::LazyLock` is race-free, so the same
///   contract holds for free.
///
/// Both functions below are therefore total: neither has a branch that returns without having
/// read (respectively written) the one global cell, and neither can panic on the poison path.
/// This was not always so — see `lib-q-aead/CHANGELOG.md` and card `t_8f408920`.
#[cfg(feature = "std")]
static GLOBAL_SECURITY_CONFIG: LazyLock<RwLock<SecurityConfig>> =
    LazyLock::new(|| RwLock::new(SecurityConfig::default()));
#[cfg(not(feature = "std"))]
static GLOBAL_SECURITY_CONFIG: spin::LazyLock<spin::Mutex<SecurityConfig>> =
    spin::LazyLock::new(|| spin::Mutex::new(SecurityConfig::default()));

/// Get the current process-wide security configuration.
///
/// Returns the value most recently passed to [`set_security_config`], or
/// [`SecurityConfig::default`] if it has never been called. This read is infallible: a
/// poisoned lock (a panic in another thread while writing) is recovered and the stored value
/// is returned — never a fallback.
///
/// This value is **process-global** (see [`set_security_config`]). It is read by
/// [`SecurityContext::new`]; prefer [`SecurityContext::with_config`] when you need a posture
/// that other code in the process cannot change under you.
pub fn get_security_config() -> SecurityConfig {
    #[cfg(feature = "std")]
    {
        *GLOBAL_SECURITY_CONFIG
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    #[cfg(not(feature = "std"))]
    {
        *GLOBAL_SECURITY_CONFIG.lock()
    }
}

/// Set the process-wide security configuration.
///
/// # Scope and precedence
///
/// There is exactly one configuration per process, shared by every crate that links
/// `lib-q-aead`, and the last writer wins. A library should not call this to protect its own
/// operations — another dependency may overwrite it at any time. Libraries should use
/// [`SecurityContext::with_config`] instead; this function is for the *application* to set a
/// process-wide default consumed by [`SecurityContext::new`].
///
/// # This write is infallible
///
/// It always takes effect: initialisation races cannot drop it, and a poisoned lock (a panic
/// in another thread) is recovered rather than skipped. After this returns,
/// [`get_security_config`] returns exactly `config` until the next call.
pub fn set_security_config(config: SecurityConfig) {
    #[cfg(feature = "std")]
    {
        *GLOBAL_SECURITY_CONFIG
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
    }
    #[cfg(not(feature = "std"))]
    {
        *GLOBAL_SECURITY_CONFIG.lock() = config;
    }
}

/// Serialises the unit tests in this crate that touch process-global security state.
///
/// Covers all three of them — [`GLOBAL_SECURITY_CONFIG`], `validation::GLOBAL_VALIDATOR` and
/// `timing::GLOBAL_TIMING_PROTECTION` — with one lock rather than three. They are only ever
/// contended by tests, so the cost of over-serialising is nil, and one lock cannot be
/// acquired in two different orders.
///
/// Same rationale and same poison-tolerant shape as the `lock_security_config()` helper in
/// `tests/security_tests.rs`: each getter/setter pair operates on one process-wide singleton,
/// so tests that do `set(x); assert(get() == x)` — or that merely *read* a global and assert
/// on it — race each other under `cargo test`'s default in-binary parallelism. `cargo test` runs test *binaries* sequentially, so a per-binary
/// mutex is sufficient (this one for the `--lib` binary, the one in `security_tests.rs` for
/// that integration binary).
///
/// Poisoning is tolerated deliberately: if one test panics while holding this guard, the
/// others should still report their own results rather than all failing with a poison error
/// and hiding the original failure.
#[cfg(all(test, feature = "std"))]
pub(crate) static TEST_CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire [`TEST_CONFIG_LOCK`]; see its documentation.
#[cfg(all(test, feature = "std"))]
pub(crate) fn lock_for_test() -> std::sync::MutexGuard<'static, ()> {
    TEST_CONFIG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Security context for cryptographic operations
pub struct SecurityContext {
    config: SecurityConfig,
    operation_id: u64,
    start_time: u64,
}

impl SecurityContext {
    /// Create a new security context
    ///
    /// Uses the process-wide configuration from [`get_security_config`]; use
    /// [`with_config`](Self::with_config) to pin a posture other code cannot change.
    pub fn new() -> Self {
        Self {
            config: get_security_config(),
            operation_id: Self::generate_operation_id(),
            start_time: Self::get_timestamp(),
        }
    }

    /// Create a security context with custom configuration
    pub fn with_config(config: SecurityConfig) -> Self {
        Self {
            config,
            operation_id: Self::generate_operation_id(),
            start_time: Self::get_timestamp(),
        }
    }

    /// Get the operation ID
    pub fn operation_id(&self) -> u64 {
        self.operation_id
    }

    /// Get the elapsed time since context creation
    pub fn elapsed_time(&self) -> u64 {
        Self::get_timestamp() - self.start_time
    }

    /// Check if constant-time operations are enabled
    pub fn constant_time_enabled(&self) -> bool {
        self.config.constant_time
    }

    /// Check if side-channel protection is enabled
    pub fn side_channel_protection_enabled(&self) -> bool {
        self.config.side_channel_protection
    }

    /// Check if secure memory handling is enabled
    pub fn secure_memory_enabled(&self) -> bool {
        self.config.secure_memory
    }

    /// Check if strict validation is enabled
    pub fn strict_validation_enabled(&self) -> bool {
        self.config.strict_validation
    }

    /// Check if timing protection is enabled
    pub fn timing_protection_enabled(&self) -> bool {
        self.config.timing_protection
    }

    /// Check if fault injection protection is enabled
    pub fn fault_injection_protection_enabled(&self) -> bool {
        self.config.fault_injection_protection
    }

    /// Generate a unique operation ID
    fn generate_operation_id() -> u64 {
        // Use a simple counter for now - in production, this should use
        // cryptographically secure random number generation.
        //
        // `AtomicU64::fetch_add` (rather than a `static mut` read-modify-write) is what
        // makes concurrent calls from multiple threads race-free; see `get_timestamp`
        // below for the same type used for the same reason on the no_std/wasm path.
        use core::sync::atomic::Ordering;

        use portable_atomic::AtomicU64;
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        // Compile-time, non-flaky proof that this is really atomic and not a
        // `static mut` read-modify-write: forming a shared reference to `COUNTER` and
        // calling `fetch_add` through it only type-checks for an atomic type. Reverting
        // to `static mut COUNTER: u64` makes this line fail to compile twice over --
        // `u64` has no `fetch_add` method, and forming `&COUNTER` on a `static mut`
        // outside `unsafe` is independently denied by `static_mut_refs` on this edition.
        // A concurrency test was deliberately not used here: it would only be a
        // probabilistic detector of already-UB behaviour, not a deterministic one (see
        // progress.md for the 40x/0-failures run against the pre-fix code).
        let counter: &AtomicU64 = &COUNTER;
        counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Get current timestamp with high-resolution timing
    fn get_timestamp() -> u64 {
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        }
        // wasm32-unknown-unknown has no working `SystemTime`; no_std targets
        // have no clock at all. Both fall back to a monotonic counter that
        // still gives consistent relative measurements.
        #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
        {
            use core::sync::atomic::Ordering;

            use portable_atomic::AtomicU64;
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::SeqCst)
        }
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(config.constant_time);
        assert!(config.side_channel_protection);
        assert!(config.secure_memory);
        assert!(config.strict_validation);
        assert!(config.timing_protection);
        assert!(config.fault_injection_protection);
    }

    #[test]
    fn test_security_config_strict() {
        let config = SecurityConfig::strict();
        assert!(config.constant_time);
        assert!(config.side_channel_protection);
        assert!(config.secure_memory);
        assert!(config.strict_validation);
        assert!(config.timing_protection);
        assert!(config.fault_injection_protection);
    }

    #[test]
    fn test_security_config_permissive() {
        let config = SecurityConfig::permissive();
        assert!(!config.constant_time);
        assert!(!config.side_channel_protection);
        assert!(!config.secure_memory);
        assert!(!config.strict_validation);
        assert!(!config.timing_protection);
        assert!(!config.fault_injection_protection);
    }

    #[test]
    fn test_security_config_balanced() {
        let config = SecurityConfig::balanced();
        assert!(config.constant_time);
        assert!(config.side_channel_protection);
        assert!(config.secure_memory);
        assert!(config.strict_validation);
        assert!(!config.timing_protection);
        assert!(!config.fault_injection_protection);
    }

    #[test]
    fn test_security_context_creation() {
        // Reads the process-global config (via `SecurityContext::new`) and asserts on it, so
        // it must not run while another test has the global set to `permissive()`. Measured:
        // without this guard, 10 of 60 runs of this binary at `--test-threads=64` fail here.
        #[cfg(feature = "std")]
        let _guard = lock_for_test();
        let ctx = SecurityContext::new();
        assert!(ctx.operation_id() > 0);
        // Note: elapsed_time() returns u64, so it's always >= 0
        // We just verify it's a valid timestamp
        let _elapsed = ctx.elapsed_time();
        assert!(ctx.constant_time_enabled());
    }

    #[test]
    fn test_security_context_with_config() {
        let config = SecurityConfig::permissive();
        let ctx = SecurityContext::with_config(config);
        assert!(!ctx.constant_time_enabled());
        assert!(!ctx.side_channel_protection_enabled());
        assert!(!ctx.secure_memory_enabled());
        assert!(!ctx.strict_validation_enabled());
        assert!(!ctx.timing_protection_enabled());
        assert!(!ctx.fault_injection_protection_enabled());
    }

    #[test]
    fn test_global_security_config() {
        #[cfg(feature = "std")]
        let _guard = lock_for_test();

        let original_config = get_security_config();

        let new_config = SecurityConfig::permissive();
        set_security_config(new_config);

        let retrieved_config = get_security_config();
        assert_eq!(retrieved_config, new_config);

        // Restore original config
        set_security_config(original_config);
    }

    /// Poison `GLOBAL_SECURITY_CONFIG` from another thread, deliberately.
    ///
    /// A `RwLock` is poisoned only by a panic while a **write** guard is held, so this takes
    /// the write guard and panics. It joins the thread before returning, so the lock is
    /// guaranteed poisoned (and the panic guaranteed to have happened) by the time the caller
    /// continues.
    #[cfg(feature = "std")]
    fn poison_global_config_lock() {
        let poisoner = std::thread::spawn(|| {
            let _write_guard = GLOBAL_SECURITY_CONFIG
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("deliberately poisoning GLOBAL_SECURITY_CONFIG");
        });
        assert!(
            poisoner.join().is_err(),
            "the poisoning thread did not panic, so the lock is not poisoned and this test \
             would prove nothing"
        );
    }

    /// D1, poison half: a poisoned lock must not turn `set_security_config` into a silent
    /// no-op. Encodes the invariant "after `set(c)` returns, `get()` returns `c`".
    ///
    /// Poisoning is std-only: the `no_std` branch uses `spin::Mutex`, which has no poison
    /// state at all, so there is nothing to test there.
    #[cfg(feature = "std")]
    #[test]
    fn set_applies_even_after_poison() {
        let _guard = lock_for_test();

        poison_global_config_lock();

        set_security_config(SecurityConfig::permissive());
        assert_eq!(
            get_security_config(),
            SecurityConfig::permissive(),
            "set_security_config silently did not apply after the lock was poisoned"
        );

        set_security_config(SecurityConfig::default());
    }

    /// D1, getter half: after a poisoning panic, `get_security_config` must return the value
    /// that was actually stored, not a fabricated fallback.
    #[cfg(feature = "std")]
    #[test]
    fn get_returns_last_set_even_after_poison() {
        let _guard = lock_for_test();

        set_security_config(SecurityConfig::permissive());
        assert_eq!(
            get_security_config(),
            SecurityConfig::permissive(),
            "set_security_config did not apply before any poisoning happened"
        );

        poison_global_config_lock();

        assert_eq!(
            get_security_config(),
            SecurityConfig::permissive(),
            "get_security_config invented a value instead of returning the stored one"
        );

        set_security_config(SecurityConfig::default());
        assert_eq!(get_security_config(), SecurityConfig::default());
    }
}
