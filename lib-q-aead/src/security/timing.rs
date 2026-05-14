//! Constant-time operation wrapper.
//!
//! Enforces a fixed wall-clock duration for wrapped operations to prevent
//! timing side-channels from leaking information about internal control flow.
//! The configured [`target_duration_ns`](TimingProtection::target_duration_ns)
//! must exceed the worst-case execution time of the protected function;
//! if the operation overruns the target the call returns after its natural
//! duration (time cannot be compressed).
//!
//! The wrapper uses `compiler_fence(SeqCst)` and `core::hint::black_box` to
//! prevent the compiler from eliding the busy-wait or reordering the result
//! past the timing barrier.
//!
//! On `no_std` and `wasm32` targets the "nanosecond" unit is backed by a
//! monotonic atomic counter rather than a real clock, so durations are
//! approximate but the spin-loop guarantee still holds.

use core::future::Future;
use core::sync::atomic::{
    Ordering,
    compiler_fence,
};

/// Constant-time wrapper configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingProtection {
    /// Enable constant-time wrapping.
    pub enabled: bool,
    /// Fixed wall-clock duration in nanoseconds. Every protected call takes
    /// at least this long regardless of the wrapped operation's actual cost.
    pub target_duration_ns: u64,
}

impl Default for TimingProtection {
    fn default() -> Self {
        Self {
            enabled: true,
            target_duration_ns: 1_000, // 1 µs
        }
    }
}

impl TimingProtection {
    /// Create a new timing protection configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// 5 µs fixed duration — suitable for latency-tolerant paths.
    pub fn strict() -> Self {
        Self {
            enabled: true,
            target_duration_ns: 5_000,
        }
    }

    /// Disabled — zero overhead, no constant-time guarantee.
    pub fn permissive() -> Self {
        Self {
            enabled: false,
            target_duration_ns: 0,
        }
    }

    /// 1 µs fixed duration — same as the default.
    pub fn balanced() -> Self {
        Self {
            enabled: true,
            target_duration_ns: 1_000,
        }
    }

    /// Run `func` and busy-wait until [`target_duration_ns`](Self::target_duration_ns)
    /// has elapsed from the start of the call.
    pub fn protect<F, R>(&self, func: F) -> R
    where
        F: FnOnce() -> R,
    {
        if !self.enabled {
            return func();
        }

        let start = Self::timestamp_ns();
        let result = func();
        let result = core::hint::black_box(result);
        compiler_fence(Ordering::SeqCst);

        Self::spin_until(start, self.target_duration_ns);
        result
    }

    /// Async variant of [`protect`](Self::protect).
    pub async fn protect_async<F, Fut, R>(&self, func: F) -> R
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = R>,
    {
        if !self.enabled {
            return func().await;
        }

        let start = Self::timestamp_ns();
        let result = func().await;
        let result = core::hint::black_box(result);
        compiler_fence(Ordering::SeqCst);

        Self::spin_until(start, self.target_duration_ns);
        result
    }

    /// Run `func` with constant-time protection and return `(result, elapsed_ns)`.
    ///
    /// `elapsed_ns` is the total wall-clock time including the busy-wait.
    /// When the wrapper is disabled it reflects only the operation's natural
    /// duration.
    pub fn protect_with_timing<F, R>(&self, func: F) -> (R, u64)
    where
        F: FnOnce() -> R,
    {
        let start = Self::timestamp_ns();

        if !self.enabled {
            let result = func();
            let elapsed = Self::timestamp_ns().wrapping_sub(start);
            return (result, elapsed);
        }

        let result = func();
        let result = core::hint::black_box(result);
        compiler_fence(Ordering::SeqCst);

        Self::spin_until(start, self.target_duration_ns);

        let elapsed = Self::timestamp_ns().wrapping_sub(start);
        (result, elapsed)
    }

    /// Async variant of [`protect_with_timing`](Self::protect_with_timing).
    pub async fn protect_with_timing_async<F, Fut, R>(&self, func: F) -> (R, u64)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = R>,
    {
        let start = Self::timestamp_ns();

        if !self.enabled {
            let result = func().await;
            let elapsed = Self::timestamp_ns().wrapping_sub(start);
            return (result, elapsed);
        }

        let result = func().await;
        let result = core::hint::black_box(result);
        compiler_fence(Ordering::SeqCst);

        Self::spin_until(start, self.target_duration_ns);

        let elapsed = Self::timestamp_ns().wrapping_sub(start);
        (result, elapsed)
    }

    // ---- internal helpers ------------------------------------------------

    /// Monotonic timestamp in nanoseconds.
    ///
    /// On `std` (non-wasm) this uses `Instant` anchored to a process-local
    /// epoch. On `no_std` / `wasm32` it falls back to an atomic counter.
    #[inline]
    fn timestamp_ns() -> u64 {
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            use std::sync::OnceLock;
            use std::time::Instant;
            static EPOCH: OnceLock<Instant> = OnceLock::new();
            let epoch = EPOCH.get_or_init(Instant::now);
            epoch.elapsed().as_nanos() as u64
        }
        #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
        {
            use core::sync::atomic::AtomicU64;
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::SeqCst)
        }
    }

    /// Spin-loop until at least `duration_ns` has elapsed since `start`.
    ///
    /// Marked `#[inline(never)]` so the loop body is not inlined into the
    /// caller where the compiler might reason about it more aggressively.
    #[inline(never)]
    fn spin_until(start: u64, duration_ns: u64) {
        while Self::timestamp_ns().wrapping_sub(start) < duration_ns {
            core::hint::spin_loop();
        }
        compiler_fence(Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Global configuration
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
use std::sync::{
    Arc,
    RwLock,
};

#[cfg(feature = "std")]
static GLOBAL_TIMING_PROTECTION: std::sync::OnceLock<Arc<RwLock<TimingProtection>>> =
    std::sync::OnceLock::new();
#[cfg(not(feature = "std"))]
static GLOBAL_TIMING_PROTECTION: once_cell::sync::Lazy<spin::Mutex<TimingProtection>> =
    once_cell::sync::Lazy::new(|| spin::Mutex::new(TimingProtection::default()));

/// Get the global timing protection configuration.
pub fn get_timing_protection() -> TimingProtection {
    #[cfg(feature = "std")]
    {
        GLOBAL_TIMING_PROTECTION
            .get_or_init(|| Arc::new(RwLock::new(TimingProtection::default())))
            .read()
            .map(|guard| *guard)
            .unwrap_or_else(|_| TimingProtection::default())
    }
    #[cfg(not(feature = "std"))]
    {
        *GLOBAL_TIMING_PROTECTION.lock()
    }
}

/// Set the global timing protection configuration.
pub fn set_timing_protection(protection: TimingProtection) {
    #[cfg(feature = "std")]
    {
        if let Some(global_protection) = GLOBAL_TIMING_PROTECTION.get() {
            if let Ok(mut global) = global_protection.write() {
                *global = protection;
            }
        } else {
            let _ = GLOBAL_TIMING_PROTECTION.set(Arc::new(RwLock::new(protection)));
        }
    }
    #[cfg(not(feature = "std"))]
    {
        *GLOBAL_TIMING_PROTECTION.lock() = protection;
    }
}

/// Apply global constant-time protection to `func`.
pub fn protect_timing<F, R>(func: F) -> R
where
    F: FnOnce() -> R,
{
    get_timing_protection().protect(func)
}

/// Async variant of [`protect_timing`].
pub async fn protect_timing_async<F, Fut, R>(func: F) -> R
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = R>,
{
    get_timing_protection().protect_async(func).await
}

/// Apply global constant-time protection and return `(result, elapsed_ns)`.
pub fn protect_timing_with_timing<F, R>(func: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    get_timing_protection().protect_with_timing(func)
}

/// Async variant of [`protect_timing_with_timing`].
pub async fn protect_timing_with_timing_async<F, Fut, R>(func: F) -> (R, u64)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = R>,
{
    get_timing_protection()
        .protect_with_timing_async(func)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_protection_defaults() {
        let protection = TimingProtection::default();
        assert!(protection.enabled);
        assert_eq!(protection.target_duration_ns, 1_000);
    }

    #[test]
    fn test_timing_protection_strict() {
        let protection = TimingProtection::strict();
        assert!(protection.enabled);
        assert_eq!(protection.target_duration_ns, 5_000);
    }

    #[test]
    fn test_timing_protection_permissive() {
        let protection = TimingProtection::permissive();
        assert!(!protection.enabled);
        assert_eq!(protection.target_duration_ns, 0);
    }

    #[test]
    fn test_timing_protection_balanced() {
        let protection = TimingProtection::balanced();
        assert!(protection.enabled);
        assert_eq!(protection.target_duration_ns, 1_000);
    }

    #[test]
    fn test_protect() {
        let protection = TimingProtection::new();
        let result = protection.protect(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_protect_with_timing() {
        let protection = TimingProtection::new();
        let (result, elapsed) = protection.protect_with_timing(|| 42);
        assert_eq!(result, 42);
        assert!(elapsed > 0);
    }

    #[test]
    fn test_global_timing_protection() {
        let result = protect_timing(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_global_timing_protection_with_timing() {
        let (result, elapsed) = protect_timing_with_timing(|| 42);
        assert_eq!(result, 42);
        assert!(elapsed > 0);
    }

    #[test]
    fn test_global_timing_protection_config() {
        let config = get_timing_protection();
        assert_eq!(config, TimingProtection::default());

        let new_config = TimingProtection::strict();
        set_timing_protection(new_config);

        let _result = protect_timing(|| 42);
        let (_result, _elapsed) = protect_timing_with_timing(|| 42);
    }
}
