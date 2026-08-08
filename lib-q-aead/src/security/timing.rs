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
//! ## Platform semantics
//!
//! - **Native + `std`**: [`std::time::Instant`] provides monotonic nanosecond
//!   resolution for [`TimingProtection::target_duration_ns`].
//! - **`wasm32` + `wasm` feature** (browser or worker with Web APIs): time is
//!   read from [`Performance::now`](https://developer.mozilla.org/en-US/docs/Web/API/Performance/now)
//!   on `globalThis.performance` (sub-millisecond resolution; values are
//!   converted to nanoseconds for the same `target_duration_ns` field).
//! - **Other `no_std` / bare-metal, or `wasm32` without `wasm`**: there is no
//!   portable monotonic wall clock. The implementation falls back to an atomic
//!   **call counter**, so `target_duration_ns` is **not** wall nanoseconds and
//!   sub-microsecond padding is not meaningful. Prefer disabling the wrapper
//!   ([`TimingProtection::permissive`]) on those targets unless you accept
//!   tick-based (non wall-clock) pacing only.
//!
//! This layer does not make non-constant-time algorithms constant-time; it
//! only pads elapsed time when a real clock (or explicit tick fallback) is used.

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
    /// Target minimum duration for the protected call, in **nanoseconds** when
    /// a wall-clock source is available (native `std`, or `wasm32` with the
    /// `wasm` feature and `global.performance`).
    ///
    /// On platforms that use the tick counter fallback (see module docs), this
    /// value is measured in counter ticks, not literal nanoseconds.
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

    /// Run `func` with constant-time protection and return `(result, elapsed)`.
    ///
    /// When a wall clock is available (native `std`, or `wasm32` + `wasm`), the
    /// second value is elapsed time in nanoseconds including the busy-wait. On
    /// tick-counter-only targets (see module docs), the delta is in counter
    /// ticks, not literal nanoseconds. When the wrapper is disabled, the
    /// delta reflects only the operation's natural duration in the same units.
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
    ///
    /// See [`protect_with_timing`](Self::protect_with_timing) for semantics of
    /// the elapsed value.
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

    /// Monotonic time basis for [`spin_until`](Self::spin_until).
    ///
    /// Returns nanoseconds since an arbitrary origin when a wall clock exists;
    /// otherwise an increasing tick count (see module documentation).
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

        #[cfg(all(target_arch = "wasm32", feature = "wasm"))]
        {
            Self::wasm_performance_now_ns()
        }

        #[cfg(not(any(
            all(feature = "std", not(target_arch = "wasm32")),
            all(target_arch = "wasm32", feature = "wasm"),
        )))]
        {
            Self::monotonic_tick_counter()
        }
    }

    /// `Performance.now()`-based monotonic time in nanoseconds (DOMHighResTimeStamp).
    ///
    /// Uses `globalThis.performance` so this works in dedicated workers where
    /// `window` is unavailable.
    #[cfg(all(target_arch = "wasm32", feature = "wasm"))]
    #[inline]
    fn wasm_performance_now_ns() -> u64 {
        use wasm_bindgen::JsCast;

        let global = js_sys::global();
        let Ok(perf_val) =
            js_sys::Reflect::get(&global, &wasm_bindgen::JsValue::from_str("performance"))
        else {
            return Self::monotonic_tick_counter();
        };
        if perf_val.is_null() || perf_val.is_undefined() {
            return Self::monotonic_tick_counter();
        }
        let Ok(perf) = perf_val.dyn_into::<web_sys::Performance>() else {
            return Self::monotonic_tick_counter();
        };
        let ms = perf.now();
        if !ms.is_finite() || ms < 0.0 {
            return Self::monotonic_tick_counter();
        }
        (ms * 1_000_000.0) as u64
    }

    /// Monotonic counter used when no wall clock exists (see module docs).
    ///
    /// Not referenced on native `std` builds (those use [`std::time::Instant`]).
    #[cfg_attr(all(feature = "std", not(target_arch = "wasm32")), allow(dead_code))]
    #[inline]
    fn monotonic_tick_counter() -> u64 {
        use portable_atomic::AtomicU64;
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::SeqCst)
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
    LazyLock,
    RwLock,
};

/// The process-wide timing-protection configuration.
///
/// # Invariant (both `cfg` branches — any edit must preserve this on BOTH)
///
/// After `set_timing_protection(p)` returns, `get_timing_protection()` returns `p` until the
/// next `set_timing_protection` call, on every target and regardless of any prior panic in
/// any thread.
///
/// `LazyLock` makes initialisation race-free, so no writer's value can be discarded by a
/// concurrent first reader, and poisoned guards are recovered with `PoisonError::into_inner`
/// so no path can silently drop a write or substitute a value for the stored one. The
/// `no_std` branch gets the same contract for free: `spin` locks cannot poison. Matches
/// `GLOBAL_SECURITY_CONFIG` in `security::mod`; see card `t_8f408920` for why the previous
/// shape was replaced.
#[cfg(feature = "std")]
static GLOBAL_TIMING_PROTECTION: LazyLock<RwLock<TimingProtection>> =
    LazyLock::new(|| RwLock::new(TimingProtection::default()));
#[cfg(not(feature = "std"))]
static GLOBAL_TIMING_PROTECTION: spin::LazyLock<spin::Mutex<TimingProtection>> =
    spin::LazyLock::new(|| spin::Mutex::new(TimingProtection::default()));

/// Get the global timing protection configuration.
///
/// This read is infallible: a poisoned lock is recovered and the stored configuration
/// returned, never a fallback. The value is process-global and last-writer-wins — see
/// [`set_timing_protection`].
pub fn get_timing_protection() -> TimingProtection {
    #[cfg(feature = "std")]
    {
        *GLOBAL_TIMING_PROTECTION
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    #[cfg(not(feature = "std"))]
    {
        *GLOBAL_TIMING_PROTECTION.lock()
    }
}

/// Set the global timing protection configuration.
///
/// There is exactly one configuration per process, shared by every crate that links
/// `lib-q-aead`, and the last writer wins. The write is infallible: it always takes effect,
/// because initialisation races cannot drop it and a poisoned lock is recovered rather than
/// skipped.
pub fn set_timing_protection(protection: TimingProtection) {
    #[cfg(feature = "std")]
    {
        *GLOBAL_TIMING_PROTECTION
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = protection;
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

/// Apply global constant-time protection and return `(result, elapsed)`.
///
/// The elapsed component follows [`TimingProtection::protect_with_timing`].
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
        // Asserts on the process-global value, so it must not run while another test has it
        // set; see `security::TEST_CONFIG_LOCK`.
        #[cfg(feature = "std")]
        let _guard = super::super::lock_for_test();

        let config = get_timing_protection();
        assert_eq!(config, TimingProtection::default());

        let new_config = TimingProtection::strict();
        set_timing_protection(new_config);

        let _result = protect_timing(|| 42);
        let (_result, _elapsed) = protect_timing_with_timing(|| 42);

        // Restore, so the assertion above still holds however tests are ordered.
        set_timing_protection(TimingProtection::default());
    }

    /// A poisoned lock must not turn `set_timing_protection` into a silent no-op, nor make
    /// `get_timing_protection` invent a value. Encodes the invariant on
    /// `GLOBAL_TIMING_PROTECTION`; same defect class as card `t_8f408920`.
    ///
    /// Poisoning is std-only: the `no_std` branch uses `spin::Mutex`, which has no poison
    /// state, so there is nothing to test there.
    #[cfg(feature = "std")]
    #[test]
    fn timing_protection_survives_a_poisoned_lock() {
        let _guard = super::super::lock_for_test();

        // A `RwLock` is poisoned only by a panic while a *write* guard is held. Joining the
        // thread guarantees the panic has happened before the assertions below.
        let poisoner = std::thread::spawn(|| {
            let _write_guard = GLOBAL_TIMING_PROTECTION
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("deliberately poisoning GLOBAL_TIMING_PROTECTION");
        });
        assert!(
            poisoner.join().is_err(),
            "the poisoning thread did not panic, so the lock is not poisoned and this test \
             would prove nothing"
        );

        set_timing_protection(TimingProtection::strict());
        assert_eq!(
            get_timing_protection(),
            TimingProtection::strict(),
            "set_timing_protection silently did not apply after the lock was poisoned"
        );

        set_timing_protection(TimingProtection::default());
        assert_eq!(
            get_timing_protection(),
            TimingProtection::default(),
            "get_timing_protection invented a value instead of returning the stored one"
        );
    }
}
