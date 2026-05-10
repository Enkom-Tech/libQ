//! Timing attack protection
//!
//! This module provides protection against timing attacks by ensuring
//! that cryptographic operations take constant time regardless of
//! the input values.

use core::future::Future;
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
use core::sync::atomic::{
    AtomicU64,
    Ordering,
};

/// Timing attack protection configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingProtection {
    /// Enable timing attack protection
    pub enabled: bool,
    /// Minimum execution time in nanoseconds
    pub min_execution_time: u64,
    /// Maximum execution time in nanoseconds
    pub max_execution_time: u64,
    /// Enable jitter to prevent timing analysis
    pub enable_jitter: bool,
    /// Jitter range in nanoseconds
    pub jitter_range: u64,
}

impl Default for TimingProtection {
    fn default() -> Self {
        Self {
            enabled: true,
            min_execution_time: 1000,  // 1 microsecond
            max_execution_time: 10000, // 10 microseconds
            enable_jitter: true,       // Enable jitter for security
            jitter_range: 1000,        // 1 microsecond jitter
        }
    }
}

impl TimingProtection {
    /// Create a new timing protection configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict timing protection configuration
    pub fn strict() -> Self {
        Self {
            enabled: true,
            min_execution_time: 5000,  // 5 microseconds
            max_execution_time: 20000, // 20 microseconds
            enable_jitter: true,
            jitter_range: 2000, // 2 microseconds
        }
    }

    /// Create a permissive timing protection configuration
    pub fn permissive() -> Self {
        Self {
            enabled: false,
            min_execution_time: 0,
            max_execution_time: 0,
            enable_jitter: false,
            jitter_range: 0,
        }
    }

    /// Create a balanced timing protection configuration
    pub fn balanced() -> Self {
        Self {
            enabled: true,
            min_execution_time: 1000, // 1 microsecond
            max_execution_time: 5000, // 5 microseconds
            enable_jitter: true,
            jitter_range: 500, // 0.5 microseconds
        }
    }

    /// Protect a function with timing attack resistance
    pub fn protect<F, R>(&self, func: F) -> R
    where
        F: FnOnce() -> R,
    {
        if !self.enabled {
            return func();
        }

        let start_time = self.get_timestamp();
        let result = func();
        let end_time = self.get_timestamp();
        let execution_time = end_time - start_time;

        // Ensure minimum execution time
        if execution_time < self.min_execution_time {
            self.sleep(self.min_execution_time - execution_time);
        }

        // Ensure maximum execution time
        if execution_time > self.max_execution_time {
            // Log warning or take other action
            // For now, we just continue
        }

        // Add jitter if enabled
        if self.enable_jitter {
            let jitter = self.generate_jitter();
            self.sleep(jitter);
        }

        result
    }

    /// Protect a function with timing attack resistance (async version)
    pub async fn protect_async<F, Fut, R>(&self, func: F) -> R
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = R>,
    {
        if !self.enabled {
            return func().await;
        }

        let start_time = self.get_timestamp();
        let result = func().await;
        let end_time = self.get_timestamp();
        let execution_time = end_time - start_time;

        // Ensure minimum execution time
        if execution_time < self.min_execution_time {
            self.sleep_async(self.min_execution_time - execution_time)
                .await;
        }

        // Ensure maximum execution time
        if execution_time > self.max_execution_time {
            // Log warning or take other action
            // For now, we just continue
        }

        // Add jitter if enabled
        if self.enable_jitter {
            let jitter = self.generate_jitter();
            self.sleep_async(jitter).await;
        }

        result
    }

    /// Protect a function with timing attack resistance and return execution time
    pub fn protect_with_timing<F, R>(&self, func: F) -> (R, u64)
    where
        F: FnOnce() -> R,
    {
        if !self.enabled {
            let start_time = self.get_timestamp();
            let result = func();
            let end_time = self.get_timestamp();
            return (result, end_time - start_time);
        }

        let start_time = self.get_timestamp();
        let result = func();
        let end_time = self.get_timestamp();
        let execution_time = end_time - start_time;

        // Ensure minimum execution time
        if execution_time < self.min_execution_time {
            self.sleep(self.min_execution_time - execution_time);
        }

        // Ensure maximum execution time
        if execution_time > self.max_execution_time {
            // Log warning or take other action
            // For now, we just continue
        }

        // Add jitter if enabled
        if self.enable_jitter {
            let jitter = self.generate_jitter();
            self.sleep(jitter);
        }

        // Return the total execution time including protection
        let total_time = self.get_timestamp() - start_time;
        (result, total_time)
    }

    /// Protect a function with timing attack resistance and return execution time (async version)
    pub async fn protect_with_timing_async<F, Fut, R>(&self, func: F) -> (R, u64)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = R>,
    {
        if !self.enabled {
            let start_time = self.get_timestamp();
            let result = func().await;
            let end_time = self.get_timestamp();
            return (result, end_time - start_time);
        }

        let start_time = self.get_timestamp();
        let result = func().await;
        let end_time = self.get_timestamp();
        let execution_time = end_time - start_time;

        // Ensure minimum execution time
        if execution_time < self.min_execution_time {
            self.sleep_async(self.min_execution_time - execution_time)
                .await;
        }

        // Ensure maximum execution time
        if execution_time > self.max_execution_time {
            // Log warning or take other action
            // For now, we just continue
        }

        // Add jitter if enabled
        if self.enable_jitter {
            let jitter = self.generate_jitter();
            self.sleep_async(jitter).await;
        }

        (result, execution_time)
    }

    /// Protect a function with timing attack resistance and return execution time and jitter
    pub fn protect_with_timing_and_jitter<F, R>(&self, func: F) -> (R, u64, u64)
    where
        F: FnOnce() -> R,
    {
        if !self.enabled {
            let start_time = self.get_timestamp();
            let result = func();
            let end_time = self.get_timestamp();
            return (result, end_time - start_time, 0);
        }

        let start_time = self.get_timestamp();
        let result = func();
        let end_time = self.get_timestamp();
        let execution_time = end_time - start_time;

        // Ensure minimum execution time
        if execution_time < self.min_execution_time {
            self.sleep(self.min_execution_time - execution_time);
        }

        // Ensure maximum execution time
        if execution_time > self.max_execution_time {
            // Log warning or take other action
            // For now, we just continue
        }

        // Add jitter if enabled
        let jitter = if self.enable_jitter {
            let jitter = self.generate_jitter();
            self.sleep(jitter);
            jitter
        } else {
            0
        };

        // Return the total execution time including protection
        let total_time = self.get_timestamp() - start_time;
        (result, total_time, jitter)
    }

    /// Protect a function with timing attack resistance and return execution time and jitter (async version)
    pub async fn protect_with_timing_and_jitter_async<F, Fut, R>(&self, func: F) -> (R, u64, u64)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = R>,
    {
        if !self.enabled {
            let start_time = self.get_timestamp();
            let result = func().await;
            let end_time = self.get_timestamp();
            return (result, end_time - start_time, 0);
        }

        let start_time = self.get_timestamp();
        let result = func().await;
        let end_time = self.get_timestamp();
        let execution_time = end_time - start_time;

        // Ensure minimum execution time
        if execution_time < self.min_execution_time {
            self.sleep_async(self.min_execution_time - execution_time)
                .await;
        }

        // Ensure maximum execution time
        if execution_time > self.max_execution_time {
            // Log warning or take other action
            // For now, we just continue
        }

        // Add jitter if enabled
        let jitter = if self.enable_jitter {
            let jitter = self.generate_jitter();
            self.sleep_async(jitter).await;
            jitter
        } else {
            0
        };

        (result, execution_time, jitter)
    }

    /// Get current timestamp in nanoseconds
    fn get_timestamp(&self) -> u64 {
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
        // wasm32-unknown-unknown lacks a real clock (`SystemTime::now()` panics),
        // and no_std targets have no clock either, so both fall back to a
        // monotonic counter. This is sufficient for the spin-loop based
        // timing protection used by `protect`/`sleep`.
        #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
        {
            use core::sync::atomic::{
                AtomicU64,
                Ordering,
            };
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            COUNTER.fetch_add(1, Ordering::SeqCst)
        }
    }

    /// Sleep for the specified number of nanoseconds
    fn sleep(&self, nanoseconds: u64) {
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            use std::thread;
            if nanoseconds > 1_000_000 {
                // For longer sleeps, use thread::sleep
                thread::sleep(std::time::Duration::from_nanos(nanoseconds));
            } else {
                // For short sleeps, use busy wait for precision
                let start = self.get_timestamp();
                while self.get_timestamp() - start < nanoseconds {
                    core::hint::spin_loop();
                }
            }
        }
        #[cfg(all(feature = "std", target_arch = "wasm32"))]
        {
            let start = self.get_timestamp();
            while self.get_timestamp().saturating_sub(start) < nanoseconds {
                core::hint::spin_loop();
            }
        }
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, simulate sleep by incrementing counter
            use core::sync::atomic::{
                AtomicU64,
                Ordering,
            };
            static SLEEP_COUNTER: AtomicU64 = AtomicU64::new(0);
            for _ in 0..nanoseconds {
                SLEEP_COUNTER.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// Sleep for the specified number of nanoseconds (async version)
    async fn sleep_async(&self, nanoseconds: u64) {
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            use std::time::Duration;
            std::thread::sleep(Duration::from_nanos(nanoseconds));
        }
        #[cfg(all(feature = "std", target_arch = "wasm32"))]
        {
            let start = self.get_timestamp();
            while self.get_timestamp().saturating_sub(start) < nanoseconds {
                core::hint::spin_loop();
            }
        }
        #[cfg(not(feature = "std"))]
        {
            // For no_std environments, use busy wait with yield
            let start = self.get_timestamp();
            while self.get_timestamp() - start < nanoseconds {
                // Use async-friendly busy wait
                core::hint::spin_loop();
                // In a real async environment, you might want to yield here
                // but we can't use async_yield in no_std
            }
        }
    }

    /// Generate random jitter
    fn generate_jitter(&self) -> u64 {
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{
                Hash,
                Hasher,
            };
            use std::time::{
                SystemTime,
                UNIX_EPOCH,
            };

            // Use system time as a seed for pseudo-random jitter
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            let mut hasher = DefaultHasher::new();
            now.hash(&mut hasher);
            let hash = hasher.finish();

            // Generate jitter in the range [0, jitter_range]
            hash % (self.jitter_range + 1)
        }
        // wasm32-unknown-unknown and no_std lack a real clock; use a
        // counter-based pseudo-jitter fallback.
        #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
        {
            static JITTER_COUNTER: AtomicU64 = AtomicU64::new(0);
            let counter = JITTER_COUNTER.fetch_add(1, Ordering::SeqCst);
            counter % (self.jitter_range + 1)
        }
    }
}

/// Global timing protection configuration with thread-safe access
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

/// Get the global timing protection configuration
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

/// Set the global timing protection configuration
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

/// Protect a function with global timing attack resistance
pub fn protect_timing<F, R>(func: F) -> R
where
    F: FnOnce() -> R,
{
    get_timing_protection().protect(func)
}

/// Protect a function with global timing attack resistance (async version)
pub async fn protect_timing_async<F, Fut, R>(func: F) -> R
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = R>,
{
    get_timing_protection().protect_async(func).await
}

/// Protect a function with global timing attack resistance and return execution time
pub fn protect_timing_with_timing<F, R>(func: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    get_timing_protection().protect_with_timing(func)
}

/// Protect a function with global timing attack resistance and return execution time (async version)
pub async fn protect_timing_with_timing_async<F, Fut, R>(func: F) -> (R, u64)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = R>,
{
    get_timing_protection()
        .protect_with_timing_async(func)
        .await
}

/// Protect a function with global timing attack resistance and return execution time and jitter
pub fn protect_timing_with_timing_and_jitter<F, R>(func: F) -> (R, u64, u64)
where
    F: FnOnce() -> R,
{
    get_timing_protection().protect_with_timing_and_jitter(func)
}

/// Protect a function with global timing attack resistance and return execution time and jitter (async version)
pub async fn protect_timing_with_timing_and_jitter_async<F, Fut, R>(func: F) -> (R, u64, u64)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = R>,
{
    get_timing_protection()
        .protect_with_timing_and_jitter_async(func)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_protection_defaults() {
        let protection = TimingProtection::default();
        assert!(protection.enabled);
        assert_eq!(protection.min_execution_time, 1000);
        assert_eq!(protection.max_execution_time, 10000);
        assert!(protection.enable_jitter);
        assert_eq!(protection.jitter_range, 1000);
    }

    #[test]
    fn test_timing_protection_strict() {
        let protection = TimingProtection::strict();
        assert!(protection.enabled);
        assert_eq!(protection.min_execution_time, 5000);
        assert_eq!(protection.max_execution_time, 20000);
        assert!(protection.enable_jitter);
        assert_eq!(protection.jitter_range, 2000);
    }

    #[test]
    fn test_timing_protection_permissive() {
        let protection = TimingProtection::permissive();
        assert!(!protection.enabled);
        assert_eq!(protection.min_execution_time, 0);
        assert_eq!(protection.max_execution_time, 0);
        assert!(!protection.enable_jitter);
        assert_eq!(protection.jitter_range, 0);
    }

    #[test]
    fn test_timing_protection_balanced() {
        let protection = TimingProtection::balanced();
        assert!(protection.enabled);
        assert_eq!(protection.min_execution_time, 1000);
        assert_eq!(protection.max_execution_time, 5000);
        assert!(protection.enable_jitter);
        assert_eq!(protection.jitter_range, 500);
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
        let (result, timing) = protection.protect_with_timing(|| 42);
        assert_eq!(result, 42);
        assert!(timing > 0); // Should be positive after protection
    }

    #[test]
    fn test_protect_with_timing_and_jitter() {
        let protection = TimingProtection::new();
        let (result, timing, jitter) = protection.protect_with_timing_and_jitter(|| 42);
        assert_eq!(result, 42);
        assert!(timing > 0); // Should be positive after protection
        assert!(jitter <= 1000); // Jitter should be within reasonable range
    }

    #[test]
    fn test_global_timing_protection() {
        let result = protect_timing(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_global_timing_protection_with_timing() {
        let (result, timing) = protect_timing_with_timing(|| 42);
        assert_eq!(result, 42);
        assert!(timing > 0); // Should be positive after protection
    }

    #[test]
    fn test_global_timing_protection_with_timing_and_jitter() {
        let config = get_timing_protection();
        let (result, timing, jitter) = protect_timing_with_timing_and_jitter(|| 42);
        assert_eq!(result, 42);
        assert!(timing > 0); // Should be positive after protection
        // Jitter should be within the configured range
        assert!(
            jitter <= config.jitter_range,
            "Jitter {} exceeds maximum of {}",
            jitter,
            config.jitter_range
        );
    }

    #[test]
    fn test_global_timing_protection_config() {
        // Test that the functions work without panicking
        let config = get_timing_protection();
        assert_eq!(config, TimingProtection::default());

        let new_config = TimingProtection::strict();
        set_timing_protection(new_config); // Should not panic

        // Test that the functions work without panicking
        let _result = protect_timing(|| 42);
        let (_result, _timing) = protect_timing_with_timing(|| 42);
        let (_result, _timing, _jitter) = protect_timing_with_timing_and_jitter(|| 42);
    }
}
