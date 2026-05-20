//! Custom Entropy Source System for `no_std` and WASM Environments
//!
//! This module provides a secure, callback-based entropy source system that allows
//! developers to plug in custom entropy sources for `no_std` and WASM environments.
//! The system uses function pointers and thread-local storage to avoid global state
//! while maintaining security and performance.

use core::sync::atomic::{
    AtomicPtr,
    Ordering,
};
use core::{
    fmt,
    ptr,
};

use crate::{
    Error,
    Result,
};

/// Function pointer type for custom entropy sources
///
/// This function should fill the provided buffer with cryptographically secure
/// random bytes. The function must be thread-safe and should not block indefinitely.
///
/// # Arguments
///
/// * `dest` - Buffer to fill with random bytes
/// * `len` - Number of bytes to generate
/// * `context` - Optional context data passed to the entropy source
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if entropy generation fails.
///
/// # Safety
///
/// The `dest` pointer must be valid for `len` bytes and must not be null.
/// The function must not cause undefined behavior.
pub type EntropyCallback = unsafe extern "C" fn(dest: *mut u8, len: usize, context: *mut u8) -> i32;

/// Context data for entropy callbacks
///
/// This structure can be used to pass additional context to entropy callbacks,
/// such as user data or configuration.
#[derive(Debug, Clone, Copy)]
pub struct EntropyContext {
    /// User-defined context data
    pub user_data: *mut u8,
    /// Context size in bytes
    pub size: usize,
}

impl EntropyContext {
    /// Create a new entropy context
    ///
    /// # Arguments
    ///
    /// * `user_data` - User-defined context data
    /// * `size` - Size of the context data in bytes
    ///
    /// # Safety
    ///
    /// The `user_data` pointer must be valid for `size` bytes if `size > 0`.
    pub const unsafe fn new(user_data: *mut u8, size: usize) -> Self {
        Self { user_data, size }
    }

    /// Create an empty entropy context
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            user_data: ptr::null_mut(),
            size: 0,
        }
    }
}

/// Entropy source quality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntropyQuality {
    /// Hardware-based entropy source (highest quality)
    Hardware,
    /// OS-provided entropy source
    Os,
    /// User-provided entropy source
    User,
    /// Deterministic source (lowest quality, testing only)
    Deterministic,
}

impl EntropyQuality {
    /// Get the numeric quality value (0.0 to 1.0)
    #[must_use]
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Hardware => 1.0,
            Self::Os => 0.95,
            Self::User => 0.8,
            Self::Deterministic => 0.0,
        }
    }

    /// Check if this quality level is cryptographically secure
    #[must_use]
    pub fn is_secure(self) -> bool {
        matches!(self, Self::Hardware | Self::Os | Self::User)
    }
}

/// Custom entropy source configuration
#[derive(Debug, Clone)]
pub struct CustomEntropyConfig {
    /// Minimum entropy quality required
    pub min_quality: EntropyQuality,
    /// Maximum bytes per entropy call
    pub max_bytes_per_call: usize,
    /// Whether to validate entropy quality
    pub validate_quality: bool,
    /// Timeout for entropy generation (in some unit)
    pub timeout_ms: u32,
}

impl Default for CustomEntropyConfig {
    fn default() -> Self {
        Self {
            min_quality: EntropyQuality::User,
            max_bytes_per_call: 1024,
            validate_quality: true,
            timeout_ms: 1000,
        }
    }
}

/// Custom entropy source registration
///
/// This structure manages the registration of custom entropy sources
/// for the current thread.
#[derive(Debug)]
pub struct CustomEntropySource {
    /// Callback function for entropy generation
    pub callback: EntropyCallback,
    /// Context data for the callback
    pub context: EntropyContext,
    /// Quality level of this entropy source
    pub quality: EntropyQuality,
    /// Configuration for this entropy source
    pub config: CustomEntropyConfig,
    /// Source identifier
    pub source_id: &'static str,
}

impl CustomEntropySource {
    /// Create a new custom entropy source
    ///
    /// # Arguments
    ///
    /// * `callback` - Function to call for entropy generation
    /// * `context` - Context data for the callback
    /// * `quality` - Quality level of this entropy source
    /// * `config` - Configuration for this entropy source
    /// * `source_id` - Unique identifier for this source
    ///
    /// # Safety
    ///
    /// The `callback` function must be thread-safe and must not cause
    /// undefined behavior. The `context.user_data` must be valid for
    /// `context.size` bytes if `context.size > 0`.
    pub const unsafe fn new(
        callback: EntropyCallback,
        context: EntropyContext,
        quality: EntropyQuality,
        config: CustomEntropyConfig,
        source_id: &'static str,
    ) -> Self {
        Self {
            callback,
            context,
            quality,
            config,
            source_id,
        }
    }

    /// Get the callback function
    #[must_use]
    pub fn callback(&self) -> EntropyCallback {
        self.callback
    }

    /// Get the context data
    #[must_use]
    pub fn context(&self) -> EntropyContext {
        self.context
    }

    /// Get the quality level
    #[must_use]
    pub fn quality(&self) -> EntropyQuality {
        self.quality
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &CustomEntropyConfig {
        &self.config
    }

    /// Get the source identifier
    #[must_use]
    pub fn source_id(&self) -> &'static str {
        self.source_id
    }

    /// Generate entropy using this source
    ///
    /// # Arguments
    ///
    /// * `dest` - Buffer to fill with random bytes
    ///
    /// # Errors
    ///
    /// Returns an error if entropy generation fails or if the generated
    /// entropy doesn't meet quality requirements.
    pub fn generate_entropy(&self, dest: &mut [u8]) -> Result<()> {
        if dest.len() > self.config.max_bytes_per_call {
            return Err(Error::EntropySourceUnavailable {
                source: self.source_id,
                context: Some("requested bytes exceed maximum per call"),
            });
        }

        if !self.quality.is_secure() && self.config.validate_quality {
            return Err(Error::EntropyValidationFailed {
                reason: "entropy source quality too low",
                quality: self.quality.as_f64(),
                details: Some("deterministic sources not allowed in secure mode"),
            });
        }

        // Call the custom entropy function
        let result =
            unsafe { (self.callback)(dest.as_mut_ptr(), dest.len(), self.context.user_data) };

        if result == 0 {
            Ok(())
        } else {
            Err(Error::EntropySourceUnavailable {
                source: self.source_id,
                context: Some("custom entropy callback failed"),
            })
        }
    }
}

/// Thread-local entropy source registry
///
/// This structure manages custom entropy sources for the current thread.
/// It uses atomic operations to ensure thread safety.
pub struct ThreadEntropyRegistry {
    /// Currently registered entropy source
    source: AtomicPtr<CustomEntropySource>,
}

impl Default for ThreadEntropyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadEntropyRegistry {
    /// Create a new thread entropy registry
    #[must_use]
    pub const fn new() -> Self {
        Self {
            source: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Register a custom entropy source for this thread
    ///
    /// # Arguments
    ///
    /// * `source` - The custom entropy source to register
    ///
    /// # Safety
    ///
    /// The `source` must remain valid for the lifetime of the registry.
    /// The caller is responsible for ensuring the source is not dropped
    /// while registered.
    pub unsafe fn register(&self, source: *const CustomEntropySource) {
        self.source.store(source.cast_mut(), Ordering::Release);
    }

    /// Unregister the current entropy source
    pub fn unregister(&self) {
        self.source.store(ptr::null_mut(), Ordering::Release);
    }

    /// Get the currently registered entropy source
    ///
    /// # Returns
    ///
    /// Returns a reference to the registered entropy source, or `None`
    /// if no source is registered.
    ///
    /// # Safety
    ///
    /// The returned reference is only valid as long as the source remains
    /// registered and not dropped.
    pub unsafe fn get_source(&self) -> Option<&CustomEntropySource> {
        let ptr = self.source.load(Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            unsafe { Some(&*ptr) }
        }
    }

    /// Generate entropy using the registered source
    ///
    /// # Arguments
    ///
    /// * `dest` - Buffer to fill with random bytes
    ///
    /// # Errors
    ///
    /// Returns an error if no source is registered or if entropy generation fails.
    pub fn generate_entropy(&self, dest: &mut [u8]) -> Result<()> {
        unsafe {
            if let Some(source) = self.get_source() {
                source.generate_entropy(dest)
            } else {
                Err(Error::EntropySourceUnavailable {
                    source: "thread_local",
                    context: Some("no custom entropy source registered"),
                })
            }
        }
    }
}

thread_local! {
    static THREAD_REGISTRY: ThreadEntropyRegistry = const { ThreadEntropyRegistry::new() };
}

/// Register a custom entropy source for the current thread
///
/// # Arguments
///
/// * `source` - The custom entropy source to register
///
/// # Safety
///
/// The `source` must remain valid for the lifetime of the registration.
/// The caller is responsible for ensuring the source is not dropped
/// while registered.
pub unsafe fn register_custom_entropy_source(source: *const CustomEntropySource) {
    THREAD_REGISTRY.with(|registry| unsafe { registry.register(source) });
}

/// Unregister the current custom entropy source
pub fn unregister_custom_entropy_source() {
    THREAD_REGISTRY.with(ThreadEntropyRegistry::unregister);
}

/// Generate entropy using the registered custom source
///
/// # Arguments
///
/// * `dest` - Buffer to fill with random bytes
///
/// # Errors
///
/// Returns an error if no source is registered or if entropy generation fails.
pub fn generate_custom_entropy(dest: &mut [u8]) -> Result<()> {
    THREAD_REGISTRY.with(|registry| registry.generate_entropy(dest))
}

/// Check if a custom entropy source is registered
pub fn has_custom_entropy_source() -> bool {
    THREAD_REGISTRY.with(|registry| unsafe { registry.get_source().is_some() })
}

/// Get information about the registered entropy source
///
/// # Returns
///
/// Returns a tuple of (`source_id`, quality) if a source is registered.
pub fn get_entropy_source_info() -> Option<(&'static str, EntropyQuality)> {
    THREAD_REGISTRY.with(|registry| unsafe {
        registry
            .get_source()
            .map(|source| (source.source_id(), source.quality()))
    })
}

impl fmt::Display for EntropyQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hardware => write!(f, "Hardware"),
            Self::Os => write!(f, "OS"),
            Self::User => write!(f, "User"),
            Self::Deterministic => write!(f, "Deterministic"),
        }
    }
}

impl fmt::Display for CustomEntropyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CustomEntropyConfig {{ min_quality: {}, max_bytes: {}, validate: {}, timeout: {}ms }}",
            self.min_quality, self.max_bytes_per_call, self.validate_quality, self.timeout_ms
        )
    }
}

impl fmt::Display for CustomEntropySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CustomEntropySource {{ id: {}, quality: {}, config: {} }}",
            self.source_id, self.quality, self.config
        )
    }
}

// CustomEntropySource is not an RNG itself, it's a source of entropy for RNGs

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::format;

    use super::*;

    // Test entropy callback that generates predictable data
    #[allow(clippy::cast_possible_truncation)]
    unsafe extern "C" fn test_entropy_callback(
        dest: *mut u8,
        len: usize,
        _context: *mut u8,
    ) -> i32 {
        if dest.is_null() {
            return -1;
        }

        // Generate predictable test data (handle empty buffer case)
        for i in 0..len {
            unsafe {
                *dest.add(i) = (i as u8).wrapping_add(42);
            }
        }

        0
    }

    #[test]
    fn test_entropy_context_creation() {
        let context = EntropyContext::empty();
        assert!(context.user_data.is_null());
        assert_eq!(context.size, 0);

        let data = [1u8, 2, 3, 4];
        let context = unsafe { EntropyContext::new(data.as_ptr().cast_mut(), data.len()) };
        assert!(!context.user_data.is_null());
        assert_eq!(context.size, 4);
    }

    #[test]
    fn test_entropy_quality() {
        assert!(EntropyQuality::Hardware.is_secure());
        assert!(EntropyQuality::Os.is_secure());
        assert!(EntropyQuality::User.is_secure());
        assert!(!EntropyQuality::Deterministic.is_secure());

        assert!((EntropyQuality::Hardware.as_f64() - 1.0).abs() < f64::EPSILON);
        assert!((EntropyQuality::Os.as_f64() - 0.95).abs() < f64::EPSILON);
        assert!((EntropyQuality::User.as_f64() - 0.8).abs() < f64::EPSILON);
        assert!((EntropyQuality::Deterministic.as_f64() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_custom_entropy_config_default() {
        let config = CustomEntropyConfig::default();
        assert_eq!(config.min_quality, EntropyQuality::User);
        assert_eq!(config.max_bytes_per_call, 1024);
        assert!(config.validate_quality);
        assert_eq!(config.timeout_ms, 1000);
    }

    #[test]
    fn test_custom_entropy_source_creation() {
        let context = EntropyContext::empty();
        let config = CustomEntropyConfig::default();

        let source = unsafe {
            CustomEntropySource::new(
                test_entropy_callback,
                context,
                EntropyQuality::User,
                config,
                "test_source",
            )
        };

        assert_eq!(source.source_id(), "test_source");
        assert_eq!(source.quality(), EntropyQuality::User);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_custom_entropy_generation() {
        let context = EntropyContext::empty();
        let config = CustomEntropyConfig::default();

        let source = unsafe {
            CustomEntropySource::new(
                test_entropy_callback,
                context,
                EntropyQuality::User,
                config,
                "test_source",
            )
        };

        let mut buffer = [0u8; 16];
        source.generate_entropy(&mut buffer).unwrap();

        // Check that the callback was called (predictable test data)
        for (i, &byte) in buffer.iter().enumerate() {
            let expected = (i as u8).wrapping_add(42);
            assert_eq!(byte, expected);
        }
    }

    #[test]
    fn test_custom_entropy_max_bytes_validation() {
        let context = EntropyContext::empty();
        let config = CustomEntropyConfig {
            max_bytes_per_call: 8,
            ..Default::default()
        };

        let source = unsafe {
            CustomEntropySource::new(
                test_entropy_callback,
                context,
                EntropyQuality::User,
                config,
                "test_source",
            )
        };

        let mut buffer = [0u8; 16]; // Exceeds max_bytes_per_call
        let result = source.generate_entropy(&mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_entropy_quality_validation() {
        let context = EntropyContext::empty();
        let config = CustomEntropyConfig {
            validate_quality: true,
            ..Default::default()
        };

        let source = unsafe {
            CustomEntropySource::new(
                test_entropy_callback,
                context,
                EntropyQuality::Deterministic, // Low quality
                config,
                "test_source",
            )
        };

        let mut buffer = [0u8; 8];
        let result = source.generate_entropy(&mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_thread_entropy_registry() {
        let _registry = ThreadEntropyRegistry::new();

        // Initially no source registered
        assert!(!has_custom_entropy_source());
        assert!(get_entropy_source_info().is_none());

        let context = EntropyContext::empty();
        let config = CustomEntropyConfig::default();
        let source = CustomEntropySource {
            callback: test_entropy_callback,
            context,
            quality: EntropyQuality::User,
            config,
            source_id: "test_registry",
        };

        // Register the source
        unsafe {
            register_custom_entropy_source(&raw const source);
        }

        assert!(has_custom_entropy_source());
        let info = get_entropy_source_info().unwrap();
        assert_eq!(info.0, "test_registry");
        assert_eq!(info.1, EntropyQuality::User);

        // Test entropy generation
        let mut buffer = [0u8; 8];
        generate_custom_entropy(&mut buffer).unwrap();

        // Unregister the source
        unregister_custom_entropy_source();
        assert!(!has_custom_entropy_source());
        assert!(get_entropy_source_info().is_none());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_entropy_source_display() {
        let context = EntropyContext::empty();
        let config = CustomEntropyConfig::default();

        let source = unsafe {
            CustomEntropySource::new(
                test_entropy_callback,
                context,
                EntropyQuality::Hardware,
                config,
                "display_test",
            )
        };

        let display = format!("{source}");
        assert!(display.contains("display_test"));
        assert!(display.contains("Hardware"));
    }
}
