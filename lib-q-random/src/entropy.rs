// Allow clippy warnings in entropy source code
// These are legitimate patterns for platform-specific implementations
#![allow(
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::manual_clamp,
    clippy::needless_return,
    clippy::collapsible_if,
    clippy::match_same_arms,
    clippy::unreadable_literal,
    clippy::missing_errors_doc
)]

//! Entropy source implementations
//!
//! This module provides various entropy source implementations for different
//! platforms and use cases, including OS entropy, hardware RNGs, and
//! deterministic sources for testing.

#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    vec::Vec,
};

use crate::traits::{
    EntropyConfig,
    EntropySource,
    EntropySourceType,
};
use crate::{
    Error,
    Result,
};

/// Operating system entropy source
///
/// This entropy source uses the operating system's secure random number
/// generator, typically `/dev/urandom` on Unix-like systems or
/// `CryptGenRandom` on Windows.
#[derive(Debug, Clone)]
pub struct OsEntropySource {
    /// Platform identifier
    platform: &'static str,
    /// Quality estimate
    quality: f64,
    /// Maximum entropy per call (from config)
    max_per_call: Option<usize>,
}

impl OsEntropySource {
    /// Create a new OS entropy source
    pub fn new() -> Self {
        let platform = Self::detect_platform();
        let quality = Self::estimate_platform_quality(platform);
        Self {
            platform,
            quality,
            max_per_call: None,
        }
    }

    /// Estimate quality based on platform
    fn estimate_platform_quality(platform: &'static str) -> f64 {
        match platform {
            "Linux" => 0.95,       // /dev/urandom is generally high quality
            "macOS" => 0.95,       // SecRandomCopyBytes is high quality
            "Windows" => 0.95,     // CryptGenRandom is high quality
            "FreeBSD" => 0.95,     // /dev/urandom is high quality
            "OpenBSD" => 0.95,     // /dev/urandom is high quality
            "NetBSD" => 0.95,      // /dev/urandom is high quality
            "WebAssembly" => 0.90, // Browser crypto.getRandomValues() is good but slightly lower
            _ => 0.80,             // Unknown platforms get conservative estimate
        }
    }

    /// Get the platform identifier
    pub fn platform(&self) -> &'static str {
        self.platform
    }

    /// Detect the current platform
    fn detect_platform() -> &'static str {
        #[cfg(target_os = "linux")]
        return "Linux";
        #[cfg(target_os = "macos")]
        return "macOS";
        #[cfg(target_os = "windows")]
        return "Windows";
        #[cfg(target_os = "freebsd")]
        return "FreeBSD";
        #[cfg(target_os = "openbsd")]
        return "OpenBSD";
        #[cfg(target_os = "netbsd")]
        return "NetBSD";
        #[cfg(target_arch = "wasm32")]
        return "WebAssembly";
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_arch = "wasm32"
        )))]
        return "Unknown";
    }
}

impl EntropySource for OsEntropySource {
    fn get_entropy(&mut self, dest: &mut [u8]) -> Result<()> {
        // Check if the requested amount exceeds the maximum per call
        if let Some(max_per_call) = self.max_entropy_per_call() {
            if dest.len() > max_per_call {
                return Err(Error::entropy_source_unavailable(
                    "Requested entropy exceeds maximum per call",
                ));
            }
        }

        #[cfg(feature = "std")]
        {
            getrandom::fill(dest).map_err(|_| {
                Error::platform_rng_failed_with_code(
                    self.platform,
                    -1,
                    "Failed to get entropy from OS",
                )
            })
        }
        #[cfg(not(feature = "std"))]
        {
            Err(Error::feature_not_available("OS entropy source", &["std"]))
        }
    }

    fn initialize(&mut self, config: &EntropyConfig) -> Result<()> {
        // Validate that the source meets the minimum quality requirement
        if self.quality() < config.min_quality {
            return Err(Error::entropy_source_unavailable(
                "OS entropy source quality below required minimum",
            ));
        }

        // Update max_per_call if specified in config
        if let Some(max_per_call) = config.max_per_call {
            if max_per_call > 256 {
                return Err(Error::entropy_source_unavailable(
                    "Requested max_per_call exceeds OS entropy source limit",
                ));
            }
            self.max_per_call = Some(max_per_call);
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        #[cfg(feature = "std")]
        {
            true
        }
        #[cfg(not(feature = "std"))]
        {
            false
        }
    }

    fn quality(&self) -> f64 {
        self.quality
    }

    fn name(&self) -> &'static str {
        match self.platform {
            "Linux" => "Linux OS Entropy Source",
            "macOS" => "macOS OS Entropy Source",
            "Windows" => "Windows OS Entropy Source",
            "FreeBSD" => "FreeBSD OS Entropy Source",
            "OpenBSD" => "OpenBSD OS Entropy Source",
            "NetBSD" => "NetBSD OS Entropy Source",
            "WebAssembly" => "WebAssembly OS Entropy Source",
            _ => "Unknown OS Entropy Source",
        }
    }

    fn source_type(&self) -> EntropySourceType {
        EntropySourceType::OperatingSystem
    }

    fn max_entropy_per_call(&self) -> Option<usize> {
        self.max_per_call.or(Some(16384)) // Use config value or default limit (16KB)
    }
}

impl Default for OsEntropySource {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardware random number generator entropy source
///
/// This entropy source attempts to use hardware random number generators
/// when available, such as Intel RDRAND or ARM TRNG.
#[derive(Debug, Clone)]
pub struct HardwareEntropySource {
    /// Hardware device identifier
    device: &'static str,
    /// Quality estimate
    quality: f64,
    /// Whether hardware RNG is available
    available: bool,
}

impl HardwareEntropySource {
    /// Create a new hardware entropy source
    pub fn new() -> Self {
        let (device, available) = Self::detect_hardware_rng();
        Self {
            device,
            quality: if available { 0.99 } else { 0.0 },
            available,
        }
    }

    /// Detect available hardware RNG
    fn detect_hardware_rng() -> (&'static str, bool) {
        // For now, we don't have a working hardware RNG implementation
        // so we always return false to fall back to OS entropy
        #[cfg(target_arch = "x86_64")]
        {
            return ("Intel x86_64", false);
        }
        #[cfg(target_arch = "aarch64")]
        {
            return ("ARM TRNG", false);
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            return ("Unknown", false);
        }
    }
}

impl EntropySource for HardwareEntropySource {
    fn get_entropy(&mut self, dest: &mut [u8]) -> Result<()> {
        if !self.available {
            return Err(Error::hardware_rng_failed(self.device));
        }

        // Check if the requested amount exceeds the maximum per call
        if let Some(max_per_call) = self.max_entropy_per_call() {
            if dest.len() > max_per_call {
                return Err(Error::entropy_source_unavailable(
                    "Requested entropy exceeds hardware RNG maximum per call",
                ));
            }
        }

        // This is a placeholder implementation
        // In a real implementation, you would use platform-specific
        // hardware RNG APIs
        Err(Error::hardware_rng_failed_with_status(
            self.device,
            0,
            "Hardware RNG not implemented",
        ))
    }

    fn initialize(&mut self, config: &EntropyConfig) -> Result<()> {
        // Validate that the source meets the minimum quality requirement
        if self.quality() < config.min_quality {
            return Err(Error::entropy_source_unavailable(
                "Hardware entropy source quality below required minimum",
            ));
        }

        // Update max_per_call if specified in config
        if let Some(max_per_call) = config.max_per_call {
            if max_per_call > 64 {
                return Err(Error::entropy_source_unavailable(
                    "Requested max_per_call exceeds hardware RNG limit",
                ));
            }
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn quality(&self) -> f64 {
        self.quality
    }

    fn name(&self) -> &'static str {
        "Hardware RNG"
    }

    fn source_type(&self) -> EntropySourceType {
        EntropySourceType::Hardware
    }

    fn max_entropy_per_call(&self) -> Option<usize> {
        Some(64) // Hardware RNGs typically provide limited entropy per call
    }
}

impl Default for HardwareEntropySource {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic entropy source for testing
///
/// This entropy source provides deterministic "entropy" based on a seed,
/// making it suitable for testing and reproducible operations.
/// **NOT CRYPTOGRAPHICALLY SECURE**.
#[derive(Debug, Clone)]
pub struct DeterministicEntropySource {
    /// Seed for deterministic generation
    seed: u64,
    /// Counter for generation
    counter: u64,
    /// Quality estimate (low for deterministic)
    quality: f64,
}

impl DeterministicEntropySource {
    /// Create a new deterministic entropy source
    pub fn new(seed: &[u8]) -> Self {
        let mut seed_value = 0u64;

        // Use a better hash function to combine seed bytes
        for (i, &byte) in seed.iter().enumerate() {
            let shift = (i % 8) * 8;
            seed_value ^= (byte as u64) << shift;
            // Add some mixing
            seed_value = seed_value.wrapping_mul(0x9E3779B97F4A7C15u64);
        }

        // Ensure different seeds produce different initial states
        if seed_value == 0 {
            seed_value = 1;
        }

        Self {
            seed: seed_value,
            counter: 0,
            quality: 0.0, // Deterministic sources have no entropy
        }
    }

    /// Generate deterministic "entropy"
    fn generate_deterministic_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            // Simple LCG for deterministic generation
            self.seed = self
                .seed
                .wrapping_mul(6364136223846793005u64)
                .wrapping_add(1442695040888963407u64);
            self.counter = self.counter.wrapping_add(1);

            let value = self.seed ^ self.counter;
            let bytes = value.to_le_bytes();

            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&bytes[..len]);
        }
    }
}

impl EntropySource for DeterministicEntropySource {
    fn get_entropy(&mut self, dest: &mut [u8]) -> Result<()> {
        self.generate_deterministic_bytes(dest);
        Ok(())
    }

    fn initialize(&mut self, config: &EntropyConfig) -> Result<()> {
        // For deterministic sources, we don't enforce quality requirements
        // since they're meant for testing and have 0.0 quality by design
        let _ = config;
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn quality(&self) -> f64 {
        self.quality
    }

    fn name(&self) -> &'static str {
        "Deterministic Entropy Source"
    }

    fn source_type(&self) -> EntropySourceType {
        EntropySourceType::Deterministic
    }

    fn max_entropy_per_call(&self) -> Option<usize> {
        None // No limit for deterministic sources
    }
}

/// User-provided entropy source
///
/// This entropy source allows users to provide their own entropy data,
/// useful for specialized applications or when integrating with external
/// entropy sources.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct UserEntropySource {
    /// User-provided entropy data
    entropy_data: Vec<u8>,
    /// Current position in the entropy data
    position: usize,
    /// Quality estimate
    quality: f64,
    /// Configured maximum entropy per call
    max_per_call: Option<usize>,
}

#[cfg(feature = "alloc")]
impl UserEntropySource {
    /// Create a new user entropy source
    pub fn new(entropy_data: Vec<u8>) -> Self {
        Self {
            quality: 0.8, // Assume reasonable quality for user-provided data
            entropy_data,
            position: 0,
            max_per_call: None, // No limit by default
        }
    }

    /// Create a new user entropy source with quality assessment
    pub fn with_quality(entropy_data: Vec<u8>, quality: f64) -> Self {
        Self {
            quality: quality.max(0.0).min(1.0),
            entropy_data,
            position: 0,
            max_per_call: None, // No limit by default
        }
    }
}

#[cfg(feature = "alloc")]
impl EntropySource for UserEntropySource {
    fn get_entropy(&mut self, dest: &mut [u8]) -> Result<()> {
        if self.entropy_data.is_empty() {
            return Err(Error::entropy_source_unavailable("User entropy source"));
        }

        // Check if the requested amount exceeds the maximum per call
        if let Some(max_per_call) = self.max_per_call {
            if dest.len() > max_per_call {
                return Err(Error::entropy_source_unavailable(
                    "Requested entropy exceeds user entropy source maximum per call",
                ));
            }
        }

        for (i, byte) in dest.iter_mut().enumerate() {
            let index = (self.position + i) % self.entropy_data.len();
            *byte = self.entropy_data[index];
        }

        self.position = (self.position + dest.len()) % self.entropy_data.len();
        Ok(())
    }

    fn initialize(&mut self, config: &EntropyConfig) -> Result<()> {
        // Validate that the source meets the minimum quality requirement
        if self.quality() < config.min_quality {
            return Err(Error::entropy_source_unavailable(
                "User entropy source quality below required minimum",
            ));
        }

        // For user entropy sources, we allow max_per_call to be larger than the entropy data size
        // because the source can cycle through the data. We only enforce reasonable limits.
        if let Some(max_per_call) = config.max_per_call {
            if max_per_call > 1024 {
                return Err(Error::entropy_source_unavailable(
                    "Requested max_per_call exceeds reasonable limit for user entropy source",
                ));
            }
            // Store the configured max_per_call
            self.max_per_call = Some(max_per_call);
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        !self.entropy_data.is_empty()
    }

    fn quality(&self) -> f64 {
        self.quality
    }

    fn name(&self) -> &'static str {
        "User Entropy Source"
    }

    fn source_type(&self) -> EntropySourceType {
        EntropySourceType::User
    }

    fn max_entropy_per_call(&self) -> Option<usize> {
        Some(self.entropy_data.len())
    }
}

/// Entropy source factory
///
/// This factory provides convenient methods for creating different types
/// of entropy sources based on requirements and platform capabilities.
#[cfg(feature = "alloc")]
pub struct EntropySourceFactory;

#[cfg(feature = "alloc")]
impl EntropySourceFactory {
    /// Create the best available entropy source
    ///
    /// This method attempts to create the highest quality entropy source
    /// available on the current platform.
    pub fn create_best_available() -> Result<Box<dyn EntropySource>> {
        Self::create_best_available_with_config(&EntropyConfig::default())
    }

    /// Create the best available entropy source with configuration
    ///
    /// This method attempts to create the highest quality entropy source
    /// available on the current platform that meets the specified requirements.
    pub fn create_best_available_with_config(
        config: &EntropyConfig,
    ) -> Result<Box<dyn EntropySource>> {
        // Try hardware RNG first
        let mut hardware_source = HardwareEntropySource::new();
        if hardware_source.is_available() {
            if hardware_source.initialize(config).is_ok() {
                return Ok(Box::new(hardware_source));
            }
        }

        // Fall back to OS entropy
        let mut os_source = OsEntropySource::new();
        if os_source.is_available() {
            if os_source.initialize(config).is_ok() {
                return Ok(Box::new(os_source));
            }
        }

        // As a last resort, use secure fallback with relaxed quality requirements
        let mut fallback_config = config.clone();
        fallback_config.min_quality = 0.5; // Lower threshold for fallback

        let mut fallback_source = crate::secure_fallback::SecureFallbackEntropySource::new();
        if fallback_source.initialize(&fallback_config).is_ok() {
            #[cfg(feature = "std")]
            eprintln!(
                "Warning: Using secure fallback entropy source. \
                This may indicate limited entropy availability on this system."
            );
            return Ok(Box::new(fallback_source));
        }

        // If even fallback fails, return an error
        Err(Error::entropy_source_unavailable(
            "No entropy sources available that meet the requirements, including fallback",
        ))
    }

    /// Create an OS entropy source
    pub fn create_os_entropy() -> Result<Box<dyn EntropySource>> {
        Self::create_os_entropy_with_config(&EntropyConfig::default())
    }

    /// Create an OS entropy source with configuration
    pub fn create_os_entropy_with_config(config: &EntropyConfig) -> Result<Box<dyn EntropySource>> {
        let mut source = OsEntropySource::new();
        if source.is_available() {
            source.initialize(config)?;
            Ok(Box::new(source))
        } else {
            Err(Error::entropy_source_unavailable("OS entropy source"))
        }
    }

    /// Create a hardware entropy source
    pub fn create_hardware_entropy() -> Result<Box<dyn EntropySource>> {
        Self::create_hardware_entropy_with_config(&EntropyConfig::default())
    }

    /// Create a hardware entropy source with configuration
    pub fn create_hardware_entropy_with_config(
        config: &EntropyConfig,
    ) -> Result<Box<dyn EntropySource>> {
        let mut source = HardwareEntropySource::new();
        if source.is_available() {
            source.initialize(config)?;
            Ok(Box::new(source))
        } else {
            Err(Error::entropy_source_unavailable("Hardware entropy source"))
        }
    }

    /// Create a deterministic entropy source
    pub fn create_deterministic_entropy(seed: &[u8]) -> Box<dyn EntropySource> {
        Box::new(DeterministicEntropySource::new(seed))
    }

    /// Create a user entropy source
    pub fn create_user_entropy(entropy_data: Vec<u8>) -> Box<dyn EntropySource> {
        Box::new(UserEntropySource::new(entropy_data))
    }

    /// Create a user entropy source with quality assessment
    pub fn create_user_entropy_with_quality(
        entropy_data: Vec<u8>,
        quality: f64,
    ) -> Box<dyn EntropySource> {
        Box::new(UserEntropySource::with_quality(entropy_data, quality))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::{
        format,
        vec,
    };

    use super::*;

    #[test]
    fn test_os_entropy_source_creation() {
        let source = OsEntropySource::new();
        assert!(!source.name().is_empty());
        assert_eq!(source.source_type(), EntropySourceType::OperatingSystem);

        // Test that platform is detected and used in name
        let platform = source.platform();
        assert!(!platform.is_empty());
        assert!(source.name().contains(platform));

        // Test that quality is set based on platform
        assert!(source.quality() > 0.0);
        assert!(source.quality() <= 1.0);
    }

    #[test]
    fn test_hardware_entropy_source_creation() {
        let source = HardwareEntropySource::new();
        assert!(!source.name().is_empty());
        assert_eq!(source.source_type(), EntropySourceType::Hardware);
    }

    #[test]
    fn test_deterministic_entropy_source_creation() {
        let seed = [1, 2, 3, 4, 5, 6, 7, 8];
        let source = DeterministicEntropySource::new(&seed);
        assert!(!source.name().is_empty());
        assert_eq!(source.source_type(), EntropySourceType::Deterministic);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(source.quality(), 0.0);
        }
    }

    #[test]
    fn test_deterministic_entropy_consistency() {
        let seed = [42u8; 16];
        let mut source1 = DeterministicEntropySource::new(&seed);
        let mut source2 = DeterministicEntropySource::new(&seed);

        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];

        source1.get_entropy(&mut bytes1).unwrap();
        source2.get_entropy(&mut bytes2).unwrap();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_user_entropy_source_creation() {
        let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let source = UserEntropySource::new(entropy_data);
        assert!(!source.name().is_empty());
        assert_eq!(source.source_type(), EntropySourceType::User);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_user_entropy_source_with_quality() {
        let entropy_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let source = UserEntropySource::with_quality(entropy_data, 0.9);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(source.quality(), 0.9);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_user_entropy_source_cycling() {
        let entropy_data = vec![1, 2, 3];
        let mut source = UserEntropySource::new(entropy_data);

        // Initialize with a config that allows more bytes per call
        let config = EntropyConfig {
            max_per_call: Some(6), // Allow up to 6 bytes per call (same as what we're requesting)
            ..Default::default()
        };
        source.initialize(&config).unwrap();

        let mut bytes = [0u8; 6];
        source.get_entropy(&mut bytes).unwrap();

        // Should cycle through the entropy data
        assert_eq!(bytes, [1, 2, 3, 1, 2, 3]);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_entropy_source_factory_deterministic() {
        let seed = [1, 2, 3, 4];
        let source = EntropySourceFactory::create_deterministic_entropy(&seed);
        assert_eq!(source.source_type(), EntropySourceType::Deterministic);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_entropy_source_factory_user() {
        let entropy_data = vec![1, 2, 3, 4, 5];
        let source = EntropySourceFactory::create_user_entropy(entropy_data);
        assert_eq!(source.source_type(), EntropySourceType::User);
    }

    #[test]
    fn test_entropy_config_validation() {
        let config = EntropyConfig {
            min_quality: 0.9, // High quality requirement
            max_per_call: Some(32),
            ..Default::default()
        };

        // Test OS entropy source with high quality requirement
        let mut os_source = OsEntropySource::new();
        // OS entropy should meet the quality requirement (0.95 > 0.9)
        assert!(os_source.initialize(&config).is_ok());

        // Test with quality requirement too high
        let config2 = EntropyConfig {
            min_quality: 0.99,
            ..config
        };
        let mut os_source2 = OsEntropySource::new();
        // OS entropy should not meet this requirement (0.95 < 0.99)
        assert!(os_source2.initialize(&config2).is_err());
    }

    #[test]
    fn test_entropy_config_max_per_call() {
        let config = EntropyConfig {
            max_per_call: Some(16),
            ..Default::default()
        };

        let mut os_source = OsEntropySource::new();
        os_source.initialize(&config).unwrap();

        // Test requesting more than max_per_call
        let mut buffer = [0u8; 32]; // Request 32 bytes, but max is 16
        assert!(os_source.get_entropy(&mut buffer).is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_entropy_source_factory_with_config() {
        let config = EntropyConfig {
            min_quality: 0.8,
            max_per_call: Some(64),
            ..Default::default()
        };

        // This should work with default config
        let result = EntropySourceFactory::create_best_available_with_config(&config);
        // The result depends on platform capabilities, so we just check it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_platform_specific_error_messages() {
        let mut os_source = OsEntropySource::new();
        let platform = os_source.platform();

        // Test quality error message
        let config = EntropyConfig {
            min_quality: 1.0, // Set to impossible value
            ..Default::default()
        };

        let result = os_source.initialize(&config);
        assert!(result.is_err());
        if let Err(error) = result {
            let error_msg = format!("{error}");
            assert!(error_msg.contains("quality below required minimum"));
        }

        // Test max_per_call error message
        let config2 = EntropyConfig {
            max_per_call: Some(1000), // Exceeds limit
            ..Default::default()
        };

        let result2 = os_source.initialize(&config2);
        assert!(result2.is_err());
        if let Err(error) = result2 {
            let error_msg = format!("{error}");
            assert!(error_msg.contains("exceeds OS entropy source limit"));
        }

        // Test that platform is still accessible and used in name
        assert!(!platform.is_empty());
        assert!(os_source.name().contains(platform));
    }
}
