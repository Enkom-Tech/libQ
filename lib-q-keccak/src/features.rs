//! Feature configuration and runtime optimization selection
//!
//! This module provides runtime feature detection and optimization selection
//! capabilities, allowing users to choose the best available optimizations
//! for their specific use case.

use crate::optimized_core::OptimizationLevel;

/// Runtime feature detection and configuration
///
/// This struct provides methods to detect available hardware features
/// and select appropriate optimization levels.
#[derive(Debug, Clone)]
pub struct FeatureConfig {
    /// The selected optimization level
    pub optimization_level: OptimizationLevel,
    /// Whether to use parallel processing when available
    pub enable_parallel: bool,
    /// Whether to use advanced SIMD features when available
    pub enable_advanced_simd: bool,
    /// Whether to use platform-specific optimizations
    pub enable_platform_optimizations: bool,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            optimization_level: OptimizationLevel::best_available(),
            enable_parallel: true,
            enable_advanced_simd: true,
            enable_platform_optimizations: true,
        }
    }
}

impl FeatureConfig {
    /// Create a new feature configuration with automatic detection
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a feature configuration with specific optimization level
    pub fn with_optimization_level(level: OptimizationLevel) -> Self {
        Self {
            optimization_level: level,
            enable_parallel: true,
            enable_advanced_simd: true,
            enable_platform_optimizations: true,
        }
    }

    /// Create a feature configuration optimized for security
    ///
    /// This configuration prioritizes security over performance by using
    /// only well-tested reference implementations.
    pub fn security_optimized() -> Self {
        Self {
            optimization_level: OptimizationLevel::Reference,
            enable_parallel: false,
            enable_advanced_simd: false,
            enable_platform_optimizations: false,
        }
    }

    /// Create a feature configuration optimized for performance
    ///
    /// This configuration enables all available optimizations for maximum
    /// performance, potentially at the cost of some security guarantees.
    pub fn performance_optimized() -> Self {
        Self {
            optimization_level: OptimizationLevel::Maximum,
            enable_parallel: true,
            enable_advanced_simd: true,
            enable_platform_optimizations: true,
        }
    }

    /// Create a feature configuration optimized for compatibility
    ///
    /// This configuration uses only stable, widely-supported optimizations
    /// to ensure maximum compatibility across different platforms.
    pub fn compatibility_optimized() -> Self {
        Self {
            optimization_level: OptimizationLevel::Basic,
            enable_parallel: false,
            enable_advanced_simd: false,
            enable_platform_optimizations: true,
        }
    }

    /// Check if parallel processing is available and enabled
    pub fn parallel_available(&self) -> bool {
        self.enable_parallel &&
            cfg!(feature = "simd") &&
            self.optimization_level != OptimizationLevel::Reference
    }

    /// Check if advanced SIMD features are available and enabled
    pub fn advanced_simd_available(&self) -> bool {
        self.enable_advanced_simd &&
            cfg!(feature = "simd") &&
            self.optimization_level != OptimizationLevel::Reference
    }

    /// Check if platform-specific optimizations are available and enabled
    pub fn platform_optimizations_available(&self) -> bool {
        self.enable_platform_optimizations &&
            self.optimization_level != OptimizationLevel::Reference
    }

    /// Get the effective optimization level based on current configuration
    pub fn effective_optimization_level(&self) -> OptimizationLevel {
        if !self.enable_platform_optimizations {
            return OptimizationLevel::Reference;
        }

        if !self.enable_advanced_simd && self.optimization_level == OptimizationLevel::Maximum {
            return OptimizationLevel::Advanced;
        }

        self.optimization_level
    }

    /// Get a human-readable description of the current configuration
    pub fn description(&self) -> &'static str {
        let _level = self.effective_optimization_level();

        if self.parallel_available() &&
            self.advanced_simd_available() &&
            self.platform_optimizations_available()
        {
            "maximum optimization with all features"
        } else if self.parallel_available() && self.platform_optimizations_available() {
            "advanced optimization with parallel processing"
        } else if self.platform_optimizations_available() {
            "basic optimization with platform features"
        } else {
            "reference implementation"
        }
    }
}

/// Global feature configuration
///
/// This static configuration is used by default when no specific
/// configuration is provided.
static mut GLOBAL_CONFIG: Option<FeatureConfig> = None;

/// Set the global feature configuration
///
/// This function sets the global configuration that will be used
/// by default for all operations.
pub fn set_global_config(config: FeatureConfig) {
    unsafe {
        GLOBAL_CONFIG = Some(config);
    }
}

/// Get the global feature configuration
///
/// This function returns the current global configuration, or a default
/// configuration if none has been set.
pub fn get_global_config() -> FeatureConfig {
    #[allow(static_mut_refs)]
    unsafe {
        GLOBAL_CONFIG.clone().unwrap_or_default()
    }
}

/// Reset the global feature configuration to defaults
pub fn reset_global_config() {
    unsafe {
        GLOBAL_CONFIG = None;
    }
}

/// Runtime feature detection utilities
pub mod detection {
    use super::*;

    /// Detect all available hardware features
    ///
    /// This function returns a comprehensive report of all available
    /// hardware features that can be used for optimization.
    pub fn detect_available_features() -> FeatureReport {
        FeatureReport {
            x86_64: cfg!(target_arch = "x86_64"),
            avx2: cfg!(all(target_arch = "x86_64", target_feature = "avx2")),
            avx512f: cfg!(all(target_arch = "x86_64", target_feature = "avx512f")),
            aarch64: cfg!(target_arch = "aarch64"),
            sha3_intrinsics: cfg!(all(
                target_arch = "aarch64",
                feature = "arm64_sha3",
                target_feature = "sha3",
                not(cross_compile)
            )),
            simd_support: cfg!(feature = "simd"),
            nightly_features: cfg!(feature = "nightly"),
        }
    }

    /// Get the best available optimization level for the current platform
    pub fn best_available_optimization() -> OptimizationLevel {
        OptimizationLevel::best_available()
    }

    /// Check if a specific optimization level is available
    pub fn is_optimization_available(level: OptimizationLevel) -> bool {
        level.is_available()
    }
}

/// Comprehensive feature availability report
#[derive(Debug, Clone)]
pub struct FeatureReport {
    /// x86_64 architecture support
    pub x86_64: bool,
    /// AVX2 instruction set support
    pub avx2: bool,
    /// AVX-512 instruction set support
    pub avx512f: bool,
    /// AArch64 architecture support
    pub aarch64: bool,
    /// SHA3 intrinsics support (AArch64)
    pub sha3_intrinsics: bool,
    /// SIMD support (nightly feature)
    pub simd_support: bool,
    /// Nightly Rust features support
    pub nightly_features: bool,
}

impl FeatureReport {
    /// Get a human-readable summary of available features
    pub fn summary(&self) -> &'static str {
        if self.avx512f {
            "Available features: x86_64, AVX2, AVX-512, SIMD, nightly features"
        } else if self.avx2 {
            "Available features: x86_64, AVX2, SIMD, nightly features"
        } else if self.sha3_intrinsics {
            "Available features: AArch64, SHA3 intrinsics, SIMD, nightly features"
        } else if self.x86_64 {
            "Available features: x86_64, SIMD, nightly features"
        } else if self.aarch64 {
            "Available features: AArch64, SIMD, nightly features"
        } else if self.simd_support {
            "Available features: SIMD, nightly features"
        } else if self.nightly_features {
            "Available features: nightly features"
        } else {
            "No special features available"
        }
    }

    /// Get the recommended optimization level based on available features
    pub fn recommended_optimization_level(&self) -> OptimizationLevel {
        if self.avx512f {
            OptimizationLevel::Maximum
        } else if self.avx2 {
            OptimizationLevel::Advanced
        } else if self.sha3_intrinsics {
            OptimizationLevel::Basic
        } else {
            OptimizationLevel::Reference
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_config_default() {
        let config = FeatureConfig::default();
        assert!(config.optimization_level.is_available());
        assert!(config.enable_parallel);
        assert!(config.enable_advanced_simd);
        assert!(config.enable_platform_optimizations);
    }

    #[test]
    fn test_feature_config_security_optimized() {
        let config = FeatureConfig::security_optimized();
        assert_eq!(config.optimization_level, OptimizationLevel::Reference);
        assert!(!config.enable_parallel);
        assert!(!config.enable_advanced_simd);
        assert!(!config.enable_platform_optimizations);
    }

    #[test]
    fn test_feature_config_performance_optimized() {
        let config = FeatureConfig::performance_optimized();
        assert_eq!(config.optimization_level, OptimizationLevel::Maximum);
        assert!(config.enable_parallel);
        assert!(config.enable_advanced_simd);
        assert!(config.enable_platform_optimizations);
    }

    #[test]
    fn test_feature_detection() {
        let report = detection::detect_available_features();
        assert!(!report.summary().is_empty());

        let recommended = report.recommended_optimization_level();
        assert!(recommended.is_available());
    }

    #[test]
    fn test_global_config() {
        let config = FeatureConfig::security_optimized();
        set_global_config(config.clone());

        let retrieved = get_global_config();
        assert_eq!(retrieved.optimization_level, config.optimization_level);

        reset_global_config();
        let default = get_global_config();
        assert_eq!(
            default.optimization_level,
            OptimizationLevel::best_available()
        );
    }
}
