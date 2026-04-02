//! lib-Q AEAD - Post-quantum Authenticated Encryption
//!
//! This crate provides a flexible, algorithm-agnostic implementation of post-quantum
//! authenticated encryption with associated data (AEAD). It supports dynamic algorithm
//! registration and follows libQ's architectural principles.

#![cfg_attr(not(feature = "std"), no_std)]
// Note: We need unsafe code for global registry initialization
#![deny(unused_qualifications)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{
    boxed::Box,
    vec::Vec,
};

// Re-export types: algorithm IDs from `lib-q-types`; crypto API from `lib-q-core`
pub use lib_q_core::{
    Aead,
    AeadKey,
    Nonce,
    Result,
};
pub use lib_q_types::{
    Algorithm,
    AlgorithmCategory,
};

// Internal modules
mod metadata;
mod plugin;
mod registry;
pub mod security;

// Re-export public API
pub use metadata::{
    AeadMetadata,
    AeadWithMetadata,
    PerformanceTier,
};
pub use plugin::{
    AeadPlugin,
    PluginRegistry,
};
pub use registry::AeadRegistry;
// Re-export security sub-modules for testing
pub use security::constant_time;
// Re-export security API
pub use security::{
    SecurityConfig,
    SecurityContext,
    get_security_config,
    set_security_config,
};
pub use security::{
    memory,
    nonce,
    side_channel,
    stack_buffer,
    timing,
    validation,
};

#[cfg(feature = "alloc")]
mod provider;
#[cfg(feature = "alloc")]
pub use provider::LibQAeadProvider;

// Macro is exported at crate root via #[macro_export] in plugin.rs

// Algorithm implementations
#[cfg(feature = "duplex-sponge-aead")]
mod duplex_aead_impl;
#[cfg(feature = "kem-aead")]
mod kem_aead_impl;
#[cfg(feature = "romulus-m")]
mod romulus_m_impl;
#[cfg(feature = "romulus-n")]
mod romulus_n_impl;
#[cfg(feature = "saturnin")]
mod saturnin_impl;
#[cfg(feature = "shake256")]
mod shake256_impl;
#[cfg(feature = "tweak-aead")]
mod tweak_aead_impl;

// Re-export implementations
#[cfg(feature = "duplex-sponge-aead")]
pub use duplex_aead_impl::DuplexSpongeAead;
#[cfg(feature = "kem-aead")]
pub use kem_aead_impl::KemAead;
#[cfg(feature = "romulus-m")]
pub use romulus_m_impl::RomulusMAead;
#[cfg(feature = "romulus-n")]
pub use romulus_n_impl::RomulusNAead;
#[cfg(feature = "saturnin")]
pub use saturnin_impl::SaturninAead;
#[cfg(feature = "shake256")]
pub use shake256_impl::Shake256Aead;
#[cfg(feature = "tweak-aead")]
pub use tweak_aead_impl::TweakAead;

/// Global AEAD registry instance
///
/// This uses thread-safe initialization when compiled with std features,
/// and single-threaded initialization for no_std environments.
/// The key insight is that when the HPKE crate is compiled with std features,
/// it expects thread-safe statics, so we need to provide them.
#[cfg(feature = "std")]
static REGISTRY: once_cell::sync::Lazy<AeadRegistry> = once_cell::sync::Lazy::new(|| {
    let registry = AeadRegistry::new();

    // Register built-in algorithms
    #[cfg(feature = "saturnin")]
    let _ = registry.register_algorithm(Algorithm::Saturnin, || {
        Ok(Box::new(SaturninAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "shake256")]
    let _ = registry.register_algorithm(Algorithm::Shake256Aead, || {
        Ok(Box::new(Shake256Aead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "kem-aead")]
    let _ = registry.register_algorithm(Algorithm::KemAead, || {
        Ok(Box::new(KemAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "duplex-sponge-aead")]
    let _ = registry.register_algorithm(Algorithm::DuplexSpongeAead, || {
        Ok(Box::new(DuplexSpongeAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "tweak-aead")]
    let _ = registry.register_algorithm(Algorithm::TweakAead, || {
        Ok(Box::new(TweakAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "romulus-n")]
    let _ = registry.register_algorithm(Algorithm::RomulusN, || {
        Ok(Box::new(RomulusNAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "romulus-m")]
    let _ = registry.register_algorithm(Algorithm::RomulusM, || {
        Ok(Box::new(RomulusMAead::new()) as Box<dyn AeadWithMetadata>)
    });

    registry
});

/// Global AEAD registry instance for no_std environments
///
/// This uses thread-safe initialization for WASM and other targets that require Sync.
/// For true no_std environments without threading, this is still safe.
#[cfg(not(feature = "std"))]
static REGISTRY: once_cell::sync::Lazy<AeadRegistry> = once_cell::sync::Lazy::new(|| {
    let registry = AeadRegistry::new();

    // Register built-in algorithms
    #[cfg(feature = "saturnin")]
    let _ = registry.register_algorithm(Algorithm::Saturnin, || {
        Ok(Box::new(SaturninAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "shake256")]
    let _ = registry.register_algorithm(Algorithm::Shake256Aead, || {
        Ok(Box::new(Shake256Aead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "kem-aead")]
    let _ = registry.register_algorithm(Algorithm::KemAead, || {
        Ok(Box::new(KemAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "duplex-sponge-aead")]
    let _ = registry.register_algorithm(Algorithm::DuplexSpongeAead, || {
        Ok(Box::new(DuplexSpongeAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "tweak-aead")]
    let _ = registry.register_algorithm(Algorithm::TweakAead, || {
        Ok(Box::new(TweakAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "romulus-n")]
    let _ = registry.register_algorithm(Algorithm::RomulusN, || {
        Ok(Box::new(RomulusNAead::new()) as Box<dyn AeadWithMetadata>)
    });

    #[cfg(feature = "romulus-m")]
    let _ = registry.register_algorithm(Algorithm::RomulusM, || {
        Ok(Box::new(RomulusMAead::new()) as Box<dyn AeadWithMetadata>)
    });

    registry
});

/// Get the global AEAD registry
pub fn registry() -> &'static AeadRegistry {
    &REGISTRY
}

/// Get available AEAD algorithms
pub fn available_algorithms() -> Vec<Algorithm> {
    registry().available_algorithms()
}

/// Create an AEAD instance by algorithm
pub fn create_aead(algorithm: Algorithm) -> Result<Box<dyn AeadWithMetadata>> {
    // Validate algorithm category
    if algorithm.category() != AlgorithmCategory::Aead {
        return Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: "Algorithm is not an AEAD algorithm",
        });
    }

    registry().create_aead(algorithm)
}

/// Check if an algorithm is available
pub fn is_algorithm_available(algorithm: Algorithm) -> bool {
    algorithm.category() == AlgorithmCategory::Aead && registry().is_available(algorithm)
}

/// Get algorithm metadata
pub fn get_algorithm_metadata(algorithm: Algorithm) -> Option<&'static AeadMetadata> {
    if algorithm.category() != AlgorithmCategory::Aead {
        return None;
    }
    registry().get_metadata(algorithm)
}

/// Register a custom AEAD algorithm
#[cfg(feature = "std")]
pub fn register_algorithm<F>(_algorithm: Algorithm, _constructor: F) -> Result<()>
where
    F: Fn() -> Result<Box<dyn AeadWithMetadata>> + Send + Sync + 'static,
{
    // For std, we need to modify the registry, but it's immutable
    // This is a limitation of the current design
    Err(lib_q_core::Error::NotImplemented {
        feature: "Dynamic algorithm registration requires mutable registry".to_string(),
    })
}

/// Register a custom AEAD algorithm for no_std - using safe approach
#[cfg(not(feature = "std"))]
pub fn register_algorithm<F>(algorithm: Algorithm, constructor: F) -> Result<()>
where
    F: Fn() -> Result<Box<dyn AeadWithMetadata>> + Send + Sync + 'static,
{
    if algorithm.category() != AlgorithmCategory::Aead {
        return Err(lib_q_core::Error::InvalidAlgorithm {
            algorithm: "Algorithm is not an AEAD algorithm",
        });
    }

    // Use the registry's safe registration method
    // Note: This will only work if the registry hasn't been initialized yet
    // In a real implementation, you might want to use a different approach
    // such as a global mutex or atomic operations
    registry().register_algorithm(algorithm, constructor)
}

/// Register a plugin
#[cfg(feature = "std")]
pub fn register_plugin(_plugin: Box<dyn AeadPlugin>) -> Result<()> {
    // For std, we need to modify the registry, but it's immutable
    // This is a limitation of the current design
    Err(lib_q_core::Error::NotImplemented {
        feature: "Dynamic plugin registration requires mutable registry".to_string(),
    })
}

/// Register a plugin for no_std - using safe approach
#[cfg(not(feature = "std"))]
pub fn register_plugin(plugin: Box<dyn AeadPlugin>) -> Result<()> {
    // Use the registry's safe registration method
    registry().register_plugin(plugin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_algorithms() {
        let algorithms = available_algorithms();
        assert!(!algorithms.is_empty());

        // All returned algorithms should be AEAD algorithms
        for algorithm in algorithms {
            assert_eq!(algorithm.category(), AlgorithmCategory::Aead);
        }
    }

    #[test]
    fn test_create_aead() {
        let algorithms = available_algorithms();

        for algorithm in algorithms {
            let aead = create_aead(algorithm);
            assert!(aead.is_ok(), "Failed to create AEAD for {:?}", algorithm);
        }
    }

    #[test]
    fn test_invalid_algorithm() {
        // Try to create AEAD with non-AEAD algorithm
        let result = create_aead(Algorithm::MlKem512);
        assert!(result.is_err());

        if let Err(lib_q_core::Error::InvalidAlgorithm { algorithm }) = result {
            assert!(algorithm.contains("not an AEAD algorithm"));
        } else {
            panic!("Expected InvalidAlgorithm error");
        }
    }

    #[test]
    fn test_algorithm_availability() {
        let algorithms = available_algorithms();

        for algorithm in algorithms {
            assert!(is_algorithm_available(algorithm));
        }

        // Non-AEAD algorithms should not be available
        assert!(!is_algorithm_available(Algorithm::MlKem512));
    }

    #[test]
    fn test_algorithm_metadata() {
        let algorithms = available_algorithms();

        for algorithm in algorithms {
            let metadata = get_algorithm_metadata(algorithm);
            assert!(metadata.is_some(), "No metadata for {:?}", algorithm);

            if let Some(meta) = metadata {
                assert_eq!(meta.algorithm, algorithm);
                assert!(meta.key_size > 0);
                assert!(meta.nonce_size > 0);
                assert!(meta.tag_size > 0);
            }
        }
    }
}
