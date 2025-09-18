//! lib-Q - Post-Quantum Cryptography Library
//!
//! A modern, secure cryptography library built exclusively with NIST-approved
//! post-quantum algorithms. Written in Rust with WASM compilation support.
//!
//! # Architecture Principles
//!
//! - **Zero Dynamic Allocations**: Stack-only operations for constrained environments
//! - **Memory Safety**: Automatic zeroization of sensitive data using `Zeroize` trait
//! - **Constant-Time**: Operations designed to prevent timing attacks
//! - **Post-Quantum Only**: NIST-approved algorithms for quantum resistance
//! - **Provider Pattern**: Pluggable cryptographic implementations
//! - **Unified API**: Same interface for Rust crate and WASM usage
//!
//! # Security Features
//!
//! - **Four-Tier Security**: Level 1 (128-bit), Level 3 (192-bit), Level 4 (256-bit), Level 5 (256-bit+)
//! - **Algorithm Diversity**: ML-KEM, ML-DSA, FN-DSA, Saturnin, DAWN, and RCPKC
//! - **Input Validation**: Comprehensive validation of all cryptographic inputs
//! - **Error Handling**: Secure error messages that don't leak sensitive information
//!
//! # Example Usage
//!
//! ```rust
//! use libq::{
//!     Algorithm,
//!     HashContext,
//!     Utils,
//!     create_hash_context,
//! };
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize hash context
//!     let mut hash_ctx = create_hash_context();
//!
//!     // Hash data (returns NotImplemented error with current architecture)
//!     let result = hash_ctx.hash(Algorithm::Shake256, b"Hello, World!");
//!     match result {
//!         Ok(hash) => println!("Hash: {}", Utils::bytes_to_hex(&hash)),
//!         Err(e) => println!("Hash operation not implemented: {:?}", e),
//!     }
//!
//!     // Generate random bytes
//!     let random_bytes = Utils::random_bytes(32)?;
//!     println!("Random bytes: {}", Utils::bytes_to_hex(&random_bytes));
//!
//!     // Note: Algorithm operations require feature flags:
//!     // - For ML-DSA signatures: enable 'ml-dsa' feature
//!     // - For ML-KEM key exchange: enable 'ml-kem' feature
//!     // - For FN-DSA signatures: enable 'fn-dsa' feature
//!     // - For Saturnin AEAD: enable 'saturnin' feature
//!     // - For DAWN KEM: enable 'dawn' feature
//!     // - For RCPKC: enable 'rcpkc' feature
//!
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! - `std`: Enable standard library features (default)
//! - `no_std`: Disable standard library for embedded environments
//! - `wasm`: Enable WebAssembly compilation support
//! - `ml-kem`: Enable ML-KEM key encapsulation mechanism
//! - `ml-dsa`: Enable ML-DSA digital signature algorithm
//! - `fn-dsa`: Enable FN-DSA digital signature algorithm
//! - `saturnin`: Enable Saturnin authenticated encryption
//! - `dawn`: Enable DAWN key encapsulation mechanism
//! - `rcpkc`: Enable RCPKC cryptographic primitives
//! - `all-algorithms`: Enable all available algorithms
//! - `security-hardened`: Enable comprehensive security features
//!
//! # Security Considerations
//!
//! This library is designed with security as the primary concern:
//! - All sensitive data is automatically zeroized when dropped
//! - Operations are designed to be constant-time where possible
//! - Input validation is comprehensive and secure
//! - Error messages don't leak sensitive information
//! - Memory allocations are minimized for constrained environments
//!
//! # WASM Support
//!
//! The library can be compiled to WebAssembly for use in web applications:
//!
//! ```bash
//! wasm-pack build --target web --out-dir pkg
//! ```
//!
//! This provides a JavaScript API that mirrors the Rust API.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-export everything from lib-q-core
// Re-export the core provider as the main provider
// Re-export specific types and functions for convenience
pub use lib_q_core::{
    // Context types
    AeadContext,
    Algorithm,
    AlgorithmCategory,
    Error,
    HashContext,
    KemContext,
    // Core provider types
    LibQCryptoProvider as CoreLibQCryptoProvider,
    Result,
    SecurityLevel,
    // Security validation
    SecurityValidator,
    SignatureContext,
    // Version information
    VERSION,
    // Algorithm registry
    algorithms_by_category,
    algorithms_by_security_level,
    init,
    supported_algorithms,
    version,
};
// Re-export specific items from lib-q-core to avoid conflicts
pub use lib_q_core::{
    LibQCryptoProvider,
    Utils,
    create_aead_context,
    create_hash_context,
    create_kem_context,
    create_signature_context,
};
// Re-export from other crates for convenience
#[cfg(feature = "ml-kem")]
pub use lib_q_kem::{
    LibQKemProvider,
    available_algorithms,
};
#[cfg(feature = "ml-dsa")]
pub use lib_q_sig::{
    LibQSignatureProvider,
    available_algorithms,
    create_signature,
};

// Note: hash, aead, and utils features are handled by individual crates
// and don't need separate feature flags in the main lib-q crate

// WASM bindings
#[cfg(feature = "wasm")]
pub mod wasm {
    //! WebAssembly bindings for lib-Q
    //!
    //! This module provides JavaScript-compatible bindings for use in web applications.
    //! It integrates with the new modular architecture and provides comprehensive
    //! cryptographic functionality for web environments.

    // Re-export WASM components from lib-q-core
    // Import ToString trait and String type for string conversions
    #[cfg(not(feature = "std"))]
    use alloc::string::{
        String,
        ToString,
    };
    #[cfg(feature = "std")]
    use std::string::{
        String,
        ToString,
    };

    pub use lib_q_core::wasm::*;
    use wasm_bindgen::prelude::*;

    /// Initialize the library for WASM usage
    #[wasm_bindgen]
    pub fn init_wasm() -> Result<(), JsValue> {
        lib_q_core::init().map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get the library version
    #[wasm_bindgen]
    pub fn get_version() -> String {
        lib_q_core::version().to_string()
    }

    /// Check if an algorithm is supported
    #[wasm_bindgen]
    pub fn is_algorithm_supported_wasm(algorithm: &str) -> bool {
        // Use the new provider manager for algorithm support checking
        let manager = WasmProviderManager::new();
        manager.is_algorithm_supported(algorithm)
    }

    /// Get supported algorithms by category
    #[wasm_bindgen]
    pub fn get_supported_algorithms_wasm() -> JsValue {
        // Use the new provider manager for algorithm listing
        let manager = WasmProviderManager::new();
        let algorithms = manager.get_all_algorithms();
        JsValue::from_str(&algorithms)
    }

    /// Get library information for WASM
    #[wasm_bindgen]
    pub fn get_library_info_wasm() -> String {
        get_library_info()
    }

    /// Get security recommendations
    #[wasm_bindgen]
    pub fn get_security_recommendations_wasm() -> String {
        let manager = WasmProviderManager::new();
        manager.get_security_recommendations()
    }

    /// Get performance benchmarks
    #[wasm_bindgen]
    pub fn get_performance_benchmarks_wasm() -> String {
        let manager = WasmProviderManager::new();
        manager.get_performance_benchmarks()
    }

    /// Create a new KEM context for WASM
    #[wasm_bindgen]
    pub fn create_kem_context() -> WasmKemContext {
        WasmKemContext::new()
    }

    /// Create a new Signature context for WASM
    #[wasm_bindgen]
    pub fn create_signature_context() -> WasmSignatureContext {
        WasmSignatureContext::new()
    }

    /// Create a new Hash context for WASM
    #[wasm_bindgen]
    pub fn create_hash_context() -> WasmHashContext {
        WasmHashContext::new()
    }

    /// Create a new AEAD context for WASM
    #[wasm_bindgen]
    pub fn create_aead_context() -> WasmAeadContext {
        WasmAeadContext::new()
    }

    /// Create a new provider manager for WASM
    #[wasm_bindgen]
    pub fn create_provider_manager() -> WasmProviderManager {
        WasmProviderManager::new()
    }

    /// Generate secure random bytes for WASM
    #[wasm_bindgen]
    pub fn generate_random_bytes(length: usize) -> Result<js_sys::Uint8Array, JsValue> {
        random_bytes(length).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Convert bytes to hexadecimal string
    #[wasm_bindgen]
    pub fn bytes_to_hex_wasm(data: &js_sys::Uint8Array) -> String {
        bytes_to_hex(data)
    }

    /// Convert hexadecimal string to bytes
    #[wasm_bindgen]
    pub fn hex_to_bytes_wasm(hex: &str) -> Result<js_sys::Uint8Array, JsValue> {
        hex_to_bytes(hex).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use lib_q_core::{
        CryptoProvider,
        KemOperations,
    };

    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
        assert_eq!(version(), VERSION);
    }

    #[test]
    fn test_supported_algorithms() {
        let algorithms = algorithms_by_category(AlgorithmCategory::Hash);
        assert!(
            !algorithms.is_empty(),
            "Should have at least one hash algorithm"
        );
    }

    #[test]
    fn test_algorithms_by_security_level() {
        let level_1_algorithms = algorithms_by_security_level(SecurityLevel::Level1 as u32);
        assert!(
            !level_1_algorithms.is_empty(),
            "Should have at least one Level 1 algorithm"
        );
    }

    #[test]
    fn test_unified_api() {
        // Test that the unified API works correctly
        let provider = LibQCryptoProvider::new();
        assert!(provider.is_ok(), "Provider should be created successfully");

        let provider = provider.unwrap();

        // Test KEM operations - core provider should always return NotImplemented
        let kem_result = provider
            .kem()
            .unwrap()
            .generate_keypair(Algorithm::MlKem512, None);

        // Core provider always returns NotImplemented for KEM operations
        assert!(kem_result.is_err());
        if let Err(Error::NotImplemented { feature }) = kem_result {
            assert!(
                feature.contains("ML-KEM implementations are provided by the main lib-q crate")
            );
        } else {
            panic!("Expected NotImplemented error for KEM operations");
        }

        // Test that lib-q-kem provider works when used directly
        #[cfg(feature = "ml-kem")]
        {
            let kem_provider = LibQKemProvider::new().unwrap();
            let kem_result = kem_provider.generate_keypair(Algorithm::MlKem512, None);
            assert!(
                kem_result.is_ok(),
                "ML-KEM key generation should succeed with lib-q-kem provider"
            );
            let keypair = kem_result.unwrap();
            assert!(!keypair.public_key().as_bytes().is_empty());
            assert!(!keypair.secret_key().as_bytes().is_empty());
        }

        // Test signature operations - ML-DSA requires feature flag
        let sig_result = provider
            .signature()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65, None);
        #[cfg(feature = "ml-dsa")]
        {
            assert!(
                sig_result.is_ok(),
                "ML-DSA key generation should succeed with provider and ml-dsa feature"
            );
            let keypair = sig_result.unwrap();
            assert!(!keypair.public_key().as_bytes().is_empty());
            assert!(!keypair.secret_key().as_bytes().is_empty());
        }
        #[cfg(not(feature = "ml-dsa"))]
        {
            assert!(sig_result.is_err());
            if let Err(Error::NotImplemented { feature }) = sig_result {
                assert!(
                    feature.contains("ML-DSA implementations are provided by the main lib-q crate")
                );
            } else {
                panic!("Expected NotImplemented error for ML-DSA without feature flag");
            }
        }

        // Test hash operations
        let hash_result = provider
            .hash()
            .unwrap()
            .hash(Algorithm::Sha3_256, b"test data");
        // Hash operations should always return NotImplemented since implementations are in separate crates
        assert!(hash_result.is_err());
        if let Err(Error::NotImplemented { feature }) = hash_result {
            assert!(feature.contains("SHA3 implementations are provided by the main lib-q crate"));
        } else {
            panic!("Expected NotImplemented error for hash operations");
        }

        // Test AEAD operations
        #[cfg(not(feature = "std"))]
        use alloc::vec;

        use lib_q_core::traits::{
            AeadKey,
            Nonce,
        };
        // Generate proper random key and nonce that pass security validation
        let mut key_bytes = vec![0u8; 32];
        let mut nonce_bytes = vec![0u8; 16]; // Saturnin requires 16-byte nonce

        // Use a simple but valid key pattern that should pass entropy checks
        for i in 0..32 {
            key_bytes[i] = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        for i in 0..16 {
            nonce_bytes[i] = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }

        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let aead_result = provider.aead().unwrap().encrypt(
            Algorithm::Saturnin,
            &key,
            &nonce,
            b"plaintext",
            Some(b"associated data"),
        );
        // AEAD operations should always return NotImplemented since implementations are in separate crates
        assert!(aead_result.is_err());
        match aead_result {
            Err(Error::NotImplemented { feature }) => {
                assert!(
                    feature.contains("Saturnin implementation is provided by the main lib-q crate")
                );
            }
            Err(e) => {
                panic!(
                    "Expected NotImplemented error for AEAD operations, got: {:?}",
                    e
                );
            }
            Ok(_) => {
                panic!("Expected error for AEAD operations, but got success");
            }
        }
    }
}
