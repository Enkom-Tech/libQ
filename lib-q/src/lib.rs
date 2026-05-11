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
//! - **Algorithm Diversity**: ML-KEM, HQC, ML-DSA, FN-DSA, Saturnin, Romulus (N/M)
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
//!     // Hash data via the umbrella-wired `lib-q-hash` provider
//!     let result = hash_ctx.hash(Algorithm::Shake256, b"Hello, World!");
//!     match result {
//!         Ok(hash) => println!("Hash: {}", Utils::bytes_to_hex(&hash)),
//!         Err(e) => println!("Hash error: {:?}", e),
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
//!     // - For AEAD: use `libq::aead::context()` and enable `saturnin`, `romulus`, or other AEAD features
//!
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! - `std`: Enable standard library features (default)
//! - `no_std`: Marker feature; this crate uses `#![no_std]` when `std` is off, but path
//!   dependencies may still enable `std` (see crate README). For embedded builds, prefer
//!   leaf crates (`lib-q-core`, `lib-q-kem`, …) with `--no-default-features` and `alloc`.
//! - `wasm`: Enable WebAssembly compilation support
//! - `ml-kem`: Enable ML-KEM key encapsulation mechanism
//! - `ml-dsa`: Enable ML-DSA digital signature algorithm
//! - `slh-dsa`: Enable SLH-DSA (FIPS 205) algorithm metadata and shared types in `lib-q-core`
//! - `fn-dsa`: Enable FN-DSA digital signature algorithm
//! - `saturnin`: Enable Saturnin authenticated encryption
//! - `romulus`: Enable Romulus-N and Romulus-M AEAD (LWC / SKINNY-128-384+)
//! - `hqc`: Enable HQC key encapsulation mechanism (HQC-128 / HQC-192 / HQC-256)
//! - `random`: Enable lib-q-random for secure random number generation
//! - `random-custom-entropy`: Enable custom entropy source support
//! - `all-algorithms`: Enable all available algorithms
//! - `zkp`: Expose zero-knowledge / STARK API under `libq::zkp` (STARK core is always linked)
//! - `zkp-plonky` / `zkp-plonky-*`: Add the Plonky3-derived STARK stack under `libq::zkp::plonky`
//! - `zkp-parallel`: Rayon-backed parallel proving (STARK)
//! - `zkp-recursive-experimental`: Experimental recursive proof Merkle path (STARK)
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
//! For `getrandom` on `wasm32-unknown-unknown`, use the same flags as CI:
//! `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C panic=abort'`.
//!
//! This provides a JavaScript API that mirrors the Rust API where `wasm-bindgen` is enabled.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::boxed::Box;

#[cfg(feature = "alloc")]
pub mod aead;

// Re-export everything from lib-q-core
// Re-export the core provider as the main provider
// Re-export specific types and functions for convenience
#[cfg(feature = "cb-kem")]
pub use lib_q_cb_kem::LibQCbKemProvider;
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
    create_kem_context,
};
#[cfg(feature = "alloc")]
pub use lib_q_hash::LibQHashProvider;
#[cfg(feature = "hqc")]
pub use lib_q_hqc::LibQHqcProvider;
// Re-export from other crates for convenience
#[cfg(any(feature = "ml-kem", feature = "hqc"))]
pub use lib_q_kem::{
    LibQKemProvider,
    available_algorithms,
};
// Re-export lib-q-random for random number generation
#[cfg(feature = "random")]
pub use lib_q_random::{
    EntropyQuality,
    EntropyValidator,
    LibQRng,
    new_custom_rng,
    new_deterministic_rng,
    new_secure_rng,
};
// Note: random-no-std feature integration requires proper feature alignment
// between lib-q and lib-q-random crates. Currently, the no_std functions
// are gated behind #[cfg(not(feature = "alloc"))] in lib-q-random, but
// the main lib-q crate always enables alloc through default features.
// This integration can be added in a future update.
#[cfg(feature = "random-custom-entropy")]
pub use lib_q_random::{
    custom_entropy::{
        CustomEntropyConfig,
        CustomEntropySource,
        EntropyContext,
        EntropyQuality as CustomEntropyQuality,
    },
    get_custom_entropy_source_info,
    has_custom_entropy_source,
    register_custom_entropy_source,
    unregister_custom_entropy_source,
};
/// Legacy boxed `Signature` factory (`std` only; matches `lib-q-sig` / `Box<dyn Signature>`).
#[cfg(feature = "std")]
pub use lib_q_sig::create_signature;
pub use lib_q_sig::{
    LibQSignatureProvider,
    available_algorithms as sig_available_algorithms,
};

/// Create a [`SignatureContext`] with [`LibQSignatureProvider`]
/// already installed (ML-DSA and SLH-DSA from `lib-q-sig` defaults; FN-DSA when the `fn-dsa`
/// feature is enabled on this crate).
///
/// This is the umbrella-crate entry point: [`lib_q_core::create_signature_context`] returns an
/// empty context for composition in leaf crates; `libq::create_signature_context` wires the
/// production signature backend used by this workspace.
#[cfg(feature = "alloc")]
pub fn create_signature_context() -> SignatureContext {
    let provider = LibQSignatureProvider::new()
        .expect("lib-q-sig LibQSignatureProvider / SecurityValidator initialization");
    SignatureContext::with_provider(Box::new(provider))
}

/// Create a [`HashContext`] with [`LibQHashProvider`] installed.
///
/// This is the umbrella entry point: [`lib_q_core::create_hash_context`] returns an empty
/// context; `libq::create_hash_context` wires the hash implementation from `lib-q-hash` (all
/// registered hash [`Algorithm`] values, `no_std` + `alloc`, and WASM-compatible).
/// For the same wiring without panicking on setup failure, use
/// [`lib_q_hash::create_hash_context`] and handle its [`Result`].
#[cfg(feature = "alloc")]
pub fn create_hash_context() -> HashContext {
    let provider = LibQHashProvider::new()
        .expect("lib-q-hash LibQHashProvider / SecurityValidator initialization");
    HashContext::with_provider(Box::new(provider))
}

#[cfg(feature = "zkp")]
pub mod zkp {
    //! Zero-knowledge proof types and functions.
    //!
    //! Re-exports from `lib-q-zkp` for convenient top-level access.

    pub use lib_q_zkp::api::{
        MerklePath,
        prove_membership,
        prove_preimage,
        verify_membership,
        verify_membership_with_depth,
        verify_preimage,
    };
    pub use lib_q_zkp::circuit::{
        ArithmeticCircuit,
        CircuitAir,
        CircuitBuilder,
    };
    pub use lib_q_zkp::ip::credential::{
        IpCredential,
        compute_credential_commitment,
        prove_credential_attributes,
        verify_credential_proof,
    };
    /// Plonky3-derived STARK components (batch/uni STARK, Keccak AIR, lookup, multilinear util).
    ///
    /// Enable via `zkp-plonky` or a granular `zkp-plonky-*` feature on the `lib-q` crate.
    #[cfg(any(
        feature = "zkp-plonky",
        feature = "zkp-plonky-keccak-air",
        feature = "zkp-plonky-lookup",
        feature = "zkp-plonky-uni-stark",
        feature = "zkp-plonky-batch-stark",
    ))]
    pub use lib_q_zkp::plonky;
    pub use lib_q_zkp::stark::{
        StarkProver,
        StarkVerifier,
        default_config,
    };
    pub use lib_q_zkp::{
        ProofMetadata,
        ProofType,
        ZkpField,
        ZkpProof,
        ZkpProver,
        ZkpVerifier,
    };
}

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
    use alloc::boxed::Box;
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
        lib_q_core::init().map_err(|e| lib_q_core::wasm_common::wasm_js_error("LIB_Q_INIT", e))
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

    /// Create a new Signature context for WASM backed by `lib-q-sig` (same wiring as native
    /// `SignatureContext` with [`LibQSignatureProvider`](lib_q_sig::LibQSignatureProvider)).
    #[wasm_bindgen]
    pub fn create_signature_context() -> WasmSignatureContext {
        let provider = lib_q_sig::LibQSignatureProvider::new()
            .expect("lib-q-sig LibQSignatureProvider / SecurityValidator initialization");
        WasmSignatureContext::from_signature_context(lib_q_core::SignatureContext::with_provider(
            Box::new(provider),
        ))
    }

    /// Create a new Hash context for WASM backed by `lib-q-hash` (same wiring as
    /// [`crate::create_hash_context`]).
    #[wasm_bindgen]
    pub fn create_hash_context() -> WasmHashContext {
        let provider = lib_q_hash::LibQHashProvider::new()
            .expect("lib-q-hash LibQHashProvider / SecurityValidator initialization");
        WasmHashContext::from_hash_context(lib_q_core::HashContext::with_provider(Box::new(
            provider,
        )))
    }

    /// Create an AEAD context for WASM backed by `lib-q-aead` (same wiring as `libq::aead::context`).
    #[wasm_bindgen]
    pub fn create_aead_context() -> WasmAeadContext {
        WasmAeadContext::from_aead_context(lib_q_core::AeadContext::with_aead_operations(Box::new(
            lib_q_aead::LibQAeadProvider::new()
                .expect("lib-q-aead LibQAeadProvider / SecurityValidator initialization"),
        )))
    }

    /// Create a new provider manager for WASM
    #[wasm_bindgen]
    pub fn create_provider_manager() -> WasmProviderManager {
        WasmProviderManager::new()
    }

    /// Generate secure random bytes for WASM
    #[wasm_bindgen]
    pub fn generate_random_bytes(length: usize) -> Result<js_sys::Uint8Array, JsValue> {
        random_bytes(length).map_err(|e| lib_q_core::wasm_common::wasm_js_error("LIB_Q_RANDOM", e))
    }

    /// Convert bytes to hexadecimal string
    #[wasm_bindgen]
    pub fn bytes_to_hex_wasm(data: &js_sys::Uint8Array) -> String {
        bytes_to_hex(data)
    }

    /// Convert hexadecimal string to bytes
    #[wasm_bindgen]
    pub fn hex_to_bytes_wasm(hex: &str) -> Result<js_sys::Uint8Array, JsValue> {
        hex_to_bytes(hex).map_err(|e| lib_q_core::wasm_common::wasm_js_error("LIB_Q_HEX", e))
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use lib_q_core::{
        CryptoProvider,
        KemOperations, // Required for trait methods to be in scope
    };
    #[cfg(feature = "hqc")]
    use lib_q_hqc::HqcParams;

    use super::*;
    #[cfg(feature = "alloc")]
    use crate::aead;

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

    /// `libq::create_signature_context` must ship with `LibQSignatureProvider` wired so ML-DSA works
    /// without callers manually calling `set_provider`.
    #[cfg(feature = "alloc")]
    #[test]
    fn test_signature_context_pre_wired_ml_dsa_roundtrip() {
        let mut ctx = create_signature_context();
        let keypair = ctx
            .generate_keypair(Algorithm::MlDsa65, None)
            .expect("ML-DSA-65 keygen with pre-wired provider");
        let message = b"lib-q umbrella signature integration";
        let signature = ctx
            .sign(Algorithm::MlDsa65, keypair.secret_key(), message, None)
            .expect("sign");
        assert!(
            ctx.verify(
                Algorithm::MlDsa65,
                keypair.public_key(),
                message,
                signature.as_slice(),
            )
            .expect("verify")
        );
    }

    #[cfg(all(feature = "alloc", feature = "fn-dsa"))]
    #[test]
    fn test_signature_context_fn_dsa512_roundtrip() {
        let mut ctx = create_signature_context();
        let keypair = ctx
            .generate_keypair(Algorithm::FnDsa512, None)
            .expect("FN-DSA-512 keygen");
        let message = b"fn-dsa umbrella path";
        let signature = ctx
            .sign(Algorithm::FnDsa512, keypair.secret_key(), message, None)
            .expect("sign");
        assert!(
            ctx.verify(
                Algorithm::FnDsa512,
                keypair.public_key(),
                message,
                signature.as_slice(),
            )
            .expect("verify")
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

        #[cfg(feature = "hqc")]
        {
            let kem_provider = LibQKemProvider::new().unwrap();
            let keypair = kem_provider
                .generate_keypair(Algorithm::Hqc128, None)
                .expect("HQC-128 key generation with lib-q-kem provider");
            assert_eq!(
                keypair.public_key().as_bytes().len(),
                lib_q_hqc::Hqc1Params::PUBLIC_KEY_BYTES
            );
            assert_eq!(
                keypair.secret_key().as_bytes().len(),
                lib_q_hqc::Hqc1Params::SECRET_KEY_BYTES
            );
            let (ciphertext, shared1) = kem_provider
                .encapsulate(Algorithm::Hqc128, &keypair.public_key, None)
                .expect("HQC-128 encapsulate");
            assert_eq!(ciphertext.len(), lib_q_hqc::Hqc1Params::CIPHERTEXT_BYTES);
            let shared2 = kem_provider
                .decapsulate(Algorithm::Hqc128, &keypair.secret_key, &ciphertext)
                .expect("HQC-128 decapsulate");
            assert_eq!(shared1, shared2);
        }

        // Test signature operations - ML-DSA requires feature flag
        let sig_result = provider
            .signature()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65, None);
        #[cfg(feature = "ml-dsa")]
        {
            // Core provider should return NotImplemented for ML-DSA operations
            // The actual ML-DSA implementation is provided by the main lib-q crate
            assert!(sig_result.is_err());
            if let Err(Error::NotImplemented { feature }) = sig_result {
                assert!(
                    feature.contains("ML-DSA implementations are provided by the main lib-q crate")
                );
            } else {
                panic!("Expected NotImplemented error for ML-DSA in core provider");
            }
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
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        for (i, byte) in nonce_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
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
        // `LibQCryptoProvider::new()` uses `LibQAeadStubProvider` for AEAD; use `libq::aead::context()` or
        // `lib_q_aead::LibQAeadProvider` for registry-backed AEAD.
        assert!(aead_result.is_err());
        match aead_result {
            Err(Error::NotImplemented { feature }) => {
                assert!(
                    feature.contains("LibQAeadProvider") || feature.contains("libq::aead::context")
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

    #[cfg(feature = "alloc")]
    #[test]
    fn test_create_hash_context_sha3_256_roundtrip() {
        let mut ctx = create_hash_context();
        let out = ctx
            .hash(Algorithm::Sha3_256, b"lib-q umbrella hash")
            .expect("SHA3-256 with pre-wired LibQHashProvider");
        assert_eq!(out.len(), 32);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_create_aead_context_shake256_roundtrip() {
        use lib_q_core::traits::{
            AeadKey,
            Nonce,
        };

        let mut key_bytes = vec![0u8; 32];
        let mut nonce_bytes = vec![0u8; 16];
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x1F).wrapping_add(0x2B);
        }
        for (i, byte) in nonce_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x3D).wrapping_add(0x7E);
        }

        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let plaintext = b"hello lib-q aead bridge";
        let ad = b"associated data";

        let mut ctx = aead::context();
        let ciphertext = ctx
            .encrypt(
                Algorithm::Shake256Aead,
                &key,
                &nonce,
                plaintext.as_slice(),
                Some(ad.as_slice()),
            )
            .expect("SHAKE256-AEAD encrypt");

        let recovered = ctx
            .decrypt(
                Algorithm::Shake256Aead,
                &key,
                &nonce,
                &ciphertext,
                Some(ad.as_slice()),
            )
            .expect("SHAKE256-AEAD decrypt");

        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[cfg(all(feature = "alloc", feature = "duplex-sponge-aead"))]
    #[test]
    fn test_create_aead_context_duplex_sponge_roundtrip() {
        use lib_q_core::traits::{
            AeadKey,
            Nonce,
        };

        let mut key_bytes = vec![0u8; 32];
        let mut nonce_bytes = vec![0u8; 16];
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x11).wrapping_add(0x3C);
        }
        for (i, byte) in nonce_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x29).wrapping_add(0x71);
        }

        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let plaintext = b"duplex-sponge roundtrip";
        let ad = b"ad";

        let mut ctx = aead::context();
        let ciphertext = ctx
            .encrypt(
                Algorithm::DuplexSpongeAead,
                &key,
                &nonce,
                plaintext.as_slice(),
                Some(ad.as_slice()),
            )
            .expect("Duplex-Sponge-AEAD encrypt");

        let recovered = ctx
            .decrypt(
                Algorithm::DuplexSpongeAead,
                &key,
                &nonce,
                &ciphertext,
                Some(ad.as_slice()),
            )
            .expect("Duplex-Sponge-AEAD decrypt");

        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[cfg(all(feature = "alloc", feature = "tweak-aead"))]
    #[test]
    fn test_create_aead_context_tweak_aead_roundtrip() {
        use lib_q_core::traits::{
            AeadKey,
            Nonce,
        };

        let mut key_bytes = vec![0u8; 32];
        let mut nonce_bytes = vec![0u8; 16];
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x13).wrapping_add(0x2E);
        }
        for (i, byte) in nonce_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x2B).wrapping_add(0x6D);
        }

        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let plaintext = b"tweak aead roundtrip";
        let ad = b"ad2";

        let mut ctx = aead::context();
        let ciphertext = ctx
            .encrypt(
                Algorithm::TweakAead,
                &key,
                &nonce,
                plaintext.as_slice(),
                Some(ad.as_slice()),
            )
            .expect("Tweak-AEAD encrypt");

        let recovered = ctx
            .decrypt(
                Algorithm::TweakAead,
                &key,
                &nonce,
                &ciphertext,
                Some(ad.as_slice()),
            )
            .expect("Tweak-AEAD decrypt");

        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[cfg(all(feature = "alloc", feature = "romulus"))]
    #[test]
    fn test_create_aead_context_romulus_n_roundtrip() {
        use lib_q_core::traits::{
            AeadKey,
            Nonce,
        };

        let mut key_bytes = vec![0u8; 16];
        let mut nonce_bytes = vec![0u8; 16];
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x17).wrapping_add(0x31);
        }
        for (i, byte) in nonce_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x2Du8).wrapping_add(0x6Au8);
        }

        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let plaintext = b"romulus-n roundtrip";
        let ad = b"ad-rn";

        let mut ctx = aead::context();
        let ciphertext = ctx
            .encrypt(
                Algorithm::RomulusN,
                &key,
                &nonce,
                plaintext.as_slice(),
                Some(ad.as_slice()),
            )
            .expect("Romulus-N encrypt");

        let recovered = ctx
            .decrypt(
                Algorithm::RomulusN,
                &key,
                &nonce,
                &ciphertext,
                Some(ad.as_slice()),
            )
            .expect("Romulus-N decrypt");

        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[cfg(all(feature = "alloc", feature = "romulus"))]
    #[test]
    fn test_create_aead_context_romulus_m_roundtrip() {
        use lib_q_core::traits::{
            AeadKey,
            Nonce,
        };

        let mut key_bytes = vec![0u8; 16];
        let mut nonce_bytes = vec![0u8; 16];
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x19).wrapping_add(0x2Fu8);
        }
        for (i, byte) in nonce_bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x2Fu8).wrapping_add(0x68u8);
        }

        let key = AeadKey::new(key_bytes);
        let nonce = Nonce::new(nonce_bytes);
        let plaintext = b"romulus-m roundtrip";
        let ad = b"ad-rm";

        let mut ctx = aead::context();
        let ciphertext = ctx
            .encrypt(
                Algorithm::RomulusM,
                &key,
                &nonce,
                plaintext.as_slice(),
                Some(ad.as_slice()),
            )
            .expect("Romulus-M encrypt");

        let recovered = ctx
            .decrypt(
                Algorithm::RomulusM,
                &key,
                &nonce,
                &ciphertext,
                Some(ad.as_slice()),
            )
            .expect("Romulus-M decrypt");

        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }
}
