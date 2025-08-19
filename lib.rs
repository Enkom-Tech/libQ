//! lib-Q - Post-Quantum Cryptography Library
//!
//! A modern, secure cryptography library built exclusively with NIST-approved
//! post-quantum algorithms. Written in Rust with WASM compilation support.
//!
//! # Features
//!
//! - **Unified API**: Same interface for Rust crate and WASM usage
//! - **Type Safety**: Strong type system prevents misuse
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **Constant-Time**: Operations designed to prevent timing attacks
//! - **Post-Quantum**: NIST-approved algorithms for quantum resistance
//!
//! # Example Usage
//!
//! ```rust
//! use libq::{KemContext, SignatureContext, HashContext, Algorithm, Utils};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize contexts
//!     let mut kem_ctx = KemContext::new();
//!     let mut sig_ctx = SignatureContext::new();
//!     let mut hash_ctx = HashContext::new();
//!
//!     // Generate KEM keypair
//!     let kem_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512)?;
//!
//!     // Generate signature keypair
//!     let sig_keypair = sig_ctx.generate_keypair(Algorithm::Dilithium2)?;
//!
//!     // Hash data
//!     let hash = hash_ctx.hash(Algorithm::Shake256, b"Hello, World!")?;
//!
//!     // Generate random bytes
//!     let random_bytes = Utils::random_bytes(32)?;
//!
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

// Re-export core API - provides the unified interface (Algorithm, Context structs, Utils)
pub use lib_q_core::*;

// Re-export specific items from individual crates to provide unified access
// This creates a single entry point for the entire library, eliminating the need
// for users to import from multiple crates. The main API is in lib_q_core::*,
// these are additional convenience exports.
pub use lib_q_aead::{Aead, AeadKey, Nonce, create_aead};
pub use lib_q_core::{Kem, KemKeypair, KemPublicKey, KemSecretKey};
pub use lib_q_hash::{Hash, create_hash};
pub use lib_q_kem::create_kem;
pub use lib_q_sig::{SigKeypair, SigPublicKey, SigSecretKey, Signature, create_signature};
pub use lib_q_zkp::create_zkp;

// Constants
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the library
pub fn init() -> Result<()> {
    lib_q_core::init()
}

/// Get library version information
pub fn version() -> &'static str {
    VERSION
}

/// Get all supported algorithms
pub fn supported_algorithms() -> Vec<Algorithm> {
    lib_q_core::algorithm_registry::supported_algorithms()
}

/// Get algorithms by category
pub fn algorithms_by_category(category: AlgorithmCategory) -> Vec<Algorithm> {
    lib_q_core::algorithm_registry::algorithms_by_category(category)
}

/// Get algorithms by security level
pub fn algorithms_by_security_level(level: u32) -> Vec<Algorithm> {
    lib_q_core::algorithm_registry::algorithms_by_security_level(level)
}

// WASM API Module - Provides identical interface for WASM
#[cfg(feature = "wasm")]
pub mod wasm {
    use super::*;
    use js_sys::{Array, Object, Uint8Array};
    use std::result::Result as StdResult;
    use wasm_bindgen::prelude::*;
    use web_sys::console;

    /// WASM-compatible key pair for KEM operations
    #[wasm_bindgen]
    pub struct KemKeyPairWasm {
        public_key: Uint8Array,
        secret_key: Uint8Array,
    }

    #[wasm_bindgen]
    impl KemKeyPairWasm {
        #[wasm_bindgen(constructor)]
        pub fn new(public_key: Uint8Array, secret_key: Uint8Array) -> Self {
            Self {
                public_key,
                secret_key,
            }
        }

        #[wasm_bindgen(getter)]
        pub fn public_key(&self) -> Uint8Array {
            self.public_key.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn secret_key(&self) -> Uint8Array {
            self.secret_key.clone()
        }
    }

    /// WASM-compatible key pair for signature operations
    #[wasm_bindgen]
    pub struct SigKeyPairWasm {
        public_key: Uint8Array,
        secret_key: Uint8Array,
    }

    #[wasm_bindgen]
    impl SigKeyPairWasm {
        #[wasm_bindgen(constructor)]
        pub fn new(public_key: Uint8Array, secret_key: Uint8Array) -> Self {
            Self {
                public_key,
                secret_key,
            }
        }

        #[wasm_bindgen(getter)]
        pub fn public_key(&self) -> Uint8Array {
            self.public_key.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn secret_key(&self) -> Uint8Array {
            self.secret_key.clone()
        }
    }

    /// WASM-compatible hash result
    #[wasm_bindgen]
    pub struct HashResultWasm {
        hash: Uint8Array,
        algorithm: String,
    }

    #[wasm_bindgen]
    impl HashResultWasm {
        #[wasm_bindgen(constructor)]
        pub fn new(hash: Uint8Array, algorithm: String) -> Self {
            Self { hash, algorithm }
        }

        #[wasm_bindgen(getter)]
        pub fn hash(&self) -> Uint8Array {
            self.hash.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn algorithm(&self) -> String {
            self.algorithm.clone()
        }
    }

    /// Main WASM API for lib-Q
    #[wasm_bindgen]
    pub struct LibQ {
        kem_context: KemContext,
        sig_context: SignatureContext,
        hash_context: HashContext,
        initialized: bool,
    }

    #[wasm_bindgen]
    impl LibQ {
        /// Create a new LibQ instance
        #[wasm_bindgen(constructor)]
        pub fn new() -> LibQ {
            let mut libq = LibQ {
                kem_context: KemContext::new(),
                sig_context: SignatureContext::new(),
                hash_context: HashContext::new(),
                initialized: false,
            };
            let _ = libq.init();
            libq
        }

        /// Initialize the library
        pub fn init(&mut self) -> StdResult<(), JsValue> {
            if self.initialized {
                return Ok(());
            }

            match super::init() {
                Ok(()) => {
                    self.initialized = true;
                    console::log_1(&"lib-Q initialized successfully".into());
                    Ok(())
                }
                Err(_) => Err(JsValue::from_str("Failed to initialize lib-Q")),
            }
        }

        /// Get library version
        pub fn version(&self) -> String {
            super::version().to_string()
        }

        /// Generate KEM keypair
        pub fn kem_generate_keypair(
            &mut self,
            algorithm: &str,
        ) -> StdResult<KemKeyPairWasm, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let algorithm = match algorithm {
                "mlkem512" => Algorithm::MlKem512,
                "mlkem768" => Algorithm::MlKem768,
                "mlkem1024" => Algorithm::MlKem1024,
                _ => return Err(JsValue::from_str("Unsupported KEM algorithm")),
            };

            match self.kem_context.generate_keypair(algorithm) {
                Ok(keypair) => {
                    let public_key = Uint8Array::from(keypair.public_key().as_bytes());
                    let secret_key = Uint8Array::from(keypair.secret_key().as_bytes());
                    Ok(KemKeyPairWasm::new(public_key, secret_key))
                }
                Err(_) => Err(JsValue::from_str("Failed to generate KEM keypair")),
            }
        }

        /// Generate signature keypair
        pub fn sig_generate_keypair(
            &mut self,
            algorithm: &str,
        ) -> StdResult<SigKeyPairWasm, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let algorithm = match algorithm {
                "dilithium2" => Algorithm::Dilithium2,
                "dilithium3" => Algorithm::Dilithium3,
                "dilithium5" => Algorithm::Dilithium5,
                _ => return Err(JsValue::from_str("Unsupported signature algorithm")),
            };

            match self.sig_context.generate_keypair(algorithm) {
                Ok(keypair) => {
                    let public_key = Uint8Array::from(keypair.public_key().as_bytes());
                    let secret_key = Uint8Array::from(keypair.secret_key().as_bytes());
                    Ok(SigKeyPairWasm::new(public_key, secret_key))
                }
                Err(_) => Err(JsValue::from_str("Failed to generate signature keypair")),
            }
        }

        /// Hash data
        pub fn hash(
            &mut self,
            algorithm: &str,
            data: &Uint8Array,
        ) -> StdResult<HashResultWasm, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let algorithm = match algorithm {
                "shake128" => Algorithm::Shake128,
                "shake256" => Algorithm::Shake256,
                "cshake128" => Algorithm::CShake128,
                "cshake256" => Algorithm::CShake256,
                _ => return Err(JsValue::from_str("Unsupported hash algorithm")),
            };

            let data_vec: Vec<u8> = data.to_vec();
            match self.hash_context.hash(algorithm, &data_vec) {
                Ok(hash) => {
                    let hash_array = Uint8Array::from(&hash[..]);
                    Ok(HashResultWasm::new(hash_array, format!("{algorithm:?}")))
                }
                Err(_) => Err(JsValue::from_str("Failed to hash data")),
            }
        }

        /// Generate random bytes
        pub fn random_bytes(&self, length: usize) -> StdResult<Uint8Array, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            match Utils::random_bytes(length) {
                Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
                Err(_) => Err(JsValue::from_str("Failed to generate random bytes")),
            }
        }

        /// Convert bytes to hex string
        pub fn bytes_to_hex(&self, bytes: &Uint8Array) -> String {
            let bytes_vec: Vec<u8> = bytes.to_vec();
            Utils::bytes_to_hex(&bytes_vec)
        }

        /// Convert hex string to bytes
        pub fn hex_to_bytes(&self, hex: &str) -> StdResult<Uint8Array, JsValue> {
            match Utils::hex_to_bytes(hex) {
                Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
                Err(_) => Err(JsValue::from_str("Failed to convert hex to bytes")),
            }
        }

        /// Get supported algorithms
        pub fn get_supported_algorithms(&self) -> Object {
            let algorithms = Object::new();

            // KEM algorithms
            let kem_algorithms = Array::new();
            for alg in algorithms_by_category(AlgorithmCategory::Kem) {
                kem_algorithms.push(&format!("{alg:?}").to_lowercase().into());
            }
            let _ = js_sys::Reflect::set(&algorithms, &"kem".into(), &kem_algorithms);

            // Signature algorithms
            let sig_algorithms = Array::new();
            for alg in algorithms_by_category(AlgorithmCategory::Signature) {
                sig_algorithms.push(&format!("{alg:?}").to_lowercase().into());
            }
            let _ = js_sys::Reflect::set(&algorithms, &"signature".into(), &sig_algorithms);

            // Hash algorithms
            let hash_algorithms = Array::new();
            for alg in algorithms_by_category(AlgorithmCategory::Hash) {
                hash_algorithms.push(&format!("{alg:?}").to_lowercase().into());
            }
            let _ = js_sys::Reflect::set(&algorithms, &"hash".into(), &hash_algorithms);

            // Security levels
            let security_levels = Array::new();
            security_levels.push(&1u32.into());
            security_levels.push(&3u32.into());
            security_levels.push(&4u32.into());
            security_levels.push(&5u32.into());
            let _ = js_sys::Reflect::set(&algorithms, &"securityLevels".into(), &security_levels);

            algorithms
        }
    }

    impl Default for LibQ {
        fn default() -> Self {
            Self::new()
        }
    }

    // Standalone functions for convenience
    #[wasm_bindgen]
    pub fn libq_version_standalone() -> String {
        super::version().to_string()
    }

    #[wasm_bindgen]
    pub fn libq_init_standalone() -> StdResult<(), JsValue> {
        match super::init() {
            Ok(()) => Ok(()),
            Err(_) => Err(JsValue::from_str("Failed to initialize lib-Q")),
        }
    }

    #[wasm_bindgen]
    pub fn libq_random_bytes_standalone(length: usize) -> StdResult<Uint8Array, JsValue> {
        match Utils::random_bytes(length) {
            Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
            Err(_) => Err(JsValue::from_str("Failed to generate random bytes")),
        }
    }

    #[wasm_bindgen]
    pub fn libq_bytes_to_hex_standalone(bytes: &Uint8Array) -> String {
        let bytes_vec: Vec<u8> = bytes.to_vec();
        Utils::bytes_to_hex(&bytes_vec)
    }

    #[wasm_bindgen]
    pub fn libq_hex_to_bytes_standalone(hex: &str) -> StdResult<Uint8Array, JsValue> {
        match Utils::hex_to_bytes(hex) {
            Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
            Err(_) => Err(JsValue::from_str("Failed to convert hex to bytes")),
        }
    }
}

#[cfg(test)]
mod tests {
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
        let algorithms = supported_algorithms();
        assert!(!algorithms.is_empty());

        // Check that we have algorithms from each category
        let kem_algs = algorithms_by_category(AlgorithmCategory::Kem);
        let sig_algs = algorithms_by_category(AlgorithmCategory::Signature);
        let hash_algs = algorithms_by_category(AlgorithmCategory::Hash);

        assert!(!kem_algs.is_empty());
        assert!(!sig_algs.is_empty());
        assert!(!hash_algs.is_empty());
    }

    #[test]
    fn test_algorithms_by_security_level() {
        let level_1 = algorithms_by_security_level(1);
        let level_3 = algorithms_by_security_level(3);
        let level_4 = algorithms_by_security_level(4);

        assert!(!level_1.is_empty());
        assert!(!level_3.is_empty());
        assert!(!level_4.is_empty());

        // Verify all algorithms have the correct security level
        for alg in level_1 {
            assert_eq!(alg.security_level(), 1);
        }
        for alg in level_3 {
            assert_eq!(alg.security_level(), 3);
        }
        for alg in level_4 {
            assert_eq!(alg.security_level(), 4);
        }
    }

    #[test]
    fn test_unified_api() {
        // Test that the unified API works consistently
        let mut kem_ctx = KemContext::new();
        let mut sig_ctx = SignatureContext::new();
        let mut hash_ctx = HashContext::new();

        // Test KEM operations
        let kem_keypair = kem_ctx.generate_keypair(Algorithm::MlKem512).unwrap();
        assert!(!kem_keypair.public_key().as_bytes().is_empty());
        assert!(!kem_keypair.secret_key().as_bytes().is_empty());

        // Test signature operations
        let sig_keypair = sig_ctx.generate_keypair(Algorithm::Dilithium2).unwrap();
        assert!(!sig_keypair.public_key().as_bytes().is_empty());
        assert!(!sig_keypair.secret_key().as_bytes().is_empty());

        // Test hash operations
        let hash = hash_ctx.hash(Algorithm::Shake256, b"test").unwrap();
        assert_eq!(hash.len(), 32);

        // Test utility functions
        let random_bytes = Utils::random_bytes(32).unwrap();
        assert_eq!(random_bytes.len(), 32);

        let hex = Utils::bytes_to_hex(&[0x01, 0x23, 0x45, 0x67]);
        assert_eq!(hex, "01234567");

        let decoded = Utils::hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, vec![0x01, 0x23, 0x45, 0x67]);
    }
}
