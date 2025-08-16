//! libQ - Post-Quantum Cryptography Library
//!
//! A modern, secure cryptography library built exclusively with NIST-approved
//! post-quantum algorithms. Written in Rust with WASM compilation support.

#![cfg_attr(not(feature = "std"), no_std)]

// Core modules
pub mod aead;
pub mod error;
pub mod hash;
pub mod kem;
pub mod sig;
pub mod utils;
pub mod zkp;

// Re-exports for convenience
pub use aead::{Aead, AeadKey, Nonce};
pub use error::{Error, Result};
pub use hash::{Hash, HashAlgorithm};
pub use kem::{Kem, KemKeypair, KemPublicKey, KemSecretKey};
pub use sig::{SigKeypair, SigPublicKey, SigSecretKey, Signature};

// Constants
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the library
pub fn init() -> Result<()> {
    Ok(())
}

/// Get library version information
pub fn version() -> &'static str {
    VERSION
}

// WASM API Module
#[cfg(feature = "wasm")]
pub mod wasm_api {
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

    /// Main WASM API for libQ
    #[wasm_bindgen]
    pub struct LibQ {
        initialized: bool,
    }

    #[wasm_bindgen]
    impl LibQ {
        /// Create a new LibQ instance
        #[wasm_bindgen(constructor)]
        pub fn new() -> LibQ {
            let mut libq = LibQ { initialized: false };
            let _ = libq.init();
            libq
        }
    }

    impl Default for LibQ {
        fn default() -> Self {
            Self::new()
        }
    }

    #[wasm_bindgen]
    impl LibQ {
        /// Initialize the library
        pub fn init(&mut self) -> StdResult<(), JsValue> {
            if self.initialized {
                return Ok(());
            }

            match super::init() {
                Ok(()) => {
                    self.initialized = true;
                    console::log_1(&"libQ initialized successfully".into());
                    Ok(())
                }
                Err(_) => Err(JsValue::from_str("Failed to initialize libQ")),
            }
        }

        /// Get library version
        pub fn version(&self) -> String {
            super::version().to_string()
        }

        /// Generate random bytes
        pub fn random_bytes(&self, length: usize) -> StdResult<Uint8Array, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            match utils::random_bytes(length) {
                Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
                Err(_) => Err(JsValue::from_str("Failed to generate random bytes")),
            }
        }

        /// Generate a random key
        pub fn random_key(&self, size: usize) -> StdResult<Uint8Array, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            match utils::random_key(size) {
                Ok(key) => Ok(Uint8Array::from(&key[..])),
                Err(_) => Err(JsValue::from_str("Failed to generate random key")),
            }
        }

        /// Convert bytes to hex string
        pub fn bytes_to_hex(&self, bytes: &Uint8Array) -> String {
            let bytes_vec: Vec<u8> = bytes.to_vec();
            utils::bytes_to_hex(&bytes_vec)
        }

        /// Convert hex string to bytes
        pub fn hex_to_bytes(&self, hex: &str) -> StdResult<Uint8Array, JsValue> {
            match utils::hex_to_bytes(hex) {
                Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
                Err(_) => Err(JsValue::from_str("Failed to convert hex to bytes")),
            }
        }

        /// Hash data using SHAKE256
        pub fn hash_shake256(&self, data: &Uint8Array) -> StdResult<HashResultWasm, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let data_vec: Vec<u8> = data.to_vec();
            let hash_impl = HashAlgorithm::Shake256.create_hash();
            match hash_impl.hash(&data_vec) {
                Ok(hash) => Ok(HashResultWasm::new(
                    Uint8Array::from(&hash[..]),
                    "SHAKE256".to_string(),
                )),
                Err(_) => Err(JsValue::from_str("Failed to hash data")),
            }
        }

        /// Generate KEM key pair (placeholder implementation)
        pub fn kem_generate_keypair(
            &self,
            algorithm: &str,
            security_level: u32,
        ) -> StdResult<KemKeyPairWasm, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            // Simple validation
            if ![1, 3, 4, 5].contains(&security_level) {
                return Err(JsValue::from_str("Invalid security level"));
            }

            // Placeholder implementation - will be replaced with actual algorithms
            let public_key_size = match algorithm {
                "kyber" => 800,
                "mceliece" => 261120,
                "hqc" => 2241,
                _ => return Err(JsValue::from_str("Unsupported algorithm")),
            };

            match utils::random_bytes(public_key_size) {
                Ok(public_key) => match utils::random_bytes(public_key_size) {
                    Ok(secret_key) => Ok(KemKeyPairWasm::new(
                        Uint8Array::from(&public_key[..]),
                        Uint8Array::from(&secret_key[..]),
                    )),
                    Err(_) => Err(JsValue::from_str("Failed to generate secret key")),
                },
                Err(_) => Err(JsValue::from_str("Failed to generate public key")),
            }
        }

        /// Generate signature key pair (placeholder implementation)
        pub fn sig_generate_keypair(
            &self,
            algorithm: &str,
            security_level: u32,
        ) -> StdResult<SigKeyPairWasm, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            // Simple validation
            if ![1, 3, 4, 5].contains(&security_level) {
                return Err(JsValue::from_str("Invalid security level"));
            }

            // Placeholder implementation - will be replaced with actual algorithms
            let public_key_size = match algorithm {
                "dilithium" => 1312,
                "falcon" => 897,
                "sphincs" => 32,
                _ => return Err(JsValue::from_str("Unsupported algorithm")),
            };

            match utils::random_bytes(public_key_size) {
                Ok(public_key) => match utils::random_bytes(public_key_size) {
                    Ok(secret_key) => Ok(SigKeyPairWasm::new(
                        Uint8Array::from(&public_key[..]),
                        Uint8Array::from(&secret_key[..]),
                    )),
                    Err(_) => Err(JsValue::from_str("Failed to generate secret key")),
                },
                Err(_) => Err(JsValue::from_str("Failed to generate public key")),
            }
        }

        /// Get supported algorithms
        pub fn get_supported_algorithms(&self) -> Object {
            let algorithms = Object::new();

            // KEM algorithms
            let kem_algorithms = Array::new();
            kem_algorithms.push(&"kyber".into());
            kem_algorithms.push(&"mceliece".into());
            kem_algorithms.push(&"hqc".into());
            let _ = js_sys::Reflect::set(&algorithms, &"kem".into(), &kem_algorithms);

            // Signature algorithms
            let sig_algorithms = Array::new();
            sig_algorithms.push(&"dilithium".into());
            sig_algorithms.push(&"falcon".into());
            sig_algorithms.push(&"sphincs".into());
            let _ = js_sys::Reflect::set(&algorithms, &"signature".into(), &sig_algorithms);

            // Hash algorithms
            let hash_algorithms = Array::new();
            hash_algorithms.push(&"shake256".into());
            hash_algorithms.push(&"shake128".into());
            hash_algorithms.push(&"cshake256".into());
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

    // Standalone functions for convenience
    #[wasm_bindgen]
    pub fn libq_version_standalone() -> String {
        super::version().to_string()
    }

    #[wasm_bindgen]
    pub fn libq_init_standalone() -> StdResult<(), JsValue> {
        match super::init() {
            Ok(()) => Ok(()),
            Err(_) => Err(JsValue::from_str("Failed to initialize libQ")),
        }
    }

    #[wasm_bindgen]
    pub fn libq_random_bytes_standalone(length: usize) -> StdResult<Uint8Array, JsValue> {
        match utils::random_bytes(length) {
            Ok(bytes) => Ok(Uint8Array::from(&bytes[..])),
            Err(_) => Err(JsValue::from_str("Failed to generate random bytes")),
        }
    }

    #[wasm_bindgen]
    pub fn libq_bytes_to_hex_standalone(bytes: &Uint8Array) -> String {
        let bytes_vec: Vec<u8> = bytes.to_vec();
        utils::bytes_to_hex(&bytes_vec)
    }

    #[wasm_bindgen]
    pub fn libq_hex_to_bytes_standalone(hex: &str) -> StdResult<Uint8Array, JsValue> {
        match utils::hex_to_bytes(hex) {
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
}
