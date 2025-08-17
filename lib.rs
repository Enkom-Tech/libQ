//! lib-Q - Post-Quantum Cryptography Library
//!
//! A modern, secure cryptography library built exclusively with NIST-approved
//! post-quantum algorithms. Written in Rust with WASM compilation support.

#![cfg_attr(not(feature = "std"), no_std)]

// Re-export from individual crates
pub use lib_q_core::*;

// Re-export specific items to avoid conflicts
pub use lib_q_kem::{Kem, KemKeypair, KemPublicKey, KemSecretKey, create_kem};
pub use lib_q_sig::{Signature, SigKeypair, SigPublicKey, SigSecretKey, create_signature};
pub use lib_q_hash::{Hash, create_hash};
pub use lib_q_aead::{Aead, AeadKey, Nonce, create_aead};
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

    /// Main WASM API for lib-Q
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

        /// Generate random bytes
        pub fn random_bytes(&self, length: usize) -> StdResult<Uint8Array, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            // TODO: Implement using lib_q_utils
            Err(JsValue::from_str("Random bytes not implemented yet"))
        }

        /// Generate a random key
        pub fn random_key(&self, size: usize) -> StdResult<Uint8Array, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            // TODO: Implement using lib_q_utils
            Err(JsValue::from_str("Random key not implemented yet"))
        }

        /// Convert bytes to hex string
        pub fn bytes_to_hex(&self, bytes: &Uint8Array) -> String {
            // TODO: Implement using lib_q_utils
            "not implemented".to_string()
        }

        /// Convert hex string to bytes
        pub fn hex_to_bytes(&self, hex: &str) -> StdResult<Uint8Array, JsValue> {
            // TODO: Implement using lib_q_utils
            Err(JsValue::from_str("Hex conversion not implemented yet"))
        }

        /// Hash data using SHAKE256
        pub fn hash_shake256(&self, data: &Uint8Array) -> StdResult<HashResultWasm, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            // TODO: Implement using lib_q_hash
            Err(JsValue::from_str("SHAKE256 not implemented yet"))
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

            // TODO: Implement using lib_q_kem
            Err(JsValue::from_str("KEM key generation not implemented yet"))
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

            // TODO: Implement using lib_q_sig
            Err(JsValue::from_str("Signature key generation not implemented yet"))
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
            Err(_) => Err(JsValue::from_str("Failed to initialize lib-Q")),
        }
    }

    #[wasm_bindgen]
    pub fn libq_random_bytes_standalone(length: usize) -> StdResult<Uint8Array, JsValue> {
        // TODO: Implement using lib_q_utils
        Err(JsValue::from_str("Random bytes not implemented yet"))
    }

    #[wasm_bindgen]
    pub fn libq_bytes_to_hex_standalone(bytes: &Uint8Array) -> String {
        // TODO: Implement using lib_q_utils
        "not implemented".to_string()
    }

    #[wasm_bindgen]
    pub fn libq_hex_to_bytes_standalone(hex: &str) -> StdResult<Uint8Array, JsValue> {
        // TODO: Implement using lib_q_utils
        Err(JsValue::from_str("Hex conversion not implemented yet"))
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
