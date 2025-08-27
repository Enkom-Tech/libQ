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
//!     // Hash data (multiple hash algorithms available)
//!     let hash = hash_ctx.hash(Algorithm::Shake256, b"Hello, World!")?;
//!     println!("Hash: {}", Utils::bytes_to_hex(&hash));
//!
//!     // Generate random bytes
//!     let random_bytes = Utils::random_bytes(32)?;
//!     println!("Random bytes: {}", Utils::bytes_to_hex(&random_bytes));
//!
//!     // Note: Signature and KEM operations require feature flags:
//!     // - For ML-DSA signatures: enable 'ml-dsa' feature
//!     // - For ML-KEM key exchange: enable 'ml-kem' feature
//!     // Example with features enabled:
//!     // let mut sig_ctx = create_signature_context();
//!     // let sig_keypair = sig_ctx.generate_keypair(Algorithm::MlDsa65)?;
//!
//!     Ok(())
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![deny(unused_qualifications)]

#[cfg(feature = "std")]
extern crate std;

// Re-export core API - provides the unified interface (Algorithm, Context structs, Utils)
// Re-export specific items from individual crates to provide unified access
// This creates a single entry point for the entire library, eliminating the need
// for users to import from multiple crates. The main API is in lib_q_core::*,
// these are additional convenience exports.
pub use lib_q_aead::{
    Aead,
    AeadKey,
    Nonce,
    create_aead,
};
pub use lib_q_core::{
    Kem,
    KemKeypair,
    KemPublicKey,
    KemSecretKey,
    *,
};
pub use lib_q_hash::{
    Hash,
    create_hash,
};
// HPKE support (post-quantum only)
#[cfg(feature = "hpke")]
pub use lib_q_hpke::*;
pub use lib_q_kem::create_kem;
pub use lib_q_ml_dsa::types::*;
#[cfg(feature = "std")]
pub use lib_q_sig::create_signature;
pub use lib_q_sig::{
    SigKeypair,
    SigPublicKey,
    SigSecretKey,
    Signature,
};
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

#[cfg(feature = "std")]
pub struct LibQCryptoProvider;

#[cfg(feature = "std")]
impl LibQCryptoProvider {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "std")]
impl Default for LibQCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl CryptoProvider for LibQCryptoProvider {
    fn kem(&self) -> Option<&dyn KemOperations> {
        Some(&RealKemImpl)
    }

    fn signature(&self) -> Option<&dyn SignatureOperations> {
        Some(&RealSignatureImpl)
    }

    fn hash(&self) -> Option<&dyn HashOperations> {
        Some(&RealHashImpl)
    }
}

// Real implementations that delegate to actual crypto crates
#[cfg(feature = "std")]
struct RealKemImpl;

#[cfg(feature = "std")]
impl KemOperations for RealKemImpl {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        _randomness: Option<&[u8]>,
    ) -> Result<KemKeypair> {
        match algorithm {
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                let kem = create_kem(algorithm)?;
                kem.generate_keypair()
            }
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: "ML-KEM support requires 'ml-kem' feature flag".to_string(),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported",
            }),
        }
    }

    fn encapsulate(
        &self,
        algorithm: Algorithm,
        _public_key: &KemPublicKey,
        _randomness: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match algorithm {
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                let kem = create_kem(algorithm)?;
                kem.encapsulate(_public_key)
            }
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: "ML-KEM support requires 'ml-kem' feature flag".to_string(),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported",
            }),
        }
    }

    fn decapsulate(
        &self,
        algorithm: Algorithm,
        _secret_key: &KemSecretKey,
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        match algorithm {
            #[cfg(feature = "ml-kem")]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                let kem = create_kem(algorithm)?;
                kem.decapsulate(_secret_key, _ciphertext)
            }
            #[cfg(not(feature = "ml-kem"))]
            Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
                Err(Error::NotImplemented {
                    feature: "ML-KEM support requires 'ml-kem' feature flag".to_string(),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported",
            }),
        }
    }
}

#[cfg(feature = "std")]
struct RealSignatureImpl;

#[cfg(feature = "std")]
impl SignatureOperations for RealSignatureImpl {
    fn generate_keypair(
        &self,
        algorithm: Algorithm,
        _randomness: Option<&[u8]>,
    ) -> Result<SigKeypair> {
        match algorithm {
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa44 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_44();
                ml_dsa.generate_keypair()
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa65 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_65();
                ml_dsa.generate_keypair()
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa87 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_87();
                ml_dsa.generate_keypair()
            }
            #[cfg(not(feature = "ml-dsa"))]
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(Error::NotImplemented {
                    feature: "ML-DSA support requires 'ml-dsa' feature flag".to_string(),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported",
            }),
        }
    }

    fn sign(
        &self,
        algorithm: Algorithm,
        _secret_key: &SigSecretKey,
        _message: &[u8],
        _randomness: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        match algorithm {
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa44 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_44();
                ml_dsa.sign(_secret_key, _message)
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa65 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_65();
                ml_dsa.sign(_secret_key, _message)
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa87 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_87();
                ml_dsa.sign(_secret_key, _message)
            }
            #[cfg(not(feature = "ml-dsa"))]
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(Error::NotImplemented {
                    feature: "ML-DSA support requires 'ml-dsa' feature flag".to_string(),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported",
            }),
        }
    }

    fn verify(
        &self,
        algorithm: Algorithm,
        _public_key: &SigPublicKey,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool> {
        match algorithm {
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa44 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_44();
                ml_dsa.verify(_public_key, _message, _signature)
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa65 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_65();
                ml_dsa.verify(_public_key, _message, _signature)
            }
            #[cfg(feature = "ml-dsa")]
            Algorithm::MlDsa87 => {
                let ml_dsa = lib_q_sig::ml_dsa::MlDsa::ml_dsa_87();
                ml_dsa.verify(_public_key, _message, _signature)
            }
            #[cfg(not(feature = "ml-dsa"))]
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(Error::NotImplemented {
                    feature: "ML-DSA support requires 'ml-dsa' feature flag".to_string(),
                })
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm not supported",
            }),
        }
    }
}

#[cfg(feature = "std")]
struct RealHashImpl;

#[cfg(feature = "std")]
impl HashOperations for RealHashImpl {
    fn hash(&self, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>> {
        // Use the hash wrapper types that implement the lib-q-core Hash trait
        match algorithm {
            Algorithm::Sha3_224 => {
                let hasher = lib_q_hash::Sha3_224Hash::new();
                hasher.hash(data)
            }
            Algorithm::Sha3_256 => {
                let hasher = lib_q_hash::Sha3_256Hash::new();
                hasher.hash(data)
            }
            Algorithm::Sha3_384 => {
                let hasher = lib_q_hash::Sha3_384Hash::new();
                hasher.hash(data)
            }
            Algorithm::Sha3_512 => {
                let hasher = lib_q_hash::Sha3_512Hash::new();
                hasher.hash(data)
            }
            Algorithm::Shake128 => {
                let hasher = lib_q_hash::Shake128Hash::new();
                hasher.hash(data)
            }
            Algorithm::Shake256 => {
                let hasher = lib_q_hash::Shake256Hash::new();
                hasher.hash(data)
            }
            Algorithm::CShake128 => {
                let hasher = lib_q_hash::CShake128Hash::new();
                hasher.hash(data)
            }
            Algorithm::CShake256 => {
                let hasher = lib_q_hash::CShake256Hash::new();
                hasher.hash(data)
            }
            Algorithm::Kmac128 => {
                let hasher = lib_q_hash::Kmac128Hash::new();
                hasher.hash(data)
            }
            Algorithm::Kmac256 => {
                let hasher = lib_q_hash::Kmac256Hash::new();
                hasher.hash(data)
            }
            Algorithm::TupleHash128 => {
                let hasher = lib_q_hash::TupleHash128Hash::new();
                hasher.hash(data)
            }
            Algorithm::TupleHash256 => {
                let hasher = lib_q_hash::TupleHash256Hash::new();
                hasher.hash(data)
            }
            Algorithm::ParallelHash128 => {
                let hasher = lib_q_hash::ParallelHash128Hash::new();
                hasher.hash(data)
            }
            Algorithm::ParallelHash256 => {
                let hasher = lib_q_hash::ParallelHash256Hash::new();
                hasher.hash(data)
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Hash algorithm not supported",
            }),
        }
    }
}

// Convenience functions for users
#[cfg(feature = "std")]
pub fn create_kem_context() -> KemContext {
    KemContext::with_provider(Box::new(LibQCryptoProvider::new()))
}

#[cfg(feature = "std")]
pub fn create_signature_context() -> SignatureContext {
    SignatureContext::with_provider(Box::new(LibQCryptoProvider::new()))
}

#[cfg(feature = "std")]
pub fn create_hash_context() -> HashContext {
    HashContext::with_provider(Box::new(LibQCryptoProvider::new()))
}

/// Create a new HPKE context with default provider
#[cfg(all(feature = "std", feature = "hpke"))]
pub fn create_hpke_context() -> HpkeContext {
    lib_q_hpke::create_hpke_context()
}

/// Get all supported algorithms
pub fn supported_algorithms() -> Vec<Algorithm> {
    algorithm_registry::supported_algorithms()
}

/// Get algorithms by category
pub fn algorithms_by_category(category: AlgorithmCategory) -> Vec<Algorithm> {
    algorithm_registry::algorithms_by_category(category)
}

/// Get algorithms by security level
pub fn algorithms_by_security_level(level: u32) -> Vec<Algorithm> {
    algorithm_registry::algorithms_by_security_level(level)
}

// WASM API Module - Provides identical interface for WASM
#[cfg(feature = "wasm")]
pub mod wasm {
    use std::result::Result as StdResult;

    use js_sys::{
        Array,
        Object,
        Uint8Array,
    };
    use wasm_bindgen::prelude::*;
    use web_sys::console;

    use super::*;

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
                kem_context: KemContext::with_provider(Box::new(LibQCryptoProvider::new())),
                sig_context: SignatureContext::with_provider(Box::new(LibQCryptoProvider::new())),
                hash_context: HashContext::with_provider(Box::new(LibQCryptoProvider::new())),
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

            match init() {
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
            version().to_string()
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
                Err(err) => {
                    let error_msg = match err {
                        Error::NotImplemented { feature } => {
                            format!("KEM not implemented: {}", feature)
                        }
                        Error::InvalidAlgorithm { algorithm: alg } => {
                            format!("Invalid KEM algorithm: {}", alg)
                        }
                        _ => "Failed to generate KEM keypair".to_string(),
                    };
                    Err(JsValue::from_str(&error_msg))
                }
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
                "mldsa44" => Algorithm::MlDsa44,
                "mldsa65" => Algorithm::MlDsa65,
                "mldsa87" => Algorithm::MlDsa87,
                _ => return Err(JsValue::from_str("Unsupported signature algorithm")),
            };

            match self.sig_context.generate_keypair(algorithm) {
                Ok(keypair) => {
                    let public_key = Uint8Array::from(keypair.public_key().as_bytes());
                    let secret_key = Uint8Array::from(keypair.secret_key().as_bytes());
                    Ok(SigKeyPairWasm::new(public_key, secret_key))
                }
                Err(err) => {
                    let error_msg = match err {
                        Error::NotImplemented { feature } => {
                            format!("Signature not implemented: {}", feature)
                        }
                        Error::InvalidAlgorithm { algorithm: alg } => {
                            format!("Invalid signature algorithm: {}", alg)
                        }
                        _ => "Failed to generate signature keypair".to_string(),
                    };
                    Err(JsValue::from_str(&error_msg))
                }
            }
        }

        /// Encapsulate a shared secret using KEM
        pub fn kem_encapsulate(
            &mut self,
            algorithm: &str,
            public_key: &Uint8Array,
        ) -> StdResult<Object, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let algorithm = match algorithm {
                "mlkem512" => Algorithm::MlKem512,
                "mlkem768" => Algorithm::MlKem768,
                "mlkem1024" => Algorithm::MlKem1024,
                _ => return Err(JsValue::from_str("Unsupported KEM algorithm")),
            };

            let public_key_vec: Vec<u8> = public_key.to_vec();
            let public_key = KemPublicKey::new(public_key_vec);

            match self.kem_context.encapsulate(algorithm, &public_key) {
                Ok((ciphertext, shared_secret)) => {
                    let result = Object::new();
                    let _ = js_sys::Reflect::set(
                        &result,
                        &"ciphertext".into(),
                        &Uint8Array::from(&ciphertext[..]),
                    );
                    let _ = js_sys::Reflect::set(
                        &result,
                        &"sharedSecret".into(),
                        &Uint8Array::from(&shared_secret[..]),
                    );
                    Ok(result)
                }
                Err(_) => Err(JsValue::from_str("Failed to encapsulate")),
            }
        }

        /// Decapsulate a shared secret using KEM
        pub fn kem_decapsulate(
            &mut self,
            algorithm: &str,
            secret_key: &Uint8Array,
            ciphertext: &Uint8Array,
        ) -> StdResult<Uint8Array, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let algorithm = match algorithm {
                "mlkem512" => Algorithm::MlKem512,
                "mlkem768" => Algorithm::MlKem768,
                "mlkem1024" => Algorithm::MlKem1024,
                _ => return Err(JsValue::from_str("Unsupported KEM algorithm")),
            };

            let secret_key_vec: Vec<u8> = secret_key.to_vec();
            let ciphertext_vec: Vec<u8> = ciphertext.to_vec();

            let secret_key = KemSecretKey::new(secret_key_vec);

            match self
                .kem_context
                .decapsulate(algorithm, &secret_key, &ciphertext_vec)
            {
                Ok(shared_secret) => Ok(Uint8Array::from(&shared_secret[..])),
                Err(_) => Err(JsValue::from_str("Failed to decapsulate")),
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
                "sha3-224" => Algorithm::Sha3_224,
                "sha3-256" => Algorithm::Sha3_256,
                "sha3-384" => Algorithm::Sha3_384,
                "sha3-512" => Algorithm::Sha3_512,
                "shake128" => Algorithm::Shake128,
                "shake256" => Algorithm::Shake256,
                "cshake128" => Algorithm::CShake128,
                "cshake256" => Algorithm::CShake256,
                "kmac128" => Algorithm::Kmac128,
                "kmac256" => Algorithm::Kmac256,
                "tuplehash128" => Algorithm::TupleHash128,
                "tuplehash256" => Algorithm::TupleHash256,
                "parallelhash128" => Algorithm::ParallelHash128,
                "parallelhash256" => Algorithm::ParallelHash256,
                _ => return Err(JsValue::from_str("Unsupported hash algorithm")),
            };

            let data_vec: Vec<u8> = data.to_vec();
            match self.hash_context.hash(algorithm, &data_vec) {
                Ok(hash) => {
                    let hash_array = Uint8Array::from(&hash[..]);
                    Ok(HashResultWasm::new(hash_array, format!("{algorithm:?}")))
                }
                Err(err) => {
                    let error_msg = match err {
                        Error::NotImplemented { feature } => {
                            format!("Hash not implemented: {}", feature)
                        }
                        Error::InvalidAlgorithm { algorithm: alg } => {
                            format!("Invalid hash algorithm: {}", alg)
                        }
                        _ => "Failed to hash data".to_string(),
                    };
                    Err(JsValue::from_str(&error_msg))
                }
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

        /// Sign data with a signature key
        pub fn sig_sign(
            &mut self,
            algorithm: &str,
            secret_key: &Uint8Array,
            message: &Uint8Array,
        ) -> StdResult<Uint8Array, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let algorithm = match algorithm {
                "mldsa44" => Algorithm::MlDsa44,
                "mldsa65" => Algorithm::MlDsa65,
                "mldsa87" => Algorithm::MlDsa87,
                _ => return Err(JsValue::from_str("Unsupported signature algorithm")),
            };

            let secret_key_vec: Vec<u8> = secret_key.to_vec();
            let message_vec: Vec<u8> = message.to_vec();

            let secret_key = SigSecretKey::new(secret_key_vec);

            match self.sig_context.sign(algorithm, &secret_key, &message_vec) {
                Ok(signature) => Ok(Uint8Array::from(&signature[..])),
                Err(err) => {
                    let error_msg = match err {
                        Error::NotImplemented { feature } => {
                            format!("Signature not implemented: {}", feature)
                        }
                        Error::InvalidAlgorithm { algorithm: alg } => {
                            format!("Invalid signature algorithm: {}", alg)
                        }
                        Error::InvalidKeySize { expected, actual } => {
                            format!("Invalid key size: expected {}, got {}", expected, actual)
                        }
                        _ => "Failed to sign message".to_string(),
                    };
                    Err(JsValue::from_str(&error_msg))
                }
            }
        }

        /// Verify signature
        pub fn sig_verify(
            &mut self,
            algorithm: &str,
            public_key: &Uint8Array,
            message: &Uint8Array,
            signature: &Uint8Array,
        ) -> StdResult<bool, JsValue> {
            if !self.initialized {
                return Err(JsValue::from_str("Library not initialized"));
            }

            let algorithm = match algorithm {
                "mldsa44" => Algorithm::MlDsa44,
                "mldsa65" => Algorithm::MlDsa65,
                "mldsa87" => Algorithm::MlDsa87,
                _ => return Err(JsValue::from_str("Unsupported signature algorithm")),
            };

            let public_key_vec: Vec<u8> = public_key.to_vec();
            let message_vec: Vec<u8> = message.to_vec();
            let signature_vec: Vec<u8> = signature.to_vec();

            let public_key = SigPublicKey::new(public_key_vec);

            match self
                .sig_context
                .verify(algorithm, &public_key, &message_vec, &signature_vec)
            {
                Ok(is_valid) => Ok(is_valid),
                Err(err) => {
                    let error_msg = match err {
                        Error::NotImplemented { feature } => {
                            format!("Signature verification not implemented: {}", feature)
                        }
                        Error::InvalidAlgorithm { algorithm: alg } => {
                            format!("Invalid signature algorithm: {}", alg)
                        }
                        Error::InvalidKeySize { expected, actual } => {
                            format!("Invalid key size: expected {}, got {}", expected, actual)
                        }
                        _ => "Failed to verify signature".to_string(),
                    };
                    Err(JsValue::from_str(&error_msg))
                }
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
                let alg_name = match alg {
                    Algorithm::MlDsa44 => "mldsa44",
                    Algorithm::MlDsa65 => "mldsa65",
                    Algorithm::MlDsa87 => "mldsa87",
                    _ => &format!("{alg:?}").to_lowercase(),
                };
                sig_algorithms.push(&alg_name.into());
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
        version().to_string()
    }

    #[wasm_bindgen]
    pub fn libq_init_standalone() -> StdResult<(), JsValue> {
        match init() {
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
        // Test that the unified API works correctly with providers
        let mut kem_ctx = create_kem_context();
        let mut sig_ctx = create_signature_context();
        let mut hash_ctx = create_hash_context();

        // Test KEM operations - ML-KEM implementation integrated with feature flag
        let kem_result = kem_ctx.generate_keypair(Algorithm::MlKem512);
        #[cfg(feature = "ml-kem")]
        {
            assert!(
                kem_result.is_ok(),
                "KEM should succeed with ml-kem feature enabled"
            );
            let keypair = kem_result.unwrap();
            assert!(!keypair.public_key().as_bytes().is_empty());
            assert!(!keypair.secret_key().as_bytes().is_empty());
        }
        #[cfg(not(feature = "ml-kem"))]
        {
            assert!(kem_result.is_err());
            if let Err(Error::NotImplemented { feature }) = kem_result {
                assert!(feature.contains("ML-KEM support requires 'ml-kem' feature flag"));
            } else {
                panic!("Expected NotImplemented error for KEM without feature flag");
            }
        }

        // Test signature operations - ML-DSA requires feature flag
        let sig_result = sig_ctx.generate_keypair(Algorithm::MlDsa65);
        #[cfg(feature = "ml-dsa")]
        {
            assert!(
                sig_result.is_ok(),
                "ML-DSA key generation should succeed with provider and ml-dsa feature"
            );
            let sig_keypair = sig_result.unwrap();
            assert!(!sig_keypair.public_key().as_bytes().is_empty());
            assert!(!sig_keypair.secret_key().as_bytes().is_empty());

            // Test signing and verification
            let message = b"Hello, ML-DSA!";
            let sig_result = sig_ctx.sign(Algorithm::MlDsa65, sig_keypair.secret_key(), message);
            assert!(
                sig_result.is_ok(),
                "ML-DSA signing should succeed with provider and ml-dsa feature"
            );
            let signature = sig_result.unwrap();

            let verify_result = sig_ctx.verify(
                Algorithm::MlDsa65,
                sig_keypair.public_key(),
                message,
                &signature,
            );
            assert!(
                verify_result.is_ok(),
                "ML-DSA verification should succeed with provider and ml-dsa feature"
            );
            assert!(verify_result.unwrap(), "Signature should be valid");
        }
        #[cfg(not(feature = "ml-dsa"))]
        {
            assert!(sig_result.is_err());
            if let Err(Error::NotImplemented { feature }) = sig_result {
                assert!(feature.contains("ML-DSA support requires 'ml-dsa' feature flag"));
            } else {
                panic!("Expected NotImplemented error for ML-DSA without feature flag");
            }
        }

        // Test hash operations - should work with provider
        let hash_result = hash_ctx.hash(Algorithm::Shake256, b"test");
        assert!(
            hash_result.is_ok(),
            "Hash operation should succeed with provider"
        );
        let hash = hash_result.unwrap();
        assert!(!hash.is_empty(), "Hash output should not be empty");

        // Test a different hash algorithm
        let sha3_result = hash_ctx.hash(Algorithm::Sha3_256, b"test");
        assert!(sha3_result.is_ok(), "SHA3-256 should succeed with provider");
        let sha3_hash = sha3_result.unwrap();
        assert!(!sha3_hash.is_empty(), "SHA3-256 output should not be empty");

        // Test utility functions - these should work without providers
        let random_bytes = Utils::random_bytes(32).unwrap();
        assert_eq!(random_bytes.len(), 32);

        let hex = Utils::bytes_to_hex(&[0x01, 0x23, 0x45, 0x67]);
        assert_eq!(hex, "01234567");

        let decoded = Utils::hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, vec![0x01, 0x23, 0x45, 0x67]);
    }
}
