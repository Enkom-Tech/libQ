//! Common WASM patterns and utilities for lib-Q
//!
//! This module provides shared WASM structures and utilities to eliminate
//! code duplication across the library.

#[cfg(feature = "wasm")]
use js_sys::Uint8Array;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Common trait for WASM key pairs
#[cfg(feature = "wasm")]
pub trait WasmKeyPair {
    fn public_key(&self) -> Uint8Array;
    fn secret_key(&self) -> Uint8Array;
}

/// Generic WASM key pair implementation
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmKeyPairImpl {
    public_key: Uint8Array,
    secret_key: Uint8Array,
}

#[cfg(feature = "wasm")]
impl WasmKeyPairImpl {
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

#[cfg(feature = "wasm")]
impl WasmKeyPair for WasmKeyPairImpl {
    fn public_key(&self) -> Uint8Array {
        self.public_key.clone()
    }

    fn secret_key(&self) -> Uint8Array {
        self.secret_key.clone()
    }
}

/// WASM-compatible hash result
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct HashResultWasm {
    hash: Uint8Array,
    algorithm: String,
}

#[cfg(feature = "wasm")]
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

/// Utility functions for WASM conversions
#[cfg(feature = "wasm")]
pub mod conversions {
    use super::*;
    use js_sys::Uint8Array;

    /// Convert Rust Vec<u8> to WASM Uint8Array
    pub fn vec_to_uint8array(data: &[u8]) -> Uint8Array {
        let array = Uint8Array::new_with_length(data.len() as u32);
        array.copy_from(data);
        array
    }

    /// Convert WASM Uint8Array to Rust Vec<u8>
    pub fn uint8array_to_vec(array: &Uint8Array) -> Vec<u8> {
        let length = array.length() as usize;
        let mut vec = vec![0u8; length];
        array.copy_to(&mut vec);
        vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_common_structure() {
        // Test that the module compiles correctly
        // In a real WASM environment, these would be tested with wasm-bindgen-test
        assert!(true);
    }
}
