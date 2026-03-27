//! WASM Example for FN-DSA
//!
//! This example demonstrates how to use FN-DSA in a WebAssembly environment.
//! It shows the complete workflow of key generation, signing, and verification
//! in a browser-compatible context.

#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::new_without_default)]
#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

use lib_q_core::Result;
use lib_q_fn_dsa::*;

/// WASM-compatible FN-DSA operations
pub struct WasmFnDsa {
    fn_dsa: FnDsa512,
}

impl WasmFnDsa {
    /// Create a new WASM-compatible FN-DSA instance
    pub fn new() -> Self {
        Self {
            fn_dsa: FnDsa512::new(),
        }
    }

    /// Generate a keypair for WASM environment
    pub fn generate_keypair(&self) -> Result<WasmKeypair> {
        let keypair = self.fn_dsa.generate_keypair()?;
        Ok(WasmKeypair {
            public_key: keypair.public_key.as_bytes().to_vec(),
            secret_key: keypair.secret_key.as_bytes().to_vec(),
        })
    }

    /// Sign a message in WASM environment
    pub fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let secret_key = lib_q_core::SigSecretKey::new(secret_key.to_vec());
        self.fn_dsa.sign(&secret_key, message)
    }

    /// Verify a signature in WASM environment
    pub fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let public_key = lib_q_core::SigPublicKey::new(public_key.to_vec());
        self.fn_dsa.verify(&public_key, message, signature)
    }

    /// Get key sizes for WASM environment
    pub fn get_key_sizes(&self) -> (usize, usize, usize) {
        self.fn_dsa.security_level().key_sizes()
    }
}

/// WASM-compatible keypair structure
#[derive(Debug, Clone)]
pub struct WasmKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl WasmKeypair {
    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the secret key as bytes
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

/// WASM-specific utility functions
pub mod wasm_utils {
    use super::*;

    /// Convert bytes to hex string for WASM
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut hex = String::new();
        for byte in bytes {
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    /// Convert hex string to bytes for WASM
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
        if hex.len() % 2 != 0 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 0,
                actual: hex.len(),
            });
        }

        let mut bytes = Vec::new();
        for chunk in hex.as_bytes().chunks(2) {
            let hex_str =
                core::str::from_utf8(chunk).map_err(|_| lib_q_core::Error::InvalidKeySize {
                    expected: 0,
                    actual: chunk.len(),
                })?;
            let byte =
                u8::from_str_radix(hex_str, 16).map_err(|_| lib_q_core::Error::InvalidKeySize {
                    expected: 0,
                    actual: chunk.len(),
                })?;
            bytes.push(byte);
        }
        Ok(bytes)
    }

    /// Create a WASM-compatible error message
    pub fn error_to_string(error: &lib_q_core::Error) -> String {
        match error {
            lib_q_core::Error::InvalidKeySize { expected, actual } => {
                format!("Invalid key size: expected {}, got {}", expected, actual)
            }
            lib_q_core::Error::InvalidSignatureSize { expected, actual } => {
                format!(
                    "Invalid signature size: expected {}, got {}",
                    expected, actual
                )
            }
            lib_q_core::Error::VerificationFailed { operation: _ } => {
                "Signature verification failed".to_string()
            }
            lib_q_core::Error::KeyGenerationFailed { operation: _ } => {
                "Key generation failed".to_string()
            }
            lib_q_core::Error::SigningFailed { operation: _ } => "Signing failed".to_string(),
            _ => "Unknown error".to_string(),
        }
    }
}

/// Example usage for WASM environment
#[cfg(target_arch = "wasm32")]
pub fn wasm_example() -> Result<String> {
    // Create FN-DSA instance
    let fn_dsa = WasmFnDsa::new();

    // Generate keypair
    let keypair = fn_dsa.generate_keypair()?;

    // Get key sizes
    let (sign_size, vrfy_size, sig_size) = fn_dsa.get_key_sizes();

    // Sign a message
    let message = b"Hello, WASM FN-DSA!";
    let signature = fn_dsa.sign(keypair.secret_key_bytes(), message)?;

    // Verify the signature
    let is_valid = fn_dsa.verify(keypair.public_key_bytes(), message, &signature)?;

    // Create result string
    let result = format!(
        "WASM FN-DSA Example:\n\
        Key sizes - Sign: {} bytes, Verify: {} bytes, Signature: {} bytes\n\
        Message: {}\n\
        Signature valid: {}\n\
        Public key (hex): {}\n\
        Signature (hex): {}",
        sign_size,
        vrfy_size,
        sig_size,
        core::str::from_utf8(message).unwrap_or("Invalid UTF-8"),
        is_valid,
        wasm_utils::bytes_to_hex(keypair.public_key_bytes()),
        wasm_utils::bytes_to_hex(&signature)
    );

    Ok(result)
}

/// Example for non-WASM environments (for testing)
#[cfg(not(target_arch = "wasm32"))]
pub fn wasm_example() -> Result<String> {
    // Create FN-DSA instance
    let fn_dsa = WasmFnDsa::new();

    // Generate keypair
    let keypair = fn_dsa.generate_keypair()?;

    // Get key sizes
    let (sign_size, vrfy_size, sig_size) = fn_dsa.get_key_sizes();

    // Sign a message
    let message = b"Hello, WASM FN-DSA!";
    let signature = fn_dsa.sign(keypair.secret_key_bytes(), message)?;

    // Verify the signature
    let is_valid = fn_dsa.verify(keypair.public_key_bytes(), message, &signature)?;

    // Create result string
    let result = format!(
        "WASM FN-DSA Example:\n\
        Key sizes - Sign: {} bytes, Verify: {} bytes, Signature: {} bytes\n\
        Message: {}\n\
        Signature valid: {}\n\
        Public key (hex): {}\n\
        Signature (hex): {}",
        sign_size,
        vrfy_size,
        sig_size,
        std::str::from_utf8(message).unwrap_or("Invalid UTF-8"),
        is_valid,
        wasm_utils::bytes_to_hex(keypair.public_key_bytes()),
        wasm_utils::bytes_to_hex(&signature)
    );

    Ok(result)
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🌐 WASM FN-DSA Example");
    println!("====================\n");

    match wasm_example() {
        Ok(result) => {
            println!("{}", result);
            println!("\n✅ WASM example completed successfully!");
        }
        Err(e) => {
            println!("❌ Error: {}", wasm_utils::error_to_string(&e));
        }
    }

    Ok(())
}
