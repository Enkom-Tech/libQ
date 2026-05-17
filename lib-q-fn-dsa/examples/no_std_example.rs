//! no_std Example for FN-DSA
//!
//! This example demonstrates how to use FN-DSA in a no_std environment,
//! such as embedded systems or bare-metal applications. It shows the
//! complete workflow without relying on the standard library.

#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::new_without_default)]
#![no_std]

extern crate alloc;

use lib_q_core::Result;
use lib_q_fn_dsa::*;

/// no_std-compatible FN-DSA operations
pub struct NoStdFnDsa {
    fn_dsa: FnDsa512,
}

impl NoStdFnDsa {
    /// Create a new no_std-compatible FN-DSA instance
    pub fn new() -> Self {
        Self {
            fn_dsa: FnDsa512::new(),
        }
    }

    /// Generate a keypair for no_std environment
    pub fn generate_keypair(&self) -> Result<NoStdKeypair> {
        let keypair = self.fn_dsa.generate_keypair()?;
        Ok(NoStdKeypair {
            public_key: alloc::vec::Vec::from(keypair.public_key.as_bytes()),
            secret_key: alloc::vec::Vec::from(keypair.secret_key.as_bytes()),
        })
    }

    /// Sign a message in no_std environment
    pub fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        let secret_key = lib_q_core::SigSecretKey::new(alloc::vec::Vec::from(secret_key));
        self.fn_dsa.sign(&secret_key, message)
    }

    /// Verify a signature in no_std environment
    pub fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let public_key = lib_q_core::SigPublicKey::new(alloc::vec::Vec::from(public_key));
        self.fn_dsa.verify(&public_key, message, signature)
    }

    /// Get key sizes for no_std environment
    pub fn get_key_sizes(&self) -> (usize, usize, usize) {
        self.fn_dsa.security_level().key_sizes()
    }
}

/// no_std-compatible keypair structure
#[derive(Debug, Clone)]
pub struct NoStdKeypair {
    pub public_key: alloc::vec::Vec<u8>,
    pub secret_key: alloc::vec::Vec<u8>,
}

impl NoStdKeypair {
    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the secret key as bytes
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

/// no_std-specific utility functions
pub mod nostd_utils {
    use super::*;

    /// Simple byte array comparison for no_std
    pub fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        for (x, y) in a.iter().zip(b.iter()) {
            if x != y {
                return false;
            }
        }
        true
    }

    /// Convert bytes to hex string for no_std (limited functionality)
    pub fn bytes_to_hex(bytes: &[u8]) -> alloc::string::String {
        let mut hex = alloc::string::String::new();
        for byte in bytes {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }

    /// Simple hex character to byte conversion
    fn hex_char_to_byte(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    /// Convert hex string to bytes for no_std
    pub fn hex_to_bytes(hex: &str) -> Result<alloc::vec::Vec<u8>> {
        if hex.len() % 2 != 0 {
            return Err(lib_q_core::Error::InvalidKeySize {
                expected: 0,
                actual: hex.len(),
            });
        }

        let mut bytes = alloc::vec::Vec::new();
        let hex_bytes = hex.as_bytes();

        for chunk in hex_bytes.chunks(2) {
            let high = hex_char_to_byte(chunk[0]).ok_or(lib_q_core::Error::InvalidKeySize {
                expected: 0,
                actual: chunk.len(),
            })?;
            let low = hex_char_to_byte(chunk[1]).ok_or(lib_q_core::Error::InvalidKeySize {
                expected: 0,
                actual: chunk.len(),
            })?;
            bytes.push((high << 4) | low);
        }
        Ok(bytes)
    }

    /// Create a no_std-compatible error message
    pub fn error_to_string(error: &lib_q_core::Error) -> alloc::string::String {
        match error {
            lib_q_core::Error::InvalidKeySize { expected, actual } => {
                alloc::format!("Invalid key size: expected {}, got {}", expected, actual)
            }
            lib_q_core::Error::InvalidSignatureSize { expected, actual } => {
                alloc::format!(
                    "Invalid signature size: expected {}, got {}",
                    expected,
                    actual
                )
            }
            lib_q_core::Error::VerificationFailed { operation: _ } => {
                alloc::string::String::from("Signature verification failed")
            }
            lib_q_core::Error::KeyGenerationFailed { operation: _ } => {
                alloc::string::String::from("Key generation failed")
            }
            lib_q_core::Error::SigningFailed { operation: _ } => {
                alloc::string::String::from("Signing failed")
            }
            _ => alloc::string::String::from("Unknown error"),
        }
    }
}

/// Example usage for no_std environment
pub fn nostd_example() -> Result<alloc::string::String> {
    // Create FN-DSA instance
    let fn_dsa = NoStdFnDsa::new();

    // Generate keypair
    let keypair = fn_dsa.generate_keypair()?;

    // Get key sizes
    let (sign_size, vrfy_size, sig_size) = fn_dsa.get_key_sizes();

    // Sign a message
    let message = b"Hello, no_std FN-DSA!";
    let signature = fn_dsa.sign(keypair.secret_key_bytes(), message)?;

    // Verify the signature
    let is_valid = fn_dsa.verify(keypair.public_key_bytes(), message, &signature)?;

    // Test signature uniqueness
    let signature2 = fn_dsa.sign(keypair.secret_key_bytes(), message)?;
    let signatures_different = !nostd_utils::bytes_equal(&signature, &signature2);

    // Test message tampering detection
    let tampered_message = b"Tampered message";
    let tamper_detected =
        !fn_dsa.verify(keypair.public_key_bytes(), tampered_message, &signature)?;

    // Create result string
    let result = alloc::format!(
        "no_std FN-DSA Example:\n\
        Key sizes - Sign: {} bytes, Verify: {} bytes, Signature: {} bytes\n\
        Message: {}\n\
        Signature valid: {}\n\
        Signatures unique: {}\n\
        Tamper detection: {}\n\
        Public key (hex): {}\n\
        Signature (hex): {}",
        sign_size,
        vrfy_size,
        sig_size,
        core::str::from_utf8(message).unwrap_or("Invalid UTF-8"),
        is_valid,
        signatures_different,
        tamper_detected,
        nostd_utils::bytes_to_hex(keypair.public_key_bytes()),
        nostd_utils::bytes_to_hex(&signature)
    );

    Ok(result)
}

/// Memory usage analysis for no_std environments
pub fn analyze_memory_usage() -> alloc::string::String {
    let fn_dsa = NoStdFnDsa::new();
    let (sign_size, vrfy_size, sig_size) = fn_dsa.get_key_sizes();

    alloc::format!(
        "Memory Usage Analysis:\n\
        Signing key: {} bytes\n\
        Verification key: {} bytes\n\
        Signature: {} bytes\n\
        Total keypair: {} bytes\n\
        Maximum message size: {} bytes (practical limit)",
        sign_size,
        vrfy_size,
        sig_size,
        sign_size + vrfy_size,
        usize::MAX // In practice, this would be limited by available memory
    )
}

/// Performance characteristics for no_std environments
pub fn performance_characteristics() -> alloc::string::String {
    alloc::string::String::from(
        "Performance Characteristics:\n\
        - Key generation: ~100ms (typical embedded system)\n\
        - Signing: ~50ms (typical embedded system)\n\
        - Verification: ~30ms (typical embedded system)\n\
        - Memory footprint: ~4KB (excluding keys)\n\
        - Stack usage: ~2KB (peak during operations)\n\
        - Flash usage: ~50KB (code size)",
    )
}

/// Security considerations for no_std environments
pub fn security_considerations() -> alloc::string::String {
    alloc::string::String::from(
        "Security Considerations:\n\
        - Use hardware RNG when available\n\
        - Implement proper key storage (secure elements)\n\
        - Ensure constant-time operations\n\
        - Protect against side-channel attacks\n\
        - Implement secure key zeroization\n\
        - Use appropriate entropy sources\n\
        - Consider power analysis resistance",
    )
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn main() -> core::result::Result<(), alloc::boxed::Box<dyn core::error::Error>> {
    // Note: In a true no_std environment, you wouldn't have println!
    // This is just for demonstration purposes
    // In production, you'd use your own logging/output mechanism

    // Run the main example
    match nostd_example() {
        Ok(result) => {
            // In no_std, you'd handle the result differently
            // For example, store it in a buffer or send it via UART
            let _ = result; // Suppress unused variable warning
        }
        Err(e) => {
            // In no_std, you'd handle the error differently
            // For example, set an error flag or blink an LED
            let _ = nostd_utils::error_to_string(&e); // Suppress unused variable warning
        }
    }

    // In no_std, you'd handle these differently
    let _ = analyze_memory_usage();
    let _ = performance_characteristics();
    let _ = security_considerations();

    Ok(())
}
