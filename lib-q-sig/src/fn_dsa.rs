//! FN-DSA (FIPS 206) Post-Quantum Digital Signatures
//!
//! This module provides the FN-DSA signature algorithm implementation.
//! FN-DSA is a post-quantum digital signature scheme based on FALCON
//! with enhanced performance and compact signature sizes.
//!
//! # Security Levels
//!
//! FN-DSA provides two main security levels:
//! - Level 1 (128-bit security): n=512
//! - Level 5 (256-bit security): n=1024
//!
//! # Example Usage
//!
//! ```rust
//! use lib_q_core::Signature;
//! use lib_q_sig::fn_dsa::{
//!     FnDsa,
//!     FnDsa512,
//!     FnDsa1024,
//! };
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create an FN-DSA instance
//!     let fn_dsa = FnDsa512::new();
//!
//!     // Generate a keypair
//!     let keypair = fn_dsa.generate_keypair()?;
//!
//!     // Sign a message
//!     let message = b"Hello, FN-DSA!";
//!     let signature = fn_dsa.sign(&keypair.secret_key(), message)?;
//!
//!     // Verify the signature
//!     let is_valid =
//!         fn_dsa.verify(&keypair.public_key(), message, &signature)?;
//!     assert!(is_valid);
//!     Ok(())
//! }
//! ```

// Re-export the actual FN-DSA implementation from lib-q-fn-dsa
pub use lib_q_fn_dsa::*;
