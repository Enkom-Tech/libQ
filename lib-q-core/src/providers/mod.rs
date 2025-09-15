//! Cryptographic provider implementations for lib-Q
//!
//! This module provides the provider pattern implementation for lib-Q,
//! allowing for pluggable cryptographic algorithm implementations
//! with proper security validation and error handling.

pub mod aead_provider;
pub mod hash_provider;
pub mod kem_provider;
pub mod libq_provider;
pub mod signature_provider;

// Re-export main provider
pub use aead_provider::LibQAeadProvider;
pub use hash_provider::LibQHashProvider;
// Re-export individual operation providers
pub use kem_provider::LibQKemProvider;
pub use libq_provider::LibQCryptoProvider;
pub use signature_provider::LibQSignatureProvider;
