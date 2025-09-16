//! Cryptographic provider implementations for lib-Q
//!
//! This module provides the provider pattern implementation for lib-Q,
//! allowing for pluggable cryptographic algorithm implementations
//! with proper security validation and error handling.

#[cfg(feature = "alloc")]
pub mod aead_provider;
#[cfg(feature = "alloc")]
pub mod hash_provider;
#[cfg(feature = "alloc")]
pub mod kem_provider;
#[cfg(feature = "alloc")]
pub mod libq_provider;
#[cfg(feature = "alloc")]
pub mod signature_provider;

// Re-export main provider
#[cfg(feature = "alloc")]
pub use aead_provider::LibQAeadProvider;
#[cfg(feature = "alloc")]
pub use hash_provider::LibQHashProvider;
// Re-export individual operation providers
#[cfg(feature = "alloc")]
pub use kem_provider::LibQKemProvider;
#[cfg(feature = "alloc")]
pub use libq_provider::LibQCryptoProvider;
#[cfg(feature = "alloc")]
pub use signature_provider::LibQSignatureProvider;
