//! WebAssembly bindings for lib-Q Core
//!
//! This module provides comprehensive WASM bindings that integrate with the
//! new modular architecture, including contexts, providers, and security validation.

#[cfg(feature = "wasm")]
pub mod contexts;
#[cfg(feature = "wasm")]
pub mod conversions;
#[cfg(feature = "wasm")]
pub mod error;
#[cfg(feature = "wasm")]
pub mod providers;
#[cfg(feature = "wasm")]
pub mod secure_contexts;
#[cfg(feature = "wasm")]
pub mod utils;

// Re-exports for convenience
#[cfg(feature = "wasm")]
pub use contexts::*;
#[cfg(feature = "wasm")]
pub use conversions::*;
#[cfg(feature = "wasm")]
pub use error::*;
#[cfg(feature = "wasm")]
pub use providers::*;
#[cfg(feature = "wasm")]
pub use secure_contexts::*;
#[cfg(feature = "wasm")]
pub use utils::*;
