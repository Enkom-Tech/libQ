//! Context management module for lib-Q Core
//!
//! This module provides a unified context management system that reduces
//! code duplication and provides better maintainability for cryptographic
//! operation contexts.

#[cfg(feature = "alloc")]
pub mod aead;
#[cfg(feature = "alloc")]
pub mod base;
#[cfg(feature = "alloc")]
pub mod hash;
#[cfg(feature = "alloc")]
pub mod kem;
#[cfg(feature = "alloc")]
pub mod signature;

#[cfg(feature = "alloc")]
pub use aead::*;
#[cfg(feature = "alloc")]
pub use base::*;
#[cfg(feature = "alloc")]
pub use hash::*;
#[cfg(feature = "alloc")]
pub use kem::*;
#[cfg(feature = "alloc")]
pub use signature::*;
