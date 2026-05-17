//! Security validation and validation utilities for lib-Q
//!
//! This module provides centralized security validation functions that ensure
//! consistent security checks across all cryptographic operations.

#[cfg(feature = "alloc")]
pub mod constants;
#[cfg(feature = "alloc")]
pub mod entropy;
#[cfg(feature = "alloc")]
pub mod timing;
#[cfg(feature = "alloc")]
pub mod validation;

// Re-export main security validator
#[cfg(feature = "alloc")]
pub use constants::SecurityConstants;
#[cfg(feature = "alloc")]
pub use entropy::EntropyValidator;
// Re-export security utilities
#[cfg(feature = "alloc")]
pub use timing::TimingValidator;
#[cfg(feature = "alloc")]
pub use validation::SecurityValidator;
