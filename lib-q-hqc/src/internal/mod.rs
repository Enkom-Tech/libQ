//! Internal HQC implementation details
//!
//! This module contains the internal cryptographic primitives and operations
//! used by the HQC implementation.

// pub mod bch; // Removed - BCH implementation was incorrect
pub mod polynomial;
pub mod shake256;
pub mod vector;
