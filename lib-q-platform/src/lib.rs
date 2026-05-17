//! lib-Q Platform Detection and Feature Support
//!
//! This crate provides platform-specific functionality for lib-Q,
//! including CPU feature detection and platform-specific optimizations.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

/// CPU feature detection
pub mod cpu;

/// Platform-specific implementations
pub mod platform;

/// SIMD support detection
pub mod simd;

pub use cpu::*;
pub use platform::*;
pub use simd::*;
