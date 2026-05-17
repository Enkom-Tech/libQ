//! A framework for finite fields.
//!
//! # Security Considerations
//!
//! ## Constant-Time Operations
//! Field operations in this module are designed to be constant-time where possible.
//! However, not all operations guarantee constant-time execution. Use the `constant_time`
//! module for operations that require timing guarantees.
//!
//! **Important**: The default `is_zero()` and `is_one()` methods use standard equality
//! comparison which may leak timing information. For secret values, always use
//! `constant_time::constant_time_is_zero()` which requires the field to implement
//! `ConstantTimeEq` from the `subtle` crate.
//!
//! Fields that implement `ConstantTimeEq` (such as `Mersenne31`) provide constant-time
//! equality comparison suitable for use with secret values.
//!
//! ## Memory Safety
//! Use the `secret` module for wrapping sensitive field values that must be
//! automatically zeroized when dropped.
//!
//! ## Secure Usage
//! - Use `SecretFieldElement` for secret values
//! - Use `constant_time::constant_time_is_zero()` for secret comparisons
//! - Use `constant_time::constant_time_eq()` for secret equality checks
//! - Validate all inputs before processing
#![no_std]

extern crate alloc;

mod array;
mod batch_inverse;
pub mod constant_time;
pub mod coset;
pub mod exponentiation;
pub mod extension;
mod field;
mod helpers;
pub mod integers;
pub mod op_assign_macros;
mod packed;
pub mod secret;

pub use array::*;
pub use batch_inverse::*;
pub use constant_time::*;
pub use field::*;
pub use helpers::*;
pub use packed::*;
pub use secret::*;
