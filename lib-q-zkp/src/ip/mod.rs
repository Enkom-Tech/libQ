//! IP (Identity Protocol) Integration Module
//!
//! This module provides high-level APIs for using lib-q-zkp with an Identity Protocol,
//! including identity proofs, anonymous authentication, and credential management.

pub mod auth;
pub mod credential;
pub mod identity;

pub use auth::*;
pub use credential::*;
pub use identity::*;
