//! IP (Identity Protocol) Integration Module
//!
//! This module provides high-level APIs for using lib-q-zkp with an Identity Protocol,
//! including identity proofs, anonymous authentication, and credential management.

pub mod auth;
pub mod credential;
pub mod identity;
pub mod recovery_policy;
pub mod recovery_policy_hybrid;

pub use auth::*;
pub use credential::*;
pub use identity::*;
pub use recovery_policy::*;
pub use recovery_policy_hybrid::*;
