//! Security features for HPKE implementation
//!
//! This module provides additional security features including:
//! - Side-channel protection mechanisms
//! - Key rotation policies
//! - Memory safety and zeroization

pub mod constant_time;
pub mod key_rotation;
pub mod memory_safety;
pub mod policy;
pub mod prng;
pub mod side_channel_protection;
pub mod validation;

// SECURITY: gated on `test-utils`, NOT `std`. `std` is an ordinary production
// feature -- lib-q's own `hpke` feature turns it on (`lib-q-hpke/std`) with no `cfg(test)`
// anywhere in the chain -- so gating this on `any(test, feature = "std")` (the prior state)
// compiled `TestRng` (fixed seed 12345, implements the real `CryptoRng` trait) into every
// release build that enabled `std`, `pub` and reachable through `HpkeContext::set_rng`. Same
// defect class as the previously-removed `SimpleRng` (see `prng.rs`). `test-utils` is NOT part
// of `default` and nothing in this crate's non-dev feature graph implies it; the crate enables
// it for its own integration tests via the self-referencing `[dev-dependencies]` entry in
// Cargo.toml, which only applies to `cargo test`/`cargo bench`/`cargo run --example`, never to
// `cargo build`/`cargo build --release`. See scripts/ci-guard-no-test-rng-in-release.sh.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_rng;

pub use constant_time::constant_time_eq;
pub use key_rotation::*;
pub use memory_safety::*;
pub use policy::*;
pub use prng::*;
pub use side_channel_protection::*;
pub use validation::*;
