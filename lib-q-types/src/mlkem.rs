//! ML-KEM (FIPS 203) object sizes (bytes) shared across the workspace.
//!
//! This module is the **single source of truth** consumed by `lib-q-core`
//! (`SecurityConstants`). The real implementation crate, `lib-q-ml-kem`, derives its own
//! sizes from `ml-kem`'s type-level `KemCore` associated constants (`EncapsulationKeySize`,
//! `DecapsulationKeySize`, `CiphertextSize`) and carries a conformance test asserting equality
//! against the constants here — see `lib-q-ml-kem/src/lib.rs`.
//!
//! These are the fixed FIPS 203 sizes and do not vary by build; they are listed here as plain
//! literals (not re-derived from a formula) because `lib-q-types` must not depend on any
//! algorithm crate (that would cycle back through `lib-q-core`, which those crates depend on).

/// ML-KEM-512 public (encapsulation) key length.
pub const MLKEM512_PUBLIC_KEY_BYTES: usize = 800;
/// ML-KEM-512 secret (decapsulation) key length.
pub const MLKEM512_SECRET_KEY_BYTES: usize = 1632;
/// ML-KEM-512 ciphertext length.
pub const MLKEM512_CIPHERTEXT_BYTES: usize = 768;

/// ML-KEM-768 public (encapsulation) key length.
pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
/// ML-KEM-768 secret (decapsulation) key length.
pub const MLKEM768_SECRET_KEY_BYTES: usize = 2400;
/// ML-KEM-768 ciphertext length.
pub const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;

/// ML-KEM-1024 public (encapsulation) key length.
pub const MLKEM1024_PUBLIC_KEY_BYTES: usize = 1568;
/// ML-KEM-1024 secret (decapsulation) key length.
pub const MLKEM1024_SECRET_KEY_BYTES: usize = 3168;
/// ML-KEM-1024 ciphertext length.
pub const MLKEM1024_CIPHERTEXT_BYTES: usize = 1568;
