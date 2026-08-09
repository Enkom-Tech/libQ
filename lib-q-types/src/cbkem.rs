//! CB-KEM (Classic McEliece) object sizes (bytes) shared across the workspace.
//!
//! Single source of truth consumed by `lib-q-core` (`SecurityConstants`). The real
//! implementation crate, `lib-q-cb-kem`, defines its own `CRYPTO_PUBLICKEYBYTES` /
//! `CRYPTO_SECRETKEYBYTES` / `CRYPTO_CIPHERTEXTBYTES` per parameter set in `src/api.rs` and
//! carries a conformance test asserting equality against the constants here.
//!
//! Classic McEliece key sizes are not simple closed-form functions of small parameters in this
//! codebase (they fall out of the field/matrix construction in `lib-q-cb-kem::params`), so they
//! are listed here as plain literals rather than re-derived — and `lib-q-types` must not depend
//! on any algorithm crate regardless (that would cycle back through `lib-q-core`).

/// CB-KEM-348864 public key length.
pub const CBKEM348864_PUBLIC_KEY_BYTES: usize = 261_120;
/// CB-KEM-348864 secret key length.
pub const CBKEM348864_SECRET_KEY_BYTES: usize = 6492;
/// CB-KEM-348864 ciphertext length.
pub const CBKEM348864_CIPHERTEXT_BYTES: usize = 96;

/// CB-KEM-460896 public key length.
pub const CBKEM460896_PUBLIC_KEY_BYTES: usize = 524_160;
/// CB-KEM-460896 secret key length.
pub const CBKEM460896_SECRET_KEY_BYTES: usize = 13_608;
/// CB-KEM-460896 ciphertext length.
pub const CBKEM460896_CIPHERTEXT_BYTES: usize = 156;

/// CB-KEM-6688128 public key length.
pub const CBKEM6688128_PUBLIC_KEY_BYTES: usize = 1_044_992;
/// CB-KEM-6688128 secret key length.
pub const CBKEM6688128_SECRET_KEY_BYTES: usize = 13_932;
/// CB-KEM-6688128 ciphertext length.
pub const CBKEM6688128_CIPHERTEXT_BYTES: usize = 208;

/// CB-KEM-6960119 public key length.
pub const CBKEM6960119_PUBLIC_KEY_BYTES: usize = 1_047_319;
/// CB-KEM-6960119 secret key length.
pub const CBKEM6960119_SECRET_KEY_BYTES: usize = 13_948;
/// CB-KEM-6960119 ciphertext length.
pub const CBKEM6960119_CIPHERTEXT_BYTES: usize = 194;

/// CB-KEM-8192128 public key length.
pub const CBKEM8192128_PUBLIC_KEY_BYTES: usize = 1_357_824;
/// CB-KEM-8192128 secret key length.
pub const CBKEM8192128_SECRET_KEY_BYTES: usize = 14_120;
/// CB-KEM-8192128 ciphertext length.
pub const CBKEM8192128_CIPHERTEXT_BYTES: usize = 208;
