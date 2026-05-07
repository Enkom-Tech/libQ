//! lib-Q Classical McEliece KEM - Post-quantum Key Encapsulation Mechanism
//!
//! This crate provides a pure Rust implementation of the Classical McEliece KEM
//! following the lib-Q architecture with proper security validation and provider pattern integration.
//!
//! ## Architecture
//!
//! This implementation follows the lib-Q provider pattern:
//! - **Provider Pattern**: Implements `KemOperations` trait for integration with lib-q-core
//! - **Security Validation**: Comprehensive input validation and security checks
//! - **Algorithm Support**: Full support for NIST-approved Classical McEliece variants
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **no_std Support**: Works in constrained environments
//!
//! ## Supported Algorithms
//!
//! - **Classical McEliece**: All NIST-approved variants (348864, 460896, 6688128, 6960119, 8192128)
//! - **Hash Functions**: SHA3 (SHAKE256) support
//!
//! ## Feature Support
//!
//! All KEM algorithms support:
//! - **no_std**: Works in constrained environments with external randomness
//! - **WASM**: JavaScript-compatible bindings for web environments
//! - **Security validation**: Comprehensive input validation and security checks
//! - **Memory safety**: Automatic zeroization of sensitive data
//! - **Hash function**: SHA3 (SHAKE256) hash function
//!
//! ## Usage
//!
//! ### With libQ Integration
//! ```rust,ignore
//! use lib_q_core::{Algorithm, KemContext, create_kem_context};
//! use lib_q_cb_kem::LibQCbKemProvider;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create KEM context with Classical McEliece provider
//!     let mut ctx = create_kem_context();
//!     ctx.set_provider(Box::new(LibQCbKemProvider::new()?));
//!
//!     // Generate keypair (requires std feature for automatic randomness)
//!     let keypair = ctx.generate_keypair(Algorithm::CbKem348864, None)?;
//!
//!     // Encapsulate shared secret
//!     let (ciphertext, shared_secret) = ctx.encapsulate(Algorithm::CbKem348864, &keypair.public_key, None)?;
//!
//!     // Decapsulate shared secret
//!     let decapsulated_secret = ctx.decapsulate(Algorithm::CbKem348864, &keypair.secret_key, &ciphertext)?;
//!     assert_eq!(shared_secret, decapsulated_secret);
//!     Ok(())
//! }
//! ```
//!
//! ### Direct Usage (no_std compatible)
//! ```rust,ignore
//! use lib_q_cb_kem::{keypair, encapsulate, decapsulate, LibQRng};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create deterministic RNG for testing (use hardware RNG in production)
//!     let mut rng = LibQRng::new_deterministic(0x0102030405060708);
//!
//!     // Generate keypair
//!     let (public_key, secret_key) = keypair(&mut rng);
//!
//!     // Encapsulate shared secret
//!     let (ciphertext, shared_secret) = encapsulate(&public_key, &mut rng);
//!
//!     // Decapsulate shared secret
//!     let decapsulated_secret = decapsulate(&secret_key, &ciphertext);
//!     assert_eq!(shared_secret.as_ref(), decapsulated_secret.as_ref());
//!     Ok(())
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Reference-style loops and explicit formulas match upstream crypto code; keep Clippy from blocking CI.
#![allow(clippy::collapsible_if)]
#![allow(clippy::identity_op)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::unnecessary_mut_passed)]

mod api;
mod benes;
mod bm;
mod controlbits;
mod crypto_hash;
mod decrypt;
mod encrypt;
mod gf;
mod int32_sort;
mod libq_provider;
mod operations;
mod params;
mod pk_gen;
mod root;
mod sk_gen;
mod synd;
mod test_utils;
mod transpose;
mod uint64_sort;
mod util;

#[cfg(feature = "nist-aes-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "nist-aes-rng")))]
mod nist_aes_rng;

use core::fmt::Debug;

use rand_core::{
    CryptoRng,
    Rng,
};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

pub use api::{
    CRYPTO_BYTES,
    CRYPTO_CIPHERTEXTBYTES,
    CRYPTO_PRIMITIVE,
    CRYPTO_PUBLICKEYBYTES,
    CRYPTO_SECRETKEYBYTES,
};
// Re-export unified RNG from lib-q-random
pub use lib_q_random::ClassicalMcElieceRng as LibQRng;
// Re-export libQ provider
#[cfg(feature = "alloc")]
pub use libq_provider::LibQCbKemProvider;
#[cfg(feature = "nist-aes-rng")]
#[cfg_attr(docsrs, doc(cfg(feature = "nist-aes-rng")))]
pub use nist_aes_rng::{
    AesState,
    MAX_BYTES_PER_REQUEST,
    NistDrbgError,
    RESEED_INTERVAL,
    SEEDLEN,
};

mod macros {
    /// This macro(A, B, C, T) allows to get “&A[B..B+C]” of type “&[T]” as type “&[T; C]”.
    /// The default type T is u8 and “mut A” instead of “A” returns a mutable reference.
    macro_rules! sub {
        ($var:expr, $offset:expr, $len:expr) => {{
            <&[u8; $len]>::try_from(&$var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        (mut $var:expr, $offset:expr, $len:expr) => {{
            <&mut [u8; $len]>::try_from(&mut $var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        ($var:expr, $offset:expr, $len:expr, $t:ty) => {{
            <&[$t; $len]>::try_from(&$var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
        (mut $var:expr, $offset:expr, $len:expr, $t:ty) => {{
            <&mut [$t; $len]>::try_from(&mut $var[$offset..($offset + $len)])
                .expect("slice has the correct length")
        }};
    }

    pub(crate) use sub;
}

#[derive(Debug)]
enum KeyBufferMut<'a, const SIZE: usize> {
    Borrowed(&'a mut [u8; SIZE]),
    #[cfg(feature = "alloc")]
    Owned(Box<[u8; SIZE]>),
}

impl<const SIZE: usize> KeyBufferMut<'_, SIZE> {
    #[cfg(feature = "alloc")]
    fn to_owned(&self) -> KeyBufferMut<'static, SIZE> {
        let mut new_buffer = util::alloc_boxed_array::<SIZE>();
        new_buffer.copy_from_slice(self.as_ref());
        KeyBufferMut::Owned(new_buffer)
    }
}

impl<const SIZE: usize> AsRef<[u8; SIZE]> for KeyBufferMut<'_, SIZE> {
    fn as_ref(&self) -> &[u8; SIZE] {
        match &self {
            KeyBufferMut::Borrowed(buf) => buf,
            #[cfg(feature = "alloc")]
            KeyBufferMut::Owned(buf) => buf.as_ref(),
        }
    }
}

impl<const SIZE: usize> AsMut<[u8; SIZE]> for KeyBufferMut<'_, SIZE> {
    fn as_mut(&mut self) -> &mut [u8; SIZE] {
        match self {
            KeyBufferMut::Borrowed(buf) => buf,
            #[cfg(feature = "alloc")]
            KeyBufferMut::Owned(buf) => buf.as_mut(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const SIZE: usize> zeroize::Zeroize for KeyBufferMut<'_, SIZE> {
    fn zeroize(&mut self) {
        match self {
            KeyBufferMut::Borrowed(buf) => buf.zeroize(),
            #[cfg(feature = "alloc")]
            KeyBufferMut::Owned(buf) => buf.zeroize(),
        }
    }
}

/// A Classic McEliece public key. These are very large compared to keys
/// in most other cryptographic algorithms.
#[derive(Debug)]
#[must_use]
pub struct PublicKey<'a>(KeyBufferMut<'a, CRYPTO_PUBLICKEYBYTES>);

impl PublicKey<'_> {
    /// Copies the key to the heap and makes it `'static`.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> PublicKey<'static> {
        PublicKey(self.0.to_owned())
    }

    pub fn as_array(&self) -> &[u8; CRYPTO_PUBLICKEYBYTES] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for PublicKey<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a mut [u8; CRYPTO_PUBLICKEYBYTES]> for PublicKey<'a> {
    fn from(data: &'a mut [u8; CRYPTO_PUBLICKEYBYTES]) -> Self {
        Self(KeyBufferMut::Borrowed(data))
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl From<Box<[u8; CRYPTO_PUBLICKEYBYTES]>> for PublicKey<'static> {
    fn from(data: Box<[u8; CRYPTO_PUBLICKEYBYTES]>) -> Self {
        Self(KeyBufferMut::Owned(data))
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for PublicKey<'_> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for PublicKey<'_> {}

impl Drop for PublicKey<'_> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.zeroize();
        }
    }
}

/// A Classic McEliece secret key.
///
/// Should be kept on the device where it's generated. Used to decapsulate the [`SharedSecret`]
/// from the [`Ciphertext`] received from the encapsulator.
#[must_use]
pub struct SecretKey<'a>(KeyBufferMut<'a, CRYPTO_SECRETKEYBYTES>);

impl SecretKey<'_> {
    /// Copies the key to the heap and makes it `'static`.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> SecretKey<'static> {
        SecretKey(self.0.to_owned())
    }

    /// Returns the secret key as an array of bytes.
    ///
    /// Please note that depending on your threat model, moving the data out of the
    /// `SecretKey` can be bad for security. The `SecretKey` type is designed to keep the
    /// backing data in a single location in memory and zeroing it out when it goes out
    /// of scope.
    pub fn as_array(&self) -> &[u8; CRYPTO_SECRETKEYBYTES] {
        self.0.as_ref()
    }
}

impl Debug for SecretKey<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"-- redacted --").finish()
    }
}

impl AsRef<[u8]> for SecretKey<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<&'a mut [u8; CRYPTO_SECRETKEYBYTES]> for SecretKey<'a> {
    /// Represents a mutable byte array of the correct size as a `SecretKey`.
    /// Please note that the array will be zeroed on drop.
    fn from(data: &'a mut [u8; CRYPTO_SECRETKEYBYTES]) -> Self {
        Self(KeyBufferMut::Borrowed(data))
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
#[cfg(feature = "alloc")]
impl From<Box<[u8; CRYPTO_SECRETKEYBYTES]>> for SecretKey<'static> {
    fn from(data: Box<[u8; CRYPTO_SECRETKEYBYTES]>) -> Self {
        Self(KeyBufferMut::Owned(data))
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for SecretKey<'_> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SecretKey<'_> {}

impl Drop for SecretKey<'_> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.zeroize();
        }
    }
}

/// The ciphertext computed by the encapsulator.
#[derive(Debug)]
#[must_use]
pub struct Ciphertext([u8; CRYPTO_CIPHERTEXTBYTES]);

impl Ciphertext {
    pub fn as_array(&self) -> &[u8; CRYPTO_CIPHERTEXTBYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; CRYPTO_CIPHERTEXTBYTES]> for Ciphertext {
    fn from(data: [u8; CRYPTO_CIPHERTEXTBYTES]) -> Self {
        Self(data)
    }
}

/// The shared secret computed by the KEM. Returned from both the
/// encapsulator and decapsulator.
#[must_use]
pub struct SharedSecret<'a>(KeyBufferMut<'a, CRYPTO_BYTES>);

impl SharedSecret<'_> {
    /// Copies the secret to the heap and makes it `'static`.
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    #[cfg(feature = "alloc")]
    pub fn to_owned(&self) -> SharedSecret<'static> {
        SharedSecret(self.0.to_owned())
    }

    pub fn as_array(&self) -> &[u8; CRYPTO_BYTES] {
        self.0.as_ref()
    }
}

impl Debug for SharedSecret<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SharedSecret")
            .field(&"-- redacted --")
            .finish()
    }
}

impl AsRef<[u8]> for SharedSecret<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for SharedSecret<'_> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SharedSecret<'_> {}

impl Drop for SharedSecret<'_> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            self.zeroize();
        }
    }
}

/// KEM Keypair generation.
///
/// Generate a public and secret key.
/// The public key is meant to be shared with any party,
/// but access to the secret key must be limited to the generating party.
pub fn keypair<'public, 'secret, R: CryptoRng + Rng>(
    public_key_buf: &'public mut [u8; CRYPTO_PUBLICKEYBYTES],
    secret_key_buf: &'secret mut [u8; CRYPTO_SECRETKEYBYTES],
    rng: &mut R,
) -> (PublicKey<'public>, SecretKey<'secret>) {
    operations::crypto_kem_keypair(public_key_buf, secret_key_buf, rng);

    (
        PublicKey(KeyBufferMut::Borrowed(public_key_buf)),
        SecretKey(KeyBufferMut::Borrowed(secret_key_buf)),
    )
}

/// Convenient wrapper around [`keypair`] that stores the public and private keys on the heap
/// and returns them with the ``'static`` lifetime.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn keypair_boxed<R: CryptoRng + Rng>(rng: &mut R) -> (PublicKey<'static>, SecretKey<'static>) {
    let mut public_key_buf = util::alloc_boxed_array::<CRYPTO_PUBLICKEYBYTES>();
    let mut secret_key_buf = util::alloc_boxed_array::<CRYPTO_SECRETKEYBYTES>();

    operations::crypto_kem_keypair(&mut public_key_buf, &mut secret_key_buf, rng);

    (
        PublicKey(KeyBufferMut::Owned(public_key_buf)),
        SecretKey(KeyBufferMut::Owned(secret_key_buf)),
    )
}

/// KEM Encapsulation.
///
/// Given a public key `public_key`, compute a shared key.
/// The returned ciphertext should be sent back to the entity holding
/// the secret key corresponding to public key given here, so they can compute
/// the same shared key.
pub fn encapsulate<'shared_secret, R: CryptoRng + Rng>(
    public_key: &PublicKey<'_>,
    shared_secret_buf: &'shared_secret mut [u8; CRYPTO_BYTES],
    rng: &mut R,
) -> (Ciphertext, SharedSecret<'shared_secret>) {
    let mut shared_secret_buf = KeyBufferMut::Borrowed(shared_secret_buf);
    let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];

    operations::crypto_kem_enc(
        &mut ciphertext_buf,
        shared_secret_buf.as_mut(),
        public_key.0.as_ref(),
        rng,
    );

    (Ciphertext(ciphertext_buf), SharedSecret(shared_secret_buf))
}

/// Convenient wrapper around [`encapsulate`] that stores the shared secret on the heap
/// and returns it with the ``'static`` lifetime.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn encapsulate_boxed<R: CryptoRng + Rng>(
    public_key: &PublicKey<'_>,
    rng: &mut R,
) -> (Ciphertext, SharedSecret<'static>) {
    let mut shared_secret_buf = KeyBufferMut::Owned(Box::new([0u8; CRYPTO_BYTES]));
    let mut ciphertext_buf = [0u8; CRYPTO_CIPHERTEXTBYTES];

    operations::crypto_kem_enc(
        &mut ciphertext_buf,
        shared_secret_buf.as_mut(),
        public_key.0.as_ref(),
        rng,
    );

    (Ciphertext(ciphertext_buf), SharedSecret(shared_secret_buf))
}

/// KEM Decapsulation.
///
/// Given a secret key `secret_key` and a ciphertext `ciphertext`,
/// determine the shared key negotiated by both parties.
pub fn decapsulate<'shared_secret>(
    ciphertext: &Ciphertext,
    secret_key: &SecretKey,
    shared_secret_buf: &'shared_secret mut [u8; CRYPTO_BYTES],
) -> SharedSecret<'shared_secret> {
    let mut shared_secret_buf = KeyBufferMut::Borrowed(shared_secret_buf);

    operations::crypto_kem_dec(
        shared_secret_buf.as_mut(),
        ciphertext.as_array(),
        secret_key.as_array(),
    );

    SharedSecret(shared_secret_buf)
}

/// Convenient wrapper around [`decapsulate`] that stores the shared secret on the heap
/// and returns it with the ``'static`` lifetime.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn decapsulate_boxed(ciphertext: &Ciphertext, secret_key: &SecretKey) -> SharedSecret<'static> {
    let mut shared_secret_buf = KeyBufferMut::Owned(Box::new([0u8; CRYPTO_BYTES]));

    operations::crypto_kem_dec(
        shared_secret_buf.as_mut(),
        ciphertext.as_array(),
        secret_key.as_array(),
    );

    SharedSecret(shared_secret_buf)
}

#[cfg(feature = "wasm")]
mod wasm;

// Tests may use `std` - no extern crate needed in Rust 2018+
