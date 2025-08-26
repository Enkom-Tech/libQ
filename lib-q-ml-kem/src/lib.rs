#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![deny(missing_docs)] // Require all public interfaces to be documented
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`

//! # Usage
//!
//! This crate implements the Module-Latice-based Key Encapsulation Method (ML-KEM) algorithm
//! being standardized by NIST in FIPS 203.  ML-KEM is a KEM in the sense that it creates an
//! (decapsulation key, encapsulation key) pair, such that anyone can use the encapsulation key to
//! establish a shared key with the holder of the decapsulation key.  ML-KEM is the first KEM
//! algorithm standardized by NIST that is designed to be resistant to attacks using quantum
//! computers.
//!
//! ```
//! # use lib_q_ml_kem::*;
//! # use lib_q_ml_kem::{Encapsulate, Decapsulate};
//! # use rand::prelude::*;
//! let mut rng = rand::rng();
//!
//! // Generate a (decapsulation key, encapsulation key) pair
//! let (dk, ek) = MlKem768::generate(&mut rng);
//!
//! // Encapsulate a shared key to the holder of the decapsulation key, receive the shared
//! // secret `k_send` and the encapsulated form `ct`.
//! let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
//!
//! // Decapsulate the shared key and verify that it was faithfully received.
//! let k_recv = dk.decapsulate(&ct).unwrap();
//! assert_eq!(k_send, k_recv);
//! ```
//!
//! [RFC 9180]: https://www.rfc-editor.org/info/rfc9180

/// The inevitable utility module
mod util;

/// Section 2.4. Interpreting the Pseudocode
/// Section 4.2.2. Sampling algorithms
/// Section 4.3. The Number-Theoretic Transform
mod algebra;

/// Section 4.1. Crytographic Functions
mod crypto;

/// Section 4.2.1. Conversion and Compression Algorithms, Compression and decompression
mod compress;

/// Section 4.2.1. Conversion and Compression Algorithms, Encoding and decoding
mod encode;

/// Section 5. The K-PKE Component Scheme
mod pke;

/// Section 6. The ML-KEM Key-Encapsulation Mechanism
pub mod kem;

/// Section 7. Parameter Sets
mod param;

use core::fmt::Debug;

pub use hybrid_array as array;
use hybrid_array::Array;
use hybrid_array::typenum::{
    U2,
    U3,
    U4,
    U5,
    U10,
    U11,
    Unsigned,
};
use rand_core::CryptoRng;

/// A value that can be encapsulated to. Often, this will just be a public key. However, it can
/// also be a bundle of public keys, or it can include a sender's private key for authenticated
/// encapsulation.
pub trait Encapsulate<EK, SS> {
    /// Encapsulation error
    type Error: Debug;

    /// Encapsulates a fresh shared secret
    ///
    /// # Errors
    ///
    /// Returns an error if the encapsulation process fails, which can happen due to
    /// cryptographic failures, invalid parameters, or insufficient entropy.
    fn encapsulate<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<(EK, SS), Self::Error>;
}

/// A value that can be used to decapsulate an encapsulated key.
///
/// Often, this will just be a secret key. But, as with [`Encapsulate`], it can be a bundle
/// of secret keys, or it can include a sender's private key for authenticated encapsulation.
pub trait Decapsulate<EK, SS> {
    /// Decapsulation error
    type Error: Debug;

    /// Decapsulates the given encapsulated key
    ///
    /// # Errors
    ///
    /// Returns an error if the decapsulation process fails, which can happen due to
    /// cryptographic failures, invalid ciphertext, or corrupted data.
    fn decapsulate(&self, encapsulated_key: &EK) -> Result<SS, Self::Error>;
}

pub use param::{
    ArraySize,
    ParameterSet,
};
#[cfg(feature = "deterministic")]
pub use util::B32;

/// An object that knows what size it is
pub trait EncodedSizeUser {
    /// The size of an encoded object
    type EncodedSize: ArraySize;

    /// Parse an object from its encoded form
    fn from_bytes(enc: &Encoded<Self>) -> Self;

    /// Serialize an object to its encoded form
    fn as_bytes(&self) -> Encoded<Self>;
}

/// A byte array encoding a value the indicated size
pub type Encoded<T> = Array<u8, <T as EncodedSizeUser>::EncodedSize>;

/// A value that can be encapsulated to.  Note that this interface is not safe: In order for the
/// KEM to be secure, the `m` input must be randomly generated.
#[cfg(feature = "deterministic")]
pub trait EncapsulateDeterministic<EK, SS> {
    /// Encapsulation error
    type Error: Debug;

    /// Encapsulates a fresh shared secret.
    ///
    /// # Errors
    ///
    /// Will vary depending on the underlying implementation.
    fn encapsulate_deterministic(&self, m: &B32) -> Result<(EK, SS), Self::Error>;
}

/// A generic interface to a Key Encapsulation Method
pub trait KemCore: Clone {
    /// The size of a shared key generated by this KEM
    type SharedKeySize: ArraySize;

    /// The size of a ciphertext encapsulating a shared key
    type CiphertextSize: ArraySize;

    /// A decapsulation key for this KEM
    type DecapsulationKey: Decapsulate<Ciphertext<Self>, SharedKey<Self>>
        + EncodedSizeUser
        + Debug
        + PartialEq;

    /// An encapsulation key for this KEM
    #[cfg(not(feature = "deterministic"))]
    type EncapsulationKey: Encapsulate<Ciphertext<Self>, SharedKey<Self>>
        + EncodedSizeUser
        + Clone
        + Debug
        + PartialEq;

    /// An encapsulation key for this KEM
    #[cfg(feature = "deterministic")]
    type EncapsulationKey: Encapsulate<Ciphertext<Self>, SharedKey<Self>>
        + EncapsulateDeterministic<Ciphertext<Self>, SharedKey<Self>>
        + EncodedSizeUser
        + Clone
        + Debug
        + PartialEq;

    /// Generate a new (decapsulation, encapsulation) key pair
    fn generate<R: CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey);

    /// Generate a new (decapsulation, encapsulation) key pair deterministically
    #[cfg(feature = "deterministic")]
    fn generate_deterministic(d: &B32, z: &B32)
    -> (Self::DecapsulationKey, Self::EncapsulationKey);
}

/// `MlKem512` is the parameter set for security category 1, corresponding to key search on a block
/// cipher with a 128-bit key.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlKem512Params;

impl ParameterSet for MlKem512Params {
    type K = U2;
    type Eta1 = U3;
    type Eta2 = U2;
    type Du = U10;
    type Dv = U4;
}

/// `MlKem768` is the parameter set for security category 3, corresponding to key search on a block
/// cipher with a 192-bit key.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlKem768Params;

impl ParameterSet for MlKem768Params {
    type K = U3;
    type Eta1 = U2;
    type Eta2 = U2;
    type Du = U10;
    type Dv = U4;
}

/// `MlKem1024` is the parameter set for security category 5, corresponding to key search on a block
/// cipher with a 256-bit key.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MlKem1024Params;

impl ParameterSet for MlKem1024Params {
    type K = U4;
    type Eta1 = U2;
    type Eta2 = U2;
    type Du = U11;
    type Dv = U5;
}

/// A shared key produced by the KEM `K`
pub type SharedKey<K> = Array<u8, <K as KemCore>::SharedKeySize>;

/// A ciphertext produced by the KEM `K`
pub type Ciphertext<K> = Array<u8, <K as KemCore>::CiphertextSize>;

/// ML-KEM with the parameter set for security category 1, corresponding to key search on a block
/// cipher with a 128-bit key.
pub type MlKem512 = kem::Kem<MlKem512Params>;

/// ML-KEM with the parameter set for security category 3, corresponding to key search on a block
/// cipher with a 192-bit key.
pub type MlKem768 = kem::Kem<MlKem768Params>;

/// ML-KEM with the parameter set for security category 5, corresponding to key search on a block
/// cipher with a 256-bit key.
pub type MlKem1024 = kem::Kem<MlKem1024Params>;

// --- Public sizes for consumers (usize), to avoid leaking typenum in downstream crates ---

/// Size in bytes of ML-KEM-512 public keys
pub const MLKEM512_PUBLIC_KEY_SIZE: usize =
    <kem::EncapsulationKey<MlKem512Params> as EncodedSizeUser>::EncodedSize::USIZE;
/// Size in bytes of ML-KEM-512 secret keys
pub const MLKEM512_SECRET_KEY_SIZE: usize =
    <kem::DecapsulationKey<MlKem512Params> as EncodedSizeUser>::EncodedSize::USIZE;
/// Size in bytes of ML-KEM-512 ciphertexts
pub const MLKEM512_CIPHERTEXT_SIZE: usize = <MlKem512 as KemCore>::CiphertextSize::USIZE;
/// Size in bytes of ML-KEM shared secrets
pub const MLKEM_SHARED_KEY_SIZE: usize = <MlKem512 as KemCore>::SharedKeySize::USIZE; // always 32

/// Size in bytes of ML-KEM-768 public keys
pub const MLKEM768_PUBLIC_KEY_SIZE: usize =
    <kem::EncapsulationKey<MlKem768Params> as EncodedSizeUser>::EncodedSize::USIZE;
/// Size in bytes of ML-KEM-768 secret keys
pub const MLKEM768_SECRET_KEY_SIZE: usize =
    <kem::DecapsulationKey<MlKem768Params> as EncodedSizeUser>::EncodedSize::USIZE;
/// Size in bytes of ML-KEM-768 ciphertexts
pub const MLKEM768_CIPHERTEXT_SIZE: usize = <MlKem768 as KemCore>::CiphertextSize::USIZE;

/// Size in bytes of ML-KEM-1024 public keys
pub const MLKEM1024_PUBLIC_KEY_SIZE: usize =
    <kem::EncapsulationKey<MlKem1024Params> as EncodedSizeUser>::EncodedSize::USIZE;
/// Size in bytes of ML-KEM-1024 secret keys
pub const MLKEM1024_SECRET_KEY_SIZE: usize =
    <kem::DecapsulationKey<MlKem1024Params> as EncodedSizeUser>::EncodedSize::USIZE;
/// Size in bytes of ML-KEM-1024 ciphertexts
pub const MLKEM1024_CIPHERTEXT_SIZE: usize = <MlKem1024 as KemCore>::CiphertextSize::USIZE;

#[cfg(test)]
mod test {
    use super::*;

    fn round_trip_test<K>()
    where
        K: KemCore,
    {
        let mut rng = rand::rng();

        let (dk, ek) = K::generate(&mut rng);

        let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
        let k_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn round_trip() {
        round_trip_test::<MlKem512>();
        round_trip_test::<MlKem768>();
        round_trip_test::<MlKem1024>();
    }
}
