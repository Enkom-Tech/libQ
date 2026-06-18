//! Pre–FIPS **Keccak** fixed digests: original Keccak padding, **not** FIPS 202 **SHA-3** (use [`lib_q_sha3`](https://docs.rs/lib-q-sha3) for `Sha3_256` and the SHA-3 family).
//!
//! # Types
//!
//! - [`Keccak224`] … [`Keccak512`], [`Keccak256Full`] (200-byte output).
//! - One-shot: [`keccak_224`], [`keccak_256`], [`keccak_384`], [`keccak_512`], [`keccak_256_full`].
//!
//! # Security
//!
//! - [`Keccak256`](crate::Keccak256) and any [`lib_q_sha3::Sha3_256`](https://docs.rs/lib-q-sha3) produce **different** digests for the same input (different padding).
//! - Do not substitute this crate for SHA-3 in a protocol without explicit specification.
//!
//! See the crate **README** for links, architecture ADR, and follow-up dependency extraction ADR.

#![no_std]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub use digest::Digest;
use digest::consts::{
    U28,
    U32,
    U48,
    U64,
    U72,
    U104,
    U136,
    U144,
    U200,
};
use lib_q_sha3::block_core::{
    KECCAK_DIGEST_PAD,
    SpongeHasherCore,
};

digest::buffer_fixed!(
    /// Non-standard 200-byte output Keccak-256 (e.g. CryptoNight-style). **Not** FIPS SHA3-256—see the crate README.
    pub struct Keccak256Full(SpongeHasherCore<U136, U200, KECCAK_DIGEST_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-224 (original Keccak padding, **not** SHA3-224).
    pub struct Keccak224(SpongeHasherCore<U144, U28, KECCAK_DIGEST_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-256 (original Keccak padding, **not** SHA3-256).
    pub struct Keccak256(SpongeHasherCore<U136, U32, KECCAK_DIGEST_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-384 (original Keccak padding, **not** SHA3-384).
    pub struct Keccak384(SpongeHasherCore<U104, U48, KECCAK_DIGEST_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-512 (original Keccak padding, **not** SHA3-512).
    pub struct Keccak512(SpongeHasherCore<U72, U64, KECCAK_DIGEST_PAD>);
    impl: FixedHashTraits;
);

mod one_shot;

pub use one_shot::{
    keccak_224,
    keccak_256,
    keccak_256_full,
    keccak_384,
    keccak_512,
};

#[cfg(test)]
mod tests {
    use digest::Digest;

    use super::*;

    #[test]
    fn keccak256_and_sha3_256_differ_on_same_input() {
        let d = b"lib-q keccak-digest != sha3";
        let k = Keccak256::digest(d);
        let s = lib_q_sha3::Sha3_256::digest(d);
        assert_ne!(k.as_slice(), s.as_slice());
    }
}
