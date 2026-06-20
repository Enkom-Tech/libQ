//! SHA-3 family for lib-Q: fixed-output **SHA-3** (FIPS 202), **SHAKE** and **cSHAKE** XOFs, **TurboSHAKE**. Raw pre-FIPS **Keccak** digests are in [`lib_q_keccak_digest`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-keccak-digest).
//!
//! # Re-exports
//!
//! - [`digest`]: the `digest` crate (version unified with the workspace).
//! - [`Digest`], [`Update`], [`ExtendableOutput`], [`ExtendableOutputReset`], [`XofReader`], [`CustomizedInit`], [`CollisionResistance`]: common [`digest`](https://docs.rs/digest) traits, re-exported at the root. For XOFs use [`Update`], [`ExtendableOutput`], and [`XofReader`]. If a module imports both [`Digest`] and [`Update`], disambiguate [`Digest::update`](Digest::update) and [`Update::update`](Update::update) with explicit trait paths.
//!
//! # Modules
//!
//! - [`cshake`]: cSHAKE-128/256 (NIST SP 800-185).
//! - [`turbo_shake`]: TurboSHAKE-128/256 (12-round Keccak; used by RFC 9861 KangarooTwelve in [`lib_q_k12`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-k12)).
//! - [`block_core`]: low-level cores and Keccak state for composition (e.g. K12); not needed for typical hashing.
//!
//! The rest of the API is re-exported at the crate root for discoverability. See the crate **README** (front page of docs) for standards links, feature flags, and **security** considerations.
//!
//! # Crate features
//!
//! Optional Cargo features: `alloc`, `oid`, `zeroize`, `asm` (see the README *Feature flags* table).
//! On [docs.rs](https://docs.rs/lib-q-sha3), this crate is built with `all-features`; the `doc_cfg`
//! rustdoc feature marks APIs that require a Cargo feature. The `zeroize` feature enables
//! [`ZeroizeOnDrop`](https://docs.rs/digest/latest/digest/trait.ZeroizeOnDrop.html) (from the `zeroize` feature) on supported types.
//!
//! # `sha3_256` vs `Sha3_256`
//!
//! [`sha3_256`](fn.sha3_256.html) is a small convenience for one-shot hashing. Prefer [`Sha3_256`] with the [`Digest`] trait when reusing a hasher or when you need serialization / OID features.

#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub use digest::{
    self,
    CollisionResistance,
    CustomizedInit,
    Digest,
    ExtendableOutput,
    ExtendableOutputReset,
    Update,
    XofReader,
};

/// Block-level types and Keccak cores for advanced composition (e.g. K12). Most callers should use the crate-root types.
pub mod block_core;
/// cSHAKE-128 and cSHAKE-256 (NIST SP 800-185). Types are re-exported at the crate root.
pub mod cshake;
/// Four-way batched TurboSHAKE (AVX2-accelerated leaf hashing for KangarooTwelve).
pub mod parallel;
/// TurboSHAKE-128 and TurboSHAKE-256. Types are re-exported at the crate root.
pub mod turbo_shake;

use block_core::{
    SpongeHasherCore,
    SpongeReaderCore,
};
#[doc(inline)]
pub use cshake::{
    CShake128,
    CShake128Reader,
    CShake256,
    CShake256Reader,
};
use digest::consts::{
    U0,
    U16,
    U28,
    U32,
    U48,
    U64,
    U72,
    U104,
    U136,
    U144,
    U168,
};
#[doc(inline)]
pub use turbo_shake::{
    TurboShake128,
    TurboShake128Reader,
    TurboShake256,
    TurboShake256Reader,
};

/// One-shot **SHA3-256** (FIPS 202) over `data`.
///
/// Equivalent to [`Sha3_256`]`::`[`digest`](Digest::digest)`(data)` but may inline more aggressively. For incremental input or state serialization, use [`Sha3_256`] and [`Digest`].
#[inline(always)]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

// Paddings
const SHA3_PAD: u8 = 0x06;
const SHAKE_PAD: u8 = 0x1F;
const CSHAKE_PAD: u8 = 0x04;

const PLEN: usize = 25;
const DEFAULT_ROUND_COUNT: usize = 24;

/// XOR a (partial) block into the Keccak state lanes (little-endian).
///
/// Shared Keccak-sponge helper used by both the block API and cSHAKE; lives at the crate root
/// so neither module has to depend on the other.
pub(crate) fn xor_block(state: &mut [u64; PLEN], block: &[u8]) {
    assert!(block.len() < 8 * PLEN);

    let mut chunks = block.chunks_exact(8);
    for (s, chunk) in state.iter_mut().zip(&mut chunks) {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(chunk);
        *s ^= u64::from_le_bytes(lane);
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        let n = block.len() / 8;
        state[n] ^= u64::from_le_bytes(buf);
    }
}

digest::buffer_fixed!(
    /// SHA-3-224 (FIPS 202).
    pub struct Sha3_224(SpongeHasherCore<U144, U28, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.7";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-256 (FIPS 202).
    pub struct Sha3_256(SpongeHasherCore<U136, U32, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.8";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-384 (FIPS 202).
    pub struct Sha3_384(SpongeHasherCore<U104, U48, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.9";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-512 (FIPS 202).
    pub struct Sha3_512(SpongeHasherCore<U72, U64, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.10";
    impl: FixedHashTraits;
);
digest::buffer_xof!(
    /// SHAKE128 (FIPS 202, extendable output).
    pub struct Shake128(SpongeHasherCore<U168, U0, SHAKE_PAD>);
    oid: "2.16.840.1.101.3.4.2.11";
    impl: XofHasherTraits;
    /// SHAKE128 XOF output reader.
    pub struct Shake128Reader(SpongeReaderCore<U168>);
    impl: XofReaderTraits;
);
digest::buffer_xof!(
    /// SHAKE256 (FIPS 202, extendable output).
    pub struct Shake256(SpongeHasherCore<U136, U0, SHAKE_PAD>);
    oid: "2.16.840.1.101.3.4.2.12";
    impl: XofHasherTraits;
    /// SHAKE256 XOF output reader.
    pub struct Shake256Reader(SpongeReaderCore<U136>);
    impl: XofReaderTraits;
);

impl CollisionResistance for Shake128 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31
    type CollisionResistance = U16;
}

impl CollisionResistance for Shake256 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31
    type CollisionResistance = U32;
}
