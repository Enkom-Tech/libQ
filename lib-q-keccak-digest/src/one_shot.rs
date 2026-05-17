//! One-shot, fixed-output Keccak (original padding).
//!
//! The public digest types in [`crate`] are built with `digest::buffer_fixed!`, which
//! often produces little or no LLVM line coverage in this crate’s `lib.rs` alone.
//! These small wrappers mirror [`lib_q_sha3::sha3_256`](https://docs.rs/lib-q-sha3) so
//! coverage and profiling see explicit call sites in this package.

use digest::Digest;

use crate::{
    Keccak224,
    Keccak256,
    Keccak256Full,
    Keccak384,
    Keccak512,
};

/// One-shot **Keccak-224** (original padding; not SHA-3-224).
#[inline(always)]
pub fn keccak_224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Keccak224::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

/// One-shot **Keccak-256** (original padding; not SHA-3-256).
#[inline(always)]
pub fn keccak_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

/// One-shot **Keccak-384** (original padding; not SHA-3-384).
#[inline(always)]
pub fn keccak_384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Keccak384::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

/// One-shot **Keccak-512** (original padding; not SHA-3-512).
#[inline(always)]
pub fn keccak_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Keccak512::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}

/// One-shot **Keccak256Full** (200-byte output, original padding).
#[inline(always)]
pub fn keccak_256_full(data: &[u8]) -> [u8; 200] {
    let mut hasher = Keccak256Full::new();
    Digest::update(&mut hasher, data);
    hasher.finalize().into()
}
