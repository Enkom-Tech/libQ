#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![cfg_attr(
    any(sha2_backend = "riscv-zknh", sha2_backend = "riscv-zknh-compact"),
    feature(riscv_ext_intrinsics)
)]
#![allow(clippy::needless_range_loop)]

#[cfg(all(
    any(sha2_backend = "riscv-zknh", sha2_backend = "riscv-zknh-compact"),
    not(any(any(target_arch = "riscv32", target_arch = "riscv64")))
))]
compile_error!("The Zknh backends can be enabled only for RISC-V targets");

use digest::block_api::CtOutWrapper;
use digest::consts::{
    U28,
    U32,
    U48,
    U64,
};
pub use digest::{
    self,
    Digest,
};
// Re-export lib-q-core types
pub use lib_q_core::{
    Algorithm,
    AlgorithmCategory,
    Error,
};

/// Block-level types
pub mod block_api;

#[cfg(feature = "alloc")]
extern crate alloc;

#[rustfmt::skip]
mod consts;
mod sha256;
mod sha512;

digest::buffer_fixed!(
    /// SHA-256 hasher.
    pub struct Sha256(CtOutWrapper<block_api::Sha256VarCore, U32>);
    oid: "2.16.840.1.101.3.4.2.1";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-384 hasher.
    pub struct Sha384(CtOutWrapper<block_api::Sha512VarCore, U48>);
    oid: "2.16.840.1.101.3.4.2.2";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-512 hasher.
    pub struct Sha512(CtOutWrapper<block_api::Sha512VarCore, U64>);
    oid: "2.16.840.1.101.3.4.2.3";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-224 hasher.
    pub struct Sha224(CtOutWrapper<block_api::Sha256VarCore, U28>);
    oid: "2.16.840.1.101.3.4.2.4";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-512/224 hasher.
    pub struct Sha512_224(CtOutWrapper<block_api::Sha512VarCore, U28>);
    oid: "2.16.840.1.101.3.4.2.5";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-512/256 hasher.
    pub struct Sha512_256(CtOutWrapper<block_api::Sha512VarCore, U32>);
    oid: "2.16.840.1.101.3.4.2.6";
    impl: FixedHashTraits;
);

/// SHA-2 hash provider for lib-Q
///
/// This provider implements SHA-2 hash operations following lib-Q's
/// provider pattern with proper security validation.
#[cfg(feature = "alloc")]
#[derive(Clone)]
pub struct Sha2HashProvider {
    security_validator: lib_q_core::SecurityValidator,
}

#[cfg(feature = "alloc")]
impl Sha2HashProvider {
    /// Create a new SHA-2 hash provider
    ///
    /// # Returns
    ///
    /// A new instance of Sha2HashProvider with security validation initialized.
    ///
    /// # Errors
    ///
    /// Returns an error if the security validator fails to initialize.
    pub fn new() -> lib_q_core::Result<Self> {
        Ok(Self {
            security_validator: lib_q_core::SecurityValidator::new()?,
        })
    }
}

#[cfg(feature = "alloc")]
impl lib_q_core::api::HashOperations for Sha2HashProvider {
    fn hash(&self, algorithm: Algorithm, data: &[u8]) -> lib_q_core::Result<alloc::vec::Vec<u8>> {
        // Validate algorithm category
        self.security_validator
            .validate_algorithm_category(algorithm, AlgorithmCategory::Hash)?;

        // Validate data
        self.security_validator.validate_message(data)?;

        // Route to specific SHA-2 algorithm implementation
        match algorithm {
            Algorithm::Sha224 => {
                let mut hasher = Sha224::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::Sha512_224 => {
                let mut hasher = Sha512_224::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            Algorithm::Sha512_256 => {
                let mut hasher = Sha512_256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
            _ => Err(Error::InvalidAlgorithm {
                algorithm: "Algorithm is not a SHA-2 algorithm",
            }),
        }
    }
}

/// Convenience function for SHA-224 hashing
///
/// This function computes the SHA-224 hash of the input data.
#[inline(always)]
pub fn sha224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Sha224::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Convenience function for SHA-256 hashing
///
/// This function computes the SHA-256 hash of the input data.
#[inline(always)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Convenience function for SHA-384 hashing
///
/// This function computes the SHA-384 hash of the input data.
#[inline(always)]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Convenience function for SHA-512 hashing
///
/// This function computes the SHA-512 hash of the input data.
#[inline(always)]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Convenience function for SHA-512/224 hashing
///
/// This function computes the SHA-512/224 hash of the input data.
#[inline(always)]
pub fn sha512_224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Sha512_224::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Convenience function for SHA-512/256 hashing
///
/// This function computes the SHA-512/256 hash of the input data.
#[inline(always)]
pub fn sha512_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(data);
    hasher.finalize().into()
}
