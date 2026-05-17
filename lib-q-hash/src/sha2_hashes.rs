//! SHA-2 family (FIPS 180-4) wrappers implementing [`lib_q_core::Hash`].
//!
//! These are standard symmetric hash functions used for interoperability and as
//! building blocks; they complement the SHA-3 / Keccak family in this crate.

use alloc::vec::Vec;

use digest::Digest;
use lib_q_core::{
    Hash,
    Result,
};
use sha2::{
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
};

macro_rules! impl_sha2_fixed_output {
    ($name:ident, $state:ty, $out_len:expr) => {
        /// Fixed-output SHA-2 wrapper for the lib-q [`Hash`] trait.
        #[derive(Clone, Debug)]
        pub struct $name($state);

        impl $name {
            /// Create a new hasher in its initial state.
            pub fn new() -> Self {
                Self(Default::default())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Hash for $name {
            fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
                let mut h = self.0.clone();
                Digest::update(&mut h, data);
                Ok(h.finalize().to_vec())
            }

            fn output_size(&self) -> usize {
                $out_len
            }
        }
    };
}

impl_sha2_fixed_output!(Sha224Hash, Sha224, 28);
impl_sha2_fixed_output!(Sha256Hash, Sha256, 32);
impl_sha2_fixed_output!(Sha384Hash, Sha384, 48);
impl_sha2_fixed_output!(Sha512Hash, Sha512, 64);
impl_sha2_fixed_output!(Sha512_224Hash, Sha512_224, 28);
impl_sha2_fixed_output!(Sha512_256Hash, Sha512_256, 32);
