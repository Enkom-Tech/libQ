//! KMAC (KECCAK Message Authentication Code) implementation
//!
//! This module provides KMAC128 and KMAC256 implementations as specified in SP800-185.
//! KMAC is a PRF and keyed hash function based on cSHAKE.

use crate::{
    cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader},
    utils::{bytepad, encode_string, left_encode, right_encode},
};
use alloc::{vec, vec::Vec};
use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, HashMarker, Reset, Update, XofReader,
    block_api::{AlgorithmName, Block, BlockSizeUser, BufferKindUser, Eager, UpdateCore},
    consts::{U16, U32, U136, U168, U400},
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
};

/// KMAC128 implementation
#[derive(Clone)]
pub struct Kmac128 {
    inner: CShake128,
}

/// KMAC256 implementation
#[derive(Clone)]
pub struct Kmac256 {
    inner: CShake256,
}

/// KMAC128 XOF reader
#[derive(Clone)]
pub struct Kmac128Reader {
    inner: CShake128Reader,
}

/// KMAC256 XOF reader
#[derive(Clone)]
pub struct Kmac256Reader {
    inner: CShake256Reader,
}

macro_rules! impl_kmac {
    (
        $name:ident, $inner_type:ident, $reader_name:ident, $inner_reader_type:ident, $rate:ident, $rate_expr:expr, $alg_name:expr
    ) => {
        impl $name {
            /// Creates a new KMAC instance with the given key and customization string
            pub fn new(key: &[u8], custom: &[u8]) -> Self {
                let mut kmac = Self {
                    inner: $inner_type::new_with_function_name(b"KMAC", custom),
                };
                kmac.init(key, $rate_expr);
                kmac
            }

            fn init(&mut self, key: &[u8], rate: usize) {
                // Build bytepad(encode_string(K), rate) exactly as per SP800-185
                let mut enc_buf = [0u8; 9];
                let mut to_pad = Vec::new();
                // left_encode(rate)
                to_pad.extend_from_slice(left_encode(rate as u64, &mut enc_buf));
                // encode_string(K)
                let enc_key = encode_string(key, &mut enc_buf);
                to_pad.extend_from_slice(&enc_key);
                // bytepad(..., rate)
                let padded = bytepad(&to_pad, rate);
                Update::update(&mut self.inner, &padded);
            }

            /// Update with data
            pub fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.inner, data);
            }

            /// Finalize with specified output length
            pub fn finalize(mut self, output: &mut [u8]) {
                self.with_bitlength((output.len() * 8) as u64);
                ExtendableOutput::finalize_xof_into(self.inner, output);
            }

            /// Finalize with specified output length and return as Vec
            pub fn finalize_with_length(mut self, output_len: usize) -> Vec<u8> {
                let mut output = vec![0u8; output_len];
                self.with_bitlength((output_len * 8) as u64);
                ExtendableOutput::finalize_xof_into(self.inner, &mut output);
                output
            }

            /// Get XOF reader for variable-length output
            pub fn xof(mut self) -> $reader_name {
                self.with_bitlength(0);
                $reader_name {
                    inner: ExtendableOutput::finalize_xof(self.inner),
                }
            }

            fn with_bitlength(&mut self, bitlength: u64) {
                let mut enc_buf = [0u8; 9];
                let length_encoded = right_encode(bitlength, &mut enc_buf);
                Update::update(&mut self.inner, length_encoded);
            }
        }

        // Digest trait implementations
        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl HashMarker for $name {}

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                Update::update(&mut self.inner, data);
            }
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.inner.update(block);
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.inner.reset();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name {}

        // Implement Default trait
        impl Default for $name {
            fn default() -> Self {
                Self::new(b"", b"")
            }
        }

        // Implement XofReader for the reader type
        impl XofReader for $reader_name {
            fn read(&mut self, buf: &mut [u8]) {
                self.inner.read(buf);
            }
        }

        impl fmt::Debug for $reader_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($reader_name), " { ... }"))
            }
        }
    };
}

impl_kmac!(
    Kmac128,
    CShake128,
    Kmac128Reader,
    CShake128Reader,
    U168,
    168usize,
    "KMAC128"
);
impl_kmac!(
    Kmac256,
    CShake256,
    Kmac256Reader,
    CShake256Reader,
    U136,
    136usize,
    "KMAC256"
);

impl CollisionResistance for Kmac128 {
    type CollisionResistance = U16;
}

impl CollisionResistance for Kmac256 {
    type CollisionResistance = U32;
}

// Add SerializableState for KMAC types
impl SerializableState for Kmac128 {
    type SerializedStateSize = U400;

    fn serialize(&self) -> SerializedState<Self> {
        self.inner.serialize()
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let inner = CShake128::deserialize(serialized_state)?;
        Ok(Self { inner })
    }
}

impl SerializableState for Kmac256 {
    type SerializedStateSize = U400;

    fn serialize(&self) -> SerializedState<Self> {
        self.inner.serialize()
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let inner = CShake256::deserialize(serialized_state)?;
        Ok(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kmac128_basic() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        let mut output = [0u8; 32];
        kmac.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_kmac256_basic() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac256::new(key, custom);
        kmac.update(data);

        let mut output = [0u8; 64];
        kmac.finalize(&mut output);
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_kmac_xof() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        let mut reader = kmac.xof();
        let mut output = [0u8; 100];
        reader.read(&mut output);
        assert_ne!(output, [0u8; 100]);
    }

    #[test]
    fn test_kmac_different_keys() {
        let custom = b"custom";
        let data = b"test data";

        let mut kmac1 = Kmac128::new(b"key1", custom);
        kmac1.update(data);
        let mut output1 = [0u8; 32];
        kmac1.finalize(&mut output1);

        let mut kmac2 = Kmac128::new(b"key2", custom);
        kmac2.update(data);
        let mut output2 = [0u8; 32];
        kmac2.finalize(&mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_kmac_different_customs() {
        let key = b"key";
        let data = b"test data";

        let mut kmac1 = Kmac128::new(key, b"custom1");
        kmac1.update(data);
        let mut output1 = [0u8; 32];
        kmac1.finalize(&mut output1);

        let mut kmac2 = Kmac128::new(key, b"custom2");
        kmac2.update(data);
        let mut output2 = [0u8; 32];
        kmac2.finalize(&mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_kmac_reset() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        // Reset and test again
        kmac.reset();
        kmac.update(data);

        let mut output = [0u8; 32];
        kmac.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_kmac_default() {
        let kmac = Kmac128::default();
        let data = b"test data";

        let mut hasher = kmac;
        hasher.update(data);
        let result = hasher.finalize_with_length(32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_kmac_serialization() {
        let key = b"key";
        let custom = b"custom";
        let data = b"test data";

        let mut kmac = Kmac128::new(key, custom);
        kmac.update(data);

        // Serialize the state
        let serialized = kmac.serialize();

        // Deserialize and continue
        let mut kmac2 = Kmac128::deserialize(&serialized).unwrap();
        kmac2.update(b"more data");

        let mut output = [0u8; 32];
        kmac2.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }
}
