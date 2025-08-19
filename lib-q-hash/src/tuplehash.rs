//! TupleHash implementation
//!
//! TupleHash is designed to hash tuples of input strings unambiguously.

use crate::{
    cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader},
    utils::{left_encode, right_encode},
};
use alloc::{vec, vec::Vec};
use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, HashMarker, Reset, Update, XofReader,
    block_api::{AlgorithmName, Block, BlockSizeUser, BufferKindUser, Eager, UpdateCore},
    consts::{U16, U32, U136, U168, U400},
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
};

/// TupleHash128 implementation
#[derive(Clone)]
pub struct TupleHash128 {
    inner: CShake128,
}

/// TupleHash256 implementation
#[derive(Clone)]
pub struct TupleHash256 {
    inner: CShake256,
}

/// TupleHash128 XOF reader
#[derive(Clone)]
pub struct TupleHash128Reader {
    inner: CShake128Reader,
}

/// TupleHash256 XOF reader
#[derive(Clone)]
pub struct TupleHash256Reader {
    inner: CShake256Reader,
}

macro_rules! impl_tuplehash {
    (
        $name:ident, $inner_type:ident, $reader_name:ident, $inner_reader_type:ident, $rate:ident, $alg_name:expr
    ) => {
        impl $name {
            /// Creates a new TupleHash instance with the given customization string
            pub fn new(custom: &[u8]) -> Self {
                Self {
                    inner: $inner_type::new_with_function_name(b"TupleHash", custom),
                }
            }

            /// Update with a tuple of strings
            pub fn update_tuple<T: AsRef<[u8]>>(&mut self, tuple: &[T]) {
                let mut enc_buf = [0u8; 9];

                for item in tuple {
                    let item_bytes = item.as_ref();

                    // encode_string(X[i])
                    let encoded = left_encode((item_bytes.len() * 8) as u64, &mut enc_buf);
                    Update::update(&mut self.inner, encoded);
                    Update::update(&mut self.inner, item_bytes);
                }
            }

            /// Update with a single string (for compatibility)
            pub fn update(&mut self, data: &[u8]) {
                let tuple = [data];
                self.update_tuple(&tuple);
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
                let tuple = [data];
                self.update_tuple(&tuple);
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
                Self::new(b"")
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

impl_tuplehash!(
    TupleHash128,
    CShake128,
    TupleHash128Reader,
    CShake128Reader,
    U168,
    "TupleHash128"
);
impl_tuplehash!(
    TupleHash256,
    CShake256,
    TupleHash256Reader,
    CShake256Reader,
    U136,
    "TupleHash256"
);

impl CollisionResistance for TupleHash128 {
    type CollisionResistance = U16;
}

impl CollisionResistance for TupleHash256 {
    type CollisionResistance = U32;
}

// Add SerializableState for TupleHash types
impl SerializableState for TupleHash128 {
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

impl SerializableState for TupleHash256 {
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
    fn test_tuplehash128_basic() {
        let custom = b"custom";
        let data = b"test";
        let tuple = vec![data];

        let mut tuplehash = TupleHash128::new(custom);
        tuplehash.update_tuple(&tuple);

        let mut output = [0u8; 32];
        tuplehash.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_tuplehash256_basic() {
        let custom = b"custom";
        let data = b"test";
        let tuple = vec![data];

        let mut tuplehash = TupleHash256::new(custom);
        tuplehash.update_tuple(&tuple);

        let mut output = [0u8; 64];
        tuplehash.finalize(&mut output);
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_tuplehash_xof() {
        let custom = b"custom";
        let data = b"test";
        let tuple = vec![data];

        let mut tuplehash = TupleHash128::new(custom);
        tuplehash.update_tuple(&tuple);

        let mut reader = tuplehash.xof();
        let mut output = [0u8; 100];
        reader.read(&mut output);
        assert_ne!(output, [0u8; 100]);
    }

    #[test]
    fn test_tuplehash_different_customs() {
        let data = b"test";
        let tuple = vec![data];

        let mut tuplehash1 = TupleHash128::new(b"custom1");
        tuplehash1.update_tuple(&tuple);
        let mut output1 = [0u8; 32];
        tuplehash1.finalize(&mut output1);

        let mut tuplehash2 = TupleHash128::new(b"custom2");
        tuplehash2.update_tuple(&tuple);
        let mut output2 = [0u8; 32];
        tuplehash2.finalize(&mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_tuplehash_empty_tuple() {
        let custom = b"custom";
        let tuple: Vec<&[u8]> = vec![];

        let mut tuplehash = TupleHash128::new(custom);
        tuplehash.update_tuple(&tuple);

        let mut output = [0u8; 32];
        tuplehash.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_tuplehash_tuple_order_matters() {
        // This is a key property of TupleHash - different tuple structures produce different hashes
        let custom = b"custom";

        // Tuple ("abc", "d")
        let abc = b"abc";
        let d = b"d";
        let tuple1: Vec<&[u8]> = vec![abc, d];
        let mut tuplehash1 = TupleHash128::new(custom);
        tuplehash1.update_tuple(&tuple1);
        let mut output1 = [0u8; 32];
        tuplehash1.finalize(&mut output1);

        // Tuple ("ab", "cd") - same concatenated string but different tuple structure
        let ab = b"ab";
        let cd = b"cd";
        let tuple2: Vec<&[u8]> = vec![ab, cd];
        let mut tuplehash2 = TupleHash128::new(custom);
        tuplehash2.update_tuple(&tuple2);
        let mut output2 = [0u8; 32];
        tuplehash2.finalize(&mut output2);

        // These should produce different hashes despite having the same concatenated content
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_tuplehash_empty_strings() {
        let custom = b"custom";

        // Tuple with empty strings
        let empty: &[u8] = &[];
        let non_empty = b"non_empty";
        let tuple = vec![empty, non_empty, empty];
        let mut tuplehash = TupleHash128::new(custom);
        tuplehash.update_tuple(&tuple);

        let mut output = [0u8; 32];
        tuplehash.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_tuplehash_multiple_updates() {
        let custom = b"custom";
        let mut tuplehash = TupleHash128::new(custom);

        // Update with multiple tuples
        let first = b"first";
        let tuple1 = vec![first];
        tuplehash.update_tuple(&tuple1);

        let second = b"second";
        let tuple2 = vec![second];
        tuplehash.update_tuple(&tuple2);

        let mut output = [0u8; 32];
        tuplehash.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_tuplehash_large_tuples() {
        let custom = b"custom";
        let large_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let tuple = vec![&large_data[..]];
        let mut tuplehash = TupleHash128::new(custom);
        tuplehash.update_tuple(&tuple);

        let mut output = [0u8; 64];
        tuplehash.finalize(&mut output);
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_tuplehash_256_vs_128() {
        let custom = b"custom";
        let tuple = vec![b"test_data"];

        // TupleHash128
        let mut tuplehash128 = TupleHash128::new(custom);
        tuplehash128.update_tuple(&tuple);
        let mut output128 = [0u8; 32];
        tuplehash128.finalize(&mut output128);

        // TupleHash256
        let mut tuplehash256 = TupleHash256::new(custom);
        tuplehash256.update_tuple(&tuple);
        let mut output256 = [0u8; 64];
        tuplehash256.finalize(&mut output256);

        // Both should produce valid hashes
        assert_ne!(output128, [0u8; 32]);
        assert_ne!(output256, [0u8; 64]);
    }

    #[test]
    fn test_tuplehash_reset() {
        let custom = b"custom";
        let data = b"test data";
        let tuple = vec![data];

        let mut tuplehash = TupleHash128::new(custom);
        tuplehash.update_tuple(&tuple);

        // Reset and test again
        tuplehash.reset();
        tuplehash.update_tuple(&tuple);

        let mut output = [0u8; 32];
        tuplehash.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_tuplehash_default() {
        let tuplehash = TupleHash128::default();
        let data = b"test data";
        let tuple = vec![data];

        let mut hasher = tuplehash;
        hasher.update_tuple(&tuple);
        let result = hasher.finalize_with_length(32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_tuplehash_serialization() {
        let custom = b"custom";
        let data = b"test data";
        let tuple = vec![data];

        let mut tuplehash = TupleHash128::new(custom);
        tuplehash.update_tuple(&tuple);

        // Serialize the state
        let serialized = tuplehash.serialize();

        // Deserialize and continue
        let mut tuplehash2 = TupleHash128::deserialize(&serialized).unwrap();
        tuplehash2.update_tuple(&[b"more data"]);

        let mut output = [0u8; 32];
        tuplehash2.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }
}
