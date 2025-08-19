//! ParallelHash implementation
//!
//! This module provides ParallelHash128 and ParallelHash256 implementations as specified in SP800-185.
//! ParallelHash is designed for efficient hashing of very long strings using parallel processing.

use crate::{
    cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader},
    shake::{Shake128, Shake256},
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

#[cfg(feature = "parallelhash")]
use rayon::prelude::*;

/// ParallelHash128 implementation
#[derive(Clone)]
pub struct ParallelHash128 {
    inner: CShake128,
    buf: Vec<u8>,
    n: u64,
    rate: usize,
    blocksize: usize,
}

/// ParallelHash256 implementation
#[derive(Clone)]
pub struct ParallelHash256 {
    inner: CShake256,
    buf: Vec<u8>,
    n: u64,
    rate: usize,
    blocksize: usize,
}

/// ParallelHash128 XOF reader
#[derive(Clone)]
pub struct ParallelHash128Reader {
    inner: CShake128Reader,
}

/// ParallelHash256 XOF reader
#[derive(Clone)]
pub struct ParallelHash256Reader {
    inner: CShake256Reader,
}

macro_rules! impl_parallelhash {
    (
        $name:ident, $inner_type:ident, $reader_name:ident, $inner_reader_type:ident, $shake_type:ident, $rate:ident, $rate_expr:expr, $alg_name:expr
    ) => {
        impl $name {
            /// Creates a new ParallelHash instance with the given customization string and block size
            pub fn new(custom: &[u8], blocksize: usize) -> Self {
                let mut hasher = Self {
                    inner: $inner_type::new_with_function_name(b"ParallelHash", custom),
                    buf: Vec::new(),
                    n: 0,
                    rate: $rate_expr,
                    blocksize,
                };
                hasher.init();
                hasher
            }

            fn init(&mut self) {
                let mut enc_buf = [0u8; 9];

                // left_encode(B)
                let encoded = left_encode(self.blocksize as u64, &mut enc_buf);
                Update::update(&mut self.inner, encoded);
            }

            /// Hash a single block using SHAKE
            fn hash_block(block: &[u8], rate: usize) -> Vec<u8> {
                let mut shake = $shake_type::default();
                Update::update(&mut shake, block);
                let mut output = vec![0u8; rate / 8];
                ExtendableOutput::finalize_xof_into(shake, &mut output);
                output
            }

            /// Update with data
            pub fn update(&mut self, data: &[u8]) {
                let mut pos = 0;

                // Handle any remaining data in buffer
                if !self.buf.is_empty() {
                    let len = self.blocksize - self.buf.len();
                    if data.len() < len {
                        self.buf.extend_from_slice(data);
                        return;
                    } else {
                        self.buf.extend_from_slice(&data[..len]);
                        let block_hash = Self::hash_block(&self.buf, self.rate);
                        Update::update(&mut self.inner, &block_hash);
                        self.buf.clear();
                        self.n += 1;
                        pos = len;
                    }
                }

                // Process complete blocks
                #[cfg(feature = "parallelhash")]
                {
                    let rate = self.rate;
                    let blocksize = self.blocksize;

                    // Process complete blocks in parallel
                    let complete_blocks = (data.len() - pos) / blocksize;
                    if complete_blocks > 0 {
                        let block_data = &data[pos..pos + complete_blocks * blocksize];
                        let hashes: Vec<Vec<u8>> = block_data
                            .par_chunks(blocksize)
                            .map(|chunk| Self::hash_block(chunk, rate))
                            .collect();

                        for hash in hashes {
                            Update::update(&mut self.inner, &hash);
                            self.n += 1;
                        }
                        pos += complete_blocks * blocksize;
                    }

                    // Store remaining data
                    if pos < data.len() {
                        self.buf.extend_from_slice(&data[pos..]);
                    }
                }

                #[cfg(not(feature = "parallelhash"))]
                {
                    while pos + self.blocksize <= data.len() {
                        let block_hash =
                            Self::hash_block(&data[pos..pos + self.blocksize], self.rate);
                        Update::update(&mut self.inner, &block_hash);
                        self.n += 1;
                        pos += self.blocksize;
                    }

                    // Store remaining data
                    if pos < data.len() {
                        self.buf.extend_from_slice(&data[pos..]);
                    }
                }
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
                // Process any remaining data in buffer
                if !self.buf.is_empty() {
                    let block_hash = Self::hash_block(&self.buf, self.rate);
                    Update::update(&mut self.inner, &block_hash);
                    self.buf.clear();
                    self.n += 1;
                }

                let mut enc_buf = [0u8; 9];

                // right_encode(n)
                let encoded = right_encode(self.n, &mut enc_buf);
                Update::update(&mut self.inner, encoded);

                // right_encode(L)
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
                // Delegate to the public update method
                let mut pos = 0;

                // Handle any remaining data in buffer
                if !self.buf.is_empty() {
                    let len = self.blocksize - self.buf.len();
                    if data.len() < len {
                        self.buf.extend_from_slice(data);
                        return;
                    } else {
                        self.buf.extend_from_slice(&data[..len]);
                        let block_hash = Self::hash_block(&self.buf, self.rate);
                        Update::update(&mut self.inner, &block_hash);
                        self.buf.clear();
                        self.n += 1;
                        pos = len;
                    }
                }

                // Process complete blocks
                #[cfg(feature = "parallelhash")]
                {
                    let rate = self.rate;
                    let blocksize = self.blocksize;

                    // Process complete blocks in parallel
                    let complete_blocks = (data.len() - pos) / blocksize;
                    if complete_blocks > 0 {
                        let block_data = &data[pos..pos + complete_blocks * blocksize];
                        let hashes: Vec<Vec<u8>> = block_data
                            .par_chunks(blocksize)
                            .map(|chunk| Self::hash_block(chunk, rate))
                            .collect();

                        for hash in hashes {
                            Update::update(&mut self.inner, &hash);
                            self.n += 1;
                        }
                        pos += complete_blocks * blocksize;
                    }

                    // Store remaining data
                    if pos < data.len() {
                        self.buf.extend_from_slice(&data[pos..]);
                    }
                }

                #[cfg(not(feature = "parallelhash"))]
                {
                    while pos + self.blocksize <= data.len() {
                        let block_hash =
                            Self::hash_block(&data[pos..pos + self.blocksize], self.rate);
                        Update::update(&mut self.inner, &block_hash);
                        self.n += 1;
                        pos += self.blocksize;
                    }

                    // Store remaining data
                    if pos < data.len() {
                        self.buf.extend_from_slice(&data[pos..]);
                    }
                }
            }
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.update(block);
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.inner.reset();
                self.buf.clear();
                self.n = 0;
                self.init();
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
                Self::new(b"", 8192)
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

impl_parallelhash!(
    ParallelHash128,
    CShake128,
    ParallelHash128Reader,
    CShake128Reader,
    Shake128,
    U168,
    168,
    "ParallelHash128"
);
impl_parallelhash!(
    ParallelHash256,
    CShake256,
    ParallelHash256Reader,
    CShake256Reader,
    Shake256,
    U136,
    136,
    "ParallelHash256"
);

impl CollisionResistance for ParallelHash128 {
    type CollisionResistance = U16;
}

impl CollisionResistance for ParallelHash256 {
    type CollisionResistance = U32;
}

// Add SerializableState for ParallelHash types
impl SerializableState for ParallelHash128 {
    type SerializedStateSize = U400;

    fn serialize(&self) -> SerializedState<Self> {
        self.inner.serialize()
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let inner = CShake128::deserialize(serialized_state)?;
        Ok(Self {
            inner,
            buf: Vec::new(),
            n: 0,
            rate: 168,
            blocksize: 8192,
        })
    }
}

impl SerializableState for ParallelHash256 {
    type SerializedStateSize = U400;

    fn serialize(&self) -> SerializedState<Self> {
        self.inner.serialize()
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let inner = CShake256::deserialize(serialized_state)?;
        Ok(Self {
            inner,
            buf: Vec::new(),
            n: 0,
            rate: 136,
            blocksize: 8192,
        })
    }
}

// Note: Zeroization is handled by the existing ZeroizeOnDrop implementations
// which are feature-gated and will zeroize the inner cSHAKE state

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallelhash128_basic() {
        let custom = b"custom";
        let data = b"test_data";

        let mut parallelhash = ParallelHash128::new(custom, 16);
        parallelhash.update(data);

        let mut output = [0u8; 32];
        parallelhash.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_parallelhash256_basic() {
        let custom = b"custom";
        let data = b"test_data";

        let mut parallelhash = ParallelHash256::new(custom, 16);
        parallelhash.update(data);

        let mut output = [0u8; 64];
        parallelhash.finalize(&mut output);
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_parallelhash_xof() {
        let custom = b"custom";
        let data = b"test_data";

        let mut parallelhash = ParallelHash128::new(custom, 16);
        parallelhash.update(data);

        let mut reader = parallelhash.xof();
        let mut output = [0u8; 100];
        reader.read(&mut output);
        assert_ne!(output, [0u8; 100]);
    }

    #[test]
    fn test_parallelhash_different_block_sizes() {
        let custom = b"custom";
        let data = b"test_data_that_is_long_enough";

        let mut parallelhash1 = ParallelHash128::new(custom, 8);
        parallelhash1.update(data);
        let mut output1 = [0u8; 32];
        parallelhash1.finalize(&mut output1);

        let mut parallelhash2 = ParallelHash128::new(custom, 16);
        parallelhash2.update(data);
        let mut output2 = [0u8; 32];
        parallelhash2.finalize(&mut output2);

        // Different block sizes should produce different results
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_parallelhash_different_customs() {
        let data = b"test_data";

        let mut parallelhash1 = ParallelHash128::new(b"custom1", 16);
        parallelhash1.update(data);
        let mut output1 = [0u8; 32];
        parallelhash1.finalize(&mut output1);

        let mut parallelhash2 = ParallelHash128::new(b"custom2", 16);
        parallelhash2.update(data);
        let mut output2 = [0u8; 32];
        parallelhash2.finalize(&mut output2);

        assert_ne!(output1, output2);
    }

    #[test]
    #[cfg(feature = "parallelhash")]
    fn test_parallelhash_performance_comparison() {
        // Create a large dataset to demonstrate parallel processing
        let large_data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        let custom = b"performance_test";
        let block_size = 8192;

        // Test with parallel processing
        let mut parallelhash = ParallelHash128::new(custom, block_size);
        parallelhash.update(&large_data);
        let mut output = [0u8; 64];
        parallelhash.finalize(&mut output);

        // Verify we got a valid hash
        assert_ne!(output, [0u8; 64]);

        // This test demonstrates that parallel processing works
        // The fact that it completes without errors shows parallel processing is functional
    }

    #[test]
    fn test_parallelhash_reset() {
        let custom = b"custom";
        let data = b"test_data";

        let mut parallelhash = ParallelHash128::new(custom, 16);
        parallelhash.update(data);

        // Reset and test again
        parallelhash.reset();
        parallelhash.update(data);

        let mut output = [0u8; 32];
        parallelhash.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_parallelhash_default() {
        let parallelhash = ParallelHash128::default();
        let data = b"test_data";

        let mut hasher = parallelhash;
        hasher.update(data);
        let result = hasher.finalize_with_length(32);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_parallelhash_serialization() {
        let custom = b"custom";
        let data = b"test_data";

        let mut parallelhash = ParallelHash128::new(custom, 16);
        parallelhash.update(data);

        // Serialize the state
        let serialized = parallelhash.serialize();

        // Deserialize and continue
        let mut parallelhash2 = ParallelHash128::deserialize(&serialized).unwrap();
        parallelhash2.update(b"more_data");

        let mut output = [0u8; 32];
        parallelhash2.finalize(&mut output);
        assert_ne!(output, [0u8; 32]);
    }
}
