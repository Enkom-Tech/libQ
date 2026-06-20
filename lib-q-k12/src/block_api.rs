#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use digest::block_api::{
    AlgorithmName,
    Block,
    BlockSizeUser,
    Buffer,
    BufferKindUser,
    Eager,
    ExtendableOutputCore,
    UpdateCore,
    XofReaderCore,
};
use digest::consts::{
    U128,
    U136,
    U168,
};
use digest::{
    ExtendableOutputReset,
    HashMarker,
    Reset,
    Update,
    XofReader,
};
#[cfg(feature = "alloc")]
use lib_q_sha3::parallel::{
    turbo_shake128_x4,
    turbo_shake256_x4,
};
use lib_q_sha3::{
    TurboShake128,
    TurboShake128Reader,
    TurboShake256,
    TurboShake256Reader,
};

const CHUNK_SIZE: usize = 8192;
/// Number of leaves hashed together by the AVX2-accelerated batched path.
#[cfg(feature = "alloc")]
const LEAF_BATCH: usize = 4;
const LENGTH_ENCODE_SIZE: usize = 255;

macro_rules! impl_k12_core {
    (
        $name:ident, $reader_name:ident, $ts_name:ident, $ts_reader_name:ident, $batch_fn:path,
        $cv_size:literal, $alg_name:literal,
    ) => {
        #[doc = "Core"]
        #[doc = $alg_name]
        #[doc = "hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name<'cs> {
            customization: &'cs [u8],
            buffer: [u8; CHUNK_SIZE],
            bufpos: usize,
            final_tshk: $ts_name<0x06>,
            chain_tshk: $ts_name<0x0B>,
            chain_length: usize,
            /// Completed full leaf chunks awaiting batched (×4) hashing.
            #[cfg(feature = "alloc")]
            pending: Vec<[u8; CHUNK_SIZE]>,
            /// Whether the K12 inner-node separator has been emitted to `final_tshk`.
            #[cfg(feature = "alloc")]
            separator_emitted: bool,
        }

        impl<'cs> $name<'cs> {
            const CHAINING_VALUE_SIZE: usize = $cv_size;

            #[doc = "Creates a new"]
            #[doc = $alg_name]
            #[doc = "instance with the given customization."]
            pub fn new(customization: &'cs [u8]) -> Self {
                Self {
                    customization,
                    buffer: [0u8; CHUNK_SIZE],
                    bufpos: 0usize,
                    final_tshk: Default::default(),
                    chain_tshk: Default::default(),
                    chain_length: 0usize,
                    #[cfg(feature = "alloc")]
                    pending: Vec::new(),
                    #[cfg(feature = "alloc")]
                    separator_emitted: false,
                }
            }

            // ---- Batched (×4) leaf path — enabled with the `alloc` feature ----
            //
            // A completed full leaf is queued in `pending` rather than hashed
            // immediately; once four have accumulated they are hashed together
            // through the AVX2 `p1600x4` permutation. The chaining values are
            // emitted to `final_tshk` in strict chunk order with the inner-node
            // separator written exactly once, so the digest is byte-identical to
            // the scalar path.
            #[cfg(feature = "alloc")]
            fn process_chunk(&mut self) {
                debug_assert!(self.bufpos == CHUNK_SIZE);
                if self.chain_length == 0 {
                    self.final_tshk.update(&self.buffer);
                } else {
                    self.pending.push(self.buffer);
                    if self.pending.len() == LEAF_BATCH {
                        self.flush_full_batches();
                    }
                }

                self.chain_length += 1;
                self.buffer = [0u8; CHUNK_SIZE];
                self.bufpos = 0;
            }

            /// Emit a chaining value, writing the one-time inner-node separator first.
            #[cfg(feature = "alloc")]
            fn emit_chaining_value(&mut self, cv: &[u8]) {
                if !self.separator_emitted {
                    self.final_tshk
                        .update(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    self.separator_emitted = true;
                }
                self.final_tshk.update(cv);
            }

            /// Hash queued leaves four at a time via the batched TurboSHAKE.
            #[cfg(feature = "alloc")]
            fn flush_full_batches(&mut self) {
                while self.pending.len() >= LEAF_BATCH {
                    let mut cvs = [[0u8; Self::CHAINING_VALUE_SIZE]; LEAF_BATCH];
                    {
                        let [c0, c1, c2, c3] = &mut cvs;
                        let p = &self.pending;
                        $batch_fn(
                            0x0B,
                            [&p[0][..], &p[1][..], &p[2][..], &p[3][..]],
                            [
                                c0.as_mut_slice(),
                                c1.as_mut_slice(),
                                c2.as_mut_slice(),
                                c3.as_mut_slice(),
                            ],
                        );
                    }
                    for cv in &cvs {
                        self.emit_chaining_value(cv);
                    }
                    self.pending.drain(0..LEAF_BATCH);
                }
            }

            /// Hash any remaining (< `LEAF_BATCH`) queued leaves with scalar TurboSHAKE.
            #[cfg(feature = "alloc")]
            fn flush_remaining_scalar(&mut self) {
                let pending = core::mem::take(&mut self.pending);
                for chunk in pending {
                    let mut result = [0u8; Self::CHAINING_VALUE_SIZE];
                    self.chain_tshk.update(&chunk);
                    self.chain_tshk.finalize_xof_reset_into(&mut result);
                    self.emit_chaining_value(&result);
                }
            }

            #[cfg(feature = "alloc")]
            fn process_chaining_chunk(&mut self) {
                debug_assert!(self.bufpos != 0);
                let mut result = [0u8; Self::CHAINING_VALUE_SIZE];
                self.chain_tshk.update(&self.buffer[..self.bufpos]);
                self.chain_tshk.finalize_xof_reset_into(&mut result);
                self.emit_chaining_value(&result);
            }

            // ---- Scalar leaf path — used when `alloc` is disabled ----
            #[cfg(not(feature = "alloc"))]
            fn process_chunk(&mut self) {
                debug_assert!(self.bufpos == CHUNK_SIZE);
                if self.chain_length == 0 {
                    self.final_tshk.update(&self.buffer);
                } else {
                    self.process_chaining_chunk();
                }

                self.chain_length += 1;
                self.buffer = [0u8; CHUNK_SIZE];
                self.bufpos = 0;
            }

            #[cfg(not(feature = "alloc"))]
            fn process_chaining_chunk(&mut self) {
                debug_assert!(self.bufpos != 0);
                if self.chain_length == 1 {
                    self.final_tshk
                        .update(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                }

                let mut result = [0u8; Self::CHAINING_VALUE_SIZE];
                self.chain_tshk.update(&self.buffer[..self.bufpos]);
                self.chain_tshk.finalize_xof_reset_into(&mut result);
                self.final_tshk.update(&result);
            }
        }

        impl HashMarker for $name<'_> {}

        impl BlockSizeUser for $name<'_> {
            type BlockSize = U128;
        }

        impl BufferKindUser for $name<'_> {
            type BufferKind = Eager;
        }

        impl UpdateCore for $name<'_> {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    if self.bufpos == CHUNK_SIZE {
                        self.process_chunk();
                    }

                    self.buffer[self.bufpos..self.bufpos + 128].clone_from_slice(block);
                    self.bufpos += 128;
                }
            }
        }

        impl ExtendableOutputCore for $name<'_> {
            type ReaderCore = $reader_name;

            #[inline]
            fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
                let mut lenbuf = [0u8; LENGTH_ENCODE_SIZE];

                // Digest customization
                buffer.digest_blocks(self.customization, |block| self.update_blocks(block));
                buffer.digest_blocks(
                    length_encode(self.customization.len(), &mut lenbuf),
                    |block| self.update_blocks(block),
                );

                if self.bufpos == CHUNK_SIZE && buffer.get_pos() != 0 {
                    self.process_chunk();
                }

                // Read leftover data from buffer
                self.buffer[self.bufpos..(self.bufpos + buffer.get_pos())]
                    .copy_from_slice(buffer.get_data());
                self.bufpos += buffer.get_pos();

                // Calculate final node
                if self.chain_length == 0 {
                    // Input did not exceed a single chaining value
                    let tshk = $ts_name::<0x07>::default()
                        .chain(&self.buffer[..self.bufpos])
                        .finalize_xof_reset();
                    return $reader_name { tshk };
                }

                // Flush queued full leaves (batched, then any scalar remainder)
                // before the final leftover leaf so chaining values stay in order.
                #[cfg(feature = "alloc")]
                {
                    self.flush_full_batches();
                    self.flush_remaining_scalar();
                }

                // Calculate last chaining value
                self.process_chaining_chunk();

                // Pad final node calculation
                self.final_tshk
                    .update(length_encode(self.chain_length, &mut lenbuf));
                self.final_tshk.update(&[0xFF, 0xFF]);

                $reader_name {
                    tshk: self.final_tshk.finalize_xof_reset(),
                }
            }
        }

        impl Default for $name<'_> {
            #[inline]
            fn default() -> Self {
                Self {
                    customization: &[],
                    buffer: [0u8; CHUNK_SIZE],
                    bufpos: 0usize,
                    final_tshk: Default::default(),
                    chain_tshk: Default::default(),
                    chain_length: 0usize,
                    #[cfg(feature = "alloc")]
                    pending: Vec::new(),
                    #[cfg(feature = "alloc")]
                    separator_emitted: false,
                }
            }
        }

        impl Reset for $name<'_> {
            #[inline]
            fn reset(&mut self) {
                *self = Self::new(self.customization);
            }
        }

        impl AlgorithmName for $name<'_> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl Drop for $name<'_> {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    use digest::zeroize::Zeroize;
                    self.buffer.zeroize();
                    self.bufpos.zeroize();
                    self.chain_length.zeroize();
                    #[cfg(feature = "alloc")]
                    {
                        for chunk in self.pending.iter_mut() {
                            chunk.zeroize();
                        }
                        self.pending.clear();
                        self.separator_emitted.zeroize();
                    }
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name<'_> {}

        #[doc = "Core"]
        #[doc = $alg_name]
        #[doc = "reader state."]
        #[derive(Clone)]
        pub struct $reader_name {
            tshk: $ts_reader_name,
        }

        impl XofReaderCore for $reader_name {
            #[inline]
            fn read_block(&mut self) -> Block<Self> {
                let mut block = Block::<Self>::default();
                self.tshk.read(&mut block);
                block
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $reader_name {}
    };
}

impl_k12_core!(
    Kt128Core,
    Kt128ReaderCore,
    TurboShake128,
    TurboShake128Reader,
    turbo_shake128_x4,
    32,
    "KT128",
);
impl_k12_core!(
    Kt256Core,
    Kt256ReaderCore,
    TurboShake256,
    TurboShake256Reader,
    turbo_shake256_x4,
    64,
    "KT256",
);

impl BlockSizeUser for Kt128ReaderCore {
    type BlockSize = U168; // TurboSHAKE128 block size
}

impl BlockSizeUser for Kt256ReaderCore {
    type BlockSize = U136; // TurboSHAKE256 block size
}

/// Length-encodes `len` for KangarooTwelve per RFC 9861 Section 3.3.
pub fn length_encode(mut length: usize, buffer: &mut [u8; LENGTH_ENCODE_SIZE]) -> &mut [u8] {
    let mut bufpos = 0usize;
    while length > 0 {
        buffer[bufpos] = (length % 256) as u8;
        length /= 256;
        bufpos += 1;
    }
    buffer[..bufpos].reverse();

    buffer[bufpos] = bufpos as u8;
    bufpos += 1;

    &mut buffer[..bufpos]
}

#[test]
fn test_length_encode() {
    let mut buffer = [0u8; LENGTH_ENCODE_SIZE];
    assert_eq!(length_encode(0, &mut buffer), &[0x00]);
    assert_eq!(length_encode(12, &mut buffer), &[0x0C, 0x01]);
    assert_eq!(length_encode(65538, &mut buffer), &[0x01, 0x00, 0x02, 0x03]);
}
