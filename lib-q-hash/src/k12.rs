use crate::block_api::{Sha3HasherCore, Sha3ReaderCore};
use core::fmt;
use digest::{
    block_api::{
        AlgorithmName, BlockSizeUser, ExtendableOutputCore, Reset, UpdateCore, XofReaderCore,
    },
    block_buffer::{EagerBuffer, ReadBuffer},
    consts::{U0, U128, U168},
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, Update, XofReader,
};

use crate::DEFAULT_ROUND_COUNT;

const CHUNK_SIZE: usize = 8192;
const CHAINING_VALUE_SIZE: usize = 32;
const LENGTH_ENCODE_SIZE: usize = 255;

/// Core KangarooTwelve hasher state.
#[derive(Clone)]
pub struct KangarooTwelveCore<'cs> {
    customization: &'cs [u8],
    buffer: [u8; CHUNK_SIZE],
    bufpos: usize,
    final_tshk: TurboShake128,
    chain_tshk: TurboShake128,
    chain_length: usize,
}

impl<'cs> KangarooTwelveCore<'cs> {
    /// Creates a new KangarooTwelve instance with the given customization.
    pub fn new(customization: &'cs [u8]) -> Self {
        Self {
            customization,
            buffer: [0u8; CHUNK_SIZE],
            bufpos: 0usize,
            final_tshk: TurboShake128::default(),
            chain_tshk: TurboShake128::default(),
            chain_length: 0usize,
        }
    }

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

    fn process_chaining_chunk(&mut self) {
        debug_assert!(self.bufpos != 0);
        if self.chain_length == 1 {
            self.final_tshk
                .update(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        let mut result = [0u8; CHAINING_VALUE_SIZE];
        self.chain_tshk.update(&self.buffer[..self.bufpos]);
        self.chain_tshk.finalize_xof_reset_into(&mut result);
        self.final_tshk.update(&result);
    }
}

impl HashMarker for KangarooTwelveCore<'_> {}

impl BlockSizeUser for KangarooTwelveCore<'_> {
    type BlockSize = U128;
}

impl digest::block_api::BufferKindUser for KangarooTwelveCore<'_> {
    type BufferKind = digest::block_api::Eager;
}

impl UpdateCore for KangarooTwelveCore<'_> {
    #[inline]
    fn update_blocks(&mut self, blocks: &[digest::block_api::Block<Self>]) {
        for block in blocks {
            if self.bufpos == CHUNK_SIZE {
                self.process_chunk();
            }

            self.buffer[self.bufpos..self.bufpos + 128].clone_from_slice(block);
            self.bufpos += 128;
        }
    }
}

impl ExtendableOutputCore for KangarooTwelveCore<'_> {
    type ReaderCore = KangarooTwelveReaderCore;

    #[inline]
    fn finalize_xof_core(
        &mut self,
        buffer: &mut digest::block_api::Buffer<Self>,
    ) -> Self::ReaderCore {
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
            let mut tshk = TurboShake128::default();
            tshk.update(&self.buffer[..self.bufpos]);
            let tshk = tshk.finalize_xof_reset();
            return KangarooTwelveReaderCore { tshk };
        }

        // Calculate last chaining value
        self.process_chaining_chunk();

        // Pad final node calculation
        self.final_tshk
            .update(length_encode(self.chain_length, &mut lenbuf));
        self.final_tshk.update(&[0xff, 0xff]);

        let core = self
            .final_tshk
            .core
            .finalize_xof_core(&mut self.final_tshk.buffer);
        KangarooTwelveReaderCore {
            tshk: TurboShake128Reader { core },
        }
    }
}

impl Default for KangarooTwelveCore<'_> {
    #[inline]
    fn default() -> Self {
        Self {
            customization: &[],
            buffer: [0u8; CHUNK_SIZE],
            bufpos: 0usize,
            final_tshk: Default::default(),
            chain_tshk: Default::default(),
            chain_length: 0usize,
        }
    }
}

impl Reset for KangarooTwelveCore<'_> {
    #[inline]
    fn reset(&mut self) {
        *self = Self::new(self.customization);
    }
}

impl AlgorithmName for KangarooTwelveCore<'_> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KangarooTwelve")
    }
}

impl fmt::Debug for KangarooTwelveCore<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KangarooTwelveCore { ... }")
    }
}

impl Drop for KangarooTwelveCore<'_> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.buffer.zeroize();
            self.bufpos.zeroize();
            self.chain_length.zeroize();
            // final_tshk and chain_tshk zeroized by their Drop impl
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelveCore<'_> {}

/// Core KangarooTwelve reader state.
#[derive(Clone)]
pub struct KangarooTwelveReaderCore {
    tshk: TurboShake128Reader,
}

impl BlockSizeUser for KangarooTwelveReaderCore {
    type BlockSize = U168; // TurboSHAKE128 block size
}

impl XofReaderCore for KangarooTwelveReaderCore {
    #[inline]
    fn read_block(&mut self) -> digest::block_api::Block<Self> {
        let mut block = digest::block_api::Block::<Self>::default();
        self.tshk.read(&mut block);
        block
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelveReaderCore {}

/// KangarooTwelve hasher.
#[derive(Default, Clone)]
pub struct KangarooTwelve<'cs> {
    core: KangarooTwelveCore<'cs>,
    buffer: EagerBuffer<U128>,
}

impl<'cs> KangarooTwelve<'cs> {
    /// Creates a new KangarooTwelve instance with the given customization.
    pub fn new(customization: &'cs [u8]) -> Self {
        Self {
            core: KangarooTwelveCore::new(customization),
            buffer: Default::default(),
        }
    }
}

impl fmt::Debug for KangarooTwelve<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KangarooTwelve { .. }")
    }
}

impl AlgorithmName for KangarooTwelve<'_> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KangarooTwelve")
    }
}

impl HashMarker for KangarooTwelve<'_> {}

impl BlockSizeUser for KangarooTwelve<'_> {
    type BlockSize = U128;
}

impl Update for KangarooTwelve<'_> {
    fn update(&mut self, data: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
    }
}

impl Reset for KangarooTwelve<'_> {
    fn reset(&mut self) {
        self.core.reset();
        self.buffer.reset();
    }
}

impl ExtendableOutput for KangarooTwelve<'_> {
    type Reader = KangarooTwelveReader;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        Self::Reader {
            core: self.core.finalize_xof_core(&mut self.buffer),
            buffer: Default::default(),
        }
    }
}

impl ExtendableOutputReset for KangarooTwelve<'_> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let core = self.core.finalize_xof_core(&mut self.buffer);
        self.reset();
        Self::Reader {
            core,
            buffer: Default::default(),
        }
    }
}

impl CollisionResistance for KangarooTwelve<'_> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-7
    type CollisionResistance = digest::consts::U16;
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelve<'_> {}

/// KangarooTwelve XOF reader.
pub struct KangarooTwelveReader {
    core: KangarooTwelveReaderCore,
    buffer: ReadBuffer<U168>,
}

impl fmt::Debug for KangarooTwelveReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KangarooTwelveReader { .. }")
    }
}

impl XofReader for KangarooTwelveReader {
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.read(buffer, |block| *block = core.read_block());
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelveReader {}

// TurboSHAKE128 implementation using the shared keccak
#[derive(Default, Clone)]
pub struct TurboShake128 {
    core: Sha3HasherCore<U168, U0, 0x06, DEFAULT_ROUND_COUNT>,
    buffer: EagerBuffer<U168>,
}

impl TurboShake128 {
    pub fn finalize_xof_reset(mut self) -> TurboShake128Reader {
        let core = self.core.finalize_xof_core(&mut self.buffer);
        TurboShake128Reader { core }
    }

    pub fn finalize_xof_reset_into(&mut self, out: &mut [u8]) {
        let core = self.core.finalize_xof_core(&mut self.buffer);
        let mut reader = TurboShake128Reader { core };
        reader.read(out);
    }
}

impl Update for TurboShake128 {
    fn update(&mut self, data: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
    }
}

#[derive(Clone)]
pub struct TurboShake128Reader {
    core: Sha3ReaderCore<U168, DEFAULT_ROUND_COUNT>,
}

impl XofReader for TurboShake128Reader {
    fn read(&mut self, buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(168) {
            let block = self.core.read_block();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

fn length_encode(mut length: usize, buffer: &mut [u8; LENGTH_ENCODE_SIZE]) -> &mut [u8] {
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
