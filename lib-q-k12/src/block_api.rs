use core::fmt;

use digest::block_api::{
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
    U168,
};
use digest::{
    ExtendableOutputReset,
    HashMarker,
    Reset,
    Update,
    XofReader,
};
use lib_q_sha3::{
    TurboShake128,
    TurboShake128Reader,
    TurboShake256,
    TurboShake256Reader,
};

const CHUNK_SIZE: usize = 8192;
const CHAINING_VALUE_SIZE: usize = 32;
const LENGTH_ENCODE_SIZE: usize = 255;

/// Core [`KangarooTwelve`] hasher state (KT128 variant).
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct KangarooTwelveCore<'cs> {
    customization: &'cs [u8],
    buffer: [u8; CHUNK_SIZE],
    bufpos: usize,
    final_tshk: TurboShake128<0x06>,
    chain_tshk: TurboShake128<0x0B>,
    chain_length: usize,
}

/// Core [`KangarooTwelve256`] hasher state (KT256 variant).
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct KangarooTwelve256Core<'cs> {
    customization: &'cs [u8],
    buffer: [u8; CHUNK_SIZE],
    bufpos: usize,
    final_tshk: TurboShake256<0x06>,
    chain_tshk: TurboShake256<0x0B>,
    chain_length: usize,
}

impl<'cs> KangarooTwelveCore<'cs> {
    /// Creates a new KangarooTwelve (KT128) instance with the given customization.
    pub fn new(customization: &'cs [u8]) -> Self {
        Self {
            customization,
            buffer: [0u8; CHUNK_SIZE],
            bufpos: 0usize,
            final_tshk: Default::default(),
            chain_tshk: Default::default(),
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
        // Note: bufpos can be 0 when processing exactly CHUNK_SIZE bytes
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

impl<'cs> KangarooTwelve256Core<'cs> {
    /// Creates a new KangarooTwelve256 (KT256) instance with the given customization.
    pub fn new(customization: &'cs [u8]) -> Self {
        Self {
            customization,
            buffer: [0u8; CHUNK_SIZE],
            bufpos: 0usize,
            final_tshk: Default::default(),
            chain_tshk: Default::default(),
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
        // Note: bufpos can be 0 when processing exactly CHUNK_SIZE bytes
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
impl HashMarker for KangarooTwelve256Core<'_> {}

impl BlockSizeUser for KangarooTwelveCore<'_> {
    type BlockSize = U128;
}

impl BlockSizeUser for KangarooTwelve256Core<'_> {
    type BlockSize = U128;
}

impl BufferKindUser for KangarooTwelveCore<'_> {
    type BufferKind = Eager;
}

impl BufferKindUser for KangarooTwelve256Core<'_> {
    type BufferKind = Eager;
}

impl UpdateCore for KangarooTwelveCore<'_> {
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

impl UpdateCore for KangarooTwelve256Core<'_> {
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

impl ExtendableOutputCore for KangarooTwelveCore<'_> {
    type ReaderCore = KangarooTwelveReaderCore;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let mut lenbuf = [0u8; LENGTH_ENCODE_SIZE];

        // Digest customization
        buffer.digest_blocks(self.customization, |block| self.update_blocks(block));
        buffer.digest_blocks(
            length_encode(self.customization.len(), &mut lenbuf),
            |block| self.update_blocks(block),
        );

        // Read leftover data from buffer
        let buffer_data = buffer.get_data();
        if !buffer_data.is_empty() {
            let remaining_space = CHUNK_SIZE - self.bufpos;
            let copy_len = buffer_data.len().min(remaining_space);
            self.buffer[self.bufpos..self.bufpos + copy_len]
                .copy_from_slice(&buffer_data[..copy_len]);
            self.bufpos += copy_len;
        }

        // Process final chunk if buffer is full
        if self.bufpos == CHUNK_SIZE {
            self.process_chunk();
        }

        // Calculate final node
        if self.chain_length == 0 {
            // Input did not exceed a single chaining value
            let tshk = TurboShake128::<0x07>::default()
                .chain(&self.buffer[..self.bufpos])
                .finalize_xof_reset();
            return KangarooTwelveReaderCore { reader: tshk };
        }

        // Calculate last chaining value
        self.process_chaining_chunk();

        // Pad final node calculation
        self.final_tshk
            .update(length_encode(self.chain_length, &mut lenbuf));
        self.final_tshk.update(&[0xFF, 0xFF]);

        KangarooTwelveReaderCore {
            reader: self.final_tshk.finalize_xof_reset(),
        }
    }
}

impl ExtendableOutputCore for KangarooTwelve256Core<'_> {
    type ReaderCore = KangarooTwelve256ReaderCore;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let mut lenbuf = [0u8; LENGTH_ENCODE_SIZE];

        // Digest customization
        buffer.digest_blocks(self.customization, |block| self.update_blocks(block));
        buffer.digest_blocks(
            length_encode(self.customization.len(), &mut lenbuf),
            |block| self.update_blocks(block),
        );

        // Read leftover data from buffer
        let buffer_data = buffer.get_data();
        if !buffer_data.is_empty() {
            let remaining_space = CHUNK_SIZE - self.bufpos;
            let copy_len = buffer_data.len().min(remaining_space);
            self.buffer[self.bufpos..self.bufpos + copy_len]
                .copy_from_slice(&buffer_data[..copy_len]);
            self.bufpos += copy_len;
        }

        // Process final chunk if buffer is full
        if self.bufpos == CHUNK_SIZE {
            self.process_chunk();
        }

        // Calculate final node
        if self.chain_length == 0 {
            // Input did not exceed a single chaining value
            let tshk = TurboShake256::<0x07>::default()
                .chain(&self.buffer[..self.bufpos])
                .finalize_xof_reset();
            return KangarooTwelve256ReaderCore { reader: tshk };
        }

        // Calculate last chaining value
        self.process_chaining_chunk();

        // Pad final node calculation
        self.final_tshk
            .update(length_encode(self.chain_length, &mut lenbuf));
        self.final_tshk.update(&[0xFF, 0xFF]);

        KangarooTwelve256ReaderCore {
            reader: self.final_tshk.finalize_xof_reset(),
        }
    }
}

impl Reset for KangarooTwelveCore<'_> {
    fn reset(&mut self) {
        self.buffer = [0u8; CHUNK_SIZE];
        self.bufpos = 0;
        self.final_tshk.reset();
        self.chain_tshk.reset();
        self.chain_length = 0;
    }
}

impl Reset for KangarooTwelve256Core<'_> {
    fn reset(&mut self) {
        self.buffer = [0u8; CHUNK_SIZE];
        self.bufpos = 0;
        self.final_tshk.reset();
        self.chain_tshk.reset();
        self.chain_length = 0;
    }
}

/// KangarooTwelve XOF reader core (KT128 variant).
#[derive(Clone)]
pub struct KangarooTwelveReaderCore {
    reader: TurboShake128Reader,
}

/// KangarooTwelve256 XOF reader core (KT256 variant).
#[derive(Clone)]
pub struct KangarooTwelve256ReaderCore {
    reader: TurboShake256Reader,
}

impl BlockSizeUser for KangarooTwelveReaderCore {
    type BlockSize = U168;
}

impl BlockSizeUser for KangarooTwelve256ReaderCore {
    type BlockSize = U168;
}

impl XofReaderCore for KangarooTwelveReaderCore {
    #[inline]
    fn read_block(&mut self) -> Block<Self> {
        let mut block = Block::<Self>::default();
        self.reader.read(&mut block);
        block
    }
}

impl XofReaderCore for KangarooTwelve256ReaderCore {
    #[inline]
    fn read_block(&mut self) -> Block<Self> {
        let mut block = Block::<Self>::default();
        self.reader.read(&mut block);
        block
    }
}

impl fmt::Debug for KangarooTwelveReaderCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KangarooTwelveReaderCore { .. }")
    }
}

impl fmt::Debug for KangarooTwelve256ReaderCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KangarooTwelve256ReaderCore { .. }")
    }
}

/// Length encoding function for KangarooTwelve.
///
/// This function encodes the length of the customization string
/// according to the KangarooTwelve specification.
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
