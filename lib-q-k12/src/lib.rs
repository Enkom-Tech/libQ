#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest;

/// Block-level types
pub mod block_api;

use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, HashMarker, Reset, Update, XofReader,
    block_api::{AlgorithmName, BlockSizeUser, ExtendableOutputCore, UpdateCore, XofReaderCore},
    block_buffer::{BlockBuffer, Eager, ReadBuffer},
    consts::{U16, U128, U168},
};

/// `KangarooTwelve` hasher (KT128 variant).
///
/// This is the original KangarooTwelve variant using TurboSHAKE128.
/// Provides 128-bit security strength.
#[derive(Clone)]
pub struct KangarooTwelve<'cs> {
    core: block_api::KangarooTwelveCore<'cs>,
    buffer: BlockBuffer<U128, Eager>,
}

/// `KangarooTwelve256` hasher (KT256 variant).
///
/// This is the extended KangarooTwelve variant using TurboSHAKE256.
/// Provides 256-bit security strength.
#[derive(Clone)]
pub struct KangarooTwelve256<'cs> {
    core: block_api::KangarooTwelve256Core<'cs>,
    buffer: BlockBuffer<U128, Eager>,
}

impl<'cs> KangarooTwelve<'cs> {
    /// Creates a new KangarooTwelve (KT128) instance with the given customization.
    pub fn new(customization: &'cs [u8]) -> Self {
        Self {
            core: block_api::KangarooTwelveCore::new(customization),
            buffer: Default::default(),
        }
    }
}

impl<'cs> KangarooTwelve256<'cs> {
    /// Creates a new KangarooTwelve256 (KT256) instance with the given customization.
    pub fn new(customization: &'cs [u8]) -> Self {
        Self {
            core: block_api::KangarooTwelve256Core::new(customization),
            buffer: Default::default(),
        }
    }
}

impl<'cs> Default for KangarooTwelve<'cs> {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl<'cs> Default for KangarooTwelve256<'cs> {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl fmt::Debug for KangarooTwelve<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KangarooTwelve { .. }")
    }
}

impl fmt::Debug for KangarooTwelve256<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KangarooTwelve256 { .. }")
    }
}

impl AlgorithmName for KangarooTwelve<'_> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KangarooTwelve")
    }
}

impl AlgorithmName for KangarooTwelve256<'_> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KangarooTwelve256")
    }
}

impl HashMarker for KangarooTwelve<'_> {}
impl HashMarker for KangarooTwelve256<'_> {}

impl BlockSizeUser for KangarooTwelve<'_> {
    type BlockSize = U128;
}

impl BlockSizeUser for KangarooTwelve256<'_> {
    type BlockSize = U128;
}

impl Update for KangarooTwelve<'_> {
    fn update(&mut self, data: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
    }
}

impl Update for KangarooTwelve256<'_> {
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

impl Reset for KangarooTwelve256<'_> {
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

impl ExtendableOutput for KangarooTwelve256<'_> {
    type Reader = KangarooTwelve256Reader;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        Self::Reader {
            core: self.core.finalize_xof_core(&mut self.buffer),
            buffer: Default::default(),
        }
    }
}

impl CollisionResistance for KangarooTwelve<'_> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-7
    type CollisionResistance = U16;
}

impl CollisionResistance for KangarooTwelve256<'_> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-7
    type CollisionResistance = U16;
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelve<'_> {}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelve256<'_> {}

/// `KangarooTwelve` XOF reader (KT128 variant).
pub struct KangarooTwelveReader {
    core: block_api::KangarooTwelveReaderCore,
    buffer: ReadBuffer<U168>,
}

/// `KangarooTwelve256` XOF reader (KT256 variant).
pub struct KangarooTwelve256Reader {
    core: block_api::KangarooTwelve256ReaderCore,
    buffer: ReadBuffer<U168>,
}

impl fmt::Debug for KangarooTwelveReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KangarooTwelveReader { .. }")
    }
}

impl fmt::Debug for KangarooTwelve256Reader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("KangarooTwelve256Reader { .. }")
    }
}

impl XofReader for KangarooTwelveReader {
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.read(buffer, |block| *block = core.read_block());
    }
}

impl XofReader for KangarooTwelve256Reader {
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.read(buffer, |block| *block = core.read_block());
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelveReader {}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelve256Reader {}
