use crate::internal_block_api::{Sha3HasherCore, Sha3ReaderCore};
use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, Update, XofReader,
    block_api::{
        AlgorithmName, BlockSizeUser, ExtendableOutputCore, Reset, UpdateCore, XofReaderCore,
    },
    block_buffer::{EagerBuffer, ReadBuffer},
    consts::{U0, U136, U168},
};

use crate::{DEFAULT_ROUND_COUNT, SHAKE_PAD};

macro_rules! impl_shake {
    (
        $name:ident, $reader_name:ident, $rate:ty, $alg_name:expr
    ) => {
        #[doc = $alg_name]
        #[doc = " hasher."]
        #[derive(Clone)]
        pub struct $name {
            core: Sha3HasherCore<$rate, U0, SHAKE_PAD, DEFAULT_ROUND_COUNT>,
            buffer: EagerBuffer<$rate>,
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    core: Default::default(),
                    buffer: Default::default(),
                }
            }
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = $rate;
        }

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                let Self { core, buffer } = self;
                buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
            }
        }

        impl ExtendableOutput for $name {
            type Reader = $reader_name;

            #[inline]
            fn finalize_xof(mut self) -> Self::Reader {
                let Self { core, buffer } = &mut self;
                let core = core.finalize_xof_core(buffer);
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }

        impl ExtendableOutputReset for $name {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                let Self { core, buffer } = self;
                let core = core.finalize_xof_core(buffer);
                self.reset();
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
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

        #[doc = $alg_name]
        #[doc = " XOF reader."]
        #[derive(Clone)]
        pub struct $reader_name {
            core: Sha3ReaderCore<$rate, DEFAULT_ROUND_COUNT>,
            buffer: ReadBuffer<$rate>,
        }

        impl XofReader for $reader_name {
            #[inline]
            fn read(&mut self, buf: &mut [u8]) {
                let Self { core, buffer } = self;
                buffer.read(buf, |block| {
                    *block = core.read_block();
                });
            }
        }

        impl fmt::Debug for $reader_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($reader_name), " { ... }"))
            }
        }
    };
}

impl_shake!(Shake128, Shake128Reader, U168, "SHAKE128");
impl_shake!(Shake256, Shake256Reader, U136, "SHAKE256");

impl CollisionResistance for Shake128 {
    // SHAKE128 provides 128-bit collision resistance
    type CollisionResistance = U168;
}

impl CollisionResistance for Shake256 {
    // SHAKE256 provides 256-bit collision resistance
    type CollisionResistance = U136;
}
