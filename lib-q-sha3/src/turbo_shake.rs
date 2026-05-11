//! TurboSHAKE-128 and TurboSHAKE-256: Keccak-`p` with a **domain byte** `DS` (`0x01`..=`0x7F`) and 12 rounds (see [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861.html) and the KangarooTwelve document). Used as the leaf primitive in [`lib_q_k12`](https://github.com/Enkom-Tech/libQ/tree/main/lib-q-k12).
//!
//! Use **distinct** `DS` values for independent protocols. [`TurboShake128`](crate::TurboShake128) and [`TurboShake256`](crate::TurboShake256) are re-exported at the crate root.

use core::fmt;

use digest::block_api::{
    AlgorithmName,
    BlockSizeUser,
    ExtendableOutputCore,
    Reset,
    UpdateCore,
    XofReaderCore,
};
use digest::block_buffer::{
    EagerBuffer,
    ReadBuffer,
};
use digest::consts::{
    U0,
    U16,
    U32,
    U136,
    U168,
};
use digest::{
    CollisionResistance,
    ExtendableOutput,
    ExtendableOutputReset,
    HashMarker,
    Update,
    XofReader,
};

use crate::{
    SpongeHasherCore,
    SpongeReaderCore,
};

const TURBO_SHAKE_ROUND_COUNT: usize = 12;

macro_rules! impl_turbo_shake {
    (
        $name:ident, $reader_name:ident, $rate:ty, $alg_name:expr
    ) => {
        #[doc = $alg_name]
        #[doc = " hasher."]
        #[derive(Clone)]
        pub struct $name<const DS: u8> {
            core: SpongeHasherCore<$rate, U0, DS, TURBO_SHAKE_ROUND_COUNT>,
            buffer: EagerBuffer<$rate>,
        }

        impl<const DS: u8> Default for $name<DS> {
            #[inline]
            fn default() -> Self {
                assert!((0x01..=0x7F).contains(&DS), "invalid domain separator");
                Self {
                    core: Default::default(),
                    buffer: Default::default(),
                }
            }
        }

        impl<const DS: u8> HashMarker for $name<DS> {}

        impl<const DS: u8> BlockSizeUser for $name<DS> {
            type BlockSize = $rate;
        }

        impl<const DS: u8> Update for $name<DS> {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                let Self { core, buffer } = self;
                buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
            }
        }

        impl<const DS: u8> ExtendableOutput for $name<DS> {
            type Reader = $reader_name;

            #[inline]
            fn finalize_xof(mut self) -> Self::Reader {
                let Self { core, buffer } = &mut self;
                let core = core.finalize_xof_core(buffer);
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }

        impl<const DS: u8> ExtendableOutputReset for $name<DS> {
            #[inline]
            fn finalize_xof_reset(&mut self) -> Self::Reader {
                let Self { core, buffer } = self;
                let core = core.finalize_xof_core(buffer);
                self.reset();
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }

        impl<const DS: u8> Reset for $name<DS> {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl<const DS: u8> AlgorithmName for $name<DS> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl<const DS: u8> fmt::Debug for $name<DS> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        #[cfg(feature = "zeroize")]
        impl<const DS: u8> digest::zeroize::ZeroizeOnDrop for $name<DS> {}

        #[doc = $alg_name]
        #[doc = " XOF reader."]
        #[derive(Clone)]
        pub struct $reader_name {
            core: SpongeReaderCore<$rate, TURBO_SHAKE_ROUND_COUNT>,
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

impl_turbo_shake!(TurboShake128, TurboShake128Reader, U168, "TurboSHAKE128");
impl_turbo_shake!(TurboShake256, TurboShake256Reader, U136, "TurboSHAKE256");

impl<const DS: u8> CollisionResistance for TurboShake128<DS> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-7
    type CollisionResistance = U16;
}

impl<const DS: u8> CollisionResistance for TurboShake256<DS> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-8
    type CollisionResistance = U32;
}
